
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>

#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/mman.h>

#include "http.h"
#include "router.h"
#include "cweb.h"
#include "map.h"

struct connection {
    int sockfd;
    struct sockaddr_in address;
};

static struct connection server_init(uint16_t port) {
    struct connection s;
    s.sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (s.sockfd == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(s.sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        close(s.sockfd);
        exit(EXIT_FAILURE);
    }

    s.address.sin_family = AF_INET;
    s.address.sin_addr.s_addr = INADDR_ANY;
    s.address.sin_port = htons(port);

    if (bind(s.sockfd, (struct sockaddr *)&s.address, sizeof(s.address)) < 0) {
        perror("Bind failed");
        close(s.sockfd);
        exit(EXIT_FAILURE);
    }

    if (listen(s.sockfd, 3) < 0) {
        perror("Listen failed");
        close(s.sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on port %d\n", port);
    return s;
}

static struct connection* server_accept(struct connection s) {
    struct connection *c = (struct connection *)malloc(sizeof(struct connection));
    if (c == NULL) {
        perror("Error allocating memory for client");
        close(s.sockfd);
        exit(EXIT_FAILURE);
    }

    int addrlen = sizeof(s.address);
    c->sockfd = accept(s.sockfd, (struct sockaddr *)&s.address, (socklen_t *)&addrlen);
    if (c->sockfd < 0) {
        perror("Accept failed");
        close(s.sockfd);
        free(c);
        exit(EXIT_FAILURE);
    }

    return c;
}

/* TODO: Run in seprate isolated process. */
static int gateway(struct http_request *req, struct http_response *res) {
    if (strncmp(req->path, "/favicon.ico", 12) == 0) {
        res->status = HTTP_404_NOT_FOUND;
        snprintf(res->body, HTTP_RESPONSE_SIZE, "404 Not Found\n");
        return 0;
    }

    struct route r = route_find(req->path, (char*)http_methods[req->method]);
    if (r.route == NULL) {
        res->status = HTTP_404_NOT_FOUND;
        snprintf(res->body, HTTP_RESPONSE_SIZE, "404 Not Found\n"); 
        return 0;
    }

    safe_execute_handler(r.route->handler, req, res);

    /* Release the read lock after handler execution */
    pthread_rwlock_unlock(r.rwlock);
    return 0;
}

static void build_headers(struct http_response *res, char *headers, int headers_size) {
    struct map *headers_map = res->headers;
    int headers_len = 0;
    for (size_t i = 0; i < map_size(headers_map); i++) {
        int written = snprintf(headers + headers_len, headers_size - headers_len, "%s: %s\r\n", headers_map->entries[i].key, (char*)headers_map->entries[i].value);
        if (written < 0 || written >= headers_size - headers_len) {
            fprintf(stderr, "Header buffer overflow\n");
            break;
        }
        headers_len += written;
    }
}

static void *thread_handle_client(void *arg) {
    struct connection *c = (struct connection *)arg;

    /* Measure time */
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Read in HTTP header */
    char buffer[8*1024] = {0};
    int read_size = read(c->sockfd, buffer, sizeof(buffer) - 1);
    if (read_size <= 0) {
        close(c->sockfd);
        free(c);
        return NULL;
    }
    buffer[read_size] = '\0';

    struct http_request req;
    req.tid = pthread_self(); /* store threadid */
    http_parse(buffer, &req);

    /* Make sure entire request is read. TODO: Cant do this for huge requests.. */
    while (req.content_length > read_size) {
        read_size += read(c->sockfd, buffer + read_size, sizeof(buffer) - read_size - 1);
        buffer[read_size] = '\0';
    }
    req.body = strdup(strstr(buffer, "\r\n\r\n") + 4);

    /* Parse potential data in the body (like form data) */
    http_parse_data(&req);

    /* Prepare response */
    struct http_response res;
    res.headers = map_create(10);
    if (res.headers == NULL) {
        perror("Error creating map");
        close(c->sockfd);
        free(c);
        return NULL;
    }

    /* Memory allocated for body with mmap to be able to share between proccesses (currently not used.) */
    res.body = mmap(NULL, HTTP_RESPONSE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (res.body == MAP_FAILED) {
        perror("Error allocating shared memory");
        close(c->sockfd);
        free(c);
        return NULL;
    }

    /* Handle management requests */
    if(strncmp(req.path, "/mgnt", 6) == 0) {
        if(mgnt_parse_request(&req) >= 0) {
            res.status = HTTP_200_OK;
            snprintf(res.body, HTTP_RESPONSE_SIZE, "Management request received.\n");
        } else{
            res.status = HTTP_500_INTERNAL_SERVER_ERROR;
            snprintf(res.body, HTTP_RESPONSE_SIZE, "Management request failed.\n");
        }
    } else {
        /* Handle gateway requests */
        gateway(&req, &res);
    }

    char headers[4*1024] = {0};
    build_headers(&res, headers, sizeof(headers));
    
    char response[8*1024] = {0};
    snprintf(response, sizeof(response), "HTTP/1.1 %s\r\n%sContent-Length: %lu\r\n\r\n%s", http_errors[res.status], headers, strlen(res.body), res.body);
    write(c->sockfd, response, strlen(response));

    /* Clean up */
    if(req.body) free(req.body);
    map_destroy(req.params);
    map_destroy(req.headers);
    map_destroy(req.data);
    map_destroy(res.headers);
    close(c->sockfd);
    munmap(res.body, HTTP_RESPONSE_SIZE); 
    free(c);

    clock_gettime(CLOCK_MONOTONIC, &end);
    double time_taken = (end.tv_sec - start.tv_sec) * 1e9;
    time_taken = (time_taken + (end.tv_nsec - start.tv_nsec)) * 1e-9;

    printf("[%ld] Request %s %s took %f seconds\n", (long)req.tid, http_methods[req.method], req.path, time_taken);
    return NULL;
}

int main() {
    struct connection s = server_init(8080);

    while(1){
        struct connection *client = server_accept(s);
        if (client == NULL) {
            perror("Error accepting client");
            close(s.sockfd);
            exit(EXIT_FAILURE);
        }

        pthread_t thread;
        if (pthread_create(&thread, NULL, thread_handle_client, client) != 0) {
            perror("Error creating thread");
            close(s.sockfd);
            close(client->sockfd);
            free(client);
            exit(EXIT_FAILURE);
        }

        /* Print counter */
        int *counter_ptr = (int*)container->get("counter");
        if (counter_ptr) {
            int counter = *counter_ptr;
            printf("Counter: %d\n", counter);
        }

        pthread_detach(thread); 
    }

    return 0;
}