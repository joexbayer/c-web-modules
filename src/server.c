
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

struct server {
    int server_fd;
    struct sockaddr_in address;
};

struct client {
    int client_sock;
    struct sockaddr_in address;
};

static struct server server_init(uint16_t port) {
    struct server s;
    s.server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s.server_fd == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(s.server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        close(s.server_fd);
        exit(EXIT_FAILURE);
    }

    s.address.sin_family = AF_INET;
    s.address.sin_addr.s_addr = INADDR_ANY;
    s.address.sin_port = htons(port);

    if (bind(s.server_fd, (struct sockaddr *)&s.address, sizeof(s.address)) < 0) {
        perror("Bind failed");
        close(s.server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(s.server_fd, 3) < 0) {
        perror("Listen failed");
        close(s.server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on port %d\n", port);
    return s;
}

static struct client* server_accept(struct server s) {
    struct client *c = (struct client *)malloc(sizeof(struct client));
    if (c == NULL) {
        perror("Error allocating memory for client");
        close(s.server_fd);
        exit(EXIT_FAILURE);
    }

    int addrlen = sizeof(s.address);
    c->client_sock = accept(s.server_fd, (struct sockaddr *)&s.address, (socklen_t *)&addrlen);
    if (c->client_sock < 0) {
        perror("Accept failed");
        close(s.server_fd);
        free(c);
        exit(EXIT_FAILURE);
    }

    return c;
}

static int gateway(struct http_request *req, struct http_response *res) {
    if (strncmp(req->path, "/favicon.ico", 12) == 0) {
        res->status = HTTP_404_NOT_FOUND;
        snprintf(res->body, HTTP_RESPONSE_SIZE, "404 Not Found\n");
        return 0;
    }

    struct route *r = route_find(req->path, http_methods[req->method]);
    if (!r) {
        res->status = HTTP_404_NOT_FOUND;
        snprintf(res->body, HTTP_RESPONSE_SIZE, "404 Not Found\n"); 
        return 0;
    }
    
    safe_execute_handler(r->handler, req, res);
    return 0;
}

static void build_headers(struct http_response *res, char *headers, int headers_size) {
    struct map *headers_map = res->headers;
    int headers_len = 0;
    for (size_t i = 0; i < map_size(headers_map); i++) {
        const char *key = headers_map->entries[i].key;
        const char *value = headers_map->entries[i].value;

        int written = snprintf(headers + headers_len, headers_size - headers_len, "%s: %s\r\n", key, value);
        if (written < 0 || written >= headers_size - headers_len) {
            fprintf(stderr, "Header buffer overflow\n");
            break;
        }
        headers_len += written;
    }
}

static void *thread_handle_client(void *arg) {
    struct client *c = (struct client *)arg;

    /* Measure time */
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Read in HTTP header */
    char buffer[8*1024] = {0};
    int read_size = read(c->client_sock, buffer, sizeof(buffer) - 1);
    if (read_size <= 0) {
        close(c->client_sock);
        free(c);
        return NULL;
    }
    buffer[read_size] = '\0';

    struct http_request req;
    req.tid = pthread_self(); /* store threadid */
    http_parse(buffer, &req);

    /* Make sure entire request is read. TODO: Cant do this for huge requests.. */
    while (req.content_length > read_size) {
        read_size += read(c->client_sock, buffer + read_size, sizeof(buffer) - read_size - 1);
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
        close(c->client_sock);
        free(c);
        return NULL;
    }

    /* Memory allocated for body with mmap to be able to share between proccesses (currently not used.) */
    res.body = mmap(NULL, HTTP_RESPONSE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (res.body == MAP_FAILED) {
        perror("Error allocating shared memory");
        close(c->client_sock);
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
    write(c->client_sock, response, strlen(response));

    /* Clean up */
    if(req.body) free(req.body);
    map_destroy(req.params);
    map_destroy(req.headers);
    map_destroy(req.data);
    map_destroy(res.headers);
    close(c->client_sock);
    munmap(res.body, HTTP_RESPONSE_SIZE); 
    free(c);

    clock_gettime(CLOCK_MONOTONIC, &end);
    double time_taken = (end.tv_sec - start.tv_sec) * 1e9;
    time_taken = (time_taken + (end.tv_nsec - start.tv_nsec)) * 1e-9;

    printf("[%ld] Request %s %s took %f seconds\n", req.tid, http_methods[req.method], req.path, time_taken);
    return NULL;
}


int main() {
    route_init();
    struct server s = server_init(8080);
    
    while(1){
        struct client *client = server_accept(s);
        if (client == NULL) {
            perror("Error accepting client");
            close(s.server_fd);
            exit(EXIT_FAILURE);
        }

        pthread_t thread;
        if (pthread_create(&thread, NULL, thread_handle_client, client) != 0) {
            perror("Error creating thread");
            close(s.server_fd);
            close(client->client_sock);
            free(client);
            exit(EXIT_FAILURE);
        }

        pthread_detach(thread); 
    }

    return 0;
}