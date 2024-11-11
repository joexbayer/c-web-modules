
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

    struct route *r = route_find(req->path);
    if (r) {
        safe_execute_handler(r->handler, req, res);
    } else {
        res->status = HTTP_404_NOT_FOUND;
        snprintf(res->body, HTTP_RESPONSE_SIZE, "404 Not Found\n"); 
    }
    return 0;
}


void *handle_client(void *arg) {
    struct client *c = (struct client *)arg;

    /* Read in HTTP header */
    char buffer[30000] = {0};
    int read_size = read(c->client_sock, buffer, sizeof(buffer) - 1);
    if (read_size <= 0) {
        close(c->client_sock);
        free(c);
        return NULL;
    }
    buffer[read_size] = '\0';

    struct http_request req;
    http_parse(buffer, &req);

    /* Make sure entire request is read. TODO: Cant do this for huge requests.. */
    while (req.content_length > read_size) {
        read_size += read(c->client_sock, buffer + read_size, sizeof(buffer) - read_size - 1);
        buffer[read_size] = '\0';
    }

    struct http_response res; 
    res.body = mmap(NULL, HTTP_RESPONSE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (res.body == MAP_FAILED) {
        perror("Error allocating shared memory");
        close(c->client_sock);
        free(c);
        return NULL;
    }

    if(strncmp(req.path, "/mgnt", 6) == 0) {
        mgnt_parse_request(&req);
        res.status = HTTP_200_OK;
        snprintf(res.body, HTTP_RESPONSE_SIZE, "Management request received.\n");
    } else {
        gateway(&req, &res);
    }

    printf("Finished processing request.\n");

    char response[30000] = {0};
    sprintf(response, "HTTP/1.1 %s\r\nContent-Length: %ld\r\n\r\n%s", http_errors[res.status], strlen(res.body), res.body);
    printf("Response: %s\n", response);
    write(c->client_sock, response, strlen(response));

    close(c->client_sock);
    munmap(res.body, HTTP_RESPONSE_SIZE); 
    free(c);
    return NULL;
}

int main() {
    mgnt_register_route("/hello", "#include <stdio.h>\nvoid hello() { printf(\"Hello, World!\\n\"); }", "hello");

    struct server s = server_init(8080);
    
    while (1) {
        struct client *client = server_accept(s);
        if (client == NULL) {
            perror("Error accepting client");
            close(s.server_fd);
            exit(EXIT_FAILURE);
        }

        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, client) != 0) {
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