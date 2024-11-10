
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "http.h"
#include "router.h"

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

static struct client server_accept(struct server s) {
    struct client c;
    int addrlen = sizeof(c.address);
    c.client_sock = accept(s.server_fd, (struct sockaddr *)&c.address, (socklen_t*)&addrlen);
    if (c.client_sock < 0) {
        perror("Accept failed");
        close(s.server_fd);
        exit(EXIT_FAILURE);
    }
    return c;
}

static int gateway(struct http_request *req, struct http_response *res) {

    if(strncmp(req->path, "/mgnt", 6) == 0) {
        ///

        return 0;
    }

    struct route *r = route_find(req->path);
    if (r) {
        r->handler(req, res);
    } else {
        res->status = HTTP_404_NOT_FOUND;
        res->body = "404 Not Found";
    }
    return 0;
}

int main() {
    struct server s = server_init(8080);
    struct client c = server_accept(s);

    mgnt_register_route("/hello", "void hello() { printf(\"Hello, World!\\n\"); }", "hello");

    char buffer[30000] = {0};
    int read_size = read(c.client_sock, buffer, sizeof(buffer) - 1);
    if (read_size <= 0) {
        close(c.client_sock);
        close(s.server_fd);
        exit(EXIT_FAILURE);
    }
    buffer[read_size] = '\0';

    struct http_request req;
    http_parse(buffer, &req);

    mgnt_parse_request(&req);

    close(c.client_sock);
    close(s.server_fd);
    return 0;
}



