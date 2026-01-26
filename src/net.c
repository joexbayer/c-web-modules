#include "server.h"
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define ACCEPT_BACKLOG 128

struct connection server_init_socket(uint16_t port) {
    struct connection s;
    s.sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (s.sockfd == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(s.sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
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

    if (listen(s.sockfd, ACCEPT_BACKLOG) < 0) {
        perror("Listen failed");
        close(s.sockfd);
        exit(EXIT_FAILURE);
    }

    return s;
}

struct connection* server_accept(struct server_state *state, struct connection s) {
    struct connection *c = (struct connection *)malloc(sizeof(struct connection));
    if (c == NULL) {
        perror("Error allocating memory for client");
        close(s.sockfd);
        return NULL;
    }

    memset(c, 0, sizeof(struct connection));

#ifndef PRODUCTION
    (void)state;
#endif

    struct sockaddr_in client_addr;
    socklen_t addrlen = (socklen_t)sizeof(client_addr);
    c->sockfd = accept(s.sockfd, (struct sockaddr *)&client_addr, &addrlen);
    if (c->sockfd < 0) {
        perror("Accept failed");
        free(c);
        return NULL;
    }
    c->address = client_addr;

#ifdef PRODUCTION
    c->ssl = SSL_new(state->crypto.ctx);
    if (!c->ssl) {
        perror("[ERROR] SSL initialization failed");
        close(c->sockfd);
        free(c);
        return NULL;
    }

    SSL_set_fd(c->ssl, c->sockfd);
    if (SSL_accept(c->ssl) <= 0) {
        perror("[ERROR] SSL handshake failed");
        SSL_free(c->ssl);
        close(c->sockfd);
        free(c);
        return NULL;
    }
#endif

    return c;
}
