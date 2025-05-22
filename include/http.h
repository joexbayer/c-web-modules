#ifndef HTTP_H
#define HTTP_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <ctype.h>

#define HTTP_VERSION "HTTP/1.1"
#define HTTP_RESPONSE_SIZE 8*1024 /* 8KB */

typedef enum http_version {
    HTTP_VERSION_1_0,
    HTTP_VERSION_1_1,
} http_version_t;

typedef enum http_method {
    HTTP_ERR = -1,
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
} http_method_t;
extern const char *http_methods[];

typedef enum http_error {
    HTTP_000_UNKNOWN,
    HTTP_101_SWITCHING_PROTOCOLS,
    HTTP_200_OK,
    HTTP_302_FOUND,
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
    HTTP_405_METHOD_NOT_ALLOWED,
    HTTP_414_URI_TOO_LONG,
    HTTP_500_INTERNAL_SERVER_ERROR
} http_error_t;
extern const char *http_errors[];

struct http_request {
    http_method_t method;
    http_version_t version;
    http_error_t status;
    char *path;
    char *body;
    int content_length;
    char keep_alive;
    char close;
    pthread_t tid;
    struct map *params;
    struct map *headers;
    struct map *data;

    int websocket;
};

struct http_response {
    http_error_t status;
    struct map *headers;
    char *body;
    int content_length;
};

struct websocket {
    char* session;
    int client_fd;
    int (*send)(struct websocket* ws, const char *message, size_t length);
    int (*close)(struct websocket* ws);
};

int http_parse(const char *request, struct http_request *req);
int http_parse_data(struct http_request *req);  
int http_is_websocket_upgrade(struct http_request *req);

#endif // HTTP_H