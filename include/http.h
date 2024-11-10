#ifndef HTTP_H
#define HTTP_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define HTTP_VERSION "HTTP/1.1"

typedef enum http_method {
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
} http_method_t;

typedef enum http_error {
    HTTP_200_OK = 200,
    HTTP_400_BAD_REQUEST = 400,
    HTTP_403_FORBIDDEN = 403,
    HTTP_404_NOT_FOUND = 404,
    HTTP_500_INTERNAL_SERVER_ERROR = 500,
} http_error_t;

struct http_request {
    http_method_t method;
    char *path;
    struct map *query_params;
    struct map *headers;
    char *body;
};

struct http_response {
    http_error_t status;
    char *body;
};

struct http_server {
    void (*handler)(struct http_request *, struct http_response *);
};

int http_parse(const char *request, struct http_request *req);

#endif // HTTP_H