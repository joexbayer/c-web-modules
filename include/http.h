#ifndef HTTP_H
#define HTTP_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <ctype.h>

#define HTTP_VERSION "HTTP/1.1"
#define HTTP_RESPONSE_SIZE 8*1024

typedef enum http_method {
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
} http_method_t;
extern const char *http_methods[];

typedef enum http_error {
    HTTP_200_OK,
    HTTP_302_FOUND,
    HTTP_400_BAD_REQUEST,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
    HTTP_500_INTERNAL_SERVER_ERROR
} http_error_t;
extern const char *http_errors[];

struct http_request {
    http_method_t method;
    char *path;
    char *body;
    int content_length;
    pthread_t tid;
    struct map *params;
    struct map *headers;
    struct map *data;
};

struct http_response {
    http_error_t status;
    struct map *headers;
    char *body;
};

int http_parse(const char *request, struct http_request *req);
int http_parse_data(struct http_request *req);  

#endif // HTTP_H