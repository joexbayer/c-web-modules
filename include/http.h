#ifndef HTTP_H
#define HTTP_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <ctype.h>
#include <stddef.h>

typedef struct http_kv_pair {
    char *key;
    char *value;
} http_kv_pair_t;

typedef struct http_kv_store {
    http_kv_pair_t *entries;
    size_t size;
    size_t capacity;
} http_kv_store_t;

http_kv_store_t *http_kv_create(size_t initial_capacity);
void http_kv_destroy(http_kv_store_t *store, int free_values);
int http_kv_insert(http_kv_store_t *store, const char *key, char *value);
char *http_kv_get(const http_kv_store_t *store, const char *key);
size_t http_kv_size(const http_kv_store_t *store);

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
    HTTP_OPTIONS,
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
    HTTP_409_CONFLICT,
    HTTP_413_PAYLOAD_TOO_LARGE,
    HTTP_414_URI_TOO_LONG,
    HTTP_426_UPGRADE_REQUIRED,
    HTTP_500_INTERNAL_SERVER_ERROR,
    HTTP_501_NOT_IMPLEMENTED
} http_error_t;
extern const char *http_errors[];

typedef struct http_request {
    http_method_t method;
    http_version_t version;
    http_error_t status;
    char *path;
    char *body;
    int content_length;
    char keep_alive;
    char close;
    pthread_t tid;
    http_kv_store_t *params;
    http_kv_store_t *headers;
    http_kv_store_t *data;

    int websocket;
    int transfer_encoding_chunked;
} http_request_t;

typedef struct http_response {
    http_error_t status;
    http_kv_store_t *headers;
    char *body;
    int content_length;
} http_response_t;

typedef struct websocket {
    char* session;
    int client_fd;
    int (*send)(struct websocket* ws, const char *message, size_t length);
    int (*close)(struct websocket* ws);
} websocket_t;

int http_parse(const char *request, size_t request_len, http_request_t *req);
int http_parse_data(http_request_t *req);
int http_is_websocket_upgrade(http_request_t *req);
/* Returns 0 on success, 1 if body is incomplete, -1 on error. */
int http_decode_chunked_body(const char *body, size_t body_len, char **out, size_t *out_len);

#endif // HTTP_H
