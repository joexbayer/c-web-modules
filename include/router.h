#ifndef ROUTER_H
#define ROUTER_H

// Include necessary standard libraries
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <cweb.h>

#define SO_PATH_MAX_LEN 256

typedef int (*handler_t)(struct http_request *, struct http_response *);
struct gateway_entry {
    void *handle;
    char so_path[SO_PATH_MAX_LEN];
    struct module *module;
    pthread_rwlock_t rwlock;
};

struct route {
    struct route_info *route;
    pthread_rwlock_t* rwlock;
};

struct ws_route {
    struct ws_info *info;
    pthread_rwlock_t* rwlock;
};

int route_register_module(char* so_path);
struct route route_find(char *route, char *method);
struct ws_route ws_route_find(char *route);
int route_gateway_json(struct http_response* res);

void* resolv(const char* module, const char* symbol);

/* TODO: Move... */
int mgnt_parse_request(struct http_request *req, struct http_response *res);
void safe_execute_handler(handler_t handler, struct http_request *req, struct http_response *res);

#define dbgprint(fmt, ...) \
    do { fprintf(stderr, fmt, __VA_ARGS__); } while (0)


#endif // ROUTER_H