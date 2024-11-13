#ifndef ROUTER_H
#define ROUTER_H

// Include necessary standard libraries
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <cweb.h>

#define ROUTE_SIZE 128
#define ROUTE_COUNT 100
typedef int (*handler_t)(struct http_request *, struct http_response *);
struct gateway_entry {
    void *handle;
    char so_path[256];
    struct module *module;
    pthread_mutex_t mutex;
};

struct route {
    struct route_info *route;
    pthread_mutex_t* mutex;
};

void route_init();
int route_register_module(char* so_path);
struct route route_find(char *route, char *method);

/* TODO: Move... */
int mgnt_parse_request(struct http_request *req);
void safe_execute_handler(handler_t handler, struct http_request *req, struct http_response *res);

#define dbgprint(fmt, ...) \
    do { fprintf(stderr, fmt, __VA_ARGS__); } while (0)


#endif // ROUTER_H