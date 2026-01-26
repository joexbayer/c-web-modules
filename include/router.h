#ifndef ROUTER_H
#define ROUTER_H

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <cweb.h>

#define SO_PATH_MAX_LEN 256
#define ROUTER_MAX_MODULES 100

typedef int (*handler_t)(struct cweb_context *, http_request_t *, http_response_t *);

struct ws_server;

struct gateway_entry {
    void *handle;
    char so_path[SO_PATH_MAX_LEN];
    module_t *module;
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

struct router {
    struct gateway_entry entries[ROUTER_MAX_MODULES];
    pthread_rwlock_t rwlock;
    pthread_mutex_t save_mutex;
    int count;
    struct ws_server *ws;
    char route_file[SO_PATH_MAX_LEN];
};

int router_init(struct router *router, struct ws_server *ws, const char *route_file, struct cweb_context *ctx);
void router_shutdown(struct router *router, struct cweb_context *ctx);
int router_register_module(struct router *router, struct cweb_context *ctx, const char* so_path);
struct route router_find(struct router *router, const char *route, const char *method);
struct ws_route router_ws_find(struct router *router, const char *route);
int router_gateway_json(struct router *router, http_response_t *res);
void* router_resolve(struct router *router, const char* module, const char* symbol);

int router_mgnt_parse_request(struct router *router, struct cweb_context *ctx, http_request_t *req, http_response_t *res);

#endif // ROUTER_H
