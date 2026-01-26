#ifndef ROUTER_H
#define ROUTER_H

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
#include <cweb.h>

#define SO_PATH_MAX_LEN 256
#define ROUTER_MAX_MODULES 100

typedef int (*handler_t)(struct cweb_context *, http_request_t *, http_response_t *);

struct ws_server;

struct module_ref {
    void *handle;
    char so_path[SO_PATH_MAX_LEN];
    char module_hash[65];
    module_t *module;
    atomic_int job_refs;
    int retired;
    struct module_ref *next;
};

struct gateway_entry {
    struct module_ref *ref;
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

struct job_route {
    struct job_info *job;
    struct module_ref *ref;
    char module_hash[65];
};

struct router {
    struct gateway_entry entries[ROUTER_MAX_MODULES];
    pthread_rwlock_t rwlock;
    pthread_mutex_t save_mutex;
    pthread_mutex_t retired_mutex;
    struct module_ref *retired;
    void *module_handle;
    int count;
    struct ws_server *ws;
    char module_dir[SO_PATH_MAX_LEN];
    char route_file[SO_PATH_MAX_LEN];
    int purge_modules;
};

int router_init(struct router *router, struct ws_server *ws, const char *route_file, const char *module_dir, int purge_modules, struct cweb_context *ctx);
void router_shutdown(struct router *router, struct cweb_context *ctx);
int router_register_module(struct router *router, struct cweb_context *ctx, const char* so_path);
struct route router_find(struct router *router, const char *route, const char *method);
struct ws_route router_ws_find(struct router *router, const char *route);
struct job_route router_job_find(struct router *router, const char *module_name, const char *job_name);
void router_job_release(struct router *router, struct module_ref *ref, struct cweb_context *ctx);
int router_gateway_json(struct router *router, http_response_t *res);
void* router_resolve(struct router *router, const char* module, const char* symbol);

int router_mgnt_parse_request(struct router *router, struct cweb_context *ctx, http_request_t *req, http_response_t *res);

#endif // ROUTER_H
