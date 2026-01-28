#ifndef JOBS_H
#define JOBS_H

#include <cweb.h>
#include <pthread.h>
#include <db.h>
#include <router.h>
#include <scheduler.h>
#include <ws.h>
#include <map.h>

typedef struct job_system {
    struct sqldb *db;
    struct scheduler *scheduler;
    struct router *router;
    struct ws_server *ws;
    struct map *subscribers;
    pthread_mutex_t subscribers_mutex;
    struct map *job_registry;
    pthread_mutex_t job_registry_mutex;
    websocket_info_t ws_info;
} job_system_t;

int jobs_init(job_system_t *jobs, struct cweb_context *ctx, struct router *router, struct ws_server *ws);
void jobs_shutdown(job_system_t *jobs);
int jobs_handle_http(job_system_t *jobs, struct cweb_context *ctx, http_request_t *req, http_response_t *res);
const websocket_info_t *jobs_ws_info(job_system_t *jobs);
int jobs_register_module(job_system_t *jobs, struct module_ref *ref);
void jobs_unregister_module(job_system_t *jobs, struct module_ref *ref);
int jobs_create_impl(void *user_data,
    const char *job_name,
    const char *payload_json,
    uuid_t *job_uuid_out);

#endif // JOBS_H
