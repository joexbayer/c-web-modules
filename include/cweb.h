#ifndef CWEB_H
#define CWEB_H

#include <http.h>
#include "uuid.h"
#include <cweb_config.h>
#include <container.h>
#include <scheduler.h>
#include <db.h>
#include <crypto.h>
#include <regex.h>

/* Third party json parser */
#include <jansson.h>

/* Macro to export a module_t configuration */
#define export __attribute__((visibility("default")))

struct symbols {
    void *user_data;
    void* (*resolv)(void *user_data, const char* module, const char* symbol);
};

struct job_system;

typedef int (*jobs_create_fn_t)(void *user_data,
    const char *job_name,
    const char *payload_json,
    uuid_t *job_uuid_out);

typedef struct cweb_context {
    struct container *cache;
    struct scheduler *scheduler;
    struct sqldb *database;
    struct crypto *crypto;
    struct symbols *symbols;
    struct job_system *jobs;
} cweb_context_t;

typedef int (*entry_t)(struct cweb_context *, http_request_t *, http_response_t *);
typedef enum {
    NONE = 0,
} cweb_feature_flag_t;

/* Websocket information */
typedef struct ws_info {
    const char *path;
    void (*on_open)(struct cweb_context *, websocket_t *);
    void (*on_message)(struct cweb_context *, websocket_t *, const char *message, size_t length);
    void (*on_close)(struct cweb_context *, websocket_t *);
} websocket_info_t;

typedef struct job_payload {
    const char *json;
    size_t json_len;
} job_payload_t;

typedef struct job_ctx {
    const char *job_uuid;
    int (*emit_event)(struct job_ctx *job, const char *type, const char *data_json);
    int (*set_result)(struct job_ctx *job, const char *result_json);
    int (*set_error)(struct job_ctx *job, const char *error_text);
} job_ctx_t;

typedef int (*job_run_t)(struct cweb_context *ctx, const job_payload_t *payload, job_ctx_t *job);

typedef struct job_info {
    const char *name;
    job_run_t run;
    void (*cancel)(struct cweb_context *ctx, const char *job_uuid);
} job_info_t;

/* Route information */
typedef struct route_info {
    const char *path;
    const char *method;
    entry_t handler;
    int flags;
    regex_t regex;
    int regex_compiled;
} route_info_t;

/* Module information */
typedef struct module {
    char name[128];
    char author[128];
    route_info_t routes[MAX_ROUTES];
    int size;
    websocket_info_t websockets[MAX_WEBSOCKETS];
    int ws_size;
    job_info_t jobs[MAX_JOBS];
    int job_size;
    
    void (*onload)(struct cweb_context *);
    void (*unload)(struct cweb_context *);
} module_t;

void jobs_bind(jobs_create_fn_t fn, void *user_data);
int jobs_create(const char *job_name, const char *payload_json, uuid_t *job_uuid_out);

#endif // CWEB_H
