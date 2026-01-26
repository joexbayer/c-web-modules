#ifndef CWEB_H
#define CWEB_H

#include <http.h>
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

typedef struct cweb_context {
    struct container *cache;
    struct scheduler *scheduler;
    struct sqldb *database;
    struct crypto *crypto;
    struct symbols *symbols;
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
    route_info_t routes[10];
    int size;
    websocket_info_t websockets[10];
    int ws_size;
    
    void (*onload)(struct cweb_context *);
    void (*unload)(struct cweb_context *);
} module_t;

#endif // CWEB_H
