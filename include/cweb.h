#ifndef CWEB_H
#define CWEB_H

#include <http.h>
#include <map.h>

/* Macro to export a module_t configuration */
#define export __attribute__((visibility("default"))) 

typedef int (*entry_t)(struct http_request *, struct http_response *);
typedef enum {
    FEATURE_FLAG_NONE = 0,
} cweb_feature_flag_t;

/* Route information */
typedef struct route_info {
    const char *path;
    const char *method;
    entry_t handler;
    int flags;
    /* Used by the module handler */
    int loaded;
} route_info_t;

/* Module information */
typedef struct module {
    char name[128];
    char author[128];
    route_info_t routes[10];
    int size;
} module_t;

#endif // CWEB_H