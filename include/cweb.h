#ifndef CWEB_H
#define CWEB_H

#include <http.h>
#include <map.h>

typedef void (*entry_t)(struct http_request *, struct http_response *);

typedef struct route_info {
    const char *path;
    const char *method;
    int (*handler)(struct http_request *req, struct http_response *res);
} route_info_t;

typedef struct routes {
    route_info_t routes;
    size_t size;
} routes_t;


#endif // CWEB_H