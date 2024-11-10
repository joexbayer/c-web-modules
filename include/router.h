#ifndef ROUTER_H
#define ROUTER_H

// Include necessary standard libraries
#include <stdio.h>
#include <stdlib.h>

#define ROUTE_SIZE 100
#define ROUTE_COUNT 100

struct route {
    char route[ROUTE_SIZE];
    char so_path[256];
    char func[100];
    void *handle;
    void (*handler)(struct http_request *, struct http_response *);
};

int route_register(const char *route, const char *so_path, const char *func);
struct route* route_find(const char *route);

#endif // ROUTER_H