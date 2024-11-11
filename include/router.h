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

/* TODO: Move... */
int mgnt_register_route(char* route, char* code, char* func_name);
int mgnt_parse_request(struct http_request *req);
void safe_execute_handler(void (*handler)(struct http_request *req, struct http_response *res), struct http_request *req, struct http_response *res);

typedef void (*handler_t)(struct http_request *, struct http_response *);

#define dbgprint(fmt, ...) \
    do { fprintf(stderr, fmt, __VA_ARGS__); } while (0)


#endif // ROUTER_H