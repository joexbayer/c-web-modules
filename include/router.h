#ifndef ROUTER_H
#define ROUTER_H

// Include necessary standard libraries
#include <stdio.h>
#include <stdlib.h>

#define ROUTE_SIZE 100
#define ROUTE_COUNT 100
typedef void (*handler_t)(struct http_request *, struct http_response *);

struct route {
    char route[ROUTE_SIZE];
    char so_path[256];
    char func[100];
    char method[10];
    void *handle;
    handler_t handler;
    int loaded;
};

int route_register(const char *route, const char *so_path, const char *func, const char *method);
struct route* route_find(const char *route, const char *method);    

/* TODO: Move... */
int mgnt_register_route(char* route, char* code, char* func_name, char* method);
int mgnt_parse_request(struct http_request *req);
void safe_execute_handler(handler_t handler, struct http_request *req, struct http_response *res);


#define dbgprint(fmt, ...) \
    do { fprintf(stderr, fmt, __VA_ARGS__); } while (0)


#endif // ROUTER_H