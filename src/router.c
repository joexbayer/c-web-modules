#include "http.h"
#include "cweb.h"
#include "router.h"
#include <dlfcn.h>

struct route routes[100];
int route_count = 0;

struct route* route_find(const char *route) {
    for (int i = 0; i < route_count; i++) {
        if (strcmp(routes[i].route, route) == 0) {
            return &routes[i];
        }
    }
    return NULL;
}

static int load_shared_object(struct route *r, const char *so_path, const char *func) {
    dbgprint("Loading shared object: %s\n", so_path);
    r->handle = dlopen(so_path, RTLD_LAZY);
    if (!r->handle) {
        fprintf(stderr, "Error loading shared object: %s\n", dlerror());
        return -1;
    }
    r->handler = (void (*)(struct http_request *, struct http_response *))dlsym(r->handle, func);
    if (!r->handler) {
        fprintf(stderr, "Error finding function '%s': %s\n", func, dlerror());
        dlclose(r->handle);
        return -1;
    }
    return 0;
}

static void update_route(struct route *r, const char *so_path, const char *func) {
    dlclose(r->handle);
    strncpy(r->so_path, so_path, sizeof(r->so_path));
    if (load_shared_object(r, so_path, func) == 0) {
        printf("Route '%s' overwritten successfully.\n", r->route);
    }
}

static int add_route(const char *route, const char *so_path, const char *func) {
    if (route_count >= ROUTE_COUNT) {
        fprintf(stderr, "Route limit reached\n");
        return -1;
    }

    strncpy(routes[route_count].route, route, sizeof(routes[route_count].route));
    strncpy(routes[route_count].so_path, so_path, sizeof(routes[route_count].so_path));
    strncpy(routes[route_count].func, func, sizeof(routes[route_count].func));

    if (load_shared_object(&routes[route_count], so_path, func) == 0) {
        route_count++;
        printf("Route '%s' registered successfully.\n", route);
        return 0;
    }
    return -1;
}

int route_register(const char *route, const char *so_path, const char *func) {
    struct route *r = route_find(route);
    if (r) {
        update_route(r, so_path, func);
        return 0;
    }
    return add_route(route, so_path, func);
}


void route_cleanup() {
    for (int i = 0; i < route_count; i++) {
        dlclose(routes[i].handle);
        unlink(routes[i].so_path);
    }
}
