#include "http.h"
#include "cweb.h"
#include "router.h"
#include <dlfcn.h>
#include <unistd.h>

struct route routes[100];
int route_count = 0;

struct route* route_find(const char *route, const char *method) {
    for (int i = 0; i < route_count; i++) {
        if (strcmp(routes[i].route, route) == 0 && strcmp(routes[i].method, method) == 0) {
            return &routes[i];
        }
    }
    return NULL;
}

static int load_shared_object(struct route *r, const char *so_path, const char *func) {
    for (int i = 0; i < route_count; i++) {
        if (strcmp(routes[i].so_path, so_path) == 0 && routes[i].loaded) {
            r->handle = routes[i].handle;
            r->handler = (void (*)(struct http_request *, struct http_response *))dlsym(r->handle, func);
            if (!r->handler) {
                fprintf(stderr, "Error finding existing function '%s': %s\n", func, dlerror());
                dlclose(r->handle);
                return -1;
            }
            printf("Route '%s' already loaded.\n", r->route);
            return 0;
        }
    }

    dbgprint("Loading shared object: %s\n", so_path);
    if (setenv("LD_LIBRARY_PATH", "./libs", 1) != 0) {
        fprintf(stderr, "Failed to set LD_LIBRARY_PATH\n");
        return -1;
    }

    /* Load libmap.so dependency - Only needed for Linux, perhaps wrap in #ifdef */
    void *map_handle = dlopen("./libs/libmap.so", RTLD_GLOBAL | RTLD_LAZY);
    if (!map_handle) {
        fprintf(stderr, "Error loading dependency libmap: %s\n", dlerror());
        return -1;
    }

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

    r->loaded = 1;

    return 0;
}

static void update_route(struct route *r, const char *so_path, const char *func) {
    for (int i = 0; i < route_count; i++) {
        if (strcmp(routes[i].so_path, so_path) == 0) {
            routes[i].loaded = 0;
        }
    }
    r->loaded = 0;
    dlclose(r->handle);
    strncpy(r->so_path, so_path, sizeof(r->so_path));
    if (load_shared_object(r, so_path, func) == 0) {
        printf("Route '%s' overwritten successfully.\n", r->route);
    }
}

static int add_route(const char *route, const char *so_path, const char *func, const char *method) {
    if (route_count >= ROUTE_COUNT) {
        fprintf(stderr, "Route limit reached\n");
        return -1;
    }

    strncpy(routes[route_count].route, route, sizeof(routes[route_count].route));
    strncpy(routes[route_count].so_path, so_path, sizeof(routes[route_count].so_path));
    strncpy(routes[route_count].func, func, sizeof(routes[route_count].func));
    strncpy(routes[route_count].method, method, sizeof(routes[route_count].method));
    
    routes[route_count].loaded = 0;

    if (load_shared_object(&routes[route_count], so_path, func) == 0) {
        route_count++;
        printf("Route '%s' registered successfully.\n", route);
        return 0;
    }
    return -1;
}

int route_register(const char *route, const char *so_path, const char *func, const char *method) {
    struct route *r = route_find(route, method);
    if (r) {
        update_route(r, so_path, func);
        return 0;
    }
    return add_route(route, so_path, func, method);
}

void route_cleanup() {
    for (int i = 0; i < route_count; i++) {
        dlclose(routes[i].handle);
        unlink(routes[i].so_path);
    }
}

int route_init(){
    
}