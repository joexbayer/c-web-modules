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
    /* Check if routes .so file is already loaded */
    for (int i = 0; i < route_count; i++) {
        if (strcmp(routes[i].so_path, so_path) == 0 && routes[i].loaded) {
            r->handle = routes[i].handle;
            r->handler = (handler_t)dlsym(r->handle, func);
            if (!r->handler) {
                fprintf(stderr, "Error finding existing function '%s': %s\n", func, dlerror());
                dlclose(r->handle);
                return -1;
            }
            printf("Route '%s' already loaded.\n", r->route);
            return 0;
        }
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

static int update_route(struct route *r, const char *so_path, const char *func) {
    pthread_mutex_lock(&r->mutex);

    /* Unload all routes to depdent on current .so file */
    for (int i = 0; i < route_count; i++) {
        if (strcmp(routes[i].so_path, so_path) == 0) {
            pthread_mutex_lock(&routes[i].mutex);
            routes[i].loaded = 0;
            dlclose(routes[i].handle);
            pthread_mutex_unlock(&routes[i].mutex);
        }
    }
    r->loaded = 0;
    
    dlclose(r->handle);
    strncpy(r->so_path, so_path, sizeof(r->so_path));
    if (load_shared_object(r, so_path, func) == 0) {
        printf("Route '%s' overwritten successfully.\n", r->route);
        pthread_mutex_unlock(&r->mutex);
        return 0;
    }

    pthread_mutex_unlock(&r->mutex);
    return -1;
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
    pthread_mutex_init(&routes[route_count].mutex, NULL);

    if (load_shared_object(&routes[route_count], so_path, func) == 0) {
        route_count++;
        printf("Route '%s' registered successfully.\n", route);
        return 0;
    }
    return -1;
}

static int load_routes_from_disk(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file for reading");
        return -1;
    }

    struct route_disk_header header;
    if (fread(&header, sizeof(header), 1, file) != 1) {
        perror("Error reading header from file");
        fclose(file);
        return -1;
    }

    if (strcmp(header.magic, "RTS") != 0) {
        fprintf(stderr, "Invalid file format\n");
        fclose(file);
        return -1;
    }

    for (int i = 0; i < header.count; i++) {
        struct route_disk rd;
        if (fread(&rd, sizeof(rd), 1, file) != 1) {
            perror("Error reading route from file");
            fclose(file);
            return -1;
        }
        add_route(rd.route, rd.so_path, rd.func, rd.method);
    }

    fclose(file);
    return 0;
}

static int save_routes_to_disk(const char *filename) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Error opening file for writing");
        return -1;
    }

    struct route_disk_header header = { "RTS", route_count };
    if (fwrite(&header, sizeof(header), 1, file) != 1) {
        perror("Error writing header to file");
        fclose(file);
        return -1;
    }

    for (int i = 0; i < route_count; i++) {
        struct route_disk rd;
        strncpy(rd.route, routes[i].route, sizeof(rd.route));
        strncpy(rd.so_path, routes[i].so_path, sizeof(rd.so_path));
        strncpy(rd.func, routes[i].func, sizeof(rd.func));
        strncpy(rd.method, routes[i].method, sizeof(rd.method));

        if (fwrite(&rd, sizeof(rd), 1, file) != 1) {
            perror("Error writing route to file");
            fclose(file);
            return -1;
        }
    }

    fclose(file);
    return 0;
}

int route_register(const char *route, const char *so_path, const char *func, const char *method) {
    struct route *r = route_find(route, method);
    if (r) {
        return update_route(r, so_path, func);
    }

    int ret = add_route(route, so_path, func, method);
    save_routes_to_disk("routes.dat");
    return ret;
}

void route_cleanup() {
    for (int i = 0; i < route_count; i++) {
        dlclose(routes[i].handle);
        unlink(routes[i].so_path);
    }
}

void route_init() {
    load_routes_from_disk("routes.dat");
}   