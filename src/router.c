#include "http.h"
#include "cweb.h"
#include "router.h"
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include <container.h>

#define MODULE_TAG "config"
#define ROUTE_FILE "modules/routes.dat"

struct route_disk_header {
    char magic[5];
    int count;
};
pthread_mutex_t save_mutex = PTHREAD_MUTEX_INITIALIZER;

struct gateway {
    struct gateway_entry entries[100];
    int count;
} gateway = {0};

static int route_save_to_disk(char* filename);
static int route_load_from_disk(char* filename);

struct route route_find(char *route, char *method) {
    for (int i = 0; i < gateway.count; i++) {

        pthread_rwlock_rdlock(&gateway.entries[i].rwlock);
        for (int j = 0; j < gateway.entries[i].module->size; j++) {
            if (strcmp(gateway.entries[i].module->routes[j].path, route) == 0 &&
                strcmp(gateway.entries[i].module->routes[j].method, method) == 0) {
                /* Caller is responsible for unlocking the read lock! */
                return (struct route){
                    .route = &gateway.entries[i].module->routes[j],
                    .rwlock = &gateway.entries[i].rwlock
                };
            }
        }
        pthread_rwlock_unlock(&gateway.entries[i].rwlock);
    }
    return (struct route){0};
}

static int update_gateway_entry(int index, char* so_path, struct module* routes, void* handle) {
    pthread_rwlock_wrlock(&gateway.entries[index].rwlock);

    if (gateway.entries[index].handle)
        dlclose(gateway.entries[index].handle);

    gateway.entries[index].handle = handle;
    memset(gateway.entries[index].so_path, 0, SO_PATH_MAX_LEN);
    strncpy(gateway.entries[index].so_path, so_path, SO_PATH_MAX_LEN); 
    gateway.entries[index].module = routes;

    pthread_rwlock_unlock(&gateway.entries[index].rwlock);

    route_save_to_disk(ROUTE_FILE);
    return 0;
}
static void* load_shared_object(char* so_path){
    void* handle = dlopen(so_path, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "Error loading shared object: %s\n", dlerror());
        return NULL;
    }
    return handle;
}

static int load_from_shared_object(char* so_path){
    void* handle = load_shared_object(so_path);
    if (!handle) {
        return -1;
    }

    struct module* module = dlsym(handle, MODULE_TAG);
    if (!module || module->size == 0 || strnlen(module->name, 128) == 0) {
        fprintf(stderr, "Error finding module definition: %s\n", dlerror());
        dlclose(handle);
        return -1;
    }

    /* Check if gateway is full */
    if (gateway.count >= 100) {
        fprintf(stderr, "Gateway is full\n");
        dlclose(handle);
        return -1;
    }

    /* Check if module already exists */
    for (int i = 0; i < gateway.count; i++) {
        if (strcmp(gateway.entries[i].module->name, module->name) == 0) {
            /* Update existing entry, if so_path differ */
            if(strcmp(gateway.entries[i].so_path, so_path) == 0) {
                return 0;
            }

            printf("[INFO   ] Module %s is updated.\n", module->name);
            return update_gateway_entry(i, so_path, module, handle);
        }
    }

    pthread_rwlock_init(&gateway.entries[gateway.count].rwlock, NULL);
    update_gateway_entry(gateway.count, so_path, module, handle);
    gateway.count++;

    printf("[INFO   ] Module %s is loaded.\n", module->name);
    route_save_to_disk(ROUTE_FILE);

    return 0;
}

int route_register_module(char* so_path) {
    return load_from_shared_object(so_path);
}

void route_cleanup() {
    for (int i = 0; i < gateway.count; i++) {
        pthread_rwlock_wrlock(&gateway.entries[i].rwlock);
        dlclose(gateway.entries[i].handle);
        pthread_rwlock_unlock(&gateway.entries[i].rwlock);
    }
}

static int route_save_to_disk(char* filename) {
    pthread_mutex_lock(&save_mutex);

    FILE *fp = fopen(filename, "wb");
    if (fp == NULL) {
        perror("Error creating route file");
        return -1;
    }

    struct route_disk_header header = {
        .magic = "CWEB",
        .count = gateway.count
    };
    fwrite(&header, sizeof(struct route_disk_header), 1, fp);

    for (int i = 0; i < gateway.count; i++) {
        fwrite(gateway.entries[i].so_path, SO_PATH_MAX_LEN, 1, fp);
    }

    fclose(fp);
    pthread_mutex_unlock(&save_mutex);
    return 0;
}

static int route_load_from_disk(char* filename) {
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        perror("Error opening route file");
        return -1;
    }

    struct route_disk_header header;
    fread(&header, sizeof(struct route_disk_header), 1, fp);
    if(strcmp(header.magic, "CWEB") != 0) {
        fprintf(stderr, "Invalid route file\n");
        fclose(fp);
        return -1;
    }

    for (int i = 0; i < header.count; i++) {
        char so_path[SO_PATH_MAX_LEN];
        fread(so_path, SO_PATH_MAX_LEN, 1, fp);
        route_register_module(so_path);
    }

    fclose(fp);
    return 0;
}

__attribute__((constructor)) void route_init() {
    /* Load libmap.so dependency - Only needed for Linux, perhaps wrap in #ifdef */
    void *map_handle = dlopen("./libs/libmodule.so", RTLD_GLOBAL | RTLD_LAZY);
    if (!map_handle) {
        fprintf(stderr, "Error loading dependency libmap: %s\n", dlerror());
        return;
    }

    route_load_from_disk(ROUTE_FILE);

    printf("[STARTUP] Router initialized\n");
}

__attribute__((destructor)) void route_close() {
    route_save_to_disk(ROUTE_FILE);
    route_cleanup();
    printf("[SHUTDOWN] Router closed\n");
}