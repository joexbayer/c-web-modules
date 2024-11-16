#include <stdio.h>
#include <container.h>
#include <map.h>
#include <pthread.h>

/* Container functions */
static int container_set(const char *name, void* value);
static void* container_get(const char *name);

/* Main internal container */
static struct container internal_container = {
    .set = container_set,
    .get = container_get,
    .data = NULL,
};
__attribute__((visibility("default"))) struct container* exposed_container = &internal_container;
static pthread_mutex_t container_mutex = PTHREAD_MUTEX_INITIALIZER;

static int container_set(const char *name, void* value) {
    if (name == NULL || value == NULL) return -1;
    pthread_mutex_lock(&container_mutex);
    int result = map_insert(internal_container.data, name, value);
    pthread_mutex_unlock(&container_mutex);
    return result;
}

static void* container_get(const char *name) { 
    /* map_get handles input validation */
    pthread_mutex_lock(&container_mutex);
    void* result = map_get(internal_container.data, name);
    pthread_mutex_unlock(&container_mutex);    
    return result;
}

__attribute__((constructor)) static void container_init() {
    internal_container.data = map_create(32);
    printf("[STARTUP] Container initialized\n");
}

__attribute__((destructor)) static void container_destroy() {
    map_destroy(internal_container.data);
    printf("[SHUTDOWN] Container destroyed\n");
}

