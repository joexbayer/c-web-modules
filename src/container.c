#include <stdio.h>
#include <container.h>
#include <map.h>

int container_init(struct container *container, size_t initial_capacity) {
    if (!container) {
        return -1;
    }

    container->data = map_create(initial_capacity);
    if (!container->data) {
        return -1;
    }

    if (pthread_mutex_init(&container->mutex, NULL) != 0) {
        map_destroy(container->data);
        container->data = NULL;
        return -1;
    }

    printf("[STARTUP] Container initialized\n");
    return 0;
}

void container_shutdown(struct container *container) {
    if (!container) {
        return;
    }

    pthread_mutex_destroy(&container->mutex);
    map_destroy(container->data);
    container->data = NULL;
    printf("[SHUTDOWN] Container destroyed\n");
}

map_error_t container_set(struct container *container, const char *name, void *value) {
    if (!container || !name || !value) {
        return MAP_ERR;
    }

    pthread_mutex_lock(&container->mutex);
    map_error_t result = map_insert(container->data, name, value);
    pthread_mutex_unlock(&container->mutex);
    return result;
}

void *container_get(struct container *container, const char *name) {
    if (!container || !name) {
        return NULL;
    }

    pthread_mutex_lock(&container->mutex);
    void *result = map_get(container->data, name);
    pthread_mutex_unlock(&container->mutex);
    return result;
}

map_error_t container_remove(struct container *container, const char *name) {
    if (!container || !name) {
        return MAP_ERR;
    }

    pthread_mutex_lock(&container->mutex);
    map_error_t result = map_remove(container->data, name);
    pthread_mutex_unlock(&container->mutex);
    return result;
}
