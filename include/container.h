#ifndef CONTAINER_H
#define CONTAINER_H

#include <map.h>
#include <pthread.h>

/* Container key value structure */
struct container {
    struct map *data;
    pthread_mutex_t mutex;
};

int container_init(struct container *container, size_t initial_capacity);
void container_shutdown(struct container *container);
map_error_t container_set(struct container *container, const char *name, void *value);
void *container_get(struct container *container, const char *name);
map_error_t container_remove(struct container *container, const char *name);

#endif // CONTAINER_H
