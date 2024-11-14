#ifndef CONTAINER_H
#define CONTAINER_H

#include <stdint.h>
#include <map.h>

/* Container key value structure */
struct container {
    int (*set)(const char *name, void* value);
    void* (*get)(const char *name);
    struct map *data;
};

#endif // CONTAINER_H