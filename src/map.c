#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "map.h"

struct map *map_create(size_t initial_capacity) {
    if (initial_capacity <= 0)
        return NULL;

    struct map *m = malloc(sizeof(struct map));
    if (!m)
    return NULL;

    m->entries = malloc(initial_capacity * sizeof(struct map_entry));
    if (!m->entries) {
        free(m);
        return NULL;
    }

    m->size = 0;
    m->capacity = initial_capacity;
    return m;
}

void map_destroy(struct map *map) {
    if (!map)
        return;
    
    for (size_t i = 0; i < map->size; ++i) {
        free(map->entries[i].key);
    }

    free(map->entries);
    free(map);
}

int map_insert(struct map *map, const char *key, void *value) {
    if (!map)
        return -MAP_ERR;

    if (map->size >= map->capacity) {
        return -MAP_ERR; // No reallocation, return error if capacity is exceeded
    }

    for (size_t i = 0; i < map->size; ++i) {
        if (strcmp(map->entries[i].key, key) == 0) {
            return 0;
        }
    }

    map->entries[map->size].key = strdup(key);
    if (!map->entries[map->size].key)
        return -MAP_ERR;

    map->entries[map->size].value = value;
    map->size++;
    return 0;
}

void *map_get(const struct map *map, const char *key) {
    for (size_t i = 0; i < map->size; ++i) {
        if (strcmp(map->entries[i].key, key) == 0) {
            return map->entries[i].value;
        }
    }
    return NULL;
}

int map_remove(struct map *map, const char *key) {
    for (size_t i = 0; i < map->size; ++i) {
        if (strcmp(map->entries[i].key, key) == 0) {
            free(map->entries[i].key);
            map->entries[i] = map->entries[map->size - 1];
            map->size--;
            return 0;
        }
    }
    return -MAP_KEY_NOT_FOUND;
}

size_t map_size(const struct map *map) {
    return map->size;
}