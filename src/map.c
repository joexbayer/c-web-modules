#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include "map.h"

/* Create a new map with shared memory allocation */
struct map *map_create(size_t initial_capacity) {
    if (initial_capacity <= 0)
        return NULL;

    /* Allocate memory for the map structure */
    struct map *m = malloc(sizeof(struct map));
    if (!m)
        return NULL;

    /* Allocate memory for the entries array */
    m->entries = malloc(initial_capacity * sizeof(struct map_entry));
    if (!m->entries) {
        free(m);
        return NULL;
    }

    m->size = 0;
    m->capacity = initial_capacity;
    return m;
}

/* Destroy the map and free shared memory */
void map_destroy(struct map *map) {
    if (!map)
        return;
    
    /* Free each key's shared memory */
    for (size_t i = 0; i < map->size; ++i) {
        if (map->entries[i].key) {
            free(map->entries[i].key);
        }
    }

    /* Free the entries array and the map structure */
    free(map->entries);
    free(map);
}

/* Insert a key-value pair into the map using shared memory for the key */
int map_insert(struct map *map, const char *key, void *value) {
    if (!map)
        return -MAP_ERR;

    /* Check if capacity is exceeded */
    if (map->size >= map->capacity) {
        return -MAP_ERR;
    }

    /* Check for existing key to avoid duplicates */
    for (size_t i = 0; i < map->size; ++i) {
        if (strcmp(map->entries[i].key, key) == 0) {
            return 0; // Key already exists, no insertion
        }
    }

    /* Allocate shared memory for the key string */
    size_t key_len = strlen(key) + 1;
    map->entries[map->size].key = malloc(key_len);
    if (!map->entries[map->size].key) {
        return -MAP_ERR;
    }

    /* Copy the key into shared memory */
    strncpy(map->entries[map->size].key, key, key_len);

    /* Assign the value and increment the size */
    map->entries[map->size].value = value;
    map->size++;
    return 0;
}

/* Retrieve a value from the map by key */
void *map_get(const struct map *map, const char *key) {
    if (!map) return NULL;

    for (size_t i = 0; i < map->size; ++i) {
        if (strcmp(map->entries[i].key, key) == 0) {
            return map->entries[i].value;
        }
    }
    return NULL;
}

/* Remove a key-value pair from the map */
int map_remove(struct map *map, const char *key) {
    for (size_t i = 0; i < map->size; ++i) {
        if (strcmp(map->entries[i].key, key) == 0) {
            /* Free the shared memory for the key */
            free(map->entries[i].key);

            /* Move the last entry to the current position to fill the gap */
            map->entries[i] = map->entries[map->size - 1];
            map->size--;
            return 0;
        }
    }
    return -MAP_KEY_NOT_FOUND;
}

/* Get the number of entries in the map */
size_t map_size(const struct map *map) {
    return map->size;
}