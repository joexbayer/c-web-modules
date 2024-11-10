#ifndef MAP_H
#define MAP_H

#include <stdint.h>

typedef enum map_error {
    MAP_OK = 0,
    MAP_ERR = 1,
    MAP_FULL = 2,
    MAP_KEY_NOT_FOUND = 3,
} map_error_t;

struct map {
    struct map_entry {
        char *key;
        void *value;
    } *entries;
    size_t size;
    size_t capacity;
};

struct map *map_create(size_t initial_capacity);
void map_destroy(struct map *map);
int map_insert(struct map *map, const char *key, void *value);
void *map_get(const struct map *map, const char *key);
int map_remove(struct map *map, const char *key);
size_t map_size(const struct map *map);

#endif // MAP_H