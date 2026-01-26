#ifndef MAP_H
#define MAP_H

#include <stdint.h>
#include <stddef.h>

typedef enum map_error {
    MAP_OK = 0,
    MAP_ERR = 1,
    MAP_FULL = 2,
    MAP_KEY_NOT_FOUND = 3,
} map_error_t;

typedef enum map_entry_state {
    MAP_ENTRY_EMPTY = 0,
    MAP_ENTRY_OCCUPIED = 1,
    MAP_ENTRY_TOMBSTONE = 2,
} map_entry_state_t;

struct map_entry {
    char *key;
    void *value;
    uint64_t hash;
    map_entry_state_t state;
};

struct map {
    struct map_entry *entries;
    size_t size;
    size_t capacity;
    size_t tombstones;
};

struct map *map_create(size_t initial_capacity);
void map_destroy(struct map *map);
map_error_t map_insert(struct map *map, const char *key, void *value);
void *map_get(const struct map *map, const char *key);
map_error_t map_remove(struct map *map, const char *key);
size_t map_size(const struct map *map);

#endif // MAP_H
