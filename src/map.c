#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "map.h"

#define MAP_MIN_CAPACITY 8u
#define MAP_MAX_LOAD_NUM 7u
#define MAP_MAX_LOAD_DEN 10u

static size_t map_next_pow2(size_t value) {
    size_t cap = MAP_MIN_CAPACITY;
    while (cap < value) {
        cap <<= 1u;
    }
    return cap;
}

static uint64_t map_hash_key(const char *key) {
    const uint64_t fnv_offset = 1469598103934665603ULL;
    const uint64_t fnv_prime = 1099511628211ULL;
    uint64_t hash = fnv_offset;

    for (const unsigned char *p = (const unsigned char *)key; *p; ++p) {
        hash ^= (uint64_t)(*p);
        hash *= fnv_prime;
    }

    return hash;
}

static int map_should_grow(const struct map *map) {
    if (map->capacity == 0) {
        return 1;
    }
    size_t used = map->size + map->tombstones;
    return (used * MAP_MAX_LOAD_DEN) >= (map->capacity * MAP_MAX_LOAD_NUM);
}

static map_error_t map_rehash(struct map *map, size_t new_capacity) {
    struct map_entry *old_entries = map->entries;
    size_t old_capacity = map->capacity;

    struct map_entry *entries = calloc(new_capacity, sizeof(*entries));
    if (!entries) {
        return MAP_ERR;
    }

    map->entries = entries;
    map->capacity = new_capacity;
    map->size = 0;
    map->tombstones = 0;

    for (size_t i = 0; i < old_capacity; i++) {
        struct map_entry *entry = &old_entries[i];
        if (entry->state != MAP_ENTRY_OCCUPIED) {
            continue;
        }

        size_t mask = map->capacity - 1u;
        size_t first_tombstone = SIZE_MAX;
        for (size_t probe = 0; probe < map->capacity; ++probe) {
            size_t idx = (entry->hash + probe) & mask;
            struct map_entry *target = &map->entries[idx];

            if (target->state == MAP_ENTRY_EMPTY) {
                size_t insert_idx = (first_tombstone != SIZE_MAX) ? first_tombstone : idx;
                struct map_entry *insert_entry = &map->entries[insert_idx];
                *insert_entry = *entry;
                insert_entry->state = MAP_ENTRY_OCCUPIED;
                map->size++;
                if (first_tombstone != SIZE_MAX) {
                    map->tombstones--;
                }
                break;
            }

            if (target->state == MAP_ENTRY_TOMBSTONE && first_tombstone == SIZE_MAX) {
                first_tombstone = idx;
            }
        }
    }

    free(old_entries);
    return MAP_OK;
}

struct map *map_create(size_t initial_capacity) {
    if (initial_capacity == 0) {
        return NULL;
    }

    struct map *map = malloc(sizeof(*map));
    if (!map) {
        return NULL;
    }

    size_t capacity = map_next_pow2(initial_capacity);
    map->entries = calloc(capacity, sizeof(*map->entries));
    if (!map->entries) {
        free(map);
        return NULL;
    }

    map->size = 0;
    map->capacity = capacity;
    map->tombstones = 0;

    return map;
}

void map_destroy(struct map *map) {
    if (!map) {
        return;
    }

    if (map->entries) {
        for (size_t i = 0; i < map->capacity; ++i) {
            if (map->entries[i].state == MAP_ENTRY_OCCUPIED) {
                free(map->entries[i].key);
            }
        }
        free(map->entries);
    }

    free(map);
}

map_error_t map_insert(struct map *map, const char *key, void *value) {
    if (!map || !key) {
        return MAP_ERR;
    }

    if (map_should_grow(map)) {
        map_error_t ret = map_rehash(map, map->capacity ? map->capacity << 1u : MAP_MIN_CAPACITY);
        if (ret != MAP_OK) {
            return ret;
        }
    }

    uint64_t hash = map_hash_key(key);
    size_t mask = map->capacity - 1u;
    size_t first_tombstone = SIZE_MAX;

    for (size_t i = 0; i < map->capacity; ++i) {
        size_t idx = (hash + i) & mask;
        struct map_entry *entry = &map->entries[idx];

        if (entry->state == MAP_ENTRY_EMPTY) {
            size_t target = (first_tombstone != SIZE_MAX) ? first_tombstone : idx;
            struct map_entry *target_entry = &map->entries[target];
            target_entry->key = strdup(key);
            if (!target_entry->key) {
                return MAP_ERR;
            }
            target_entry->value = value;
            target_entry->hash = hash;
            target_entry->state = MAP_ENTRY_OCCUPIED;
            map->size++;
            if (first_tombstone != SIZE_MAX) {
                map->tombstones--;
            }
            return MAP_OK;
        }

        if (entry->state == MAP_ENTRY_TOMBSTONE) {
            if (first_tombstone == SIZE_MAX) {
                first_tombstone = idx;
            }
            continue;
        }

        if (entry->hash == hash && strcmp(entry->key, key) == 0) {
            entry->value = value;
            return MAP_OK;
        }
    }

    return MAP_FULL;
}

void *map_get(const struct map *map, const char *key) {
    if (!map || !key || map->capacity == 0) {
        return NULL;
    }

    uint64_t hash = map_hash_key(key);
    size_t mask = map->capacity - 1u;

    for (size_t i = 0; i < map->capacity; ++i) {
        size_t idx = (hash + i) & mask;
        const struct map_entry *entry = &map->entries[idx];

        if (entry->state == MAP_ENTRY_EMPTY) {
            return NULL;
        }

        if (entry->state == MAP_ENTRY_OCCUPIED && entry->hash == hash && strcmp(entry->key, key) == 0) {
            return entry->value;
        }
    }

    return NULL;
}

map_error_t map_remove(struct map *map, const char *key) {
    if (!map || !key || map->capacity == 0) {
        return MAP_ERR;
    }

    uint64_t hash = map_hash_key(key);
    size_t mask = map->capacity - 1u;

    for (size_t i = 0; i < map->capacity; ++i) {
        size_t idx = (hash + i) & mask;
        struct map_entry *entry = &map->entries[idx];

        if (entry->state == MAP_ENTRY_EMPTY) {
            return MAP_KEY_NOT_FOUND;
        }

        if (entry->state == MAP_ENTRY_OCCUPIED && entry->hash == hash && strcmp(entry->key, key) == 0) {
            free(entry->key);
            entry->key = NULL;
            entry->value = NULL;
            entry->state = MAP_ENTRY_TOMBSTONE;
            map->size--;
            map->tombstones++;
            return MAP_OK;
        }
    }

    return MAP_KEY_NOT_FOUND;
}

size_t map_size(const struct map *map) {
    if (!map) {
        return 0;
    }
    return map->size;
}
