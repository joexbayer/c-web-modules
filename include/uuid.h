#ifndef UUID_H
#define UUID_H

#include <stddef.h>

#define UUID_STR_LEN 37

typedef struct uuid {
    char str[UUID_STR_LEN];
} uuid_t;

void uuid_clear(uuid_t *uuid);
int uuid_from_string(uuid_t *uuid, const char *str);
int uuid_is_valid(const uuid_t *uuid);
int uuid_equal(const uuid_t *a, const uuid_t *b);
const char *uuid_c_str(const uuid_t *uuid);

#endif // UUID_H
