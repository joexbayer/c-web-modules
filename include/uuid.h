#ifndef UUID_H
#define UUID_H

#include <stddef.h>

#define UUID_STR_LEN 37

typedef struct cweb_uuid {
    char str[UUID_STR_LEN];
} cweb_uuid_t;

void uuid_clear(cweb_uuid_t *uuid);
int uuid_from_string(cweb_uuid_t *uuid, const char *str);
int uuid_is_valid(const cweb_uuid_t *uuid);
int uuid_equal(const cweb_uuid_t *a, const cweb_uuid_t *b);
const char *uuid_c_str(const cweb_uuid_t *uuid);

#endif // UUID_H
