#include "uuid.h"

#include <ctype.h>
#include <string.h>

static int uuid_is_hex(char ch) {
    return isxdigit((unsigned char)ch) ? 1 : 0;
}

static int uuid_is_valid_str(const char *str) {
    if (!str) {
        return 0;
    }
    if (strlen(str) != (UUID_STR_LEN - 1)) {
        return 0;
    }

    for (size_t i = 0; i < UUID_STR_LEN - 1; i++) {
        char ch = str[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (ch != '-') {
                return 0;
            }
        } else if (!uuid_is_hex(ch)) {
            return 0;
        }
    }

    return 1;
}

void uuid_clear(cweb_uuid_t *uuid) {
    if (!uuid) {
        return;
    }
    uuid->str[0] = '\0';
}

int uuid_from_string(cweb_uuid_t *uuid, const char *str) {
    if (!uuid || !str) {
        return -1;
    }
    if (!uuid_is_valid_str(str)) {
        return -1;
    }
    memcpy(uuid->str, str, UUID_STR_LEN - 1);
    uuid->str[UUID_STR_LEN - 1] = '\0';
    return 0;
}

int uuid_is_valid(const cweb_uuid_t *uuid) {
    if (!uuid) {
        return 0;
    }
    return uuid_is_valid_str(uuid->str);
}

int uuid_equal(const cweb_uuid_t *a, const cweb_uuid_t *b) {
    if (!a || !b) {
        return 0;
    }
    return strcmp(a->str, b->str) == 0;
}

const char *uuid_c_str(const cweb_uuid_t *uuid) {
    if (!uuid) {
        return "";
    }
    return uuid->str;
}
