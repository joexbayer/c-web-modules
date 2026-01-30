#include "http.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

static int http_hex_value(char c);
static int http_token_equals(const char *token, size_t token_len, const char *expected);
static int http_parse_transfer_encoding_value(const char *value, int *is_chunked, int *has_other);
static int http_header_has_token(const char *value, const char *token);
static const char *http_find_crlf(const char *buf, size_t len);
static const char *http_find_crlfcrlf(const char *buf, size_t len);
static int http_validate_trailer_fields(const char *trailers, size_t len);
static const char *http_find_char(const char *buf, size_t len, char c);

static char* http_strstr(const char *str, const char *substr) {
    const char *p = str;
    while (*p != '\0') {
        const char *p1 = p;
        const char *p2 = substr;
        while (*p1 != '\0' && *p2 != '\0' && *p1 == *p2) {
            p1++;
            p2++;
        }
        if (*p2 == '\0') {
            return (char *)p;
        }
        p++;
    }
    return NULL;
}

static char* http_strchr(const char *str, char c) {
    const char *begin = str;
    while (*str != '\0' && (str - begin) < 1024) {
        if (*str == c) {
            return (char *)str;
        }
        str++;
    }
    return NULL;
}

static int http_strcasecmp(const char *a, const char *b) {
    while (*a && *b) {
        int ca = tolower((unsigned char)*a);
        int cb = tolower((unsigned char)*b);
        if (ca != cb) {
            return ca - cb;
        }
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

static void http_str_to_lower(char *str) {
    if (!str) {
        return;
    }
    for (; *str != '\0'; str++) {
        *str = (char)tolower((unsigned char)*str);
    }
}

static char* http_strdup(const char *str) {
    if (!str) {
        return NULL;
    }
    
    int len = strlen(str);
    char *dup = malloc(len + 1);
    
    if (!dup) {
        printf("[ERROR] Failed to allocate memory for string duplication");
        return NULL;
    }
    
    strcpy(dup, str);
    return dup;
}

http_kv_store_t *http_kv_create(size_t initial_capacity) {
    if (initial_capacity == 0) {
        return NULL;
    }

    http_kv_store_t *store = malloc(sizeof(http_kv_store_t));
    if (!store) {
        return NULL;
    }

    store->entries = calloc(initial_capacity, sizeof(http_kv_pair_t));
    if (!store->entries) {
        free(store);
        return NULL;
    }

    store->size = 0;
    store->capacity = initial_capacity;
    return store;
}

void http_kv_destroy(http_kv_store_t *store, int free_values) {
    if (!store) {
        return;
    }

    for (size_t i = 0; i < store->size; ++i) {
        free(store->entries[i].key);
        if (free_values && store->entries[i].value) {
            free(store->entries[i].value);
        }
    }

    free(store->entries);
    free(store);
}

int http_kv_insert(http_kv_store_t *store, const char *key, char *value) {
    if (!store || !key) {
        return -1;
    }

    if (store->size >= store->capacity) {
        return -1;
    }

    for (size_t i = 0; i < store->size; ++i) {
        if (http_strcasecmp(store->entries[i].key, key) == 0) {
            return 0;
        }
    }

    char *dup_key = http_strdup(key);
    if (!dup_key) {
        return -1;
    }
    /* RFC 9110 §5.1: field names are case-insensitive. */
    http_str_to_lower(dup_key);

    store->entries[store->size].key = dup_key;
    store->entries[store->size].value = value;
    store->size++;
    return 0;
}

char *http_kv_get(const http_kv_store_t *store, const char *key) {
    if (!store || !key) {
        return NULL;
    }

    for (size_t i = 0; i < store->size; ++i) {
        if (http_strcasecmp(store->entries[i].key, key) == 0) {
            return store->entries[i].value;
        }
    }
    return NULL;
}

size_t http_kv_size(const http_kv_store_t *store) {
    return store ? store->size : 0;
}

/* Hypertext Transfer Protocol -- HTTP/1.1 Spec: RFC 9110 / RFC 9112 */
const char *http_methods[] = {"GET", "POST", "PUT", "DELETE", "OPTIONS"};
const char *http_errors[] = {
    "400 Bad Request", /* Unknown defaults to 400 */
    "101 Switching Protocols",
    "200 OK",
    "302 Found",
    "400 Bad Request", "401 Unauthorized", "403 Forbidden", "404 Not Found", "405 Method Not Allowed", "409 Conflict", "413 Payload Too Large", "414 URI Too Long",
    "426 Upgrade Required",
    "500 Internal Server Error",
    "501 Not Implemented"
};

/* Helper function to trim trailing whitespace */
static void trim_trailing_whitespace(char *str) {
    int len = strlen(str);
    while (len > 0 && (str[len - 1] == '\r' || str[len - 1] == '\n' || isspace((unsigned char)str[len - 1]))) {
        str[--len] = '\0';
    }
}

/* Parse HTTP method token (length-bounded) */
static int http_parse_method_token(const char *method, size_t len, http_request_t *req) {
    if (len == 3 && memcmp(method, "GET", 3) == 0) {
        req->method = HTTP_GET;
    } else if (len == 4 && memcmp(method, "POST", 4) == 0) {
        req->method = HTTP_POST;
    } else if (len == 3 && memcmp(method, "PUT", 3) == 0) {
        req->method = HTTP_PUT;
    } else if (len == 6 && memcmp(method, "DELETE", 6) == 0) {
        req->method = HTTP_DELETE;
    } else if (len == 7 && memcmp(method, "OPTIONS", 7) == 0) {
        req->method = HTTP_OPTIONS;
    } else {
        req->method = -1;
    }
    return req->method == -1 ? -1 : 0;
}

static int http_is_tchar(unsigned char c) {
    if (isalnum(c)) {
        return 1;
    }
    switch (c) {
        case '!':
        case '#':
        case '$':
        case '%':
        case '&':
        case '\'':
        case '*':
        case '+':
        case '-':
        case '.':
        case '^':
        case '_':
        case '`':
        case '|':
        case '~':
            return 1;
        default:
            return 0;
    }
}

static int http_header_name_invalid_range(const char *name, size_t len) {
    /* RFC 9110 §5.1: field-name is a token. */
    if (!name || len == 0) {
        return 1;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)name[i];
        if (!http_is_tchar(c)) {
            return 1;
        }
    }
    return 0;
}

static int http_header_name_invalid(const char *name) {
    return http_header_name_invalid_range(name, strlen(name));
}

static int http_header_value_invalid_range(const char *value, size_t len) {
    /* RFC 9110 §5.5: no CTL in field values. HTAB is allowed. */
    if (!value) {
        return 1;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)value[i];
        if ((c < 0x20 && c != '\t') || c == 0x7f) {
            return 1;
        }
    }
    return 0;
}

static int http_header_value_invalid(const char *value) {
    return http_header_value_invalid_range(value, strlen(value));
}

static const char *http_find_crlf(const char *buf, size_t len) {
    for (size_t i = 0; i + 1 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n') {
            return buf + i;
        }
    }
    return NULL;
}

static const char *http_find_char(const char *buf, size_t len, char c) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == c) {
            return buf + i;
        }
    }
    return NULL;
}

static const char *http_find_crlfcrlf(const char *buf, size_t len) {
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return buf + i;
        }
    }
    return NULL;
}

/* RFC 9112 §7.1: chunked transfer coding. */
int http_decode_chunked_body(const char *body, size_t body_len, char **out, size_t *out_len) {
    if (!body || !out || !out_len) {
        return -1;
    }

    char *decoded = malloc(body_len + 1);
    if (!decoded) {
        return -1;
    }

    size_t decoded_len = 0;
    size_t pos = 0;

    while (pos < body_len) {
        const char *line_end = http_find_crlf(body + pos, body_len - pos);
        if (!line_end) {
            free(decoded);
            return 1;
        }

        size_t line_len = (size_t)(line_end - (body + pos));
        if (line_len == 0) {
            free(decoded);
            return -1;
        }

        size_t chunk_size = 0;
        int saw_digit = 0;
        for (size_t i = 0; i < line_len; i++) {
            char c = body[pos + i];
            if (c == ';') {
                break;
            }
            if (c == ' ' || c == '\t') {
                continue;
            }
            int hex = http_hex_value(c);
            if (hex < 0) {
                free(decoded);
                return -1;
            }
            saw_digit = 1;
            if (chunk_size > (SIZE_MAX - (size_t)hex) / 16) {
                free(decoded);
                return -1;
            }
            chunk_size = chunk_size * 16 + (size_t)hex;
        }

        if (!saw_digit) {
            free(decoded);
            return -1;
        }

        pos += line_len + 2;
        if (chunk_size == 0) {
            const char *trail_end = http_find_crlfcrlf(body + pos, body_len - pos);
            if (!trail_end) {
                free(decoded);
                return 1;
            }
            if (http_validate_trailer_fields(body + pos, (size_t)(trail_end - (body + pos)) + 2) != 0) {
                free(decoded);
                return -1;
            }
            decoded[decoded_len] = '\0';
            *out = decoded;
            *out_len = decoded_len;
            return 0;
        }

        if (body_len - pos < chunk_size + 2) {
            free(decoded);
            return 1;
        }

        if (decoded_len + chunk_size > body_len) {
            free(decoded);
            return -1;
        }

        memcpy(decoded + decoded_len, body + pos, chunk_size);
        decoded_len += chunk_size;
        pos += chunk_size;

        if (body[pos] != '\r' || body[pos + 1] != '\n') {
            free(decoded);
            return -1;
        }
        pos += 2;
    }

    free(decoded);
    return 1;
}

/* Parses HTTP headers and puts them into headers map */
typedef struct http_header_parse_state {
    int content_length_seen;
    int content_length_value;
    int content_length_conflict;
    int host_seen;
    int host_conflict;
    int host_empty;
    int te_invalid;
} http_header_parse_state_t;

static int http_parse_content_length_list(const char *value, http_header_parse_state_t *state) {
    const char *p = value;

    if (http_header_value_invalid(value)) {
        return -1;
    }

    while (*p != '\0') {
        while (*p == ' ' || *p == '\t' || *p == ',') {
            p++;
        }
        if (*p == '\0') {
            break;
        }

        const char *token_start = p;
        while (*p != '\0' && *p != ',') {
            p++;
        }
        const char *token_end = p;
        while (token_end > token_start && (token_end[-1] == ' ' || token_end[-1] == '\t')) {
            token_end--;
        }

        if (token_end == token_start) {
            return -1;
        }

        unsigned long value_num = 0;
        for (const char *t = token_start; t < token_end; t++) {
            if (*t < '0' || *t > '9') {
                return -1;
            }
            if (value_num > (unsigned long)INT_MAX / 10) {
                return -1;
            }
            value_num = value_num * 10 + (unsigned long)(*t - '0');
            if (value_num > (unsigned long)INT_MAX) {
                return -1;
            }
        }

        if (!state->content_length_seen) {
            state->content_length_seen = 1;
            state->content_length_value = (int)value_num;
        } else if (state->content_length_value != (int)value_num) {
            state->content_length_conflict = 1;
        }
    }

    return 0;
}

static void http_trim_ows_range(const char **value, size_t *len) {
    const char *start = *value;
    const char *end = start + *len;
    while (start < end && (*start == ' ' || *start == '\t')) {
        start++;
    }
    while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
        end--;
    }
    *value = start;
    *len = (size_t)(end - start);
}

static int http_value_equals_case_insensitive(const char *a, size_t a_len, const char *b, size_t b_len) {
    if (a_len != b_len) {
        return 0;
    }
    for (size_t i = 0; i < a_len; i++) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) {
            return 0;
        }
    }
    return 1;
}

static int http_parse_te_header(const char *value) {
    const char *p = value;

    if (http_header_value_invalid(value)) {
        return -1;
    }

    while (*p != '\0') {
        while (*p == ' ' || *p == '\t' || *p == ',') {
            p++;
        }
        if (*p == '\0') {
            break;
        }

        const char *token_start = p;
        while (*p != '\0' && *p != ',') {
            p++;
        }
        const char *token_end = p;
        while (token_end > token_start && (token_end[-1] == ' ' || token_end[-1] == '\t')) {
            token_end--;
        }
        if (token_end == token_start) {
            return -1;
        }

        const char *semi = memchr(token_start, ';', (size_t)(token_end - token_start));
        if (semi != NULL) {
            return -1;
        }

        if (!http_value_equals_case_insensitive(token_start, (size_t)(token_end - token_start), "trailers", 8)) {
            return -1;
        }
    }

    return 0;
}

static int http_parse_headers(const char *headers, size_t headers_len, http_request_t *req, http_header_parse_state_t *state) {
    const char *line_start = headers;
    const char *headers_end = headers + headers_len;

    while (line_start < headers_end) {
        const char *line_end = http_find_crlf(line_start, (size_t)(headers_end - line_start));
        if (!line_end) {
            return -1;
        }

        size_t line_length = (size_t)(line_end - line_start);
        if (line_length == 0) {
            return -1;
        }

        char *line = malloc(line_length + 1);
        if (!line) {
            printf("[ERROR] Failed to allocate memory for header line");
            return -1;
        }
        memcpy(line, line_start, line_length);
        line[line_length] = '\0';

        /* RFC 9112 §5.1: obs-fold is invalid; reject header lines starting with SP/HTAB. */
        if (line[0] == ' ' || line[0] == '\t') {
            free(line);
            return -1;
        }

        char *colon = memchr(line, ':', line_length);
        if (!colon) {
            free(line);
            return -1;
        }

        *colon = '\0';
        char *key = line;
        char *value = colon + 1;
        if (http_header_name_invalid(key)) {
            free(line);
            return -1;
        }

        while (*value == ' ' || *value == '\t') {
            value++;
        }

        if (http_header_value_invalid(value)) {
            free(line);
            return -1;
        }

        if (http_strcasecmp(key, "Host") == 0) {
            const char *host_value = value;
            size_t host_len = strlen(host_value);
            http_trim_ows_range(&host_value, &host_len);
            if (host_len == 0) {
                state->host_empty = 1;
            } else if (!state->host_seen) {
                state->host_seen = 1;
                /* store first host value by letting it fall through */
            } else {
                char *existing = http_kv_get(req->headers, "Host");
                if (existing) {
                    const char *existing_trim = existing;
                    size_t existing_len = strlen(existing_trim);
                    http_trim_ows_range(&existing_trim, &existing_len);
                    if (!http_value_equals_case_insensitive(existing_trim, existing_len, host_value, host_len)) {
                        state->host_conflict = 1;
                    }
                } else {
                    state->host_conflict = 1;
                }
            }
        }

        if (http_strcasecmp(key, "Content-Length") == 0) {
            if (http_parse_content_length_list(value, state) != 0) {
                free(line);
                return -1;
            }
        }

        if (http_strcasecmp(key, "TE") == 0) {
            if (http_parse_te_header(value) != 0) {
                state->te_invalid = 1;
            }
        }

        if (http_kv_get(req->headers, key) != NULL) {
            free(line);
            continue;
        }

        char *k_value = http_strdup(value);
        if (!k_value) {
            printf("[ERROR] Failed to allocate memory for header key");
            free(line);
            return -1;
        }

        if (http_kv_insert(req->headers, key, k_value) != 0) {
            free(k_value);
            free(line);
            return -1;
        }

        free(line);

        line_start = line_end + 2;
    }

    return 0;
}

/* Parses query parameters and puts them into params map */
static void http_parse_params(const char *query, http_request_t *req) {
    const char *param_start = query;

    while (*param_start != '\0') {
        const char *param_end = http_strchr(param_start, '&');
        const char *key_end = http_strchr(param_start, '=');

        if (key_end && (!param_end || key_end < param_end)) {
            size_t key_length = key_end - param_start;
            size_t value_length = param_end ? (size_t)(param_end - key_end - 1) : strlen(key_end + 1);

            char *key = malloc(key_length + 1);
            char *value = malloc(value_length + 1);
            if (!key || !value) {
                printf("[ERROR] Failed to allocate memory for query parameters");
                free(key);
                free(value);
                return;
            }

            strncpy(key, param_start, key_length);
            key[key_length] = '\0';

            strncpy(value, key_end + 1, value_length);
            value[value_length] = '\0';

            http_kv_insert(req->params, key, value);
            
            free(key);
            param_start = param_end ? param_end + 1 : "";
        } else {
            break;
        }
    }
}



/* Mainly parses the header of the HTTP request (length-bounded) */
static void http_parse_request(const char *request, size_t request_len, http_request_t *req) {
    if (!request || request_len == 0) {
        req->method = -1;
        req->status = HTTP_400_BAD_REQUEST;
        return;
    }

    const char *line_end = http_find_crlf(request, request_len);
    if (!line_end) {
        req->method = -1;
        req->status = HTTP_400_BAD_REQUEST;
        return;
    }

    size_t line_len = (size_t)(line_end - request);
    const char *method_end = http_find_char(request, line_len, ' ');
    if (!method_end || method_end == request) {
        req->method = -1;
        req->status = HTTP_400_BAD_REQUEST;
        return;
    }

    const char *path_start = method_end + 1;
    if (path_start >= request || path_start >= request + line_len ||
        *path_start == ' ' || *path_start == '\t') {
        req->method = -1;
        req->status = HTTP_400_BAD_REQUEST;
        return;
    }

    size_t method_len = (size_t)(method_end - request);
    if (http_parse_method_token(request, method_len, req) != 0) {
        req->status = HTTP_400_BAD_REQUEST;
        req->method = -1;
        return;
    }

    const char *path_end = http_find_char(path_start, (size_t)(line_len - (size_t)(path_start - request)), ' ');
    if (!path_end || path_end == path_start) {
        req->method = -1;
        req->status = HTTP_400_BAD_REQUEST;
        return;
    }

    const char *version_start = path_end + 1;
    if (version_start >= request + line_len || *version_start == ' ' || *version_start == '\t') {
        req->method = -1;
        req->status = HTTP_400_BAD_REQUEST;
        return;
    }

    size_t path_len = (size_t)(path_end - path_start);
    if (path_len > 255) {
        fprintf(stderr, "[ERROR] URI length exceeds 255 bytes\n");
        req->status = HTTP_414_URI_TOO_LONG;
        req->method = -1;
        return;
    }

    req->path = malloc(path_len + 1);
    if (!req->path) {
        printf("[ERROR] Failed to allocate memory for path");
        req->method = -1;
        req->status = HTTP_500_INTERNAL_SERVER_ERROR;
        return;
    }
    memcpy(req->path, path_start, path_len);
    req->path[path_len] = '\0';

    size_t version_len = (size_t)((request + line_len) - version_start);
    if (version_len == 0) {
        req->method = -1;
        req->status = HTTP_400_BAD_REQUEST;
        return;
    }
    if (version_len == 8 && memcmp(version_start, "HTTP/1.0", 8) == 0) {
        req->version = HTTP_VERSION_1_0;
    } else if (version_len == strlen(HTTP_VERSION) &&
               memcmp(version_start, HTTP_VERSION, strlen(HTTP_VERSION)) == 0) {
        req->version = HTTP_VERSION_1_1;
    } else {
        req->method = -1;
        req->status = HTTP_400_BAD_REQUEST;
        return;
    }

    req->headers = http_kv_create(32);
    req->params = http_kv_create(10);
    if (!req->headers || !req->params) {
        printf("[ERROR] Failed to create map");
        req->method = -1;
        req->status = HTTP_500_INTERNAL_SERVER_ERROR;
        return;
    }

    const char *headers_end = http_find_crlfcrlf(request, request_len);
    if (!headers_end || headers_end < line_end + 2) {
        req->status = HTTP_400_BAD_REQUEST;
        req->method = -1;
        return;
    }

    const char *headers_start = line_end + 2;
    size_t headers_len = (size_t)(headers_end - headers_start);
    http_header_parse_state_t header_state = {0};
    if (headers_len > 0) {
        if (http_parse_headers(headers_start, headers_len, req, &header_state) != 0) {
            req->status = HTTP_400_BAD_REQUEST;
            req->method = -1;
            return;
        }
    }

    char *query = http_strchr(req->path, '?');
    if (query) {
        *query = '\0';
        query++;
        http_parse_params(query, req);
    }

    req->body = NULL;

    const char *transfer_encoding = http_kv_get(req->headers, "Transfer-Encoding");
    if (transfer_encoding) {
        int is_chunked = 0;
        int has_other = 0;
        http_parse_transfer_encoding_value(transfer_encoding, &is_chunked, &has_other);
        if (has_other) {
            req->status = HTTP_501_NOT_IMPLEMENTED;
            req->method = -1;
            return;
        }
        req->transfer_encoding_chunked = is_chunked ? 1 : 0;
    }

    if (header_state.content_length_conflict || header_state.host_conflict || header_state.host_empty || header_state.te_invalid) {
        req->status = HTTP_400_BAD_REQUEST;
        req->method = -1;
        return;
    }
    if (header_state.content_length_seen && !req->transfer_encoding_chunked) {
        req->content_length = header_state.content_length_value;
    } else {
        req->content_length = 0;
    }

    const char *connection = http_kv_get(req->headers, "Connection");
    if (connection && http_header_has_token(connection, "keep-alive")) {
        req->keep_alive = 1;
    }
    if (connection && http_header_has_token(connection, "close")) {
        req->close = 1;
    }
}

static int http_validate_trailer_fields(const char *trailers, size_t len) {
    const char *p = trailers;

    while (p < trailers + len) {
        const char *line_end = http_find_crlf(p, len - (size_t)(p - trailers));
        if (!line_end) {
            return -1;
        }

        size_t line_len = (size_t)(line_end - p);
        if (line_len == 0) {
            if (line_end + 2 != trailers + len) {
                return -1;
            }
            return 0;
        }

        if (p[0] == ' ' || p[0] == '\t') {
            return -1;
        }

        const char *colon = memchr(p, ':', line_len);
        if (!colon) {
            return -1;
        }

        size_t name_len = (size_t)(colon - p);
        if (http_header_name_invalid_range(p, name_len)) {
            return -1;
        }

        if (http_value_equals_case_insensitive(p, name_len, "transfer-encoding", 17) ||
            http_value_equals_case_insensitive(p, name_len, "content-length", 14) ||
            http_value_equals_case_insensitive(p, name_len, "host", 4) ||
            http_value_equals_case_insensitive(p, name_len, "connection", 10) ||
            http_value_equals_case_insensitive(p, name_len, "upgrade", 7) ||
            http_value_equals_case_insensitive(p, name_len, "te", 2) ||
            http_value_equals_case_insensitive(p, name_len, "trailer", 7)) {
            return -1;
        }

        const char *value = colon + 1;
        while (value < line_end && (*value == ' ' || *value == '\t')) {
            value++;
        }
        if (http_header_value_invalid_range(value, (size_t)(line_end - value))) {
            return -1;
        }

        p = line_end + 2;
    }

    return 0;
}


/* Tries to get boundary if multipart data is present. */
static int http_parse_content_type(const http_request_t *req, char **boundary) {
    const char *content_type = http_kv_get(req->headers, "Content-Type");
    if (content_type == NULL) {
        fprintf(stderr, "[ERROR] Content-Type header not found\n");
        return -1;
    }


    const char *boundary_prefix = "boundary=";
    *boundary = http_strstr(content_type, boundary_prefix);
    if (*boundary == NULL) {
        fprintf(stderr, "[ERROR] Boundary not found in Content-Type header\n");
        return -1;
    }

    *boundary += strlen(boundary_prefix);
    if (**boundary == '\0') {
        fprintf(stderr, "[ERROR] Boundary value is empty\n");
        return -1;
    }

    return 0;
}

static void http_extract_field(const char *src, char *dst, int max_len) {
    int i = 0;
    while (i < max_len - 1 && src[i] != '\0' && src[i] != '"') {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';  // Null-terminate
}

static int http_hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

static int http_token_equals(const char *token, size_t token_len, const char *expected) {
    size_t expected_len = strlen(expected);
    if (token_len != expected_len) {
        return 0;
    }
    for (size_t i = 0; i < token_len; i++) {
        if (tolower((unsigned char)token[i]) != tolower((unsigned char)expected[i])) {
            return 0;
        }
    }
    return 1;
}

static int http_parse_transfer_encoding_value(const char *value, int *is_chunked, int *has_other) {
    const char *p = value;
    *is_chunked = 0;
    *has_other = 0;

    while (*p != '\0') {
        while (*p == ' ' || *p == '\t' || *p == ',') {
            p++;
        }
        if (*p == '\0') {
            break;
        }

        const char *token_start = p;
        while (*p != '\0' && *p != ',') {
            p++;
        }
        const char *token_end = p;
        while (token_end > token_start && isspace((unsigned char)token_end[-1])) {
            token_end--;
        }
        const char *semi = memchr(token_start, ';', (size_t)(token_end - token_start));
        if (semi) {
            token_end = semi;
            while (token_end > token_start && isspace((unsigned char)token_end[-1])) {
                token_end--;
            }
        }

        size_t token_len = (size_t)(token_end - token_start);
        if (token_len == 0) {
            *has_other = 1;
            continue;
        }

        if (http_token_equals(token_start, token_len, "chunked")) {
            *is_chunked = 1;
        } else if (http_token_equals(token_start, token_len, "identity")) {
            /* identity is a no-op. */
        } else {
            *has_other = 1;
        }
    }

    return 0;
}

static int http_header_has_token(const char *value, const char *token) {
    const char *p = value;

    while (*p != '\0') {
        while (*p == ' ' || *p == '\t' || *p == ',') {
            p++;
        }
        if (*p == '\0') {
            break;
        }

        const char *token_start = p;
        while (*p != '\0' && *p != ',') {
            p++;
        }
        const char *token_end = p;
        while (token_end > token_start && isspace((unsigned char)token_end[-1])) {
            token_end--;
        }

        if (http_token_equals(token_start, (size_t)(token_end - token_start), token)) {
            return 1;
        }
    }

    return 0;
}

/**
 * Extract form data from body
 * Multiple form fields are separated by boundary
 * @param body Request body
 * @param boundary Boundary string
 * @param form_data Map to store form data   
 */
static int http_extract_multipart_form_data(const char *body, const char *boundary, http_kv_store_t *form_data) {
    char *boundary_start = http_strstr(body, boundary);
    if (boundary_start == NULL) {
        fprintf(stderr, "[ERROR] Boundary not found in body\n");
        return -1;
    }

    char *boundary_end = http_strstr(boundary_start, boundary);
    if (boundary_end == NULL) {
        fprintf(stderr, "[ERROR] Boundary end not found in body\n");
        return -1;
    }

    while (boundary_start != NULL) {
        boundary_start += strlen(boundary);
        if (strncmp(boundary_start, "--", 2) == 0) break;

        /* Find Content-Disposition */
        char *content_disposition = http_strstr(boundary_start, "Content-Disposition: form-data; name=\"");
        if (content_disposition == NULL) break;

        /* Extract field name */
        content_disposition += strlen("Content-Disposition: form-data; name=\"");
        char field_name[50];
        http_extract_field(content_disposition, field_name, sizeof(field_name));

        /* Extract value */
        char *value_start = http_strstr(content_disposition, "\r\n\r\n");
        if (value_start == NULL) break;
        value_start += 4;

        char *value_end = http_strstr(value_start, boundary);
        if (value_end == NULL) break;
        value_end -= 2;

        char *value = (char *)malloc(value_end - value_start + 1);
        if (value == NULL) {
            printf("[ERROR] Error allocating memory");
            return -1;
        }

        strncpy(value, value_start, value_end - value_start);
        value[value_end - value_start] = '\0';

        trim_trailing_whitespace(value);

        http_kv_insert(form_data, field_name, value);

        boundary_start = http_strstr(value_end, boundary);
    }

    return 0;
}

/* Parses body data if its either multipart of x-www-form */
int http_parse_data(http_request_t *req) {
    if (!req->body) {
        return 0;
    }

    req->data = http_kv_create(32);
    if(!req->data) {
        printf("[ERROR] Failed to create map");
        return -1;
    }

    /* Handle multipart/form-data */
    char *content_type = http_kv_get(req->headers, "Content-Type");
    if (content_type && http_strstr(content_type, "multipart/form-data")) {
        char *boundary = NULL;
        if (http_parse_content_type(req, &boundary) == 0) {
            if (http_extract_multipart_form_data(req->body, boundary, req->data) != 0) {
                fprintf(stderr, "[ERROR] Failed to extract multipart form data\n");
                return -1;
            }
        }
    }

    /* Handle application/x-www-form-urlencoded */
    if (content_type && http_strstr(content_type, "application/x-www-form-urlencoded")) {
        const char *param_start = req->body;

        while (*param_start != '\0') {

            const char *param_end = http_strchr(param_start, '&');
            const char *key_end = http_strchr(param_start, '=');
            if (key_end && (!param_end || key_end < param_end)) {
                size_t key_length = key_end - param_start;
                size_t value_length = param_end ? (size_t)(param_end - key_end - 1) : strlen(key_end + 1);

                char *key = malloc(key_length + 1);
                char *value = malloc(value_length + 1);
                if (!key || !value) {
                    printf("[ERROR] Failed to allocate memory for form data");
                    free(key);
                    free(value);
                    return -1;
                }

                strncpy(key, param_start, key_length);
                key[key_length] = '\0';

                strncpy(value, key_end + 1, value_length);
                value[value_length] = '\0';

                http_kv_insert(req->data, key, value);

                param_start = param_end ? param_end + 1 : "";

                /* Map mallocs its key value and copies over content. So we free our key. */
                free(key);
            } else {
                break;
            }
        }
    }

    return 0;
}

int http_parse(const char *request, size_t request_len, http_request_t *req) {
    http_parse_request(request, request_len, req);
    if (req->method == -1) {
        return -1;
    }

    /* RFC 9112 §3.2: HTTP/1.1 requests must include Host. */
    char* host = http_kv_get(req->headers, "Host");
    if (!host) {
        fprintf(stderr, "[ERROR] Host header not found\n");
        req->method = -1;
        req->status = HTTP_400_BAD_REQUEST;
        return -1;
    }

    return 0;
}
