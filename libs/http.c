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

/* Parse HTTP method */
static void http_parse_method(const char *method, http_request_t *req) {
    if (strncmp(method, "GET", 3) == 0) {
        req->method = HTTP_GET;
    } else if (strncmp(method, "POST", 4) == 0) {
        req->method = HTTP_POST;
    } else if (strncmp(method, "PUT", 3) == 0) {
        req->method = HTTP_PUT;
    } else if (strncmp(method, "DELETE", 6) == 0) {
        req->method = HTTP_DELETE;
    } else if (strncmp(method, "OPTIONS", 7) == 0) {
        req->method = HTTP_OPTIONS;
    } else {
        req->method = -1;
    }
}

static int http_header_name_invalid(const char *name) {
    /* RFC 9110 §5.1: field-name is a token; no whitespace allowed. */
    if (!name || *name == '\0') {
        return 1;
    }
    for (const char *p = name; *p != '\0'; p++) {
        if (*p == ' ' || *p == '\t') {
            return 1;
        }
    }
    return 0;
}

static const char *http_find_crlf(const char *buf, size_t len) {
    for (size_t i = 0; i + 1 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n') {
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
static int http_parse_headers(const char *headers, http_request_t *req) {
    const char *line_start = headers;

    while (*line_start != '\0') {
        const char *line_end = http_strstr(line_start, "\r\n");
        if (!line_end) {
            line_end = line_start + strlen(line_start);
        }

        /* Calculate line length and copy it into a temporary buffer */
        size_t line_length = line_end - line_start;
        char *line = malloc(line_length + 1);
        if (!line) {
            printf("[ERROR] Failed to allocate memory for header line");
            return -1;
        }
        strncpy(line, line_start, line_length);
        line[line_length] = '\0';

        /* RFC 9112 §5.1: obs-fold is invalid; reject header lines starting with SP/HTAB. */
        if (line[0] == ' ' || line[0] == '\t') {
            free(line);
            return -1;
        }

        char *colon = http_strchr(line, ':');
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

        if (http_kv_get(req->headers, key) != NULL) {
            free(line);
            continue;
        }

        while (*value == ' ' || *value == '\t') {
            value++;
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

        if (*line_end == '\0') {
            break;
        }
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



/* Mainly parses the header of the HTTP request */
static void http_parse_request(const char *request, http_request_t *req) {
    char *request_copy = http_strdup(request);
    if (!request_copy) {
        printf("[ERROR] Failed to allocate request copy");
        return;
    }

    char *cursor = request_copy;

    /* Parse method */
    char *method_end = http_strchr(cursor, ' ');
    if (!method_end) {
        printf("[ERROR] Failed to parse method");
        free(request_copy);
        req->method = -1;
        return;
    }
    *method_end = '\0';
    http_parse_method(cursor, req);

    /**
    * Parse path
    * Note: Servers ought to be cautious about depending on URI lengths
    * above 255 bytes, because some older client or proxy
    * implementations might not properly support these lengths.
    */
    cursor = method_end + 1;
    char *path_end = http_strchr(cursor, ' ');
    if (!path_end) {
        printf("[ERROR] Failed to parse path");
        free(request_copy);
        req->method = -1;
        return;
    }
    *path_end = '\0';
    if (strlen(cursor) > 255) {
        fprintf(stderr, "[ERROR] URI length exceeds 255 bytes\n");
        /**
         * A server SHOULD return 414 (Request-URI Too Long) status if a URI is longer
         * than the server can handle.
         */
        req->status = HTTP_414_URI_TOO_LONG;
        free(request_copy);
        req->method = -1;
        return;
    }
    req->path = http_strdup(cursor);
    if (!req->path) {
        printf("[ERROR] Failed to allocate memory for path");
        free(request_copy);
        return;
    }

    /* Parse HTTP version */
    cursor = path_end + 1;
    char *version_end = http_strstr(cursor, "\r\n");
    if (!version_end) {
        printf("[ERROR] Failed to parse HTTP version");
        free(request_copy);
        req->method = -1;
        return;
    }
    *version_end = '\0';
    if (strncmp(cursor, HTTP_VERSION, strlen(HTTP_VERSION)) != 0) {   
        req->version = HTTP_VERSION_1_0;
    } else {
        req->version = HTTP_VERSION_1_1;
    }

    /* Move cursor to headers */
    cursor = version_end + 2;

    /* Create maps for headers and params */
    req->headers = http_kv_create(32);
    req->params = http_kv_create(10);
    if (!req->headers || !req->params) {
        printf("[ERROR] Failed to create map");
        free(request_copy);
        return;
    }

    /* Parse headers */
    char *headers_end = http_strstr(cursor, "\r\n\r\n");
    if (headers_end) {
        size_t headers_length = headers_end - cursor;
        
        char *headers = malloc(headers_length + 1);
        if (!headers) {
            printf("[ERROR] Failed to allocate memory for headers");
            free(request_copy);
            return;
        }

        strncpy(headers, cursor, headers_length);
        headers[headers_length] = '\0';
        if (http_parse_headers(headers, req) != 0) {
            /* RFC 9112 §5: invalid header field syntax => 400 Bad Request. */
            req->status = HTTP_400_BAD_REQUEST;
            req->method = -1;
            free(headers);
            free(request_copy);
            return;
        }
        free(headers);

        cursor = headers_end + 4; /* Move past "\r\n\r\n" */
    }

    /* Parse query params */
    char *query = http_strchr(req->path, '?');
    if (query) {
        *query = '\0';
        query++;
        http_parse_params(query, req);
    }

    req->body = NULL;

    /* RFC 9112 §6.1: Transfer-Encoding overrides Content-Length. */
    const char *transfer_encoding = http_kv_get(req->headers, "Transfer-Encoding");
    if (transfer_encoding) {
        int is_chunked = 0;
        int has_other = 0;
        http_parse_transfer_encoding_value(transfer_encoding, &is_chunked, &has_other);
        if (has_other) {
            /* RFC 9112 §6.1: respond 501 to unsupported transfer codings. */
            req->status = HTTP_501_NOT_IMPLEMENTED;
            req->method = -1;
            free(request_copy);
            return;
        }
        req->transfer_encoding_chunked = is_chunked ? 1 : 0;
    }

    /* Parse Content-Length */
    char *content_length_str = http_kv_get(req->headers, "Content-Length");
    if (content_length_str && !req->transfer_encoding_chunked) {
        while (*content_length_str == ' ' || *content_length_str == '\t') {
            content_length_str++;
        }
        char *endptr = NULL;
        errno = 0;
        unsigned long length = strtoul(content_length_str, &endptr, 10);
        while (endptr && (*endptr == ' ' || *endptr == '\t')) {
            endptr++;
        }
        if (errno != 0 || endptr == content_length_str || *endptr != '\0' || length > INT_MAX) {
            req->status = HTTP_400_BAD_REQUEST;
            req->method = -1;
            free(request_copy);
            return;
        }
        req->content_length = (int)length;
    } else {
        req->content_length = 0;
    }

    /* Parse Connection */
    const char *connection = http_kv_get(req->headers, "Connection");
    /* RFC 9110 §7.6.1: Connection header is a list of tokens. */
    if (connection && http_header_has_token(connection, "keep-alive")) {
        req->keep_alive = 1;
    }
    if (connection && http_header_has_token(connection, "close")) {
        req->close = 1;
    }

    free(request_copy);
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

int http_parse(const char *request, http_request_t *req) {
    http_parse_request(request, req);
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
