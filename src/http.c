
#include "http.h"
#include "map.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

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

/* Hypertext Transfer Protocol -- HTTP/1.1 Spec:  https://datatracker.ietf.org/doc/html/rfc2616 */
const char *http_methods[] = {"GET", "POST", "PUT", "DELETE"};
const char *http_errors[] = {
    "400 Bad Request", /* Unknown defaults to 400 */
    "101 Switching Protocols",
    "200 OK",
    "302 Found",
    "400 Bad Request", "401 Unauthorized", "403 Forbidden", "404 Not Found", "405 Method Not Allowed", "414 URI Too Long",
    "500 Internal Server Error"
};

/* Helper function to trim trailing whitespace */
static void trim_trailing_whitespace(char *str) {
    int len = strlen(str);
    while (len > 0 && (str[len - 1] == '\r' || str[len - 1] == '\n' || isspace((unsigned char)str[len - 1]))) {
        str[--len] = '\0';
    }
}

/* Parse HTTP method */
static void http_parse_method(const char *method, struct http_request *req) {
    if (strncmp(method, "GET", 3) == 0) {
        req->method = HTTP_GET;
    } else if (strncmp(method, "POST", 4) == 0) {
        req->method = HTTP_POST;
    } else if (strncmp(method, "PUT", 3) == 0) {
        req->method = HTTP_PUT;
    } else if (strncmp(method, "DELETE", 6) == 0) {
        req->method = HTTP_DELETE;
    } else {
        req->method = -1;
    }
}

/* Parses HTTP headers and puts them into headers map */
static void http_parse_headers(const char *headers, struct http_request *req) {
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
            return;
        }
        strncpy(line, line_start, line_length);
        line[line_length] = '\0';

        char *colon = http_strchr(line, ':');
        if (colon) {
            *colon = '\0';
            char *key = line;
            char *value = colon + 1;
            while (*value == ' ') {
                value++;
            }

            char* k_value = http_strdup(value);
            if(!k_value) {
                printf("[ERROR] Failed to allocate memory for header key");
                free(line);
                return;
            }

            
            map_insert(req->headers, key, k_value);
        }

        free(line);

        if (*line_end == '\0') {
            break;
        }
        line_start = line_end + 2;
    }
}

/* Parses query parameters and puts them into params map */
static void http_parse_params(const char *query, struct http_request *req) {
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

            /* Malloced value is handed of too map. */
            map_insert(req->params, key, value);
            
            free(key);
            param_start = param_end ? param_end + 1 : "";
        } else {
            break;
        }
    }
}



/* Allocates and copies request body */
static void http_parse_body(const char *request, struct http_request *req) {
    char *body = http_strstr(request, "\r\n\r\n");
    if (body) {
        body += 4; /* Skip past the "\r\n\r\n" */
        req->body = http_strdup(body);
        if (!req->body) {
            printf("[ERROR] Failed to allocate body");
        }
    } else {
        req->body = NULL;
    }
}

/* Mainly parses the header of the HTTP request */
static void http_parse_request(const char *request, struct http_request *req) {
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
    req->headers = map_create(32);
    req->params = map_create(10);
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
        http_parse_headers(headers, req);
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

    /* Parse body */
    http_parse_body(cursor, req);

    /* Parse Content-Length */
    char *content_length_str = map_get(req->headers, "Content-Length");
    if (content_length_str) {
        req->content_length = atoi(content_length_str);
    } else {
        req->content_length = 0;
    }

    /* Parse Connection */
    const char *connection = map_get(req->headers, "Connection");
    if (connection && strcasecmp(connection, "keep-alive") == 0) {
        req->keep_alive = 1;
    } else if (connection && strcasecmp(connection, "close") == 0) {
        req->close = 1;
    }

    free(request_copy);
}


/* Tries to get boundary if multipart data is present. */
static int http_parse_content_type(const struct http_request *req, char **boundary) {
    const char *content_type = map_get(req->headers, "Content-Type");
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

/**
 * Extract form data from body
 * Multiple form fields are separated by boundary
 * @param body Request body
 * @param boundary Boundary string
 * @param form_data Map to store form data   
 */
static int http_extract_multipart_form_data(const char *body, const char *boundary, struct map *form_data) {
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

        map_insert(form_data, field_name, value);

        boundary_start = http_strstr(value_end, boundary);
    }

    return 0;
}

/* Parses body data if its either multipart of x-www-form */
int http_parse_data(struct http_request *req) {
    req->data = map_create(32);
    if(!req->data) {
        printf("[ERROR] Failed to create map");
        return -1;
    }

    /* Handle multipart/form-data */
    char *content_type = map_get(req->headers, "Content-Type");
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

                map_insert(req->data, key, value);

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

int http_parse(const char *request, struct http_request *req) {
    http_parse_request(request, req);
    if (req->method == -1) {
        return -1;
    }

    /**
     * Requests MUST include the Host header field, and the server MUST reject requests without it (400 Bad Request).
     */
    char* host = map_get(req->headers, "Host");
    if (!host) {
        fprintf(stderr, "[ERROR] Host header not found\n");
        req->method = -1;
        req->status = HTTP_400_BAD_REQUEST;
        return -1;
    }

    return 0;
}