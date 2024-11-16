#include "http.h"
#include "map.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

const char *http_methods[] = {"GET", "POST", "PUT", "DELETE"};
const char *http_errors[] = {"101 Switching Protocols", "200 OK", "302 Found", "400 Bad Request", "403 Forbidden", "404 Not Found", "500 Internal Server Error"};

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
static void http_parse_headers(char *line, struct http_request *req) {
    while (line) {
        char *colon = strchr(line, ':');
        if (colon) {
            *colon = '\0';
            char *key = line;
            char *value = colon + 1;
            while (*value == ' ') value++; /* Skip leading spaces */
            map_insert(req->headers, strdup(key), strdup(value));
        }
        line = strtok(NULL, "\r\n");
    }
}

/* Parses query parameters and puts them into params map */
static void http_parse_params(char *query, struct http_request *req) {
    char *param = strtok(query, "&");
    while (param) {
        char *key = strtok(param, "=");
        char *value = strtok(NULL, "");
        if (key && value) {
            map_insert(req->params, strdup(key), strdup(value));
        }
        param = strtok(NULL, "&");
    }
}

/* Allocates and copies request body */
static void http_parse_body(const char *request, struct http_request *req) {
    char *body = strstr(request, "\r\n\r\n");
    if (body) {
        body += 4; /* Skip past the "\r\n\r\n" */
        req->body = strdup(body);
        if (!req->body) {
            perror("Failed to allocate body");
        }
    } else {
        req->body = NULL;
    }
}

/* Mainly parses the header of the HTTP request */
static void http_parse_request(const char *request, struct http_request *req) {
    char *request_copy = strdup(request);
    if (!request_copy) {
        perror("Failed to allocate request copy");
        return;
    }

    char *method = strtok(request_copy, " ");
    http_parse_method(method, req);

    /* Check for valid method */
    req->path = strdup(strtok(NULL, " "));
    if (!req->path) {
        perror("Failed to parse path");
        free(request_copy);
        return;
    }

    /* Check HTTP version */
    char *version = strtok(NULL, "\r\n");
    if (strncmp(version, HTTP_VERSION, strlen(HTTP_VERSION)) != 0) {
        req->method = -1;
    }

    req->headers = map_create(32);
    req->params = map_create(10);
    if (!req->headers || !req->params) {
        perror("Failed to create map");
        free(request_copy);
        return;
    }

    /* Parse headers */
    char *line = strtok(NULL, "\r\n");
    while (line && *line != '\0') {
        http_parse_headers(line, req);
        line = strtok(NULL, "\r\n");
    }

    /* Parse query params */
    char *query = strchr(req->path, '?');
    if (query) {
        *query = '\0';
        query++;
        http_parse_params(query, req);
    }

    http_parse_body(request, req);

    char *content_length_str = map_get(req->headers, "Content-Length");
    if (content_length_str) {
        req->content_length = atoi(content_length_str);
    } else {
        req->content_length = 0;
    }

    free(request_copy);
}

/* Tries to get boundary if multipart data is present. */
static int http_parse_content_type(const struct http_request *req, char **boundary) {
    const char *content_type = map_get(req->headers, "Content-Type");
    if (content_type == NULL) {
        fprintf(stderr, "Content-Type header not found\n");
        return -1;
    }


    const char *boundary_prefix = "boundary=";
    *boundary = strstr(content_type, boundary_prefix);
    if (*boundary == NULL) {
        fprintf(stderr, "Boundary not found in Content-Type header\n");
        return -1;
    }

    *boundary += strlen(boundary_prefix);
    if (**boundary == '\0') {
        fprintf(stderr, "Boundary value is empty\n");
        return -1;
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
static int http_extract_multipart_form_data(const char *body, const char *boundary, struct map *form_data) {
    char *boundary_start = strstr(body, boundary);
    if (boundary_start == NULL) {
        fprintf(stderr, "Boundary not found in body\n");
        return -1;
    }

    char *boundary_end = strstr(boundary_start, boundary);
    if (boundary_end == NULL) {
        fprintf(stderr, "Boundary end not found in body\n");
        return -1;
    }

    while (boundary_start != NULL) {
        boundary_start += strlen(boundary);
        if (strncmp(boundary_start, "--", 2) == 0) break;

        /* Find Content-Disposition */
        char *content_disposition = strstr(boundary_start, "Content-Disposition: form-data; name=\"");
        if (content_disposition == NULL) break;

        /* Extract field name */
        content_disposition += strlen("Content-Disposition: form-data; name=\"");
        char field_name[50];
        sscanf(content_disposition, "%49[^\"]", field_name);

        /* Extract value */
        char *value_start = strstr(content_disposition, "\r\n\r\n");
        if (value_start == NULL) break;
        value_start += 4;

        char *value_end = strstr(value_start, boundary);
        if (value_end == NULL) break;
        value_end -= 2;

        char *value = (char *)malloc(value_end - value_start + 1);
        if (value == NULL) {
            perror("Error allocating memory");
            return -1;
        }

        strncpy(value, value_start, value_end - value_start);
        value[value_end - value_start] = '\0';

        trim_trailing_whitespace(value);

        map_insert(form_data, field_name, value);

        boundary_start = strstr(value_end, boundary);
    }

    return 0;
}

/* Parses body data if its either multipart of x-www-form */
int http_parse_data(struct http_request *req) {
    req->data = map_create(10);
    char* content_type = map_get(req->headers, "Content-Type");
    if (content_type && strstr(content_type, "multipart/form-data")) {
        char *boundary = NULL;
        if (http_parse_content_type(req, &boundary) == 0) {
            if (http_extract_multipart_form_data(req->body, boundary, req->data) != 0) {
                fprintf(stderr, "Failed to extract multipart form data\n");
                return -1;
            }
        }
    }

    if(content_type && strstr(content_type, "application/x-www-form-urlencoded")) {
        char *body_copy = strdup(req->body);
        if (!body_copy) {
            perror("Failed to allocate body copy");
            return -1;
        }

        char *param = strtok(body_copy, "&");
        while (param) {
            char *key = strtok(param, "=");
            char *value = strtok(NULL, "");
            if (key && value) {
            map_insert(req->data, strdup(key), strdup(value));
            }
            param = strtok(NULL, "&");
        }

        free(body_copy);
    }

    return 0;
}

int http_parse(const char *request, struct http_request *req) {
    http_parse_request(request, req);
    if (req->method == -1) {
        return -1;
    }

    // for (size_t i = 0; i < map_size(req->params); i++) {
    //     const char *key = req->params->entries[i].key;
    //     const char *value = req->params->entries[i].value;
    //     printf("  %s: %s\n", key, value);
    // }
    // printf("Headers:\n");
    // for (size_t i = 0; i < map_size(req->headers); i++) {
    //     const char *key = req->headers->entries[i].key;
    //     const char *value = req->headers->entries[i].value;
    //     printf("  %s: %s\n", key, value);
    // }
    return 0;
}