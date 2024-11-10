#include "http.h"
#include "map.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static void http_parse_request(const char *request, struct http_request *req) {
    char *request_copy = strdup(request);
    if (!request_copy) {
        perror("Failed to allocate request copy");
        return;
    }

    char *method = strtok(request_copy, " ");
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

    req->path = strdup(strtok(NULL, " "));
    if (!req->path) {
        perror("Failed to parse path");
        free(request_copy);
        return;
    }

    char *version = strtok(NULL, "\r\n");
    if (strncmp(version, HTTP_VERSION, strlen(HTTP_VERSION)) != 0) {
        req->method = -1;
    }

    req->headers = map_create(10);
    req->query_params = map_create(10);
    if (!req->headers || !req->query_params) {
        perror("Failed to create map");
        free(request_copy);
        return;
    }

    char *line = strtok(NULL, "\r\n");
    while (line) {
        printf("Line: %s\n", line);
        char *colon = strchr(line, ':');
        if (colon) {
            *colon = '\0';
            char *key = line;
            char *value = colon + 1;
            while (*value == ' ') value++; // Skip leading spaces
            map_insert(req->headers, strdup(key), strdup(value));
        }
        line = strtok(NULL, "\r\n");
    }

    char *query = strchr(req->path, '?');
    if (query) {
        *query = '\0';
        query++;
        char *param = strtok(query, "&");
        while (param) {
            char *key = strtok(param, "=");
            char *value = strtok(NULL, "");
            if (key && value) {
                map_insert(req->query_params, strdup(key), strdup(value));
            }
            param = strtok(NULL, "&");
        }
    }

    char *body = strstr(request, "\r\n\r\n");
    if (body) {
        body += 4; // Skip past the "\r\n\r\n"
        req->body = strdup(body);
        if (!req->body) {
            perror("Failed to allocate body");
        }
    } else {
        req->body = NULL;
    }

    free(request_copy);
}

static void http_send_response(int client_fd, struct http_response *res) {
    const char *status;
    switch (res->status) {
        case HTTP_200_OK:
            status = "200 OK";
            break;
        case HTTP_400_BAD_REQUEST:
            status = "400 Bad Request";
            break;
        case HTTP_403_FORBIDDEN:
            status = "403 Forbidden";
            break;
        case HTTP_404_NOT_FOUND:
            status = "404 Not Found";
            break;
        case HTTP_500_INTERNAL_SERVER_ERROR:
            status = "500 Internal Server Error";
            break;
        default:
            status = "500 Internal Server Error";
            break;
    }

    dprintf(client_fd, "HTTP/1.1 %s\r\nContent-Length: %lu\r\n\r\n%s", status, strlen(res->body), res->body);
}

int http_parse(const char *request, struct http_request *req) {
    http_parse_request(request, req);
    if (req->method == -1) {
        return -1;
    }

    printf("Method: %d\n", req->method);
    printf("Path: %s\n", req->path);
    printf("Query params:\n");
    for (size_t i = 0; i < map_size(req->query_params); i++) {
        const char *key = req->query_params->entries[i].key;
        const char *value = req->query_params->entries[i].value;
        printf("  %s: %s\n", key, value);
    }
    printf("Headers:\n");
    for (size_t i = 0; i < map_size(req->headers); i++) {
        const char *key = req->headers->entries[i].key;
        const char *value = req->headers->entries[i].value;
        printf("  %s: %s\n", key, value);
    }


    return 0;
}