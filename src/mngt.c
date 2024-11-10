#include "http.h"
#include "router.h"
#include "cweb.h"
#include "map.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <dlfcn.h>

#define TMP_DIR "./tmp"

static 

int engine_write_and_compile(const char *filename, const char *code) {
    char source_path[256], so_path[256];
    snprintf(source_path, sizeof(source_path), "%s/%s.c", TMP_DIR, filename);
    snprintf(so_path, sizeof(so_path), "%s/%s.so", TMP_DIR, filename);

    FILE *fp = fopen(source_path, "w");
    if (fp == NULL) {
        perror("Error creating C file");
        return -1;
    }
    fprintf(fp, "%s", code);
    fclose(fp);

    char command[512];
    snprintf(command, sizeof(command), "gcc -fPIC -shared -o %s %s", so_path, source_path);
    if (system(command) != 0) {
        fprintf(stderr, "Compilation failed for %s\n", source_path);
        unlink(source_path);
        return -1;
    }
    unlink(source_path);

    dbgprint("Compilation successful for %s\n", filename);
    return 0;
}

int mgnt_register_route(char* route, char* code, char* func_name) {
    char filename[256];
    snprintf(filename, sizeof(filename), "%s_%ld", func_name, time(NULL));

    if (engine_write_and_compile(filename, code) != 0) {
        fprintf(stderr, "Failed to register route '%s' due to compilation error.\n", route);
        return -1;
    }

    char so_path[256];
    snprintf(so_path, sizeof(so_path), "%s/%s.so", TMP_DIR, filename);

    route_register(route, so_path, func_name);

    struct route *r = route_find(route);
    if (r != NULL) {
        r->handler(NULL, NULL);
    } else {
        fprintf(stderr, "Route not found: %s\n", route);
        return -1;
    }

    return 0;
}

int mgnt_parse_request(struct http_request *req) {
    if (req->method == -1) {
        return -1;
    }

    const char *content_type = map_get(req->headers, "Content-Type");
    if (content_type == NULL) {
        fprintf(stderr, "Content-Type header not found\n");
        return -1;
    }

    const char *boundary_prefix = "boundary=";
    char *boundary = strstr(content_type, boundary_prefix);
    if (boundary == NULL) {
        fprintf(stderr, "Boundary not found in Content-Type header\n");
        return -1;
    }

    boundary += strlen(boundary_prefix);
    if (*boundary == '\0') {
        fprintf(stderr, "Boundary value is empty\n");
        return -1;
    }

    printf("Boundary: %s\n", boundary);
    printf("Body: %s\n", req->body);

    struct map *form_data = map_create(10);

    char *body = req->body;
    char *part = strtok(body, boundary);
    while (part != NULL) {
        printf("Part: %s\n", part);
        part = strtok(NULL, boundary);
    }

    for(size_t i = 0; i < form_data->size; i++) {
        printf("Key: %s, Value: %s\n", form_data->entries[i].key, (char *)form_data->entries[i].value);
    }

    return 0;
}