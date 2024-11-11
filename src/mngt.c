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
#include <time.h>
#include <ctype.h>

#define TMP_DIR "./tmp"

/* static prototypes */
static void trim_trailing_whitespace(char *str);
static int write_and_compile(const char *filename, const char *code);
static int parse_content_type(const struct http_request *req, char **boundary);
static int extract_multipart_form_data(const char *body, const char *boundary, struct map *form_data);

/* exposed prototypes */
int mgnt_parse_request(struct http_request *req);
int mgnt_register_route(char* route, char* code, char* func_name);

/* Helper function to trim trailing whitespace */
static void trim_trailing_whitespace(char *str) {
    int len = strlen(str);
    while (len > 0 && (str[len - 1] == '\r' || str[len - 1] == '\n' || isspace((unsigned char)str[len - 1]))) {
        str[--len] = '\0';
    }
}

/**
 * Write code to a temporary file and compile it to .so
 * @param filename Name of the file
 * @param code Code to write to the file
 */
int write_and_compile(const char *filename, const char *code) {
    char source_path[256], so_path[256];
    snprintf(source_path, sizeof(source_path), "%s/%s.c", TMP_DIR, filename);
    snprintf(so_path, sizeof(so_path), "%s/%s.so", TMP_DIR, filename);

    /* Save code to file for compilation. */
    FILE *fp = fopen(source_path, "w");
    if (fp == NULL) {
        perror("Error creating C file");
        return -1;
    }
    fprintf(fp, "%s", code);
    fclose(fp);

    char command[512];
    snprintf(command, sizeof(command), "gcc -fPIC -L./libs -lmap -shared -I./include -o %s %s", so_path, source_path);
    if (system(command) != 0) {
        fprintf(stderr, "Compilation failed for %s -> %s\n", source_path, so_path);
        unlink(source_path);
        return -1;
    }
    unlink(source_path);

    dbgprint("Compilation successful for %s\n", filename);
    return 0;
}

int mgnt_register_route(char* route, char* code, char* func_name) {
    if (strlen(func_name) > 50) {
        fprintf(stderr, "Function name '%s' is too long.\n", func_name);
        return -1;
    }

    char filename[256];
    //snprintf(filename, sizeof(filename), "%s_%ld", func_name, time(NULL));
    snprintf(filename, sizeof(filename), "%s", func_name);

    if (write_and_compile(filename, code) != 0) {
        fprintf(stderr, "Failed to register route '%s' due to compilation error.\n", route);
        return -1;
    }

    char so_path[256];
    snprintf(so_path, sizeof(so_path), "%s/%s.so", TMP_DIR, filename);

    route_register(route, so_path, func_name);

    return 0;
}

static int parse_content_type(const struct http_request *req, char **boundary) {
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
static int extract_multipart_form_data(const char *body, const char *boundary, struct map *form_data) {
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

int mgnt_parse_request(struct http_request *req) {
    if (req->method == -1) {
        return -1;
    }

    char *boundary = NULL;
    if (parse_content_type(req, &boundary) != 0) {
        return -1;
    }

    struct map *form_data = map_create(10);
    if (extract_multipart_form_data(req->body, boundary, form_data) != 0) {
        return -1;
    }
    mgnt_register_route(map_get(form_data, "route"), map_get(form_data, "code"), map_get(form_data, "function_name"));

    return 0;
}