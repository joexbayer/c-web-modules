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


#define TMP_DIR "./tmp"

/* static prototypes */
static int write_and_compile(const char *filename, const char *code);
/* exposed prototypes */
int mgnt_parse_request(struct http_request *req);
int mgnt_register_route(char* route, char* code, char* func_name, char* method);


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

char* hash_code(char* code) {
    char* hash = malloc(256);
    if(hash == NULL) {
        fprintf(stderr, "Failed to allocate memory for hash.\n");
        return NULL;
    }

    unsigned long hash_value = 5381;
    int c;
    const char *tmp = code;
    while ((c = *tmp++))
        hash_value = ((hash_value << 5) + hash_value) + c; /* hash * 33 + c */
    snprintf(hash, sizeof(hash), "%lu", hash_value);    

    return hash;
}

int mgnt_register_route(char* route, char* code, char* func_name, char* method) {
    if(route == NULL || code == NULL || func_name == NULL || method == NULL) {
        fprintf(stderr, "Invalid route registration: route=%s, code=%s, func_name=%s, method=%s\n", route, code, func_name, method);
        return -1;
    }

    char* hash = hash_code(code);   

    if (strlen(func_name) > 50) {
        fprintf(stderr, "Function name '%s' is too long.\n", func_name);
        return -1;
    }

    char filename[256];
    //snprintf(filename, sizeof(filename), "%s_%ld", func_name, time(NULL));
    snprintf(filename, sizeof(filename), "%s", hash);

    if (write_and_compile(filename, code) != 0) {
        fprintf(stderr, "Failed to register route '%s' due to compilation error.\n", route);
        return -1;
    }

    char so_path[256];
    snprintf(so_path, sizeof(so_path), "%s/%s.so", TMP_DIR, filename);

    route_register(route, so_path, func_name, method);

    free(hash);

    return 0;
}

int mgnt_parse_request(struct http_request *req) {
    if (req->method == -1) {
        return -1;
    }

    mgnt_register_route(map_get(req->data, "route"), map_get(req->data, "code"), map_get(req->data, "function_name"), map_get(req->data, "method"));

    return 0;
}