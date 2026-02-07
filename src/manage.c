#include "router.h"
#include "http.h"
#include "cweb.h"
#include <jansson.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <time.h>

#ifdef __APPLE__
    #define CFLAGS "-fPIC -shared -I./include -I/opt/homebrew/opt/jansson/include -I/opt/homebrew/opt/openssl@3/include"
    #define LIBS "-L./libs -lmodule -lhttp -L/opt/homebrew/opt/jansson/lib -ljansson -lsqlite3 -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto"
#elif __linux__
    #define CFLAGS "-fPIC -shared -I./include -Wl,-rpath=./libs"
    #define LIBS "-L./libs -lmodule -lhttp -ljansson -lsqlite3"
#else
    #error "Unsupported platform"
#endif

int write_and_compile(const char *module_dir, const char *filename, const char *code, char *error_buffer, size_t buffer_size) {
    char source_path[SO_PATH_MAX_LEN * 2], so_path[SO_PATH_MAX_LEN * 2];
    if (snprintf(source_path, sizeof(source_path), "%s/%s.c", module_dir, filename) >= (int)sizeof(source_path) ||
        snprintf(so_path, sizeof(so_path), "%s/%s.so", module_dir, filename) >= (int)sizeof(so_path)) {
        fprintf(stderr, "[ERROR] Path buffer overflow.\n");
        return -1;
    }

    FILE *fp = fopen(source_path, "w");
    if (fp == NULL) {
        perror("Error creating C file");
        return -1;
    }
    if (fprintf(fp, "%s", code) < 0) {
        perror("Error writing to C file");
        fclose(fp);
        return -1;
    }
    fclose(fp);

    char command[SO_PATH_MAX_LEN * 2 + 200];
    if (snprintf(command, sizeof(command), "gcc "LIBS" "CFLAGS"  -o %s %s 2>&1", so_path, source_path) >= (int)sizeof(command)) {
        fprintf(stderr, "[ERROR] Command buffer overflow.\n");
        unlink(source_path);
        return -1;
    }

    FILE *gcc_output = popen(command, "r");
    if (gcc_output == NULL) {
        perror("Error running gcc");
        unlink(source_path);
        return -1;
    }

    size_t bytes_read = 0;
    while (fgets(error_buffer + bytes_read, buffer_size - bytes_read, gcc_output) != NULL) {
        bytes_read = strlen(error_buffer);
        if (bytes_read >= buffer_size - 1) {
            break;
        }
    }

    int exit_code = pclose(gcc_output);
    if (exit_code != 0) {
        fprintf(stderr, "Compilation failed for %s -> %s\n", source_path, so_path);
        unlink(source_path);
        return -1;
    }

    unlink(source_path);
    return 0;
}

int router_gateway_json(struct router *router, http_response_t* res) {
    json_t *root = json_object();
    json_t *modules = json_array();

    for (int i = 0; i < router->count; i++) {
        if (!router->entries[i].ref) {
            continue;
        }
        json_t *module = json_object();
        json_object_set_new(module, "name", json_string(router->entries[i].ref->module->name));
        json_object_set_new(module, "author", json_string(router->entries[i].ref->module->author));
        json_object_set_new(module, "path", json_string(router->entries[i].ref->so_path));
        json_object_set_new(module, "module_hash", json_string(router->entries[i].ref->module_hash));

        json_t *routes = json_array();
        for (int j = 0; j < router->entries[i].ref->module->size; j++) {
            json_t *route = json_object();
            json_object_set_new(route, "method", json_string(router->entries[i].ref->module->routes[j].method));
            json_object_set_new(route, "path", json_string(router->entries[i].ref->module->routes[j].path));
            json_array_append_new(routes, route);
        }
        json_object_set_new(module, "routes", routes);

        json_t *websockets = json_array();
        for (int j = 0; j < router->entries[i].ref->module->ws_size; j++) {
            json_t *ws_route = json_object();
            json_object_set_new(ws_route, "path", json_string(router->entries[i].ref->module->websockets[j].path));
            json_array_append_new(websockets, ws_route);
        }

        json_object_set_new(module, "websockets", websockets);

        json_t *jobs = json_array();
        for (int j = 0; j < router->entries[i].ref->module->job_size; j++) {
            json_t *job = json_object();
            json_object_set_new(job, "name", json_string(router->entries[i].ref->module->jobs[j].name));
            json_array_append_new(jobs, job);
        }
        json_object_set_new(module, "jobs", jobs);

        json_array_append_new(modules, module);
    }

    json_object_set_new(root, "modules", modules);
    char *json_str = json_dumps(root, JSON_INDENT(2));
    json_decref(root);

    http_kv_insert(res->headers, "Content-Type", strdup("application/json"));
    if (res->body) {
        free(res->body);
    }
    res->body = json_str;
    res->content_length = (int)strlen(json_str);
    res->status = HTTP_200_OK;

    return 0;
}

int router_mgnt_parse_request(struct router *router, struct cweb_context *ctx, http_request_t *req, http_response_t *res) {
    (void)ctx;
    if (req->method == -1) {
        return -1;
    }

    const char *code = http_kv_get(req->data, "code");
    if (!code) {
        fprintf(stderr, "[ERROR] Code is not provided.\n");
        return -1;
    }

    extern int write_and_compile(const char *module_dir, const char *filename, const char *code, char *error_buffer, size_t buffer_size);

    char* hash = NULL;
    {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        unsigned char hash_raw[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, code, strlen(code));
        SHA256_Final(hash_raw, &sha256);
#pragma GCC diagnostic pop

        hash = (char*)calloc(65, sizeof(char));
        if (!hash) {
            fprintf(stderr, "[ERROR] Memory allocation failed for hash.\n");
            return -1;
        }
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(hash + (i * 2), "%02x", hash_raw[i]);
        }
        hash[64] = 0;
    }

    char filename[256];
    snprintf(filename, sizeof(filename), "%s", hash);

    if (write_and_compile(router->module_dir, filename, code, res->body, HTTP_RESPONSE_SIZE) == -1) {
        fprintf(stderr, "[ERROR] Failed to register '%s' due to compilation error.\n", filename);
        free(hash);
        return -1;
    }

    char so_path[SO_PATH_MAX_LEN * 2];
    if (snprintf(so_path, sizeof(so_path), "%s/%s.so", router->module_dir, filename) >= (int)sizeof(so_path)) {
        fprintf(stderr, "[ERROR] Module path overflow.\n");
        free(hash);
        return -1;
    }

    free(hash);

    return router_register_module(router, ctx, so_path);
}
