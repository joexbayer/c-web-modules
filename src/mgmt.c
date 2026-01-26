#include "router.h"
#include <jansson.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
