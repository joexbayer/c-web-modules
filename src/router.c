#include "http.h"
#include "cweb.h"
#include "router.h"
#include "ws.h"
#include "engine.h"
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include <container.h>
#include <regex.h>
#include <jansson.h>
#include <string.h>
#include <openssl/evp.h>
#include <stdlib.h>

#define MODULE_TAG "config"
#define ROUTE_FILE "modules/routes.dat"

static int router_save_to_disk(struct router *router, const char* filename);
static int router_load_from_disk(struct router *router, const char* filename, struct cweb_context *ctx);
static void router_release_routes(module_t *module);

static int router_compute_module_hash(const char *so_path, char *out, size_t out_size) {
    if (!so_path || !out || out_size < 65) {
        return -1;
    }

    FILE *fp = fopen(so_path, "rb");
    if (!fp) {
        return -1;
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        fclose(fp);
        return -1;
    }

    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(md_ctx);
        fclose(fp);
        return -1;
    }

    unsigned char buffer[4096];
    size_t read_bytes = 0;
    while ((read_bytes = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        if (EVP_DigestUpdate(md_ctx, buffer, read_bytes) != 1) {
            EVP_MD_CTX_free(md_ctx);
            fclose(fp);
            return -1;
        }
    }

    if (ferror(fp)) {
        EVP_MD_CTX_free(md_ctx);
        fclose(fp);
        return -1;
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(md_ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(md_ctx);
        fclose(fp);
        return -1;
    }

    EVP_MD_CTX_free(md_ctx);
    fclose(fp);

    if (hash_len < 32) {
        return -1;
    }

    for (size_t i = 0; i < 32; i++) {
        snprintf(out + (i * 2), out_size - (i * 2), "%02x", hash[i]);
    }
    out[64] = '\0';
    return 0;
}

static struct module_ref *module_ref_create(const char *so_path, module_t *module, void *handle) {
    struct module_ref *ref = calloc(1, sizeof(*ref));
    if (!ref) {
        return NULL;
    }

    ref->handle = handle;
    ref->module = module;
    ref->retired = 0;
    atomic_init(&ref->job_refs, 0);
    strncpy(ref->so_path, so_path, SO_PATH_MAX_LEN - 1);
    ref->so_path[SO_PATH_MAX_LEN - 1] = '\0';

    if (router_compute_module_hash(so_path, ref->module_hash, sizeof(ref->module_hash)) != 0) {
        snprintf(ref->module_hash, sizeof(ref->module_hash), "unknown");
    }

    return ref;
}

static void module_ref_destroy(struct module_ref *ref, struct cweb_context *ctx) {
    if (!ref) {
        return;
    }

    if (ref->module && ref->module->unload) {
        safe_execute_module_hook(ref->module->unload, ctx);
    }

    if (ref->module) {
        router_release_routes(ref->module);
    }

    if (ref->handle) {
        unlink(ref->so_path);
        dlclose(ref->handle);
    }

    free(ref);
}

static void router_retire_module_ref(struct router *router, struct module_ref *ref, struct cweb_context *ctx) {
    if (!router || !ref) {
        return;
    }

    if (atomic_load(&ref->job_refs) == 0) {
        module_ref_destroy(ref, ctx);
        return;
    }

    ref->retired = 1;
    pthread_mutex_lock(&router->retired_mutex);
    ref->next = router->retired;
    router->retired = ref;
    pthread_mutex_unlock(&router->retired_mutex);
}

void router_job_release(struct router *router, struct module_ref *ref, struct cweb_context *ctx) {
    if (!router || !ref) {
        return;
    }

    int refs = atomic_fetch_sub(&ref->job_refs, 1) - 1;
    if (refs > 0 || !ref->retired) {
        return;
    }

    pthread_mutex_lock(&router->retired_mutex);
    struct module_ref **cursor = &router->retired;
    while (*cursor) {
        if (*cursor == ref) {
            *cursor = ref->next;
            break;
        }
        cursor = &(*cursor)->next;
    }
    pthread_mutex_unlock(&router->retired_mutex);

    module_ref_destroy(ref, ctx);
}
static struct gateway_entry* find_gateway_entry(struct router *router, const char* module) {
    for (int i = 0; i < router->count; i++) {
        if (router->entries[i].ref && strcmp(router->entries[i].ref->module->name, module) == 0) {
            return &router->entries[i];
        }
    }
    return NULL;
}

void* router_resolve(struct router *router, const char* module, const char* symbol) {
    struct gateway_entry* entry = find_gateway_entry(router, module);
    if (!entry) {
        return NULL;
    }

    void* sym = dlsym(entry->ref->handle, symbol);
    if (!sym) {
        fprintf(stderr, "Error resolving symbol: %s\n", dlerror());
        return NULL;
    }

    return sym;
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
    http_kv_insert(res->headers, "Access-Control-Allow-Origin", strdup("*"));
    if (res->body) {
        free(res->body);
    }
    res->body = json_str;
    res->content_length = (int)strlen(json_str);
    res->status = HTTP_200_OK;

    return 0;
}

static int router_compile_routes(module_t *module) {
    for (int i = 0; i < module->size; i++) {
        struct route_info *entry = &module->routes[i];
        if (!entry->path || !entry->method) {
            continue;
        }

        if (entry->regex_compiled) {
            regfree(&entry->regex);
            entry->regex_compiled = 0;
        }

        char anchored_pattern[1024];
        snprintf(anchored_pattern, sizeof(anchored_pattern), "^%s$", entry->path);
        if (regcomp(&entry->regex, anchored_pattern, REG_EXTENDED | REG_NOSUB) != 0) {
            fprintf(stderr, "Invalid regex pattern: %s\n", anchored_pattern);
            return -1;
        }
        entry->regex_compiled = 1;
    }
    return 0;
}

static void router_release_routes(module_t *module) {
    for (int i = 0; i < module->size; i++) {
        struct route_info *entry = &module->routes[i];
        if (entry->regex_compiled) {
            regfree(&entry->regex);
            entry->regex_compiled = 0;
        }
    }
}

static int router_is_reserved_path(const char *path) {
    if (!path) {
        return 0;
    }
    if (strncmp(path, "/jobs", 5) != 0) {
        return 0;
    }
    return path[5] == '\0' || path[5] == '/';
}

static int router_module_has_reserved_paths(module_t *module) {
    if (!module) {
        return 0;
    }

    for (int i = 0; i < module->size; i++) {
        if (router_is_reserved_path(module->routes[i].path)) {
            return 1;
        }
    }

    for (int i = 0; i < module->ws_size; i++) {
        if (router_is_reserved_path(module->websockets[i].path)) {
            return 1;
        }
    }

    return 0;
}

struct route router_find(struct router *router, const char *route, const char *method) {
    pthread_rwlock_rdlock(&router->rwlock);
    for (int i = 0; i < router->count; i++) {
        pthread_rwlock_rdlock(&router->entries[i].rwlock);
        if (!router->entries[i].ref) {
            pthread_rwlock_unlock(&router->entries[i].rwlock);
            continue;
        }
        for (int j = 0; j < router->entries[i].ref->module->size; j++) {
            struct route_info *entry = &router->entries[i].ref->module->routes[j];
            if (entry->path == NULL || entry->method == NULL) {
                continue;
            }

            if (strcmp(method, entry->method) == 0) {
                if (!entry->regex_compiled) {
                    pthread_rwlock_unlock(&router->entries[i].rwlock);
                    pthread_rwlock_unlock(&router->rwlock);
                    return (struct route){0};
                }

                if (regexec(&entry->regex, route, 0, NULL, 0) == 0) {
                    pthread_rwlock_unlock(&router->rwlock);
                    return (struct route){
                        .route = entry,
                        .rwlock = &router->entries[i].rwlock
                    };
                }
            }
        }
        pthread_rwlock_unlock(&router->entries[i].rwlock);
    }
    pthread_rwlock_unlock(&router->rwlock);
    return (struct route){0};
}

struct ws_route router_ws_find(struct router *router, const char *route) {
    pthread_rwlock_rdlock(&router->rwlock);
    for (int i = 0; i < router->count; i++) {
        pthread_rwlock_rdlock(&router->entries[i].rwlock);
        if (!router->entries[i].ref) {
            pthread_rwlock_unlock(&router->entries[i].rwlock);
            continue;
        }
        for (int j = 0; j < router->entries[i].ref->module->ws_size; j++) {
            if (strcmp(router->entries[i].ref->module->websockets[j].path, route) == 0) {
                pthread_rwlock_unlock(&router->rwlock);
                return (struct ws_route){
                    .info = &router->entries[i].ref->module->websockets[j],
                    .rwlock = &router->entries[i].rwlock
                };
            }
        }
        pthread_rwlock_unlock(&router->entries[i].rwlock);
    }
    pthread_rwlock_unlock(&router->rwlock);
    return (struct ws_route){0};
}

struct job_route router_job_find(struct router *router, const char *module_name, const char *job_name) {
    if (!router || !module_name || !job_name) {
        return (struct job_route){0};
    }

    pthread_rwlock_rdlock(&router->rwlock);
    for (int i = 0; i < router->count; i++) {
        pthread_rwlock_rdlock(&router->entries[i].rwlock);
        if (!router->entries[i].ref) {
            pthread_rwlock_unlock(&router->entries[i].rwlock);
            continue;
        }

        module_t *module = router->entries[i].ref->module;
        if (strcmp(module->name, module_name) != 0) {
            pthread_rwlock_unlock(&router->entries[i].rwlock);
            continue;
        }

        for (int j = 0; j < module->job_size; j++) {
            if (!module->jobs[j].name) {
                continue;
            }
            if (strcmp(module->jobs[j].name, job_name) == 0) {
                atomic_fetch_add(&router->entries[i].ref->job_refs, 1);
                struct job_route result = {
                    .job = &module->jobs[j],
                    .ref = router->entries[i].ref
                };
                snprintf(result.module_hash, sizeof(result.module_hash), "%s", router->entries[i].ref->module_hash);
                pthread_rwlock_unlock(&router->entries[i].rwlock);
                pthread_rwlock_unlock(&router->rwlock);
                return result;
            }
        }

        pthread_rwlock_unlock(&router->entries[i].rwlock);
        pthread_rwlock_unlock(&router->rwlock);
        return (struct job_route){0};
    }

    pthread_rwlock_unlock(&router->rwlock);
    return (struct job_route){0};
}

static int update_gateway_entry(struct router *router, int index, const char* so_path, module_t* module, void* handle, struct cweb_context *ctx) {
    pthread_rwlock_wrlock(&router->entries[index].rwlock);

    if (router_compile_routes(module) != 0) {
        router_release_routes(module);
        dlclose(handle);
        pthread_rwlock_unlock(&router->entries[index].rwlock);
        return -1;
    }

    struct module_ref *new_ref = module_ref_create(so_path, module, handle);
    if (!new_ref) {
        router_release_routes(module);
        dlclose(handle);
        pthread_rwlock_unlock(&router->entries[index].rwlock);
        return -1;
    }

    struct module_ref *old_ref = router->entries[index].ref;
    router->entries[index].ref = new_ref;

    for (int i = 0; router->entries[index].ref && i < router->entries[index].ref->module->ws_size; i++) {
        ws_update_container(router->ws, router->entries[index].ref->module->websockets[i].path, &router->entries[index].ref->module->websockets[i]);
    }

    if (old_ref) {
        router_retire_module_ref(router, old_ref, ctx);
    }

    if (router->entries[index].ref->module->onload) {
        safe_execute_module_hook(router->entries[index].ref->module->onload, ctx);
    }

    pthread_rwlock_unlock(&router->entries[index].rwlock);
    printf("[INFO   ] Module %s is updated.\n", module->name);
    return 0;
}

static void* load_shared_object(const char* so_path) {
    void* handle = dlopen(so_path, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "[ERROR] Error loading shared object: %s\n", dlerror());
        return NULL;
    }
    return handle;
}

static int load_from_shared_object(struct router *router, const char* so_path, struct cweb_context *ctx) {
    void* handle = load_shared_object(so_path);
    if (!handle) {
        return -1;
    }

    module_t* module = dlsym(handle, MODULE_TAG);
    if (!module || strnlen(module->name, 128) == 0) {
        fprintf(stderr, "[ERROR] Error finding module definition: %s\n", dlerror());
        dlclose(handle);
        return -1;
    }

    if (router->count >= ROUTER_MAX_MODULES) {
        fprintf(stderr, "[ERROR] Gateway is full\n");
        dlclose(handle);
        return -1;
    }

    if (router_module_has_reserved_paths(module)) {
        fprintf(stderr, "[ERROR] Module uses reserved /jobs path\n");
        dlclose(handle);
        return -1;
    }

    pthread_rwlock_rdlock(&router->rwlock);

    for (int i = 0; i < router->count; i++) {
        if (!router->entries[i].ref) {
            continue;
        }
        if (strcmp(router->entries[i].ref->module->name, module->name) == 0) {
            if (strcmp(router->entries[i].ref->so_path, so_path) == 0) {
                pthread_rwlock_unlock(&router->rwlock);
                dlclose(handle);
                return 0;
            }
            int ret = update_gateway_entry(router, i, so_path, module, handle, ctx);

            pthread_rwlock_unlock(&router->rwlock);
            return ret;
        }
    }

    printf("[INFO   ] Module %s is loaded.\n", module->name);

    if (router_compile_routes(module) != 0) {
        pthread_rwlock_unlock(&router->rwlock);
        dlclose(handle);
        return -1;
    }

    for (int i = 0; i < module->size; i++) {
        struct route_info *new_route = &module->routes[i];
        if (!new_route->path || !new_route->method) {
            continue;
        }

        for (int j = 0; j < router->count; j++) {
            pthread_rwlock_rdlock(&router->entries[j].rwlock);
            if (!router->entries[j].ref) {
                pthread_rwlock_unlock(&router->entries[j].rwlock);
                continue;
            }
            for (int k = 0; k < router->entries[j].ref->module->size; k++) {
                struct route_info *existing = &router->entries[j].ref->module->routes[k];
                if (!existing->path || !existing->method || !existing->regex_compiled) {
                    continue;
                }

                if (strcmp(existing->method, new_route->method) == 0 &&
                    regexec(&existing->regex, new_route->path, 0, NULL, 0) == 0) {
                    pthread_rwlock_unlock(&router->entries[j].rwlock);
                    pthread_rwlock_unlock(&router->rwlock);
                    fprintf(stderr, "[ERROR] Route conflict: %s %s\n", new_route->method, new_route->path);
                    router_release_routes(module);
                    dlclose(handle);
                    return -1;
                }
            }
            pthread_rwlock_unlock(&router->entries[j].rwlock);
        }
    }

    pthread_rwlock_init(&router->entries[router->count].rwlock, NULL);
    update_gateway_entry(router, router->count, so_path, module, handle, ctx);
    router->count++;

    pthread_rwlock_unlock(&router->rwlock);

    return 0;
}

int router_register_module(struct router *router, struct cweb_context *ctx, const char* so_path) {
    return load_from_shared_object(router, so_path, ctx);
}

static void router_cleanup(struct router *router, struct cweb_context *ctx) {
    for (int i = 0; i < router->count; i++) {
        pthread_rwlock_wrlock(&router->entries[i].rwlock);
        if (router->entries[i].ref) {
            module_ref_destroy(router->entries[i].ref, ctx);
            router->entries[i].ref = NULL;
        }
        pthread_rwlock_unlock(&router->entries[i].rwlock);
        pthread_rwlock_destroy(&router->entries[i].rwlock);
    }

    pthread_mutex_lock(&router->retired_mutex);
    struct module_ref *ref = router->retired;
    while (ref) {
        struct module_ref *next = ref->next;
        module_ref_destroy(ref, ctx);
        ref = next;
    }
    router->retired = NULL;
    pthread_mutex_unlock(&router->retired_mutex);
}

static int router_save_to_disk(struct router *router, const char* filename) {
    int ret;
    pthread_mutex_lock(&router->save_mutex);

    FILE *fp = fopen(filename, "wb");
    if (fp == NULL) {
        perror("Error creating route file");
        pthread_mutex_unlock(&router->save_mutex);
        return -1;
    }

    struct {
        char magic[5];
        int count;
    } header = {
        .magic = "CWEB",
        .count = router->count
    };

    ret = (int)fwrite(&header, sizeof(header), 1, fp);
    if (ret != 1) {
        fprintf(stderr, "Error writing route file header\n");
        fclose(fp);
        pthread_mutex_unlock(&router->save_mutex);
        return -1;
    }

    for (int i = 0; i < router->count; i++) {
        const char *path = router->entries[i].ref ? router->entries[i].ref->so_path : "";
        ret = (int)fwrite(path, SO_PATH_MAX_LEN, 1, fp);
        if (ret != 1) {
            fprintf(stderr, "Error writing route file entry\n");
            fclose(fp);
            pthread_mutex_unlock(&router->save_mutex);
            return -1;
        }
    }

    fclose(fp);
    pthread_mutex_unlock(&router->save_mutex);
    return 0;
}

static int router_load_from_disk(struct router *router, const char* filename, struct cweb_context *ctx) {
    int ret;
    pthread_mutex_lock(&router->save_mutex);
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        pthread_mutex_unlock(&router->save_mutex);
        return -1;
    }

    struct {
        char magic[5];
        int count;
    } header;

    ret = (int)fread(&header, sizeof(header), 1, fp);
    if (ret != 1) {
        fprintf(stderr, "Error reading route file header\n");
        fclose(fp);
        pthread_mutex_unlock(&router->save_mutex);
        return -1;
    }

    if (strcmp(header.magic, "CWEB") != 0) {
        fprintf(stderr, "Invalid route file\n");
        fclose(fp);
        pthread_mutex_unlock(&router->save_mutex);
        return -1;
    }

    for (int i = 0; i < header.count; i++) {
        char so_path[SO_PATH_MAX_LEN];
        ret = (int)fread(so_path, SO_PATH_MAX_LEN, 1, fp);
        if (ret != 1) {
            fprintf(stderr, "Error reading route file entry\n");
            fclose(fp);
            pthread_mutex_unlock(&router->save_mutex);
            return -1;
        }

        router_register_module(router, ctx, so_path);
    }

    fclose(fp);
    pthread_mutex_unlock(&router->save_mutex);
    return 0;
}

int router_init(struct router *router, struct ws_server *ws, const char *route_file, struct cweb_context *ctx) {
    if (!router) {
        return -1;
    }

    router->count = 0;
    router->ws = ws;
    router->route_file[0] = '\0';

    if (route_file) {
        strncpy(router->route_file, route_file, sizeof(router->route_file) - 1);
    } else {
        strncpy(router->route_file, ROUTE_FILE, sizeof(router->route_file) - 1);
    }

    pthread_rwlock_init(&router->rwlock, NULL);
    pthread_mutex_init(&router->save_mutex, NULL);
    pthread_mutex_init(&router->retired_mutex, NULL);
    router->retired = NULL;
    router->module_handle = NULL;

    router->module_handle = dlopen("./libs/libmodule.so", RTLD_GLOBAL | RTLD_LAZY);
    if (!router->module_handle) {
        fprintf(stderr, "Error loading dependency libmodule: %s\n", dlerror());
    }

    router_load_from_disk(router, router->route_file, ctx);
    printf("[STARTUP] Router initialized\n");
    return 0;
}

void router_shutdown(struct router *router, struct cweb_context *ctx) {
    if (!router) {
        return;
    }

    router_save_to_disk(router, router->route_file);
    router_cleanup(router, ctx);
    if (router->module_handle) {
        dlclose(router->module_handle);
        router->module_handle = NULL;
    }
    pthread_mutex_destroy(&router->save_mutex);
    pthread_mutex_destroy(&router->retired_mutex);
    pthread_rwlock_destroy(&router->rwlock);
    printf("[SHUTDOWN] Router closed\n");
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

    extern int write_and_compile(const char *filename, const char *code, char *error_buffer, size_t buffer_size);

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

    if (write_and_compile(filename, code, res->body, HTTP_RESPONSE_SIZE) == -1) {
        fprintf(stderr, "[ERROR] Failed to register '%s' due to compilation error.\n", filename);
        free(hash);
        return -1;
    }

    char so_path[SO_PATH_MAX_LEN + 12];
    snprintf(so_path, sizeof(so_path), "modules/%s.so", filename);

    free(hash);

    return router_register_module(router, ctx, so_path);
}
