#include "router.h"
#include "engine.h"
#include "ws.h"
#include "jobs.h"
#include <dlfcn.h>
#include <pthread.h>
#include <regex.h>
#include <openssl/evp.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MODULE_TAG "config"

static int router_compile_routes(module_t *module);
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

static void module_ref_destroy(struct module_ref *ref, struct cweb_context *ctx, int purge_modules) {
    if (!ref) {
        return;
    }

    if (ctx && ctx->jobs) {
        jobs_unregister_module(ctx->jobs, ref);
    }

    if (ref->module && ref->module->unload) {
        safe_execute_module_hook(ref->module->unload, ctx);
    }

    if (ref->module) {
        router_release_routes(ref->module);
    }

    if (ref->handle) {
        if (purge_modules) {
            unlink(ref->so_path);
        }
        dlclose(ref->handle);
    }

    free(ref);
}

static void router_retire_module_ref(struct router *router, struct module_ref *ref, struct cweb_context *ctx) {
    if (!router || !ref) {
        return;
    }

    if (atomic_load(&ref->job_refs) == 0) {
        module_ref_destroy(ref, ctx, router->purge_modules);
        return;
    }

    ref->retired = 1;
    pthread_mutex_lock(&router->retired_mutex);
    ref->next = router->retired;
    router->retired = ref;
    pthread_mutex_unlock(&router->retired_mutex);
}

void router_cleanup(struct router *router, struct cweb_context *ctx) {
    for (int i = 0; i < router->count; i++) {
        pthread_rwlock_wrlock(&router->entries[i].rwlock);
        if (router->entries[i].ref) {
            module_ref_destroy(router->entries[i].ref, ctx, router->purge_modules);
            router->entries[i].ref = NULL;
        }
        pthread_rwlock_unlock(&router->entries[i].rwlock);
        pthread_rwlock_destroy(&router->entries[i].rwlock);
    }

    pthread_mutex_lock(&router->retired_mutex);
    struct module_ref *ref = router->retired;
    while (ref) {
        struct module_ref *next = ref->next;
        module_ref_destroy(ref, ctx, router->purge_modules);
        ref = next;
    }
    router->retired = NULL;
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

    module_ref_destroy(ref, ctx, router->purge_modules);
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

    if (ctx && ctx->jobs && ctx->jobs->job_registry) {
        if (jobs_register_module(ctx->jobs, new_ref) != 0) {
            fprintf(stderr, "[ERROR] Failed to register jobs for module %s\n", module->name);
        }
    }

    if (old_ref) {
        if (ctx && ctx->jobs && ctx->jobs->job_registry) {
            jobs_unregister_module(ctx->jobs, old_ref);
        }
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
