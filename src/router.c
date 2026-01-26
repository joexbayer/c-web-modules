#include "router.h"
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DEFAULT_MODULE_DIR "modules"

int router_save_to_disk(struct router *router, const char* filename);
int router_load_from_disk(struct router *router, const char* filename, struct cweb_context *ctx);
void router_cleanup(struct router *router, struct cweb_context *ctx);

static int router_ensure_module_dir(const char *module_dir) {
    struct stat st;
    if (stat(module_dir, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 0;
        }
        fprintf(stderr, "[ERROR] Module dir exists but is not a directory: %s\n", module_dir);
        return -1;
    }
    if (mkdir(module_dir, 0755) != 0) {
        perror("[ERROR] Failed to create module directory");
        return -1;
    }
    return 0;
}

int router_init(struct router *router, struct ws_server *ws, const char *route_file, const char *module_dir, int purge_modules, struct cweb_context *ctx) {
    if (!router) {
        return -1;
    }

    router->count = 0;
    router->ws = ws;
    router->module_dir[0] = '\0';
    router->route_file[0] = '\0';
    router->purge_modules = purge_modules;

    if (module_dir && module_dir[0] != '\0') {
        strncpy(router->module_dir, module_dir, sizeof(router->module_dir) - 1);
    } else {
        strncpy(router->module_dir, DEFAULT_MODULE_DIR, sizeof(router->module_dir) - 1);
    }

    if (router_ensure_module_dir(router->module_dir) != 0) {
        return -1;
    }

    if (route_file && route_file[0] != '\0') {
        strncpy(router->route_file, route_file, sizeof(router->route_file) - 1);
    } else {
        if (snprintf(router->route_file, sizeof(router->route_file), "%s/routes.dat", router->module_dir) >= (int)sizeof(router->route_file)) {
            fprintf(stderr, "[ERROR] Route file path overflow\n");
            return -1;
        }
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
