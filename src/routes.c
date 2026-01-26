#include "router.h"
#include <pthread.h>
#include <regex.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

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
