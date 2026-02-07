#include "router.h"
#include <pthread.h>
#include <stdio.h>
#include <string.h>

int router_save_to_disk(struct router *router, const char* filename) {
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

int router_load_from_disk(struct router *router, const char* filename, struct cweb_context *ctx) {
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
