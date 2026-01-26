#include "http.h"
#include "router.h"
#include "cweb.h"

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
