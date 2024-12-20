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
#include <openssl/sha.h>

#define TMP_DIR "modules"
#ifdef __APPLE__
    #define CFLAGS "-fPIC -shared -I./include -I/opt/homebrew/opt/jansson/include -I/opt/homebrew/opt/openssl@3/include"
    #define LIBS "-L./libs -lmodule -L/opt/homebrew/opt/jansson/lib -ljansson -lsqlite3 -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto"
#elif __linux__
    #define CFLAGS "-fPIC -shared -I./include -Wl,-rpath=./libs" /* -Wl,-rpath needed for archlinux. */
    #define LIBS "-L./libs -lmodule -ljansson -lsqlite3"
#else
    #error "Unsupported platform"
#endif

/**
 * Write code to a temporary file and compile it to .so
 * @param filename Name of the file
 * @param code Code to write to the file
 */
int write_and_compile(const char *filename, const char *code, char *error_buffer, size_t buffer_size) {
    char source_path[SO_PATH_MAX_LEN], so_path[SO_PATH_MAX_LEN];
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

    char command[SO_PATH_MAX_LEN * 2 + 200];
    snprintf(command, sizeof(command), "gcc "LIBS" "CFLAGS"  -o %s %s 2>&1", so_path, source_path);

    FILE *gcc_output = popen(command, "r");
    if (gcc_output == NULL) {
        perror("Error running gcc");
        unlink(source_path);
        return -1;
    }

    /* Read gcc output into the error buffer */
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

/**
 * Hash code to a SHA256 hash
 * Used to create a unique hash for each code snippet
 * @param code Code to hash
 * @return Hashed code
 */
static char* hash_code(char* code) {
// Disable deprecation warning for SHA256, probably should fix this...
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, code, strlen(code));
    SHA256_Final(hash, &sha256);

    char* hash_str = (char*)malloc(65);
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash_str + (i * 2), "%02x", hash[i]);
    }
    hash_str[64] = 0;

#pragma GCC diagnostic pop

    return hash_str;
}

/**
 * Register a route with the given code
 * Creates a hash of the code and compiles it to a .so file
 * @param route Route to register
 * @param code Code to register
 * @param func_name Function name to call
 * @param method HTTP method
 * @return 0 on success, -1 on failure
 */
static int mgnt_register_module(struct http_response *req, char* code) {
    if(code == NULL ) {
        fprintf(stderr, "[ERROR] Code is not provided.\n");
        return -1;
    }

    char* hash = hash_code(code);   
    if(hash == NULL) {
        fprintf(stderr, "[ERROR] Failed to hash code\n");
        return -1;
    }

    char filename[256];
    snprintf(filename, sizeof(filename), "%s", hash);

    if (write_and_compile(filename, code, req->body, HTTP_RESPONSE_SIZE) == -1) {
        fprintf(stderr, "[ERROR] Failed to register '%s' due to compilation error.\n", filename);
        return -1;
    }

    char so_path[SO_PATH_MAX_LEN + 12];
    snprintf(so_path, sizeof(so_path), "%s/%s.so", TMP_DIR, filename);

    free(hash);

    return route_register_module(so_path);
}

int mgnt_parse_request(struct http_request *req, struct http_response *res) {
    if (req->method == -1) {
        return -1;
    }

    return mgnt_register_module(res, map_get(req->data, "code"));;
}