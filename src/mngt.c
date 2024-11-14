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

/* static prototypes */
static int write_and_compile(const char *filename, const char *code);

/**
 * Write code to a temporary file and compile it to .so
 * @param filename Name of the file
 * @param code Code to write to the file
 */
int write_and_compile(const char *filename, const char *code) {
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

    /* Need enough space for both source, output and command. */
    char command[SO_PATH_MAX_LEN*2 + 100];
    snprintf(command, sizeof(command), "gcc -fPIC -L./libs -lmodule -shared -I./include -o %s %s", so_path, source_path);
    if (system(command) != 0) {
        fprintf(stderr, "Compilation failed for %s -> %s\n", source_path, so_path);
        unlink(source_path);
        return -1;
    }
    unlink(source_path);

    //dbgprint("Compilation successful for %s\n", filename);
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
static int mgnt_register_module(char* code) {
    if(code == NULL ) {
        fprintf(stderr, "Code is NULL\n");
        return -1;
    }

    char* hash = hash_code(code);   
    if(hash == NULL) {
        fprintf(stderr, "Failed to hash code\n");
        return -1;
    }

    char filename[256];
    snprintf(filename, sizeof(filename), "%s", hash);

    if (write_and_compile(filename, code) != 0) {
        fprintf(stderr, "Failed to register '%s' due to compilation error.\n", filename);
        return -1;
    }

    char so_path[SO_PATH_MAX_LEN];
    snprintf(so_path, sizeof(so_path), "%s/%s.so", TMP_DIR, filename);

    free(hash);

    return route_register_module(so_path);
}

int mgnt_parse_request(struct http_request *req) {
    if (req->method == -1) {
        return -1;
    }

    return mgnt_register_module(map_get(req->data, "code"));;
}