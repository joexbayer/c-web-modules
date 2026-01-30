#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include <netinet/in.h>

#include "cweb.h"
#include "container.h"
#include "scheduler.h"
#include "db.h"
#include "crypto.h"
#include "router.h"
#include "ws.h"
#include "jobs.h"
#include "shutdown.h"
#include "active_conn.h"

typedef struct ssl_st SSL;
struct thread_pool;

struct connection {
    int sockfd;
    struct sockaddr_in address;
    SSL *ssl;
};

typedef enum env {
    DEV,
    PROD
} env_t;

typedef struct cors_config {
    const char *allow_origins;
    const char *allow_methods;
    const char *allow_headers;
    int allow_credentials;
    int max_age;
    int allow_all_origins;
    int allow_origin_list;
} cors_config_t;

struct server_config {
    uint16_t port;
    int thread_pool_size;
    char silent_mode;
    env_t environment;
    int shutdown_timeout_ms;
    shutdown_policy_t shutdown_policy;
    const char *admin_key;
    size_t admin_key_len;
    size_t max_body_bytes;
    char module_dir[SO_PATH_MAX_LEN];
    int purge_modules;
    cors_config_t cors;
};

struct server_state {
    struct cweb_context ctx;
    struct container cache;
    struct scheduler scheduler;
    struct sqldb database;
    struct crypto crypto;
    struct symbols symbols;
    struct router router;
    struct ws_server ws;
    job_system_t jobs;
    struct thread_pool *pool;
    active_conn_list_t active_conns;
    struct server_config config;
    atomic_int shutting_down;
    atomic_int active_clients;
};

struct client_task {
    struct server_state *state;
    struct connection *connection;
};

#endif // SERVER_H
