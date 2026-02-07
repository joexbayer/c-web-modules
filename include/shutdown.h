#ifndef SHUTDOWN_H
#define SHUTDOWN_H

#include <stdint.h>
#include <stdatomic.h>
#include <scheduler.h>
#include <pool.h>
#include <ws.h>
#include <router.h>
#include <container.h>
#include <db.h>
#include <crypto.h>
#include <jobs.h>
#include <active_conn.h>

typedef enum shutdown_policy {
    SHUTDOWN_POLICY_GRACEFUL = 0,
    SHUTDOWN_POLICY_FORCE = 1
} shutdown_policy_t;

typedef struct shutdown_context {
    int listen_fd;
    struct thread_pool *pool;
    struct scheduler *scheduler;
    struct ws_server *ws;
    struct router *router;
    job_system_t *jobs;
    cweb_context_t *ctx;
    struct crypto *crypto;
    struct sqldb *database;
    struct container *cache;
    active_conn_list_t *active_conns;
    atomic_int *active_clients;
    int timeout_ms;
    shutdown_policy_t policy;
} shutdown_context_t;

void shutdown_run(shutdown_context_t *shutdown_ctx);

#endif // SHUTDOWN_H
