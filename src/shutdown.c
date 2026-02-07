#include <shutdown.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>

#define SHUTDOWN_POLL_MS 50

static int shutdown_elapsed_ms(const struct timespec *start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long sec = now.tv_sec - start->tv_sec;
    long nsec = now.tv_nsec - start->tv_nsec;
    return (int)(sec * 1000 + nsec / 1000000);
}

static void shutdown_sleep_ms(int ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static int shutdown_is_idle(shutdown_context_t *shutdown_ctx) {
    int pending_pool = 0;
    int pending_scheduler = 0;
    int active_clients = 0;

    if (shutdown_ctx->pool) {
        pending_pool = thread_pool_pending_count(shutdown_ctx->pool);
    }

    if (shutdown_ctx->scheduler) {
        pending_scheduler = scheduler_pending_count(shutdown_ctx->scheduler);
    }

    if (shutdown_ctx->active_clients) {
        active_clients = atomic_load(shutdown_ctx->active_clients);
    }

    return pending_pool == 0 && pending_scheduler == 0 && active_clients == 0;
}

void shutdown_run(shutdown_context_t *shutdown_ctx) {
    if (!shutdown_ctx) {
        return;
    }

    if (shutdown_ctx->listen_fd >= 0) {
        shutdown(shutdown_ctx->listen_fd, SHUT_RDWR);
        close(shutdown_ctx->listen_fd);
        shutdown_ctx->listen_fd = -1;
    }

    if (shutdown_ctx->active_conns) {
        active_conn_close_all(shutdown_ctx->active_conns);
    }

    if (shutdown_ctx->pool) {
        thread_pool_request_stop(shutdown_ctx->pool);
    }

    if (shutdown_ctx->scheduler) {
        scheduler_request_stop(shutdown_ctx->scheduler, 1);
    }

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);

    while (!shutdown_is_idle(shutdown_ctx)) {
        if (shutdown_ctx->timeout_ms <= 0) {
            break;
        }
        if (shutdown_ctx->timeout_ms > 0 && shutdown_elapsed_ms(&start) >= shutdown_ctx->timeout_ms) {
            break;
        }
        shutdown_sleep_ms(SHUTDOWN_POLL_MS);
    }

    if (!shutdown_is_idle(shutdown_ctx) && shutdown_ctx->policy == SHUTDOWN_POLICY_FORCE) {
        if (shutdown_ctx->pool) {
            thread_pool_cancel_all(shutdown_ctx->pool);
        }
        if (shutdown_ctx->scheduler) {
            scheduler_cancel(shutdown_ctx->scheduler);
        }
    }

    if (shutdown_ctx->pool) {
        if (shutdown_ctx->policy == SHUTDOWN_POLICY_FORCE && shutdown_ctx->timeout_ms <= 0) {
            shutdown_ctx->pool = NULL;
        } else {
            thread_pool_destroy(shutdown_ctx->pool);
            shutdown_ctx->pool = NULL;
        }
    }

    if (shutdown_ctx->router) {
        router_shutdown(shutdown_ctx->router, shutdown_ctx->ctx);
        shutdown_ctx->router = NULL;
    }

    if (shutdown_ctx->jobs) {
        jobs_shutdown(shutdown_ctx->jobs);
        shutdown_ctx->jobs = NULL;
    }

    if (shutdown_ctx->ws) {
        ws_shutdown(shutdown_ctx->ws, shutdown_ctx->ctx);
        shutdown_ctx->ws = NULL;
    }

    if (shutdown_ctx->crypto) {
        crypto_shutdown(shutdown_ctx->crypto);
        shutdown_ctx->crypto = NULL;
    }

    if (shutdown_ctx->database) {
        sqldb_shutdown(shutdown_ctx->database);
        shutdown_ctx->database = NULL;
    }

    if (shutdown_ctx->scheduler) {
        scheduler_shutdown(shutdown_ctx->scheduler);
        shutdown_ctx->scheduler = NULL;
    }

    if (shutdown_ctx->cache) {
        container_shutdown(shutdown_ctx->cache);
        shutdown_ctx->cache = NULL;
    }

    if (shutdown_ctx->active_conns) {
        active_conn_shutdown(shutdown_ctx->active_conns);
        shutdown_ctx->active_conns = NULL;
    }
}
