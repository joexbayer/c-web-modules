#include "server.h"
#include "engine.h"
#include "pool.h"
#include "shutdown.h"
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static const char* allowed_management_commands[] = {
    "reload",
    "shutdown",
    "status",
    "routes",
    "modules",
    "help"
};

static const char* allowed_ip_prefixes[] = {
    "192.168.",
    "10.0.",
    "172.16."
};

void server_load_shutdown_policy(struct server_state *state);
void server_set_shutdown_policy(struct server_state *state, shutdown_policy_t policy);
void server_load_auth_config(struct server_state *state);
void server_set_cors_defaults(struct server_state *state);
int server_init_services(struct server_state *state);
struct connection server_init_socket(uint16_t port);
struct connection* server_accept(struct server_state *state, struct connection s);
void thread_handle_client(void *arg);

#define INIT_OPTIONS (OPENSSL_INIT_NO_ATEXIT)
static void openssl_init_wrapper(void) {
    if (OPENSSL_init_crypto(INIT_OPTIONS, NULL) == 0) {
        fprintf(stderr, "[ERROR] Failed to initialize OpenSSL\n");
        exit(EXIT_FAILURE);
    }
}

static volatile sig_atomic_t stop = 0;
static void server_signal_handler(int sig) {
    (void)sig;
    stop = 1;
}

int main(int argc, char *argv[]) {
    (void)allowed_management_commands;
    (void)allowed_ip_prefixes;

    struct server_state state;
    memset(&state, 0, sizeof(state));
    atomic_init(&state.active_clients, 0);

    state.config.port = DEFAULT_PORT;
    state.config.thread_pool_size = 0;
    state.config.silent_mode = 0;
    state.config.purge_modules = 0;
    snprintf(state.config.module_dir, sizeof(state.config.module_dir), "%s", "modules");
#ifdef PRODUCTION
    state.config.environment = PROD;
#else
    state.config.environment = DEV;
#endif
    server_load_shutdown_policy(&state);
    server_load_auth_config(&state);
    server_set_cors_defaults(&state);

    int opt;
    static struct option long_options[] = {
        {"module-dir", required_argument, NULL, 'm'},
        {"purge-modules", no_argument, NULL, 'P'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "p:t:sFm:P", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                state.config.port = (uint16_t)atoi(optarg);
                break;
            case 't':
                state.config.thread_pool_size = atoi(optarg);
                break;
            case 's':
                state.config.silent_mode = 1;
                break;
            case 'F':
                server_set_shutdown_policy(&state, SHUTDOWN_POLICY_FORCE);
                break;
            case 'm':
                snprintf(state.config.module_dir, sizeof(state.config.module_dir), "%s", optarg);
                break;
            case 'P':
                state.config.purge_modules = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s [-p port] [-t thread_pool_size] [-s (silent mode)] [-F (force shutdown)] [--module-dir path] [--purge-modules]\n", argv[0]);
        }
    }

    engine_init();

#ifdef PRODUCTION
    printf("[SERVER] SSL context initialization in progress\n");
#endif

    int num_cores = (int)sysconf(_SC_NPROCESSORS_ONLN);
    printf("[SERVER] Detected %d cores\n", num_cores);

    CRYPTO_ONCE openssl_once = CRYPTO_ONCE_STATIC_INIT;
    if (!CRYPTO_THREAD_run_once(&openssl_once, openssl_init_wrapper)) {
        fprintf(stderr, "[ERROR] Failed to run OpenSSL initialization\n");
        exit(EXIT_FAILURE);
    }

    struct sigaction sa;
    sa.sa_handler = server_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (server_init_services(&state) != 0) {
        fprintf(stderr, "[ERROR] Failed to initialize services\n");
        return 1;
    }

    struct connection s = server_init_socket(state.config.port);

#ifdef PRODUCTION
    state.pool = thread_pool_init(state.config.thread_pool_size ? state.config.thread_pool_size : num_cores * DEFAULT_PROD_THREAD_POOL_MULTIPLIER);
#else
    state.pool = thread_pool_init(state.config.thread_pool_size ? state.config.thread_pool_size : DEFAULT_DEV_THREAD_POOL_SIZE);
#endif
    if (state.pool == NULL) {
        fprintf(stderr, "[ERROR] Failed to initialize thread pool\n");
        shutdown_context_t fail_shutdown_ctx = {
            .listen_fd = -1,
            .pool = NULL,
            .scheduler = &state.scheduler,
            .ws = &state.ws,
            .router = &state.router,
            .jobs = &state.jobs,
            .ctx = &state.ctx,
            .crypto = &state.crypto,
            .database = &state.database,
            .cache = &state.cache,
            .active_clients = &state.active_clients,
            .timeout_ms = state.config.shutdown_timeout_ms,
            .policy = state.config.shutdown_policy
        };
        shutdown_run(&fail_shutdown_ctx);
        return 1;
    }

    printf("\n Version: %s\n", "0.0.1");
    printf(" Thread Pool Size: %d\n", state.pool->max_threads);
    printf(" Environment: %s\n", state.config.environment == PROD ? "Production" : "Development");
    printf(" PID: %d\n", getpid());
    printf(" Listening on %s://%s:%d\n", state.config.environment == PROD ? "https" : "http", inet_ntoa(s.address.sin_addr), ntohs(s.address.sin_port));
    while (!stop) {
        struct connection *client = server_accept(&state, s);
        if (client == NULL) {
            if (stop) {
                break;
            }
            if (errno == EINTR) {
                if (stop) {
                    break;
                }
                continue;
            }
            perror("Error accepting client");
            continue;
        }
        if (!state.config.silent_mode) {
            printf("[SERVER] Accepted connection from %s:%d\n", inet_ntoa(client->address.sin_addr), ntohs(client->address.sin_port));
        }

        struct client_task *task = malloc(sizeof(*task));
        if (!task) {
            close(client->sockfd);
            free(client);
            continue;
        }
        task->state = &state;
        task->connection = client;

        thread_pool_add_task(state.pool, thread_handle_client, task);
    }

    shutdown_context_t shutdown_ctx = {
        .listen_fd = s.sockfd,
        .pool = state.pool,
        .scheduler = &state.scheduler,
        .ws = &state.ws,
        .router = &state.router,
        .jobs = &state.jobs,
        .ctx = &state.ctx,
        .crypto = &state.crypto,
        .database = &state.database,
        .cache = &state.cache,
        .active_clients = &state.active_clients,
        .timeout_ms = state.config.shutdown_timeout_ms,
        .policy = state.config.shutdown_policy
    };

    shutdown_run(&shutdown_ctx);
    printf("[SERVER] Server shutting down gracefully.\n");

    return 0;
}
