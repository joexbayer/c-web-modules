#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <limits.h>
#include <stdatomic.h>

#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "http.h"
#include "router.h"
#include "cweb.h"
#include "db.h"
#include "scheduler.h"
#include "pool.h"
#include "crypto.h"
#include "engine.h"
#include "ws.h"
#include "jobs.h"
#include "container.h"
#include "shutdown.h"

#define DEFAULT_PORT 8080
#define ACCEPT_BACKLOG 128
#define MODULE_URL "/mgnt"
#define REQUEST_BUFFER_SIZE (8 * 1024)

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

struct connection {
    int sockfd;
    struct sockaddr_in address;
    SSL *ssl;
};

typedef enum env {
    DEV,
    PROD
} env_t;

struct server_config {
    uint16_t port;
    int thread_pool_size;
    char silent_mode;
    env_t environment;
    int shutdown_timeout_ms;
    shutdown_policy_t shutdown_policy;
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
    struct server_config config;
    atomic_int active_clients;
};

struct client_task {
    struct server_state *state;
    struct connection *connection;
};

static void* server_resolve(void *user_data, const char* module, const char* symbol) {
    struct router *router = (struct router *)user_data;
    return router_resolve(router, module, symbol);
}

static void server_load_shutdown_policy(struct server_state *state) {
    state->config.shutdown_timeout_ms = 5000;
    state->config.shutdown_policy = SHUTDOWN_POLICY_GRACEFUL;

    const char *timeout_env = getenv("CWEB_SHUTDOWN_TIMEOUT_MS");
    if (timeout_env) {
        int timeout_ms = atoi(timeout_env);
        if (timeout_ms >= 0) {
            state->config.shutdown_timeout_ms = timeout_ms;
        }
    }

    const char *force_env = getenv("CWEB_SHUTDOWN_FORCE");
    if (force_env && atoi(force_env) != 0) {
        state->config.shutdown_policy = SHUTDOWN_POLICY_FORCE;
    }
}

static void server_set_shutdown_policy(struct server_state *state, shutdown_policy_t policy) {
    state->config.shutdown_policy = policy;
}

static int server_init_services(struct server_state *state) {
    if (container_init(&state->cache, 32) != 0) {
        return -1;
    }

    if (scheduler_init(&state->scheduler, 0) != 0) {
        container_shutdown(&state->cache);
        return -1;
    }

    if (sqldb_init(&state->database, "db.sqlite3") != 0) {
        scheduler_shutdown(&state->scheduler);
        container_shutdown(&state->cache);
        return -1;
    }

    int crypto_ok = crypto_init(&state->crypto, NULL, NULL);
    if (crypto_ok != 0 && state->config.environment == PROD) {
        sqldb_shutdown(&state->database);
        scheduler_shutdown(&state->scheduler);
        container_shutdown(&state->cache);
        return -1;
    }

    state->ctx.cache = &state->cache;
    state->ctx.scheduler = &state->scheduler;
    state->ctx.database = &state->database;
    state->ctx.crypto = &state->crypto;
    state->symbols.user_data = &state->router;
    state->symbols.resolv = server_resolve;
    state->ctx.symbols = &state->symbols;
    state->ctx.jobs = &state->jobs;

    if (ws_init(&state->ws) != 0) {
        crypto_shutdown(&state->crypto);
        sqldb_shutdown(&state->database);
        scheduler_shutdown(&state->scheduler);
        container_shutdown(&state->cache);
        return -1;
    }

    if (router_init(&state->router, &state->ws, NULL, &state->ctx) != 0) {
        ws_shutdown(&state->ws, &state->ctx);
        crypto_shutdown(&state->crypto);
        sqldb_shutdown(&state->database);
        scheduler_shutdown(&state->scheduler);
        container_shutdown(&state->cache);
        return -1;
    }

    if (jobs_init(&state->jobs, &state->ctx, &state->router, &state->ws) != 0) {
        router_shutdown(&state->router, &state->ctx);
        ws_shutdown(&state->ws, &state->ctx);
        crypto_shutdown(&state->crypto);
        sqldb_shutdown(&state->database);
        scheduler_shutdown(&state->scheduler);
        container_shutdown(&state->cache);
        return -1;
    }

    return 0;
}


static struct connection server_init_socket(uint16_t port) {
    struct connection s;
    s.sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (s.sockfd == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(s.sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
        perror("setsockopt failed");
        close(s.sockfd);
        exit(EXIT_FAILURE);
    }

    s.address.sin_family = AF_INET;
    s.address.sin_addr.s_addr = INADDR_ANY;
    s.address.sin_port = htons(port);

    if (bind(s.sockfd, (struct sockaddr *)&s.address, sizeof(s.address)) < 0) {
        perror("Bind failed");
        close(s.sockfd);
        exit(EXIT_FAILURE);
    }

    if (listen(s.sockfd, ACCEPT_BACKLOG) < 0) {
        perror("Listen failed");
        close(s.sockfd);
        exit(EXIT_FAILURE);
    }

    return s;
}

static struct connection* server_accept(struct server_state *state, struct connection s) {
    struct connection *c = (struct connection *)malloc(sizeof(struct connection));
    if (c == NULL) {
        perror("Error allocating memory for client");
        close(s.sockfd);
        return NULL;
    }

    memset(c, 0, sizeof(struct connection));

#ifndef PRODUCTION
    (void)state;
#endif

    struct sockaddr_in client_addr;
    socklen_t addrlen = (socklen_t)sizeof(client_addr);
    c->sockfd = accept(s.sockfd, (struct sockaddr *)&client_addr, &addrlen);
    if (c->sockfd < 0) {
        perror("Accept failed");
        free(c);
        return NULL;
    }
    c->address = client_addr;

#ifdef PRODUCTION
    c->ssl = SSL_new(state->crypto.ctx);
    if (!c->ssl) {
        perror("[ERROR] SSL initialization failed");
        close(c->sockfd);
        free(c);
        return NULL;
    }

    SSL_set_fd(c->ssl, c->sockfd);
    if (SSL_accept(c->ssl) <= 0) {
        perror("[ERROR] SSL handshake failed");
        SSL_free(c->ssl);
        close(c->sockfd);
        free(c);
        return NULL;
    }
#endif

    return c;
}

static int gateway(struct server_state *state, int fd, http_request_t *req, http_response_t *res) {
    if (strncmp(req->path, "/favicon.ico", 12) == 0) {
        res->status = HTTP_404_NOT_FOUND;
        snprintf(res->body, HTTP_RESPONSE_SIZE, "404 Not Found\n");
        return 0;
    }

    if (strncmp(req->path, MODULE_URL, 6) == 0) {
        if (req->method == HTTP_GET) {
            router_gateway_json(&state->router, res);
        } else if (req->method == HTTP_POST) {
            if (router_mgnt_parse_request(&state->router, &state->ctx, req, res) >= 0) {
                res->status = HTTP_200_OK;
            } else {
                res->status = HTTP_500_INTERNAL_SERVER_ERROR;
            }
        } else {
            res->status = HTTP_405_METHOD_NOT_ALLOWED;
        }
        return 0;
    }

    if (http_is_websocket_upgrade(req)) {
        if (strcmp(req->path, "/jobs/ws") == 0) {
            const websocket_info_t *jobs_ws = jobs_ws_info(&state->jobs);
            if (!jobs_ws) {
                res->status = HTTP_500_INTERNAL_SERVER_ERROR;
                return 0;
            }
            ws_handle_client(&state->ws, &state->ctx, fd, req, res, (struct ws_info *)jobs_ws);
            return 0;
        }
        struct ws_route ws = router_ws_find(&state->router, req->path);
        if (ws.info == NULL) {
            res->status = HTTP_404_NOT_FOUND;
            snprintf(res->body, HTTP_RESPONSE_SIZE, "404 Not Found\n");
            return 0;
        }

        ws_handle_client(&state->ws, &state->ctx, fd, req, res, ws.info);

        pthread_rwlock_unlock(ws.rwlock);

        return 0;
    }

    if (strncmp(req->path, "/jobs", 5) == 0 && (req->path[5] == '\0' || req->path[5] == '/')) {
        if (jobs_handle_http(&state->jobs, &state->ctx, req, res)) {
            return 0;
        }
        res->status = HTTP_404_NOT_FOUND;
        snprintf(res->body, HTTP_RESPONSE_SIZE, "404 Not Found\n");
        return 0;
    }

    struct route r = router_find(&state->router, req->path, http_methods[req->method]);
    if (r.route == NULL) {
        res->status = HTTP_404_NOT_FOUND;
        snprintf(res->body, HTTP_RESPONSE_SIZE, "404 Not Found\n");
        return 0;
    }

    safe_execute_handler(r.route->handler, &state->ctx, req, res);

    pthread_rwlock_unlock(r.rwlock);
    return 0;
}

static void build_headers(http_response_t *res, char *headers, int headers_size) {
    http_kv_store_t *headers_map = res->headers;
    int headers_len = 0;
    for (size_t i = 0; i < http_kv_size(headers_map); i++) {
        int written = snprintf(headers + headers_len, headers_size - headers_len, "%s: %s\r\n", headers_map->entries[i].key, (char*)headers_map->entries[i].value);
        if (written < 0 || written >= headers_size - headers_len) {
            fprintf(stderr, "[ERROR] Header buffer overflow\n");
            break;
        }
        headers_len += written;
    }
}

static void measure_time(struct timespec *start, struct timespec *end, double *time_taken) {
    clock_gettime(CLOCK_MONOTONIC, end);
    *time_taken = (end->tv_sec - start->tv_sec) * 1e9;
    *time_taken = (*time_taken + (end->tv_nsec - start->tv_nsec)) * 1e-9;
}

static void thread_clean_up_request(http_request_t *req) {
    if (req->body) free(req->body);
    if (req->path) free(req->path);

    if (req->params != NULL) {
        http_kv_destroy(req->params, 1);
        req->params = NULL;
    }

    if (req->headers != NULL) {
        http_kv_destroy(req->headers, 1);
        req->headers = NULL;
    }

    if (req->data != NULL) {
        http_kv_destroy(req->data, 1);
        req->data = NULL;
    }
}

static void thread_clean_up(http_request_t *req, http_response_t *res) {
    thread_clean_up_request(req);
    http_kv_destroy(res->headers, 1);
    free(res->body);
}

static void thread_set_timeout(int sockfd, int seconds) {
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) != 0) {
        perror("[ERROR] Failed to set socket timeout");
    }
}

static void thread_clear_timeout(int sockfd) {
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) != 0) {
        perror("[ERROR] Failed to clear socket timeout");
    }
}

static void thread_handle_client(void *arg) {
    int ret;
    struct client_task *task = (struct client_task *)arg;
    struct server_state *state = task->state;
    struct connection *c = task->connection;
    free(task);
    atomic_fetch_add(&state->active_clients, 1);
    int close_socket = 1;

    thread_set_timeout(c->sockfd, 2);

    while (1) {
        int close_connection = 0;

        char buffer[REQUEST_BUFFER_SIZE] = {0};
#ifdef PRODUCTION
        int read_size = SSL_read(c->ssl, buffer, sizeof(buffer) - 1);
        if (read_size <= 0) {
            if (SSL_get_error(c->ssl, read_size) == SSL_ERROR_ZERO_RETURN) {
                break;
            }
            break;
        }
#else
        int read_size = (int)read(c->sockfd, buffer, sizeof(buffer) - 1);
        if (read_size <= 0) {
            break;
        }
#endif

        buffer[read_size] = '\0';

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        http_request_t req;
        memset(&req, 0, sizeof(req));
        req.tid = pthread_self();

        http_parse(buffer, &req);
        if (req.method == HTTP_ERR) {
            dprintf(c->sockfd, "HTTP/1.1 %s\r\nContent-Length: 0\r\n\r\n", http_errors[req.status]);
            thread_clean_up_request(&req);
            goto thread_handle_client_exit;
        }

        int request_too_large = req.content_length > (int)(sizeof(buffer) - 1);

        while (req.content_length > read_size && read_size < (int)sizeof(buffer) - 1) {
#ifdef PRODUCTION
            ret = SSL_read(c->ssl, buffer + read_size, sizeof(buffer) - read_size - 1);
#else
            ret = (int)read(c->sockfd, buffer + read_size, sizeof(buffer) - read_size - 1);
#endif
            if (ret <= 0) {
                break;
            }

            read_size += ret;
            buffer[read_size] = '\0';
        }

        char* body_ptr = strstr(buffer, "\r\n\r\n");
        if (body_ptr) {
            req.body = strdup(body_ptr + 4);
        } else {
            req.body = strdup("");
        }
        if (!req.body) {
            perror("[ERROR] Failed to allocate request body");
            thread_clean_up_request(&req);
            goto thread_handle_client_exit;
        }

        http_parse_data(&req);
        close_connection = req.close;

        http_response_t res;
        res.headers = http_kv_create(32);
        if (res.headers == NULL) {
            perror("[ERROR] Error creating map");
            thread_clean_up_request(&req);
            goto thread_handle_client_exit;
        }

        res.body = (char *)malloc(HTTP_RESPONSE_SIZE);
        if (res.body == NULL) {
            perror("[ERROR] Error allocating memory for response body");
            http_kv_destroy(res.headers, 1);
            res.headers = NULL;
            thread_clean_up_request(&req);
            goto thread_handle_client_exit;
        }
        res.content_length = 0;
        res.status = HTTP_200_OK;
        res.body[0] = '\0';

        if (request_too_large) {
            res.status = HTTP_414_URI_TOO_LONG;
            snprintf(res.body, HTTP_RESPONSE_SIZE, "Request too large\n");
            close_connection = 1;
        } else {
            gateway(state, c->sockfd, &req, &res);
        }

        if (thread_pool_is_full(state->pool)) {
            http_kv_insert(res.headers, "Connection", strdup("close"));
            close_connection = 1;
        }

        time_t now = time(NULL);
        struct tm tm;
        gmtime_r(&now, &tm);
        char date[128];
        strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", &tm);
        http_kv_insert(res.headers, "Date", strdup(date));

        char headers[4*1024] = {0};
        char response_head[4*1024] = {0};
        build_headers(&res, headers, sizeof(headers));
        size_t body_len = res.content_length > 0 ? (size_t)res.content_length : strlen(res.body);
        snprintf(response_head, sizeof(response_head), HTTP_VERSION" %s\r\n%sContent-Length: %zu\r\n\r\n", http_errors[res.status], headers, body_len);

#ifdef PRODUCTION
        size_t header_len = strlen(response_head);
        if (header_len > INT_MAX) {
            fprintf(stderr, "[ERROR] Response header too large\n");
            break;
        }
        if (SSL_write(c->ssl, response_head, (int)header_len) <= 0) {
            perror("[ERROR] SSL write failed");
            break;
        }
        if (body_len > INT_MAX) {
            fprintf(stderr, "[ERROR] Response body too large\n");
            break;
        }
        if (body_len > 0 && SSL_write(c->ssl, res.body, (int)body_len) <= 0) {
            perror("[ERROR] SSL write failed");
            break;
        }
#else
        if (write(c->sockfd, response_head, strlen(response_head)) <= 0) {
            perror("[ERROR] Write failed");
            break;
        }
        if (body_len > 0 && write(c->sockfd, res.body, body_len) <= 0) {
            perror("[ERROR] Write failed");
            break;
        }
#endif

        double time_taken;
        measure_time(&start, &end, &time_taken);

        if (!state->config.silent_mode) {
            printf("[%ld] %s - Request %s %s took %f seconds.\n", (long)req.tid, http_errors[res.status], http_methods[req.method], req.path, time_taken);
        }

        thread_clean_up(&req, &res);
        if (req.websocket) {
            thread_clear_timeout(c->sockfd);
            ws_confirm_open(&state->ws, &state->ctx, c->sockfd);
            close_socket = 0;
            goto thread_handle_client_exit;
        }

        if (close_connection || req.version == HTTP_VERSION_1_0) {
            goto thread_handle_client_exit;
        }
    }
thread_handle_client_exit:

#ifdef PRODUCTION
    if (close_socket && c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
#endif
    if (close_socket) {
        close(c->sockfd);
    }
    free(c);
    atomic_fetch_sub(&state->active_clients, 1);
    return;
}

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
#ifdef PRODUCTION
    state.config.environment = PROD;
#else
    state.config.environment = DEV;
#endif
    server_load_shutdown_policy(&state);

    int opt;
    while ((opt = getopt(argc, argv, "p:t:sF")) != -1) {
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
            default:
                fprintf(stderr, "Usage: %s [-p port] [-t thread_pool_size] [-s (silent mode)] [-F (force shutdown)]\n", argv[0]);
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
    state.pool = thread_pool_init(state.config.thread_pool_size ? state.config.thread_pool_size : num_cores * 2);
#else
    state.pool = thread_pool_init(2);
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
