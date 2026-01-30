#include "server.h"
#include "engine.h"
#include "pool.h"
#include <limits.h>
#include <dlfcn.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define MODULE_URL "/mgnt"

void cors_apply_response(const cors_config_t *cors, const http_request_t *req, http_response_t *res);
int auth_require_admin(struct server_state *state, int fd, http_request_t *req, http_response_t *res);

static void* server_resolve(void *user_data, const char* module, const char* symbol) {
    struct router *router = (struct router *)user_data;
    return router_resolve(router, module, symbol);
}

int server_init_services(struct server_state *state) {
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

    if (router_init(&state->router, &state->ws, NULL, state->config.module_dir, state->config.purge_modules, &state->ctx) != 0) {
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
    if (!state->router.module_handle) {
        fprintf(stderr, "[ERROR] libmodule handle missing\n");
        jobs_shutdown(&state->jobs);
        router_shutdown(&state->router, &state->ctx);
        ws_shutdown(&state->ws, &state->ctx);
        crypto_shutdown(&state->crypto);
        sqldb_shutdown(&state->database);
        scheduler_shutdown(&state->scheduler);
        container_shutdown(&state->cache);
        return -1;
    }

    void (*bind_fn)(jobs_create_fn_t, void *) = dlsym(state->router.module_handle, "jobs_bind");
    if (!bind_fn) {
        fprintf(stderr, "[ERROR] Failed to bind jobs_create\n");
        jobs_shutdown(&state->jobs);
        router_shutdown(&state->router, &state->ctx);
        ws_shutdown(&state->ws, &state->ctx);
        crypto_shutdown(&state->crypto);
        sqldb_shutdown(&state->database);
        scheduler_shutdown(&state->scheduler);
        container_shutdown(&state->cache);
        return -1;
    }
    bind_fn(jobs_create_impl, &state->ctx);

    return 0;
}

static int gateway(struct server_state *state, int fd, http_request_t *req, http_response_t *res) {
    if (req->method == HTTP_OPTIONS) {
        res->status = HTTP_200_OK;
        res->content_length = 0;
        res->body[0] = '\0';
        return 0;
    }

    if (strncmp(req->path, "/favicon.ico", 12) == 0) {
        res->status = HTTP_404_NOT_FOUND;
        snprintf(res->body, HTTP_RESPONSE_SIZE, "404 Not Found\n");
        return 0;
    }

    if (strncmp(req->path, MODULE_URL, 6) == 0) {
        if (!auth_require_admin(state, fd, req, res)) {
            return 0;
        }
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
            if (!auth_require_admin(state, fd, req, res)) {
                return 0;
            }
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
        if (!auth_require_admin(state, fd, req, res)) {
            return 0;
        }
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
    if (req->body) {
        free(req->body);
    }
    if (req->path) {
        free(req->path);
    }

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

void thread_handle_client(void *arg) {
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

        char *header_end = strstr(buffer, "\r\n\r\n");
        while (!header_end && read_size < (int)sizeof(buffer) - 1) {
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
            header_end = strstr(buffer, "\r\n\r\n");
        }

        if (!header_end) {
            dprintf(c->sockfd, "HTTP/1.1 %s\r\nContent-Length: 0\r\n\r\n", http_errors[HTTP_400_BAD_REQUEST]);
            goto thread_handle_client_exit;
        }

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

        size_t header_len = (size_t)(header_end - buffer) + 4;
        size_t body_len_in_buffer = read_size > (int)header_len ? (size_t)(read_size - (int)header_len) : 0;
        size_t max_body_bytes = state->config.max_body_bytes;
        int request_too_large = 0;
        int parse_error_status = 0;

        if (req.transfer_encoding_chunked) {
            /* RFC 9112 §7.1: chunked transfer coding */
            char *decoded_body = NULL;
            size_t decoded_len = 0;
            int decode_status = http_decode_chunked_body(buffer + header_len, body_len_in_buffer, &decoded_body, &decoded_len);
            while (decode_status == 1 && read_size < (int)sizeof(buffer) - 1) {
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
                body_len_in_buffer = read_size > (int)header_len ? (size_t)(read_size - (int)header_len) : 0;
                decode_status = http_decode_chunked_body(buffer + header_len, body_len_in_buffer, &decoded_body, &decoded_len);
                if (max_body_bytes > 0 && decoded_len > max_body_bytes) {
                    request_too_large = 1;
                    break;
                }
            }

            if (request_too_large) {
                parse_error_status = HTTP_413_PAYLOAD_TOO_LARGE;
                free(decoded_body);
            } else if (decode_status != 0) {
                parse_error_status = HTTP_400_BAD_REQUEST;
                free(decoded_body);
            } else if (decoded_len > INT_MAX) {
                parse_error_status = HTTP_400_BAD_REQUEST;
                free(decoded_body);
            } else if (max_body_bytes > 0 && decoded_len > max_body_bytes) {
                parse_error_status = HTTP_413_PAYLOAD_TOO_LARGE;
                free(decoded_body);
            } else {
                req.body = decoded_body;
                req.content_length = (int)decoded_len;
            }
        } else {
            if (max_body_bytes > 0 && req.content_length > 0 &&
                (size_t)req.content_length > max_body_bytes) {
                request_too_large = 1;
            }
            if (req.content_length > (int)(sizeof(buffer) - header_len)) {
                request_too_large = 1;
            }

            while (!request_too_large && body_len_in_buffer < (size_t)req.content_length &&
                   read_size < (int)sizeof(buffer) - 1) {
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
                body_len_in_buffer = read_size > (int)header_len ? (size_t)(read_size - (int)header_len) : 0;
            }

            if (!request_too_large && body_len_in_buffer < (size_t)req.content_length) {
                parse_error_status = HTTP_400_BAD_REQUEST;
            }

            if (!request_too_large && !parse_error_status) {
                size_t body_len = req.content_length > 0 ? (size_t)req.content_length : body_len_in_buffer;
                req.body = malloc(body_len + 1);
                if (!req.body) {
                    perror("[ERROR] Failed to allocate request body");
                    thread_clean_up_request(&req);
                    goto thread_handle_client_exit;
                }
                if (body_len > 0) {
                    memcpy(req.body, buffer + header_len, body_len);
                }
                req.body[body_len] = '\0';
            }
        }

        if (!parse_error_status) {
            http_parse_data(&req);
        }
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

        if (parse_error_status) {
            res.status = parse_error_status;
            if (parse_error_status == HTTP_413_PAYLOAD_TOO_LARGE) {
                snprintf(res.body, HTTP_RESPONSE_SIZE, "Payload too large\n");
            } else {
                snprintf(res.body, HTTP_RESPONSE_SIZE, "Bad Request\n");
            }
            close_connection = 1;
        } else if (request_too_large) {
            res.status = HTTP_413_PAYLOAD_TOO_LARGE;
            snprintf(res.body, HTTP_RESPONSE_SIZE, "Payload too large\n");
            close_connection = 1;
        } else {
            gateway(state, c->sockfd, &req, &res);
        }

        cors_apply_response(&state->config.cors, &req, &res);

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
