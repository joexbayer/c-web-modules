
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>

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
#include "map.h"
#include "db.h"
#include "scheduler.h"
#include "pool.h"

#define DEFAULT_PORT 8080
#define ACCEPT_BACKLOG 128
#define MODULE_URL "/mgnt"

/* Feature for later... */
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

struct cidr_prefix {
    uint32_t prefix; 
    uint8_t prefix_len;
};

struct connection {
    int sockfd;
    struct sockaddr_in address;
    SSL *ssl;
};

static struct thread_pool *pool;
__attribute__((used)) static SSL_CTX *ssl_ctx; // Global SSL context

typedef enum env {
    DEV,
    PROD
} env_t;

static struct server_config {
    uint16_t port;
    int thread_pool_size;
    char silent_mode;
    const char* certificate;
    const char* private_key;
    env_t environment;
} config = {
    .port = DEFAULT_PORT,
    .thread_pool_size = 0,
    .silent_mode = 0,
    .certificate = "server.crt",
    .private_key = "server.key",
#ifdef PRODUCTION
    .environment = PROD
#else
    .environment = DEV
#endif 
};

// static int parse_cidr(const char *cidr_str, struct cidr_prefix *result) {
//     char ip[INET_ADDRSTRLEN];
//     int prefix_len;

//     if (sscanf(cidr_str, "%15[^/]/%d", ip, &prefix_len) != 2) {
//         fprintf(stderr, "Invalid CIDR format: %s\n", cidr_str);
//         return -1;
//     }

//     if (prefix_len < 0 || prefix_len > 32) {
//         fprintf(stderr, "Invalid prefix length: %d\n", prefix_len);
//         return -1;
//     }

//     struct in_addr addr;
//     if (inet_pton(AF_INET, ip, &addr) != 1) {
//         fprintf(stderr, "Invalid IP address: %s\n", ip);
//         return -1;
//     }

//     result->prefix = ntohl(addr.s_addr); // Convert to host byte order
//     result->prefix_len = (uint8_t)prefix_len;

//     return 0;
// }

/* TODO: Ugly fix to allow server access to these.. */
void ws_handle_client(int sd, struct http_request *req, struct http_response *res, struct ws_info *ws_module_info);
int ws_confirm_open(int sd);

#ifdef PRODUCTION
static SSL_CTX* initialize_ssl_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("[ERROR] Failed to initialize SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, config.certificate, SSL_FILETYPE_PEM) <= 0) {
        perror("[ERROR] Failed to load server certificate");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, config.private_key , SSL_FILETYPE_PEM) <= 0) {
        perror("[ERROR] Failed to load server private key");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "[ERROR] Private key does not match the certificate\n");
        exit(EXIT_FAILURE);
    }

    return ctx;
}
#endif

static struct connection server_init(uint16_t port) {
    struct connection s;
    s.sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (s.sockfd == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(s.sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
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

static struct connection* server_accept(struct connection s) {
    struct connection *c = (struct connection *)malloc(sizeof(struct connection));
    if (c == NULL) {
        perror("Error allocating memory for client");
        close(s.sockfd);
        exit(EXIT_FAILURE);
    }

    int addrlen = sizeof(s.address);
    c->sockfd = accept(s.sockfd, (struct sockaddr *)&s.address, (socklen_t *)&addrlen);
    if (c->sockfd < 0) {
        perror("Accept failed");
        free(c);
        return NULL;
    }

#ifdef PRODUCTION
    c->ssl = SSL_new(ssl_ctx);
    if (!c->ssl) {
        perror("[ERROR] SSL initialization failed");
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

static int gateway(int fd, struct http_request *req, struct http_response *res) {
    if (strncmp(req->path, "/favicon.ico", 12) == 0) {
        res->status = HTTP_404_NOT_FOUND;
        snprintf(res->body, HTTP_RESPONSE_SIZE, "404 Not Found\n");
        return 0;
    }

    if(strncmp(req->path, MODULE_URL, 6) == 0) {
        if (req->method == HTTP_GET) {
           route_gateway_json(res);
        } else if (req->method == HTTP_POST) {
            if (mgnt_parse_request(req, res) >= 0) {
                res->status = HTTP_200_OK;
            } else {
                res->status = HTTP_500_INTERNAL_SERVER_ERROR;
            }
        } else {
            res->status = HTTP_405_METHOD_NOT_ALLOWED;
        }
        return 0;
    }

    if(http_is_websocket_upgrade(req)) {
        struct ws_route ws = ws_route_find(req->path);
        if (ws.info == NULL) {
            res->status = HTTP_404_NOT_FOUND;
            snprintf(res->body, HTTP_RESPONSE_SIZE, "404 Not Found\n");
            return 0;
        }

        /* Upgrade to websocket */
        ws_handle_client(fd, req, res, ws.info);

        pthread_rwlock_unlock(ws.rwlock);

        return 0;
    }

    struct route r = route_find(req->path, (char*)http_methods[req->method]);
    if (r.route == NULL) {
        res->status = HTTP_404_NOT_FOUND;
        snprintf(res->body, HTTP_RESPONSE_SIZE, "404 Not Found\n"); 
        return 0;
    }

    safe_execute_handler(r.route->handler, req, res);

    /* Release the read lock after handler execution */
    pthread_rwlock_unlock(r.rwlock);
    return 0;
}

/* Build headers for response */
static void build_headers(struct http_response *res, char *headers, int headers_size) {
    struct map *headers_map = res->headers;
    int headers_len = 0;
    for (size_t i = 0; i < map_size(headers_map); i++) {
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

static void thread_clean_up_request(struct http_request *req) {
    if (req->body) free(req->body);
    if (req->path) free(req->path);

    if(req->params != NULL){
        for (size_t i = 0; i < map_size(req->params); i++) {
            free(req->params->entries[i].value);
        }
        map_destroy(req->params);
    }

    if(req->headers != NULL){
        for (size_t i = 0; i < map_size(req->headers); i++) {
            free(req->headers->entries[i].value);
        }
        map_destroy(req->headers);
    }

    if(req->data != NULL){
        for (size_t i = 0; i < map_size(req->data); i++) {
            free(req->data->entries[i].value);
        }
        map_destroy(req->data);
    }
}

static void thread_clean_up(struct http_request *req, struct http_response *res) {
    thread_clean_up_request(req);
    map_destroy(res->headers);
    free(res->body);
}

static void thread_set_timeout(int sockfd, int seconds) {
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
}

static void thread_handle_client(void *arg) {
    int ret;
    struct connection *c = (struct connection *)arg;

    while(1){
        int close_connection = 0;

        /* Read initial request */
        char buffer[8*1024] = {0};
#ifdef PRODUCTION
        int read_size = SSL_read(c->ssl, buffer, sizeof(buffer) - 1);
        if (read_size <= 0) {
            if (SSL_get_error(c->ssl, read_size) == SSL_ERROR_ZERO_RETURN) {
                break; // Client closed the connection
            }
            perror("[ERROR] SSL read failed");
            break;
        }
#else
        int read_size = read(c->sockfd, buffer, sizeof(buffer) - 1);
        if (read_size <= 0) {
            perror("[ERROR] Read failed");
            break;
        }
#endif

        buffer[read_size] = '\0';

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        struct http_request req;
        req.tid = pthread_self();

        http_parse(buffer, &req);
        if(req.method == HTTP_ERR) {
            dprintf(c->sockfd, "HTTP/1.1 %s\r\nContent-Length: 0\r\n\r\n", http_errors[req.status]);
            thread_clean_up_request(&req);
            goto thread_handle_client_exit;
        }

        /* Read the rest of the request */
        while (req.content_length > read_size) {
#ifdef PRODUCTION
            ret = SSL_read(c->ssl, buffer + read_size, sizeof(buffer) - read_size - 1);
#else
            ret = read(c->sockfd, buffer + read_size, sizeof(buffer) - read_size - 1);
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

        http_parse_data(&req);
        close_connection = req.close;

        struct http_response res;
        res.headers = map_create(32);
        if (res.headers == NULL) {
            perror("[ERROR] Error creating map");
            goto thread_handle_client_exit;
        }

        res.body = (char *)malloc(HTTP_RESPONSE_SIZE);
        if (res.body == NULL) {
            perror("[ERROR] Error allocating memory for response body");
            goto thread_handle_client_exit;
        }

        gateway(c->sockfd, &req, &res);

        /* If all threads are in use, send close */
        if(thread_pool_is_full(pool)) {
            map_insert(res.headers, "Connection", "close");
            close_connection = 1;
        }


        /* Servers MUST include a valid Date header in HTTP responses. */
        time_t now = time(NULL);
        struct tm tm = *gmtime(&now);
        char date[128];
        strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", &tm);
        map_insert(res.headers, "Date", strdup(date));

        char headers[4*1024] = {0};
        char response[8*1024] = {0};
        build_headers(&res, headers, sizeof(headers));
        snprintf(response, sizeof(response), HTTP_VERSION" %s\r\n%sContent-Length: %lu\r\n\r\n%s", http_errors[res.status], headers, strlen(res.body), res.body);

#ifdef PRODUCTION        
        if (SSL_write(c->ssl, response, strlen(response)) <= 0) {
            perror("[ERROR] SSL write failed");
            break;
        }
#else
        if (write(c->sockfd, response, strlen(response)) <= 0) {
            perror("[ERROR] Write failed");
            break;
        }
#endif

        double time_taken;
        measure_time(&start, &end, &time_taken);

        if (!config.silent_mode)
            printf("[%ld] %s - Request %s %s took %f seconds.\n", (long)req.tid, http_errors[res.status], http_methods[req.method], req.path, time_taken);

        /* Ugly hacks */
        char* ac = map_get(res.headers, "Sec-WebSocket-Accept");
        if (ac) free(ac);
        char* dt = map_get(res.headers, "Date");
        if (dt) free(dt);

        thread_clean_up(&req, &res);
        if (req.websocket) {
            ws_confirm_open(c->sockfd);
            return; /* Websocket connection is handled by the websocket thread */
        } else {
            /* Set timeout for client */
            thread_set_timeout(c->sockfd, 2);
        }

        /**
         * HTTP/1.1 connections MUST be persistent by default unless a Connection: close header is explicitly included.
         */
        if (close_connection) {
            goto thread_handle_client_exit;
        }
    }
thread_handle_client_exit:

#ifdef PRODUCTION
    SSL_shutdown(c->ssl);
    SSL_free(c->ssl);
#endif
    close(c->sockfd);
    free(c);
    return;
}

#define INIT_OPTIONS (OPENSSL_INIT_NO_ATEXIT)
static void openssl_init_wrapper(void) {
    if (OPENSSL_init_crypto(INIT_OPTIONS, NULL) == 0) {
        fprintf(stderr, "[ERROR] Failed to initialize OpenSSL\n");
        exit(EXIT_FAILURE);
    }
}

/* Signal handler */
static volatile sig_atomic_t stop = 0;
static void server_signal_handler(int sig) {
(void)sig;
    stop = 1;
}

#include <unistd.h>

int main(int argc, char *argv[]) {
    (void)allowed_management_commands;
    (void)allowed_ip_prefixes;

    int opt;
    while ((opt = getopt(argc, argv, "p:t:s")) != -1) {
        switch (opt) {
            case 'p':
                config.port = atoi(optarg);
                break;
            case 't':
                config.thread_pool_size = atoi(optarg);
                break;
            case 's':
                config.silent_mode = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s [-p port] [-t thread_pool_size] [-s (silent mode)]\n", argv[0]);
        }
    }

#ifdef PRODUCTION
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ssl_ctx = initialize_ssl_context();
    printf("[SERVER] SSL context initialized\n");
#endif

    int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
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

    struct connection s = server_init(config.port);

    /* Initialize thread pool, 2 times numbers of cores */
    pool = thread_pool_init(config.thread_pool_size ? config.thread_pool_size : num_cores*2);
    if (pool == NULL) {
        fprintf(stderr, "[ERROR] Failed to initialize thread pool\n");
        return 1;
    }

    /* Main server loop */
    printf("\n Version: %s\n", "0.0.1");
    printf(" Thread Pool Size: %d\n", pool->max_threads);
    printf(" Environment: %s\n", config.environment == PROD ? "Production" : "Development");
    printf(" PID: %d\n", getpid());
    printf(" Listening on %s://%s:%d\n",config.environment == PROD ? "https" : "http", inet_ntoa(s.address.sin_addr), ntohs(s.address.sin_port));
    while (!stop) {
        struct connection *client = server_accept(s);
        if (client == NULL) {
            if (stop) {
                break;
            }
            perror("Error accepting client");
            continue;
        }

        /* Add client handling task to the thread pool */
        thread_pool_add_task(pool, thread_handle_client, client);
    }

    /* Clean up */
    thread_pool_destroy(pool);
    close(s.sockfd);
#ifdef PRODUCTION
    SSL_CTX_free(ssl_ctx);
#endif
    printf("[SERVER] Server shutting down gracefully.\n");

    return 0;
}