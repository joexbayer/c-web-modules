#include "server.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void server_load_shutdown_policy(struct server_state *state) {
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

void server_set_shutdown_policy(struct server_state *state, shutdown_policy_t policy) {
    state->config.shutdown_policy = policy;
}

void server_load_request_limits(struct server_state *state) {
    state->config.max_body_bytes = DEFAULT_MAX_BODY_BYTES;

    const char *max_body_env = getenv("CWEB_MAX_BODY_BYTES");
    if (max_body_env && max_body_env[0] != '\0') {
        char *endptr = NULL;
        errno = 0;
        unsigned long long value = strtoull(max_body_env, &endptr, 10);
        while (endptr && (*endptr == ' ' || *endptr == '\t')) {
            endptr++;
        }
        if (errno == 0 && endptr && *endptr == '\0' && value > 0 && value <= SIZE_MAX) {
            state->config.max_body_bytes = (size_t)value;
        }
    }
}

void server_load_auth_config(struct server_state *state) {
    const char *admin_key = getenv("CWEB_ADMIN_KEY");
    if (admin_key && admin_key[0] != '\0') {
        state->config.admin_key = admin_key;
        state->config.admin_key_len = strlen(admin_key);
    } else {
        state->config.admin_key = NULL;
        state->config.admin_key_len = 0;
    }
}

static int cors_origin_matches_list(const char *list, const char *origin) {
    const char *cursor = list;
    size_t origin_len = strlen(origin);

    while (*cursor != '\0') {
        while (*cursor == ' ' || *cursor == '\t') {
            cursor++;
        }

        const char *segment_start = cursor;
        while (*cursor != '\0' && *cursor != ',') {
            cursor++;
        }
        const char *segment_end = cursor;

        while (segment_end > segment_start &&
               (segment_end[-1] == ' ' || segment_end[-1] == '\t')) {
            segment_end--;
        }

        size_t segment_len = (size_t)(segment_end - segment_start);
        if (segment_len == origin_len &&
            strncmp(segment_start, origin, origin_len) == 0) {
            return 1;
        }

        if (*cursor == ',') {
            cursor++;
        }
    }

    return 0;
}

static const char *cors_select_origin(const cors_config_t *cors,
                                      const http_request_t *req,
                                      int *vary_origin) {
    const char *origin = http_kv_get(req->headers, "Origin");

    *vary_origin = 0;
    if (!cors->allow_origins || cors->allow_origins[0] == '\0') {
        return NULL;
    }

    if (cors->allow_all_origins) {
        if (cors->allow_credentials && origin && origin[0] != '\0') {
            *vary_origin = 1;
            return origin;
        }
        return "*";
    }

    if (cors->allow_origin_list) {
        if (!origin || origin[0] == '\0') {
            return NULL;
        }
        if (cors_origin_matches_list(cors->allow_origins, origin)) {
            *vary_origin = 1;
            return origin;
        }
        return NULL;
    }

    return cors->allow_origins;
}

static void cors_add_header(http_response_t *res, const char *key, const char *value) {
    if (http_kv_get(res->headers, key) != NULL) {
        return;
    }
    char *dup_value = strdup(value);
    if (!dup_value) {
        perror("[ERROR] Failed to allocate CORS header value");
        return;
    }
    if (http_kv_insert(res->headers, key, dup_value) != 0) {
        free(dup_value);
    }
}

void cors_apply_response(const cors_config_t *cors,
                         const http_request_t *req,
                         http_response_t *res) {
    int vary_origin = 0;
    const char *origin_value = cors_select_origin(cors, req, &vary_origin);
    if (!origin_value) {
        return;
    }

    cors_add_header(res, "Access-Control-Allow-Origin", origin_value);
    if (vary_origin) {
        cors_add_header(res, "Vary", "Origin");
    }
    if (cors->allow_credentials) {
        cors_add_header(res, "Access-Control-Allow-Credentials", "true");
    }

    if (req->method == HTTP_OPTIONS) {
        if (cors->allow_methods && cors->allow_methods[0] != '\0') {
            cors_add_header(res, "Access-Control-Allow-Methods", cors->allow_methods);
        }
        if (cors->allow_headers && cors->allow_headers[0] != '\0') {
            cors_add_header(res, "Access-Control-Allow-Headers", cors->allow_headers);
        }
        if (cors->max_age > 0) {
            char max_age[32];
            snprintf(max_age, sizeof(max_age), "%d", cors->max_age);
            cors_add_header(res, "Access-Control-Max-Age", max_age);
        }
    }
}

void server_set_cors_defaults(struct server_state *state) {
    state->config.cors = (cors_config_t){
        .allow_origins = "*",
        .allow_methods = "GET, POST, PUT, DELETE, OPTIONS",
        .allow_headers = "Content-Type, Authorization",
        .allow_credentials = 0,
        .max_age = 600,
        .allow_all_origins = 1,
        .allow_origin_list = 0
    };
}

static int auth_is_localhost(int fd) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    if (getpeername(fd, (struct sockaddr *)&addr, &len) != 0) {
        return 0;
    }
    return addr.sin_addr.s_addr == htonl(INADDR_LOOPBACK);
}

static const char *auth_extract_token(const http_request_t *req) {
    const char *api_key = http_kv_get(req->headers, "X-API-Key");
    if (api_key && api_key[0] != '\0') {
        return api_key;
    }

    const char *auth = http_kv_get(req->headers, "Authorization");
    if (!auth) {
        return NULL;
    }
    if (strncmp(auth, "Bearer ", 7) == 0) {
        return auth + 7;
    }
    return auth;
}

int auth_require_admin(struct server_state *state, int fd, http_request_t *req, http_response_t *res) {
    if (state->config.environment == DEV && auth_is_localhost(fd)) {
        return 1;
    }

    if (!state->config.admin_key) {
        res->status = HTTP_401_UNAUTHORIZED;
        snprintf(res->body, HTTP_RESPONSE_SIZE, "admin key required\n");
        return 0;
    }

    const char *token = auth_extract_token(req);
    if (token && strcmp(token, state->config.admin_key) == 0) {
        return 1;
    }

    res->status = HTTP_401_UNAUTHORIZED;
    snprintf(res->body, HTTP_RESPONSE_SIZE, "unauthorized\n");
    return 0;
}
