#include <openssl/sha.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <http.h>
#include <list.h>
#include <cweb.h>
#include <libevent.h>
#include <ws.h>

#define WS_MAX_FRAME_SIZE 2048

typedef enum {
    WS_OPCODE_CONTINUATION = 0x0,
    WS_OPCODE_TEXT = 0x1,
    WS_OPCODE_BINARY = 0x2,
    WS_OPCODE_CLOSE = 0x8,
    WS_OPCODE_PING = 0x9,
    WS_OPCODE_PONG = 0xA
} ws_opcode_t;

typedef enum {
    WS_FRAME_INCOMPLETE,
    WS_FRAME_COMPLETE,
    WS_FRAME_ERROR
} ws_frame_status_t;

typedef struct websocket_frame {
    uint8_t fin;
    uint8_t opcode;
    uint8_t masked;
    uint64_t payload_len;
    uint8_t mask[4];
    unsigned char *payload;
} websocket_frame_t;

struct ws_container {
    char path[128];
    struct event *ev;
    websocket_t *ws;
    struct ws_info *info;
    pthread_mutex_t mutex;
    struct ws_server *server;
    struct cweb_context *ctx;
};

static int ws_send(websocket_t *ws, const char *message, size_t length);
static int ws_close(websocket_t *ws);

static void ws_handle_event_callback(struct event *ev, void *arg);
static void ws_handle_frames(struct ws_container container[static 1]);
static int ws_send_frame(int client_fd, const char *message, int length, uint8_t opcode);

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const unsigned char *input, size_t input_len, char *output) {
    size_t j = 0;
    unsigned char buffer[3];
    while (input_len > 0) {
        size_t chunk_len = input_len >= 3 ? 3 : input_len;
        memset(buffer, 0, 3);
        memcpy(buffer, input, chunk_len);

        output[j++] = base64_chars[(buffer[0] & 0xFC) >> 2];
        output[j++] = base64_chars[((buffer[0] & 0x03) << 4) | ((buffer[1] & 0xF0) >> 4)];
        output[j++] = chunk_len > 1 ? base64_chars[((buffer[1] & 0x0F) << 2) | ((buffer[2] & 0xC0) >> 6)] : '=';
        output[j++] = chunk_len > 2 ? base64_chars[buffer[2] & 0x3F] : '=';

        input += chunk_len;
        input_len -= chunk_len;
    }
    output[j] = '\0';
}

static void ws_compute_accept_key(const char *client_key, char *accept_key) {
    const char *websocket_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    size_t client_key_len = strlen(client_key);
    size_t guid_len = strlen(websocket_guid);
    char combined[256];

    if (client_key_len + guid_len >= sizeof(combined)) {
        fprintf(stderr, "[ERROR] Client key and GUID combination too long\n");
        return;
    }

    unsigned char sha1_result[SHA_DIGEST_LENGTH];
    snprintf(combined, sizeof(combined), "%s%s", client_key, websocket_guid);

    SHA1((unsigned char *)combined, strlen(combined), sha1_result);
    base64_encode(sha1_result, SHA_DIGEST_LENGTH, accept_key);
}

static struct ws_container *ws_container_create(struct ws_server *server, struct cweb_context *ctx, int client_fd, struct ws_info *info, const char *path) {
    websocket_t *ws = malloc(sizeof(websocket_t));
    if (!ws) {
        perror("Failed to allocate memory for websocket");
        return NULL;
    }

    ws->client_fd = client_fd;
    ws->session = NULL;
    ws->send = ws_send;
    ws->close = ws_close;

    struct ws_container *container = malloc(sizeof(struct ws_container));
    if (!container) {
        perror("Failed to allocate memory for ws_container");
        free(ws);
        return NULL;
    }

    container->ws = ws;
    container->info = info;
    container->server = server;
    container->ctx = ctx;
    snprintf(container->path, sizeof(container->path), "%s", path);
    container->mutex = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    container->ev = event_new(client_fd, 0, ws_handle_event_callback, container);
    if (!container->ev) {
        perror("Failed to create event");
        free(ws);
        free(container);
        return NULL;
    }

    pthread_mutex_lock(&server->mutex);
    list_add(server->containers, container);
    pthread_mutex_unlock(&server->mutex);

    return container;
}

static int ws_container_destroy(struct ws_container *container) {
    if (!container) {
        return -1;
    }

    struct ws_server *server = container->server;

    pthread_mutex_lock(&server->mutex);
    list_remove(server->containers, container);
    pthread_mutex_unlock(&server->mutex);

    pthread_mutex_lock(&container->mutex);

    event_del(container->ev);
    close(container->ws->client_fd);
    free(container->ws->session);
    free(container->ws);

    pthread_mutex_unlock(&container->mutex);
    pthread_mutex_destroy(&container->mutex);

    free(container);

    return 0;
}

static struct ws_container *ws_container_find(struct ws_server *server, int client_fd) {
    struct ws_container *container = NULL;
    pthread_mutex_lock(&server->mutex);

    LIST_FOREACH(server->containers, node) {
        struct ws_container *current = node->data;
        if (current->ws->client_fd == client_fd) {
            container = current;
            break;
        }
    }

    pthread_mutex_unlock(&server->mutex);
    return container;
}

static void ws_handle_event_callback(struct event *ev, void *arg) {
    struct ws_container *container = (struct ws_container *)arg;
    (void)ev;

    pthread_mutex_lock(&container->mutex);
    if (!container || !container->ws || !container->info) {
        fprintf(stderr, "Invalid container or resources\n");
        pthread_mutex_unlock(&container->mutex);
        return;
    }
    pthread_mutex_unlock(&container->mutex);

    ws_handle_frames(container);
}

int ws_update_container(struct ws_server *server, const char* path, struct ws_info *info) {
    if (!server || !info || !server->containers) {
        return -1;
    }

    pthread_mutex_lock(&server->mutex);
    LIST_FOREACH(server->containers, node) {
        struct ws_container *container = node->data;
        pthread_mutex_lock(&container->mutex);
        if (strcmp(container->path, path) == 0) {
            container->info = info;
        }
        pthread_mutex_unlock(&container->mutex);
    }
    pthread_mutex_unlock(&server->mutex);

    return 0;
}

static ws_frame_status_t ws_decode_frame(const unsigned char *data, size_t data_len, websocket_frame_t *frame) {
    if (data_len < 2) return WS_FRAME_INCOMPLETE;

    frame->fin = (data[0] & 0x80) != 0;
    frame->opcode = data[0] & 0x0F;
    frame->masked = (data[1] & 0x80) != 0;
    frame->payload_len = data[1] & 0x7F;

    size_t offset = 2;
    if (frame->payload_len == 126) {
        if (data_len < 4) return WS_FRAME_INCOMPLETE;
        frame->payload_len = (data[2] << 8) | data[3];
        offset += 2;
    } else if (frame->payload_len == 127) {
        if (data_len < 10) return WS_FRAME_INCOMPLETE;
        frame->payload_len = 0;
        offset += 8;
    }

    if (frame->masked) {
        if (data_len < offset + 4) return WS_FRAME_INCOMPLETE;
        memcpy(frame->mask, &data[offset], 4);
        offset += 4;
    }

    if (data_len < offset + frame->payload_len) return WS_FRAME_INCOMPLETE;

    frame->payload = malloc(frame->payload_len);
    if (!frame->payload) return WS_FRAME_ERROR;
    memcpy(frame->payload, &data[offset], frame->payload_len);

    if (frame->masked) {
        for (size_t i = 0; i < frame->payload_len; i++) {
            frame->payload[i] ^= frame->mask[i % 4];
        }
    }

    return WS_FRAME_COMPLETE;
}

static int ws_send_frame(int client_fd, const char *message, int length, uint8_t opcode) {
    unsigned char frame[WS_MAX_FRAME_SIZE];
    size_t message_len = (size_t)length;
    size_t offset = 0;

    frame[offset++] = 0x80 | opcode;
    if (message_len <= 125) {
        frame[offset++] = (unsigned char)message_len;
    } else if (message_len <= 65535) {
        frame[offset++] = 126;
        frame[offset++] = (unsigned char)((message_len >> 8) & 0xFF);
        frame[offset++] = (unsigned char)(message_len & 0xFF);
    } else {
        fprintf(stderr, "[ERROR] Message too large\n");
        return -1;
    }

    memcpy(&frame[offset], message, message_len);
    offset += message_len;

    send(client_fd, frame, offset, 0);

    return 0;
}

static void ws_free_frame(websocket_frame_t *frame) {
    if (frame->payload) free(frame->payload);
    frame->payload = NULL;
}

static void ws_handle_frames(struct ws_container container[static 1]) {
    websocket_t *ws = container->ws;
    unsigned char buffer[WS_MAX_FRAME_SIZE];
    ssize_t received = recv(ws->client_fd, buffer, sizeof(buffer), 0);

    pthread_mutex_lock(&container->mutex);
    struct ws_info *info = container->info;
    struct cweb_context *ctx = container->ctx;

    if (received <= 0) {
        if (info->on_close) info->on_close(ctx, ws);
        pthread_mutex_unlock(&container->mutex);
        ws_container_destroy(container);
        return;
    }

    websocket_frame_t frame;
    ws_frame_status_t status = ws_decode_frame(buffer, (size_t)received, &frame);
    if (status == WS_FRAME_COMPLETE) {
        if (frame.opcode == WS_OPCODE_CLOSE) {
            if (info->on_close) info->on_close(ctx, ws);
            pthread_mutex_unlock(&container->mutex);
            ws_free_frame(&frame);
            ws_container_destroy(container);
            return;
        } else if (frame.opcode == WS_OPCODE_TEXT) {
            if (info->on_message){
                char *payload_copy = malloc(frame.payload_len + 1);
                if (payload_copy) {
                    memcpy(payload_copy, frame.payload, frame.payload_len);
                    payload_copy[frame.payload_len] = '\0';
                    info->on_message(ctx, ws, payload_copy, frame.payload_len);
                    free(payload_copy);
                }
            }
        } else if (frame.opcode == WS_OPCODE_PING) {
            ws_send_frame(ws->client_fd, (const char *)frame.payload, (int)frame.payload_len, WS_OPCODE_PONG);
        }
        ws_free_frame(&frame);
    } else if (status == WS_FRAME_ERROR) {
        fprintf(stderr, "[ERROR] Error decoding WebSocket frame\n");
        ws_free_frame(&frame);
    } else {
        fprintf(stderr, "[ERROR] Incomplete WebSocket frame\n");
        ws_free_frame(&frame);
    }
    pthread_mutex_unlock(&container->mutex);
}

void ws_force_close(struct ws_server *server, struct ws_info *info) {
    if (!server || !info) {
        return;
    }

    pthread_mutex_lock(&server->mutex);
    LIST_FOREACH_SAFE(server->containers, node, tmp) {
        struct ws_container *container = node->data;
        if (container->info == info) {
            event_del(container->ev);
            close(container->ws->client_fd);
            free(container->ws->session);
            free(container->ws);
            free(container);
            list_remove(server->containers, container);
        }
    }
    pthread_mutex_unlock(&server->mutex);
}

static int ws_send(websocket_t *ws, const char *message, size_t length) {
    return ws_send_frame(ws->client_fd, message, (int)length, WS_OPCODE_TEXT);
}

static int ws_close(websocket_t *ws) {
    return ws_send_frame(ws->client_fd, "", 0, WS_OPCODE_CLOSE);
}

static void* ws_event_thread(void* args) {
    (void)args;
    event_dispatch();
    return NULL;
}

int http_is_websocket_upgrade(http_request_t *req) {
    const char *connection = http_kv_get(req->headers, "Connection");
    const char *upgrade = http_kv_get(req->headers, "Upgrade");

    if (connection && upgrade && strstr(connection, "Upgrade") && strcmp(upgrade, "websocket") == 0) {
        return 1;
    }

    return 0;
}

int ws_confirm_open(struct ws_server *server, struct cweb_context *ctx, int sd) {
    struct ws_container *container = ws_container_find(server, sd);
    if (!container) return -1;

    pthread_mutex_lock(&container->mutex);
    if (container->info->on_open) container->info->on_open(ctx, container->ws);
    pthread_mutex_unlock(&container->mutex);

    return 0;
}

void ws_handle_client(struct ws_server *server, struct cweb_context *ctx, int sd, http_request_t *req, http_response_t *res, struct ws_info *info) {
    printf("[WS] Upgrading connection to WebSocket %d\n", sd);

    const char *client_key = http_kv_get(req->headers, "Sec-WebSocket-Key");
    if (!client_key) {
        fprintf(stderr, "[ERROR] Missing Sec-WebSocket-Key header\n");
        res->status = HTTP_400_BAD_REQUEST;
        return;
    }

    struct ws_container *container = ws_container_create(server, ctx, sd, info, req->path);
    if (!container) {
        fprintf(stderr, "[ERROR] Failed to create WebSocket container\n");
        res->status = HTTP_500_INTERNAL_SERVER_ERROR;
        return;
    }

    const char *id = http_kv_get(req->params, "id");
    const char *since = http_kv_get(req->params, "since_event_id");
    if (id) {
        size_t id_len = strlen(id);
        size_t since_len = since ? strlen(since) : 1;
        size_t total = id_len + 1 + since_len + 1;
        container->ws->session = malloc(total);
        if (container->ws->session) {
            snprintf(container->ws->session, total, "%s|%s", id, since ? since : "0");
        }
    }

    if (event_add(container->ev) < 0) {
        fprintf(stderr, "[ERROR] Failed to add event to event loop\n");
        ws_container_destroy(container);
        res->status = HTTP_500_INTERNAL_SERVER_ERROR;
        return;
    }

    char* accept_key = malloc(128);
    if (!accept_key) {
        perror("[ERROR] Failed to allocate memory for accept key");
        res->status = HTTP_500_INTERNAL_SERVER_ERROR;
        return;
    }
    ws_compute_accept_key(client_key, accept_key);

    req->websocket = 1;
    res->status = HTTP_101_SWITCHING_PROTOCOLS;
    http_kv_insert(res->headers, "Sec-WebSocket-Accept", accept_key);
    http_kv_insert(res->headers, "Upgrade", strdup("websocket"));
    http_kv_insert(res->headers, "Connection", strdup("Upgrade"));
    res->body[0] = '\0';
}

int ws_init(struct ws_server *ws) {
    if (!ws) {
        return -1;
    }

    ws->containers = list_create();
    if (!ws->containers) {
        return -1;
    }

    ws->running = 1;
    pthread_mutex_init(&ws->mutex, NULL);

    if (pthread_create(&ws->thread, NULL, ws_event_thread, NULL) != 0) {
        list_destroy(ws->containers);
        pthread_mutex_destroy(&ws->mutex);
        return -1;
    }

    printf("[WS] WebSocket thread started\n");
    return 0;
}

void ws_shutdown(struct ws_server *ws, struct cweb_context *ctx) {
    if (!ws) {
        return;
    }

    printf("[INFO   ] Destroying WebSocket module\n");
    pthread_mutex_lock(&ws->mutex);

    LIST_FOREACH_SAFE(ws->containers, node, tmp) {
        struct ws_container *container = node->data;
        pthread_mutex_lock(&container->mutex);

        event_del(container->ev);
        close(container->ws->client_fd);
        if (container->info && container->info->on_close) {
            container->info->on_close(ctx, container->ws);
        }
        free(container->ws);
        pthread_mutex_unlock(&container->mutex);
        pthread_mutex_destroy(&container->mutex);
        free(container);

        list_remove(ws->containers, container);
    }

    list_destroy(ws->containers);

    pthread_mutex_unlock(&ws->mutex);
    pthread_mutex_destroy(&ws->mutex);

    event_dispatch_stop();
    pthread_join(ws->thread, NULL);

    printf("[INFO   ] WebSocket module destroyed\n");
}
