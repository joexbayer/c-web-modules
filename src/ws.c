#include <openssl/sha.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <http.h>
#include <map.h>
#include <list.h>
#include <cweb.h>
#include <libevent.h>

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

struct websocket_frame {
    uint8_t fin;
    uint8_t opcode;
    uint8_t masked;
    uint64_t payload_len;
    uint8_t mask[4];
    unsigned char *payload;
};

struct ws_container {
    char path[128];
    struct event *ev;
    struct websocket *ws;
    struct ws_info *info;
    pthread_mutex_t mutex;
};

/* WebSocket container functions prototypes */
static int ws_send(struct websocket *ws, const char *message, size_t length);
static int ws_close(struct websocket *ws);

/* Internal function prototypes */
static void ws_handle_event_callback(struct event *ev, void *arg);
static void ws_handle_frames(struct ws_container *container);
static int ws_send_frame(int client_fd, const char *message, int length, uint8_t opcode);

/* Global variables */
static struct list *ws_container_list = NULL;
static pthread_mutex_t ws_container_list_mutex = PTHREAD_MUTEX_INITIALIZER;

__attribute__((constructor)) void ws_init() {
    ws_container_list = list_create();
    pthread_mutex_init(&ws_container_list_mutex, NULL);
}

__attribute__((destructor)) void ws_destroy() {
    printf("[INFO   ] Destroying WebSocket module\n");
    pthread_mutex_lock(&ws_container_list_mutex);

    LIST_FOREACH(ws_container_list, node) {
        struct ws_container *container = node->data;
        pthread_mutex_lock(&container->mutex);
        printf("Destroying WebSocket container %d: %s\n", container->ws->client_fd, container->path);
        event_del(container->ev);
        close(container->ws->client_fd);
        free(container->ws);
        pthread_mutex_unlock(&container->mutex);
        pthread_mutex_destroy(&container->mutex);
        free(container);

        list_remove(ws_container_list, node);
    }

    list_destroy(ws_container_list);

    pthread_mutex_unlock(&ws_container_list_mutex);
    pthread_mutex_destroy(&ws_container_list_mutex);
    
    printf("[INFO   ] WebSocket module destroyed\n");
}

/* helper for websockets base64 */
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

/* helper for websockets sha1, accept key is the result of combining the client key and the websocket guid */
static void ws_compute_accept_key(const char *client_key, char *accept_key) {
    const char *websocket_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char combined[256];
    unsigned char sha1_result[SHA_DIGEST_LENGTH];
    snprintf(combined, sizeof(combined), "%s%s", client_key, websocket_guid);

    SHA1((unsigned char *)combined, strlen(combined), sha1_result);
    base64_encode(sha1_result, SHA_DIGEST_LENGTH, accept_key);
}

static struct ws_container *ws_container_create(int client_fd, struct ws_info *info, char *path) {
    struct websocket *ws = malloc(sizeof(struct websocket));
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
    snprintf(container->path, sizeof(container->path), "%s", path);
    container->mutex = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    container->ev = event_new(client_fd, 0, ws_handle_event_callback, container);
    if (!container->ev) {
        perror("Failed to create event");
        free(ws);
        free(container);
        return NULL;
    }

    pthread_mutex_lock(&ws_container_list_mutex);
    list_add(ws_container_list, container);
    pthread_mutex_unlock(&ws_container_list_mutex);

    return container;
}

static int ws_container_destroy(struct ws_container *container) {
    if (!container) return -1;

    /* Remove from list */
    pthread_mutex_lock(&ws_container_list_mutex);
    list_remove(ws_container_list, container);
    pthread_mutex_unlock(&ws_container_list_mutex);

    /* Free resources */
    pthread_mutex_lock(&container->mutex);
    
    event_del(container->ev);
    close(container->ws->client_fd);
    free(container->ws);

    pthread_mutex_unlock(&container->mutex);
    pthread_mutex_destroy(&container->mutex);

    free(container);

    printf("WebSocket container destroyed\n");
    return 0;
}

__attribute__((unused)) static struct ws_container *ws_container_find(int client_fd) {
    struct ws_container *container = NULL;
    pthread_mutex_lock(&ws_container_list_mutex);

    LIST_FOREACH(ws_container_list, node) {
        struct ws_container *current = node->data;
        if (current->ws->client_fd == client_fd) {
            container = current;
            break;
        }
    }

    pthread_mutex_unlock(&ws_container_list_mutex);
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

int ws_update_container(const char* path, struct ws_info *info) {
    if (!info || !ws_container_list) return -1;

    pthread_mutex_lock(&ws_container_list_mutex);
    LIST_FOREACH(ws_container_list, node) {
        struct ws_container *container = node->data;
        pthread_mutex_lock(&container->mutex);
        if (strcmp(container->path, path) == 0) {
            printf("Updating WebSocket container %d: %s\n", container->ws->client_fd, container->path);
            container->info = info;
        }
        pthread_mutex_unlock(&container->mutex);

    }
    pthread_mutex_unlock(&ws_container_list_mutex);

    return 0;
}

static ws_frame_status_t ws_decode_frame(const unsigned char *data, size_t data_len, struct websocket_frame *frame) {
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
    unsigned char frame[1024];
    size_t message_len = length;
    size_t offset = 0;

    frame[offset++] = 0x80 | opcode;
    if (message_len <= 125) {
        frame[offset++] = message_len;
    } else if (message_len <= 65535) {
        frame[offset++] = 126;
        frame[offset++] = (message_len >> 8) & 0xFF;
        frame[offset++] = message_len & 0xFF;
    } else {
        fprintf(stderr, "Message too large\n");
        return -1; 
    }

    memcpy(&frame[offset], message, message_len);
    offset += message_len;

    send(client_fd, frame, offset, 0);

    return 0;
}

static void ws_free_frame(struct websocket_frame *frame){
    if (frame->payload) free(frame->payload);
    frame->payload = NULL;
}

static void ws_handle_frames(struct ws_container* container) {

    struct websocket *ws = container->ws;
    unsigned char buffer[2048];
    ssize_t received = recv(ws->client_fd, buffer, sizeof(buffer), 0);
    
    /* Lock incase modules is about to get updated. */
    pthread_mutex_lock(&container->mutex);
    struct ws_info *info = container->info;

    if (received <= 0) {
        perror("Connection closed or error");
        if (info->on_close) info->on_close(ws);
        pthread_mutex_unlock(&container->mutex);
        ws_container_destroy(container);
        return;
    }

    struct websocket_frame frame;
    ws_frame_status_t status = ws_decode_frame(buffer, received, &frame);
    
    if (status == WS_FRAME_COMPLETE) {
        if (frame.opcode == WS_OPCODE_CLOSE) {
            if (info->on_close) info->on_close(ws);
            pthread_mutex_unlock(&container->mutex);
            ws_free_frame(&frame);
            ws_container_destroy(container);
            return;
        } else if (frame.opcode == WS_OPCODE_TEXT) {
            if (info->on_message){
                info->on_message(ws, (const char *)frame.payload, frame.payload_len);
            }
        } else if (frame.opcode == WS_OPCODE_PING) {
            ws_send_frame(ws->client_fd, (const char *)frame.payload, frame.payload_len, WS_OPCODE_PONG);
        }
        ws_free_frame(&frame);
    } else if (status == WS_FRAME_ERROR) {
        fprintf(stderr, "Error decoding WebSocket frame\n");
    }
    pthread_mutex_unlock(&container->mutex);
}

void ws_force_close(struct ws_info *info) {
    if (!info) return;

    pthread_mutex_lock(&ws_container_list_mutex);
    LIST_FOREACH(ws_container_list, node) {
        struct ws_container *container = node->data;
        if (container->info == info) {
            printf("Forcing close of WebSocket %d\n", container->ws->client_fd);
            event_del(container->ev);
            close(container->ws->client_fd);
            free(container->ws);
            free(container);
        }
        list_remove(ws_container_list, node);
    }
    pthread_mutex_unlock(&ws_container_list_mutex);
}

static int ws_send(struct websocket *ws, const char *message, size_t length) {
    return ws_send_frame(ws->client_fd, message, length, WS_OPCODE_TEXT);
}

static int ws_close(struct websocket *ws) {
    return ws_send_frame(ws->client_fd, NULL, 0, WS_OPCODE_CLOSE);
}

static void* ws_event_thread(void* args) {
    (void)args;
    event_dispatch();
    return NULL;
}

int http_is_websocket_upgrade(struct http_request *req) {
    const char *connection = map_get(req->headers, "Connection");
    const char *upgrade = map_get(req->headers, "Upgrade");
    
    if (connection && upgrade && strstr(connection, "Upgrade") && strcmp(upgrade, "websocket") == 0) {
        return 1;
    }
    
    return 0;
}

void ws_handle_client(int sd, struct http_request *req, struct http_response *res, struct ws_info *info) {
    printf("Upgrading connection to WebSocket %d\n", sd);

    const char *client_key = map_get(req->headers, "Sec-WebSocket-Key");
    if (!client_key) {
        fprintf(stderr, "Missing Sec-WebSocket-Key header\n");
        res->status = HTTP_400_BAD_REQUEST;
        return;
    }

    req->websocket = 1;

    struct ws_container *container = ws_container_create(sd, info, req->path);
    if (!container) {
        fprintf(stderr, "Failed to create WebSocket container\n");
        res->status = HTTP_500_INTERNAL_SERVER_ERROR;
        return;
    }

    if (info->on_open){
        info->on_open(container->ws);
    }

    event_add(container->ev);

    /* Freed by main server */
    char* accept_key = malloc(128);
    if(!accept_key) {
        perror("Failed to allocate memory for accept key");
        res->status = HTTP_500_INTERNAL_SERVER_ERROR;
        return;
    }
    ws_compute_accept_key(client_key, accept_key);

    res->status = HTTP_101_SWITCHING_PROTOCOLS;
    map_insert(res->headers, "Sec-WebSocket-Accept", accept_key);
    map_insert(res->headers, "Upgrade", "websocket");
    map_insert(res->headers, "Connection", "Upgrade");
    res->body[0] = '\0';
}

static pthread_t ws_thread;
__attribute__((constructor)) void ws_constructor() {
    pthread_create(&ws_thread, NULL, ws_event_thread, NULL);
}

__attribute__((destructor)) void ws_destructor() {
    printf("Shutting down WebSocket thread\n");

    event_dispatch_stop();
    pthread_join(ws_thread, NULL);
}
