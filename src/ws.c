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

typedef enum {
    WS_OPCODE_CONTINUATION = 0x0,
    WS_OPCODE_TEXT = 0x1,
    WS_OPCODE_BINARY = 0x2,
    WS_OPCODE_CLOSE = 0x8,
    WS_OPCODE_PING = 0x9,
    WS_OPCODE_PONG = 0xA
} websocket_opcode_t;

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

static struct list* websocket_list;
static pthread_mutex_t websocket_list_mutex = PTHREAD_MUTEX_INITIALIZER;

__attribute__((constructor)) void ws_init() {
    websocket_list = list_create();
    pthread_mutex_init(&websocket_list_mutex, NULL);
}

__attribute__((destructor)) void ws_close() {
    pthread_mutex_lock(&websocket_list_mutex);

    LIST_FOREACH(websocket_list, node) {
        struct websocket *ws = node->data;
        close(ws->client_fd);
        free(ws);
    }

    list_destroy(websocket_list);
    pthread_mutex_unlock(&websocket_list_mutex);
    pthread_mutex_destroy(&websocket_list_mutex);
}

/* Exposed, Needed for later */
static int ws_send(struct websocket *ws, const char *message, size_t length) {
    (void)ws;
    (void)message;
    (void)length;
    return 0;
}

__attribute__((used)) static struct websocket *ws_create(int client_fd) {
    struct websocket *ws = malloc(sizeof(struct websocket));
    if (!ws) {
        perror("Failed to allocate memory for websocket");
        return NULL;
    }

    ws->client_fd = client_fd;
    ws->session = NULL;
    ws->send = ws_send;

    pthread_mutex_lock(&websocket_list_mutex);
    list_add(websocket_list, ws);
    pthread_mutex_unlock(&websocket_list_mutex);

    return ws;
}

int ws_destroy(struct websocket *ws) {
    if (!ws) return -1;

    pthread_mutex_lock(&websocket_list_mutex);
    list_remove(websocket_list, ws);
    pthread_mutex_unlock(&websocket_list_mutex);

    free(ws);
    return 0;
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

void ws_compute_accept_key(const char *client_key, char *accept_key) {
    const char *websocket_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char combined[256];
    unsigned char sha1_result[SHA_DIGEST_LENGTH];

    snprintf(combined, sizeof(combined), "%s%s", client_key, websocket_guid);
    SHA1((unsigned char *)combined, strlen(combined), sha1_result);
    base64_encode(sha1_result, SHA_DIGEST_LENGTH, accept_key);
}

int http_is_websocket_upgrade(struct http_request *req) {
    const char *connection = map_get(req->headers, "Connection");
    const char *upgrade = map_get(req->headers, "Upgrade");
    
    if (connection && upgrade && strcasestr(connection, "Upgrade") && strcasecmp(upgrade, "websocket") == 0) {
        return 1;
    }
    
    return 0;
}

static void ws_handle_upgrade(int client_fd, struct http_request *req) {
    const char *client_key = map_get(req->headers, "Sec-WebSocket-Key");
    if (!client_key) {
        fprintf(stderr, "Missing Sec-WebSocket-Key header\n");
        close(client_fd);
        return;
    }

    char accept_key[128];
    ws_compute_accept_key(client_key, accept_key);

    char response[256];
    snprintf(response, sizeof(response),
             "HTTP/1.1 101 Switching Protocols\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Accept: %s\r\n\r\n",
             accept_key);

    send(client_fd, response, strlen(response), 0);
    req->websocket = 1;
}

static ws_frame_status_t ws_decode_frame(const unsigned char *data, size_t data_len, struct websocket_frame *frame) {
    if (data_len < 2) {
        return WS_FRAME_INCOMPLETE;
    }

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

static void ws_free_frame(struct websocket_frame *frame) {
    if (frame->payload) {
        free(frame->payload);
        frame->payload = NULL;
    }
}

static void ws_send_frame(int client_fd, const char *message, uint8_t opcode) {
    unsigned char frame[1024];
    size_t message_len = strlen(message);
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
        return;
    }

    memcpy(&frame[offset], message, message_len);
    offset += message_len;

    send(client_fd, frame, offset, 0);
}

static void ws_handle_websocket_frames(int client_fd) {
    unsigned char buffer[2048];
    ssize_t received = recv(client_fd, buffer, sizeof(buffer), 0);
    if (received <= 0) {
        perror("Connection closed or error");
        return;
    }

    struct websocket_frame frame;
    ws_frame_status_t status = ws_decode_frame(buffer, received, &frame);
    if (status == WS_FRAME_COMPLETE) {
        printf("Received WebSocket frame: Opcode=%d, Payload=%.*s\n",
               frame.opcode, (int)frame.payload_len, frame.payload);

        ws_send_frame(client_fd, (const char *)frame.payload, frame.opcode);
        ws_free_frame(&frame);
    } else if (status == WS_FRAME_ERROR) {
        fprintf(stderr, "Error decoding WebSocket frame\n");
    }
}

void ws_handle_client(int client_fd, struct http_request *req) {
    printf("Upgrading connection to WebSocket\n");
    ws_handle_upgrade(client_fd, req);
    while (req->websocket) {
        ws_handle_websocket_frames(client_fd);
    }

    close(client_fd);
}