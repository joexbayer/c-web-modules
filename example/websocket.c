#include <stdio.h>
#include <cweb.h>

static void on_open(struct websocket *ws) {
    printf("WebSocket opened\n");
}

static void on_message(struct websocket *ws, const char *message, size_t length) {
    printf("Received message: %.*s\n", (int)length, message);
    ws->send(ws, message, length);
}

static void on_close(struct websocket *ws) {
    printf("WebSocket closed\n");
}

/* Define the routes for the module */
export module_t config = {
    .name = "websocket",
    .author = "cweb",
    .websockets = {
        {"/websocket", on_open, on_message, on_close},
    },
    .ws_size = 1,
};