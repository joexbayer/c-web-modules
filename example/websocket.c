#include <stdio.h>
#include <string.h>
#include <cweb.h>

static void on_open(struct cweb_context *ctx, websocket_t *ws) {
    printf("WebSocket opened\n");
}

static void on_message(struct cweb_context *ctx, websocket_t *ws, const char *message, size_t length) {
    char response[1024];
    snprintf(response, sizeof(response), "You: %s", message);
    ws->send(ws, response, strlen(response));
}

static void on_close(struct cweb_context *ctx, websocket_t *ws) {
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
