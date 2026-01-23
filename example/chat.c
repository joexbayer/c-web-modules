#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <cweb.h>

#define MAX_USERS 100

/* User Management */
static struct websocket *users[MAX_USERS];
static int user_count = 0;
static pthread_mutex_t user_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Add a WebSocket to the user list */
static void add_user(struct websocket *ws) {
    pthread_mutex_lock(&user_mutex);
    if (user_count < MAX_USERS) {
        users[user_count++] = ws;
    } else {
        printf("User limit reached. Cannot add more users.\n");
    }
    pthread_mutex_unlock(&user_mutex);
}

/* Remove a WebSocket from the user list */
static void remove_user(struct websocket *ws) {
    pthread_mutex_lock(&user_mutex);
    for (int i = 0; i < user_count; i++) {
        if (users[i] == ws) {
            users[i] = users[--user_count];
            break;
        }
    }
    pthread_mutex_unlock(&user_mutex);
}

/* Broadcast a message to all connected users */
static void broadcast_message(const char *message, size_t length) {
    pthread_mutex_lock(&user_mutex);
    for (int i = 0; i < user_count; i++) {
        users[i]->send(users[i], message, length);
    }
    pthread_mutex_unlock(&user_mutex);
}

/* WebSocket Handlers */
static void on_open(struct websocket *ws) {
    printf("WebSocket opened\n");
    add_user(ws);
    const char *welcome = "A new user has joined the chat!";
    broadcast_message(welcome, strlen(welcome));
}

static void on_message(struct websocket *ws, const char *message, size_t length) {
    printf("Message received: %.*s\n", (int)length, message);

    /* Create a broadcast message */
    char response[1024];
    snprintf(response, sizeof(response), "User %d: %.*s", (int)(ws - users[0] + 1), (int)length, message);
    broadcast_message(response, strlen(response));
}

static void on_close(struct websocket *ws) {
    printf("WebSocket closed\n");
    remove_user(ws);
    const char *goodbye = "A user has left the chat.";
    broadcast_message(goodbye, strlen(goodbye));
}

/* Serve the chat HTML page */
int chat_page(struct http_request *req, struct http_response *res) {
    const char *html = 
        "<!DOCTYPE html>"
        "<html>"
        "<head><title>Chat App</title></head>"
        "<body>"
        "<h1>Simple Chat App</h1>"
        "<textarea id=\"log\" cols=\"50\" rows=\"10\" readonly></textarea><br>"
        "<input id=\"msg\" type=\"text\" placeholder=\"Type your message...\"/>"
        "<button onclick=\"sendMessage()\">Send</button>"
        "<script>"
        "  const ws = new WebSocket('ws://localhost:8080/chat/ws');"
        "  ws.onmessage = (event) => {"
        "    document.getElementById('log').value += '\\n' + event.data;"
        "  };"
        "  function sendMessage() {"
        "    const msg = document.getElementById('msg').value;"
        "    ws.send(msg);"
        "    document.getElementById('msg').value = '';"
        "  }"
        "</script>"
        "</body>"
        "</html>";

    snprintf(res->body, HTTP_RESPONSE_SIZE, "%s", html);
    http_kv_insert(res->headers, "Content-Type", "text/html");
    res->status = HTTP_200_OK;
    return 0;
}

void unload() {
    /* Close connections */
    pthread_mutex_lock(&user_mutex);
    for (int i = 0; i < user_count; i++) {
        users[i]->close(users[i]);
    }
    pthread_mutex_unlock(&user_mutex);
}

/* Define the module */
export module_t config = {
    .name = "chat_app",
    .author = "cweb",
    .routes = {
        {"/chat", "GET", chat_page, NONE},
    },
    .size = 1,
    .websockets = {
        {"/chat/ws", on_open, on_message, on_close},
    },
    .ws_size = 1,
};
