#ifndef WS_H
#define WS_H

#include <pthread.h>
#include <list.h>
#include <cweb.h>

struct ws_server {
    struct list *containers;
    pthread_mutex_t mutex;
    pthread_t thread;
    int running;
};

int ws_init(struct ws_server *ws);
void ws_shutdown(struct ws_server *ws, struct cweb_context *ctx);
void ws_handle_client(struct ws_server *ws, struct cweb_context *ctx, int sd, http_request_t *req, http_response_t *res, struct ws_info *info);
int ws_confirm_open(struct ws_server *ws, struct cweb_context *ctx, int sd);
int ws_update_container(struct ws_server *ws, const char* path, struct ws_info *info);
void ws_force_close(struct ws_server *ws, struct ws_info *info);

#endif // WS_H
