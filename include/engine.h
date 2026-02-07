#ifndef ENGINE_H
#define ENGINE_H

#include <router.h>

void engine_init(void);
void engine_shutdown(void);
void block_signals_in_thread(void);
void setup_thread_signals(void);
void safe_execute_handler(handler_t handler, struct cweb_context *ctx, http_request_t *req, http_response_t *res);
void safe_execute_module_hook(void (*hook)(struct cweb_context *), struct cweb_context *ctx);
int safe_execute_job_run(job_run_t handler, struct cweb_context *ctx, const job_payload_t *payload, job_ctx_t *job, int *rc_out);
void safe_execute_job_cancel(void (*cancel)(struct cweb_context *ctx, const char *job_uuid), struct cweb_context *ctx, const char *job_uuid);
int safe_execute_ws_on_open(void (*on_open)(struct cweb_context *, websocket_t *), struct cweb_context *ctx, websocket_t *ws);
int safe_execute_ws_on_message(void (*on_message)(struct cweb_context *, websocket_t *, const char *message, size_t length), struct cweb_context *ctx, websocket_t *ws, const char *message, size_t length);
int safe_execute_ws_on_close(void (*on_close)(struct cweb_context *, websocket_t *), struct cweb_context *ctx, websocket_t *ws);

#endif // ENGINE_H
