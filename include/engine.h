#ifndef ENGINE_H
#define ENGINE_H

#include <router.h>

void engine_init(void);
void engine_shutdown(void);
void block_signals_in_thread(void);
void setup_thread_signals(void);
void safe_execute_handler(handler_t handler, struct cweb_context *ctx, http_request_t *req, http_response_t *res);
void safe_execute_module_hook(void (*hook)(struct cweb_context *), struct cweb_context *ctx);

#endif // ENGINE_H
