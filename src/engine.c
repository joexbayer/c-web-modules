#include "http.h"
#include "router.h"
#include "engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h>
#include <setjmp.h>

static __thread sigjmp_buf jump_buffer;
static __thread int guard_depth = 0;
static int handlers_installed = 0;
static struct sigaction prev_segv;
static struct sigaction prev_bus;
static struct sigaction prev_fpe;
static struct sigaction prev_ill;

static void fault_handler(int sig, siginfo_t *info, void *ucontext) {
    (void)ucontext;
    const char *signal_name;

    switch (sig) {
        case SIGSEGV: signal_name = "Segmentation fault"; break;
        case SIGBUS:  signal_name = "Bus error"; break;
        case SIGFPE:  signal_name = "Floating-point exception"; break;
        case SIGILL:  signal_name = "Illegal instruction"; break;
        default:      signal_name = "Unknown signal"; break;
    }

    fprintf(stderr, "%s detected in handler execution. Signal %d received at address %p.\n",
            signal_name, sig, info->si_addr);
    siglongjmp(jump_buffer, 1);
}

void engine_init(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fault_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;

    if (sigaction(SIGSEGV, &sa, &prev_segv) == -1 ||
        sigaction(SIGBUS, &sa, &prev_bus) == -1 ||
        sigaction(SIGFPE, &sa, &prev_fpe) == -1 ||
        sigaction(SIGILL, &sa, &prev_ill) == -1) {
        perror("[ERROR] Failed to set up global signal handlers");
        exit(EXIT_FAILURE);
    }
    handlers_installed = 1;
}

void engine_shutdown(void) {
    if (!handlers_installed) {
        return;
    }

    if (sigaction(SIGSEGV, &prev_segv, NULL) == -1 ||
        sigaction(SIGBUS, &prev_bus, NULL) == -1 ||
        sigaction(SIGFPE, &prev_fpe, NULL) == -1 ||
        sigaction(SIGILL, &prev_ill, NULL) == -1) {
        perror("[ERROR] Failed to restore signal handlers");
    }
    handlers_installed = 0;
}

void block_signals_in_thread(void) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGSEGV);
    sigaddset(&mask, SIGBUS);
    sigaddset(&mask, SIGFPE);
    sigaddset(&mask, SIGILL);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL) != 0) {
        perror("[ERROR] Failed to block signals in thread");
        exit(EXIT_FAILURE);
    }
}

void setup_thread_signals(void) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGSEGV);
    sigaddset(&mask, SIGBUS);
    sigaddset(&mask, SIGFPE);
    sigaddset(&mask, SIGILL);

    if (pthread_sigmask(SIG_UNBLOCK, &mask, NULL) != 0) {
        perror("[ERROR] Failed to unblock signals for thread");
        exit(EXIT_FAILURE);
    }
}

static int safe_guard_enter(void) {
    setup_thread_signals();
    if (guard_depth == 0) {
        if (sigsetjmp(jump_buffer, 1) != 0) {
            guard_depth = 0;
            return -1;
        }
    }
    guard_depth++;
    return 0;
}

static void safe_guard_exit(void) {
    if (guard_depth > 0) {
        guard_depth--;
    }
}

void safe_execute_handler(handler_t handler, struct cweb_context *ctx, http_request_t *req, http_response_t *res) {
    if (safe_guard_enter() == 0) {
        handler(ctx, req, res);
        safe_guard_exit();
    } else {
        snprintf(res->body, HTTP_RESPONSE_SIZE, "Handler execution failed: Fatal signal detected.\n");
        res->status = HTTP_500_INTERNAL_SERVER_ERROR;
    }
}

void safe_execute_module_hook(void (*hook)(struct cweb_context *), struct cweb_context *ctx) {
    if (!hook) {
        return;
    }

    if (safe_guard_enter() == 0) {
        hook(ctx);
        safe_guard_exit();
    } else {
        fprintf(stderr, "Module hook execution failed: Fatal signal detected.\n");
    }
}

int safe_execute_job_run(job_run_t handler, struct cweb_context *ctx, const job_payload_t *payload, job_ctx_t *job, int *rc_out) {
    if (!handler) {
        return -1;
    }

    if (safe_guard_enter() != 0) {
        if (rc_out) {
            *rc_out = -1;
        }
        fprintf(stderr, "[ERROR] Job handler crashed: Fatal signal detected.\n");
        return -1;
    }

    int rc = handler(ctx, payload, job);
    safe_guard_exit();
    if (rc_out) {
        *rc_out = rc;
    }
    return 0;
}

void safe_execute_job_cancel(void (*cancel)(struct cweb_context *ctx, const char *job_uuid), struct cweb_context *ctx, const char *job_uuid) {
    if (!cancel) {
        return;
    }

    if (safe_guard_enter() == 0) {
        cancel(ctx, job_uuid);
        safe_guard_exit();
    } else {
        fprintf(stderr, "[ERROR] Job cancel crashed: Fatal signal detected.\n");
    }
}

int safe_execute_ws_on_open(void (*on_open)(struct cweb_context *, websocket_t *), struct cweb_context *ctx, websocket_t *ws) {
    if (!on_open) {
        return 0;
    }

    if (safe_guard_enter() != 0) {
        fprintf(stderr, "[ERROR] WebSocket on_open crashed: Fatal signal detected.\n");
        return -1;
    }

    on_open(ctx, ws);
    safe_guard_exit();
    return 0;
}

int safe_execute_ws_on_message(void (*on_message)(struct cweb_context *, websocket_t *, const char *message, size_t length), struct cweb_context *ctx, websocket_t *ws, const char *message, size_t length) {
    if (!on_message) {
        return 0;
    }

    if (safe_guard_enter() != 0) {
        fprintf(stderr, "[ERROR] WebSocket on_message crashed: Fatal signal detected.\n");
        return -1;
    }

    on_message(ctx, ws, message, length);
    safe_guard_exit();
    return 0;
}

int safe_execute_ws_on_close(void (*on_close)(struct cweb_context *, websocket_t *), struct cweb_context *ctx, websocket_t *ws) {
    if (!on_close) {
        return 0;
    }

    if (safe_guard_enter() != 0) {
        fprintf(stderr, "[ERROR] WebSocket on_close crashed: Fatal signal detected.\n");
        return -1;
    }

    on_close(ctx, ws);
    safe_guard_exit();
    return 0;
}
