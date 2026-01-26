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

    if (sigaction(SIGSEGV, &sa, NULL) == -1 ||
        sigaction(SIGBUS, &sa, NULL) == -1 ||
        sigaction(SIGFPE, &sa, NULL) == -1 ||
        sigaction(SIGILL, &sa, NULL) == -1) {
        perror("[ERROR] Failed to set up global signal handlers");
        exit(EXIT_FAILURE);
    }
}

void engine_shutdown(void) {
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

void safe_execute_handler(handler_t handler, struct cweb_context *ctx, http_request_t *req, http_response_t *res) {
    setup_thread_signals();

    if (sigsetjmp(jump_buffer, 1) == 0) {
        handler(ctx, req, res);
    } else {
        snprintf(res->body, HTTP_RESPONSE_SIZE, "Handler execution failed: Fatal signal detected.\n");
        res->status = HTTP_500_INTERNAL_SERVER_ERROR;
    }
}

void safe_execute_module_hook(void (*hook)(struct cweb_context *), struct cweb_context *ctx) {
    if (!hook) {
        return;
    }

    setup_thread_signals();

    if (sigsetjmp(jump_buffer, 1) == 0) {
        hook(ctx);
    } else {
        fprintf(stderr, "Module hook execution failed: Fatal signal detected.\n");
    }
}
