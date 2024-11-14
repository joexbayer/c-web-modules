#include "http.h"
#include "router.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <setjmp.h>

static sigjmp_buf jump_buffer;

/* Signal handler for fatal errors */
void fault_handler(int sig, siginfo_t *info, void *ucontext) {
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

void safe_execute_handler(handler_t handler, struct http_request *req, struct http_response *res) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fault_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;

    if (sigaction(SIGSEGV, &sa, NULL) == -1 ||
        sigaction(SIGBUS, &sa, NULL) == -1 ||
        sigaction(SIGFPE, &sa, NULL) == -1 ||
        sigaction(SIGILL, &sa, NULL) == -1) {
        perror("Failed to set up signal handlers");
        exit(EXIT_FAILURE);
    }

    if (sigsetjmp(jump_buffer, 1) == 0) {
        handler(req, res);
    } else {
        snprintf(res->body, HTTP_RESPONSE_SIZE, "Handler execution failed: Fatal signal detected.\n");
        res->status = HTTP_500_INTERNAL_SERVER_ERROR;
    }

    sa.sa_handler = SIG_DFL;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
}