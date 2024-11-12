#define _GNU_SOURCE
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

#ifdef __linux__
#include <sched.h>
#endif

static sigjmp_buf jump_buffer;

/* Signal handler for segmentation faults */
void segfault_handler(int sig, siginfo_t *info, void *ucontext) {
    fprintf(stderr, "Segmentation fault detected in handler execution. Signal %d received at address %p.\n", sig, info->si_addr);
    siglongjmp(jump_buffer, 1);
}

void safe_execute_handler(handler_t handler, struct http_request *req, struct http_response *res) {
    struct sigaction sa;
    sa.sa_sigaction = segfault_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;

    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        perror("Failed to set up signal handler");
        exit(EXIT_FAILURE);
    }

    if (sigsetjmp(jump_buffer, 1) == 0) {
        handler(req, res);
    } else {
        snprintf(res->body, HTTP_RESPONSE_SIZE, "Handler execution failed: Segmentation fault.\n");
        res->status = HTTP_500_INTERNAL_SERVER_ERROR;
    }
}