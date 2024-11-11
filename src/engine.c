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

#define SANDBOX_DIR "./tmp"
#define SHARED_MEM_SIZE HTTP_RESPONSE_SIZE

static sigjmp_buf jump_buffer;

/* Signal handler for segmentation faults */
void segfault_handler(int sig, siginfo_t *info, void *ucontext) {
    fprintf(stderr, "Segmentation fault detected in handler execution. Signal %d received at address %p.\n", sig, info->si_addr);
    siglongjmp(jump_buffer, 1);
}

void safe_execute_handler(handler_t handler, struct http_request *req, struct http_response *res) {
    
    pid_t pid = fork();
    if (pid < 0) {
        perror("Fork failed");
        res->status = HTTP_500_INTERNAL_SERVER_ERROR;
        snprintf(res->body, SHARED_MEM_SIZE, "Internal error: Fork failed.\n");
        munmap(res->body, SHARED_MEM_SIZE);
        return;
    }

    if (pid == 0) {
        if (chroot(SANDBOX_DIR) != 0 || chdir("/") != 0) {
            perror("Failed to set up chroot sandbox");
            exit(EXIT_FAILURE);
        }

        if (setgid(getgid()) != 0 || setuid(getuid()) != 0) {
            perror("Failed to drop privileges");
            exit(EXIT_FAILURE);
        }

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
            printf("Handler executed successfully\n");
            exit(0);
        } else {
            snprintf(res->body, SHARED_MEM_SIZE, "Handler execution failed: Segmentation fault.\n");
            fprintf(stderr, "Recovered from segmentation fault in handler\n");
            exit(1); 
        }
    } else {
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            res->status = HTTP_200_OK;
        } else {
            res->status = HTTP_500_INTERNAL_SERVER_ERROR;
            if (strlen(res->body) == 0) {
                snprintf(res->body, SHARED_MEM_SIZE, "Internal error: Handler execution failed.\n");
            }
        }
    }
}