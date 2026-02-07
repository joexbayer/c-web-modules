#ifndef SCHEDULER_H
#define SCHEDULER_H

#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>

typedef void (*work_t)(void *);
typedef enum {
    ASYNC,
    SYNC
} worker_state_t;

struct work {
    work_t work;
    void *data;
    struct work *next;
};

struct scheduler {
    struct work *head;
    struct work *tail;
    size_t size;
    size_t capacity;
    pthread_mutex_t mutex;
    pthread_cond_t work_available;
    atomic_int running;
    atomic_int accepting;
    atomic_int draining;
    pthread_t thread;
};

int scheduler_init(struct scheduler *scheduler, size_t capacity);
void scheduler_shutdown(struct scheduler *scheduler);
int scheduler_add(struct scheduler *scheduler, work_t work, void *data, worker_state_t state);
void scheduler_request_stop(struct scheduler *scheduler, int drain);
int scheduler_pending_count(struct scheduler *scheduler);
void scheduler_cancel(struct scheduler *scheduler);

#endif // SCHEDULER_H
