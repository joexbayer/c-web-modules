#ifndef POOL_H
#define POOL_H

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdatomic.h>

struct task {
    void (*function)(void *);
    void *arg;
    struct task *next;
};

struct thread_pool {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_t *threads;
    struct task *task_queue;
    struct task *task_tail;
    int max_threads;
    int queue_length;
    atomic_int stop;
    atomic_int active_threads;
};

struct thread_pool *thread_pool_init(int num_threads);
void thread_pool_add_task(struct thread_pool *pool, void (*function)(void *), void *arg);
void thread_pool_request_stop(struct thread_pool *pool);
int thread_pool_pending_count(struct thread_pool *pool);
void thread_pool_cancel_all(struct thread_pool *pool);
void thread_pool_destroy(struct thread_pool *pool);
int thread_pool_is_full(struct thread_pool *pool);

#endif /* POOL_H */
