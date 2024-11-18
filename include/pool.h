#ifndef POOL_H
#define POOL_H

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdatomic.h>

/* Task structure */
struct task {
    void (*function)(void *);
    void *arg;
    struct task *next;
};

/* Thread pool structure */
struct thread_pool {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_t *threads;
    int *thread_active;
    struct task *task_queue;
    atomic_int num_threads;
    int max_threads;
    int queue_length;
    volatile int stop;
    atomic_int active_threads; /* Number of threads actively processing */
};

struct thread_pool *thread_pool_init(int num_threads);
void thread_pool_add_task(struct thread_pool *pool, void (*function)(void *), void *arg);
void thread_pool_destroy(struct thread_pool *pool);
int thread_pool_is_full(struct thread_pool *pool);

#endif /* POOL_H */
