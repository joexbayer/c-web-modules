#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include "pool.h"
#include <errno.h>

static void *thread_pool_worker(void *arg);

struct thread_pool *thread_pool_init(int num_threads) {
    if (num_threads <= 0) {
        return NULL;
    }

    struct thread_pool *pool = malloc(sizeof(struct thread_pool));
    if (pool == NULL) {
        fprintf(stderr, "[ERROR] Failed to allocate memory for thread pool\n");
        return NULL;
    }

    pool->max_threads = num_threads;
    pool->task_queue = NULL;
    pool->task_tail = NULL;
    pool->queue_length = 0;
    atomic_init(&pool->stop, 0);
    atomic_init(&pool->active_threads, 0);

    if (pthread_mutex_init(&pool->lock, NULL) != 0) {
        free(pool);
        return NULL;
    }

    if (pthread_cond_init(&pool->cond, NULL) != 0) {
        pthread_mutex_destroy(&pool->lock);
        free(pool);
        return NULL;
    }

    pool->threads = malloc((size_t)num_threads * sizeof(pthread_t));
    if (pool->threads == NULL) {
        fprintf(stderr, "[ERROR] Failed to allocate memory for threads\n");
        pthread_cond_destroy(&pool->cond);
        pthread_mutex_destroy(&pool->lock);
        free(pool);
        return NULL;
    }

    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&pool->threads[i], NULL, thread_pool_worker, pool) != 0) {
            fprintf(stderr, "[ERROR] Failed to create thread %d\n", i);
            free(pool->threads);
            pthread_cond_destroy(&pool->cond);
            pthread_mutex_destroy(&pool->lock);
            free(pool);
            return NULL;
        }
    }

    printf("[INFO] Initialized thread pool with %d threads\n", num_threads);

    return pool;
}

static void cleanup_unlock(void *arg) {
    pthread_mutex_unlock((pthread_mutex_t *)arg);
}

static void *thread_pool_worker(void *arg) {
    struct thread_pool *pool = (struct thread_pool *)arg;

    pthread_cleanup_push(cleanup_unlock, &pool->lock);

    while (1) {
        pthread_mutex_lock(&pool->lock);

        while (pool->task_queue == NULL && !atomic_load(&pool->stop)) {
            pthread_cond_wait(&pool->cond, &pool->lock);
        }

        if (atomic_load(&pool->stop) && pool->task_queue == NULL) {
            pthread_mutex_unlock(&pool->lock);
            break;
        }

        struct task *task = pool->task_queue;
        if (task != NULL) {
            pool->task_queue = task->next;
            if (pool->task_queue == NULL) {
                pool->task_tail = NULL;
            }
            pool->queue_length--;
            atomic_fetch_add(&pool->active_threads, 1);
        }

        pthread_mutex_unlock(&pool->lock);

        if (task != NULL) {
            task->function(task->arg);
            atomic_fetch_sub(&pool->active_threads, 1);
            free(task);
        }
    }

    pthread_cleanup_pop(1);
    return NULL;
}

int thread_pool_is_full(struct thread_pool *pool) {
    if (!pool) {
        return 0;
    }
    return atomic_load(&pool->active_threads) >= pool->max_threads;
}

void thread_pool_add_task(struct thread_pool *pool, void (*function)(void *), void *arg) {
    if (!pool || !function) {
        return;
    }

    struct task *task = malloc(sizeof(struct task));
    if (task == NULL) {
        fprintf(stderr, "[ERROR] Failed to allocate memory for task\n");
        return;
    }

    task->function = function;
    task->arg = arg;
    task->next = NULL;

    pthread_mutex_lock(&pool->lock);

    if (atomic_load(&pool->stop)) {
        pthread_mutex_unlock(&pool->lock);
        free(task);
        return;
    }

    if (pool->task_tail == NULL) {
        pool->task_queue = task;
        pool->task_tail = task;
    } else {
        pool->task_tail->next = task;
        pool->task_tail = task;
    }

    pool->queue_length++;
    pthread_cond_signal(&pool->cond);
    pthread_mutex_unlock(&pool->lock);
}

void thread_pool_request_stop(struct thread_pool *pool) {
    if (!pool) {
        return;
    }

    pthread_mutex_lock(&pool->lock);
    atomic_store(&pool->stop, 1);
    pthread_cond_broadcast(&pool->cond);
    pthread_mutex_unlock(&pool->lock);
}

int thread_pool_pending_count(struct thread_pool *pool) {
    if (!pool) {
        return 0;
    }

    pthread_mutex_lock(&pool->lock);
    int pending = pool->queue_length + atomic_load(&pool->active_threads);
    pthread_mutex_unlock(&pool->lock);
    return pending;
}

void thread_pool_cancel_all(struct thread_pool *pool) {
    if (!pool || !pool->threads) {
        return;
    }

    for (int i = 0; i < pool->max_threads; i++) {
        pthread_cancel(pool->threads[i]);
    }
}

void thread_pool_destroy(struct thread_pool *pool) {
    if (!pool) {
        return;
    }

    printf("[INFO] Destroying thread pool\n");

    thread_pool_request_stop(pool);

    for (int i = 0; i < pool->max_threads; i++) {
        int ret = pthread_join(pool->threads[i], NULL);
        if (ret != 0) {
            fprintf(stderr, "[ERROR] Failed to join thread %d: %s\n", i, strerror(ret));
        }
    }

    free(pool->threads);
    pthread_mutex_destroy(&pool->lock);
    pthread_cond_destroy(&pool->cond);

    while (pool->task_queue != NULL) {
        struct task *tmp = pool->task_queue;
        pool->task_queue = tmp->next;
        free(tmp);
    }

    free(pool);
    printf("[INFO] Thread pool destroyed\n");
}
