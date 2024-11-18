#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include "pool.h"
#include <errno.h>

/* Prototypes */
static void *thread_pool_worker(void *arg);

/* Initialize the thread pool */
struct thread_pool *thread_pool_init(int num_threads) {
    struct thread_pool *pool = malloc(sizeof(struct thread_pool));
    if (pool == NULL) {
        fprintf(stderr, "[ERROR] Failed to allocate memory for thread pool\n");
        return NULL;
    }

    pool->num_threads = num_threads;
    pool->max_threads = num_threads;
    pool->task_queue = NULL;
    pool->stop = 0;
    pool->queue_length = 0;

    pthread_mutex_init(&pool->lock, NULL);
    pthread_cond_init(&pool->cond, NULL);

    pool->threads = malloc(num_threads * sizeof(pthread_t));
    if (pool->threads == NULL) {
        fprintf(stderr, "[ERROR] Failed to allocate memory for threads\n");
        free(pool);
        return NULL;
    }

    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&pool->threads[i], NULL, thread_pool_worker, pool) != 0) {
            fprintf(stderr, "[ERROR] Failed to create thread %d\n", i);
            free(pool->threads);
            free(pool);
            return NULL;
        }
    }

    printf("[INFO] Initialized thread pool with %d threads\n", num_threads);

    return pool;
}


/* Worker thread function */
static void *thread_pool_worker(void *arg) {
    struct thread_pool *pool = (struct thread_pool *)arg;

    while (1) {
        pthread_mutex_lock(&pool->lock);

        /* Wait for tasks or stop signal */
        while (pool->task_queue == NULL && !pool->stop) {
            pthread_cond_wait(&pool->cond, &pool->lock);
        }

        if (pool->stop) {
            pthread_mutex_unlock(&pool->lock);
            break;
        }

        /* Fetch a task from the queue */
        struct task *task = pool->task_queue;
        if (task != NULL) {
            pool->task_queue = task->next;
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

    return NULL;
}

int thread_pool_is_full(struct thread_pool *pool) {
    return atomic_load(&pool->active_threads) == pool->num_threads;
}

/* Add a task to the thread pool */
void thread_pool_add_task(struct thread_pool *pool, void (*function)(void *), void *arg) {
    struct task *task = malloc(sizeof(struct task));
    if (task == NULL) {
        fprintf(stderr, "[ERROR] Failed to allocate memory for task\n");
        return;
    }

    task->function = function;
    task->arg = arg;
    task->next = NULL;

    pthread_mutex_lock(&pool->lock);

    /* Add the task to the queue */
    if (pool->task_queue == NULL) {
        pool->task_queue = task;
    } else {
        struct task *tmp = pool->task_queue;
        while (tmp->next != NULL) {
            tmp = tmp->next;
        }
        tmp->next = task;
    }

    pool->queue_length++;
    pthread_cond_signal(&pool->cond);
    pthread_mutex_unlock(&pool->lock);
}


/* Destroy the thread pool */
void thread_pool_destroy(struct thread_pool *pool) {
    printf("[INFO] Destroying thread pool\n");

    pthread_mutex_lock(&pool->lock);
    pool->stop = 1;
    pthread_cond_broadcast(&pool->cond);
    pthread_mutex_unlock(&pool->lock);

    /* Join all threads */
    for (int i = 0; i < pool->num_threads; i++) {
        pthread_join(pool->threads[i], NULL);
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
