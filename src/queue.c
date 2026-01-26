#include <queue.h>
#include <stdlib.h>
#include <stdio.h>

struct queue* queue_create(size_t max_size) {
    if (max_size == 0) {
        return NULL;
    }
    struct queue* q = (struct queue*)malloc(sizeof(struct queue));
    if (q == NULL) {
        return NULL;
    }

    q->buffer = (void**)malloc(max_size * sizeof(void*));
    if (q->buffer == NULL) {
        free(q);
        return NULL;
    }

    q->head = 0;
    q->tail = 0;
    q->max_size = max_size;
    q->current_size = 0;

    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->not_full, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    return q;
}

void queue_destroy(struct queue* q) {
    if (!q) {
        return;
    }

    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->not_full);
    pthread_cond_destroy(&q->not_empty);
    free(q->buffer);
    free(q);
}

queue_status_t queue_try_enqueue(struct queue* q, void* item) {
    if (!q) {
        return QUEUE_ERROR;
    }

    pthread_mutex_lock(&q->lock);

    if (q->current_size == q->max_size) {
        pthread_mutex_unlock(&q->lock);
        return QUEUE_FULL;
    }

    q->buffer[q->tail] = item;
    q->tail = (q->tail + 1) % q->max_size;
    q->current_size++;

    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
    return QUEUE_OK;
}

queue_status_t queue_enqueue(struct queue* q, void* item) {
    if (!q) {
        return QUEUE_ERROR;
    }

    pthread_mutex_lock(&q->lock);

    while (q->current_size == q->max_size) {
        pthread_cond_wait(&q->not_full, &q->lock);
    }

    q->buffer[q->tail] = item;
    q->tail = (q->tail + 1) % q->max_size;
    q->current_size++;

    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
    return QUEUE_OK;
}

queue_status_t queue_try_dequeue(struct queue* q, void** item) {
    if (!q || !item) {
        return QUEUE_ERROR;
    }

    pthread_mutex_lock(&q->lock);

    if (q->current_size == 0) {
        pthread_mutex_unlock(&q->lock);
        return QUEUE_EMPTY;
    }

    *item = q->buffer[q->head];
    q->head = (q->head + 1) % q->max_size;
    q->current_size--;

    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->lock);
    return QUEUE_OK;
}

queue_status_t queue_dequeue(struct queue* q, void** item) {
    if (!q || !item) {
        return QUEUE_ERROR;
    }

    pthread_mutex_lock(&q->lock);
    while (q->current_size == 0) {
        pthread_cond_wait(&q->not_empty, &q->lock);
    }

    *item = q->buffer[q->head];
    q->head = (q->head + 1) % q->max_size;
    q->current_size--;

    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->lock);
    return QUEUE_OK;
}

size_t queue_size(struct queue* q) {
    if (!q) {
        return 0;
    }

    pthread_mutex_lock(&q->lock);
    size_t size = q->current_size;
    pthread_mutex_unlock(&q->lock);
    return size;
}
