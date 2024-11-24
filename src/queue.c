#include <queue.h>
#include <stdlib.h>
#include <stdio.h>

struct queue* queue_create(size_t max_size) {
    struct queue* q = (struct queue*)malloc(sizeof(struct queue));
    if (q == NULL) {
        return NULL;
    }

    q->buffer = (void**)malloc(max_size * sizeof(void*));
    if (q->buffer == NULL) {
        free(q);
        return NULL;
    }
    
    /* Initialize queue */
    q->head = 0;
    q->tail = 0;
    q->max_size = max_size;
    q->current_size = 0;
    
    /* Initialize mutex and condition variables */
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->not_full, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    return q;
}

void queue_destroy(struct queue* q) {
    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->not_full);
    pthread_cond_destroy(&q->not_empty);
    free(q->buffer);
    free(q);
}

queue_status_t queue_enqueue(struct queue* q, void* item) {
    pthread_mutex_lock(&q->lock);
    
    /* Wait until queue is not full */
    while (q->current_size == q->max_size) {
        pthread_cond_wait(&q->not_full, &q->lock);
    }
    
    /* Enqueue item at tail and move pointer */
    q->buffer[q->tail] = item;
    q->tail = (q->tail + 1) % q->max_size;
    q->current_size++;
    
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
    return QUEUE_OK;
}

queue_status_t queue_dequeue(struct queue* q, void** item) {
    pthread_mutex_lock(&q->lock);
    while (q->current_size == 0) {
        pthread_cond_wait(&q->not_empty, &q->lock);
    }

    /* Dequeue item at head and move pointer */
    *item = q->buffer[q->head];
    q->head = (q->head + 1) % q->max_size;
    q->current_size--;

    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->lock);
    return QUEUE_OK;
}

size_t queue_size(struct queue* q) {
    pthread_mutex_lock(&q->lock);
    size_t size = q->current_size;
    pthread_mutex_unlock(&q->lock);
    return size;
}