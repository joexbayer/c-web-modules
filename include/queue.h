#ifndef QUEUE_H
#define QUEUE_H

#include <stdint.h>
#include <pthread.h>
#include <stddef.h>

typedef enum queue_status {
    QUEUE_OK,
    QUEUE_FULL,
    QUEUE_EMPTY,
    QUEUE_ERROR
} queue_status_t;

struct queue {
    void **buffer;
    size_t head;
    size_t tail;
    size_t max_size;
    size_t current_size;
    pthread_mutex_t lock;
    pthread_cond_t not_full;
    pthread_cond_t not_empty;
};

struct queue* queue_create(size_t max_size);
void queue_destroy(struct queue* q);
queue_status_t queue_enqueue(struct queue* q, void* item);
queue_status_t queue_try_enqueue(struct queue* q, void* item);
queue_status_t queue_dequeue(struct queue* q, void** item);
queue_status_t queue_try_dequeue(struct queue* q, void** item);
size_t queue_size(struct queue* q);

#endif // QUEUE_H
