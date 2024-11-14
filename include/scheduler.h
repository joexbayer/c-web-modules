#ifndef SCHEDULER_H
#define SCHEDULER_H

#include <pthread.h>

typedef enum {
    ASYNC,
    SYNC
} worker_state_t;

struct work {
    void (*work)(void *);
    void *data;
    struct work *next;
}; 

struct scheduler {
    struct work *queue;
    int size;
    int capacity;

    pthread_mutex_t mutex;

    void (*add)(void (*work)(void *), void *data, worker_state_t state);
};
extern struct scheduler *exposed_scheduler;

#endif // SCHEDULER_H