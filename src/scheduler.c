#include <scheduler.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>

static int add_work(work_t work, void *data, worker_state_t state);

struct scheduler internal_scheduler = {
    .queue = NULL,
    .size = 0,
    .capacity = 10,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .add = add_work,
};
struct scheduler *exposed_scheduler = &internal_scheduler;

static pthread_t scheduler_thread;
static pthread_cond_t work_available = PTHREAD_COND_INITIALIZER;
static volatile atomic_int running = 1;

static int add_work(work_t work, void *data, worker_state_t state) {
    struct work *new_work = (struct work *)malloc(sizeof(struct work));
    if (new_work == NULL) {
        perror("Error allocating memory for work");
        return -1;
    }

    /* TODO: Implement the choice of state... */
    (void)state;

    new_work->work = work;
    new_work->data = data;
    new_work->next = NULL;

    pthread_mutex_lock(&internal_scheduler.mutex);
    if (internal_scheduler.size == 0) {
        internal_scheduler.queue = new_work;
    } else {
        struct work *current = internal_scheduler.queue;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = new_work;
    }
    internal_scheduler.size++;
    pthread_mutex_unlock(&internal_scheduler.mutex);

    /* use this to signal the thread that new work is available */
    pthread_cond_signal(&work_available);

    return 0;
}

static void* scheduler_thread_function(void *arg) {
    (void)arg;

    while (running) {
        pthread_mutex_lock(&internal_scheduler.mutex);

        /* Wait until the add_work functions signals that new work is avaiable. */
        while (internal_scheduler.size == 0 && running) {
            /* Avoid constantly running */
            pthread_cond_wait(&work_available, &internal_scheduler.mutex);
        }
 
        if (!running) {
            pthread_mutex_unlock(&internal_scheduler.mutex);
            break;
        }

        struct work *current = internal_scheduler.queue;
        internal_scheduler.queue = current->next;
        internal_scheduler.size--;

        pthread_mutex_unlock(&internal_scheduler.mutex);

        current->work(current->data);
        free(current);
    }

    return NULL;
}

__attribute__((constructor)) void scheduler_init() {
    if (pthread_create(&scheduler_thread, NULL, scheduler_thread_function, NULL) != 0) {
        perror("Error creating scheduler thread");
        exit(EXIT_FAILURE);
    }
    /* We dont wnat to pthread_detach(scheduler_thread); as the pthread_join in the destructor.*/
}

__attribute__((destructor)) void scheduler_destroy() {
    running = 0;
    pthread_cond_signal(&work_available);
    pthread_join(scheduler_thread, NULL);
    printf("[SHUTDOWN] Scheduler destroyed\n");
}