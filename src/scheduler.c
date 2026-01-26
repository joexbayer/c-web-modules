#include <scheduler.h>
#include <stdlib.h>
#include <stdio.h>

static void* scheduler_thread_function(void *arg) {
    struct scheduler *scheduler = (struct scheduler *)arg;

    while (atomic_load(&scheduler->running)) {
        pthread_mutex_lock(&scheduler->mutex);

        while (scheduler->size == 0 && atomic_load(&scheduler->running)) {
            pthread_cond_wait(&scheduler->work_available, &scheduler->mutex);
        }

        if (!atomic_load(&scheduler->running)) {
            pthread_mutex_unlock(&scheduler->mutex);
            break;
        }

        struct work *current = scheduler->head;
        if (current) {
            scheduler->head = current->next;
            if (!scheduler->head) {
                scheduler->tail = NULL;
            }
            scheduler->size--;
        }

        pthread_mutex_unlock(&scheduler->mutex);

        if (current) {
            current->work(current->data);
            free(current);
        }
    }

    return NULL;
}

int scheduler_init(struct scheduler *scheduler, size_t capacity) {
    if (!scheduler) {
        return -1;
    }

    scheduler->head = NULL;
    scheduler->tail = NULL;
    scheduler->size = 0;
    scheduler->capacity = capacity;

    if (pthread_mutex_init(&scheduler->mutex, NULL) != 0) {
        return -1;
    }

    if (pthread_cond_init(&scheduler->work_available, NULL) != 0) {
        pthread_mutex_destroy(&scheduler->mutex);
        return -1;
    }

    atomic_store(&scheduler->running, 1);
    if (pthread_create(&scheduler->thread, NULL, scheduler_thread_function, scheduler) != 0) {
        pthread_cond_destroy(&scheduler->work_available);
        pthread_mutex_destroy(&scheduler->mutex);
        return -1;
    }

    return 0;
}

void scheduler_shutdown(struct scheduler *scheduler) {
    if (!scheduler) {
        return;
    }

    atomic_store(&scheduler->running, 0);
    pthread_cond_signal(&scheduler->work_available);
    pthread_join(scheduler->thread, NULL);

    pthread_mutex_destroy(&scheduler->mutex);
    pthread_cond_destroy(&scheduler->work_available);

    while (scheduler->head) {
        struct work *current = scheduler->head;
        scheduler->head = current->next;
        free(current);
    }

    scheduler->tail = NULL;
    scheduler->size = 0;
    printf("[SHUTDOWN] Scheduler destroyed\n");
}

int scheduler_add(struct scheduler *scheduler, work_t work, void *data, worker_state_t state) {
    if (!scheduler || !work) {
        return -1;
    }

    struct work *new_work = malloc(sizeof(*new_work));
    if (!new_work) {
        perror("Error allocating memory for work");
        return -1;
    }

    (void)state;

    new_work->work = work;
    new_work->data = data;
    new_work->next = NULL;

    pthread_mutex_lock(&scheduler->mutex);

    if (scheduler->capacity && scheduler->size >= scheduler->capacity) {
        pthread_mutex_unlock(&scheduler->mutex);
        free(new_work);
        return -1;
    }

    if (scheduler->tail) {
        scheduler->tail->next = new_work;
    } else {
        scheduler->head = new_work;
    }
    scheduler->tail = new_work;
    scheduler->size++;

    pthread_mutex_unlock(&scheduler->mutex);
    pthread_cond_signal(&scheduler->work_available);

    return 0;
}
