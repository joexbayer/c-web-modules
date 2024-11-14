#include <scheduler.h>

static add_work(void (*work)(void *), void *data, worker_state_t state);

struct scheduler internal_scheduler = {
    .queue = NULL,
    .size = 0,
    .capacity = 10,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .add = add_work,
};
struct scheduler *exposed_scheduler = &internal_scheduler;

static add_work(void (*work)(void *), void *data, worker_state_t state) {
    struct work *new_work = (struct work *)malloc(sizeof(struct work));
    if (new_work == NULL) {
        perror("Error allocating memory for work");
        return;
    }

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
}

static void run_work(void) {
    pthread_mutex_lock(&internal_scheduler.mutex);
    if (internal_scheduler.size == 0) {
        pthread_mutex_unlock(&internal_scheduler.mutex);
        return;
    }

    struct work *current = internal_scheduler.queue;
    internal_scheduler.queue = current->next;
    internal_scheduler.size--;

    pthread_mutex_unlock(&internal_scheduler.mutex);

    current->work(current->data);
    free(current);
}

pthread_t scheduler_thread;
__constructor__ void scheduler_init() {
    if (pthread_create(&scheduler_thread, NULL, run_work, NULL) != 0) {
        perror("Error creating scheduler thread");
        exit(EXIT_FAILURE);
    }
    pthread_detach(thread);
}