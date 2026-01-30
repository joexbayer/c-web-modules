#ifndef ACTIVE_CONN_H
#define ACTIVE_CONN_H

#include <pthread.h>
#include <stddef.h>

typedef struct active_conn_list {
    pthread_mutex_t lock;
    int *fds;
    size_t count;
    size_t capacity;
} active_conn_list_t;

int active_conn_init(active_conn_list_t *list, size_t initial_capacity);
void active_conn_shutdown(active_conn_list_t *list);
int active_conn_add(active_conn_list_t *list, int fd);
void active_conn_remove(active_conn_list_t *list, int fd);
void active_conn_close_all(active_conn_list_t *list);

#endif /* ACTIVE_CONN_H */
