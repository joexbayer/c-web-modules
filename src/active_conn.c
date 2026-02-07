#include "active_conn.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int active_conn_init(active_conn_list_t *list, size_t initial_capacity) {
    if (!list || initial_capacity == 0) {
        return -1;
    }

    memset(list, 0, sizeof(*list));
    if (pthread_mutex_init(&list->lock, NULL) != 0) {
        return -1;
    }

    list->fds = malloc(initial_capacity * sizeof(int));
    if (!list->fds) {
        pthread_mutex_destroy(&list->lock);
        return -1;
    }
    list->capacity = initial_capacity;
    list->count = 0;
    return 0;
}

void active_conn_shutdown(active_conn_list_t *list) {
    if (!list) {
        return;
    }

    pthread_mutex_lock(&list->lock);
    free(list->fds);
    list->fds = NULL;
    list->count = 0;
    list->capacity = 0;
    pthread_mutex_unlock(&list->lock);
    pthread_mutex_destroy(&list->lock);
}

int active_conn_add(active_conn_list_t *list, int fd) {
    if (!list || fd < 0) {
        return -1;
    }

    pthread_mutex_lock(&list->lock);
    if (list->count >= list->capacity) {
        size_t new_capacity = list->capacity * 2;
        int *new_fds = realloc(list->fds, new_capacity * sizeof(int));
        if (!new_fds) {
            pthread_mutex_unlock(&list->lock);
            return -1;
        }
        list->fds = new_fds;
        list->capacity = new_capacity;
    }

    list->fds[list->count++] = fd;
    pthread_mutex_unlock(&list->lock);
    return 0;
}

void active_conn_remove(active_conn_list_t *list, int fd) {
    if (!list || fd < 0) {
        return;
    }

    pthread_mutex_lock(&list->lock);
    for (size_t i = 0; i < list->count; i++) {
        if (list->fds[i] == fd) {
            list->fds[i] = list->fds[list->count - 1];
            list->count--;
            break;
        }
    }
    pthread_mutex_unlock(&list->lock);
}

void active_conn_close_all(active_conn_list_t *list) {
    if (!list) {
        return;
    }

    pthread_mutex_lock(&list->lock);
    size_t count = list->count;
    int *fds = NULL;
    if (count > 0) {
        fds = malloc(count * sizeof(int));
        if (fds) {
            memcpy(fds, list->fds, count * sizeof(int));
            list->count = 0;
        }
    }
    if (!fds && count > 0) {
        for (size_t i = 0; i < count; i++) {
            if (shutdown(list->fds[i], SHUT_RDWR) != 0 && errno != ENOTCONN) {
                perror("[WARN] Failed to shutdown active connection");
            }
            if (close(list->fds[i]) != 0) {
                perror("[WARN] Failed to close active connection");
            }
        }
        list->count = 0;
        pthread_mutex_unlock(&list->lock);
        return;
    }
    pthread_mutex_unlock(&list->lock);

    if (!fds) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        if (shutdown(fds[i], SHUT_RDWR) != 0 && errno != ENOTCONN) {
            perror("[WARN] Failed to shutdown active connection");
        }
        if (close(fds[i]) != 0) {
            perror("[WARN] Failed to close active connection");
        }
    }
    free(fds);
}
