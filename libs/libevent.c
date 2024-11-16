/**
 * @file libevent.c
 * @author Joe Bayer (joexbayer)
 * @brief A simple event library for Linux and MacOS
 * handling epoll and kqueue for network socket events.
 * @version 0.1
 * @date 2024-11-16
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pthread.h>

#ifdef __APPLE__
#include <sys/event.h>
#include <sys/queue.h>
#elif __linux__
#include <sys/epoll.h>
#include <fcntl.h>
#endif

#include "libevent.h"

#define DEBUG_PRINT(fmt, args...) fprintf(stderr, fmt, ## args)

static int notify_pipe[2] = {-1, -1};
static int stop_flag = 0;
static pthread_mutex_t stop_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t event_mutex = PTHREAD_MUTEX_INITIALIZER;
static void lock() {
    pthread_mutex_lock(&event_mutex);
}
static void unlock() {
    pthread_mutex_unlock(&event_mutex);
}

#ifdef __APPLE__
#define MAX_EVENTS 64
static int kq = -1;
#elif __linux__
#define MAX_EVENTS 64
static int epoll_fd = -1;
#endif

/* Simple linked list to manage events */
struct event_list {
    struct event *ev;
    struct event_list *next;
};

static struct event_list *events = NULL;

#ifdef __linux__
static pthread_once_t epoll_init_once = PTHREAD_ONCE_INIT;

void initialize_epoll(void) {
    epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll creation failed");
        exit(EXIT_FAILURE);
    }

    /* Create a self pipe used to wakeup epoll on demand */
    if (pipe(notify_pipe) == -1) {
        perror("pipe creation failed");
        exit(EXIT_FAILURE);
    }

    struct epoll_event ep;
    ep.events = EPOLLIN;
    ep.data.fd = notify_pipe[0];
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, notify_pipe[0], &ep) == -1) {
        perror("epoll_ctl failed for pipe");
        exit(EXIT_FAILURE);
    }

    DEBUG_PRINT("epoll_fd initialized: %d\n", epoll_fd);
}

#endif

/* Create a new event */
struct event *event_new(int fd, short events, event_callback_t callback, void *arg) {
    struct event *ev = malloc(sizeof(struct event));
    if (!ev) {
        perror("Failed to allocate memory for event");
        return NULL;
    }
    ev->fd = fd;
    ev->events = events;
    ev->callback = callback;
    ev->arg = arg;
    return ev;
}

/* Free an event */
void event_free(struct event *event) {
    if (event) {
        free(event);
    }
}

/* Add an event to the event loop */
int event_add(struct event *ev) {
    if (!ev) return -1;

    lock();

#ifdef __APPLE__
    if (kq == -1) {
        kq = kqueue();
        if (kq == -1) {
            perror("kqueue creation failed");
            unlock();
            return -1;
        }
    }

    struct kevent ke;
    EV_SET(&ke, ev->fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, ev);
    if (kevent(kq, &ke, 1, NULL, 0, NULL) == -1) {
        perror("kevent add failed");
        unlock();
        return -1;
    }
#elif __linux__
    pthread_once(&epoll_init_once, initialize_epoll);

    struct epoll_event ep;
    ep.events = EPOLLIN | EPOLLET; /* Edge-triggered */
    ep.data.ptr = ev;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ev->fd, &ep) == -1) {
        perror("epoll_ctl add failed");
        unlock();
        return -1;
    }
#endif

    /* Add to the internal list */
    struct event_list *new_node = malloc(sizeof(struct event_list));
    if (!new_node) {
        perror("Failed to allocate memory for event_list");
        unlock();
        return -1;
    }
    new_node->ev = ev;
    new_node->next = events;
    events = new_node;

    unlock(); /* Unlock after modification */
    return 0;
}

/* Remove an event from the event loop */
int event_del(struct event *ev) {
    if (!ev) return -1;

    lock();

#ifdef __APPLE__
    struct kevent ke;
    EV_SET(&ke, ev->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    if (kevent(kq, &ke, 1, NULL, 0, NULL) == -1) {
        perror("kevent delete failed");
        unlock();
        return -1;
    }
#elif __linux__
    if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, ev->fd, NULL) == -1) {
        perror("epoll_ctl delete failed");
        unlock();
        return -1;
    }
#endif

    /* Remove from the internal list */
    struct event_list **current = &events;
    while (*current) {
        if ((*current)->ev == ev) {
            struct event_list *to_free = *current;
            *current = (*current)->next;
            free(to_free);
            unlock();
            return 0;
        }
        current = &(*current)->next;
    }

    unlock(); 
    return -1;
}

/* Stop the event dispatch loop */
void event_dispatch_stop(void) {
    pthread_mutex_lock(&stop_mutex);
    stop_flag = 1;
    pthread_mutex_unlock(&stop_mutex);

#ifdef __linux__
    /* Kind of a hack to alert epoll and let it shutdown gracefully... probably find a better way. */
    if (notify_pipe[1] != -1) {
        if (write(notify_pipe[1], "1", 1) == -1) {
            perror("write to pipe failed");
        }
    }
    DEBUG_PRINT("Stopping event dispatch\n");
#elif __APPLE__
    struct kevent stop_event;
    EV_SET(&stop_event, -1, EVFILT_USER, EV_ADD | EV_ENABLE, NOTE_TRIGGER, 0, NULL);
    kevent(kq, &stop_event, 1, NULL, 0, NULL);
#endif
}

/* Main loop which dispatch events*/
void event_dispatch(void) {
    DEBUG_PRINT("Starting event dispatch\n");

#ifdef __linux__
    struct epoll_event triggered_events[MAX_EVENTS];
    pthread_once(&epoll_init_once, initialize_epoll);
#endif

    while (1) {
        pthread_mutex_lock(&stop_mutex);
        if (stop_flag) {
            pthread_mutex_unlock(&stop_mutex);
            break;
        }
        pthread_mutex_unlock(&stop_mutex);

#ifdef __linux__
        int n = epoll_wait(epoll_fd, triggered_events, MAX_EVENTS, -1);
        if (n == -1) {
            perror("epoll_wait dispatch failed");
            break;
        }

#endif
        for (int i = 0; i < n; i++) {
            if (triggered_events[i].data.fd == notify_pipe[0]) {
                printf("Received stop signal\n");
                char buf[1];
                read(notify_pipe[0], buf, 1);
                continue;
            }

            struct event *ev = (struct event *)triggered_events[i].data.ptr;
            if (ev && ev->callback) {
                ev->callback(ev, ev->arg);
            }
        }
    }
    printf("Event dispatch stopped\n");
}
