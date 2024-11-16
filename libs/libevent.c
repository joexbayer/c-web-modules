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
static pthread_once_t epoll_init_once = PTHREAD_ONCE_INIT; // Ensure epoll_fd is initialized only once

static void initialize_epoll(void) {
    epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll creation failed");
        exit(EXIT_FAILURE); // Fail fast if epoll initialization fails
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

    lock(); /* Lock before modifying shared resources */

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

    lock(); /* Lock before modifying shared resources */

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

            DEBUG_PRINT("Event removed\n");
            unlock();
            return 0;
        }
        current = &(*current)->next;
    }

    DEBUG_PRINT("Event not found\n");

    unlock(); /* Unlock after modification */
    return -1; /* Event not found */
}

/* Dispatch events */
void event_dispatch(void) {
    DEBUG_PRINT("Starting event dispatch\n");

#ifdef __APPLE__
    struct kevent triggered_events[MAX_EVENTS];
#elif __linux__
    struct epoll_event triggered_events[MAX_EVENTS];

    pthread_once(&epoll_init_once, initialize_epoll);
#endif

    while (1) {
#ifdef __APPLE__
        int n = kevent(kq, NULL, 0, triggered_events, MAX_EVENTS, NULL);
        if (n == -1) {
            perror("kevent dispatch failed");
            break;
        }
#elif __linux__
        int n = epoll_wait(epoll_fd, triggered_events, MAX_EVENTS, -1);
        if (n == -1) {
            perror("epoll_wait dispatch failed");
            break;
        }
#endif

        // Process each triggered event
        for (int i = 0; i < n; i++) {
#ifdef __APPLE__
            struct event *ev = (struct event *)triggered_events[i].udata;
#elif __linux__
            struct event *ev = (struct event *)triggered_events[i].data.ptr;
#endif
            DEBUG_PRINT("Event triggered on fd %d\n", ev->fd);

            if (ev && ev->callback) {
                ev->callback(ev, ev->arg);
            }
        }
    }
}