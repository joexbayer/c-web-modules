#ifndef LIBEVENT_H
#define LIBEVENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>

struct event;
typedef void (*event_callback_t)(struct event *event, void *arg);

struct event {
    int fd;
    short events;
    event_callback_t callback;
    void *arg;
};

struct event  *event_new(int fd, short events, event_callback_t callback, void *arg);
void event_free(struct event  *event);
int event_add(struct event  *event);
int event_del(struct event  *event);
void event_dispatch(void);
void event_dispatch_stop(void);

#ifdef __cplusplus
}
#endif

#endif // LIBEVENT_H