#ifndef LIST_H
#define LIST_H

#include <stddef.h>

/* Node structure */
struct list_node {
    void *data;
    struct list_node *next;
};

/* List structure */
struct list {
    struct list_node *head;
    size_t size;
};

#define LIST_FOREACH(list, node) \
    for (struct list_node *node = list->head; node != NULL; node = node->next)

#define LIST_FOREACH_SAFE(list, node, tmp) \
    for (struct list_node *node = list->head, *tmp = NULL; node != NULL && (tmp = node->next); node = tmp)

/* Initialize a new list */
struct list *list_create(void);
void list_destroy(struct list *list);
void list_add(struct list *list, void *data);
int list_remove(struct list *list, void *data);
void list_iterate(struct list *list, void (*func)(void *data));

#endif /* LIST_H */