#include <list.h>
#include <stdlib.h>
#include <stdio.h>

/* Create a new list */
struct list *list_create(void) {
    struct list *list = malloc(sizeof(struct list));
    if (!list) {
        perror("Failed to allocate memory for list");
        return NULL;
    }
    list->head = NULL;
    list->size = 0;
    return list;
}

/* Destroy the list and free all nodes (data is not freed) */
void list_destroy(struct list *list) {
    if (!list) return;

    struct list_node *current = list->head;
    while (current) {
        struct list_node *next = current->next;
        free(current); 
        current = next;
    }

    free(list);
}

/* Add an element to the front of the list */
void list_add(struct list *list, void *data) {
    if (!list) return;

    struct list_node *new_node = malloc(sizeof(struct list_node));
    if (!new_node) {
        perror("Failed to allocate memory for list node");
        return;
    }

    new_node->data = data;
    new_node->next = list->head;
    list->head = new_node;
    list->size++;
}

/* Remove the first occurrence of an element (uses pointer comparison) */
int list_remove(struct list *list, void *data) {
    if (!list || !list->head) return 0;

    struct list_node **current = &list->head;
    while (*current) {
        if ((*current)->data == data) {
            struct list_node *to_remove = *current;
            *current = to_remove->next;
            free(to_remove);
            list->size--;
            return 1; 
        }
        current = &(*current)->next;
    }

    return 0;
}

/* Iterate over the list and apply a function to each element */
void list_iterate(struct list *list, void (*func)(void *data)) {
    if (!list || !func) return;

    struct list_node *current = list->head;
    while (current) {
        func(current->data);
        current = current->next;
    }
}