/**
 * @file json.c
 * @author Joe Bayer (joexbayer)
 * @brief Example program that uses jansson to serialize a list into JSON
 * @usage: curl http://localhost:8080/list
 * @usage: curl -X POST http://localhost:8080/json/add -d "item=Test Item"
 * @version 0.1
 * @date 2024-11-17
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cweb.h>

#define MAX_ITEMS 10

static const char* list[MAX_ITEMS];
static int list_count = 0;

/* Helper: Serialize the list into JSON */
static void serialize_list(char *buffer, size_t buffer_size) {
    json_t *json_arr = json_array();
    for (int i = 0; i < list_count; i++) {
        json_array_append_new(json_arr, json_string(list[i]));
    }

    char *json_string_data = json_dumps(json_arr, JSON_COMPACT);
    snprintf(buffer, buffer_size, "%s", json_string_data);
    free(json_string_data);
    json_decref(json_arr);
}

/* Route: /list - Method GET */
int get_list_route(struct http_request *req, struct http_response *res) {
    char json_response[1024];
    serialize_list(json_response, sizeof(json_response));

    /* HTTP response */
    snprintf(res->body, HTTP_RESPONSE_SIZE, "%s", json_response);
    map_insert(res->headers, "Content-Type", "application/json");
    res->status = HTTP_200_OK;
    return 0;
}

/* Route: /json/add - Method POST */
int add_item_route(struct http_request *req, struct http_response *res) {
    if (list_count >= MAX_ITEMS) {
        json_t *error = json_pack("{s:s}", "error", "List is full");
        
        char *error_json = json_dumps(error, JSON_COMPACT);
        snprintf(res->body, HTTP_RESPONSE_SIZE, "%s", error_json);
        map_insert(res->headers, "Content-Type", "application/json");
        
        free(error_json);
        json_decref(error);
        res->status = HTTP_400_BAD_REQUEST;
        return 0;
    }

    const char *new_item = map_get(req->data, "item");
    if (new_item && strlen(new_item) < 256) {
        list[list_count++] = strdup(new_item); /* uses malloc */
    }

    json_t *message = json_pack("{s:s}", "message", "Item added");
    char *message_json = json_dumps(message, JSON_COMPACT);
    snprintf(res->body, HTTP_RESPONSE_SIZE, "%s", message_json);
    map_insert(res->headers, "Content-Type", "application/json");
    
    free(message_json);
    json_decref(message);
    res->status = HTTP_200_OK;
    return 0;
}

void unload() {
    printf("Unloading json_example_jansson %d\n", list_count);
    for (int i = 0; i < list_count; i++) {
        free((void*)list[i]);
    }
}

/* Export module */
export module_t config = {
    .name = "json_example_jansson",
    .author = "cweb",
    .size = 2,
    .routes = {
        {"/list", "GET", get_list_route, NONE},
        {"/json/add", "POST", add_item_route, NONE},
    },
    .unload = unload,
};
