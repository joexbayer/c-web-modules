#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cweb.h>

#define MAX_ITEMS 10

static const char* list[MAX_ITEMS];
static int list_count = 0;

const char* head = 
    "<title>CWeb</title>\n"
    "<link rel=\"stylesheet\" href=\"https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css\">\n";

const char* todo_template = 
    "<div class=\"container mt-5\">\n"
    "  <h1>My TODO List</h1>\n"
    "  <ul class=\"list-group\">\n"
    "    %s\n"  // Placeholder for list items
    "  </ul>\n"
    "  <form method=\"POST\" action=\"/add\" class=\"mt-3\">\n"
    "    <div class=\"form-group\">\n"
    "      <input type=\"text\" name=\"item\" class=\"form-control\" placeholder=\"New TODO item\" required />\n"
    "    </div>\n"
    "    <button type=\"submit\" class=\"btn btn-primary\">Add Item</button>\n"
    "  </form>\n"
    "</div>\n";

const char* home_template = 
    "<html>\n"
    "  <head>\n" 
    "    %s\n"  // Placeholder for head
    "  </head>\n"
    "  <body>\n"
    "    %s\n"  // Placeholder for content
    "  </body>\n"
    "</html>\n";

/* Helper */
static void render_todo_list(char *buffer, size_t buffer_size) {
    char items_buffer[1024] = "";
    for (int i = 0; i < list_count; i++) {
        char item[256];
        snprintf(item, sizeof(item), "<li class=\"list-group-item\">%s</li>\n", list[i]);
        strncat(items_buffer, item, sizeof(items_buffer) - strlen(items_buffer) - 1);
    }
    snprintf(buffer, buffer_size, todo_template, items_buffer);
}

/* Route: / - Method GET */
int index_route(struct http_request *req, struct http_response *res) {
    char content[2048];
    char rendered_page[4096];

    render_todo_list(content, sizeof(content));
    snprintf(rendered_page, sizeof(rendered_page), home_template, head, content);
    snprintf(res->body, HTTP_RESPONSE_SIZE, "%s", rendered_page);
    
    map_insert(res->headers, "Content-Type", "text/html");
    map_insert(res->headers, "x-custom-header", "Hello, World!");

    res->status = HTTP_200_OK;
    return 0;
}

/* Route: /add - Method POST */
int add_todo_route(struct http_request *req, struct http_response *res) {
    if (list_count >= MAX_ITEMS) {
        snprintf(res->body, HTTP_RESPONSE_SIZE, "TODO list is full.");
        res->status = HTTP_400_BAD_REQUEST;
        return 0;
    }

    const char *new_item = map_get(req->data, "item");
    if (new_item && strlen(new_item) < 256) {
        list[list_count++] = strdup(new_item); // Add to the TODO list
    }

    res->status = HTTP_302_FOUND;
    map_insert(res->headers, "Location", "/");
    return 0;
}

export module_t config = {
    .name = "todo",
    .author = "cweb",
    .size = 2,
    .routes = {
        {"/", "GET", index_route, FEATURE_FLAG_NONE},
        {"/add", "POST", add_todo_route, FEATURE_FLAG_NONE},
    }
};