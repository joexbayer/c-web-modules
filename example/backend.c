#include <stdio.h>
#include <http.h>
#include <map.h>

const char* template = 
    "<html>\n"
    "  <body>\n"
    "    <h1>%s</h1>\n"
    "  </body>\n"
    "</html>\n";

void func2(struct http_request *req, struct http_response *res) {
    char *name = map_get(req->params, "name");
    if (name) {
        sprintf(res->body, template, name);
    } else {
        sprintf(res->body, template, "World");
    }

    FILE *file = fopen("name.txt", "w");
    if (file) {
        fprintf(file, "Name: %s\n", name);
        fclose(file);
    } else {
        perror("Failed to open file");
    }

    // int* ptr = NULL;
    // *ptr = 42;
    res->status = HTTP_200_OK;
}

void func3(struct http_request *req, struct http_response *res) {
    char *name = map_get(req->params, "name");
    if (name) {
        sprintf(res->body, template, "Hello, World!");
    } else {
        sprintf(res->body, template, "World");
    }

    FILE *file = fopen("name.txt", "w");
    if (file) {
        fprintf(file, "Name: %s\n", name);
        fclose(file);
    } else {
        perror("Failed to open file");
    }

    // int* ptr = NULL;
    // *ptr = 42;
    res->status = HTTP_200_OK;
}