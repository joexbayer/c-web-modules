#include <stdio.h>
#include <http.h>
#include <map.h>

void func2(struct http_request *req, struct http_response *res) {
    char *name = map_get(req->query_params, "name");
    if (name) {
        sprintf(res->body, "<html><body><h1>Hello, %s!</h1></body></html>\n", name);
    } else {
        sprintf(res->body, "<html><body><h1>Hello from func2!</h1></body></html>\n");
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