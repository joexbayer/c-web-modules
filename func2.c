#include <stdio.h>
#include <http.h>
#include <map.h>

void func2(struct http_request *req, struct http_response *res) {
    res->status = HTTP_200_OK;
    sprintf(res->body, "<html><body><h1>Hello from func2!</h1></body></html>\n");

    char *name = map_get(req->query_params, "name");
    if (name) {
        sprintf(res->body, "<html><body><h1>Hello, %s!</h1></body></html>\n", name);
    }

    // int* ptr = NULL;
    // *ptr = 42;
}