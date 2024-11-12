#include <stdio.h>
#include <http.h>
#include <map.h>

const char* template = 
    "<html>\n"
    "  <body>\n"
    "    <h1>Counter: %d</h1>\n"
    "  </body>\n"
    "</html>\n";

int counter = 0;

/* Route: / - Method GET */
int index_route(struct http_request *req, struct http_response *res) {

    snprintf(res->body, HTTP_RESPONSE_SIZE, template, counter++);

    res->status = HTTP_200_OK;
    return 0;
}