#include <stdio.h>
#include <cweb.h>

static int counter = 0;
static const char* template = 
    "<html>\n"
    "  <body>\n"
    "    <h1>Counter two: %d</h1>\n"
    "  </body>\n"
    "</html>\n";

/* Route: /counter - Method GET */
int index_route(struct http_request *req, struct http_response *res) {
    snprintf(res->body, HTTP_RESPONSE_SIZE, template, counter++);
    res->status = HTTP_200_OK;
    return 0;
}