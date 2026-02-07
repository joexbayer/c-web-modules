#include <stdio.h>
#include <cweb.h>

static int counter = 0;
static const char* template = 
    "<html>\n"
    "  <body>\n"
    "    <h1>Counter: %d</h1>\n"
    "  </body>\n"
    "</html>\n";

/* Route: /counter - Method GET */
static int index_route(struct cweb_context *ctx, http_request_t *req, http_response_t *res) {
    snprintf(res->body, HTTP_RESPONSE_SIZE, template, counter++);
    res->status = HTTP_200_OK;
    return 0;
}

/* Define the routes for the module */
export module_t config = {
    .name = "counter",
    .author = "cweb",
    .routes = {
        {"/counter", "GET", index_route, NONE},
    },
    .size = 1,
};
