#include <router.h>

struct job_route router_job_find(struct router *router, const char *module_name, const char *job_name) {
    (void)router;
    (void)module_name;
    (void)job_name;
    return (struct job_route){0};
}

void router_job_release(struct router *router, struct module_ref *ref, struct cweb_context *ctx) {
    (void)router;
    (void)ref;
    (void)ctx;
}
