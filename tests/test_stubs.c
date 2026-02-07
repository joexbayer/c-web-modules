#include <router.h>
#include <engine.h>

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

int safe_execute_job_run(job_run_t handler, struct cweb_context *ctx, const job_payload_t *payload, job_ctx_t *job, int *rc_out) {
    if (!handler) {
        return -1;
    }
    int rc = handler(ctx, payload, job);
    if (rc_out) {
        *rc_out = rc;
    }
    return 0;
}

void safe_execute_job_cancel(void (*cancel)(struct cweb_context *ctx, const char *job_uuid), struct cweb_context *ctx, const char *job_uuid) {
    if (cancel) {
        cancel(ctx, job_uuid);
    }
}
