#include <cweb.h>

static jobs_create_fn_t g_jobs_create = NULL;
static void *g_jobs_create_data = NULL;

void cweb_module_unused(void) {
}

void jobs_bind(jobs_create_fn_t fn, void *user_data) {
    g_jobs_create = fn;
    g_jobs_create_data = user_data;
}

int jobs_create(const char *job_name, const char *payload_json, uuid_t *job_uuid_out) {
    if (!g_jobs_create) {
        return -1;
    }
    return g_jobs_create(g_jobs_create_data, job_name, payload_json, job_uuid_out);
}
