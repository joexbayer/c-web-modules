#include <stdio.h>
#include <stdint.h>
#include <jansson.h>
#include <cweb.h>

static int job_sum(struct cweb_context *ctx, const job_payload_t *payload, job_ctx_t *job) {
    (void)ctx;

    if (!payload || !job || !job->set_error || !job->set_result) {
        return -1;
    }

    json_error_t error;
    const char *json_str = payload->json ? payload->json : "{}";
    json_t *root = json_loads(json_str, 0, &error);
    if (!root || !json_is_object(root)) {
        if (root) {
            json_decref(root);
        }
        job->set_error(job, "invalid payload");
        return -1;
    }

    json_t *n_val = json_object_get(root, "n");
    if (!json_is_integer(n_val)) {
        json_decref(root);
        job->set_error(job, "missing n");
        return -1;
    }

    uint64_t n = (uint64_t)json_integer_value(n_val);
    uint64_t sum = 0;
    for (uint64_t i = 1; i <= n; i++) {
        sum += i;
    }

    json_decref(root);

    char result[128];
    snprintf(result, sizeof(result), "{\"n\":%llu,\"sum\":%llu}",
        (unsigned long long)n,
        (unsigned long long)sum);

    return job->set_result(job, result);
}

export module_t config = {
    .name = "job_sum",
    .author = "cweb",
    .size = 0,
    .ws_size = 0,
    .job_size = 1,
    .jobs = {
        {"sum", job_sum},
    }
};
