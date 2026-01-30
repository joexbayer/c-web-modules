#include "test.h"

#include <db.h>
#include <http.h>
#include <jobs.h>
#include <router.h>
#include <scheduler.h>
#include <ws.h>
#include <jansson.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

typedef struct jobs_fixture {
    struct sqldb db;
    struct scheduler scheduler;
    struct router router;
    struct ws_server ws;
    job_system_t jobs;
    cweb_context_t ctx;
    module_t module;
    struct module_ref ref;
} jobs_fixture_t;

static int test_job_run(struct cweb_context *ctx, const job_payload_t *payload, job_ctx_t *job) {
    (void)ctx;
    (void)payload;
    return job->set_result(job, "{\"ok\":true}");
}

static int jobs_fixture_init(jobs_fixture_t *fixture) {
    if (!fixture) {
        return -1;
    }

    memset(fixture, 0, sizeof(*fixture));
    if (sqldb_init(&fixture->db, ":memory:") != 0) {
        return -1;
    }

    if (scheduler_init(&fixture->scheduler, 8) != 0) {
        sqldb_shutdown(&fixture->db);
        return -1;
    }

    fixture->ctx.database = &fixture->db;
    fixture->ctx.scheduler = &fixture->scheduler;
    fixture->ctx.jobs = &fixture->jobs;

    if (jobs_init(&fixture->jobs, &fixture->ctx, &fixture->router, &fixture->ws) != 0) {
        scheduler_shutdown(&fixture->scheduler);
        sqldb_shutdown(&fixture->db);
        return -1;
    }

    memset(&fixture->module, 0, sizeof(fixture->module));
    snprintf(fixture->module.name, sizeof(fixture->module.name), "%s", "test_module");
    fixture->module.jobs[0] = (job_info_t){ .name = "test_job", .run = test_job_run, .cancel = NULL };
    fixture->module.job_size = 1;

    memset(&fixture->ref, 0, sizeof(fixture->ref));
    fixture->ref.module = &fixture->module;
    snprintf(fixture->ref.module_hash, sizeof(fixture->ref.module_hash), "%s", "hash");
    atomic_init(&fixture->ref.job_refs, 0);

    if (jobs_register_module(&fixture->jobs, &fixture->ref) != 0) {
        jobs_shutdown(&fixture->jobs);
        scheduler_shutdown(&fixture->scheduler);
        sqldb_shutdown(&fixture->db);
        return -1;
    }

    return 0;
}

static void jobs_fixture_shutdown(jobs_fixture_t *fixture) {
    if (!fixture) {
        return;
    }

    jobs_shutdown(&fixture->jobs);
    scheduler_shutdown(&fixture->scheduler);
    sqldb_shutdown(&fixture->db);
}

static void http_request_init(http_request_t *req) {
    memset(req, 0, sizeof(*req));
    req->headers = http_kv_create(8);
    req->params = http_kv_create(8);
    req->data = http_kv_create(8);
}

static void http_request_cleanup(http_request_t *req) {
    if (!req) {
        return;
    }

    free(req->path);
    free(req->body);
    http_kv_destroy(req->headers, 1);
    http_kv_destroy(req->params, 1);
    http_kv_destroy(req->data, 1);
}

static void http_response_init(http_response_t *res) {
    memset(res, 0, sizeof(*res));
    res->headers = http_kv_create(8);
    res->body = malloc(HTTP_RESPONSE_SIZE);
    if (res->body) {
        res->body[0] = '\0';
    }
}

static void http_response_cleanup(http_response_t *res) {
    if (!res) {
        return;
    }

    http_kv_destroy(res->headers, 1);
    free(res->body);
}

static int fetch_job_state(struct sqldb *db, const char *job_uuid, char *state_out, size_t state_len) {
    sqlite3_stmt *stmt = NULL;
    if (db->prepare(db, "SELECT state FROM jobs WHERE uuid = ?", -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }

    db->bind_text(stmt, 1, job_uuid, -1, SQLITE_TRANSIENT);
    if (db->step(stmt) != SQLITE_ROW) {
        db->finalize(stmt);
        return -1;
    }

    const char *state = db->column_text(stmt, 0);
    if (!state) {
        db->finalize(stmt);
        return -1;
    }

    snprintf(state_out, state_len, "%s", state);
    db->finalize(stmt);
    return 0;
}

static int wait_for_job_state(struct sqldb *db, const char *job_uuid, const char *expected, int timeout_ms) {
    int waited_ms = 0;
    char state[32];
    struct timespec ts = {0};

    while (waited_ms < timeout_ms) {
        if (fetch_job_state(db, job_uuid, state, sizeof(state)) == 0) {
            if (strcmp(state, expected) == 0) {
                return 0;
            }
        }
        ts.tv_sec = 0;
        ts.tv_nsec = 10 * 1000 * 1000;
        nanosleep(&ts, NULL);
        waited_ms += 10;
    }

    return -1;
}

static int create_job(jobs_fixture_t *fixture, const char *payload_json, char *uuid_out, size_t uuid_len) {
    http_request_t req;
    http_response_t res;
    http_request_init(&req);
    http_response_init(&res);

    req.method = HTTP_POST;
    req.path = strdup("/jobs");
    req.body = strdup(payload_json);
    if (!req.path || !req.body || !res.body) {
        http_response_cleanup(&res);
        http_request_cleanup(&req);
        return -1;
    }
    req.content_length = (int)strlen(req.body);

    jobs_handle_http(&fixture->jobs, &fixture->ctx, &req, &res);

    json_error_t error;
    json_t *root = json_loads(res.body, 0, &error);
    if (!root) {
        http_response_cleanup(&res);
        http_request_cleanup(&req);
        return -1;
    }

    const char *job_uuid = json_string_value(json_object_get(root, "job_uuid"));
    if (!job_uuid) {
        json_decref(root);
        http_response_cleanup(&res);
        http_request_cleanup(&req);
        return -1;
    }
    snprintf(uuid_out, uuid_len, "%s", job_uuid);
    json_decref(root);

    http_response_cleanup(&res);
    http_request_cleanup(&req);
    return 0;
}

TEST(test_jobs_create_and_status) {
    jobs_fixture_t fixture;
    ASSERT_INT_EQ(jobs_fixture_init(&fixture), 0);

    char job_uuid[64];
    ASSERT_INT_EQ(create_job(&fixture, "{\"job\":\"test_job\",\"payload\":{\"v\":1}}", job_uuid, sizeof(job_uuid)), 0);

    ASSERT_INT_EQ(wait_for_job_state(&fixture.db, job_uuid, "done", 1000), 0);

    http_request_t req;
    http_response_t res;
    http_request_init(&req);
    http_response_init(&res);

    req.method = HTTP_GET;
    size_t path_len = strlen("/jobs/") + strlen(job_uuid) + 1;
    req.path = malloc(path_len);
    ASSERT_NOT_NULL(req.path);
    snprintf(req.path, path_len, "/jobs/%s", job_uuid);

    jobs_handle_http(&fixture.jobs, &fixture.ctx, &req, &res);
    ASSERT_INT_EQ(res.status, HTTP_200_OK);

    json_error_t error;
    json_t *root = json_loads(res.body, 0, &error);
    ASSERT_NOT_NULL(root);

    const char *state = json_string_value(json_object_get(root, "state"));
    ASSERT_STR_EQ(state, "done");

    const char *module_hash = json_string_value(json_object_get(root, "module_hash"));
    ASSERT_STR_EQ(module_hash, "hash");

    json_t *result = json_object_get(root, "result");
    ASSERT_NOT_NULL(result);
    ASSERT_TRUE(json_is_object(result));
    json_t *ok = json_object_get(result, "ok");
    ASSERT_TRUE(json_is_true(ok));

    json_decref(root);
    http_response_cleanup(&res);
    http_request_cleanup(&req);
    jobs_fixture_shutdown(&fixture);
}

TEST(test_jobs_list_filter) {
    jobs_fixture_t fixture;
    ASSERT_INT_EQ(jobs_fixture_init(&fixture), 0);

    char job_uuid[64];
    ASSERT_INT_EQ(create_job(&fixture, "{\"job\":\"test_job\",\"payload\":{}}", job_uuid, sizeof(job_uuid)), 0);
    ASSERT_INT_EQ(wait_for_job_state(&fixture.db, job_uuid, "done", 1000), 0);

    http_request_t req;
    http_response_t res;
    http_request_init(&req);
    http_response_init(&res);

    req.method = HTTP_GET;
    req.path = strdup("/jobs");
    http_kv_insert(req.params, "state", strdup("done"));

    jobs_handle_http(&fixture.jobs, &fixture.ctx, &req, &res);
    ASSERT_INT_EQ(res.status, HTTP_200_OK);

    json_error_t error;
    json_t *root = json_loads(res.body, 0, &error);
    ASSERT_NOT_NULL(root);

    json_t *jobs_array = json_object_get(root, "jobs");
    ASSERT_TRUE(json_is_array(jobs_array));

    int found = 0;
    size_t index;
    json_t *item;
    json_array_foreach(jobs_array, index, item) {
        const char *uuid = json_string_value(json_object_get(item, "job_uuid"));
        if (uuid && strcmp(uuid, job_uuid) == 0) {
            found = 1;
            break;
        }
    }

    ASSERT_TRUE(found);

    json_decref(root);
    http_response_cleanup(&res);
    http_request_cleanup(&req);
    jobs_fixture_shutdown(&fixture);
}

TEST(test_jobs_cancel_unknown) {
    jobs_fixture_t fixture;
    ASSERT_INT_EQ(jobs_fixture_init(&fixture), 0);

    http_request_t req;
    http_response_t res;
    http_request_init(&req);
    http_response_init(&res);

    req.method = HTTP_POST;
    const char *job_uuid = "00000000-0000-0000-0000-000000000000";
    size_t path_len = strlen("/jobs/") + strlen(job_uuid) + strlen("/cancel") + 1;
    req.path = malloc(path_len);
    ASSERT_NOT_NULL(req.path);
    snprintf(req.path, path_len, "/jobs/%s/cancel", job_uuid);

    jobs_handle_http(&fixture.jobs, &fixture.ctx, &req, &res);
    ASSERT_INT_EQ(res.status, HTTP_404_NOT_FOUND);

    http_response_cleanup(&res);
    http_request_cleanup(&req);
    jobs_fixture_shutdown(&fixture);
}

void register_jobs_tests(void) {
    test_register("jobs_create_and_status", test_jobs_create_and_status);
    test_register("jobs_list_filter", test_jobs_list_filter);
    test_register("jobs_cancel_unknown", test_jobs_cancel_unknown);
}
