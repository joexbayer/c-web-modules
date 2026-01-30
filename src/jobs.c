#include <jobs.h>
#include <engine.h>

#include <jansson.h>
#include <openssl/rand.h>
#include <sqlite3.h>
#include <list.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define JOB_UUID_STR_LEN 37
#define JOBS_LIST_LIMIT 100

typedef enum job_state {
    JOB_STATE_PENDING = 0,
    JOB_STATE_RUNNING,
    JOB_STATE_DONE,
    JOB_STATE_FAILED,
    JOB_STATE_CANCELED
} job_state_t;

typedef struct job_subscriber {
    websocket_t *ws;
    int since_event_id;
} job_subscriber_t;

typedef struct job_runtime {
    job_ctx_t api;
    job_system_t *jobs;
    int job_id;
    char job_uuid[JOB_UUID_STR_LEN];
    int completed;
} job_runtime_t;

typedef struct job_work {
    job_system_t *jobs;
    struct cweb_context *ctx;
    struct module_ref *ref;
    job_info_t *job;
    int job_id;
    char job_uuid[JOB_UUID_STR_LEN];
    char *payload_json;
} job_work_t;

typedef struct job_registry_entry {
    struct module_ref *ref;
    job_info_t *job;
} job_registry_entry_t;

static const char *job_state_to_string(job_state_t state) {
    switch (state) {
        case JOB_STATE_PENDING:
            return "pending";
        case JOB_STATE_RUNNING:
            return "running";
        case JOB_STATE_DONE:
            return "done";
        case JOB_STATE_FAILED:
            return "failed";
        case JOB_STATE_CANCELED:
            return "canceled";
        default:
            return "unknown";
    }
}

static int jobs_generate_uuid(char uuid[JOB_UUID_STR_LEN]) {
    unsigned char bytes[16];
    if (RAND_bytes(bytes, (int)sizeof(bytes)) != 1) {
        return -1;
    }

    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;

    snprintf(uuid, JOB_UUID_STR_LEN,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15]);
    return 0;
}

static int jobs_db_exec(struct sqldb *db, const char *sql) {
    if (!db || !sql) {
        return -1;
    }
    int rc = db->exec(db, sql, NULL, NULL);
    return rc == SQLITE_OK ? 0 : -1;
}

static int jobs_db_prepare(struct sqldb *db, const char *sql, sqlite3_stmt **stmt) {
    if (!db || !sql || !stmt) {
        return -1;
    }
    int rc = db->prepare(db, sql, -1, stmt, NULL);
    return rc == SQLITE_OK ? 0 : -1;
}

static int jobs_db_step_done(struct sqldb *db, sqlite3_stmt *stmt) {
    if (!db || !stmt) {
        return -1;
    }
    int rc = db->step(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int jobs_db_step_row(struct sqldb *db, sqlite3_stmt *stmt) {
    if (!db || !stmt) {
        return -1;
    }
    int rc = db->step(stmt);
    return rc == SQLITE_ROW ? 0 : -1;
}

static int jobs_parse_ws_session(const char *session, char *uuid_out, size_t uuid_len, int *since_event_id) {
    if (!session || !uuid_out || uuid_len < JOB_UUID_STR_LEN || !since_event_id) {
        return -1;
    }

    const char *sep = strchr(session, '|');
    size_t uuid_size = sep ? (size_t)(sep - session) : strlen(session);
    if (uuid_size >= uuid_len) {
        return -1;
    }

    memcpy(uuid_out, session, uuid_size);
    uuid_out[uuid_size] = '\0';

    if (sep && *(sep + 1) != '\0') {
        *since_event_id = atoi(sep + 1);
    } else {
        *since_event_id = 0;
    }

    return 0;
}

static void jobs_subscribers_free_list(struct list *list) {
    if (!list) {
        return;
    }

    LIST_FOREACH_SAFE(list, node, tmp) {
        job_subscriber_t *subscriber = node->data;
        list_remove(list, subscriber);
        free(subscriber);
    }
    list_destroy(list);
}

static void jobs_subscribers_remove(job_system_t *jobs, const char *job_uuid, websocket_t *ws) {
    if (!jobs || !job_uuid || !ws) {
        return;
    }

    pthread_mutex_lock(&jobs->subscribers_mutex);
    struct list *list = map_get(jobs->subscribers, job_uuid);
    if (!list) {
        pthread_mutex_unlock(&jobs->subscribers_mutex);
        return;
    }

    LIST_FOREACH_SAFE(list, node, tmp) {
        job_subscriber_t *subscriber = node->data;
        if (subscriber && subscriber->ws == ws) {
            list_remove(list, subscriber);
            free(subscriber);
            break;
        }
    }

    if (list->size == 0) {
        jobs_subscribers_free_list(list);
        map_remove(jobs->subscribers, job_uuid);
    }

    pthread_mutex_unlock(&jobs->subscribers_mutex);
}

static int jobs_subscribers_add(job_system_t *jobs, const char *job_uuid, websocket_t *ws, int since_event_id) {
    if (!jobs || !job_uuid || !ws) {
        return -1;
    }

    job_subscriber_t *subscriber = malloc(sizeof(*subscriber));
    if (!subscriber) {
        return -1;
    }

    subscriber->ws = ws;
    subscriber->since_event_id = since_event_id;

    pthread_mutex_lock(&jobs->subscribers_mutex);
    struct list *list = map_get(jobs->subscribers, job_uuid);
    if (!list) {
        list = list_create();
        if (!list) {
            pthread_mutex_unlock(&jobs->subscribers_mutex);
            free(subscriber);
            return -1;
        }
        if (map_insert(jobs->subscribers, job_uuid, list) != MAP_OK) {
            pthread_mutex_unlock(&jobs->subscribers_mutex);
            list_destroy(list);
            free(subscriber);
            return -1;
        }
    }

    list_add(list, subscriber);
    pthread_mutex_unlock(&jobs->subscribers_mutex);
    return 0;
}

static void jobs_registry_free(job_registry_entry_t *entry) {
    if (!entry) {
        return;
    }
    free(entry);
}

static int jobs_registry_insert(job_system_t *jobs, const char *job_name, struct module_ref *ref, job_info_t *job) {
    if (!jobs || !job_name || !ref || !job) {
        return -1;
    }

    job_registry_entry_t *entry = malloc(sizeof(*entry));
    if (!entry) {
        return -1;
    }

    entry->ref = ref;
    entry->job = job;

    job_registry_entry_t *existing = map_get(jobs->job_registry, job_name);
    if (existing) {
        jobs_registry_free(existing);
    }

    if (map_insert(jobs->job_registry, job_name, entry) != MAP_OK) {
        jobs_registry_free(entry);
        return -1;
    }

    return 0;
}

int jobs_register_module(job_system_t *jobs, struct module_ref *ref) {
    if (!jobs || !jobs->job_registry || !ref || !ref->module) {
        return -1;
    }

    pthread_mutex_lock(&jobs->job_registry_mutex);
    int rc = 0;
    for (int i = 0; i < ref->module->job_size; i++) {
        job_info_t *job = &ref->module->jobs[i];
        if (!job || !job->name) {
            continue;
        }
        if (jobs_registry_insert(jobs, job->name, ref, job) != 0) {
            rc = -1;
        }
    }
    pthread_mutex_unlock(&jobs->job_registry_mutex);
    return rc;
}

void jobs_unregister_module(job_system_t *jobs, struct module_ref *ref) {
    if (!jobs || !jobs->job_registry || !ref) {
        return;
    }

    pthread_mutex_lock(&jobs->job_registry_mutex);
    for (size_t i = 0; i < jobs->job_registry->capacity; i++) {
        struct map_entry *entry = &jobs->job_registry->entries[i];
        if (entry->state != MAP_ENTRY_OCCUPIED) {
            continue;
        }
        job_registry_entry_t *value = entry->value;
        if (value && value->ref == ref) {
            jobs_registry_free(value);
            map_remove(jobs->job_registry, entry->key);
        }
    }
    pthread_mutex_unlock(&jobs->job_registry_mutex);
}

static struct job_route jobs_registry_find(job_system_t *jobs, const char *job_name) {
    if (!jobs || !jobs->job_registry || !job_name) {
        return (struct job_route){0};
    }

    pthread_mutex_lock(&jobs->job_registry_mutex);
    job_registry_entry_t *entry = map_get(jobs->job_registry, job_name);
    if (!entry || !entry->ref || !entry->job) {
        pthread_mutex_unlock(&jobs->job_registry_mutex);
        return (struct job_route){0};
    }

    atomic_fetch_add(&entry->ref->job_refs, 1);
    struct job_route route = {
        .job = entry->job,
        .ref = entry->ref
    };
    snprintf(route.module_hash, sizeof(route.module_hash), "%s", entry->ref->module_hash);
    pthread_mutex_unlock(&jobs->job_registry_mutex);
    return route;
}

static void jobs_send_event_to_ws(websocket_t *ws, const char *job_uuid, int event_id, int ts, const char *type, const char *data_json) {
    if (!ws || !job_uuid || !type) {
        return;
    }

    json_t *root = json_object();
    json_object_set_new(root, "job_uuid", json_string(job_uuid));
    json_object_set_new(root, "event_id", json_integer(event_id));
    json_object_set_new(root, "ts", json_integer(ts));
    json_object_set_new(root, "type", json_string(type));

    if (data_json) {
        json_error_t error;
        json_t *data = json_loads(data_json, 0, &error);
        if (!data) {
            json_object_set_new(root, "data", json_string(data_json));
        } else {
            json_object_set_new(root, "data", data);
        }
    } else {
        json_object_set_new(root, "data", json_null());
    }

    char *payload = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    if (!payload) {
        return;
    }

    if (ws->send(ws, payload, strlen(payload)) < 0) {
        fprintf(stderr, "[ERROR] Failed to send job event to websocket\n");
    }

    free(payload);
}

static void jobs_notify_subscribers(job_system_t *jobs, const char *job_uuid, int event_id, int ts, const char *type, const char *data_json) {
    if (!jobs || !job_uuid || !type) {
        return;
    }

    pthread_mutex_lock(&jobs->subscribers_mutex);
    struct list *list = map_get(jobs->subscribers, job_uuid);
    if (!list) {
        pthread_mutex_unlock(&jobs->subscribers_mutex);
        return;
    }

    LIST_FOREACH(list, node) {
        job_subscriber_t *subscriber = node->data;
        if (!subscriber) {
            continue;
        }
        jobs_send_event_to_ws(subscriber->ws, job_uuid, event_id, ts, type, data_json);
    }

    pthread_mutex_unlock(&jobs->subscribers_mutex);
}

static int jobs_insert_event(job_system_t *jobs, int job_id, int ts, const char *type, const char *data_json, int *event_id_out) {
    if (!jobs || !jobs->db || !type) {
        return -1;
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT INTO job_events (job_id, ts, type, data_json) VALUES (?, ?, ?, ?)";
    if (jobs_db_prepare(jobs->db, sql, &stmt) != 0) {
        return -1;
    }

    jobs->db->bind_int(stmt, 1, job_id);
    jobs->db->bind_int(stmt, 2, ts);
    jobs->db->bind_text(stmt, 3, type, -1, SQLITE_TRANSIENT);
    if (data_json) {
        jobs->db->bind_text(stmt, 4, data_json, -1, SQLITE_TRANSIENT);
    } else {
        jobs->db->bind_text(stmt, 4, "", -1, SQLITE_TRANSIENT);
    }

    if (jobs_db_step_done(jobs->db, stmt) != 0) {
        jobs->db->finalize(stmt);
        return -1;
    }

    jobs->db->finalize(stmt);
    if (event_id_out) {
        *event_id_out = jobs->db->last_insert_rowid(jobs->db);
    }
    return 0;
}

static int jobs_update_state(job_system_t *jobs, int job_id, job_state_t state, const char *result_json, const char *error_text) {
    if (!jobs || !jobs->db) {
        return -1;
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql = "UPDATE jobs SET state = ?, result_json = ?, error_text = ?, updated_at = ? WHERE id = ?";
    if (jobs_db_prepare(jobs->db, sql, &stmt) != 0) {
        return -1;
    }

    jobs->db->bind_text(stmt, 1, job_state_to_string(state), -1, SQLITE_TRANSIENT);
    if (result_json) {
        jobs->db->bind_text(stmt, 2, result_json, -1, SQLITE_TRANSIENT);
    } else {
        jobs->db->bind_text(stmt, 2, "", -1, SQLITE_TRANSIENT);
    }
    if (error_text) {
        jobs->db->bind_text(stmt, 3, error_text, -1, SQLITE_TRANSIENT);
    } else {
        jobs->db->bind_text(stmt, 3, "", -1, SQLITE_TRANSIENT);
    }

    jobs->db->bind_int(stmt, 4, (int)time(NULL));
    jobs->db->bind_int(stmt, 5, job_id);

    if (jobs_db_step_done(jobs->db, stmt) != 0) {
        jobs->db->finalize(stmt);
        return -1;
    }

    jobs->db->finalize(stmt);
    return 0;
}

static job_runtime_t *jobs_runtime_from_ctx(job_ctx_t *job) {
    return (job_runtime_t *)job;
}

static int jobs_ctx_emit_event(job_ctx_t *job, const char *type, const char *data_json) {
    if (!job || !type) {
        return -1;
    }

    job_runtime_t *runtime = jobs_runtime_from_ctx(job);
    int event_id = 0;
    int ts = (int)time(NULL);

    if (jobs_insert_event(runtime->jobs, runtime->job_id, ts, type, data_json, &event_id) != 0) {
        return -1;
    }

    jobs_notify_subscribers(runtime->jobs, runtime->job_uuid, event_id, ts, type, data_json);
    return 0;
}

static int jobs_ctx_set_result(job_ctx_t *job, const char *result_json) {
    if (!job) {
        return -1;
    }

    job_runtime_t *runtime = jobs_runtime_from_ctx(job);
    if (runtime->completed) {
        return -1;
    }
    runtime->completed = 1;

    if (jobs_update_state(runtime->jobs, runtime->job_id, JOB_STATE_DONE, result_json, NULL) != 0) {
        return -1;
    }

    return jobs_ctx_emit_event(job, "done", result_json);
}

static int jobs_ctx_set_error(job_ctx_t *job, const char *error_text) {
    if (!job) {
        return -1;
    }

    job_runtime_t *runtime = jobs_runtime_from_ctx(job);
    if (runtime->completed) {
        return -1;
    }
    runtime->completed = 1;

    if (jobs_update_state(runtime->jobs, runtime->job_id, JOB_STATE_FAILED, NULL, error_text) != 0) {
        return -1;
    }

    return jobs_ctx_emit_event(job, "failed", error_text);
}

static void jobs_execute(void *data) {
    job_work_t *work = data;
    if (!work || !work->job || !work->jobs) {
        free(work);
        return;
    }

    job_payload_t payload = {
        .json = work->payload_json ? work->payload_json : "{}",
        .json_len = work->payload_json ? strlen(work->payload_json) : 2
    };

    job_runtime_t runtime = {
        .api = {
            .job_uuid = work->job_uuid,
            .emit_event = jobs_ctx_emit_event,
            .set_result = jobs_ctx_set_result,
            .set_error = jobs_ctx_set_error
        },
        .jobs = work->jobs,
        .job_id = work->job_id,
        .completed = 0
    };
    snprintf(runtime.job_uuid, sizeof(runtime.job_uuid), "%s", work->job_uuid);

    jobs_update_state(work->jobs, work->job_id, JOB_STATE_RUNNING, NULL, NULL);
    jobs_ctx_emit_event(&runtime.api, "started", NULL);

    if (!work->job->run) {
        jobs_ctx_set_error(&runtime.api, "job handler missing");
        router_job_release(work->jobs->router, work->ref, work->ctx);
        free(work->payload_json);
        free(work);
        return;
    }

    int rc = 0;
    int exec_rc = safe_execute_job_run(work->job->run, work->ctx, &payload, &runtime.api, &rc);
    if (exec_rc != 0 && !runtime.completed) {
        jobs_ctx_set_error(&runtime.api, "job crashed");
    } else if (rc != 0 && !runtime.completed) {
        jobs_ctx_set_error(&runtime.api, "job failed");
    } else if (!runtime.completed) {
        jobs_ctx_set_result(&runtime.api, "{}");
    }

    router_job_release(work->jobs->router, work->ref, work->ctx);
    free(work->payload_json);
    free(work);
}

static int jobs_insert_job(job_system_t *jobs, const char *job_uuid, const char *module_name, const char *job_name, const char *module_hash, const char *payload_json, int *job_id_out) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT INTO jobs (uuid, module_name, job_name, state, module_hash, created_at, updated_at, payload_json, result_json, error_text) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    if (jobs_db_prepare(jobs->db, sql, &stmt) != 0) {
        return -1;
    }

    int now = (int)time(NULL);
    jobs->db->bind_text(stmt, 1, job_uuid, -1, SQLITE_TRANSIENT);
    jobs->db->bind_text(stmt, 2, module_name, -1, SQLITE_TRANSIENT);
    jobs->db->bind_text(stmt, 3, job_name, -1, SQLITE_TRANSIENT);
    jobs->db->bind_text(stmt, 4, job_state_to_string(JOB_STATE_PENDING), -1, SQLITE_TRANSIENT);
    jobs->db->bind_text(stmt, 5, module_hash, -1, SQLITE_TRANSIENT);
    jobs->db->bind_int(stmt, 6, now);
    jobs->db->bind_int(stmt, 7, now);
    jobs->db->bind_text(stmt, 8, payload_json ? payload_json : "{}", -1, SQLITE_TRANSIENT);
    jobs->db->bind_text(stmt, 9, "", -1, SQLITE_TRANSIENT);
    jobs->db->bind_text(stmt, 10, "", -1, SQLITE_TRANSIENT);

    if (jobs_db_step_done(jobs->db, stmt) != 0) {
        jobs->db->finalize(stmt);
        return -1;
    }

    jobs->db->finalize(stmt);
    if (job_id_out) {
        *job_id_out = jobs->db->last_insert_rowid(jobs->db);
    }
    return 0;
}

static int jobs_fetch_job_id(job_system_t *jobs, const char *job_uuid, int *job_id_out) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT id FROM jobs WHERE uuid = ?";
    if (jobs_db_prepare(jobs->db, sql, &stmt) != 0) {
        return -1;
    }

    jobs->db->bind_text(stmt, 1, job_uuid, -1, SQLITE_TRANSIENT);
    int rc = jobs_db_step_row(jobs->db, stmt);
    if (rc != 0) {
        jobs->db->finalize(stmt);
        return -1;
    }

    if (job_id_out) {
        *job_id_out = jobs->db->column_int(stmt, 0);
    }
    jobs->db->finalize(stmt);
    return 0;
}

static int jobs_respond_error(http_response_t *res, int status, const char *message) {
    if (!res || !res->body || !res->headers) {
        return -1;
    }
    json_t *root = json_object();
    json_object_set_new(root, "error", json_string(message ? message : "unknown"));
    char *payload = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    if (!payload) {
        return -1;
    }
    snprintf(res->body, HTTP_RESPONSE_SIZE, "%s", payload);
    free(payload);
    http_kv_insert(res->headers, "Content-Type", strdup("application/json"));
    res->status = status;
    return 0;
}

static void jobs_ws_on_open(struct cweb_context *ctx, websocket_t *ws) {
    if (!ctx || !ctx->jobs || !ws || !ws->session) {
        if (ws) {
            ws->send(ws, "{\"error\":\"missing job id\"}", strlen("{\"error\":\"missing job id\"}"));
            ws->close(ws);
        }
        return;
    }

    job_system_t *jobs = ctx->jobs;
    char job_uuid[JOB_UUID_STR_LEN];
    int since_event_id = 0;
    if (jobs_parse_ws_session(ws->session, job_uuid, sizeof(job_uuid), &since_event_id) != 0) {
        ws->send(ws, "{\"error\":\"invalid session\"}", strlen("{\"error\":\"invalid session\"}"));
        ws->close(ws);
        return;
    }

    int job_id = 0;
    if (jobs_fetch_job_id(jobs, job_uuid, &job_id) != 0) {
        ws->send(ws, "{\"error\":\"job not found\"}", strlen("{\"error\":\"job not found\"}"));
        ws->close(ws);
        return;
    }

    if (jobs_subscribers_add(jobs, job_uuid, ws, since_event_id) != 0) {
        ws->send(ws, "{\"error\":\"subscription failed\"}", strlen("{\"error\":\"subscription failed\"}"));
        ws->close(ws);
        return;
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT id, ts, type, data_json FROM job_events WHERE job_id = ? AND id > ? ORDER BY id ASC";
    if (jobs_db_prepare(jobs->db, sql, &stmt) != 0) {
        return;
    }

    jobs->db->bind_int(stmt, 1, job_id);
    jobs->db->bind_int(stmt, 2, since_event_id);
    while (jobs->db->step(stmt) == SQLITE_ROW) {
        int event_id = jobs->db->column_int(stmt, 0);
        int ts = jobs->db->column_int(stmt, 1);
        const char *type = jobs->db->column_text(stmt, 2);
        const char *data_json = jobs->db->column_text(stmt, 3);
        jobs_send_event_to_ws(ws, job_uuid, event_id, ts, type ? type : "", data_json);
    }

    jobs->db->finalize(stmt);
}

static void jobs_ws_on_message(struct cweb_context *ctx, websocket_t *ws, const char *message, size_t length) {
    (void)ctx;
    (void)ws;
    (void)message;
    (void)length;
}

static void jobs_ws_on_close(struct cweb_context *ctx, websocket_t *ws) {
    if (!ctx || !ctx->jobs || !ws || !ws->session) {
        return;
    }

    job_system_t *jobs = ctx->jobs;
    char job_uuid[JOB_UUID_STR_LEN];
    int since_event_id = 0;
    if (jobs_parse_ws_session(ws->session, job_uuid, sizeof(job_uuid), &since_event_id) != 0) {
        return;
    }

    jobs_subscribers_remove(jobs, job_uuid, ws);
}

int jobs_init(job_system_t *jobs, struct cweb_context *ctx, struct router *router, struct ws_server *ws) {
    if (!jobs || !ctx || !ctx->database || !router || !ws) {
        return -1;
    }

    jobs->db = ctx->database;
    jobs->scheduler = ctx->scheduler;
    jobs->router = router;
    jobs->ws = ws;
    jobs->subscribers = map_create(16);
    if (!jobs->subscribers) {
        return -1;
    }

    if (pthread_mutex_init(&jobs->subscribers_mutex, NULL) != 0) {
        map_destroy(jobs->subscribers);
        jobs->subscribers = NULL;
        return -1;
    }

    jobs->job_registry = map_create(16);
    if (!jobs->job_registry) {
        pthread_mutex_destroy(&jobs->subscribers_mutex);
        map_destroy(jobs->subscribers);
        jobs->subscribers = NULL;
        return -1;
    }

    if (pthread_mutex_init(&jobs->job_registry_mutex, NULL) != 0) {
        map_destroy(jobs->job_registry);
        jobs->job_registry = NULL;
        pthread_mutex_destroy(&jobs->subscribers_mutex);
        map_destroy(jobs->subscribers);
        jobs->subscribers = NULL;
        return -1;
    }

    const char *jobs_table =
        "CREATE TABLE IF NOT EXISTS jobs ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "uuid TEXT UNIQUE,"
        "module_name TEXT,"
        "job_name TEXT,"
        "state TEXT,"
        "module_hash TEXT,"
        "created_at INTEGER,"
        "updated_at INTEGER,"
        "payload_json TEXT,"
        "result_json TEXT,"
        "error_text TEXT"
        ")";

    const char *events_table =
        "CREATE TABLE IF NOT EXISTS job_events ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "job_id INTEGER,"
        "ts INTEGER,"
        "type TEXT,"
        "data_json TEXT"
        ")";

    const char *events_index =
        "CREATE INDEX IF NOT EXISTS idx_job_events_job_id ON job_events(job_id)";

    if (jobs_db_exec(jobs->db, jobs_table) != 0 ||
        jobs_db_exec(jobs->db, events_table) != 0 ||
        jobs_db_exec(jobs->db, events_index) != 0) {
        pthread_mutex_destroy(&jobs->job_registry_mutex);
        map_destroy(jobs->job_registry);
        jobs->job_registry = NULL;
        pthread_mutex_destroy(&jobs->subscribers_mutex);
        map_destroy(jobs->subscribers);
        jobs->subscribers = NULL;
        return -1;
    }

    jobs->ws_info.path = "/jobs/ws";
    jobs->ws_info.on_open = jobs_ws_on_open;
    jobs->ws_info.on_message = jobs_ws_on_message;
    jobs->ws_info.on_close = jobs_ws_on_close;

    for (int i = 0; i < router->count; i++) {
        if (router->entries[i].ref) {
            jobs_register_module(jobs, router->entries[i].ref);
        }
    }

    return 0;
}

void jobs_shutdown(job_system_t *jobs) {
    if (!jobs) {
        return;
    }

    pthread_mutex_lock(&jobs->subscribers_mutex);
    if (jobs->subscribers) {
        for (size_t i = 0; i < jobs->subscribers->capacity; i++) {
            struct map_entry *entry = &jobs->subscribers->entries[i];
            if (entry->state == MAP_ENTRY_OCCUPIED) {
                jobs_subscribers_free_list(entry->value);
            }
        }
        map_destroy(jobs->subscribers);
        jobs->subscribers = NULL;
    }
    pthread_mutex_unlock(&jobs->subscribers_mutex);
    pthread_mutex_destroy(&jobs->subscribers_mutex);

    pthread_mutex_lock(&jobs->job_registry_mutex);
    if (jobs->job_registry) {
        for (size_t i = 0; i < jobs->job_registry->capacity; i++) {
            struct map_entry *entry = &jobs->job_registry->entries[i];
            if (entry->state == MAP_ENTRY_OCCUPIED) {
                jobs_registry_free(entry->value);
            }
        }
        map_destroy(jobs->job_registry);
        jobs->job_registry = NULL;
    }
    pthread_mutex_unlock(&jobs->job_registry_mutex);
    pthread_mutex_destroy(&jobs->job_registry_mutex);
}

const websocket_info_t *jobs_ws_info(job_system_t *jobs) {
    if (!jobs) {
        return NULL;
    }
    return &jobs->ws_info;
}

static int jobs_handle_create(job_system_t *jobs, struct cweb_context *ctx, http_request_t *req, http_response_t *res) {
    if (!jobs || !ctx || !req || !res || !res->body) {
        return -1;
    }

    if (!req->body) {
        return jobs_respond_error(res, HTTP_400_BAD_REQUEST, "missing body");
    }

    if (!res->headers) {
        return -1;
    }

    json_error_t error;
    json_t *root = json_loads(req->body, 0, &error);
    if (!root) {
        return jobs_respond_error(res, HTTP_400_BAD_REQUEST, "invalid json");
    }
    if (!json_is_object(root)) {
        json_decref(root);
        return jobs_respond_error(res, HTTP_400_BAD_REQUEST, "json must be object");
    }

    json_t *job_val = json_object_get(root, "job");
    json_t *payload_val = json_object_get(root, "payload");

    if (!json_is_string(job_val)) {
        json_decref(root);
        return jobs_respond_error(res, HTTP_400_BAD_REQUEST, "missing job");
    }

    const char *job_name = json_string_value(job_val);

    struct job_route job_route = jobs_registry_find(jobs, job_name);
    if (!job_route.job) {
        json_decref(root);
        return jobs_respond_error(res, HTTP_404_NOT_FOUND, "job not found");
    }

    if (!jobs->scheduler) {
        router_job_release(jobs->router, job_route.ref, ctx);
        json_decref(root);
        return jobs_respond_error(res, HTTP_500_INTERNAL_SERVER_ERROR, "scheduler unavailable");
    }

    char *payload_json = NULL;
    if (payload_val) {
        payload_json = json_dumps(payload_val, JSON_COMPACT);
    } else {
        payload_json = strdup("{}");
    }

    if (!payload_json) {
        router_job_release(jobs->router, job_route.ref, ctx);
        json_decref(root);
        return jobs_respond_error(res, HTTP_500_INTERNAL_SERVER_ERROR, "payload encode failed");
    }

    char job_uuid[JOB_UUID_STR_LEN];
    if (jobs_generate_uuid(job_uuid) != 0) {
        router_job_release(jobs->router, job_route.ref, ctx);
        json_decref(root);
        free(payload_json);
        return jobs_respond_error(res, HTTP_500_INTERNAL_SERVER_ERROR, "uuid failed");
    }

    int job_id = 0;
    const char *module_name = job_route.ref && job_route.ref->module ? job_route.ref->module->name : "";
    if (jobs_insert_job(jobs, job_uuid, module_name, job_name, job_route.module_hash, payload_json, &job_id) != 0) {
        router_job_release(jobs->router, job_route.ref, ctx);
        json_decref(root);
        free(payload_json);
        return jobs_respond_error(res, HTTP_500_INTERNAL_SERVER_ERROR, "job insert failed");
    }

    jobs_insert_event(jobs, job_id, (int)time(NULL), "created", payload_json, NULL);

    job_work_t *work = calloc(1, sizeof(*work));
    if (!work) {
        router_job_release(jobs->router, job_route.ref, ctx);
        json_decref(root);
        free(payload_json);
        return jobs_respond_error(res, HTTP_500_INTERNAL_SERVER_ERROR, "allocation failed");
    }

    work->jobs = jobs;
    work->ctx = ctx;
    work->ref = job_route.ref;
    work->job = job_route.job;
    work->job_id = job_id;
    snprintf(work->job_uuid, sizeof(work->job_uuid), "%s", job_uuid);
    work->payload_json = payload_json;

    if (scheduler_add(jobs->scheduler, jobs_execute, work, ASYNC) != 0) {
        jobs_update_state(jobs, job_id, JOB_STATE_FAILED, NULL, "scheduler unavailable");
        jobs_insert_event(jobs, job_id, (int)time(NULL), "failed", "scheduler unavailable", NULL);
        router_job_release(jobs->router, job_route.ref, ctx);
        json_decref(root);
        free(payload_json);
        free(work);
        return jobs_respond_error(res, HTTP_500_INTERNAL_SERVER_ERROR, "scheduler full");
    }

    json_t *resp = json_object();
    json_object_set_new(resp, "job_uuid", json_string(job_uuid));
    json_object_set_new(resp, "state", json_string(job_state_to_string(JOB_STATE_PENDING)));
    json_object_set_new(resp, "module_hash", json_string(job_route.module_hash));

    char *response = json_dumps(resp, JSON_COMPACT);
    json_decref(resp);
    json_decref(root);
    if (!response) {
        return jobs_respond_error(res, HTTP_500_INTERNAL_SERVER_ERROR, "response failed");
    }

    snprintf(res->body, HTTP_RESPONSE_SIZE, "%s", response);
    free(response);
    http_kv_insert(res->headers, "Content-Type", strdup("application/json"));
    res->status = HTTP_200_OK;
    return 0;
}

int jobs_create_impl(void *user_data,
    const char *job_name,
    const char *payload_json,
    cweb_uuid_t *job_uuid_out) {
    struct cweb_context *ctx = user_data;
    if (!ctx || !ctx->jobs || !job_name || !job_uuid_out) {
        return -1;
    }

    job_system_t *jobs = ctx->jobs;
    struct job_route job_route = jobs_registry_find(jobs, job_name);
    if (!job_route.job) {
        return -1;
    }

    if (!jobs->scheduler) {
        router_job_release(jobs->router, job_route.ref, ctx);
        return -1;
    }

    char *payload_copy = NULL;
    if (payload_json && payload_json[0] != '\0') {
        payload_copy = strdup(payload_json);
    } else {
        payload_copy = strdup("{}");
    }

    if (!payload_copy) {
        router_job_release(jobs->router, job_route.ref, ctx);
        return -1;
    }

    char job_uuid[JOB_UUID_STR_LEN];
    if (jobs_generate_uuid(job_uuid) != 0) {
        router_job_release(jobs->router, job_route.ref, ctx);
        free(payload_copy);
        return -1;
    }

    int job_id = 0;
    const char *module_name = job_route.ref && job_route.ref->module ? job_route.ref->module->name : "";
    if (jobs_insert_job(jobs, job_uuid, module_name, job_name, job_route.module_hash, payload_copy, &job_id) != 0) {
        router_job_release(jobs->router, job_route.ref, ctx);
        free(payload_copy);
        return -1;
    }

    jobs_insert_event(jobs, job_id, (int)time(NULL), "created", payload_copy, NULL);

    job_work_t *work = calloc(1, sizeof(*work));
    if (!work) {
        router_job_release(jobs->router, job_route.ref, ctx);
        free(payload_copy);
        return -1;
    }

    work->jobs = jobs;
    work->ctx = ctx;
    work->ref = job_route.ref;
    work->job = job_route.job;
    work->job_id = job_id;
    snprintf(work->job_uuid, sizeof(work->job_uuid), "%s", job_uuid);
    work->payload_json = payload_copy;

    if (scheduler_add(jobs->scheduler, jobs_execute, work, ASYNC) != 0) {
        jobs_update_state(jobs, job_id, JOB_STATE_FAILED, NULL, "scheduler unavailable");
        jobs_insert_event(jobs, job_id, (int)time(NULL), "failed", "scheduler unavailable", NULL);
        router_job_release(jobs->router, job_route.ref, ctx);
        free(payload_copy);
        free(work);
        return -1;
    }

    if (uuid_from_string(job_uuid_out, job_uuid) != 0) {
        return -1;
    }
    return 0;
}

static int jobs_handle_status(job_system_t *jobs, http_response_t *res, const char *job_uuid) {
    if (!res || !res->body || !res->headers) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT module_name, job_name, state, module_hash, created_at, updated_at, result_json, error_text FROM jobs WHERE uuid = ?";
    if (jobs_db_prepare(jobs->db, sql, &stmt) != 0) {
        return jobs_respond_error(res, HTTP_500_INTERNAL_SERVER_ERROR, "db error");
    }

    jobs->db->bind_text(stmt, 1, job_uuid, -1, SQLITE_TRANSIENT);
    if (jobs_db_step_row(jobs->db, stmt) != 0) {
        jobs->db->finalize(stmt);
        return jobs_respond_error(res, HTTP_404_NOT_FOUND, "job not found");
    }

    const char *module_name = jobs->db->column_text(stmt, 0);
    const char *job_name = jobs->db->column_text(stmt, 1);
    const char *state = jobs->db->column_text(stmt, 2);
    const char *module_hash = jobs->db->column_text(stmt, 3);
    int created_at = jobs->db->column_int(stmt, 4);
    int updated_at = jobs->db->column_int(stmt, 5);
    const char *result_json = jobs->db->column_text(stmt, 6);
    const char *error_text = jobs->db->column_text(stmt, 7);

    json_t *root = json_object();
    json_object_set_new(root, "job_uuid", json_string(job_uuid));
    json_object_set_new(root, "module", json_string(module_name ? module_name : ""));
    json_object_set_new(root, "job", json_string(job_name ? job_name : ""));
    json_object_set_new(root, "state", json_string(state ? state : ""));
    json_object_set_new(root, "module_hash", json_string(module_hash ? module_hash : ""));
    json_object_set_new(root, "created_at", json_integer(created_at));
    json_object_set_new(root, "updated_at", json_integer(updated_at));

    if (result_json && strlen(result_json) > 0) {
        json_error_t error;
        json_t *result = json_loads(result_json, 0, &error);
        if (result) {
            json_object_set_new(root, "result", result);
        } else {
            json_object_set_new(root, "result", json_string(result_json));
        }
    } else {
        json_object_set_new(root, "result", json_null());
    }

    if (error_text && strlen(error_text) > 0) {
        json_object_set_new(root, "error", json_string(error_text));
    } else {
        json_object_set_new(root, "error", json_null());
    }

    char *response = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    jobs->db->finalize(stmt);

    if (!response) {
        return jobs_respond_error(res, HTTP_500_INTERNAL_SERVER_ERROR, "response failed");
    }

    snprintf(res->body, HTTP_RESPONSE_SIZE, "%s", response);
    free(response);
    http_kv_insert(res->headers, "Content-Type", strdup("application/json"));
    res->status = HTTP_200_OK;
    return 0;
}

static int jobs_handle_cancel(job_system_t *jobs, struct cweb_context *ctx, http_response_t *res, const char *job_uuid) {
    if (!res || !res->body || !res->headers) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT module_name, job_name, state, id FROM jobs WHERE uuid = ?";
    if (jobs_db_prepare(jobs->db, sql, &stmt) != 0) {
        return jobs_respond_error(res, HTTP_500_INTERNAL_SERVER_ERROR, "db error");
    }

    jobs->db->bind_text(stmt, 1, job_uuid, -1, SQLITE_TRANSIENT);
    if (jobs_db_step_row(jobs->db, stmt) != 0) {
        jobs->db->finalize(stmt);
        return jobs_respond_error(res, HTTP_404_NOT_FOUND, "job not found");
    }

    const char *module_name = jobs->db->column_text(stmt, 0);
    const char *job_name = jobs->db->column_text(stmt, 1);
    const char *state = jobs->db->column_text(stmt, 2);
    int job_id = jobs->db->column_int(stmt, 3);
    jobs->db->finalize(stmt);

    if (state && (strcmp(state, "done") == 0 || strcmp(state, "failed") == 0)) {
        return jobs_respond_error(res, HTTP_409_CONFLICT, "job already finished");
    }

    jobs_update_state(jobs, job_id, JOB_STATE_CANCELED, NULL, "canceled");
    jobs_insert_event(jobs, job_id, (int)time(NULL), "canceled", NULL, NULL);

    struct job_route job_route = router_job_find(jobs->router, module_name ? module_name : "", job_name ? job_name : "");
    if (job_route.job && job_route.job->cancel) {
        safe_execute_job_cancel(job_route.job->cancel, ctx, job_uuid);
    }
    if (job_route.job) {
        router_job_release(jobs->router, job_route.ref, ctx);
    }

    json_t *root = json_object();
    json_object_set_new(root, "job_uuid", json_string(job_uuid));
    json_object_set_new(root, "state", json_string(job_state_to_string(JOB_STATE_CANCELED)));
    char *response = json_dumps(root, JSON_COMPACT);
    json_decref(root);

    if (!response) {
        return jobs_respond_error(res, HTTP_500_INTERNAL_SERVER_ERROR, "response failed");
    }

    snprintf(res->body, HTTP_RESPONSE_SIZE, "%s", response);
    free(response);
    http_kv_insert(res->headers, "Content-Type", strdup("application/json"));
    res->status = HTTP_200_OK;
    return 0;
}

static int jobs_handle_list(job_system_t *jobs, http_request_t *req, http_response_t *res) {
    if (!req || !res || !res->body || !res->headers) {
        return -1;
    }
    const char *state = http_kv_get(req->params, "state");
    sqlite3_stmt *stmt = NULL;
    const char *sql_with_state = "SELECT uuid, state, module_name, job_name, module_hash, updated_at FROM jobs WHERE state = ? ORDER BY updated_at DESC LIMIT ?";
    const char *sql_no_state = "SELECT uuid, state, module_name, job_name, module_hash, updated_at FROM jobs ORDER BY updated_at DESC LIMIT ?";

    if (state) {
        if (jobs_db_prepare(jobs->db, sql_with_state, &stmt) != 0) {
            return jobs_respond_error(res, HTTP_500_INTERNAL_SERVER_ERROR, "db error");
        }
        jobs->db->bind_text(stmt, 1, state, -1, SQLITE_TRANSIENT);
        jobs->db->bind_int(stmt, 2, JOBS_LIST_LIMIT);
    } else {
        if (jobs_db_prepare(jobs->db, sql_no_state, &stmt) != 0) {
            return jobs_respond_error(res, HTTP_500_INTERNAL_SERVER_ERROR, "db error");
        }
        jobs->db->bind_int(stmt, 1, JOBS_LIST_LIMIT);
    }

    json_t *root = json_object();
    json_t *items = json_array();

    while (jobs->db->step(stmt) == SQLITE_ROW) {
        const char *uuid = jobs->db->column_text(stmt, 0);
        const char *row_state = jobs->db->column_text(stmt, 1);
        const char *module_name = jobs->db->column_text(stmt, 2);
        const char *job_name = jobs->db->column_text(stmt, 3);
        const char *module_hash = jobs->db->column_text(stmt, 4);
        int updated_at = jobs->db->column_int(stmt, 5);

        json_t *item = json_object();
        json_object_set_new(item, "job_uuid", json_string(uuid ? uuid : ""));
        json_object_set_new(item, "state", json_string(row_state ? row_state : ""));
        json_object_set_new(item, "module", json_string(module_name ? module_name : ""));
        json_object_set_new(item, "job", json_string(job_name ? job_name : ""));
        json_object_set_new(item, "module_hash", json_string(module_hash ? module_hash : ""));
        json_object_set_new(item, "updated_at", json_integer(updated_at));
        json_array_append_new(items, item);
    }

    jobs->db->finalize(stmt);

    json_object_set_new(root, "jobs", items);
    char *response = json_dumps(root, JSON_COMPACT);
    json_decref(root);

    if (!response) {
        return jobs_respond_error(res, HTTP_500_INTERNAL_SERVER_ERROR, "response failed");
    }

    snprintf(res->body, HTTP_RESPONSE_SIZE, "%s", response);
    free(response);
    http_kv_insert(res->headers, "Content-Type", strdup("application/json"));
    res->status = HTTP_200_OK;
    return 0;
}

int jobs_handle_http(job_system_t *jobs, struct cweb_context *ctx, http_request_t *req, http_response_t *res) {
    if (!jobs || !req || !res || !req->path) {
        return 0;
    }

    if (strcmp(req->path, "/jobs") == 0) {
        if (req->method == HTTP_POST) {
            jobs_handle_create(jobs, ctx, req, res);
            return 1;
        }
        if (req->method == HTTP_GET) {
            jobs_handle_list(jobs, req, res);
            return 1;
        }
        jobs_respond_error(res, HTTP_405_METHOD_NOT_ALLOWED, "method not allowed");
        return 1;
    }

    if (strncmp(req->path, "/jobs/", 6) == 0) {
        const char *suffix = req->path + 6;
        const char *cancel = strstr(suffix, "/cancel");
        if (cancel && strcmp(cancel, "/cancel") == 0) {
            char job_uuid[JOB_UUID_STR_LEN];
            size_t len = (size_t)(cancel - suffix);
            if (len >= sizeof(job_uuid)) {
                return jobs_respond_error(res, HTTP_400_BAD_REQUEST, "invalid uuid");
            }
            memcpy(job_uuid, suffix, len);
            job_uuid[len] = '\0';
            if (req->method != HTTP_POST) {
                jobs_respond_error(res, HTTP_405_METHOD_NOT_ALLOWED, "method not allowed");
                return 1;
            }
            jobs_handle_cancel(jobs, ctx, res, job_uuid);
            return 1;
        }

        if (req->method == HTTP_GET) {
            if (strchr(suffix, '/') != NULL) {
                return jobs_respond_error(res, HTTP_404_NOT_FOUND, "invalid job path");
            }
            char job_uuid[JOB_UUID_STR_LEN];
            snprintf(job_uuid, sizeof(job_uuid), "%s", suffix);
            jobs_handle_status(jobs, res, job_uuid);
            return 1;
        }

        jobs_respond_error(res, HTTP_405_METHOD_NOT_ALLOWED, "method not allowed");
        return 1;
    }

    return 0;
}
