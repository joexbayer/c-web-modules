#include <cweb.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

struct html_builder {
    char *buffer;
    size_t size;
    size_t capacity;
};

static void html_builder_init(struct html_builder *builder) {
    builder->buffer = malloc(1024);
    builder->size = 0;
    builder->capacity = 1024;
}

static void html_append(struct html_builder *builder, const char *str) {
    size_t len = strlen(str);
    if (builder->size + len >= builder->capacity) {
        builder->capacity *= 2;
        builder->buffer = realloc(builder->buffer, builder->capacity);
    }
    memcpy(builder->buffer + builder->size, str, len);
    builder->size += len;
}

static void html_builder_free(struct html_builder *builder) {
    free(builder->buffer);
}

static void html_append_format(struct html_builder *builder, const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    size_t available = builder->capacity - builder->size;
    int needed = vsnprintf(builder->buffer + builder->size, available, format, args);
    
    if (needed >= available) {
        builder->capacity += needed + 1;
        builder->buffer = realloc(builder->buffer, builder->capacity);
        vsnprintf(builder->buffer + builder->size, needed + 1, format, args);
    }
    
    builder->size += needed;
    va_end(args);
}

static void html_tag(struct html_builder *builder, const char *tag, const char *format, ...) {
    va_list args;
    va_start(args, format);

    char content[1024];
    vsnprintf(content, sizeof(content), format, args);

    html_append_format(builder, "<%s>%s</%s>", tag, content, tag);

    va_end(args);
}

static int index_route(struct cweb_context *ctx, http_request_t *req, http_response_t *res) {
    struct sqldb *db = ctx->database;

    struct html_builder builder;
    html_builder_init(&builder);

    html_append(&builder, "<h1>Modules</h1>");

    /* Get modules from database */
    const char *sql = "SELECT * FROM module";
    sqlite3_stmt *stmt;
    if (db->prepare(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement\n");
        return -1;
    }
    
    while (db->step(stmt) == SQLITE_ROW) {
        const char *author = db->column_text(stmt, 0);
        const char *name = db->column_text(stmt, 1);
        const char *code = db->column_text(stmt, 2);

        html_tag(&builder, "li", "%s - %s", author, name);
        html_tag(&builder, "pre", "%s", code);
    }

    db->finalize(stmt);

    html_append(&builder, 
        "<form action=\"/webui\" method=\"POST\" enctype=\"multipart/form-data\">"
        "<label for=\"author\">Author:</label><br>"
        "<input type=\"text\" id=\"author\" name=\"author\"><br>"
        "<label for=\"name\">Name:</label><br>"
        "<input type=\"text\" id=\"name\" name=\"name\"><br>"
        "<label for=\"code\">Code:</label><br>"
        "<textarea id=\"code\" name=\"code\"></textarea><br>"
        "<input type=\"submit\" value=\"Submit\">"
        "</form>"
    );

    html_append(&builder, 
        "<form action=\"/clear\" method=\"POST\">"
        "<input type=\"submit\" value=\"Clear Modules\">"
        "</form>"
    );

    snprintf(res->body, HTTP_RESPONSE_SIZE, "%.*s", (int)builder.size, builder.buffer);

    html_builder_free(&builder);

    res->status = HTTP_200_OK;
    return 0;
}

static int clear(struct cweb_context *ctx, http_request_t *req, http_response_t *res) {
    struct sqldb *db = ctx->database;
    const char *sql = "DELETE FROM module";
    if (db->exec(db, sql, NULL, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to clear table\n");
        return -1;
    }

    res->status = HTTP_302_FOUND;
    http_kv_insert(res->headers, "Location", strdup("/webui"));
    return 0;
}

static int add(struct cweb_context *ctx, http_request_t *req, http_response_t *res) {
    struct sqldb *db = ctx->database;
    const char *author = http_kv_get(req->data, "author");
    const char *name = http_kv_get(req->data, "name");
    const char *code = http_kv_get(req->data, "code");

    printf("Adding module: %s - %s\n", author, name);
    printf("Code: %s\n", code);

    const char *sql = "INSERT INTO module (author, name, code) VALUES (?, ?, ?)";
    sqlite3_stmt *stmt;
    if (db->prepare(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement\n");
        return -1;
    }

    if (db->bind_text(stmt, 1, author, -1, NULL) != SQLITE_OK ||
        db->bind_text(stmt, 2, name, -1, NULL) != SQLITE_OK ||
        db->bind_text(stmt, 3, code, -1, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to bind parameters\n");
        return -1;
    }

    if (db->step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "Failed to execute statement\n");
        return -1;
    }

    db->finalize(stmt);

    res->status = HTTP_302_FOUND;
    http_kv_insert(res->headers, "Location", strdup("/webui"));
    return 0;
}

static void onload(struct cweb_context *ctx) {
    struct sqldb *db = ctx->database;
    printf("[WEBUI] Loaded.\n");

    const char *create_table_sql = "CREATE TABLE IF NOT EXISTS module (author TEXT, name TEXT, code TEXT);";
    if (db->exec(db, create_table_sql, NULL, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to create table\n");
        return;
    }
}

static void unload(struct cweb_context *ctx) {
    printf("[WEBUI] Unloaded.\n");
}

export module_t config = {
    .name = "webui",
    .author = "joebayer",
    .routes = {
        {"/webui", "GET", index_route, NONE},
        {"/webui", "POST", add, NONE},
        {"/clear", "POST", clear, NONE},
    },
    .size = 3,
    .onload = onload,
    .unload = unload,
};
