#include <cweb.h>
#include <stdlib.h>
#include <sqlite3.h>

static int index_route(struct http_request *req, struct http_response *res) {

    /* Get modules from database */
    const char *sql = "SELECT * FROM module";
    sqlite3_stmt *stmt;
    if (database->prepare(database->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement\n");
        return -1;
    }
    
    while (database->step(stmt) == SQLITE_ROW) {
        const char *author = database->column_text(stmt, 0);
        const char *name = database->column_text(stmt, 1);
        const char *code = database->column_text(stmt, 2);
         printf("Author: %s, Name: %s, Code: %s\n", author, name, code);
    }

    database->finalize(stmt);

    res->status = HTTP_200_OK;
    snprintf(res->body, HTTP_RESPONSE_SIZE, "<h1>Hello, World!</h1>");
    return 0;
}

static int add(struct http_request *req, struct http_response *res) {
    const char *author = map_get(req->data, "author");
    const char *name = map_get(req->data, "name");
    const char *code = map_get(req->data, "code");

    const char *sql = "INSERT INTO module (author, name, code) VALUES (?, ?, ?)";
    sqlite3_stmt *stmt;
    if (database->prepare(database->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement\n");
        return -1;
    }

    if (database->bind_text(stmt, 1, author, -1, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to bind author\n");
        return -1;
    }

    if (database->bind_text(stmt, 2, name, -1, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to bind name\n");
        return -1;
    }

    if (database->bind_text(stmt, 3, code, -1, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to bind code\n");
        return -1;
    }

    if (database->step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "Failed to execute statement\n");
        return -1;
    }

    database->finalize(stmt);

    res->status = HTTP_200_OK;
    snprintf(res->body, HTTP_RESPONSE_SIZE, "Module added successfully");
    return 0;
}

static void onload(){
    printf("[WEBUI] Loaded.\n");

    const char *create_table_sql = "CREATE TABLE IF NOT EXISTS module ("
                                   "author TEXT, "
                                   "name TEXT, "
                                   "code TEXT);";
    if (database->exec(create_table_sql, NULL, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to create table\n");
        return;
    }
}

static void unload(){
    printf("[WEBUI] Unloaded.\n");
}

export module_t config = {
    .name = "webui",
    .author = "joebayer",
    .routes = {
        {"/webui", "GET", index_route, NONE},
    },
    .size = 1,
    .onload = onload,
    .unload = unload,
};
