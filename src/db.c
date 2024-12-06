#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <db.h>

#define DB_FILE "db.sqlite3"

static int db_exec(const char *sql, int (*callback)(void *, int, char **, char **), void *data);
static int db_prepare(sqlite3 *db, const char *sql, int len, sqlite3_stmt **stmt, const char **tail);
static int db_step(sqlite3_stmt *stmt);
static int db_finalize(sqlite3_stmt *stmt);
static int db_bind_text(sqlite3_stmt *stmt, int pos, const char *text, int len, void (*free)(void *));
static int db_bind_int(sqlite3_stmt *stmt, int pos, int value);
static const char *db_column_text(sqlite3_stmt *stmt, int pos);
static int db_column_int(sqlite3_stmt *stmt, int pos);
static int db_column_count(sqlite3_stmt *stmt);
static int db_reset(sqlite3_stmt *stmt);
static int db_changes(sqlite3 *db);
static int db_last_insert_rowid(sqlite3 *db);
static void db_free(void *ptr);

struct sqldb sql_db = {
    .exec = db_exec,
    .prepare = db_prepare,
    .step = db_step,
    .finalize = db_finalize,
    .bind_text = db_bind_text,
    .bind_int = db_bind_int,
    .column_text = db_column_text,
    .column_int = db_column_int,
    .column_count = db_column_count,
    .reset = db_reset,
    .changes = db_changes,
    .last_insert_rowid = db_last_insert_rowid,
    .free = db_free
};
__attribute__((visibility("default"))) struct sqldb *exposed_sqldb = &sql_db;

static int db_exec(const char *sql, int (*callback)(void *, int, char **, char **), void *data) {
    char *err_msg = 0;
    int rc = sqlite3_exec(sql_db.db, sql, callback, data, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
    }
    return rc;
}

static int db_prepare(sqlite3 *db, const char *sql, int len, sqlite3_stmt **stmt, const char **tail) {
    return sqlite3_prepare_v2(db, sql, len, stmt, tail);
}

static int db_step(sqlite3_stmt *stmt) {
    return sqlite3_step(stmt);
}

static int db_finalize(sqlite3_stmt *stmt) {
    return sqlite3_finalize(stmt);
}

static int db_bind_text(sqlite3_stmt *stmt, int pos, const char *text, int len, void (*free)(void *)) {
    return sqlite3_bind_text(stmt, pos, text, len, free);
}

static int db_bind_int(sqlite3_stmt *stmt, int pos, int value) {
    return sqlite3_bind_int(stmt, pos, value);
}

static const char *db_column_text(sqlite3_stmt *stmt, int pos) {
    return (const char *)sqlite3_column_text(stmt, pos);
}

static int db_column_int(sqlite3_stmt *stmt, int pos) {
    return sqlite3_column_int(stmt, pos);
}

static int db_column_count(sqlite3_stmt *stmt) {
    return sqlite3_column_count(stmt);
}

static int db_reset(sqlite3_stmt *stmt) {
    return sqlite3_reset(stmt);
}

static int db_changes(sqlite3 *db) {
    return sqlite3_changes(db);
}

static int db_last_insert_rowid(sqlite3 *db) {
    return sqlite3_last_insert_rowid(db);
}

static void db_free(void *ptr) {
    return sqlite3_free(ptr);
}

__attribute__((constructor)) void db_init() {
    sqlite3_config(SQLITE_CONFIG_SERIALIZED);

    int rc = sqlite3_open(DB_FILE, &sql_db.db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(sql_db.db));
        exit(1);
    }
}

__attribute__((destructor)) void db_close() {
    sqlite3_close(sql_db.db);
    printf("[SHUTDOWN] Database closed\n");
}