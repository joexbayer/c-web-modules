#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <db.h>

static int db_exec(struct sqldb *db, const char *sql, int (*callback)(void *, int, char **, char **), void *data);
static int db_prepare(struct sqldb *db, const char *sql, int len, sqlite3_stmt **stmt, const char **tail);
static int db_step(sqlite3_stmt *stmt);
static int db_finalize(sqlite3_stmt *stmt);
static int db_bind_text(sqlite3_stmt *stmt, int pos, const char *text, int len, void (*free_fn)(void *));
static int db_bind_int(sqlite3_stmt *stmt, int pos, int value);
static const char *db_column_text(sqlite3_stmt *stmt, int pos);
static int db_column_int(sqlite3_stmt *stmt, int pos);
static int db_column_count(sqlite3_stmt *stmt);
static int db_reset(sqlite3_stmt *stmt);
static int db_changes(struct sqldb *db);
static int db_last_insert_rowid(struct sqldb *db);
static void db_free(void *ptr);

static void sqldb_bind_ops(struct sqldb *db) {
    db->exec = db_exec;
    db->prepare = db_prepare;
    db->step = db_step;
    db->finalize = db_finalize;
    db->bind_text = db_bind_text;
    db->bind_int = db_bind_int;
    db->column_text = db_column_text;
    db->column_int = db_column_int;
    db->column_count = db_column_count;
    db->reset = db_reset;
    db->changes = db_changes;
    db->last_insert_rowid = db_last_insert_rowid;
    db->free = db_free;
}

static int db_exec(struct sqldb *db, const char *sql, int (*callback)(void *, int, char **, char **), void *data) {
    char *err_msg = 0;
    int rc = sqlite3_exec(db->db, sql, callback, data, &err_msg);
    printf("[SQL] %s\n", sql);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
    }
    return rc;
}

static int db_prepare(struct sqldb *db, const char *sql, int len, sqlite3_stmt **stmt, const char **tail) {
    printf("[SQL] %s\n", sql);
    return sqlite3_prepare_v2(db->db, sql, len, stmt, tail);
}

static int db_step(sqlite3_stmt *stmt) {
    return sqlite3_step(stmt);
}

static int db_finalize(sqlite3_stmt *stmt) {
    return sqlite3_finalize(stmt);
}

static int db_bind_text(sqlite3_stmt *stmt, int pos, const char *text, int len, void (*free_fn)(void *)) {
    return sqlite3_bind_text(stmt, pos, text, len, free_fn);
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

static int db_changes(struct sqldb *db) {
    return sqlite3_changes(db->db);
}

static int db_last_insert_rowid(struct sqldb *db) {
    return (int)sqlite3_last_insert_rowid(db->db);
}

static void db_free(void *ptr) {
    sqlite3_free(ptr);
}

int sqldb_init(struct sqldb *db, const char *filename) {
    if (!db || !filename) {
        return -1;
    }

    sqlite3_config(SQLITE_CONFIG_SERIALIZED);

    int rc = sqlite3_open(filename, &db->db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db->db));
        return -1;
    }

    sqldb_bind_ops(db);
    return 0;
}

void sqldb_shutdown(struct sqldb *db) {
    if (!db || !db->db) {
        return;
    }

    sqlite3_close(db->db);
    db->db = NULL;
    printf("[SHUTDOWN] Database closed\n");
}
