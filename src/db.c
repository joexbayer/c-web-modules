#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <db.h>

#define DB_FILE "db.sqlite3"

static int db_exec(const char *sql, int (*callback)(void *, int, char **, char **), void *data);
struct sqldb sql_db = {
    .exec = db_exec
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