#ifndef DB_H
#define DB_H

#include <sqlite3.h>

struct sqldb {
    sqlite3 *db;
    int (*exec)(struct sqldb *, const char *, int (*)(void *, int, char **, char **), void *);
    int (*prepare)(struct sqldb *, const char *, int, sqlite3_stmt **, const char **);
    int (*step)(sqlite3_stmt *);
    int (*finalize)(sqlite3_stmt *);
    int (*bind_text)(sqlite3_stmt *, int, const char *, int, void (*)(void *));
    int (*bind_int)(sqlite3_stmt *, int, int);
    const char* (*column_text)(sqlite3_stmt *, int);
    int (*column_int)(sqlite3_stmt *, int);
    int (*column_count)(sqlite3_stmt *);
    int (*reset)(sqlite3_stmt *);
    int (*changes)(struct sqldb *);
    int (*last_insert_rowid)(struct sqldb *);
    void (*free)(void *);
};

int sqldb_init(struct sqldb *db, const char *filename);
void sqldb_shutdown(struct sqldb *db);

#endif // DB_H
