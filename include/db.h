#ifndef DB_H
#define DB_H

#include <sqlite3.h>

struct sqldb {
    sqlite3 *db;
    int (*exec)(const char *, int (*)(void *, int, char **, char **), void *);
    int (*prepare)(sqlite3 *, const char *, int, sqlite3_stmt **, const char **);
    int (*step)(sqlite3_stmt *);
    int (*finalize)(sqlite3_stmt *);
    int (*bind_text)(sqlite3_stmt *, int, const char *, int, void (*)(void *));
    int (*bind_int)(sqlite3_stmt *, int, int);
    const char* (*column_text)(sqlite3_stmt *, int);
    int (*column_int)(sqlite3_stmt *, int);
    int (*column_count)(sqlite3_stmt *);
    int (*reset)(sqlite3_stmt *);
    int (*changes)(sqlite3 *);
    int (*last_insert_rowid)(sqlite3 *);
    void (*free)(void *);

};
extern struct sqldb *exposed_sqldb;

#endif // DB_H