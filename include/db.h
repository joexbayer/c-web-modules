#ifndef DB_H
#define DB_H

#include <sqlite3.h>

struct sqldb {
    sqlite3 *db;
    int (*exec)(const char *, int (*)(void *, int, char **, char **), void *);
};
extern struct sqldb *exposed_sqldb;

#endif // DB_H