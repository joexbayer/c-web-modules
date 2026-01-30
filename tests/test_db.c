#include "test.h"

#include <db.h>
#include <sqlite3.h>

TEST(test_db_basic) {
    struct sqldb db;
    int rc = sqldb_init(&db, ":memory:");
    ASSERT_INT_EQ(rc, 0);

    rc = db.exec(&db, "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)", NULL, NULL);
    ASSERT_INT_EQ(rc, SQLITE_OK);

    rc = db.exec(&db, "INSERT INTO t (name) VALUES ('alice')", NULL, NULL);
    ASSERT_INT_EQ(rc, SQLITE_OK);

    sqlite3_stmt *stmt = NULL;
    rc = db.prepare(&db, "SELECT id, name FROM t", -1, &stmt, NULL);
    ASSERT_INT_EQ(rc, SQLITE_OK);

    rc = db.step(stmt);
    ASSERT_INT_EQ(rc, SQLITE_ROW);

    int id = db.column_int(stmt, 0);
    const char *name = db.column_text(stmt, 1);
    ASSERT_INT_EQ(id, 1);
    ASSERT_STR_EQ(name, "alice");

    db.finalize(stmt);
    sqldb_shutdown(&db);
}

void register_db_tests(void) {
    test_register("db_basic", test_db_basic);
}
