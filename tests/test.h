#ifndef TEST_H
#define TEST_H

#include <stddef.h>
#include <string.h>

typedef void (*test_fn_t)(void);

typedef struct test_case {
    const char *name;
    test_fn_t fn;
} test_case_t;

void test_register(const char *name, test_fn_t fn);
const test_case_t *test_get_all(size_t *count);
void test_reset_current_failed(void);
int test_current_failed(void);
void test_fail(const char *file, int line, const char *expr, const char *msg);

#define TEST(name) static void name(void)

#define ASSERT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            test_fail(__FILE__, __LINE__, #cond, NULL); \
            return; \
        } \
    } while (0)

#define ASSERT_NOT_NULL(ptr) \
    do { \
        if ((ptr) == NULL) { \
            test_fail(__FILE__, __LINE__, #ptr " != NULL", NULL); \
            return; \
        } \
    } while (0)

#define ASSERT_INT_EQ(a, b) \
    do { \
        long long _va = (long long)(a); \
        long long _vb = (long long)(b); \
        if (_va != _vb) { \
            test_fail(__FILE__, __LINE__, #a " == " #b, "int mismatch"); \
            return; \
        } \
    } while (0)

#define ASSERT_STR_EQ(a, b) \
    do { \
        const char *_sa = (a); \
        const char *_sb = (b); \
        if (!_sa || !_sb || strcmp(_sa, _sb) != 0) { \
            test_fail(__FILE__, __LINE__, #a " == " #b, "string mismatch"); \
            return; \
        } \
    } while (0)

#endif // TEST_H
