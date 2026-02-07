#include "test.h"

#include <stdio.h>

#define TEST_MAX_CASES 128

static test_case_t tests[TEST_MAX_CASES];
static size_t test_count = 0;
static int current_failed = 0;

void test_register(const char *name, test_fn_t fn) {
    if (!name || !fn || test_count >= TEST_MAX_CASES) {
        return;
    }

    tests[test_count++] = (test_case_t){ .name = name, .fn = fn };
}

const test_case_t *test_get_all(size_t *count) {
    if (count) {
        *count = test_count;
    }
    return tests;
}

void test_reset_current_failed(void) {
    current_failed = 0;
}

int test_current_failed(void) {
    return current_failed;
}

void test_fail(const char *file, int line, const char *expr, const char *msg) {
    current_failed = 1;
    if (msg) {
        fprintf(stderr, "[FAIL] %s:%d: %s (%s)\n", file, line, expr, msg);
    } else {
        fprintf(stderr, "[FAIL] %s:%d: %s\n", file, line, expr);
    }
}
