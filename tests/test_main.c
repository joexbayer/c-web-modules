#include "test.h"

#include <stdio.h>

void register_jobs_tests(void);
void register_db_tests(void);
void register_scheduler_tests(void);

int main(void) {
    register_jobs_tests();
    register_db_tests();
    register_scheduler_tests();

    size_t count = 0;
    const test_case_t *tests = test_get_all(&count);
    int failed = 0;

    for (size_t i = 0; i < count; i++) {
        test_reset_current_failed();
        printf("[TEST] %s\n", tests[i].name);
        tests[i].fn();
        if (test_current_failed()) {
            failed++;
            printf("[FAIL] %s\n", tests[i].name);
        } else {
            printf("[PASS] %s\n", tests[i].name);
        }
    }

    printf("[DONE] %zu tests, %d failed\n", count, failed);
    return failed == 0 ? 0 : 1;
}
