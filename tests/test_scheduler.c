#include "test.h"

#include <scheduler.h>
#include <stdatomic.h>
#include <time.h>

static void test_work_inc(void *data) {
    atomic_int *counter = data;
    atomic_fetch_add(counter, 1);
}

TEST(test_scheduler_runs_work) {
    struct scheduler scheduler;
    atomic_int counter;
    atomic_init(&counter, 0);

    int rc = scheduler_init(&scheduler, 8);
    ASSERT_INT_EQ(rc, 0);

    rc = scheduler_add(&scheduler, test_work_inc, &counter, ASYNC);
    ASSERT_INT_EQ(rc, 0);

    int waited_ms = 0;
    struct timespec ts = {0};
    while (atomic_load(&counter) < 1 && waited_ms < 500) {
        ts.tv_sec = 0;
        ts.tv_nsec = 10 * 1000 * 1000;
        nanosleep(&ts, NULL);
        waited_ms += 10;
    }

    ASSERT_INT_EQ(atomic_load(&counter), 1);
    scheduler_shutdown(&scheduler);
}

void register_scheduler_tests(void) {
    test_register("scheduler_runs_work", test_scheduler_runs_work);
}
