#ifndef __DEFER_H
#define __DEFER_H

#define __DEFER__(F, V)      \
    auto inline __attribute__((always_inline)) void F(int*);         \
    __attribute__((cleanup(F))) int V; \
    inline __attribute__((always_inline)) void F(int*)
#define __DEFER_(N) __DEFER__(__DEFER_FUNCTION_ ## N, __DEFER_VARIABLE_ ## N)
#define __DEFER(N) __DEFER_(N)
#define defer __DEFER(__COUNTER__)

#endif