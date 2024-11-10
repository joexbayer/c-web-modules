#ifndef CWEB_H
#define CWEB_H

int mgnt_register_route(char* route, char* code, char* func_name);

#include <stdio.h>

#define dbgprint(fmt, ...) \
    do { fprintf(stderr, fmt, __VA_ARGS__); } while (0)

#endif // CWEB_H