#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <container.h>

struct container* container = NULL;
void *dlhandle = NULL;

__attribute__((constructor)) void module_constructor() {
    dlhandle = dlopen(NULL, RTLD_LAZY);
    if (!dlhandle) {
        fprintf(stderr, "Error accessing server symbols: %s\n", dlerror());
        return;
    }

    /* Get internal container */
    container = *(struct container**)dlsym(dlhandle, "exposed_container");
    if(!container){
        fprintf(stderr, "Error accessing container: %s\n", dlerror());
        return;
    }
}