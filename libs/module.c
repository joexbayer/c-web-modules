#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <container.h>

struct container* container = NULL;
/* Global handle to access server symbols */
static void *dlhandle = NULL;

__attribute__((constructor)) void module_constructor() {
    dlhandle = dlopen(NULL, RTLD_GLOBAL | RTLD_LAZY);
    if (!dlhandle) {
        fprintf(stderr, "Error accessing server symbols: %s\n", dlerror());
        return;
    }

    /* Get internal container */
    struct container** container_ptr = (struct container**)dlsym(dlhandle, "exposed_container");
    if(!container_ptr){
        fprintf(stderr, "Error accessing container_ptr: %s\n", dlerror());
        return;
    }

    /* Set internal container */
    container = *container_ptr;
    if(!container){
        fprintf(stderr, "Error accessing container: %s\n", dlerror());
        return;
    }
}