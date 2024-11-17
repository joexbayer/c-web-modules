# c-web-functions

## Dependecies
```bash
sudo apt-get install libssl-dev
sudo apt-get install libsqlite3-dev
sudo apt-get install libjansson-dev

brew install openssl@3
brew install sqlite
brew install jansson

# Create certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365

```

## Important folders

### modules
Contains the modules .so files

### shared
User uploaded files, functions will have this as root.

### tmp
?? Scratch folder for functions?

## Deploy
```bash
curl -X POST "http://localhost:8080/mgnt" \
    -H "Content-Type: multipart/form-data" \
    -F "route=/route2" \
    -F "function_name=func2" \
    -F "code=@func2.c"
```

## Websockets
How to deal with "dangling" paths, that were removed?
Find difference in new module to old and remove old paths

## Memory
Memory used by a module which crashes is lost...

## Routes
Route collisions

## TODO:
trie prefix gateway for route search.
shared folder
create and change cwd to tmp for modules.
CLEANUP
route locks
caching?
Routes struct in C file
authorization
sessions (cookies)
mounted filesystem files.
cgroups?

```c
#include <sys/prctl.h>
#include <seccomp.h>

// Disable core dumpspch
prctl(PR_SET_DUMPABLE, 0);

// Drop CAP_SYS_PTRACE
prctl(PR_SET_SECUREBITS, SECBIT_NO_CAP_AMBIENT_RAISE);

// Unshare namespaces
unshare(CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUSER);

// Mount an empty tmpfs on /proc to prevent access to process info
mount("none", "/proc", "tmpfs", 0, "");

// Apply seccomp to restrict system calls
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);  // Kill on disallowed syscalls
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);  // Allow write
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);   // Allow exit
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);   // Allow read
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);  // Allow close
seccomp_load(ctx);

// Execute the isolated function
isolated_function();

// Clean up seccomp
seccomp_release(ctx);

```

```bash
sudo apt-get update
sudo apt-get install libseccomp-dev
```

