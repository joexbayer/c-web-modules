# c-web-modules: Kernel Modules for the Web  

Welcome to **c-web-modules**, a modular and efficient approach to web development in C. Inspired by kernel modules and AWS Lambda, this project allows you to upload C code directly to the server, which compiles and deploys it at runtime. No precompilation is necessary, and the server can easily be upgraded to include more features or external libraries.

---

## What is c-web-modules?  

c-web-modules is a C-based web server with a modular architecture:  

- **Upload Raw Code**: Write your C code locally and upload it to the server, which compiles it into a module.  
- **Runtime Module Deployment**: Add or update features on the server without restarting or touching the main server code.  
- **Expandable Server**: The server supports additional features and external libraries out of the box.  

Currently supported external libraries:  
- **OpenSSL**: Currently only for hashing, but later for secure communication.  
- **SQLite3**: Shared by all modules for lightweight database needs.  
- **Jansson**: For easy JSON parsing and manipulation.  

---

## Example: Counter Module  

Here’s a simple example of a module that keeps track of a counter and returns its value every time you visit `/counter`.
See more examples in the `example/` folder.

#### `counter.c`  
```c
#include <stdio.h>
#include <cweb.h>

static int counter = 0;
static const char* template = 
    "<html>\n"
    "  <body>\n"
    "    <h1>Counter: %d</h1>\n"
    "  </body>\n"
    "</html>\n";

/* Route: /counter - Method GET */
static int index_route(struct http_request *req, struct http_response *res) {
    snprintf(res->body, HTTP_RESPONSE_SIZE, template, counter++);
    res->status = HTTP_200_OK;
    return 0;
}

/* Define the routes for the module */
export module_t config = {
    .name = "counter",
    .author = "cweb",
    .routes = {
        {"/counter", "GET", index_route, NONE},
    },
    .size = 1,
};
```

---

## Why Use c-web-modules?  

1. **Code Deployment**: Upload raw C code to the server for on-the-fly compilation and deployment.  
2. **No Precompilation**: Simplify your workflow—focus on writing code, and let the server handle compilation.  
3. **Dynamic Updates**: Add or replace functionality without downtime or recompiling the entire server.  
4. **Performance**: Written in C, the server offers unmatched speed and efficiency.  
5. **WebSocket Support**: Even when modules are updated, existing WebSocket connections remain alive.  
6. **Built-In Features**: Includes a cross-module cache and scheduler for deferred tasks.  

---

# Deployment  

Deploying code to the server is simple and can be done in multiple ways, depending on your workflow.  

### 1. Basic Deployment with `curl`  

At its core, deploying code to the server involves sending a POST request with the C file attached. Here’s an example using `curl`:  

`curl -X POST -F "code=@path/to/yourcode.c" http://localhost:8080/mgnt`

### 2. Using the cweb script and .ini config
The script handles:  
- Sending the file to the server using `curl`.  
- Parsing responses for success or failure.  
- Providing helpful logs and error messages.  

#### Deploying Multiple Files with a Config File  
`./cweb deploy path/to/yourcode.c`

You can deploy multiple modules in one go using a configuration file. By default, the script looks for a file named `routes.ini`.  

Example `routes.ini` file:  
```ini
server_url=http://localhost:8080/mgnt

[modules]
example1.c
example2.c
```

When using the .ini files you run: `./cweb deploy`

### Errors

Error messages are forwarded back to you over http.

---

# Build it yourself!

Note: MacOS support is not guarenteed!

The project depends on:

```bash
# Linux
sudo apt-get install libssl-dev
sudo apt-get install libsqlite3-dev
sudo apt-get install libjansson-dev

# MacOS
brew install openssl@3
brew install sqlite
brew install jansson
```

Run make to compile and make run to start the server.

```bash
make
make run
```

