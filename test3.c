
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <ctype.h>
#include <fcntl.h>

#include <signal.h>

#define PORT 8080
#define RESPONSE_SIZE 1024
#define ROUTE_SIZE 100
#define CODE_SIZE 8000

// Helper function to trim trailing whitespace
void trim_trailing_whitespace(char *str) {
    int len = strlen(str);
    while (len > 0 && (str[len - 1] == '\r' || str[len - 1] == '\n' || isspace((unsigned char)str[len - 1]))) {
        str[--len] = '\0';
    }
}

// Structure to hold route information
typedef struct {
    char route[ROUTE_SIZE];
    char so_path[256];
    void *handle;
    void (*handler)(char *response);
} RouteEntry;

RouteEntry routes[10];
int route_count = 0;

int parse_multipart_form_data(const char *body, const char *boundary, char *route, char *function_name, char *code) {
    char *part_start = strstr(body, boundary);
    if (!part_start) return -1;

    while (part_start) {
        part_start += strlen(boundary);
        if (strncmp(part_start, "--", 2) == 0) break;

        char *content_disposition = strstr(part_start, "Content-Disposition: form-data; name=\"");
        if (!content_disposition) break;

        content_disposition += strlen("Content-Disposition: form-data; name=\"");
        char field_name[50];
        sscanf(content_disposition, "%49[^\"]", field_name);

        char *value_start = strstr(content_disposition, "\r\n\r\n");
        if (!value_start) break;
        value_start += 4;

        char *value_end = strstr(value_start, boundary);
        if (!value_end) break;
        value_end -= 2;

        if (strcmp(field_name, "route") == 0) {
            strncpy(route, value_start, value_end - value_start);
            route[value_end - value_start] = '\0';
            trim_trailing_whitespace(route);  // Remove trailing whitespace
        } else if (strcmp(field_name, "function_name") == 0) {
            strncpy(function_name, value_start, value_end - value_start);
            function_name[value_end - value_start] = '\0';
            trim_trailing_whitespace(function_name);  // Remove trailing whitespace
        } else if (strcmp(field_name, "code") == 0) {
            strncpy(code, value_start, value_end - value_start);
            code[value_end - value_start] = '\0';
            trim_trailing_whitespace(code);  // Remove trailing whitespace
        }

        part_start = strstr(value_end, boundary);
    }

    return 0;
}

// Function to parse form-urlencoded data or plain text requests
int parse_form_data(const char *body, char *route, char *function_name, char *code) {
    sscanf(body, "route=%99[^&]&function_name=%99[^&]&code=%7999[^\n]", route, function_name, code);
    trim_trailing_whitespace(route);
    trim_trailing_whitespace(function_name);
    trim_trailing_whitespace(code);
    return 0;
}

// Function to compile the code
int write_and_compile(const char *filename, const char *code, const char *func_name) {
    char source_path[256], so_path[256];
    snprintf(source_path, sizeof(source_path), "%s.c", filename);
    snprintf(so_path, sizeof(so_path), "%s.so", filename);

    FILE *fp = fopen(source_path, "w");
    if (fp == NULL) {
        perror("Error creating C file");
        return -1;
    }
    fprintf(fp, "%s", code);
    fclose(fp);

    char command[512];
    snprintf(command, sizeof(command), "gcc -fPIC -shared -o %s %s", so_path, source_path);
    if (system(command) != 0) {
        fprintf(stderr, "Compilation failed for %s\n", source_path);
        unlink(source_path);
        return -1;
    }
    unlink(source_path);
    return 0;
}

#include <time.h>

int register_route(const char *route, const char *code, const char *func_name) {
    char filename[256];
    snprintf(filename, sizeof(filename), "%s_%ld", func_name, time(NULL));  // Unique name with timestamp

    if (write_and_compile(filename, code, func_name) != 0) {
        fprintf(stderr, "Failed to register route '%s' due to compilation error.\n", route);
        return -1;
    }

    char so_path[256];
    snprintf(so_path, sizeof(so_path), "./%s.so", filename);

    void *handle = dlopen(so_path, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "Error loading shared object: %s\n", dlerror());
        return -1;
    }

    void (*handler)(char *response) = (void (*)(char *))dlsym(handle, func_name);
    if (!handler) {
        fprintf(stderr, "Error finding function '%s': %s\n", func_name, dlerror());
        dlclose(handle);
        return -1;
    }

    for (int i = 0; i < route_count; i++) {
        if (strcmp(routes[i].route, route) == 0) {
            // Cleanup previous handler and shared object
            dlclose(routes[i].handle);
            unlink(routes[i].so_path);

            // Overwrite existing route with new handler
            strncpy(routes[i].so_path, so_path, sizeof(so_path));
            routes[i].handle = handle;
            routes[i].handler = handler;
            printf("Route '%s' overwritten successfully.\n", route);
            return 0;
        }
    }

    // Register new route if it doesn't exist
    strncpy(routes[route_count].route, route, ROUTE_SIZE);
    strncpy(routes[route_count].so_path, so_path, sizeof(so_path));
    routes[route_count].handle = handle;
    routes[route_count].handler = handler;
    route_count++;

    printf("Route '%s' registered successfully.\n", route);
    return 0;
}

void safe_execute_handler(void (*handler)(char *), char *response) {
    int pipe_fd[2];
    if (pipe(pipe_fd) == -1) {
        perror("Pipe failed");
        snprintf(response, RESPONSE_SIZE, "Internal error: Pipe creation failed.\n");
        return;
    }

    pid_t pid = fork();
    if (pid == -1) {
        perror("Fork failed");
        snprintf(response, RESPONSE_SIZE, "Internal error: Fork failed.\n");
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return;
    } else if (pid == 0) {
        // Child process
        close(pipe_fd[0]); // Close read end of the pipe
        handler(response);
        write(pipe_fd[1], response, strlen(response) + 1);
        close(pipe_fd[1]);
        exit(0); // Exit normally if handler completes successfully
    } else {
        // Parent process
        close(pipe_fd[1]); // Close write end of the pipe

        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            // Child exited normally
            read(pipe_fd[0], response, RESPONSE_SIZE);
        } else if (WIFSIGNALED(status)) {
            // Child process was terminated by a signal
            int signal = WTERMSIG(status);
            snprintf(response, RESPONSE_SIZE, "Handler execution failed: Terminated by signal %d (%s)\n", signal, strsignal(signal));
        } else {
            snprintf(response, RESPONSE_SIZE, "Handler execution failed: Unknown error.\n");
        }

        close(pipe_fd[0]);
    }
}

void handle_request(int client_sock, const char *method, const char *route, const char *body, const char *boundary) {
    char response[RESPONSE_SIZE] = "HTTP/1.1 200 OK\nContent-Type: text/plain\n\n";

    if (strcmp(method, "POST") == 0 && strcmp(route, "/register") == 0) {
        char parsed_route[ROUTE_SIZE] = {0}, function_name[100] = {0}, code[CODE_SIZE] = {0};
        if (boundary) {
            // Parse multipart form data if boundary is specified
            if (parse_multipart_form_data(body, boundary, parsed_route, function_name, code) == 0) {
                if (register_route(parsed_route, code, function_name) == 0) {
                    strcat(response, "Route registered successfully\n");
                } else {
                    strcat(response, "Failed to register route\n");
                }
            } else {
                strcat(response, "Failed to parse form data\n");
            }
        // } else {
        //     // Parse as application/x-www-form-urlencoded or text/plain
        //     if (parse_form_data(body, parsed_route, function_name, code) == 0) {
        //         if (register_route(parsed_route, code, function_name) == 0) {
        //             strcat(response, "Route registered successfully\n");
        //         } else {
        //             strcat(response, "Failed to register route\n");
        //         }
        //     } else {
        //         strcat(response, "Failed to parse form data\n");
        //     }
        // }
        } else {
            strcat(response, "Invalid request\n");
        }
    } else if (strcmp(method, "GET") == 0) {
        int found = 0;
        for (int i = 0; i < route_count; i++) {
            if (strcmp(routes[i].route, route) == 0) {
                found = 1;
                safe_execute_handler(routes[i].handler, response + strlen(response));
                break;
            }
        }
        if (!found) strcat(response, "404 Not Found\n");
    }

    send(client_sock, response, strlen(response), 0);
    close(client_sock);
}

void start_server() {
    int server_fd, client_sock;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[30000] = {0};

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("Server is listening on port %d\n", PORT);

    while ((client_sock = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) >= 0) {
        int read_size = read(client_sock, buffer, sizeof(buffer) - 1);
        if (read_size <= 0) {
            close(client_sock);
            continue;
        }
        buffer[read_size] = '\0';

        //printf("Request: %s\n", buffer);

        // Extract method and route
        char method[10] = {0}, route[100] = {0};
        sscanf(buffer, "%s %s", method, route);

        // Parse Content-Length
        int content_length = 0;
        char *content_length_str = strstr(buffer, "Content-Length: ");
        if (content_length_str) {
            sscanf(content_length_str, "Content-Length: %d", &content_length);
        }

        // Parse Content-Type and boundary
        char boundary[100] = {0};
        char *content_type = strstr(buffer, "Content-Type: ");
        if (content_type && strstr(content_type, "multipart/form-data")) {
            sscanf(content_type, "Content-Type: multipart/form-data; boundary=%99s", boundary);
        }

        // Parse body
        char *body_ptr = strstr(buffer, "\r\n\r\n");
        if (body_ptr) {
            body_ptr += 4;
        } else {
            close(client_sock);
            continue;
        }

        // Handle additional body data if Content-Length is larger
        int body_read_size = read_size - (body_ptr - buffer);
        int remaining_body = content_length - body_read_size;
        while (remaining_body > 0) {
            int additional_read_size = read(client_sock, body_ptr + body_read_size, remaining_body);
            if (additional_read_size <= 0) break;
            body_read_size += additional_read_size;
            remaining_body -= additional_read_size;
        }

        handle_request(client_sock, method, route, body_ptr, boundary[0] ? boundary : NULL);

        printf("handles request for %s\n", route);
    }
}

int main() {
    const char *hello_code = "#include <stdio.h>\nvoid hello(char *response) { sprintf(response, \"Hello from dynamically loaded function!\\n\"); }\n";
    register_route("/hello", hello_code, "hello");

    const char *goodbye_code = "#include <stdio.h>\nvoid goodbye(char *response) { sprintf(response, \"Goodbye from dynamically loaded function!\\n\"); }\n";
    register_route("/goodbye", goodbye_code, "goodbye");

    start_server();

    return 0;
}
