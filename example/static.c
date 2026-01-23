#include <stdio.h>
#include <cweb.h>

static int security_check(const char *path) {
    if (strstr(path, "..") != NULL) {
        return 0;
    }
    return 1;
}

static int read_file(const char *path, char *body, int size) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return -1;
    }
    
    int ret = fread(body, 1, size, fp);
    if (ret < 0) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return ret;
}

static void set_content_type(struct http_response *res, const char *path) {
    char *ext = strrchr(path, '.');
    if (ext) {
        if (strcmp(ext, ".html") == 0) {
            http_kv_insert(res->headers, "Content-Type", "text/html");
        } else if (strcmp(ext, ".css") == 0) {
            http_kv_insert(res->headers, "Content-Type", "text/css");
        } else if (strcmp(ext, ".js") == 0) {
            http_kv_insert(res->headers, "Content-Type", "application/javascript");
        } else {
            http_kv_insert(res->headers, "Content-Type", "text/plain");
        }
    } else {
        http_kv_insert(res->headers, "Content-Type", "text/plain");
    }
}

static int download(struct http_request *req, struct http_response *res) {
    int ret;

    /* Copy path */
    char path[256] = {0};
    snprintf(path, sizeof(path), "%s", req->path+1);

    /* Security check on path */
    if (!security_check(path)) {
        res->status = HTTP_403_FORBIDDEN;
        return 0;
    }

    /* Read file */
    ret = read_file(path, res->body, HTTP_RESPONSE_SIZE);
    if (ret < 0) {
        printf("File not found\n");
        res->status = HTTP_404_NOT_FOUND;
        return 0;
    }

    /* Set content options */
    res->content_length = ret;
    set_content_type(res, req->path);

    res->status = HTTP_200_OK;
    return 0;
}
    
/* Define the routes for the module */
export module_t config = {
    .name = "static",
    .author = "cweb",
    .routes = {
        /* Allows regex in route paths */
        {"/static/.*", "GET", download, NONE},
    },
    .size = 1,
};
