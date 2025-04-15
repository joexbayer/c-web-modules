#include <cweb.h>
#include <map.h>
#include <stdio.h>
#include <stdlib.h>
#include <crypto.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>

static const char* username = "admin";
static const char* password = "admin";
static const char* secret_key = "super_secret_key";
static char* hashed_password = NULL;

static char* hash_password(const char* password) {
    unsigned char* hash = (unsigned char*)malloc(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password, strlen(password));
    SHA256_Final(hash, &sha256);

    hashed_password = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hashed_password + (i * 2), "%02x", hash[i]);
    }
    hashed_password[SHA256_DIGEST_LENGTH * 2] = '\0';

    free(hash);
    return hashed_password;
}

static char* create_signed_cookie(const char* username) {
    unsigned char* hmac_result;
    unsigned int hmac_len;

    /* Create HMAC using the secret key */
    hmac_result = HMAC(EVP_sha256(), secret_key, strlen(secret_key), 
                       (unsigned char*)username, strlen(username), 
                       NULL, &hmac_len);

    char* cookie = malloc(strlen(username) + hmac_len * 2 + 2);
    sprintf(cookie, "%s|", username); /* Add username to the cookie */

    /* Append the HMAC signature */
    for (unsigned int i = 0; i < hmac_len; i++) {
        sprintf(cookie + strlen(username) + 1 + i * 2, "%02x", hmac_result[i]);
    }

    return cookie;
}

static int verify_signed_cookie(const char* cookie) {
    char* separator = strchr(cookie, '|');
    if (!separator) {
        return 0; /* Invalid cookie format */
    }

    size_t username_len = separator - cookie;
    char* username = strndup(cookie, username_len);
    char* received_hmac = separator + 1;

    /* Recreate the HMAC for the username */
    unsigned char* hmac_result;
    unsigned int hmac_len;
    hmac_result = HMAC(EVP_sha256(), secret_key, strlen(secret_key), 
                       (unsigned char*)username, username_len, 
                       NULL, &hmac_len);

    /* Convert HMAC to hex string */
    char expected_hmac[hmac_len * 2 + 1];
    for (unsigned int i = 0; i < hmac_len; i++) {
        sprintf(expected_hmac + i * 2, "%02x", hmac_result[i]);
    }

    free(username);

    /* Compare the received HMAC with the expected HMAC */
    return strcmp(received_hmac, expected_hmac) == 0;
}

static int login_page(struct http_request *req, struct http_response *res) {
    const char* redirect_url = map_get(req->params, "redirect");
    if (!redirect_url) {
        redirect_url = "/";
    }

    char login_page[HTTP_RESPONSE_SIZE];
    snprintf(login_page, sizeof(login_page),
        "<html>\n"
        "  <body>\n"
        "    <form action=\"/auth\" method=\"POST\" enctype=\"multipart/form-data\">\n"
        "      <input type=\"hidden\" name=\"redirect\" value=\"%s\">\n"
        "      <label for=\"username\">Username:</label><br>\n"
        "      <input type=\"text\" id=\"username\" name=\"username\"><br>\n"
        "      <label for=\"password\">Password:</label><br>\n"
        "      <input type=\"password\" id=\"password\" name=\"password\"><br><br>\n"
        "      <input type=\"submit\" value=\"Submit\">\n"
        "    </form>\n"
        "  </body>\n"
        "</html>\n",
        redirect_url);

    snprintf(res->body, HTTP_RESPONSE_SIZE, "%s", login_page);
    res->status = HTTP_200_OK;
    return 0;
}

static int secret(struct http_request *req, struct http_response *res) {
    if (req->data == NULL) {
        res->status = HTTP_400_BAD_REQUEST;
        return 0;
    }

    char* cookie = map_get(req->headers, "Cookie");
    if (cookie != NULL) {
        char* cweb_auth_cookie = strstr(cookie, "cweb_auth=");
        if (cweb_auth_cookie != NULL) {
            cweb_auth_cookie += strlen("cweb_auth=");
            cookie = cweb_auth_cookie;
        } else {
            cookie = NULL;
        }
    }
    if (cookie == NULL || !verify_signed_cookie(cookie)) {
        res->status = HTTP_302_FOUND;
        char location[HTTP_RESPONSE_SIZE];
        snprintf(location, sizeof(location), "/login?redirect=/secret");
        map_insert(res->headers, "Location", location);
        return 0;
    }

    char* secret_page = 
        "<html>\n"
        "  <body>\n"
        "    <h1>Secret Page</h1>\n"
        "    <p>Welcome to the secret page!</p>\n"
        "  </body>\n"
        "</html>\n";

    snprintf(res->body, HTTP_RESPONSE_SIZE, "%s", secret_page);
    res->status = HTTP_200_OK;
    return 0;
}

static int authenticate(struct http_request *req, struct http_response *res) {
    if (req->data == NULL) {
        res->status = HTTP_400_BAD_REQUEST;
        return 0;
    }

    char* user = map_get(req->data, "username");
    char* pass = map_get(req->data, "password");
    char* redirect_url = map_get(req->data, "redirect");
    if (!redirect_url) {
        redirect_url = "/";
    }

    if (user == NULL || pass == NULL) {
        res->status = HTTP_400_BAD_REQUEST;
        return 0;
    }

    char* hashed = hash_password(pass);
    if (strcmp(user, username) != 0 || strcmp(hashed, hashed_password) != 0) {
        res->status = HTTP_401_UNAUTHORIZED;
        return 0;
    }

    const char* cookie_name = "cweb_auth=";

    /* Create a signed cookie */
    char* cookie = create_signed_cookie(user);
    char* cookie_with_name = malloc(strlen(cookie_name) + strlen(cookie) + 1);
    sprintf(cookie_with_name, "%s%s", cookie_name, cookie);
    map_insert(res->headers, "Set-Cookie", cookie_with_name);
    free(cookie_with_name);
    free(cookie);

    res->status = HTTP_302_FOUND;
    map_insert(res->headers, "Location", redirect_url);

    return 1;
}

static void onload() {
    hashed_password = hash_password(password);
}

/* Define the routes for the module */
export module_t config = {
    .name = "auth",
    .author = "cweb",
    .routes = {
        {"/login", "GET", login_page, NONE},
        {"/auth", "POST", authenticate, NONE},
        {"/secret", "GET", secret, NONE},
    },
    .size = 3,
};