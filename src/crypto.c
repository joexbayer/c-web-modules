#include <crypto.h>
#include <stdio.h>

static struct crypto_config {
    const char* certificate;
    const char* private_key;
} config = {
    .certificate = "server.crt",
    .private_key = "server.key"
};

__attribute__((used)) SSL_CTX *ssl_ctx; // Global SSL context

static int sign_token(const char *token, char *signed_token, unsigned int signed_token_len);
static int verify_token(const char *signed_token, char *token, size_t token_len);

static struct crypto_ops crypto_ops = {
    .sign_token = sign_token,
    .verify_token = verify_token
};

static struct crypto crypto = {
    .status = CRYPTO_FAILURE,
    .ops = &crypto_ops,
    .ctx = NULL
};
struct crypto* crypto_module = &crypto;

static char* base64_encode(const unsigned char *input, int length) {
    BIO *bmem, *b64;
    BUF_MEM *bptr;
    char *buff;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = '\0';

    BIO_free_all(b64);
    return buff;
}

static unsigned char* base64_decode(const char *input, int *length) {
    BIO *b64, *bmem;
    unsigned char *buffer = (unsigned char *)malloc(strlen(input));
    memset(buffer, 0, strlen(input));

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(input, -1);
    bmem = BIO_push(b64, bmem);

    *length = BIO_read(bmem, buffer, strlen(input));
    BIO_free_all(bmem);

    return buffer;
}

static int sign_token(const char *token, char *signed_token, unsigned int signed_token_len) {
    if (crypto.status != CRYPTO_LOADED) {
        fprintf(stderr, "[ERROR] Crypto module is not loaded\n");
        return -1;
    }

    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    FILE *key_file = NULL;
    unsigned char *signature = NULL;
    unsigned int actual_signed_len = 0;

    key_file = fopen(config.private_key, "r");
    if (!key_file) {
        perror("[ERROR] Unable to open private key file");
        return -1;
    }

    pkey = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);
    if (!pkey) {
        fprintf(stderr, "[ERROR] Failed to read private key\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "[ERROR] Failed to create EVP_MD_CTX\n");
        EVP_PKEY_free(pkey);
        return -1;
    }

    signature = (unsigned char *)malloc(EVP_PKEY_size(pkey));
    if (!signature) {
        fprintf(stderr, "[ERROR] Failed to allocate signature buffer\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (EVP_SignInit(mdctx, EVP_sha256()) != 1 ||
        EVP_SignUpdate(mdctx, token, strlen(token)) != 1 ||
        EVP_SignFinal(mdctx, signature, &actual_signed_len, pkey) != 1) {
        fprintf(stderr, "[ERROR] Failed to sign token\n");
        ERR_print_errors_fp(stderr);
        free(signature);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    char *encoded_signature = base64_encode(signature, actual_signed_len);
    if (strlen(encoded_signature) >= signed_token_len) {
        fprintf(stderr, "[ERROR] Signed token buffer too small\n");
        free(encoded_signature);
        free(signature);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    strncpy(signed_token, encoded_signature, signed_token_len);
    free(encoded_signature);
    free(signature);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    return strlen(signed_token); // Return the length of the Base64 encoded signature
}

static int verify_token(const char *signed_token, char *token, size_t token_len) {
    if (crypto.status != CRYPTO_LOADED) {
        fprintf(stderr, "[ERROR] Crypto module is not loaded\n");
        return -1;
    }

    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    FILE *cert_file = NULL;
    int verify_result = 0;
    unsigned char *decoded_signature = NULL;
    int decoded_len = 0;

    cert_file = fopen(config.certificate, "r");
    if (!cert_file) {
        perror("[ERROR] Unable to open certificate file");
        return -1;
    }

    X509 *cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    if (!cert) {
        fprintf(stderr, "[ERROR] Failed to read certificate\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    pkey = X509_get_pubkey(cert);
    X509_free(cert);
    if (!pkey) {
        fprintf(stderr, "[ERROR] Failed to extract public key from certificate\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "[ERROR] Failed to create EVP_MD_CTX\n");
        EVP_PKEY_free(pkey);
        return -1;
    }

    decoded_signature = base64_decode(signed_token, &decoded_len);
    if (!decoded_signature) {
        fprintf(stderr, "[ERROR] Failed to decode signed token\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (EVP_VerifyInit(mdctx, EVP_sha256()) != 1 ||
        EVP_VerifyUpdate(mdctx, token, token_len) != 1) {
        fprintf(stderr, "[ERROR] Failed to initialize verification\n");
        ERR_print_errors_fp(stderr);
        free(decoded_signature);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    verify_result = EVP_VerifyFinal(mdctx, decoded_signature, decoded_len, pkey);

    free(decoded_signature);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    if (verify_result != 1) {
        fprintf(stderr, "[ERROR] Token verification failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    return 0; // Verification succeeded
}

static SSL_CTX* initialize_ssl_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("[ERROR] Failed to initialize SSL context");
        ERR_print_errors_fp(stderr);

#ifdef PRODUCTION
        exit(EXIT_FAILURE);
#else
        return NULL;
#endif
    }

    if (SSL_CTX_use_certificate_file(ctx, config.certificate, SSL_FILETYPE_PEM) <= 0) {
        perror("[ERROR] Failed to load server certificate");
        ERR_print_errors_fp(stderr);
#ifdef PRODUCTION
        exit(EXIT_FAILURE);
#else
        return NULL;
#endif 
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, config.private_key , SSL_FILETYPE_PEM) <= 0) {
        perror("[ERROR] Failed to load server private key");
        ERR_print_errors_fp(stderr);
#ifdef PRODUCTION
        exit(EXIT_FAILURE);
#else
        return NULL;
#endif 
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "[ERROR] Private key does not match the certificate\n");
#ifdef PRODUCTION
        exit(EXIT_FAILURE);
#else
        return NULL;
#endif 
    }

    return ctx;
}

__attribute__((constructor)) int crypto_init() {
    if (OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, NULL) == 0) {
        fprintf(stderr, "[ERROR] Failed to initialize OpenSSL\n");
        return -1;
    }

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ssl_ctx = initialize_ssl_context();
    if (!ssl_ctx) {
        return -1;
    }
    crypto.status = CRYPTO_LOADED;

    char* test_token = "test_token";
    char signed_token[512];
    unsigned int signed_token_len = sizeof(signed_token);

    int sign_result = sign_token(test_token, signed_token, signed_token_len);
    if (sign_result <= 0) {
        fprintf(stderr, "[ERROR] Test signing failed\n");
        return -1;
    }

    printf("[DEBUG] Signed token: %s\n", signed_token);

    int verify_result = verify_token(signed_token, test_token, strlen(test_token));
    if (verify_result < 0) {
        fprintf(stderr, "[ERROR] Test verification failed\n");
        return -1;
    }

    printf("[CRYPTO] Crypto module loaded\n");
    return 0;
}

__attribute__((destructor)) void crypto_cleanup() {
    SSL_CTX_free(ssl_ctx);
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    EVP_cleanup();
    printf("[CRYPTO] Crypto module unloaded\n");
}