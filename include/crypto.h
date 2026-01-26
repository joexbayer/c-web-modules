#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <stddef.h>

typedef enum crypto_status {
    CRYPTO_FAILURE,
    CRYPTO_LOADED
} crypto_status_t;

struct crypto;

/**
 * Main goal is to expose functions to allow signing and verifying tokens,
 * using the main server certificate.
 */
struct crypto_ops {
    /**
     * Sign a token using the server certificate.
     * @param crypto Crypto context
     * @param token Token to sign
     * @param signed_token Buffer to store the signed token
     * @param signed_token_len Length of the signed token buffer
     * @return 0 on success, -1 on failure
     */
    int (*sign_token)(struct crypto *crypto, const char *token, char *signed_token, unsigned int signed_token_len);

    /**
     * Verify a signed token using the server certificate.
     * @param crypto Crypto context
     * @param signed_token Signed token to verify
     * @param token Buffer to store the token
     * @param token_len Length of the token buffer
     * @return 0 on success, -1 on failure
     */
    int (*verify_token)(struct crypto *crypto, const char *signed_token, const char *token, size_t token_len);
};

struct crypto {
    SSL_CTX *ctx;
    const char *certificate;
    const char *private_key;
    crypto_status_t status;
    struct crypto_ops ops;
};

/**
 * Initialize the crypto module.
 * @return 0 on success, -1 on failure
 */
int crypto_init(struct crypto *crypto, const char *certificate, const char *private_key);
/**
 * Shutdown the crypto module.
 */
void crypto_shutdown(struct crypto *crypto);

#endif // CRYPTO_H
