
#include "crypto.h"

#ifdef ENABLE_PACKET_ENCRYPTION

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include <cstring>

// Globals to hold the keys
static EVP_PKEY* g_local_key = NULL;
static EVP_PKEY* g_peer_key = NULL;

SystemStatus crypto_initialize(void) {
    // OPENSSL_init_crypto(0, NULL) is generally preferred for newer OpenSSL versions
    // but for broader compatibility, we can call specific initializers.
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    return STATUS_SUCCESS;
}

static SystemStatus pem_to_key(const char* pem, size_t pem_len, EVP_PKEY** key, bool is_private) {
    if (!pem || pem_len == 0) {
        return STATUS_ERROR_INVALID_PARAM;
    }

    BIO* bio = BIO_new_mem_buf(pem, pem_len);
    if (!bio) {
        return STATUS_ERROR_HARDWARE; // Represents an allocation failure
    }

    EVP_PKEY* new_key = NULL;
    if (is_private) {
        new_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    } else {
        new_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    }

    BIO_free(bio);

    if (!new_key) {
        return STATUS_ERROR_INVALID_PARAM;
    }

    if (*key) {
        EVP_PKEY_free(*key);
    }
    *key = new_key;

    return STATUS_SUCCESS;
}

SystemStatus crypto_set_local_private_key_pem(const char* pem, size_t pem_len) {
    return pem_to_key(pem, pem_len, &g_local_key, true);
}

SystemStatus crypto_set_peer_public_key_pem(const char* pem, size_t pem_len) {
    return pem_to_key(pem, pem_len, &g_peer_key, false);
}

SystemStatus crypto_encrypt_packet(const TelemetryPacket* pkt, uint8_t* out_buf, uint16_t* out_len) {
    if (!pkt || !out_buf || !out_len) return STATUS_ERROR_INVALID_PARAM;
    if (!g_local_key || !g_peer_key) return STATUS_ERROR_INVALID_PARAM;

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(g_local_key, NULL);
    if (!pctx) return STATUS_ERROR_HARDWARE;

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return STATUS_ERROR_HARDWARE;
    }

    if (EVP_PKEY_derive_set_peer(pctx, g_peer_key) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return STATUS_ERROR_HARDWARE;
    }

    size_t secret_len;
    if (EVP_PKEY_derive(pctx, NULL, &secret_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return STATUS_ERROR_HARDWARE;
    }

    unsigned char* secret = (unsigned char*)OPENSSL_malloc(secret_len);
    if (!secret) {
        EVP_PKEY_CTX_free(pctx);
        return STATUS_ERROR_HARDWARE;
    }

    if (EVP_PKEY_derive(pctx, secret, &secret_len) <= 0) {
        OPENSSL_free(secret);
        EVP_PKEY_CTX_free(pctx);
        return STATUS_ERROR_HARDWARE;
    }
    EVP_PKEY_CTX_free(pctx);

    // KDF: SHA-256 hash of the shared secret to get a 32-byte key
    unsigned char aes_key[SHA256_DIGEST_LENGTH];
    SHA256(secret, secret_len, aes_key);
    OPENSSL_free(secret);

    // Encrypt with AES-256-GCM
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return STATUS_ERROR_HARDWARE;

    // 12-byte IV
    uint8_t iv[12];
    if (RAND_bytes(iv, sizeof(iv)) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return STATUS_ERROR_HARDWARE;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return STATUS_ERROR_HARDWARE;
    }

    int len;
    int ciphertext_len;
    uint8_t* plaintext = (uint8_t*)pkt;
    size_t plaintext_len = sizeof(TelemetryPacket);

    if (EVP_EncryptUpdate(ctx, out_buf + 12, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return STATUS_ERROR_HARDWARE;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, out_buf + 12 + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return STATUS_ERROR_HARDWARE;
    }
    ciphertext_len += len;

    // 16-byte tag
    uint8_t tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return STATUS_ERROR_HARDWARE;
    }

    EVP_CIPHER_CTX_free(ctx);

    // Wire format: IV(12) || ciphertext || TAG(16)
    memcpy(out_buf, iv, 12);
    memcpy(out_buf + 12 + ciphertext_len, tag, 16);
    *out_len = 12 + ciphertext_len + 16;

    return STATUS_SUCCESS;
}

SystemStatus crypto_decrypt_packet(const uint8_t* in_buf, uint16_t in_len, TelemetryPacket* out_pkt) {
    if (!in_buf || !out_pkt || in_len <= 28) return STATUS_ERROR_INVALID_PARAM;
    if (!g_local_key || !g_peer_key) return STATUS_ERROR_INVALID_PARAM;

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(g_local_key, NULL);
    if (!pctx) return STATUS_ERROR_HARDWARE;

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return STATUS_ERROR_HARDWARE;
    }

    if (EVP_PKEY_derive_set_peer(pctx, g_peer_key) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return STATUS_ERROR_HARDWARE;
    }

    size_t secret_len;
    if (EVP_PKEY_derive(pctx, NULL, &secret_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return STATUS_ERROR_HARDWARE;
    }

    unsigned char* secret = (unsigned char*)OPENSSL_malloc(secret_len);
    if (!secret) {
        EVP_PKEY_CTX_free(pctx);
        return STATUS_ERROR_HARDWARE;
    }

    if (EVP_PKEY_derive(pctx, secret, &secret_len) <= 0) {
        OPENSSL_free(secret);
        EVP_PKEY_CTX_free(pctx);
        return STATUS_ERROR_HARDWARE;
    }
    EVP_PKEY_CTX_free(pctx);

    unsigned char aes_key[SHA256_DIGEST_LENGTH];
    SHA256(secret, secret_len, aes_key);
    OPENSSL_free(secret);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return STATUS_ERROR_HARDWARE;

    const uint8_t* iv = in_buf;
    const uint8_t* ciphertext = in_buf + 12;
    const uint8_t* tag = in_buf + in_len - 16;
    uint16_t ciphertext_len = in_len - 12 - 16;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return STATUS_ERROR_HARDWARE;
    }

    int len;
    int plaintext_len;
    uint8_t* plaintext = (uint8_t*)out_pkt;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return STATUS_ERROR_CRC_FAIL; // Decryption failed (tag mismatch)
    }
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return STATUS_ERROR_CRC_FAIL;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return STATUS_ERROR_CRC_FAIL;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    if (plaintext_len != sizeof(TelemetryPacket)) {
        return STATUS_ERROR_INVALID_PARAM;
    }

    return STATUS_SUCCESS;
}

#endif // ENABLE_PACKET_ENCRYPTION
