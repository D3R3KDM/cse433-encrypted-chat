// aes_gcm_cipher.cpp
// AES-256-GCM (tag only, no HMAC) implementation
#include "symmetric_cipher.h"
#include <openssl/evp.h>
#include <cstring>

class AESGCMCipher : public SymmetricCipher {
private:
    unsigned char key[32] = {
        'A','B','C','D','E','F','G','H',
        'I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X',
        'Y','Z','0','1','2','3','4','5'
    };
    unsigned char iv[12] = { 'a','b','c','d','e','f','g','h','i','j','k','l' };

public:
    int encrypt(const unsigned char* plaintext, int len, unsigned char* ciphertext, unsigned char* tag) override {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int out_len, total_len;
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
        EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, len);
        total_len = out_len;
        EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &out_len);
        total_len += out_len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
        EVP_CIPHER_CTX_free(ctx);
        return total_len;
    }

    int decrypt(const unsigned char* ciphertext, int len, unsigned char* plaintext, const unsigned char* tag) override {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int out_len, total_len;
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
        EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, len);
        total_len = out_len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);
        int ret = EVP_DecryptFinal_ex(ctx, plaintext + out_len, &out_len);
        EVP_CIPHER_CTX_free(ctx);
        return (ret > 0) ? (total_len + out_len) : -1;
    }

    const char* getName() override { return "AES-256-GCM (tag)"; }
    Authenticator* getAuthenticator() override { return nullptr; }
};
