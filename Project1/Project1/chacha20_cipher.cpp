// chacha20_cipher.cpp
// ChaCha20 (no HMAC, no tag) - for completeness
#include "symmetric_cipher.h"
#include <openssl/evp.h>

class ChaCha20Cipher : public SymmetricCipher {
private:
    unsigned char key[32] = {
        'A','B','C','D','E','F','G','H',
        'I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X',
        'Y','Z','0','1','2','3','4','5'
    };
    unsigned char nonce[12] = { 'n','o','n','c','e','x','x','x','x','x','x','x' };

public:
    int encrypt(const unsigned char* plaintext, int len, unsigned char* ciphertext, unsigned char* tag = nullptr) override {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int out_len;
        EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce);
        EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, len);
        EVP_CIPHER_CTX_free(ctx);
        return out_len;
    }

    int decrypt(const unsigned char* ciphertext, int len, unsigned char* plaintext, const unsigned char* tag = nullptr) override {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int out_len;
        EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce);
        EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, len);
        EVP_CIPHER_CTX_free(ctx);
        return out_len;
    }

    const char* getName() override { return "ChaCha20"; }
    Authenticator* getAuthenticator() override { return nullptr; }
};
