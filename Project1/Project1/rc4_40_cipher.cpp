// rc4_40_cipher.cpp
// RC4_40 + HMAC implementation
#include "symmetric_cipher.h"
#include "hmac_authenticator.cpp"
#include <openssl/evp.h>
#include <memory>

class RC440Cipher : public SymmetricCipher {
private:
    unsigned char key[5] = { '1','2','3','4','5' }; // 40-bit key
    std::unique_ptr<Authenticator> auth;

public:
    RC440Cipher() { auth = std::make_unique<HMACAuthenticator>(); }

    int encrypt(const unsigned char* plaintext, int len, unsigned char* ciphertext, unsigned char* tag = nullptr) override {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int out_len;
        EVP_EncryptInit_ex(ctx, EVP_rc4_40(), NULL, key, NULL);
        EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, len);
        EVP_CIPHER_CTX_free(ctx);
        return out_len;
    }

    int decrypt(const unsigned char* ciphertext, int len, unsigned char* plaintext, const unsigned char* tag = nullptr) override {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int out_len;
        EVP_DecryptInit_ex(ctx, EVP_rc4_40(), NULL, key, NULL);
        EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, len);
        EVP_CIPHER_CTX_free(ctx);
        return out_len;
    }

    const char* getName() override { return "RC4_40 + HMAC"; }
    Authenticator* getAuthenticator() override { return auth.get(); }
};

