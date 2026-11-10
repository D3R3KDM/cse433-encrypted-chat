// rc4_cipher.cpp
// RC4 + HMAC encryption
#include "symmetric_cipher.h"
#include "hmac_authenticator.cpp"
#include <openssl/evp.h>
#include <memory>

class RC4Cipher : public SymmetricCipher {
private:
    unsigned char key[16] = { '1','2','3','4','5','6','7','8','9','0','a','b','c','d','e','f' };
    std::unique_ptr<Authenticator> auth;

public:
    RC4Cipher() { auth = std::make_unique<HMACAuthenticator>(); }

    int encrypt(const unsigned char* plaintext, int len, unsigned char* ciphertext, unsigned char* tag = nullptr) override {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int out_len;
        EVP_EncryptInit_ex(ctx, EVP_rc4(), NULL, key, NULL);
        EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, len);
        EVP_CIPHER_CTX_free(ctx);
        return out_len;
    }

    int decrypt(const unsigned char* ciphertext, int len, unsigned char* plaintext, const unsigned char* tag = nullptr) override {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int out_len;
        EVP_DecryptInit_ex(ctx, EVP_rc4(), NULL, key, NULL);
        EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, len);
        EVP_CIPHER_CTX_free(ctx);
        return out_len;
    }

    const char* getName() override { return "RC4 + HMAC"; }
    Authenticator* getAuthenticator() override { return auth.get(); }
};
