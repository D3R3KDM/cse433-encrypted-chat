// aes_cbc_cipher.cpp
// AES-256-CBC + HMAC implementation
#include "symmetric_cipher.h"
#include "hmac_authenticator.cpp"
#include <openssl/evp.h>
#include <memory>

class AESCBCipher : public SymmetricCipher {
private:
    unsigned char key[32] = {
        'A','B','C','D','E','F','G','H',
        'I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X',
        'Y','Z','0','1','2','3','4','5'
    };
    unsigned char iv[16] = {
        'a','b','c','d','e','f','g','h',
        'i','j','k','l','m','n','o','p'
    };
    std::unique_ptr<Authenticator> auth;

public:
    AESCBCipher() { auth = std::make_unique<HMACAuthenticator>(); }

    int encrypt(const unsigned char* plaintext, int len, unsigned char* ciphertext, unsigned char* tag = nullptr) override {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int out_len, total_len;
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, len);
        total_len = out_len;
        EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &out_len);
        total_len += out_len;
        EVP_CIPHER_CTX_free(ctx);
        return total_len;
    }

    int decrypt(const unsigned char* ciphertext, int len, unsigned char* plaintext, const unsigned char* tag = nullptr) override {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int out_len, total_len;
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, len);
        total_len = out_len;
        EVP_DecryptFinal_ex(ctx, plaintext + out_len, &out_len);
        total_len += out_len;
        EVP_CIPHER_CTX_free(ctx);
        return total_len;
    }

    const char* getName() override { return "AES-256-CBC + HMAC"; }
    Authenticator* getAuthenticator() override { return auth.get(); }
};
