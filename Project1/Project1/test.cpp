#include <openssl/evp.h>
#include <iostream>

int main() {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx) {
        std::cout << "OpenSSL context created successfully!\n";
        EVP_CIPHER_CTX_free(ctx);
    }
    else {
        std::cout << "Failed to create OpenSSL context.\n";
    }
    return 0;
}
