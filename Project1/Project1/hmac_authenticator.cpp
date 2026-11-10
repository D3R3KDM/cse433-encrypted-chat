// hmac_authenticator.cpp
// Implements HMAC-SHA256
#include "authenticator.h"
#include <openssl/hmac.h>
#include <cstring>

class HMACAuthenticator : public Authenticator {
private:
    const unsigned char* key = (const unsigned char*)"hmackey";
    int keyLen = strlen((const char*)key);

public:
    void computeHMAC(const unsigned char* message, int msgLen,
        unsigned char* mac, unsigned int& macLen) override {
        HMAC_CTX* ctx = HMAC_CTX_new();
        HMAC_Init_ex(ctx, key, keyLen, EVP_sha256(), NULL);
        HMAC_Update(ctx, message, msgLen);
        HMAC_Final(ctx, mac, &macLen);
        HMAC_CTX_free(ctx);
    }

    bool verifyHMAC(const unsigned char* message, int msgLen,
        const unsigned char* receivedMac, int receivedLen) override {
        unsigned char calcMac[64];
        unsigned int macLen;
        computeHMAC(message, msgLen, calcMac, macLen);
        return (macLen == receivedLen) && memcmp(calcMac, receivedMac, macLen) == 0;
    }
};
