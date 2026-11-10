// symmetric_cipher.h
// Base class for symmetric ciphers
#pragma once

class Authenticator;

class SymmetricCipher {
public:
    virtual int encrypt(const unsigned char* plaintext, int plaintext_len,
        unsigned char* ciphertext, unsigned char* tag = nullptr) = 0;

    virtual int decrypt(const unsigned char* ciphertext, int ciphertext_len,
        unsigned char* plaintext, const unsigned char* tag = nullptr) = 0;

    virtual const char* getName() = 0;
    virtual Authenticator* getAuthenticator() = 0;
    virtual ~SymmetricCipher() {}
};

