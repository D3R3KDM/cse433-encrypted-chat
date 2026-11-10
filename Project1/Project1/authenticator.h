// authenticator.h
// Abstract base class for authentication modules
#pragma once

class Authenticator {
public:
    virtual void computeHMAC(const unsigned char* message, int msgLen,
        unsigned char* mac, unsigned int& macLen) = 0;

    virtual bool verifyHMAC(const unsigned char* message, int msgLen,
        const unsigned char* receivedMac, int receivedLen) = 0;

    virtual ~Authenticator() {}
};
