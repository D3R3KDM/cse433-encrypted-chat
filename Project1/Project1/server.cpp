// server.cpp
// Secure server: receives, verifies, decrypts message

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <memory>
#include "symmetric_cipher.h"
#include "rc4_cipher.cpp"
#include "rc4_40_cipher.cpp"
#include "aes_cbc_cipher.cpp"
#include "aes_gcm_cipher.cpp"
#include "chacha20_cipher.cpp"

using namespace std;

int main() {
    // Prompt
    cout << "[SERVER] Choose encryption mode:\n";
    cout << " 1) RC4 (with HMAC)\n";
    cout << " 2) RC4_40 (with HMAC)\n";
    cout << " 3) AES-256-CBC (with HMAC)\n";
    cout << " 4) AES-256-GCM (tag only)\n";
    cout << " 5) ChaCha20 (tag only)\n";
    int choice;
    cin >> choice; cin.ignore();

    unique_ptr<SymmetricCipher> cipher;
    if (choice == 1) cipher = make_unique<RC4Cipher>();
    else if (choice == 2) cipher = make_unique<RC440Cipher>();
    else if (choice == 3) cipher = make_unique<AESCBCipher>();
    else if (choice == 4) cipher = make_unique<AESGCMCipher>();
    else if (choice == 5) cipher = make_unique<ChaCha20Cipher>();
    else {
        cout << "Invalid.\n"; return 1;
    }

    cout << "[SERVER] Using: " << cipher->getName() << endl;

    // 1. Setup socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5194);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(sockfd, (sockaddr*)&addr, sizeof(addr));
    listen(sockfd, 1);
    int clientfd = accept(sockfd, nullptr, nullptr);

    // 2. Receive ciphertext
    int clen = 0;
    recv(clientfd, &clen, sizeof(int), 0);
    unsigned char ciphertext[1024] = {};
    recv(clientfd, ciphertext, clen, 0);

    // 3. Receive tag or HMAC
    unsigned char tag[16] = {}, mac[64] = {};
    unsigned int macLen = 0;
    if (cipher->getAuthenticator()) {
        recv(clientfd, &macLen, sizeof(unsigned int), 0);
        recv(clientfd, mac, macLen, 0);
    }
    else {
        recv(clientfd, tag, 16, 0);
    }

    // 4. Decrypt
    unsigned char plaintext[1024] = {};
    int plen = cipher->decrypt(ciphertext, clen, plaintext, tag);
    plaintext[plen > 0 ? plen : 0] = '\0';

    // 5. Authenticate
    string reply;
    if (plen < 0) {
        reply = "Decrypt failed (tag mismatch?)";
    }
    else if (cipher->getAuthenticator()) {
        if (cipher->getAuthenticator()->verifyHMAC(plaintext, plen, mac, macLen)) {
            reply = "Decryption + HMAC OK: " + string((char*)plaintext);
        }
        else {
            reply = "HMAC failed!";
        }
    }
    else {
        reply = "Decryption OK: " + string((char*)plaintext);
    }

    // 6. Respond
    send(clientfd, reply.c_str(), reply.size() + 1, 0);
    close(clientfd);
    close(sockfd);
    return 0;
}
