// client.cpp
// Secure client: sends encrypted and authenticated message

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
    cout << "[CLIENT] Choose encryption mode:\n";
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

    cout << "[CLIENT] You selected: " << cipher->getName() << endl;

    // 1. Connect to server
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(5194);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
    connect(sock, (sockaddr*)&serv_addr, sizeof(serv_addr));

    // 2. Get user input
    char msg[512];
    cout << "Enter your message: ";
    cin.getline(msg, sizeof(msg));
    int msg_len = strlen(msg);

    // 3. Encrypt
    unsigned char ciphertext[1024], tag[16] = {};
    int cipher_len = cipher->encrypt((unsigned char*)msg, msg_len, ciphertext, tag);

    // 4. Send ciphertext
    send(sock, &cipher_len, sizeof(int), 0);
    send(sock, ciphertext, cipher_len, 0);

    // 5. Send tag or HMAC
    if (cipher->getAuthenticator()) {
        unsigned char mac[64];
        unsigned int macLen = 0;
        cipher->getAuthenticator()->computeHMAC((unsigned char*)msg, msg_len, mac, macLen);
        send(sock, &macLen, sizeof(unsigned int), 0);
        send(sock, mac, macLen, 0);
    }
    else {
        send(sock, tag, 16, 0);
    }

    // 6. Receive server response
    char response[1024];
    recv(sock, response, sizeof(response), 0);
    cout << "[CLIENT] Server says: " << response << endl;

    close(sock);
    return 0;
}
