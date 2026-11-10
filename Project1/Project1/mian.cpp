// main.cpp
// Terminal chat app main control flow
#include <iostream>
#include <memory>
#include "symmetric_cipher.h"
#include "rc4_cipher.cpp"
#include "rc4_40_cipher.cpp"
#include "aes_cbc_cipher.cpp"
#include "aes_gcm_cipher.cpp"
#include "chacha20_cipher.cpp"

using namespace std;

// Prompt user for encryption mode
int prompt_user() {
    cout << "Choose encryption mode:\n";
    cout << " 1) RC4          (with HMAC)\n";
    cout << " 2) RC4_40       (with HMAC)\n";
    cout << " 3) AES-256-CBC  (with HMAC)\n";
    cout << " 4) AES-256-GCM  (tag only)\n";
    cout << " 5) ChaCha20     (tag only)\n";
    cout << "Your choice: ";
    int choice;
    cin >> choice;
    cin.ignore();
    return choice;
}

int main() {
    int mode = prompt_user();
    unique_ptr<SymmetricCipher> cipher;

    if (mode == 1) cipher = make_unique<RC4Cipher>();
    else if (mode == 2) cipher = make_unique<RC440Cipher>();
    else if (mode == 3) cipher = make_unique<AESCBCipher>();
    else if (mode == 4) cipher = make_unique<AESGCMCipher>();
    else if (mode == 5) cipher = make_unique<ChaCha20Cipher>();
    else {
        cout << "Invalid choice.\n";
        return 1;
    }

    cout << "You selected: " << cipher->getName() << "\n";
    // Placeholder: integrate socket communication & encrypt/decrypt here
    return 0;
}
