#include <iostream>
#include <cstring>
#include <thread>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

using namespace std;

atomic<bool> running(true);
int mode = 1;
unsigned char session_key[32]; // Shared session key for encryption
unsigned char hmac_key[32];   // Shared HMAC key for modes 1–3

/* ---------- RSA Key Management ---------- */
RSA* generate_rsa_keypair() {
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bn, NULL);
    BN_free(bn);
    return rsa;
}

void send_public_key(int sock, RSA* rsa) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, rsa);
    char* buf;
    long len = BIO_get_mem_data(bio, &buf);
    uint32_t len_net = htonl(len);
    send(sock, &len_net, sizeof(len_net), 0);
    send(sock, buf, len, 0);
    BIO_free(bio);
}

RSA* receive_public_key(int sock) {
    uint32_t len_net;
    recv(sock, &len_net, sizeof(len_net), 0);
    int len = ntohl(len_net);
    char* buf = new char[len];
    recv(sock, buf, len, 0);
    BIO* bio = BIO_new_mem_buf(buf, len);
    RSA* rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    delete[] buf;
    return rsa;
}

void send_encrypted_key(int sock, RSA* peer_rsa, const unsigned char* key, int key_len) {
    unsigned char encrypted[512];
    int enc_len = RSA_public_encrypt(key_len, key, encrypted, peer_rsa, RSA_PKCS1_OAEP_PADDING);
    uint32_t enc_len_net = htonl(enc_len);
    send(sock, &enc_len_net, sizeof(enc_len_net), 0);
    send(sock, encrypted, enc_len, 0);
}

void receive_encrypted_key(int sock, RSA* my_rsa, unsigned char* key, int key_len) {
    uint32_t enc_len_net;
    recv(sock, &enc_len_net, sizeof(enc_len_net), 0);
    int enc_len = ntohl(enc_len_net);
    unsigned char* encrypted = new unsigned char[enc_len];
    recv(sock, encrypted, enc_len, 0);
    RSA_private_decrypt(enc_len, encrypted, key, my_rsa, RSA_PKCS1_OAEP_PADDING);
    delete[] encrypted;
}

/* ---------- 辅助 ---------- */
string bytes_to_hex(const unsigned char* d, int len) {
    stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < len; ++i) ss << setw(2) << (int)d[i];
    return ss.str();
}

void cal_hmac(unsigned char* mac, const unsigned char* msg, int len) {
    unsigned int ml = 32;
    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, hmac_key, 32, EVP_sha256(), NULL);
    HMAC_Update(ctx, msg, len);
    HMAC_Final(ctx, mac, &ml);
    HMAC_CTX_free(ctx);
}

/* ---------- 加 / 解密函数 ---------- */
int rc4_encrypt(const EVP_CIPHER* c, unsigned char* p, int l, unsigned char* o) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, c, NULL, session_key, NULL);
    EVP_EncryptUpdate(ctx, o, &l, p, l);
    EVP_CIPHER_CTX_free(ctx);
    return l;
}

int rc4_decrypt(const EVP_CIPHER* c, unsigned char* ct, int ctl, unsigned char* o) {
    int outl;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, c, NULL, session_key, NULL);
    EVP_DecryptUpdate(ctx, o, &outl, ct, ctl);
    EVP_CIPHER_CTX_free(ctx);
    return outl;
}

int aes_cbc_encrypt(unsigned char* p, int l, unsigned char* o, unsigned char* iv) {
    RAND_bytes(iv, 16); // Random IV
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tot = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, session_key, iv);
    EVP_EncryptUpdate(ctx, o, &outl, p, l);
    tot = outl;
    EVP_EncryptFinal_ex(ctx, o + outl, &outl);
    tot += outl;
    EVP_CIPHER_CTX_free(ctx);
    return tot;
}

int aes_cbc_decrypt(unsigned char* ct, int ctl, unsigned char* o, unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tot = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, session_key, iv);
    EVP_DecryptUpdate(ctx, o, &outl, ct, ctl);
    tot = outl;
    int ok = EVP_DecryptFinal_ex(ctx, o + outl, &outl);
    tot = ok > 0 ? tot + outl : -1;
    EVP_CIPHER_CTX_free(ctx);
    return tot;
}

int aes_gcm_encrypt(unsigned char* p, int l, unsigned char* o, unsigned char* tag, unsigned char* iv) {
    RAND_bytes(iv, 12); // Random IV
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tot = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, session_key, iv);
    EVP_EncryptUpdate(ctx, o, &outl, p, l);
    tot = outl;
    EVP_EncryptFinal_ex(ctx, o + outl, &outl);
    tot += outl;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    return tot;
}

int aes_gcm_decrypt(unsigned char* ct, int ctl, unsigned char* tag, unsigned char* o, unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tot = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, session_key, iv);
    EVP_DecryptUpdate(ctx, o, &outl, ct, ctl);
    tot = outl;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    int ok = EVP_DecryptFinal_ex(ctx, o + outl, &outl);
    tot = ok > 0 ? tot + outl : -1;
    EVP_CIPHER_CTX_free(ctx);
    return tot;
}

int chacha20_encrypt(unsigned char* p, int l, unsigned char* o, unsigned char* nonce) {
    RAND_bytes(nonce, 12); // Random nonce
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, session_key, nonce);
    EVP_EncryptUpdate(ctx, o, &l, p, l);
    EVP_CIPHER_CTX_free(ctx);
    return l;
}

int chacha20_decrypt(unsigned char* ct, int ctl, unsigned char* o, unsigned char* nonce) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, session_key, nonce);
    EVP_DecryptUpdate(ctx, o, &ctl, ct, ctl);
    EVP_CIPHER_CTX_free(ctx);
    return ctl;
}

/* ---------- 发送线程 ---------- */
void sender(int sock) {
    while (running) {
        string msg;
        getline(cin, msg);

        if (msg == "end chat") {
            send(sock, "##END##", 8, 0);
            shutdown(sock, SHUT_RDWR);
            running = false;
            break;
        }

        if (msg == "change mode") {
            cout << "[CLIENT] Select new mode (1-5): ";
            string input;
            getline(cin, input);
            stringstream ss(input);
            int newMode;
            if (!(ss >> newMode) || newMode < 1 || newMode > 5) {
                cout << "[CLIENT] Invalid mode, keep " << mode << ".\n";
                continue;
            }
            mode = newMode;
            string sig = "##CHANGE##";
            send(sock, sig.c_str(), sig.size() + 1, 0);
            send(sock, &mode, sizeof(int), 0);
            continue;
        }

        unsigned char ct[1024] = { 0 }, tag[16] = { 0 }, mac[32] = { 0 }, iv[16] = { 0 };
        int ctlen = 0;
        const unsigned char* p = (const unsigned char*)msg.c_str();

        if (mode == 1) {
            ctlen = rc4_encrypt(EVP_rc4(), (unsigned char*)p, msg.size(), ct);
        }
        else if (mode == 2) {
            ctlen = rc4_encrypt(EVP_rc4_40(), (unsigned char*)p, msg.size(), ct);
        }
        else if (mode == 3) {
            ctlen = aes_cbc_encrypt((unsigned char*)p, msg.size(), ct, iv);
            // Send IV (16 bytes)
        }
        else if (mode == 4) {
            ctlen = aes_gcm_encrypt((unsigned char*)p, msg.size(), ct, tag, iv);
            // Send IV (12 bytes)
        }
        else if (mode == 5) {
            ctlen = chacha20_encrypt((unsigned char*)p, msg.size(), ct, iv);
            // Send nonce (12 bytes)
        }

        cout << "[ME] " << msg << " (ciphertext:" << bytes_to_hex(ct, ctlen);
        if (mode >= 3) cout << ", iv/nonce:" << bytes_to_hex(iv, mode == 3 ? 16 : 12);
        cout << ")\n";

        send(sock, &ctlen, sizeof(int), 0);
        if (mode == 3) send(sock, iv, 16, 0); // AES-CBC IV
        else if (mode == 4 || mode == 5) send(sock, iv, 12, 0); // AES-GCM or ChaCha20 nonce
        send(sock, ct, ctlen, 0);
        if (mode <= 3) {
            cal_hmac(mac, p, msg.size());
            send(sock, mac, 32, 0);
        }
        else if (mode == 4) {
            send(sock, tag, 16, 0);
        }
    }
}

/* ---------- 接收线程 ---------- */
void receiver(int sock) {
    while (running) {
        char hdr[16] = { 0 };
        if (recv(sock, hdr, sizeof(hdr), MSG_PEEK) <= 0) {
            running = false;
            break;
        }

        if (!strncmp(hdr, "##END##", 7)) {
            recv(sock, hdr, 8, 0);
            running = false;
            break;
        }
        if (!strncmp(hdr, "##CHANGE##", 10)) {
            recv(sock, hdr, 11, 0);
            recv(sock, &mode, sizeof(int), 0);
            cout << "[CLIENT] Mode changed to: " << mode << endl;
            continue;
        }

        int ctlen = 0;
        recv(sock, &ctlen, sizeof(int), 0);
        unsigned char ct[1024] = { 0 }, pt[1024] = { 0 }, tag[16] = { 0 }, mac[32] = { 0 }, calc[32] = { 0 }, iv[16] = { 0 };
        if (mode == 3) recv(sock, iv, 16, 0); // AES-CBC IV
        else if (mode == 4 || mode == 5) recv(sock, iv, 12, 0); // AES-GCM or ChaCha20 nonce
        recv(sock, ct, ctlen, 0);
        int ptlen = -1;

        if (mode == 1) {
            ptlen = rc4_decrypt(EVP_rc4(), ct, ctlen, pt);
        }
        else if (mode == 2) {
            ptlen = rc4_decrypt(EVP_rc4_40(), ct, ctlen, pt);
        }
        else if (mode == 3) {
            ptlen = aes_cbc_decrypt(ct, ctlen, pt, iv);
        }
        else if (mode == 4) {
            recv(sock, tag, 16, 0);
            ptlen = aes_gcm_decrypt(ct, ctlen, tag, pt, iv);
        }
        else if (mode == 5) {
            ptlen = chacha20_decrypt(ct, ctlen, pt, iv);
        }

        bool ok = true;
        if (mode <= 3) {
            recv(sock, mac, 32, 0);
            cal_hmac(calc, pt, ptlen);
            ok = memcmp(mac, calc, 32) == 0;
        }
        if (ptlen > 0 && ok) {
            pt[ptlen] = '\0';
            cout << "[FRIEND] " << pt << " (ciphertext:" << bytes_to_hex(ct, ctlen);
            if (mode >= 3) cout << ", iv/nonce:" << bytes_to_hex(iv, mode == 3 ? 16 : 12);
            cout << ")\n";
        }
        else {
            cout << "[CLIENT] Invalid message / HMAC.\n";
        }
    }
}

/* ---------- 主函数 ---------- */
int main() {
    string ip = "10.9.0.6";
    int port = 5194;

    cout << "[CLIENT] Choose encryption mode:\n"
        " 1) RC4 + HMAC\n 2) RC4_40 + HMAC\n 3) AES-256-CBC + HMAC\n"
        " 4) AES-256-GCM\n 5) ChaCha20\n> ";
    string input;
    getline(cin, input);
    stringstream ss(input);
    if (!(ss >> mode) || mode < 1 || mode > 5) {
        cerr << "Invalid start mode.\n";
        return 1;
    }

    RSA* my_rsa = generate_rsa_keypair();
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in srv{};
    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &srv.sin_addr);
    if (connect(sock, (sockaddr*)&srv, sizeof(srv)) < 0) {
        cerr << "Connection failed.\n";
        RSA_free(my_rsa);
        return 1;
    }

    send_public_key(sock, my_rsa);
    RSA* server_rsa = receive_public_key(sock);
    RAND_bytes(session_key, 32);
    RAND_bytes(hmac_key, 32);
    send_encrypted_key(sock, server_rsa, session_key, 32);
    send_encrypted_key(sock, server_rsa, hmac_key, 32);
    send(sock, &mode, sizeof(int), 0);
    cout << "[CONNECTED] to " << ip << ":" << port << '\n';

    thread t1(sender, sock), t2(receiver, sock);
    t1.join();
    t2.join();

    close(sock);
    RSA_free(my_rsa);
    RSA_free(server_rsa);
    cout << "Client shut down.\n";
    return 0;
}