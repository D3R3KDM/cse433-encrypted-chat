// chat_server.cpp  (Windows/MSVC 版本)
#define _CRT_SECURE_NO_WARNINGS
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")
#define CLOSESOCKET  closesocket
#define SHUT_RDWR    SD_BOTH
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#define CLOSESOCKET  close
#endif

#include <iostream>
#include <cstring>
#include <thread>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

using namespace std;

/* ---------- 全局 ---------- */
atomic<bool> running(true);
atomic<int>  mode(1);
unsigned char session_key[32];
unsigned char hmac_key[32];

/* ---------- RSA Key Management ---------- */
RSA* generate_rsa_keypair() {
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bn, nullptr);
    BN_free(bn);
    return rsa;
}

void send_public_key(int sock, RSA* rsa) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, rsa);
    char* buf; long len = BIO_get_mem_data(bio, &buf);
    uint32_t len_net = htonl(static_cast<uint32_t>(len));
    send(sock, reinterpret_cast<char*>(&len_net), sizeof(len_net), 0);
    send(sock, buf, static_cast<int>(len), 0);
    BIO_free(bio);
}

RSA* receive_public_key(int sock) {
    uint32_t len_net;
    recv(sock, reinterpret_cast<char*>(&len_net), sizeof(len_net), 0);
    int len = ntohl(len_net);
    auto* buf = new char[len];
    recv(sock, buf, len, 0);
    BIO* bio = BIO_new_mem_buf(buf, len);
    RSA* rsa = PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio); delete[] buf;
    return rsa;
}

void receive_encrypted_key(int sock, RSA* my_rsa,
    unsigned char* key, int key_len) {
    uint32_t enc_len_net;
    recv(sock, reinterpret_cast<char*>(&enc_len_net), sizeof(enc_len_net), 0);
    int enc_len = ntohl(enc_len_net);
    auto* encrypted = new unsigned char[enc_len];
    recv(sock, reinterpret_cast<char*>(encrypted), enc_len, 0);
    RSA_private_decrypt(enc_len, encrypted, key, my_rsa, RSA_PKCS1_OAEP_PADDING);
    delete[] encrypted;
}

/* ---------- 辅助函数（与客户端相同，省略重述） ---------- */
string bytes_to_hex(const unsigned char* d, int len) {
    stringstream ss; ss << hex << setfill('0');
    for (int i = 0; i < len; ++i) ss << setw(2) << (int)d[i];
    return ss.str();
}
void cal_hmac(unsigned char* mac, const unsigned char* msg, int len) {
    unsigned int ml = 32;
    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, hmac_key, 32, EVP_sha256(), nullptr);
    HMAC_Update(ctx, msg, len);
    HMAC_Final(ctx, mac, &ml);
    HMAC_CTX_free(ctx);
}

/* ---------- 加 / 解密函数（与客户端相同，完全一致） ---------- */
int rc4_encrypt(const EVP_CIPHER* c, unsigned char* p, int l, unsigned char* o) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, c, nullptr, session_key, nullptr);
    EVP_EncryptUpdate(ctx, o, &l, p, l);
    EVP_CIPHER_CTX_free(ctx); return l;
}
int rc4_decrypt(const EVP_CIPHER* c, unsigned char* ct, int ctl, unsigned char* o) {
    int outl; EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, c, nullptr, session_key, nullptr);
    EVP_DecryptUpdate(ctx, o, &outl, ct, ctl);
    EVP_CIPHER_CTX_free(ctx); return outl;
}
int aes_cbc_encrypt(unsigned char* p, int l, unsigned char* o, unsigned char* iv) {
    RAND_bytes(iv, 16); EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tot = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, session_key, iv);
    EVP_EncryptUpdate(ctx, o, &outl, p, l); tot = outl;
    EVP_EncryptFinal_ex(ctx, o + outl, &outl); tot += outl;
    EVP_CIPHER_CTX_free(ctx); return tot;
}
int aes_cbc_decrypt(unsigned char* ct, int ctl, unsigned char* o, unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tot = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, session_key, iv);
    EVP_DecryptUpdate(ctx, o, &outl, ct, ctl); tot = outl;
    int ok = EVP_DecryptFinal_ex(ctx, o + outl, &outl);
    tot = ok > 0 ? tot + outl : -1;
    EVP_CIPHER_CTX_free(ctx); return tot;
}
int aes_gcm_encrypt(unsigned char* p, int l, unsigned char* o,
    unsigned char* tag, unsigned char* iv) {
    RAND_bytes(iv, 12); EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tot = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, session_key, iv);
    EVP_EncryptUpdate(ctx, o, &outl, p, l); tot = outl;
    EVP_EncryptFinal_ex(ctx, o + outl, &outl); tot += outl;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx); return tot;
}
int aes_gcm_decrypt(unsigned char* ct, int ctl, unsigned char* tag,
    unsigned char* o, unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tot = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, session_key, iv);
    EVP_DecryptUpdate(ctx, o, &outl, ct, ctl); tot = outl;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    int ok = EVP_DecryptFinal_ex(ctx, o + outl, &outl);
    tot = ok > 0 ? tot + outl : -1;
    EVP_CIPHER_CTX_free(ctx); return tot;
}
int chacha20_encrypt(unsigned char* p, int l, unsigned char* o, unsigned char* nonce) {
    RAND_bytes(nonce, 12); EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), nullptr, session_key, nonce);
    EVP_EncryptUpdate(ctx, o, &l, p, l);
    EVP_CIPHER_CTX_free(ctx); return l;
}
int chacha20_decrypt(unsigned char* ct, int ctl, unsigned char* o, unsigned char* nonce) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_chacha20(), nullptr, session_key, nonce);
    EVP_DecryptUpdate(ctx, o, &ctl, ct, ctl);
    EVP_CIPHER_CTX_free(ctx); return ctl;
}

/* ---------- 发送/接收线程 与客户端逻辑对称 ---------- */
void sender(int sock) {
    while (running) {
        string msg; getline(cin, msg);
        if (!running) break;
        if (msg == "end chat") {
            send(sock, "##END##", 8, 0);
            shutdown(sock, SHUT_RDWR); running = false; break;
        }
        if (msg == "change mode") {
            cout << "[SERVER] Select new mode (1-5): ";
            string input; getline(cin, input);
            stringstream ss(input); int newMode;
            if (!(ss >> newMode) || newMode < 1 || newMode>5) {
                cout << "[SERVER] Invalid mode, keep " << mode.load() << ".\n"; continue;
            }
            mode = newMode;
            string sig = "##CHANGE##";
            send(sock, sig.c_str(), (int)sig.size() + 1, 0);
            int m = mode.load();
            send(sock, (char*)&m, sizeof(int), 0);
            continue;
        }
        unsigned char ct[1024]{}, tag[16]{}, mac[32]{}, iv[16]{};
        int ctlen = 0;
        const unsigned char* p = (const unsigned char*)msg.data();
        switch (mode.load()) {
        case 1: ctlen = rc4_encrypt(EVP_rc4(), (unsigned char*)p, (int)msg.size(), ct); break;
        case 2: ctlen = rc4_encrypt(EVP_rc4_40(), (unsigned char*)p, (int)msg.size(), ct); break;
        case 3: ctlen = aes_cbc_encrypt((unsigned char*)p, (int)msg.size(), ct, iv); break;
        case 4: ctlen = aes_gcm_encrypt((unsigned char*)p, (int)msg.size(), ct, tag, iv); break;
        case 5: ctlen = chacha20_encrypt((unsigned char*)p, (int)msg.size(), ct, iv); break;
        }
        cout << "[ME] " << msg << " (cipher:" << bytes_to_hex(ct, ctlen);
        if (mode >= 3) cout << ", iv/nonce:" << bytes_to_hex(iv, mode == 3 ? 16 : 12);
        cout << ")\n";

        send(sock, (char*)&ctlen, sizeof(int), 0);
        if (mode == 3) send(sock, (char*)iv, 16, 0);
        else if (mode == 4 || mode == 5) send(sock, (char*)iv, 12, 0);
        send(sock, (char*)ct, ctlen, 0);
        if (mode <= 3) {
            cal_hmac(mac, p, (int)msg.size());
            send(sock, (char*)mac, 32, 0);
        }
        else if (mode == 4) {
            send(sock, (char*)tag, 16, 0);
        }
    }
}
void receiver(int sock) {
    while (running) {
        char hdr[16]{}; int peek = recv(sock, hdr, sizeof(hdr), MSG_PEEK);
        if (peek <= 0) { running = false; break; }
        if (!strncmp(hdr, "##END##", 7)) {
            recv(sock, hdr, 8, 0); running = false; break;
        }
        if (!strncmp(hdr, "##CHANGE##", 10)) {
            recv(sock, hdr, 11, 0); int newm;
            recv(sock, (char*)&newm, sizeof(int), 0);
            mode = newm; cout << "[SERVER] Mode changed to: " << mode.load() << endl;
            continue;
        }
        int ctlen = 0; recv(sock, (char*)&ctlen, sizeof(int), 0);
        unsigned char ct[1024]{}, pt[1024]{}, tag[16]{}, mac[32]{}, calc[32]{}, iv[16]{};
        if (mode == 3) recv(sock, (char*)iv, 16, 0);
        else if (mode == 4 || mode == 5) recv(sock, (char*)iv, 12, 0);
        recv(sock, (char*)ct, ctlen, 0);
        int ptlen = -1;
        switch (mode.load()) {
        case 1: ptlen = rc4_decrypt(EVP_rc4(), ct, ctlen, pt); break;
        case 2: ptlen = rc4_decrypt(EVP_rc4_40(), ct, ctlen, pt); break;
        case 3: ptlen = aes_cbc_decrypt(ct, ctlen, pt, iv); break;
        case 4: recv(sock, (char*)tag, 16, 0);
            ptlen = aes_gcm_decrypt(ct, ctlen, tag, pt, iv); break;
        case 5: ptlen = chacha20_decrypt(ct, ctlen, pt, iv); break;
        }
        bool ok = true;
        if (mode <= 3) {
            recv(sock, (char*)mac, 32, 0);
            cal_hmac(calc, pt, ptlen); ok = memcmp(mac, calc, 32) == 0;
        }
        if (ptlen > 0 && ok) {
            pt[ptlen] = '\0';
            cout << "[FRIEND] " << pt << " (cipher:" << bytes_to_hex(ct, ctlen);
            if (mode >= 3) cout << ", iv/nonce:" << bytes_to_hex(iv, mode == 3 ? 16 : 12);
            cout << ")\n";
        }
        else cout << "[SERVER] Invalid message / HMAC.\n";
    }
}

/* ---------- 主函数 ---------- */
int main() {
#ifdef _WIN32
    WSADATA wsa; if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        cerr << "WSAStartup failed\n"; return 1;
    }
#endif
    string ip = "0.0.0.0";   // 监听所有网卡；也可写固定绑定 IP
    int port = 5194;

    RSA* my_rsa = generate_rsa_keypair();

    int srvSock = socket(AF_INET, SOCK_STREAM, 0);
    if (srvSock == INVALID_SOCKET) {
        cerr << "socket() fail\n"; return 1;
    }
    sockaddr_in srvAddr{}; srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &srvAddr.sin_addr);

    if (bind(srvSock, (sockaddr*)&srvAddr, sizeof(srvAddr)) != 0) {
        cerr << "bind() failed\n"; CLOSESOCKET(srvSock); return 1;
    }
    listen(srvSock, 1);
    cout << "[SERVER] Waiting on " << port << " ...\n";

    sockaddr_in cliAddr{}; int cliLen = sizeof(cliAddr);
    int cliSock = accept(srvSock, (sockaddr*)&cliAddr, &cliLen);
    if (cliSock == INVALID_SOCKET) {
        cerr << "accept() failed\n"; CLOSESOCKET(srvSock); return 1;
    }
    cout << "[CONNECTED] client joined.\n";

    RSA* client_rsa = receive_public_key(cliSock);
    send_public_key(cliSock, my_rsa);
    receive_encrypted_key(cliSock, my_rsa, session_key, 32);
    receive_encrypted_key(cliSock, my_rsa, hmac_key, 32);
    int m; recv(cliSock, (char*)&m, sizeof(int), 0);
    mode = m; cout << "[SERVER] Mode set to: " << mode.load() << endl;

    thread t1(sender, cliSock), t2(receiver, cliSock);
    t1.join(); t2.join();

    CLOSESOCKET(cliSock); CLOSESOCKET(srvSock);
    RSA_free(my_rsa); RSA_free(client_rsa);
#ifdef _WIN32
    WSACleanup();
#endif
    cout << "Server shut down.\n"; return 0;
}
