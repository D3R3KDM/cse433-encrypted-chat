// chat_client.cpp  (Windows/MSVC 版本)
#define _CRT_SECURE_NO_WARNINGS
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib,"ws2_32.lib")
// 如果你的 OpenSSL 安装目录已把 libssl/libcrypto 添加到 VS「附加库目录」，
// 可以删除以下两行；否则保持。
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
unsigned char session_key[32]; // 对称加密会话密钥
unsigned char hmac_key[32];    // HMAC-SHA256 密钥（模式 1-3）

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
    char* buf;
    long len = BIO_get_mem_data(bio, &buf);
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
    BIO_free(bio);
    delete[] buf;
    return rsa;
}

void send_encrypted_key(int sock, RSA* peer_rsa,
    const unsigned char* key, int key_len) {
    unsigned char encrypted[512]{};
    int enc_len = RSA_public_encrypt(key_len, key, encrypted,
        peer_rsa, RSA_PKCS1_OAEP_PADDING);
    uint32_t enc_len_net = htonl(enc_len);
    send(sock, reinterpret_cast<char*>(&enc_len_net), sizeof(enc_len_net), 0);
    send(sock, reinterpret_cast<char*>(encrypted), enc_len, 0);
}

/* ---------- 辅助 ---------- */
string bytes_to_hex(const unsigned char* d, int len) {
    stringstream ss; ss << hex << setfill('0');
    for (int i = 0; i < len; ++i) ss << setw(2) << (int)d[i];
    return ss.str();
}

void cal_hmac(unsigned char* mac,
    const unsigned char* msg, int len) {
    unsigned int ml = 32;
    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, hmac_key, 32, EVP_sha256(), nullptr);
    HMAC_Update(ctx, msg, len);
    HMAC_Final(ctx, mac, &ml);
    HMAC_CTX_free(ctx);
}

/* ---------- 加 / 解密函数（与原代码一致，略无改动） ---------- */
int rc4_encrypt(const EVP_CIPHER* c, unsigned char* p, int l, unsigned char* o) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, c, nullptr, session_key, nullptr);
    EVP_EncryptUpdate(ctx, o, &l, p, l);
    EVP_CIPHER_CTX_free(ctx);
    return l;
}

int rc4_decrypt(const EVP_CIPHER* c, unsigned char* ct, int ctl, unsigned char* o) {
    int outl;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, c, nullptr, session_key, nullptr);
    EVP_DecryptUpdate(ctx, o, &outl, ct, ctl);
    EVP_CIPHER_CTX_free(ctx);
    return outl;
}

int aes_cbc_encrypt(unsigned char* p, int l, unsigned char* o, unsigned char* iv) {
    RAND_bytes(iv, 16);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tot = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, session_key, iv);
    EVP_EncryptUpdate(ctx, o, &outl, p, l);  tot = outl;
    EVP_EncryptFinal_ex(ctx, o + outl, &outl);  tot += outl;
    EVP_CIPHER_CTX_free(ctx);
    return tot;
}

int aes_cbc_decrypt(unsigned char* ct, int ctl, unsigned char* o, unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tot = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, session_key, iv);
    EVP_DecryptUpdate(ctx, o, &outl, ct, ctl);  tot = outl;
    int ok = EVP_DecryptFinal_ex(ctx, o + outl, &outl);
    tot = ok > 0 ? tot + outl : -1;
    EVP_CIPHER_CTX_free(ctx);
    return tot;
}

int aes_gcm_encrypt(unsigned char* p, int l, unsigned char* o,
    unsigned char* tag, unsigned char* iv) {
    RAND_bytes(iv, 12);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tot = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, session_key, iv);
    EVP_EncryptUpdate(ctx, o, &outl, p, l);  tot = outl;
    EVP_EncryptFinal_ex(ctx, o + outl, &outl);  tot += outl;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    return tot;
}

int aes_gcm_decrypt(unsigned char* ct, int ctl, unsigned char* tag,
    unsigned char* o, unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tot = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, session_key, iv);
    EVP_DecryptUpdate(ctx, o, &outl, ct, ctl);  tot = outl;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    int ok = EVP_DecryptFinal_ex(ctx, o + outl, &outl);
    tot = ok > 0 ? tot + outl : -1;
    EVP_CIPHER_CTX_free(ctx);
    return tot;
}

int chacha20_encrypt(unsigned char* p, int l, unsigned char* o, unsigned char* nonce) {
    RAND_bytes(nonce, 12);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), nullptr, session_key, nonce);
    EVP_EncryptUpdate(ctx, o, &l, p, l);
    EVP_CIPHER_CTX_free(ctx);
    return l;
}

int chacha20_decrypt(unsigned char* ct, int ctl, unsigned char* o, unsigned char* nonce) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_chacha20(), nullptr, session_key, nonce);
    EVP_DecryptUpdate(ctx, o, &ctl, ct, ctl);
    EVP_CIPHER_CTX_free(ctx);
    return ctl;
}

/* ---------- 发送线程 ---------- */
void sender(int sock) {
    while (running) {
        string msg; getline(cin, msg);
        if (!running) break;

        if (msg == "end chat") {
            send(sock, "##END##", 8, 0);
            shutdown(sock, SHUT_RDWR);
            running = false;
            break;
        }

        if (msg == "change mode") {
            cout << "[CLIENT] Select new mode (1-5): ";
            string input; getline(cin, input);
            stringstream ss(input);
            int newMode;
            if (!(ss >> newMode) || newMode < 1 || newMode > 5) {
                cout << "[CLIENT] Invalid mode, keep " << mode.load() << ".\n";
                continue;
            }
            mode = newMode;
            string sig = "##CHANGE##";
            send(sock, sig.c_str(), static_cast<int>(sig.size()) + 1, 0);
            int m = mode.load();
            send(sock, reinterpret_cast<char*>(&m), sizeof(int), 0);
            continue;
        }

        unsigned char ct[1024]{}, tag[16]{}, mac[32]{}, iv[16]{};
        int ctlen = 0;
        const unsigned char* p = reinterpret_cast<const unsigned char*>(msg.data());

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

        send(sock, reinterpret_cast<char*>(&ctlen), sizeof(int), 0);
        if (mode == 3) send(sock, reinterpret_cast<char*>(iv), 16, 0);
        else if (mode == 4 || mode == 5) send(sock, reinterpret_cast<char*>(iv), 12, 0);
        send(sock, reinterpret_cast<char*>(ct), ctlen, 0);
        if (mode <= 3) {
            cal_hmac(mac, p, (int)msg.size());
            send(sock, reinterpret_cast<char*>(mac), 32, 0);
        }
        else if (mode == 4) {
            send(sock, reinterpret_cast<char*>(tag), 16, 0);
        }
    }
}

/* ---------- 接收线程 ---------- */
void receiver(int sock) {
    while (running) {
        char hdr[16]{};
        int peek = recv(sock, hdr, sizeof(hdr), MSG_PEEK);
        if (peek <= 0) { running = false; break; }

        if (!strncmp(hdr, "##END##", 7)) {
            recv(sock, hdr, 8, 0);
            running = false; break;
        }
        if (!strncmp(hdr, "##CHANGE##", 10)) {
            recv(sock, hdr, 11, 0);
            int newmode; recv(sock, reinterpret_cast<char*>(&newmode), sizeof(int), 0);
            mode = newmode;
            cout << "[CLIENT] Mode changed to: " << mode.load() << endl;
            continue;
        }

        int ctlen = 0;
        recv(sock, reinterpret_cast<char*>(&ctlen), sizeof(int), 0);
        unsigned char ct[1024]{}, pt[1024]{}, tag[16]{}, mac[32]{}, calc[32]{}, iv[16]{};
        if (mode == 3) recv(sock, reinterpret_cast<char*>(iv), 16, 0);
        else if (mode == 4 || mode == 5) recv(sock, reinterpret_cast<char*>(iv), 12, 0);
        recv(sock, reinterpret_cast<char*>(ct), ctlen, 0);

        int ptlen = -1;
        switch (mode.load()) {
        case 1: ptlen = rc4_decrypt(EVP_rc4(), ct, ctlen, pt); break;
        case 2: ptlen = rc4_decrypt(EVP_rc4_40(), ct, ctlen, pt); break;
        case 3: ptlen = aes_cbc_decrypt(ct, ctlen, pt, iv); break;
        case 4:
            recv(sock, reinterpret_cast<char*>(tag), 16, 0);
            ptlen = aes_gcm_decrypt(ct, ctlen, tag, pt, iv); break;
        case 5: ptlen = chacha20_decrypt(ct, ctlen, pt, iv); break;
        }

        bool ok = true;
        if (mode <= 3) {
            recv(sock, reinterpret_cast<char*>(mac), 32, 0);
            cal_hmac(calc, pt, ptlen);
            ok = memcmp(mac, calc, 32) == 0;
        }
        if (ptlen > 0 && ok) {
            pt[ptlen] = '\0';
            cout << "[FRIEND] " << pt << " (cipher:" << bytes_to_hex(ct, ctlen);
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
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        cerr << "WSAStartup failed\n"; return 1;
    }
#endif
    string ip = "127.0.0.1";      // 运行前改成服务器 Windows 机器的 IPv4
    int    port = 5194;

    cout << "[CLIENT] Choose encryption mode:\n"
        " 1) RC4 + HMAC\n 2) RC4_40 + HMAC\n 3) AES-256-CBC + HMAC\n"
        " 4) AES-256-GCM\n 5) ChaCha20\n> ";
    string input; getline(cin, input);
    stringstream ss(input);
    int m;
    if (!(ss >> m) || m < 1 || m > 5) { cerr << "Invalid mode\n"; return 1; }
    mode = m;

    RSA* my_rsa = generate_rsa_keypair();

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) { cerr << "socket() failed\n"; return 1; }

    sockaddr_in srv{}; srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &srv.sin_addr);

    if (connect(sock, reinterpret_cast<sockaddr*>(&srv), sizeof(srv)) != 0) {
        cerr << "connect() failed\n"; CLOSESOCKET(sock); return 1;
    }
    cout << "[LOG] Connected to server.\n";

    /* ---- 执行握手 ---- */
    send_public_key(sock, my_rsa);
    RSA* server_rsa = receive_public_key(sock);
    RAND_bytes(session_key, 32);
    RAND_bytes(hmac_key, 32);
    send_encrypted_key(sock, server_rsa, session_key, 32);
    send_encrypted_key(sock, server_rsa, hmac_key, 32);
    int startMode = mode.load();
    send(sock, reinterpret_cast<char*>(&startMode), sizeof(int), 0);

    thread t1(sender, sock), t2(receiver, sock);
    t1.join(); t2.join();

    CLOSESOCKET(sock);
    RSA_free(my_rsa); RSA_free(server_rsa);
#ifdef _WIN32
    WSACleanup();
#endif
    cout << "Client shut down.\n";
    return 0;
}
