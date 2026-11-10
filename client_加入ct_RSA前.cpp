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
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

using namespace std;

atomic<bool> running(true);
int mode = 1;
unsigned char session_key[32]; // 全局会话密钥
RSA* my_rsa = nullptr; // 客户端 RSA 密钥对
RSA* serv_rsa = nullptr; // 服务器公钥

/* ---------- 辅助 ---------- */
string bytes_to_hex(const unsigned char* d, int len) {
    stringstream ss; ss << hex << setfill('0');
    for (int i = 0; i < len; ++i) ss << setw(2) << (int)d[i];
    return ss.str();
}

void cal_hmac(unsigned char* mac, const unsigned char* msg, int len) {
    const char key[] = "hmackey"; unsigned int ml = 32;
    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, strlen(key), EVP_sha256(), NULL);
    HMAC_Update(ctx, msg, len); HMAC_Final(ctx, mac, &ml);
    HMAC_CTX_free(ctx);
}

/* ---------- RSA 密钥交换辅助函数 ---------- */
RSA* generate_rsa_key() {
    RSA* rsa = RSA_new();
    BIGNUM* bne = BN_new();
    BN_set_word(bne, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bne, NULL);
    BN_free(bne);
    return rsa;
}

void send_public_key(int sock, RSA* rsa) {
    unsigned char* der = nullptr;
    int der_len = i2d_RSAPublicKey(rsa, &der);
    send(sock, &der_len, sizeof(int), 0);
    send(sock, der, der_len, 0);
    OPENSSL_free(der);
}

RSA* receive_public_key(int sock) {
    int der_len;
    recv(sock, &der_len, sizeof(int), 0);
    unsigned char* der = (unsigned char*)malloc(der_len);
    recv(sock, der, der_len, 0);
    const unsigned char* p = der;
    RSA* rsa = d2i_RSAPublicKey(NULL, &p, der_len);
    free(der);
    return rsa;
}

/* ---------- 加 / 解密函数 ---------- */
int rc4_encrypt(const EVP_CIPHER* c, unsigned char* p, int l, unsigned char* o) {
    unsigned char key[16]; memcpy(key, session_key, 16); // 使用会话密钥前 16 字节
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, c, NULL, key, NULL);
    EVP_EncryptUpdate(ctx, o, &l, p, l);
    EVP_CIPHER_CTX_free(ctx); return l;
}

int rc4_decrypt(const EVP_CIPHER* c, unsigned char* ct, int ctl, unsigned char* o) {
    unsigned char key[16]; memcpy(key, session_key, 16);
    int outl; EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, c, NULL, key, NULL);
    EVP_DecryptUpdate(ctx, o, &outl, ct, ctl);
    EVP_CIPHER_CTX_free(ctx); return outl;
}

int aes_cbc_encrypt(unsigned char* p, int l, unsigned char* o, unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tot = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, session_key, iv);
    EVP_EncryptUpdate(ctx, o, &outl, p, l); tot = outl;
    EVP_EncryptFinal_ex(ctx, o + outl, &outl); tot += outl;
    EVP_CIPHER_CTX_free(ctx); return tot;
}

int aes_cbc_decrypt(unsigned char* ct, int ctl, unsigned char* o, unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tot = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, session_key, iv);
    EVP_DecryptUpdate(ctx, o, &outl, ct, ctl); tot = outl;
    int ok = EVP_DecryptFinal_ex(ctx, o + outl, &outl);
    tot = ok > 0 ? tot + outl : -1;
    EVP_CIPHER_CTX_free(ctx); return tot;
}

int aes_gcm_encrypt(unsigned char* p, int l, unsigned char* o, unsigned char* tag, unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tot = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, session_key, iv);
    EVP_EncryptUpdate(ctx, o, &outl, p, l); tot = outl;
    EVP_EncryptFinal_ex(ctx, o + outl, &outl); tot += outl;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx); return tot;
}

int aes_gcm_decrypt(unsigned char* ct, int ctl, unsigned char* tag, unsigned char* o, unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tot = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, session_key, iv);
    EVP_DecryptUpdate(ctx, o, &outl, ct, ctl); tot = outl;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    int ok = EVP_DecryptFinal_ex(ctx, o + outl, &outl);
    tot = ok > 0 ? tot + outl : -1;
    EVP_CIPHER_CTX_free(ctx); return tot;
}

int chacha20_encrypt(unsigned char* p, int l, unsigned char* o, unsigned char* nonce) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, session_key, nonce);
    EVP_EncryptUpdate(ctx, o, &l, p, l);
    EVP_CIPHER_CTX_free(ctx); return l;
}

int chacha20_decrypt(unsigned char* ct, int ctl, unsigned char* o, unsigned char* nonce) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, session_key, nonce);
    EVP_DecryptUpdate(ctx, o, &ctl, ct, ctl);
    EVP_CIPHER_CTX_free(ctx); return ctl;
}

/* ---------- 发送线程 ---------- */
void sender(int sock) {
    while (running) {
        string msg; getline(cin, msg);

        if (msg == "end chat") {
            send(sock, "##END##", 8, 0); shutdown(sock, SHUT_RDWR);
            running = false; break;
        }

        if (msg == "change mode") {
            cout << "[CLIENT] Select new mode (1-5): ";
            string input; getline(cin, input);
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
        int ctlen = 0, iv_len = 0;
        const unsigned char* p = (const unsigned char*)msg.c_str();

        // 生成随机 IV/Nonce
        if (mode == 3) { iv_len = 16; RAND_bytes(iv, iv_len); } // AES-CBC
        else if (mode == 4 || mode == 5) { iv_len = 12; RAND_bytes(iv, iv_len); } // AES-GCM, ChaCha20

        // 加密
        if (mode == 1) ctlen = rc4_encrypt(EVP_rc4(), (unsigned char*)p, msg.size(), ct);
        else if (mode == 2) ctlen = rc4_encrypt(EVP_rc4_40(), (unsigned char*)p, msg.size(), ct);
        else if (mode == 3) ctlen = aes_cbc_encrypt((unsigned char*)p, msg.size(), ct, iv);
        else if (mode == 4) ctlen = aes_gcm_encrypt((unsigned char*)p, msg.size(), ct, tag, iv);
        else if (mode == 5) ctlen = chacha20_encrypt((unsigned char*)p, msg.size(), ct, iv);

        cout << "[ME] " << msg << "(ciphertext:" << bytes_to_hex(ct, ctlen) << ")\n";

        // 发送：IV 长度，IV（如果有），密文长度，密文，HMAC/标签
        send(sock, &iv_len, sizeof(int), 0);
        if (iv_len > 0) send(sock, iv, iv_len, 0);
        send(sock, &ctlen, sizeof(int), 0);
        send(sock, ct, ctlen, 0);
        if (mode <= 3) { cal_hmac(mac, p, msg.size()); send(sock, mac, 32, 0); }
        else if (mode == 4) { send(sock, tag, 16, 0); }
    }
}

/* ---------- 接收线程 ---------- */
void receiver(int sock) {
    while (running) {
        char hdr[16] = { 0 };
        if (recv(sock, hdr, sizeof(hdr), MSG_PEEK) <= 0) { running = false; break; }

        if (!strncmp(hdr, "##END##", 7)) { recv(sock, hdr, 8, 0); running = false; break; }
        if (!strncmp(hdr, "##CHANGE##", 10)) {
            recv(sock, hdr, 11, 0); recv(sock, &mode, sizeof(int), 0);
            cout << "[CLIENT] Mode changed to: " << mode << endl; continue;
        }

        int iv_len = 0, ctlen = 0;
        unsigned char iv[16] = { 0 }, ct[1024] = { 0 }, pt[1024] = { 0 }, tag[16] = { 0 }, mac[32] = { 0 }, calc[32] = { 0 };
        recv(sock, &iv_len, sizeof(int), 0);
        if (iv_len > 0) recv(sock, iv, iv_len, 0);
        recv(sock, &ctlen, sizeof(int), 0);
        recv(sock, ct, ctlen, 0);
        int ptlen = -1;

        // 解密
        if (mode == 1) ptlen = rc4_decrypt(EVP_rc4(), ct, ctlen, pt);
        else if (mode == 2) ptlen = rc4_decrypt(EVP_rc4_40(), ct, ctlen, pt);
        else if (mode == 3) ptlen = aes_cbc_decrypt(ct, ctlen, pt, iv);
        else if (mode == 4) { recv(sock, tag, 16, 0); ptlen = aes_gcm_decrypt(ct, ctlen, tag, pt, iv); }
        else if (mode == 5) ptlen = chacha20_decrypt(ct, ctlen, pt, iv);

        bool ok = true;
        if (mode <= 3) {
            recv(sock, mac, 32, 0); cal_hmac(calc, pt, ptlen);
            ok = memcmp(mac, calc, 32) == 0;
        }
        if (ptlen > 0 && ok) {
            pt[ptlen] = '\0';
            cout << "[FRIEND] " << pt << "(ciphertext:" << bytes_to_hex(ct, ctlen) << ")\n";
        }
        else {
            cout << "[CLIENT] Invalid message / HMAC.\n";
        }
    }
}

/* ---------- 主函数 ---------- */
int main() {
    string ip = "10.9.0.6"; int port = 5194;

    cout << "[CLIENT] Choose encryption mode:\n"
        << " 1) RC4 + HMAC\n 2) RC4_40 + HMAC\n 3) AES-256-CBC + HMAC\n"
        << " 4) AES-256-GCM\n 5) ChaCha20\n> ";
    string input; getline(cin, input);
    stringstream ss(input);
    if (!(ss >> mode) || mode < 1 || mode > 5) {
        cerr << "Invalid start mode.\n"; return 1;
    }

    // 初始化 OpenSSL
    OpenSSL_add_all_algorithms();

    // 生成 RSA 密钥对
    my_rsa = generate_rsa_key();

    // 建立连接
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in srv{}; srv.sin_family = AF_INET; srv.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &srv.sin_addr);
    if (connect(sock, (sockaddr*)&srv, sizeof(srv)) < 0) {
        cerr << "Connection failed.\n"; RSA_free(my_rsa); return 1;
    }
    cout << "[CONNECTED] to " << ip << ":" << port << '\n';

    // 发送初始模式
    send(sock, &mode, sizeof(int), 0);

    // 公钥交换
    send_public_key(sock, my_rsa);
    serv_rsa = receive_public_key(sock);

    // 生成并发送会话密钥
    RAND_bytes(session_key, 32);
    int enc_len = RSA_size(serv_rsa);
    unsigned char enc_key[enc_len];
    if (RSA_public_encrypt(32, session_key, enc_key, serv_rsa, RSA_PKCS1_OAEP_PADDING) != enc_len) {
        cerr << "RSA encryption failed.\n"; RSA_free(my_rsa); RSA_free(serv_rsa); close(sock); return 1;
    }
    send(sock, &enc_len, sizeof(int), 0);
    send(sock, enc_key, enc_len, 0);

    // 启动线程
    thread t1(sender, sock), t2(receiver, sock);
    t1.join(); t2.join();

    // 清理
    RSA_free(my_rsa); RSA_free(serv_rsa);
    close(sock);
    cout << "Client shut down.\n";
    return 0;
}