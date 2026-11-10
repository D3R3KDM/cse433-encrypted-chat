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

using namespace std;

atomic<bool> running(true);
int mode = 1;

/* ---------- 辅助：字节数组转十六进制 ---------- */
string bytes_to_hex(const unsigned char* data, int len) {
    stringstream ss; ss << hex << setfill('0');
    for (int i = 0; i < len; ++i) ss << setw(2) << static_cast<int>(data[i]);
    return ss.str();
}

/* ---------- HMAC ---------- */
void cal_hmac(unsigned char* mac, const unsigned char* msg, int len) {
    const char key[] = "hmackey";
    unsigned int maclen = 32;
    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, strlen(key), EVP_sha256(), NULL);
    HMAC_Update(ctx, msg, len);
    HMAC_Final(ctx, mac, &maclen);
    HMAC_CTX_free(ctx);
}

/* ---------- 加 / 解密函数（与你原代码一致，未改） ---------- */
// — RC4/RC4_40
int rc4_encrypt(const EVP_CIPHER* c, unsigned char* p, int l, unsigned char* o) {
    unsigned char key[16] = { '1','2','3','4','5','6','7','8','9','0','a','b','c','d','e','f' };
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, c, NULL, key, NULL);
    EVP_EncryptUpdate(ctx, o, &l, p, l);
    EVP_CIPHER_CTX_free(ctx); return l;
}
int rc4_decrypt(const EVP_CIPHER* c, unsigned char* ct, int ctl, unsigned char* o) {
    unsigned char key[16] = { '1','2','3','4','5','6','7','8','9','0','a','b','c','d','e','f' };
    int outl; EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, c, NULL, key, NULL);
    EVP_DecryptUpdate(ctx, o, &outl, ct, ctl);
    EVP_CIPHER_CTX_free(ctx); return outl;
}
// — AES-CBC
int aes_cbc_encrypt(unsigned char* p, int l, unsigned char* o) {
    unsigned char key[32] = {
        'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3','4','5' };
    unsigned char iv[16] = {
        'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p' };
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tot = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, o, &outl, p, l); tot = outl;
    EVP_EncryptFinal_ex(ctx, o + outl, &outl); tot += outl;
    EVP_CIPHER_CTX_free(ctx); return tot;
}
int aes_cbc_decrypt(unsigned char* ct, int ctl, unsigned char* o) {
    unsigned char key[32] = {
        'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3','4','5' };
    unsigned char iv[16] = {
        'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p' };
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tot = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, o, &outl, ct, ctl); tot = outl;
    int ok = EVP_DecryptFinal_ex(ctx, o + outl, &outl);
    tot = ok > 0 ? tot + outl : -1;
    EVP_CIPHER_CTX_free(ctx); return tot;
}
// — AES-GCM
int aes_gcm_encrypt(unsigned char* p, int l, unsigned char* o, unsigned char* tag) {
    unsigned char key[32] = { 'A' }; unsigned char iv[12] = { 'b' };
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tot = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, o, &outl, p, l); tot = outl;
    EVP_EncryptFinal_ex(ctx, o + outl, &outl); tot += outl;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx); return tot;
}
int aes_gcm_decrypt(unsigned char* ct, int ctl, unsigned char* tag, unsigned char* o) {
    unsigned char key[32] = { 'A' }; unsigned char iv[12] = { 'b' };
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tot = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_DecryptUpdate(ctx, o, &outl, ct, ctl); tot = outl;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    int ok = EVP_DecryptFinal_ex(ctx, o + outl, &outl);
    tot = ok > 0 ? tot + outl : -1;
    EVP_CIPHER_CTX_free(ctx); return tot;
}
// — ChaCha20
int chacha20_encrypt(unsigned char* p, int l, unsigned char* o) {
    unsigned char key[32] = { '0' }; unsigned char nonce[12] = { '1' };
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce);
    EVP_EncryptUpdate(ctx, o, &l, p, l);
    EVP_CIPHER_CTX_free(ctx); return l;
}
int chacha20_decrypt(unsigned char* ct, int ctl, unsigned char* o) {
    unsigned char key[32] = { '0' }; unsigned char nonce[12] = { '1' };
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce);
    EVP_DecryptUpdate(ctx, o, &ctl, ct, ctl);
    EVP_CIPHER_CTX_free(ctx); return ctl;
}

/* ---------- 发送线程 ---------- */
void sender(int sock) {
    while (running) {
        string msg; getline(cin, msg);

        /* 结束聊天 */
        if (msg == "end chat") {
            send(sock, "##END##", 8, 0); shutdown(sock, SHUT_RDWR);
            running = false; break;
        }

        /* 换模请求 */
        if (msg == "change mode") {
            cout << "[SERVER] Select new mode (1-5): ";
            string input; getline(cin, input);
            stringstream ss(input);
            int newMode;
            /* 只有合法数字才切换 */
            if (!(ss >> newMode) || newMode < 1 || newMode > 5) {
                cout << "[SERVER] Invalid mode, keep " << mode << ".\n";
                continue;
            }
            mode = newMode;
            string sig = "##CHANGE##";
            send(sock, sig.c_str(), sig.size() + 1, 0);
            send(sock, &mode, sizeof(int), 0);
            continue;
        }

        /* 正常加密发送 */
        unsigned char ct[1024] = { 0 }, tag[16] = { 0 }, mac[32] = { 0 };
        int ctlen = 0;
        const unsigned char* p = (const unsigned char*)msg.c_str();

        if (mode == 1) ctlen = rc4_encrypt(EVP_rc4(), (unsigned char*)p, msg.size(), ct);
        else if (mode == 2) ctlen = rc4_encrypt(EVP_rc4_40(), (unsigned char*)p, msg.size(), ct);
        else if (mode == 3) ctlen = aes_cbc_encrypt((unsigned char*)p, msg.size(), ct);
        else if (mode == 4) ctlen = aes_gcm_encrypt((unsigned char*)p, msg.size(), ct, tag);
        else if (mode == 5) ctlen = chacha20_encrypt((unsigned char*)p, msg.size(), ct);

        cout << "[ME] " << msg << "(ciphertext:" << bytes_to_hex(ct, ctlen) << ")\n";

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
            cout << "[SERVER] Mode changed to: " << mode << endl; continue;
        }

        int ctlen = 0; recv(sock, &ctlen, sizeof(int), 0);
        unsigned char ct[1024] = { 0 }, pt[1024] = { 0 }, tag[16] = { 0 }, mac[32] = { 0 }, calc[32] = { 0 };
        recv(sock, ct, ctlen, 0);
        int ptlen = -1;

        if (mode == 1) ptlen = rc4_decrypt(EVP_rc4(), ct, ctlen, pt);
        else if (mode == 2) ptlen = rc4_decrypt(EVP_rc4_40(), ct, ctlen, pt);
        else if (mode == 3) ptlen = aes_cbc_decrypt(ct, ctlen, pt);
        else if (mode == 4) { recv(sock, tag, 16, 0); ptlen = aes_gcm_decrypt(ct, ctlen, tag, pt); }
        else if (mode == 5) ptlen = chacha20_decrypt(ct, ctlen, pt);

        bool ok = true;
        if (mode <= 3) {
            recv(sock, mac, 32, 0);
            cal_hmac(calc, pt, ptlen);
            ok = memcmp(mac, calc, 32) == 0;
        }
        if (ptlen > 0 && ok) {
            pt[ptlen] = '\0';
            cout << "[FRIEND] " << pt << "(ciphertext:" << bytes_to_hex(ct, ctlen) << ")\n";
        }
        else cout << "[SERVER] Invalid message / HMAC.\n";
    }
}

/* ---------- 主函数 ---------- */
int main() {
    int srvSock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in srvAddr{}, cliAddr{}; socklen_t cliLen = sizeof(cliAddr);
    string ip = "10.9.0.6"; int port = 5194;

    srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &srvAddr.sin_addr);
    bind(srvSock, (sockaddr*)&srvAddr, sizeof(srvAddr));
    listen(srvSock, 1);
    cout << "[SERVER] Waiting on " << ip << ":" << port << "...\n";

    int cliSock = accept(srvSock, (sockaddr*)&cliAddr, &cliLen);
    cout << "[CONNECTED] client joined.\n";
    recv(cliSock, &mode, sizeof(int), 0);
    cout << "[SERVER] Mode set to: " << mode << endl;

    thread t1(sender, cliSock), t2(receiver, cliSock);
    t1.join(); t2.join();
    close(cliSock); close(srvSock);
    cout << "Server shut down.\n";
    return 0;
}
