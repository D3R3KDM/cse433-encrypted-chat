# Encrypted Terminal Chat (CSE 433 Final Project)

A two-party terminal chat application in C++ that encrypts every message with a
selectable symmetric cipher, using OpenSSL. The client and server first perform an
RSA-2048 key exchange to share a random session key and HMAC key, then chat in
full duplex (separate send / receive threads).

## Features

- **RSA key exchange**: each side generates an RSA-2048 key pair; the client sends a
  random 256-bit session key and a 256-bit HMAC key encrypted with the server's public key.
- **Five encryption modes**, selectable at startup and switchable mid-chat:

  | Mode | Cipher | Integrity |
  |------|--------|-----------|
  | 1 | RC4 | HMAC-SHA256 |
  | 2 | RC4-40 (weak, export-grade) | HMAC-SHA256 |
  | 3 | AES-256-CBC | HMAC-SHA256 |
  | 4 | AES-256-GCM | GCM auth tag |
  | 5 | ChaCha20 | none |

- Each message is printed alongside its ciphertext (and IV / nonce) in hex, so the
  effect of each cipher can be observed.
- Invalid HMACs / tags are detected and reported.

## Repository layout

| Path | Description |
|------|-------------|
| `chat_server.cpp`, `chat_client.cpp` | **Final version.** Single-file server and client with RSA key exchange, Windows (MSVC / Winsock) build. |
| `rsa后的server.cpp`, `rsa后的client.cpp` | Linux version after adding RSA key exchange. |
| `server_加入ct_RSA前.cpp`, `client_加入ct_RSA前.cpp` | Earlier Linux version, before ciphertext display and RSA key exchange were added. |
| `Project1/` | Early modular prototype (Visual Studio solution): one class per cipher behind a `SymmetricCipher` interface, plus an `HMACAuthenticator`. |
| `docker-compose的yml.txt` | Docker Compose file for the SEED Ubuntu lab network (`hostA` 10.9.0.5, `hostB` 10.9.0.6). |
| `目前代码说明与后续编译建议.txt` | Original design notes and build instructions (Chinese). |

## Requirements

- A C++11 (or later) compiler
- OpenSSL 3.x development headers and libraries
  - Ubuntu: `sudo apt install libssl-dev`
  - Windows: install [OpenSSL for Windows](https://slproweb.com/products/Win32OpenSSL.html)
    (e.g. to `C:\Program Files\OpenSSL-Win64`) — it is not included in this repository.

## Build and run

### Windows (final version, Visual Studio)

1. Create a console project and add `chat_server.cpp` (or `chat_client.cpp`).
2. Add `<OpenSSL>\include` to **Additional Include Directories** and
   `<OpenSSL>\lib\VC\x64\MD` to **Additional Library Directories**.
   The source already links `ws2_32.lib`, `libssl.lib` and `libcrypto.lib` via `#pragma comment`.
3. Make sure `libssl-3-x64.dll` and `libcrypto-3-x64.dll` are on `PATH` or next to the executable.
4. In `chat_client.cpp`, set `ip` to the server's IPv4 address (default `127.0.0.1`).

### Linux (SEED Ubuntu containers)

```bash
g++ -o server "rsa后的server.cpp" -lssl -lcrypto -pthread
g++ -o client "rsa后的client.cpp" -lssl -lcrypto -pthread
```

Start the server first, then the client (default port **5194**):

```bash
./server   # terminal 1
./client   # terminal 2
```

## Usage

1. Choose an encryption mode (1–5) when prompted.
2. Type messages and press Enter to send.
3. Type `change mode` to switch cipher; the new mode is synchronised to the other side.
4. Type `end chat` to close the connection.

## Notes

This is a course project for studying and comparing ciphers. It uses the deprecated
OpenSSL `RSA_*` API and deliberately includes weak ciphers (RC4, RC4-40), so it is not
intended for real-world secure communication.
