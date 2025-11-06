#include <iostream>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fstream>

#include "src/crypto.h"
#include "src/telemetry.h"

#define PORT 12345

// Helper to read a file into a string
static bool read_file_into_string(const std::string& path, std::string& out) {
    std::ifstream fs(path);
    if (!fs) return false;
    out.assign((std::istreambuf_iterator<char>(fs)), std::istreambuf_iterator<char>());
    return true;
}

int main(int argc, char const *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <data_to_send>" << std::endl;
        return 1;
    }

    std::string data_to_send = argv[1];

    SystemStatus status;

    // Initialize crypto
    status = crypto_initialize();
    if (status != STATUS_SUCCESS) {
        std::cerr << "Crypto initialization failed: " << status << std::endl;
        return 1;
    }

    // Load keys (reverse of network_test)
    std::string local_key_pem, peer_key_pem;
    if (!read_file_into_string("peer_private.pem", local_key_pem)) {
        std::cerr << "Failed to read peer_private.pem" << std::endl;
        return 1;
    }
    if (!read_file_into_string("local_public.pem", peer_key_pem)) {
        std::cerr << "Failed to read local_public.pem" << std::endl;
        return 1;
    }

    status = crypto_set_local_private_key_pem(local_key_pem.c_str(), local_key_pem.length());
    if (status != STATUS_SUCCESS) {
        std::cerr << "Failed to load local private key: " << status << std::endl;
        return 1;
    }

    status = crypto_set_peer_public_key_pem(peer_key_pem.c_str(), peer_key_pem.length());
    if (status != STATUS_SUCCESS) {
        std::cerr << "Failed to load peer public key: " << status << std::endl;
        return 1;
    }

    // Create packet
    TelemetryPacket packet;
    telemetry_create_packet(&packet, (const uint8_t*)data_to_send.c_str(), data_to_send.length(), time(NULL));

    // Encrypt packet
    uint8_t encrypted_buf[512];
    uint16_t encrypted_len = 0;
    crypto_encrypt_packet(&packet, encrypted_buf, &encrypted_len);

    // Create socket and connect
    int sock = 0;
    struct sockaddr_in serv_addr;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        return 1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) {
        perror("inet_pton failed");
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect failed");
        return 1;
    }

    // Send packet
    if (send(sock, encrypted_buf, encrypted_len, 0) < 0) {
        perror("send failed");
        return 1;
    }

    std::cout << "Sent encrypted packet with data: \"" << data_to_send << "\"" << std::endl;

    close(sock);

    return 0;
}
