#include "../src/crypto.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <fstream>
#include <vector>

// Helper to read a file into a string
static bool read_file_into_string(const std::string& path, std::string& out) {
    std::ifstream fs(path);
    if (!fs) return false;
    out.assign((std::istreambuf_iterator<char>(fs)), std::istreambuf_iterator<char>());
    return true;
}

int main(void) {
    SystemStatus status;

    // Initialize crypto subsystem
    status = crypto_initialize();
    if (status != STATUS_SUCCESS) {
        fprintf(stderr, "crypto_initialize failed: %d\n", status);
        return 1;
    }

    // Load keys
    std::string local_key_pem, peer_key_pem;
    if (!read_file_into_string("local_private.pem", local_key_pem)) {
        fprintf(stderr, "Failed to read local_private.pem\n");
        return 1;
    }
    if (!read_file_into_string("peer_public.pem", peer_key_pem)) {
        fprintf(stderr, "Failed to read peer_public.pem\n");
        return 1;
    }

    status = crypto_set_local_private_key_pem(local_key_pem.c_str(), local_key_pem.length());
    if (status != STATUS_SUCCESS) {
        fprintf(stderr, "crypto_set_local_private_key_pem failed: %d\n", status);
        return 1;
    }

    status = crypto_set_peer_public_key_pem(peer_key_pem.c_str(), peer_key_pem.length());
    if (status != STATUS_SUCCESS) {
        fprintf(stderr, "crypto_set_peer_public_key_pem failed: %d\n", status);
        return 1;
    }

    printf("Crypto keys loaded.\n");

    // Create a sample packet
    TelemetryPacket original_packet;
    memset(&original_packet, 0, sizeof(original_packet));
    original_packet.timestamp = 1234567890;
    original_packet.packet_id = 101;
    original_packet.data_length = 4;
    original_packet.data[0] = 0xDE;
    original_packet.data[1] = 0xAD;
    original_packet.data[2] = 0xBE;
    original_packet.data[3] = 0xEF;

    // Encrypt the packet
    uint8_t encrypted_buf[512];
    uint16_t encrypted_len = 0;

    status = crypto_encrypt_packet(&original_packet, encrypted_buf, &encrypted_len);
    if (status != STATUS_SUCCESS) {
        fprintf(stderr, "crypto_encrypt_packet failed: %d\n", status);
        return 1;
    }

    printf("Packet encrypted successfully (ciphertext length: %u).\n", encrypted_len);

    // Decrypt the packet
    TelemetryPacket decrypted_packet;
    status = crypto_decrypt_packet(encrypted_buf, encrypted_len, &decrypted_packet);
    if (status != STATUS_SUCCESS) {
        fprintf(stderr, "crypto_decrypt_packet failed: %d\n", status);
        return 1;
    }

    printf("Packet decrypted successfully.\n");

    // Verify the result
    if (memcmp(&original_packet, &decrypted_packet, sizeof(TelemetryPacket)) == 0) {
        printf("Test Passed: Decrypted packet matches the original.\n");
    } else {
        fprintf(stderr, "Test Failed: Decrypted packet does not match the original.\n");
        return 1;
    }

    return 0;
}
