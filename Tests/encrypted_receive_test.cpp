#include "src/crypto.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <fstream>
#include <vector>
#include <thread>
#include <chrono>

// Helper to read a file into a string
static bool read_file_into_string(const std::string& path, std::string& out) {
    std::ifstream fs(path);
    if (!fs) return false;
    out.assign((std::istreambuf_iterator<char>(fs)), std::istreambuf_iterator<char>());
    return true;
}

// Global packet for the HAL override to write into
static TelemetryPacket g_decrypted_packet;
static bool g_packet_received = false;

// Override the weak HAL symbol to intercept the received packet
void telemetry_hal_on_receive(const uint8_t* data, uint16_t len, uint32_t timestamp) {
    (void)timestamp; // Not used in this test

    printf("telemetry_hal_on_receive: Received %u bytes. Attempting decryption...\n", len);

    SystemStatus status = crypto_decrypt_packet(data, len, &g_decrypted_packet);
    if (status != STATUS_SUCCESS) {
        fprintf(stderr, "HAL: crypto_decrypt_packet failed: %d\n", status);
        g_packet_received = false;
    } else {
        printf("HAL: Packet decrypted successfully.\n");
        g_packet_received = true;
    }
}

// Simulates the hardware receiving a raw buffer
void mock_hardware_receive(const uint8_t* data, uint16_t len) {
    // In a real system, this would be an interrupt handler from the radio chip.
    // We call the HAL function directly to simulate this.
    telemetry_hal_on_receive(data, len, 12345); // Timestamp doesn't matter for this test
}

int main(void) {
    SystemStatus status;
    TelemetryPacket original_packet;
    uint8_t encrypted_buf[512];
    uint16_t encrypted_len = 0;

    // --- Ground Station Simulation: Encrypt a packet ---
    printf("--- Simulating Ground Station ---\n");

    status = crypto_initialize();
    if (status != STATUS_SUCCESS) {
        fprintf(stderr, "crypto_initialize (ground) failed: %d\n", status);
        return 1;
    }

    // Load ground station's private key and satellite's public key
    std::string ground_private_key_pem, satellite_public_key_pem;
    if (!read_file_into_string("peer_private.pem", ground_private_key_pem)) {
        fprintf(stderr, "Failed to read peer_private.pem for ground station\n");
        return 1;
    }
    if (!read_file_into_string("local_public.pem", satellite_public_key_pem)) {
        fprintf(stderr, "Failed to read local_public.pem for ground station\n");
        return 1;
    }

    status = crypto_set_local_private_key_pem(ground_private_key_pem.c_str(), ground_private_key_pem.length());
    if (status != STATUS_SUCCESS) {
        fprintf(stderr, "crypto_set_local_private_key_pem (ground) failed: %d\n", status);
        return 1;
    }

    status = crypto_set_peer_public_key_pem(satellite_public_key_pem.c_str(), satellite_public_key_pem.length());
    if (status != STATUS_SUCCESS) {
        fprintf(stderr, "crypto_set_peer_public_key_pem (ground) failed: %d\n", status);
        return 1;
    }

    printf("Ground station crypto keys loaded.\n");

    // Create a sample command packet
    memset(&original_packet, 0, sizeof(original_packet));
    original_packet.timestamp = 987654321;
    original_packet.packet_id = 202;
    original_packet.data_length = 8;
    uint8_t command_data[] = { 'C', 'M', 'D', ' ', 'S', 'E', 'T', 'P' };
    memcpy(original_packet.data, command_data, sizeof(command_data));



    // Encrypt the command
    status = crypto_encrypt_packet(&original_packet, encrypted_buf, &encrypted_len);
    if (status != STATUS_SUCCESS) {
        fprintf(stderr, "crypto_encrypt_packet (ground) failed: %d\n", status);
        return 1;
    }
    printf("Ground station encrypted command successfully (ciphertext length: %u).\n", encrypted_len);



    // --- Satellite Simulation: Receive and Decrypt ---
    printf("\n--- Simulating Satellite ---\n");

    // Initialize satellite's radio and crypto systems
    status = radio_initialize();
    if (status != STATUS_SUCCESS) {
        fprintf(stderr, "radio_initialize (satellite) failed: %d\n", status);
        return 1;
    }

    status = crypto_initialize();
    if (status != STATUS_SUCCESS) {
        fprintf(stderr, "crypto_initialize (satellite) failed: %d\n", status);
        return 1;
    }

    // Load satellite's private key and ground station's public key
    std::string satellite_private_key_pem, ground_public_key_pem;
    if (!read_file_into_string("local_private.pem", satellite_private_key_pem)) {
        fprintf(stderr, "Failed to read local_private.pem for satellite\n");
        return 1;
    }
    if (!read_file_into_string("peer_public.pem", ground_public_key_pem)) {
        fprintf(stderr, "Failed to read peer_public.pem for satellite\n");
        return 1;
    }

    status = crypto_set_local_private_key_pem(satellite_private_key_pem.c_str(), satellite_private_key_pem.length());
    if (status != STATUS_SUCCESS) {
        fprintf(stderr, "crypto_set_local_private_key_pem (satellite) failed: %d\n", status);
        return 1;
    }

    status = crypto_set_peer_public_key_pem(ground_public_key_pem.c_str(), ground_public_key_pem.length());
    if (status != STATUS_SUCCESS) {
        fprintf(stderr, "crypto_set_peer_public_key_pem (satellite) failed: %d\n", status);
        return 1;
    }

    printf("Satellite crypto keys loaded.\n");

    // Set radio to uplink frequency and enter receiving state
    status = radio_set_state(ANTENNA_UPLINK, RADIO_STATE_RECEIVING);
    if (status != STATUS_SUCCESS) {
        fprintf(stderr, "radio_set_state to RECEIVING failed: %d\n", status);
        return 1;
    }
    printf("Radio is in RECEIVING state.\n");

    // Simulate the hardware receiving the encrypted buffer from the ground
    printf("Simulating hardware reception of encrypted command...\n");
    mock_hardware_receive(encrypted_buf, encrypted_len);



    // --- Verification ---
    printf("\n--- Verifying Result ---\n");

    if (!g_packet_received) {
        fprintf(stderr, "Test Failed: Packet was not successfully received and decrypted by the HAL.\n");
        radio_shutdown();
        return 1;
    }

    // Compare the decrypted packet with the original
    if (memcmp(&original_packet, &g_decrypted_packet, sizeof(TelemetryPacket)) == 0) {
        printf("Test Passed: Decrypted packet matches the original command.\n");
    } else {
        fprintf(stderr, "Test Failed: Decrypted packet does not match the original.\n");
        radio_shutdown();
        return 1;
    }

    radio_shutdown();
    return 0;
}