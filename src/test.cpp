#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include "crypto.h"
#include <vector>
#include <string>
#include <fstream>
#include <chrono>
#include <thread>

// Helper to read a file into a string
static bool read_file_into_string(const std::string& path, std::string& out) {
    std::ifstream fs(path);
    if (!fs) return false;
    out.assign((std::istreambuf_iterator<char>(fs)), std::istreambuf_iterator<char>());
    return true;
}

/* Helpers: write big-endian integers into a buffer (deterministic, bounded) */
static inline void write_u16_be(uint8_t *buf, uint16_t v) {
    buf[0] = (uint8_t)((v >> 8) & 0xFF);
    buf[1] = (uint8_t)(v & 0xFF);
}
static inline void write_u32_be(uint8_t *buf, uint32_t v) {
    buf[0] = (uint8_t)((v >> 24) & 0xFF);
    buf[1] = (uint8_t)((v >> 16) & 0xFF);
    buf[2] = (uint8_t)((v >> 8) & 0xFF);
    buf[3] = (uint8_t)(v & 0xFF);
}
static inline void write_i16_be(uint8_t *buf, int16_t v) {
    write_u16_be(buf, (uint16_t)v);
}
static inline void write_i32_be(uint8_t *buf, int32_t v) {
    write_u32_be(buf, (uint32_t)v);
}

/* Simple deterministic encoder for onboard telemetry into the 64-byte payload.
 * Returns STATUS_SUCCESS and fills out_len with the number of bytes written.
 */
static SystemStatus encode_onboard_telemetry(uint8_t *out_buf, uint16_t *out_len,
                                            uint16_t battery_mV,
                                            int16_t board_temp_deciC,
                                            uint32_t uptime_s,
                                            int32_t sensor1_q16)
{
    if (out_buf == NULL || out_len == NULL) return STATUS_ERROR_INVALID_PARAM;

    const uint16_t max = TELEMETRY_PACKET_SIZE;
    uint16_t idx = 0U;

    /* version */
    if (idx + 1U > max) return STATUS_ERROR_BUFFER_FULL;
    out_buf[idx++] = 1U;

    /* flags */
    if (idx + 1U > max) return STATUS_ERROR_BUFFER_FULL;
    out_buf[idx++] = 0U;

    /* battery_mV */
    if (idx + 2U > max) return STATUS_ERROR_BUFFER_FULL;
    write_u16_be(&out_buf[idx], battery_mV); idx += 2U;

    /* board_temp_deciC */
    if (idx + 2U > max) return STATUS_ERROR_BUFFER_FULL;
    write_i16_be(&out_buf[idx], board_temp_deciC); idx += 2U;

    /* uptime_s */
    if (idx + 4U > max) return STATUS_ERROR_BUFFER_FULL;
    write_u32_be(&out_buf[idx], uptime_s); idx += 4U;

    /* sensor1 (Q16 fixed-point) */
    if (idx + 4U > max) return STATUS_ERROR_BUFFER_FULL;
    write_i32_be(&out_buf[idx], sensor1_q16); idx += 4U;

    /* finished */
    *out_len = idx;
    return STATUS_SUCCESS;
}

/*
 * Example usage and test function
 * This would be replaced with actual mission-specific logic
 */
int main(void)
{
    SystemStatus status;
    TelemetryPacket packet;
    RadioControl radio_status;
    
    /* Prepare example onboard sensor values to encode */
    uint16_t battery_mV = 3700U;          /* 3.7 V */
    int16_t board_temp_deciC = 235;       /* 23.5 C */
    uint32_t uptime_s = 12345U;
    /* Example sensor value in Q16 fixed point (1.234 -> 1.234 * 2^16) */
    int32_t sensor1_q16 = (int32_t)(1.234f * 65536.0f);

#ifdef ENABLE_PACKET_ENCRYPTION
    // Initialize crypto subsystem and load keys
    (void)printf("Initializing crypto subsystem...\n");
    status = crypto_initialize();
    if (status != STATUS_SUCCESS) {
        (void)fprintf(stderr, "Crypto initialization failed: %d\n", status);
        return 1;
    }

    std::string local_key_pem, peer_key_pem;
    if (!read_file_into_string("local_private.pem", local_key_pem)) {
        (void)fprintf(stderr, "Failed to read local_private.pem\n");
        return 1;
    }
    if (!read_file_into_string("peer_public.pem", peer_key_pem)) {
        (void)fprintf(stderr, "Failed to read peer_public.pem\n");
        return 1;
    }

    status = crypto_set_local_private_key_pem(local_key_pem.c_str(), local_key_pem.length());
    if (status != STATUS_SUCCESS) {
        (void)fprintf(stderr, "Failed to load local private key: %d\n", status);
        return 1;
    }

    status = crypto_set_peer_public_key_pem(peer_key_pem.c_str(), peer_key_pem.length());
    if (status != STATUS_SUCCESS) {
        (void)fprintf(stderr, "Failed to load peer public key: %d\n", status);
        return 1;
    }
    (void)printf("Crypto keys loaded successfully.\n");
#endif
    
    /* Initialize radio subsystem */
    status = radio_initialize();
    if (status != STATUS_SUCCESS) {
        (void)fprintf(stderr, "Radio initialization failed: %d\n", status);
        return 1;
    }
    
    (void)printf("Radio subsystem initialized successfully\n");
    
    /* Set radio to standby state */
    status = radio_set_state(ANTENNA_UPLINK, RADIO_STATE_STANDBY);
    if (status != STATUS_SUCCESS) {
        (void)fprintf(stderr, "Failed to set radio state: %d\n", status);
        return 1;
    }
    status = radio_set_state(ANTENNA_DOWNLINK, RADIO_STATE_STANDBY);
    if (status != STATUS_SUCCESS) {
        (void)fprintf(stderr, "Failed to set radio state: %d\n", status);
        return 1;
    }
    
    /* Encode onboard telemetry into a compact payload */
    uint8_t payload[TELEMETRY_PACKET_SIZE];
    uint16_t payload_len = 0U;

    status = encode_onboard_telemetry(payload, &payload_len,
                                      battery_mV,
                                      board_temp_deciC,
                                      uptime_s,
                                      sensor1_q16);
    if (status != STATUS_SUCCESS) {
        (void)fprintf(stderr, "Failed to encode telemetry: %d\n", status);
        return 1;
    }

    status = telemetry_create_packet(&packet, payload, payload_len, 1000U);
    if (status != STATUS_SUCCESS) {
        (void)fprintf(stderr, "Failed to create packet: %d\n", status);
        return 1;
    }

#ifdef ENABLE_PACKET_ENCRYPTION
    (void)printf("Encrypting packet...\n");
    uint8_t encrypted_buf[512];
    uint16_t encrypted_len = 0;
    status = crypto_encrypt_packet(&packet, encrypted_buf, &encrypted_len);
    if (status != STATUS_SUCCESS) {
        (void)fprintf(stderr, "Failed to encrypt packet: %d\n", status);
        return 1;
    }
    (void)printf("Transmitting encrypted packet (%u bytes)...\n", (unsigned)encrypted_len);
    status = radio_transmit_raw_buffer(ANTENNA_DOWNLINK, encrypted_buf, encrypted_len);
#else
    status = telemetry_queue_packet(ANTENNA_DOWNLINK, &packet);
#endif

    if (status != STATUS_SUCCESS) {
        (void)fprintf(stderr, "Failed to transmit packet(s): %d\n", status);
        return 1;
    }

    {
        uint8_t uplink_payload[] = { 0xAA, 0xBB, 0xCC };
        uint16_t uplink_len = (uint16_t)sizeof(uplink_payload);
        uint32_t reply_timestamp = 2000U;

        telemetry_hal_on_receive(uplink_payload, uplink_len, reply_timestamp);
    }

    // Allow time for async transmission
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    /* Get and display radio status */
    for (int i = 0; i < NUM_ANTENNAS; ++i) {
        Antenna antenna = static_cast<Antenna>(i);
        status = radio_get_status(antenna, &radio_status);
        if (status == STATUS_SUCCESS) {
            (void)printf("\nRadio Status (Antenna %d):\n", i);
            (void)printf("  State: %d\n", radio_status.current_state);
            uint32_t khz = radio_get_frequency_khz(antenna);
            (void)printf("  Frequency: %u.%03u MHz\n", khz / 1000U, khz % 1000U);
            (void)printf("  Power: %d dBm\n", radio_status.config.transmit_power_dbm);
            (void)printf("  Packets TX: %u\n", radio_status.packets_transmitted);
            (void)printf("  Packets RX: %u\n", radio_status.packets_received);
            (void)printf("  Errors: %u\n", radio_status.error_count);
        }
    }
    
    /* Shutdown radio subsystem */
    status = radio_shutdown();
    if (status != STATUS_SUCCESS) {
        (void)fprintf(stderr, "Failed to shutdown radio: %d\n", status);
        return 1;
    }
    
    (void)printf("\nRadio subsystem shutdown successfully\n");
    
    return 0;
}
