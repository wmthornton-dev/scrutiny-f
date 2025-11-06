#include "telemetry.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

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
    
    /* Initialize radio subsystem */
    status = radio_initialize();
    if (status != STATUS_SUCCESS) {
        (void)fprintf(stderr, "Radio initialization failed: %d\n", status);
        return 1;
    }
    
    (void)printf("Radio subsystem initialized successfully\n");
    
    /* Set radio to standby state */
    status = radio_set_state(RADIO_STATE_STANDBY);
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

    /* Create and queue telemetry packet using the library API (it will compute CRC) */
    status = telemetry_create_packet(&packet, payload, payload_len, 1000U);
    if (status != STATUS_SUCCESS) {
        (void)fprintf(stderr, "Failed to create packet: %d\n", status);
        return 1;
    }

    status = telemetry_queue_packet(&packet);
    if (status != STATUS_SUCCESS) {
        (void)fprintf(stderr, "Failed to queue packet: %d\n", status);
        return 1;
    }

    (void)printf("Telemetry packet queued (payload %u bytes)\n", (unsigned)payload_len);
    
    /* Transmit queued packets (downlink). This will switch the radio to
     * uplink/RECEIVING state when complete according to
     * radio_transmit_queued_packets().
     */
    status = radio_transmit_queued_packets();
    if (status != STATUS_SUCCESS) {
        (void)fprintf(stderr, "Failed to transmit packets: %d\n", status);
        return 1;
    }

    /* At this point, radio is in RECEIVING state on the uplink frequency.
     * Simulate an uplink reception via the HAL weak hook. The default
     * implementation of telemetry_hal_on_receive() calls
     * radio_receive_and_respond(), which will queue a reply and trigger
     * a downlink send.
     */
    {
        uint8_t uplink_payload[] = { 0xAA, 0xBB, 0xCC };
        uint16_t uplink_len = (uint16_t)sizeof(uplink_payload);
        uint32_t reply_timestamp = 2000U;

        /* Signal the HAL receive hook; in production, the HAL would call this
         * when data arrives from the modem. The header provides a weak default
         * that uses radio_receive_and_respond().
         */
        telemetry_hal_on_receive(uplink_payload, uplink_len, reply_timestamp);
    }
    
    /* Get and display radio status */
    status = radio_get_status(&radio_status);
    if (status == STATUS_SUCCESS) {
        (void)printf("\nRadio Status:\n");
    (void)printf("  State: %d\n", radio_status.current_state);
    uint32_t khz = radio_get_frequency_khz();
    (void)printf("  Frequency: %u.%03u MHz\n", khz / 1000U, khz % 1000U);
        (void)printf("  Power: %d dBm\n", radio_status.config.transmit_power_dbm);
        (void)printf("  Packets TX: %u\n", radio_status.packets_transmitted);
        (void)printf("  Packets RX: %u\n", radio_status.packets_received);
        (void)printf("  Errors: %u\n", radio_status.error_count);
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