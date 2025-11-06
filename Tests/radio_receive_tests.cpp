#include <cstdio>
#include "../src/telemetry.h"

int main(void)
{
    SystemStatus st;
    TelemetryPacket pkt;
    uint8_t payload[TELEMETRY_PACKET_SIZE];
    uint16_t payload_len;
    uint8_t i;

    /* Test 1: happy path - receive and respond */
    st = radio_initialize();
    if (st != STATUS_SUCCESS) {
        std::fprintf(stderr, "radio_initialize failed: %d\n", st);
        return 2;
    }

    st = radio_set_state(RADIO_STATE_STANDBY);
    if (st != STATUS_SUCCESS) {
        std::fprintf(stderr, "radio_set_state failed: %d\n", st);
        return 2;
    }

    /* queue one packet and transmit to get into RECEIVING (uplink) state */
    payload_len = 4;
    payload[0] = 1; payload[1] = 2; payload[2] = 3; payload[3] = 4;
    st = telemetry_create_packet(&pkt, payload, payload_len, 1000U);
    if (st != STATUS_SUCCESS) { std::fprintf(stderr, "create failed\n"); return 2; }
    st = telemetry_queue_packet(&pkt);
    if (st != STATUS_SUCCESS) { std::fprintf(stderr, "queue failed\n"); return 2; }

    st = radio_transmit_queued_packets();
    if (st != STATUS_SUCCESS) { std::fprintf(stderr, "transmit failed: %d\n", st); return 2; }

    /* Now simulate uplink receive with a small reply payload */
    uint8_t reply[] = { 0xDE, 0xAD };
    st = radio_receive_and_respond(reply, (uint16_t)sizeof(reply), 2000U);
    if (st != STATUS_SUCCESS) {
        std::fprintf(stderr, "radio_receive_and_respond (happy) failed: %d\n", st);
        return 2;
    }

    std::printf("Test 1 (happy path) passed\n");

    /* Test 2: queue-full edge case */
    st = radio_initialize();
    if (st != STATUS_SUCCESS) { std::fprintf(stderr, "radio_initialize failed\n"); return 3; }

    /* Fill the transmit queue */
    for (i = 0; i < MAX_COMMAND_QUEUE_SIZE; ++i) {
        st = telemetry_create_packet(&pkt, payload, payload_len, 3000U + i);
        if (st != STATUS_SUCCESS) { std::fprintf(stderr, "create failed\n"); return 3; }
        st = telemetry_queue_packet(&pkt);
        if (st != STATUS_SUCCESS) { std::fprintf(stderr, "queue failed at idx %u\n", (unsigned)i); return 3; }
    }

    /* Ensure state is RECEIVING */
    st = radio_set_state(RADIO_STATE_RECEIVING);
    if (st != STATUS_SUCCESS) { std::fprintf(stderr, "set_state failed\n"); return 3; }

    /* Now attempt to respond; should fail with buffer full */
    st = radio_receive_and_respond(reply, (uint16_t)sizeof(reply), 4000U);
    if (st != STATUS_ERROR_BUFFER_FULL) {
        std::fprintf(stderr, "Expected STATUS_ERROR_BUFFER_FULL, got %d\n", st);
        return 3;
    }

    std::printf("Test 2 (queue-full) passed\n");
    return 0;
}
