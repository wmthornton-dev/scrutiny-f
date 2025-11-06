#include "telemetry.h"
#include <thread>
#include <mutex>

// Global state for each antenna
RadioControl g_radio_control[NUM_ANTENNAS];
TelemetryPacket g_tx_buffer[NUM_ANTENNAS][MAX_COMMAND_QUEUE_SIZE];
uint8_t g_tx_buffer_count[NUM_ANTENNAS] = {0U, 0U};
uint32_t g_radio_frequency_khz[NUM_ANTENNAS];

// Mutexes for thread safety
std::recursive_mutex g_radio_mutex[NUM_ANTENNAS];

// Transmitter threads
std::thread g_transmitter_threads[NUM_ANTENNAS];
bool g_transmitter_should_run[NUM_ANTENNAS];

static uint16_t calculate_crc16(const uint8_t* data, uint16_t length)
{
    uint16_t crc = 0xFFFFU;
    uint16_t i;
    uint8_t j;
    
    if (data == NULL) {
        return 0U;
    }
    
    for (i = 0U; i < length; i++) {
        crc ^= (uint16_t)data[i] << 8;
        
        for (j = 0U; j < 8U; j++) {
            if ((crc & 0x8000U) != 0U) {
                crc = (crc << 1) ^ 0x1021U;
            } else {
                crc = crc << 1;
            }
        }
    }
    
    return crc;
}

static SystemStatus validate_radio_config(const RadioConfig* config)
{
    if (config == NULL) {
        return STATUS_ERROR_INVALID_PARAM;
    }
    
    if ((config->transmit_power_dbm < MIN_TRANSMIT_POWER_DBM) ||
        (config->transmit_power_dbm > MAX_TRANSMIT_POWER_DBM)) {
        return STATUS_ERROR_POWER_RANGE;
    }
    
    if ((config->frequency_mhz < (NOMINAL_FREQUENCY_MHZ - FREQUENCY_TOLERANCE_MHZ)) ||
        (config->frequency_mhz > (NOMINAL_FREQUENCY_MHZ + FREQUENCY_TOLERANCE_MHZ))) {
        return STATUS_ERROR_INVALID_PARAM;
    }
    
    return STATUS_SUCCESS;
}

void transmitter_thread_entry(Antenna antenna) {
    while (g_transmitter_should_run[antenna]) {
        if (g_tx_buffer_count[antenna] > 0) {
            radio_transmit_queued_packets(antenna);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

SystemStatus radio_initialize(void)
{
    for (int i = 0; i < NUM_ANTENNAS; ++i) {
        Antenna antenna = static_cast<Antenna>(i);
        std::lock_guard<std::recursive_mutex> lock(g_radio_mutex[antenna]);

        (void)memset(&g_radio_control[antenna], 0, sizeof(RadioControl));
        
        g_radio_control[antenna].current_state = RADIO_STATE_OFF;
        g_radio_control[antenna].config.frequency_mhz = (antenna == ANTENNA_DOWNLINK) ? (DOWNLINK_FREQUENCY_KHZ / 1000U) : (UPLINK_FREQUENCY_KHZ / 1000U);
        g_radio_frequency_khz[antenna] = (antenna == ANTENNA_DOWNLINK) ? DOWNLINK_FREQUENCY_KHZ : UPLINK_FREQUENCY_KHZ;
        g_radio_control[antenna].config.transmit_power_dbm = MIN_TRANSMIT_POWER_DBM;
        g_radio_control[antenna].config.data_rate_kbps = 128U;
        g_radio_control[antenna].config.modulation_type = 1U; /* QPSK */
        g_radio_control[antenna].config.error_correction_enabled = 1U;
        g_radio_control[antenna].health_status = 0xFFU;
        
        (void)memset(g_tx_buffer[antenna], 0, sizeof(g_tx_buffer[antenna]));
        g_tx_buffer_count[antenna] = 0U;

        g_transmitter_should_run[antenna] = true;
        g_transmitter_threads[antenna] = std::thread(transmitter_thread_entry, antenna);
    }
    
    return STATUS_SUCCESS;
}

SystemStatus radio_set_configuration(Antenna antenna, const RadioConfig* config)
{
    std::lock_guard<std::recursive_mutex> lock(g_radio_mutex[antenna]);
    SystemStatus status;
    
    if (config == NULL) {
        return STATUS_ERROR_INVALID_PARAM;
    }
    
    if (g_radio_control[antenna].current_state == RADIO_STATE_TRANSMITTING) {
        return STATUS_ERROR_INVALID_PARAM;
    }
    
    status = validate_radio_config(config);
    if (status != STATUS_SUCCESS) {
        return status;
    }
    
    (void)memcpy(&g_radio_control[antenna].config, config, sizeof(RadioConfig));
    g_radio_frequency_khz[antenna] = (uint32_t)g_radio_control[antenna].config.frequency_mhz * 1000U;
    
    return STATUS_SUCCESS;
}

SystemStatus radio_set_state(Antenna antenna, RadioState new_state)
{
    std::lock_guard<std::recursive_mutex> lock(g_radio_mutex[antenna]);
    RadioState old_state = g_radio_control[antenna].current_state;
    
    if (new_state >= RADIO_STATE_ERROR) {
        return STATUS_ERROR_INVALID_PARAM;
    }
    
    if (old_state == RADIO_STATE_OFF && new_state == RADIO_STATE_TRANSMITTING) {
        return STATUS_ERROR_INVALID_PARAM;
    }
    
    g_radio_control[antenna].current_state = new_state;
    
    return STATUS_SUCCESS;
}

uint32_t radio_get_frequency_khz(Antenna antenna)
{
    std::lock_guard<std::recursive_mutex> lock(g_radio_mutex[antenna]);
    return g_radio_frequency_khz[antenna];
}

SystemStatus telemetry_create_packet(TelemetryPacket* packet,
                                     const uint8_t* data,
                                     uint16_t data_length,
                                     uint32_t timestamp)
{
    uint16_t crc;
    
    if (packet == NULL || data == NULL) {
        return STATUS_ERROR_INVALID_PARAM;
    }
    
    if (data_length > TELEMETRY_PACKET_SIZE) {
        return STATUS_ERROR_INVALID_PARAM;
    }
    
    (void)memset(packet, 0, sizeof(TelemetryPacket));
    
    packet->timestamp = timestamp;
    packet->packet_id = 0; // Packet ID is now assigned by the transmitter
    packet->data_length = data_length;
    
    (void)memcpy(packet->data, data, data_length);
    
    crc = calculate_crc16((const uint8_t*)packet,
                          (uint16_t)(offsetof(TelemetryPacket, crc)));
    packet->crc = crc;
    
    return STATUS_SUCCESS;
}

SystemStatus telemetry_queue_packet(Antenna antenna, const TelemetryPacket* packet)
{
    std::lock_guard<std::recursive_mutex> lock(g_radio_mutex[antenna]);

    if (packet == NULL) {
        return STATUS_ERROR_INVALID_PARAM;
    }
    
    if (g_tx_buffer_count[antenna] >= MAX_COMMAND_QUEUE_SIZE) {
        return STATUS_ERROR_BUFFER_FULL;
    }
    
    (void)memcpy(&g_tx_buffer[antenna][g_tx_buffer_count[antenna]], packet, sizeof(TelemetryPacket));
    g_tx_buffer_count[antenna]++;
    
    return STATUS_SUCCESS;
}

SystemStatus radio_transmit_queued_packets(Antenna antenna)
{
    std::lock_guard<std::recursive_mutex> lock(g_radio_mutex[antenna]);
    uint8_t i;
    uint16_t calculated_crc;
    SystemStatus status;
    
    if (g_radio_control[antenna].current_state != RADIO_STATE_STANDBY) {
        status = radio_set_state(antenna, RADIO_STATE_STANDBY);
        if (status != STATUS_SUCCESS) {
            return status;
        }
    }
    
    if (g_tx_buffer_count[antenna] == 0U) {
        return STATUS_SUCCESS;
    }
    
    status = radio_set_state(antenna, RADIO_STATE_TRANSMITTING);
    if (status != STATUS_SUCCESS) {
        return status;
    }
    
    for (i = 0U; i < g_tx_buffer_count[antenna]; i++) {
        calculated_crc = calculate_crc16(
            (const uint8_t*)&g_tx_buffer[antenna][i],
            (uint16_t)(offsetof(TelemetryPacket, crc))
        );
        
        if (calculated_crc != g_tx_buffer[antenna][i].crc) {
            g_radio_control[antenna].error_count++;
            continue;
        }
        
        g_radio_control[antenna].packets_transmitted++;
    }
    
    g_tx_buffer_count[antenna] = 0U;
    (void)memset(g_tx_buffer[antenna], 0, sizeof(g_tx_buffer[antenna]));
    
    status = radio_set_state(antenna, RADIO_STATE_STANDBY);
    if (status != STATUS_SUCCESS) {
        return status;
    }

    if (antenna == ANTENNA_DOWNLINK) {
        status = radio_set_state(ANTENNA_UPLINK, RADIO_STATE_RECEIVING);
    }

    return status;
}

SystemStatus radio_transmit_raw_buffer(Antenna antenna, const uint8_t* data, uint16_t len)
{
    std::lock_guard<std::recursive_mutex> lock(g_radio_mutex[antenna]);
    SystemStatus status;

    if (g_radio_control[antenna].current_state != RADIO_STATE_STANDBY) {
        status = radio_set_state(antenna, RADIO_STATE_STANDBY);
        if (status != STATUS_SUCCESS) {
            return status;
        }
    }

    status = radio_set_state(antenna, RADIO_STATE_TRANSMITTING);
    if (status != STATUS_SUCCESS) {
        return status;
    }

    g_radio_control[antenna].packets_transmitted++;

    status = radio_set_state(antenna, RADIO_STATE_STANDBY);
    if (status != STATUS_SUCCESS) {
        return status;
    }

    if (antenna == ANTENNA_DOWNLINK) {
        status = radio_set_state(ANTENNA_UPLINK, RADIO_STATE_RECEIVING);
    }

    return status;
}

SystemStatus radio_receive_and_respond(const uint8_t* reply_data,
                                      uint16_t reply_len,
                                      uint32_t timestamp)
{
    SystemStatus status;
    TelemetryPacket pkt;

    if (g_radio_control[ANTENNA_UPLINK].current_state != RADIO_STATE_RECEIVING) {
        return STATUS_ERROR_INVALID_PARAM;
    }

    g_radio_control[ANTENNA_UPLINK].packets_received++;

    if (reply_data == NULL || reply_len == 0U) {
        return STATUS_SUCCESS;
    }

    if (reply_len > TELEMETRY_PACKET_SIZE) {
        return STATUS_ERROR_INVALID_PARAM;
    }

    status = telemetry_create_packet(&pkt, reply_data, reply_len, timestamp);
    if (status != STATUS_SUCCESS) {
        return status;
    }

    status = telemetry_queue_packet(ANTENNA_DOWNLINK, &pkt);
    if (status != STATUS_SUCCESS) {
        return status;
    }

    return status;
}

__attribute__((weak)) void telemetry_hal_on_receive(const uint8_t* data, uint16_t len, uint32_t timestamp)
{
    (void)radio_receive_and_respond(data, len, timestamp);
}

SystemStatus radio_get_status(Antenna antenna, RadioControl* control)
{
    if (control == NULL) {
        return STATUS_ERROR_INVALID_PARAM;
    }
    
    std::lock_guard<std::recursive_mutex> lock(g_radio_mutex[antenna]);
    (void)memcpy(control, &g_radio_control[antenna], sizeof(RadioControl));
    
    return STATUS_SUCCESS;
}

SystemStatus radio_shutdown(void)
{
    for (int i = 0; i < NUM_ANTENNAS; ++i) {
        Antenna antenna = static_cast<Antenna>(i);
        g_transmitter_should_run[antenna] = false;
        if (g_transmitter_threads[antenna].joinable()) {
            g_transmitter_threads[antenna].join();
        }

        std::lock_guard<std::recursive_mutex> lock(g_radio_mutex[antenna]);
        g_radio_control[antenna].current_state = RADIO_STATE_OFF;
        g_tx_buffer_count[antenna] = 0U;
        (void)memset(g_tx_buffer[antenna], 0, sizeof(g_tx_buffer[antenna]));
        g_radio_control[antenna].config.transmit_power_dbm = MIN_TRANSMIT_POWER_DBM;
    }
    
    return STATUS_SUCCESS;
}

void radio_increment_packets_received(Antenna antenna)
{
    std::lock_guard<std::recursive_mutex> lock(g_radio_mutex[antenna]);
    g_radio_control[antenna].packets_received++;
}

void radio_increment_packets_transmitted(Antenna antenna)
{
    std::lock_guard<std::recursive_mutex> lock(g_radio_mutex[antenna]);
    g_radio_control[antenna].packets_transmitted++;
}

void radio_increment_error_count(Antenna antenna)
{
    std::lock_guard<std::recursive_mutex> lock(g_radio_mutex[antenna]);
    g_radio_control[antenna].error_count++;
}
