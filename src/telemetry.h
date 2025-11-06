#ifndef TELEMETRY_H
#define TELEMETRY_H

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstddef>
#include <thread>
#include <mutex>

/* Power of 2 Rule: All loop bounds shall be statically determinable */
#define MAX_TELEMETRY_BUFFER_SIZE 256U
#define MAX_COMMAND_QUEUE_SIZE 16U
#define TELEMETRY_PACKET_SIZE 64U
#define RADIO_TIMEOUT_MS 5000U
#define MAX_RETRY_ATTEMPTS 3U

/* Safety limits for geosynchronous orbit operations */
#define MIN_TRANSMIT_POWER_DBM 10
#define MAX_TRANSMIT_POWER_DBM 50
#define NOMINAL_FREQUENCY_MHZ 8367U /* Legacy integer MHz nominal for compatibility */
#define DOWNLINK_FREQUENCY_KHZ 8367800U /* 8367.800 MHz downlink */
#define UPLINK_FREQUENCY_KHZ 2312400U   /* 2312.400 MHz uplink */
#define NOMINAL_FREQUENCY_KHZ DOWNLINK_FREQUENCY_KHZ
#define FREQUENCY_TOLERANCE_MHZ 50U
#define FREQUENCY_TOLERANCE_KHZ (FREQUENCY_TOLERANCE_MHZ * 1000U)

/* Return codes - explicit error handling required */
typedef enum {
    STATUS_SUCCESS = 0,
    STATUS_ERROR_INVALID_PARAM = 1,
    STATUS_ERROR_TIMEOUT = 2,
    STATUS_ERROR_HARDWARE = 3,
    STATUS_ERROR_BUFFER_FULL = 4,
    STATUS_ERROR_CRC_FAIL = 5,
    STATUS_ERROR_POWER_RANGE = 6
} SystemStatus;

/* Radio operational states */
typedef enum {
    RADIO_STATE_OFF = 0,
    RADIO_STATE_STANDBY = 1,
    RADIO_STATE_RECEIVING = 2,
    RADIO_STATE_TRANSMITTING = 3,
    RADIO_STATE_ERROR = 4
} RadioState;

/* Antenna selection */
typedef enum {
    ANTENNA_UPLINK = 0,
    ANTENNA_DOWNLINK = 1,
    NUM_ANTENNAS
} Antenna;

/* Telemetry packet structure - fixed size for predictability */
typedef struct {
    uint32_t timestamp;
    uint16_t packet_id;
    uint16_t data_length;
    uint8_t data[TELEMETRY_PACKET_SIZE];
    uint16_t crc;
    uint8_t reserved[6]; /* Padding to 80 bytes total */
} TelemetryPacket;

/* Radio configuration structure */
typedef struct {
    uint32_t frequency_mhz;
    int16_t transmit_power_dbm;
    uint16_t data_rate_kbps;
    uint8_t modulation_type;
    uint8_t error_correction_enabled;
    uint16_t reserved;
} RadioConfig;

/* Radio control structure */
typedef struct {
    RadioState current_state;
    RadioConfig config;
    uint32_t packets_transmitted;
    uint32_t packets_received;
    uint32_t error_count;
    uint16_t last_rssi_dbm;
    uint8_t health_status;
    uint8_t reserved;
} RadioControl;

// Function declarations
SystemStatus radio_initialize(void);
SystemStatus radio_set_configuration(Antenna antenna, const RadioConfig* config);
SystemStatus radio_set_state(Antenna antenna, RadioState new_state);
uint32_t radio_get_frequency_khz(Antenna antenna);
SystemStatus telemetry_create_packet(TelemetryPacket* packet,
                                     const uint8_t* data,
                                     uint16_t data_length,
                                     uint32_t timestamp);
SystemStatus telemetry_queue_packet(Antenna antenna, const TelemetryPacket* packet);
SystemStatus radio_transmit_queued_packets(Antenna antenna);
SystemStatus radio_transmit_raw_buffer(Antenna antenna, const uint8_t* data, uint16_t len);
SystemStatus radio_receive_and_respond(const uint8_t* reply_data,
                                      uint16_t reply_len,
                                      uint32_t timestamp);
__attribute__((weak)) void telemetry_hal_on_receive(const uint8_t* data, uint16_t len, uint32_t timestamp);
SystemStatus radio_get_status(Antenna antenna, RadioControl* control);
SystemStatus radio_shutdown(void);
void radio_increment_packets_received(Antenna antenna);
void radio_increment_packets_transmitted(Antenna antenna);
void radio_increment_error_count(Antenna antenna);

#endif // TELEMETRY_H