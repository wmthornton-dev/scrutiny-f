/*******************************************************************************
* NASA Open Source Agreement
* 
* Copyright (c) 2025 United States Government as represented by the
* Administrator of the National Aeronautics and Space Administration.
* All Rights Reserved.
*
* This software is licensed under the NASA Open Source Agreement (NOSA) version 1.3
* 
* Program: Satellite Telemetry Radio Control System (STRCS-MAILDROP)
* Purpose: Control telemetry radio systems for high geosynchronous orbit satellite
* 
* Description:
*   [Detailed description of the program's functionality and objectives.]
*   
*   
*
*   Key Features:
*   - [Feature]
*
*
*   Security Considerations:
*   - [Security Consideration]
*   
*
* Author: [Your Name]
* Date: [Current Date]
*
* Version: [Version]
*
* Dependencies:
*   - [Dependency]
*  
*
* Usage:
*   
*
* Notes:
*   
*   
*******************************************************************************/

/*
 * Satellite Telemetry Radio Control System
 * 
 * Purpose: Control telemetry radio systems for high geosynchronous orbit satellite
 * Compliant with: NASA JPL Institutional Coding Standard (JPL DOCID D-60411)
 * Language: C++ (C++11 compatible subset)
 * 
 * Safety-Critical System - DO NOT MODIFY WITHOUT REVIEW
 */

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstddef>

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
/* Note: we preserve the existing RadioConfig.frequency_mhz (integer MHz)
 * layout for ABI/assembly compatibility. For higher precision (fractions of
 * MHz) use the new radio_get_frequency_khz()/radio_set_downlink()/radio_set_uplink()
 * APIs which maintain the integer MHz field for backwards compatibility.
 */

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

/* Global state - minimized per NASA guidelines */
static RadioControl g_radio_control;
static TelemetryPacket g_tx_buffer[MAX_COMMAND_QUEUE_SIZE];
static uint8_t g_tx_buffer_count = 0U;
/* High-precision runtime frequency (kHz). Initialized to downlink by default. */
static uint32_t g_radio_frequency_khz = DOWNLINK_FREQUENCY_KHZ;

/*
 * Function: calculate_crc16
 * Purpose: Calculate CRC-16-CCITT for data integrity
 * Parameters:
 *   data - pointer to data buffer (must not be NULL)
 *   length - number of bytes to process
 * Returns: 16-bit CRC value
 * Preconditions: data != NULL, length > 0
 */
static uint16_t calculate_crc16(const uint8_t* data, uint16_t length)
{
    uint16_t crc = 0xFFFFU;
    uint16_t i;
    uint8_t j;
    
    /* NULL pointer check - defensive programming */
    if (data == NULL) {
        return 0U;
    }
    
    /* Bounded loop - satisfies NASA loop requirements */
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

/*
 * Function: validate_radio_config
 * Purpose: Validate radio configuration parameters
 * Parameters:
 *   config - pointer to configuration structure
 * Returns: STATUS_SUCCESS or appropriate error code
 * Preconditions: config != NULL
 */
static SystemStatus validate_radio_config(const RadioConfig* config)
{
    /* NULL pointer check */
    if (config == NULL) {
        return STATUS_ERROR_INVALID_PARAM;
    }
    
    /* Validate power levels */
    if ((config->transmit_power_dbm < MIN_TRANSMIT_POWER_DBM) ||
        (config->transmit_power_dbm > MAX_TRANSMIT_POWER_DBM)) {
        return STATUS_ERROR_POWER_RANGE;
    }
    
    /* Validate frequency range for geosynchronous operations */
    if ((config->frequency_mhz < (NOMINAL_FREQUENCY_MHZ - FREQUENCY_TOLERANCE_MHZ)) ||
        (config->frequency_mhz > (NOMINAL_FREQUENCY_MHZ + FREQUENCY_TOLERANCE_MHZ))) {
        return STATUS_ERROR_INVALID_PARAM;
    }
    
    return STATUS_SUCCESS;
}

/*
 * Function: radio_initialize
 * Purpose: Initialize radio subsystem to known safe state
 * Parameters: None
 * Returns: STATUS_SUCCESS or appropriate error code
 * Side effects: Resets global radio control structure
 */
SystemStatus radio_initialize(void)
{
    /* Initialize to zero - ensures deterministic state */
    (void)memset(&g_radio_control, 0, sizeof(RadioControl));
    
    /* Set safe default configuration */
    g_radio_control.current_state = RADIO_STATE_OFF;
    /* Set integer MHz field for compatibility and high-precision kHz default */
    g_radio_control.config.frequency_mhz = NOMINAL_FREQUENCY_MHZ;
    g_radio_frequency_khz = NOMINAL_FREQUENCY_KHZ;
    g_radio_control.config.transmit_power_dbm = MIN_TRANSMIT_POWER_DBM;
    g_radio_control.config.data_rate_kbps = 128U;
    g_radio_control.config.modulation_type = 1U; /* QPSK */
    g_radio_control.config.error_correction_enabled = 1U;
    g_radio_control.health_status = 0xFFU; /* All systems nominal */
    
    /* Clear transmit buffer */
    (void)memset(g_tx_buffer, 0, sizeof(g_tx_buffer));
    g_tx_buffer_count = 0U;
    
    return STATUS_SUCCESS;
}

/*
 * Function: radio_set_configuration
 * Purpose: Apply new radio configuration with validation
 * Parameters:
 *   config - pointer to new configuration
 * Returns: STATUS_SUCCESS or appropriate error code
 * Preconditions: Radio must be in STANDBY or OFF state
 */
SystemStatus radio_set_configuration(const RadioConfig* config)
{
    SystemStatus status;
    
    /* Parameter validation */
    if (config == NULL) {
        return STATUS_ERROR_INVALID_PARAM;
    }
    
    /* State check - cannot reconfigure while transmitting */
    if (g_radio_control.current_state == RADIO_STATE_TRANSMITTING) {
        return STATUS_ERROR_INVALID_PARAM;
    }
    
    /* Validate configuration parameters */
    status = validate_radio_config(config);
    if (status != STATUS_SUCCESS) {
        return status;
    }
    
    /* Apply configuration - atomic operation */
    (void)memcpy(&g_radio_control.config, config, sizeof(RadioConfig));

    /* Maintain high-precision runtime frequency (kHz) from integer MHz field.
     * We keep the kHz value set to the integer MHz * 1000 to avoid surprising
     * changes to existing callers that expect integer MHz semantics. Callers
     * that require fractional MHz should call radio_set_downlink()/radio_set_uplink().
     */
    g_radio_frequency_khz = (uint32_t)g_radio_control.config.frequency_mhz * 1000U;
    
    return STATUS_SUCCESS;
}

/*
 * Function: radio_set_state
 * Purpose: Transition radio to new operational state
 * Parameters:
 *   new_state - target state
 * Returns: STATUS_SUCCESS or appropriate error code
 * Side effects: Updates global radio state
 */
SystemStatus radio_set_state(RadioState new_state)
{
    RadioState old_state = g_radio_control.current_state;
    
    /* Validate state transition */
    if (new_state >= RADIO_STATE_ERROR) {
        return STATUS_ERROR_INVALID_PARAM;
    }
    
    /* Check for valid state transitions */
    if (old_state == RADIO_STATE_OFF && new_state == RADIO_STATE_TRANSMITTING) {
        /* Cannot go directly from OFF to TRANSMITTING */
        return STATUS_ERROR_INVALID_PARAM;
    }
    
    /* Update state */
    g_radio_control.current_state = new_state;
    
    return STATUS_SUCCESS;
}

/* Set radio to the mission-defined downlink frequency (high precision). */
SystemStatus radio_set_downlink(void)
{
    /* Disallow switching to downlink while transmitting */
    if (g_radio_control.current_state == RADIO_STATE_TRANSMITTING) {
        return STATUS_ERROR_INVALID_PARAM;
    }

    g_radio_frequency_khz = DOWNLINK_FREQUENCY_KHZ;
    g_radio_control.config.frequency_mhz = (uint32_t)(g_radio_frequency_khz / 1000U);

    return STATUS_SUCCESS;
}

/* Set radio to the mission-defined uplink frequency (high precision). */
SystemStatus radio_set_uplink(void)
{
    if (g_radio_control.current_state == RADIO_STATE_TRANSMITTING) {
        return STATUS_ERROR_INVALID_PARAM;
    }

    g_radio_frequency_khz = UPLINK_FREQUENCY_KHZ;
    g_radio_control.config.frequency_mhz = (uint32_t)(g_radio_frequency_khz / 1000U);

    return STATUS_SUCCESS;
}

/* Return the currently configured radio frequency in kHz (high precision). */
uint32_t radio_get_frequency_khz(void)
{
    return g_radio_frequency_khz;
}

/*
 * Function: telemetry_create_packet
 * Purpose: Create properly formatted telemetry packet
 * Parameters:
 *   packet - pointer to packet structure to populate
 *   data - pointer to payload data
 *   data_length - length of payload (must be <= TELEMETRY_PACKET_SIZE)
 *   timestamp - packet timestamp
 * Returns: STATUS_SUCCESS or appropriate error code
 */
SystemStatus telemetry_create_packet(TelemetryPacket* packet,
                                     const uint8_t* data,
                                     uint16_t data_length,
                                     uint32_t timestamp)
{
    uint16_t crc;
    
    /* Parameter validation */
    if (packet == NULL || data == NULL) {
        return STATUS_ERROR_INVALID_PARAM;
    }
    
    if (data_length > TELEMETRY_PACKET_SIZE) {
        return STATUS_ERROR_INVALID_PARAM;
    }
    
    /* Initialize packet structure */
    (void)memset(packet, 0, sizeof(TelemetryPacket));
    
    /* Populate packet fields */
    packet->timestamp = timestamp;
    packet->packet_id = (uint16_t)(g_radio_control.packets_transmitted & 0xFFFFU);
    packet->data_length = data_length;
    
    /* Copy payload data */
    (void)memcpy(packet->data, data, data_length);
    
    /* Calculate and store CRC over entire packet except CRC field */
    crc = calculate_crc16((const uint8_t*)packet,
                          (uint16_t)(offsetof(TelemetryPacket, crc)));
    packet->crc = crc;
    
    return STATUS_SUCCESS;
}

/*
 * Function: telemetry_queue_packet
 * Purpose: Add packet to transmission queue
 * Parameters:
 *   packet - pointer to packet to queue
 * Returns: STATUS_SUCCESS or appropriate error code
 * Preconditions: packet != NULL
 */
SystemStatus telemetry_queue_packet(const TelemetryPacket* packet)
{
    /* Parameter validation */
    if (packet == NULL) {
        return STATUS_ERROR_INVALID_PARAM;
    }
    
    /* Check queue capacity */
    if (g_tx_buffer_count >= MAX_COMMAND_QUEUE_SIZE) {
        return STATUS_ERROR_BUFFER_FULL;
    }
    
    /* Add packet to queue */
    (void)memcpy(&g_tx_buffer[g_tx_buffer_count], packet, sizeof(TelemetryPacket));
    g_tx_buffer_count++;
    
    return STATUS_SUCCESS;
}

/*
 * Function: radio_transmit_queued_packets
 * Purpose: Transmit all queued telemetry packets
 * Parameters: None
 * Returns: STATUS_SUCCESS or appropriate error code
 * Side effects: Clears transmit queue on success
 */
SystemStatus radio_transmit_queued_packets(void)
{
    uint8_t i;
    uint16_t calculated_crc;
    SystemStatus status;
    
    /* Check radio state */
    if (g_radio_control.current_state != RADIO_STATE_STANDBY) {
        status = radio_set_state(RADIO_STATE_STANDBY);
        if (status != STATUS_SUCCESS) {
            return status;
        }
    }
    
    /* Check if queue is empty */
    if (g_tx_buffer_count == 0U) {
        return STATUS_SUCCESS;
    }
    
    /* Transition to transmit state */
    status = radio_set_state(RADIO_STATE_TRANSMITTING);
    if (status != STATUS_SUCCESS) {
        return status;
    }
    
    /* Process each packet in queue - bounded loop */
    for (i = 0U; i < g_tx_buffer_count; i++) {
        /* Verify packet integrity before transmission */
        calculated_crc = calculate_crc16(
            (const uint8_t*)&g_tx_buffer[i],
            (uint16_t)(offsetof(TelemetryPacket, crc))
        );
        
        if (calculated_crc != g_tx_buffer[i].crc) {
            g_radio_control.error_count++;
            continue; /* Skip corrupted packet */
        }
        
        /* 
         * Hardware transmission would occur here
         * For this example, we simulate successful transmission
         */
        g_radio_control.packets_transmitted++;
    }
    
    /* Clear queue after transmission */
    g_tx_buffer_count = 0U;
    (void)memset(g_tx_buffer, 0, sizeof(g_tx_buffer));
    
    /* After downlink transmission, switch to uplink and enter receiving state.
     * This models the mission behavior where the modem transmits (downlink)
     * then listens for replies on the uplink frequency.
     */
    status = radio_set_state(RADIO_STATE_STANDBY);
    if (status != STATUS_SUCCESS) {
        return status;
    }

    /* Set to uplink frequency and receiving state */
    status = radio_set_uplink();
    if (status != STATUS_SUCCESS) {
        return status;
    }

    status = radio_set_state(RADIO_STATE_RECEIVING);

    return status;
}

/*
 * Function: radio_receive_and_respond
 * Purpose: Simulate receiving data on the uplink and optionally send a reply.
 * Parameters:
 *   reply_data - pointer to reply payload (may be NULL if no reply)
 *   reply_len  - length of reply payload (must be <= TELEMETRY_PACKET_SIZE)
 *   timestamp  - timestamp to use for the reply packet if one is sent
 * Returns: STATUS_SUCCESS or appropriate error code
 *
 * Notes: This is a simple simulated receive/respond flow suitable for the
 * example code and unit tests. In a real system, reception would be driven by
 * hardware interrupts and a proper RX path; this function intentionally keeps
 * behavior deterministic and bounded to fit the project's safety constraints.
 */
SystemStatus radio_receive_and_respond(const uint8_t* reply_data,
                                      uint16_t reply_len,
                                      uint32_t timestamp)
{
    SystemStatus status;
    TelemetryPacket pkt;

    /* Must be in receiving state to accept incoming data */
    if (g_radio_control.current_state != RADIO_STATE_RECEIVING) {
        return STATUS_ERROR_INVALID_PARAM;
    }

    /* Simulate that a packet was received on the uplink */
    g_radio_control.packets_received++;

    /* If no reply requested, remain in receiving state */
    if (reply_data == NULL || reply_len == 0U) {
        return STATUS_SUCCESS;
    }

    /* Validate reply size */
    if (reply_len > TELEMETRY_PACKET_SIZE) {
        return STATUS_ERROR_INVALID_PARAM;
    }

    /* Create reply packet using library helper (computes CRC) */
    status = telemetry_create_packet(&pkt, reply_data, reply_len, timestamp);
    if (status != STATUS_SUCCESS) {
        return status;
    }

    /* Queue the reply for transmission */
    status = telemetry_queue_packet(&pkt);
    if (status != STATUS_SUCCESS) {
        return status;
    }

    /* Switch to downlink frequency and send the queued reply immediately */
    status = radio_set_downlink();
    if (status != STATUS_SUCCESS) {
        return status;
    }

    /* Transmit queued reply; radio_transmit_queued_packets will switch back to uplink */
    status = radio_transmit_queued_packets();

    return status;
}

/* Weak HAL hook: platform/hardware layer may override this symbol to signal
 * that uplink data has arrived. The default implementation calls the
 * deterministic radio_receive_and_respond() helper so tests and examples
 * work without a HAL. Platforms may provide their own implementation;
 * the symbol is weak to allow that override.
 */
__attribute__((weak)) void telemetry_hal_on_receive(const uint8_t* data, uint16_t len, uint32_t timestamp)
{
    /* Default behavior: directly handle receive-and-respond */
    (void)radio_receive_and_respond(data, len, timestamp);
}

/*
 * Function: radio_get_status
 * Purpose: Retrieve current radio system status
 * Parameters:
 *   control - pointer to structure to receive status
 * Returns: STATUS_SUCCESS or appropriate error code
 */
SystemStatus radio_get_status(RadioControl* control)
{
    if (control == NULL) {
        return STATUS_ERROR_INVALID_PARAM;
    }
    
    /* Copy current status - atomic read */
    (void)memcpy(control, &g_radio_control, sizeof(RadioControl));
    
    return STATUS_SUCCESS;
}

/*
 * Function: radio_shutdown
 * Purpose: Safely shutdown radio subsystem
 * Parameters: None
 * Returns: STATUS_SUCCESS or appropriate error code
 * Side effects: Clears all buffers and resets state
 */
SystemStatus radio_shutdown(void)
{
    /* Transition to safe state */
    g_radio_control.current_state = RADIO_STATE_OFF;
    
    /* Clear all buffers */
    g_tx_buffer_count = 0U;
    (void)memset(g_tx_buffer, 0, sizeof(g_tx_buffer));
    
    /* Reduce power to minimum */
    g_radio_control.config.transmit_power_dbm = MIN_TRANSMIT_POWER_DBM;
    
    return STATUS_SUCCESS;
}

