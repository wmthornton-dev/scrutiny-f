#pragma once

#include <cstdint>
#include "telemetry.h"

/* To enable encryption, compile with -DENABLE_PACKET_ENCRYPTION and link with
 * OpenSSL: -lcrypto. The implementation is optional and guarded by
 * USE_OPENSSL in the source file.
 */

#ifdef __cplusplus
extern "C" {
#endif

SystemStatus crypto_initialize(void);
SystemStatus crypto_set_local_private_key_pem(const char* pem, size_t pem_len);
SystemStatus crypto_set_peer_public_key_pem(const char* pem, size_t pem_len);

/* Encrypt a TelemetryPacket into out_buf. out_len must be large enough (>128).
 * Wire format: IV(12) || ciphertext || TAG(16)
 */
SystemStatus crypto_encrypt_packet(const TelemetryPacket* pkt, uint8_t* out_buf, uint16_t* out_len);

/* Decrypt incoming buffer into TelemetryPacket. Expects wire format above. */
SystemStatus crypto_decrypt_packet(const uint8_t* in_buf, uint16_t in_len, TelemetryPacket* out_pkt);

#ifdef __cplusplus
}
#endif
