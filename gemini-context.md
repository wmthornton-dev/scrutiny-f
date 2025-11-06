## Project Overview

This repository contains a safety-critical telemetry radio control library for a satellite, written in a C++11-compatible subset. The implementation is in `src/telemetry.h` and `src/telemetry.cpp`. The project emphasizes deterministic behavior, fixed-size buffers, and bounded loops, with no dynamic memory allocation.

An optional elliptic curve cryptography layer using OpenSSL is available for encrypting telemetry packets (`src/crypto.h`, `src/crypto.cpp`).

A minimal example and test executable is provided in `src/test.cpp`, and unit tests can be found in `Tests/`.

## Key Architectural Points & Data Flow

- **Initialization**: The system is initialized by calling `radio_initialize()`, which sets up the global state and default configurations.
- **Packet Creation**: `telemetry_create_packet()` is used to construct a `TelemetryPacket`, which includes calculating a CRC16 checksum for data integrity.
- **Encryption (Optional)**: If `ENABLE_PACKET_ENCRYPTION` is defined, `crypto_encrypt_packet()` can be used to encrypt a `TelemetryPacket` using ECDH and AES-256-GCM.
- **Transmission**: Packets can be queued for transmission using `telemetry_queue_packet()` and sent with `radio_transmit_queued_packets()`. Alternatively, pre-encrypted or other raw data can be sent using `radio_transmit_raw_buffer()`.

## Coding Conventions and Patterns

- **Deterministic Loops**: All loops must be bounded and statically determinable.
- **Error Handling**: Functions return a `SystemStatus` enum value. Callers are expected to check these return codes. **Exceptions are not used.**
- **Globals**: Global variables are used sparingly to manage state.
- **Configuration**: Buffer sizes and other limits are defined by macros (e.g., `MAX_COMMAND_QUEUE_SIZE`, `TELEMETRY_PACKET_SIZE`).
- **Safety-Critical**: The code is considered safety-critical. Changes should be conservative and accompanied by tests.

## Building and Running

### Main Executable

To build and run the main example (`test.cpp`) without encryption:

```bash
g++ -std=c++11 src/test.cpp src/telemetry.cpp -o bin/telemetry_system
./bin/telemetry_system
```

To build and run with encryption enabled:

```bash
g++ -std=c++11 -DENABLE_PACKET_ENCRYPTION src/test.cpp src/telemetry.cpp src/crypto.cpp -o bin/telemetry_system -lcrypto
./bin/telemetry_system
```

### Tests

To build and run the radio receive tests:

```bash
g++ -std=c++11 Tests/radio_receive_tests.cpp src/telemetry.cpp -o bin/radio_receive_tests
./bin/radio_receive_tests
```

To build and run the cryptography tests:

```bash
g++ -std=c++11 -DENABLE_PACKET_ENCRYPTION Tests/crypto_tests.cpp src/telemetry.cpp src/crypto.cpp -o bin/crypto_tests -lcrypto
./bin/crypto_tests
```

To build and run the encrypted receive test:

```bash
g++ -std=c++11 -I. -DENABLE_PACKET_ENCRYPTION Tests/encrypted_receive_test.cpp src/crypto.cpp src/telemetry.cpp -o bin/encrypted_receive_test -lcrypto -lssl
./bin/encrypted_receive_test
```

## AI Agent Editing Guidelines

- **Preserve Determinism**: Do not introduce unbounded loops or dynamic memory allocation.
- **Follow Error Handling**: Use the `SystemStatus` enum for error handling; do not use exceptions.
- **Document Changes**: Any changes to global state or transmission semantics must be clearly documented with a rationale and accompanied by tests.
- **Reference Existing Code**: `telemetry.h`, `crypto.h`, and the files in `Tests/` are the canonical examples of the project's style and conventions.