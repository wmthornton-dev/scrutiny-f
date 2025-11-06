## Project Overview

This repository contains a safety-critical telemetry radio control library for a satellite, written in a C++11-compatible subset. The implementation is in `src/telemetry.h` and `src/telemetry.cpp`. The project emphasizes deterministic behavior, fixed-size buffers, and bounded loops, with no dynamic memory allocation.

An optional elliptic curve cryptography layer using OpenSSL is available for encrypting telemetry packets (`src/crypto.h`, `src/crypto.cpp`).

A minimal example and test executable is provided in `src/test.cpp`. Additional test programs include `src/network_test.cpp` for network-based testing, `src/send_packet.cpp` for sending encrypted data, and `src/monitor_traffic.cpp` for monitoring network traffic. Unit tests can be found in `Tests/`.

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

### Network Test

To build and run the network test executable:

```bash
g++ -std=c++11 -pthread -I. src/network_test.cpp src/telemetry.cpp src/crypto.cpp -o bin/network_test -lcrypto -lssl -Wl,--no-as-needed
./bin/network_test
```

### Send Packet

To build and run the send packet executable:

```bash
g++ -std=c++11 -I. src/send_packet.cpp src/telemetry.cpp src/crypto.cpp -o bin/send_packet -lcrypto -lssl
./bin/send_packet
```

### Monitor Traffic

To build and run the monitor traffic executable:

```bash
g++ -std=c++11 -pthread -DENABLE_PACKET_ENCRYPTION -I. src/monitor_traffic.cpp src/telemetry.cpp src/crypto.cpp -o bin/monitor_traffic -lcrypto -lssl
./bin/monitor_traffic
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
## Conversation
The user wanted to modify the source code to run asynchronously for uplink and downlink so that commands and packets can be sent on different antennas at the same time.

I started by reading `src/telemetry.h` and `src/telemetry.cpp` to understand the current implementation.

Then, I modified `src/telemetry.h` and `src/telemetry.cpp` to introduce asynchronous uplink and downlink capabilities. This involved:
- Introducing an `Antenna` enum.
- Updating function signatures to take an `Antenna` parameter.
- Duplicating global state for each antenna.
- Introducing `std::recursive_mutex` for thread safety.
- Creating and managing transmitter threads for each antenna.

I then updated `src/test.cpp` to reflect the API changes and to test the new functionality.

After that, I compiled the code and fixed a deadlock issue by changing `std::mutex` to `std::recursive_mutex`.

The user then asked to ensure the new changes are integrated with encrypted packet transmission and receipt. I reviewed `src/crypto.h` and `src/crypto.cpp` and found no changes were needed there. I then updated `Tests/encrypted_receive_test.cpp` to be compatible with the new asynchronous API.

Next, the user asked for a new test program that sends and receives encrypted packets that can be viewed on a Linux terminal using the `socat` command. I created `src/network_test.cpp` for this purpose. This program:
- Initializes radio and crypto subsystems.
- Loads keys.
- Creates a TCP socket to send and receive packets.
- Uses separate threads for sending and receiving.
- Handles `SIGINT` for graceful shutdown.
- Prints a final status report for each antenna.

During the development of `src/network_test.cpp`, I encountered and resolved several issues:
- **No output from `network_test`**: This was due to the program waiting for a `socat` connection. I clarified the instructions for the user.
- **`Packets TX` and `Packets RX` not updating**: This was because `network_test.cpp` was bypassing the radio layer. I modified `network_test.cpp` to use `radio_transmit_raw_buffer` and `telemetry_hal_on_receive` to update the counters.
- **Program not receiving uplink packets**: This was due to the uplink transmitter thread constantly setting the uplink antenna's state to `STANDBY`, overriding the `RECEIVING` state. I fixed this by modifying `transmitter_thread_entry` in `telemetry.cpp` to only call `radio_transmit_queued_packets` if there are packets in the transmit buffer.
- **No output indicating packet reception/decryption failure**: This was because the default `telemetry_hal_on_receive` was being used, which doesn't provide output. I added `radio_increment_packets_received` and `radio_increment_error_count` functions to `telemetry.h` and `telemetry.cpp`, and then overrode `telemetry_hal_on_receive` in `network_test.cpp` to use these functions and provide detailed output.
- **Linker issue with `telemetry_hal_on_receive`**: The weak symbol `telemetry_hal_on_receive` was not being linked correctly. I fixed this by explicitly linking it using a global function pointer in `network_test.cpp` and by adding the `-Wl,--no-as-needed` linker flag.

I then created `src/send_packet.cpp` to send encrypted data to the `network_test` application. This program:
- Takes data as a command-line argument.
- Initializes crypto and loads keys (reversed for client-side).
- Creates a `TelemetryPacket` and encrypts it.
- Connects to `network_test` over TCP and sends the encrypted packet.

During the development of `src/send_packet.cpp` and its interaction with `network_test.cpp`, I resolved the following issues:
- **`network_test` exiting after one packet**: This was due to `network_test`'s main thread blocking on `join()` calls for sender/receiver threads, and the `send_packet` client disconnecting immediately. I refactored `network_test.cpp` to use `std::atomic<bool>` for connection activity, `std::thread::detach()`, and a `select()` loop in `main` to handle multiple connections and graceful shutdown.
- **Compilation error with `std::atomic<bool>`**: Fixed by adding a constructor to the `Connection` struct in `network_test.cpp` to correctly initialize `std::atomic<bool>` members.

The final `network_test` program successfully demonstrates asynchronous, encrypted communication over a network socket, with correct packet counting, detailed output, and graceful shutdown. The `send_packet` program can reliably send encrypted data to it.

I then updated the `gemini-context.md` file to reflect the new files and build commands.

Next, I created a new program `src/monitor_traffic.cpp` that connects to the `network_test` socket, and can send and receive encrypted packets, printing the decrypted content to the screen.
