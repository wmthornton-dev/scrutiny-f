## Quick context

This repository implements a small, safety-critical C++11-compatible telemetry radio control library
and a minimal example/test (`test.cpp`). The primary implementation is a single header: `telemetry.h`.

Key points an AI coding agent should know before editing or extending code:

- The project is written as a deterministic, safety-first C++ subset (C++11-compatible). No dynamic
  allocation, fixed-size buffers, and bounded loops are used throughout.
- `telemetry.h` contains both API functions and static/internal implementations (it is effectively
  a header-only module). Many functions and globals are declared `static` or are file-scoped globals
  (e.g. `g_radio_control`, `g_tx_buffer`). Treat changes carefully: this is intended for tight
  control and deterministic behavior.
- Error handling uses explicit return codes (`SystemStatus` enum). Functions return `STATUS_SUCCESS`
  or a defined error code; callers check these codes. Do not replace this with exceptions.
- The code is safety-critical and annotated with comments like "Safety-Critical System - DO NOT MODIFY
  WITHOUT REVIEW" — any behavioral change should be conservative and accompanied by tests and a
  review note.

## Architecture / data flow (short)

- Initialization: `radio_initialize()` zeros global state and sets safe defaults.
- Packet creation: `telemetry_create_packet()` builds a fixed-size `TelemetryPacket` and computes a CRC
  with `calculate_crc16()`.
- Queueing: `telemetry_queue_packet()` appends to the fixed `g_tx_buffer` (capacity `MAX_COMMAND_QUEUE_SIZE`).
- Transmission: `radio_transmit_queued_packets()` validates CRCs and simulates transmission in place of
  real hardware; the code contains the exact comment `/* Hardware transmission would occur here */` where
  platform integration should be implemented.

These functions are exercised in `test.cpp` in the order above; that file is a helpful example usage.

## Project-specific conventions and patterns

- Deterministic, bounded loops only (see `Power of 2 Rule` comment and `MAX_*` macros). Avoid introducing
  dynamic or unbounded loops.
- Defensive NULL pointer checks are present in public and internal functions (e.g., `calculate_crc16`,
  `validate_radio_config`). Keep this pattern when adding new APIs.
- Use `STATUS_*` return codes for errors instead of exceptions or errno.
- Globals are minimized but present; prefer functions that operate on provided structures where possible.
- All buffer sizes and limits are defined via macros at top of `telemetry.h` (e.g. `TELEMETRY_PACKET_SIZE`,
  `MAX_COMMAND_QUEUE_SIZE`). Use those macros for any new buffer or limit you add.

## Integration points / external dependencies

- There is no external build file in the repository. Typical local build command for development:

  g++ -std=c++11 test.cpp -o test

  Then run: `./test`

- Hardware integration: the actual radio transmission is a stub. To integrate with hardware, replace the
  commented area in `radio_transmit_queued_packets()` with platform-specific send logic. Preserve CRC
  checks and queue semantics.

## Examples to reference when editing

- To initialize and send a packet (see `test.cpp`):
  - `radio_initialize()`
  - `radio_set_state(RADIO_STATE_STANDBY)`
  - `telemetry_create_packet(...)`
  - `telemetry_queue_packet(...)`
  - `radio_transmit_queued_packets()`

- For configuration validation, follow `validate_radio_config()`'s pattern (explicit bounds checks,
  return `STATUS_ERROR_*` codes).

## Editing rules for AI agents

- Preserve deterministic behavior: keep loops bounded and buffer sizes macro-driven.
- Do not remove or replace the `SystemStatus` error-code pattern with exceptions.
- If adding new globals or changing existing global state, clearly document why and keep changes minimal.
- Any change that affects transmission semantics, timing, or CRC handling must include a short rationale
  in the PR description and an accompanying example test (see `test.cpp`) demonstrating correctness.

## Where to look for implementation and extension

- `telemetry.h` — primary implementation and canonical style examples (CRC, validation, queueing).
- `test.cpp` — minimal runnable example demonstrating correct call order and basic output.

If anything in this guidance is unclear or you want more detail (for example, a preferred build system,
unit-test harness, or integration example for a specific radio HAL), tell me what to add and I will iterate.
