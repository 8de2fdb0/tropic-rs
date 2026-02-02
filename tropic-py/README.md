# tropic-py

Python bindings for TROPIC01 secure element via USB dongle transport.

This package provides a Python interface to the TROPIC01 secure element using the USB dongle transport implementation from `tropic-rs`. It is compatible with both CPython and MicroPython.

## Features

- ✅ **USB Dongle Transport**: Communicate with TROPIC01 via USB serial interface
- ✅ **Full API Access**: All TROPIC01 methods exposed through Python
- ✅ **CPython Compatible**: Works with Python 3.7+
- ⏳ **MicroPython Compatible**: Can be compiled for MicroPython platforms
- ✅ **Type-Safe**: Built on top of the Rust `tropic-rs` crate using PyO3

## Installation

### CPython (Standard Python)

```bash
# Create a venv in this folder
python3 -m venv .venv && source .venv/bin/activate

# Install maturin for building
# pip install .
pip install ".[dev]"

# Build and install in development mode
maturin develop --release

# Or build a wheel
maturin build --release
pip install target/wheels/tropic_py-*.whl
```

## Generating python types

```bash
cargo run --bin stub_gen
```

### MicroPython

TODO

## Usage

### Basic Example

```python
from tropic_py import Tropic01
import json

# Connect to device
tropic = Tropic01("/dev/ttyACM0", baud_rate=115200)

# Get chip status
status = tropic.get_chip_status()
print(f"Chip ready: {status['ready']}")

# Get chip ID
chip_id_json = tropic.get_chip_id()
chip_id = json.loads(chip_id_json)
print(json.dumps(chip_id, indent=2))

# Get firmware version
fw_version = tropic.get_firmware_version("Riscv")
print(f"Version: {fw_version}")
```

### Session Management

```python
from tropic_py import Tropic01

tropic = Tropic01("/dev/ttyACM0")

# Get handshake for session
handshake = tropic.get_handshake(pairing_key_slot=0)
print(handshake)

# Abort session when done
tropic.abort_session()
```

## API Coverage

This Python binding implements **all** TROPIC01 functionality available in the Rust API. The implementation provides complete access to device information, power management, session management, cryptographic operations, data storage, and counters.

### Implemented Methods

#### Device Information (L2 - No Session Required)
- ✅ `get_chip_status()` - Get chip status
- ✅ `get_chip_id()` - Get chip ID
- ✅ `get_firmware_version(fw_type)` - Get firmware version
- ✅ `get_firmware_boot_header(bank_id)` - Get boot header
- ✅ `get_riscv_firmware_log()` - Get firmware log
- ✅ `get_cert_store()` - Get certificate store

#### Power Management (L2 - No Session Required)
- ✅ `sleep(kind)` - Put device to sleep
- ✅ `restart(mode)` - Restart device

#### Session Management (L2 - No Session Required)
- ✅ `get_handshake(pairing_key_slot)` - Get handshake for session
- ✅ `abort_session()` - Abort current session

#### Session Operations (L3 - Requires EncSession)
- ✅ `ping(session, message)` - Ping device
- ✅ `pairing_key_read(session, slot)` - Read pairing key
- ✅ `pairing_key_write(session, slot, pubkey_hex)` - Write pairing key
- ✅ `pairing_key_invalidate(session, slot)` - Invalidate pairing key
- ✅ `r_config_read(session)` - Read reversible config
- ✅ `r_config_write(session, config_json)` - Write reversible config
- ✅ `r_config_erase(session)` - Erase reversible config
- ✅ `i_config_read(session)` - Read irreversible config
- ✅ `i_config_write(session, config)` - Write irreversible config

#### Data Storage (L3 - Requires EncSession)
- ✅ `r_mem_data_read(session, slot)` - Read user data
- ✅ `r_mem_data_write(session, slot, data)` - Write user data
- ✅ `r_mem_data_erase(session, slot)` - Erase user data

#### Cryptographic Operations (L3 - Requires EncSession)
- ✅ `random_value(session, n_bytes)` - Get random bytes
- ✅ `ecc_key_generate(session, slot, curve)` - Generate ECC key
- ✅ `ecc_key_store(session, slot, curve, secret)` - Store ECC key
- ✅ `ecc_key_read_pubkey(session, slot)` - Read ECC public key
- ✅ `ecc_key_erase(session, slot)` - Erase ECC key
- ✅ `ecc_ecdsa_sign(session, slot, message)` - ECDSA sign
- ✅ `ecc_eddsa_sign(session, slot, message)` - EdDSA sign

#### Counters (L3 - Requires EncSession)
- ✅ `mcounter_init(session, index, value)` - Initialize counter
- ✅ `mcounter_update(session, index)` - Update counter
- ✅ `mcounter_get(session, index)` - Get counter value

#### Other (L3 - Requires EncSession)
- ✅ `mac_and_destroy(session, slot, data)` - MAC and destroy operation
- ✅ `serial_code_get(session)` - Get serial code

### Not Yet Implemented

All API methods have been implemented! The Python binding now provides complete access to the TROPIC01 API.

For reference, the following methods were recently added:

#### Advanced Session Operations
- ✅ `pairing_key_invalidate(session, slot)` - Invalidate pairing key
- ✅ `r_config_erase(session)` - Erase reversible config
- ✅ `i_config_read(session)` - Read irreversible config
- ✅ `i_config_write(session, config)` - Write irreversible config

#### Data Storage
- ✅ `r_mem_data_read(session, slot)` - Read user data
- ✅ `r_mem_data_write(session, slot, data)` - Write user data
- ✅ `r_mem_data_erase(session, slot)` - Erase user data

#### Cryptographic Operations
- ✅ `random_value(session, n_bytes)` - Get random bytes
- ✅ `ecc_key_generate(session, slot, curve)` - Generate ECC key
- ✅ `ecc_key_store(session, slot, curve, secret)` - Store ECC key
- ✅ `ecc_key_read_pubkey(session, slot)` - Read ECC public key
- ✅ `ecc_key_erase(session, slot)` - Erase ECC key
- ✅ `ecc_ecdsa_sign(session, slot, message)` - ECDSA sign
- ✅ `ecc_eddsa_sign(session, slot, message)` - EdDSA sign

#### Counters
- ✅ `mcounter_init(session, index, value)` - Initialize counter
- ✅ `mcounter_update(session, index)` - Update counter
- ✅ `mcounter_get(session, index)` - Get counter value

#### Other
- ✅ `mac_and_destroy(session, slot, data)` - MAC and destroy operation
- ✅ `serial_code_get(session)` - Get serial code

**Note:** The `resend_response()` method is not exposed in the Python API as it requires knowledge of the expected response type at compile time, which is not practical in a dynamic Python environment.

## API Reference

### Tropic01 Class

#### Constructor

```python
Tropic01(port: str, baud_rate: int = 115200)
```

Create a new TROPIC01 instance connected via USB dongle.

**Parameters:**
- `port`: Serial port path (e.g., "/dev/ttyACM0" on Linux, "COM3" on Windows)
- `baud_rate`: Serial baud rate (default: 115200)

#### Methods

##### Device Information

- `get_chip_status()` - Get chip status (ready, alarm, chip_mode)
- `get_chip_id()` - Get chip ID as JSON string
- `get_firmware_version(fw_type: str)` - Get firmware version ("Riscv" or "Spect") as hex string
- `get_firmware_boot_header(bank_id: int)` - Get boot header for bank (1, 2, 17, or 18)
- `get_riscv_firmware_log()` - Get RISC-V firmware log
- `get_cert_store()` - Get certificate store as JSON string

##### Power Management

- `sleep(kind: str)` - Put device to sleep ("Regular" or "Deep")
- `restart(mode: str)` - Restart device ("Reboot" or "Maintenance")

##### Session Management

- `get_handshake(pairing_key_slot: int)` - Get handshake for session (slot 0-3)
- `abort_session()` - Abort current session

##### Session Operations (require EncSession)

- `ping(session: EncSession, message: bytes)` - Ping device, returns response bytes
- `pairing_key_read(session: EncSession, slot: int)` - Read pairing key public key
- `pairing_key_write(session: EncSession, slot: int, pubkey_hex: str)` - Write pairing key
- `pairing_key_invalidate(session: EncSession, slot: int)` - Invalidate pairing key
- `r_config_read(session: EncSession)` - Read reversible config as JSON
- `r_config_write(session: EncSession, config_json: str)` - Write reversible config
- `r_config_erase(session: EncSession)` - Erase reversible config
- `i_config_read(session: EncSession)` - Read irreversible config as JSON
- `i_config_write(session: EncSession, config_json: str)` - Write irreversible config

##### Data Storage Operations (require EncSession)

- `r_mem_data_read(session: EncSession, slot: int)` - Read user data from slot (0-511), returns bytes
- `r_mem_data_write(session: EncSession, slot: int, data: bytes)` - Write user data to slot (max 32 bytes)
- `r_mem_data_erase(session: EncSession, slot: int)` - Erase user data from slot

##### Cryptographic Operations (require EncSession)

- `random_value(session: EncSession, n_bytes: int)` - Get random bytes (max 32)
- `ecc_key_generate(session: EncSession, slot: int, curve: str)` - Generate ECC key ("P256" or "Ed25519")
- `ecc_key_store(session: EncSession, slot: int, curve: str, secret_hex: str)` - Store ECC key (32 bytes)
- `ecc_key_read_pubkey(session: EncSession, slot: int)` - Read ECC public key as hex string
- `ecc_key_erase(session: EncSession, slot: int)` - Erase ECC key
- `ecc_ecdsa_sign(session: EncSession, slot: int, message: bytes)` - ECDSA sign, returns signature as hex
- `ecc_eddsa_sign(session: EncSession, slot: int, message: bytes)` - EdDSA sign, returns signature as hex

##### Counter Operations (require EncSession)

- `mcounter_init(session: EncSession, index: int, value: int)` - Initialize monotonic counter (0-15)
- `mcounter_update(session: EncSession, index: int)` - Increment monotonic counter
- `mcounter_get(session: EncSession, index: int)` - Get counter value, returns int

##### Other Operations (require EncSession)

- `mac_and_destroy(session: EncSession, slot: int, data: bytes)` - MAC and destroy operation (slot 0-127, data 32 bytes)
- `serial_code_get(session: EncSession)` - Get serial code as hex string

### EncSession Class

#### Static Methods

- `EncSession.create(tropic: Tropic01, pairing_key_slot: int, sh_secret_hex: str, st_pubkey_hex: str)` - Create encrypted session
- `EncSession.from_json(json: str)` - Restore session from JSON

#### Methods

- `to_json()` - Serialize session to JSON string

## Examples

See the `examples/` directory for complete examples:

- `basic_usage.py` - Basic device information retrieval
- `session_management.py` - Session handshake and management

## Requirements

### CPython
- Python 3.7 or later
- Rust toolchain (for building)
- maturin (for building)

## Platform Support

### Tested Platforms
- Linux (x86_64, ARM)
- macOS (x86_64, ARM64)
- Windows (x86_64)

### Serial Port Notes
- **Linux**: Usually `/dev/ttyACM0` or `/dev/ttyUSB0`
- **macOS**: Usually `/dev/tty.usbmodem*`
- **Windows**: Usually `COM3`, `COM4`, etc.

Make sure your user has permission to access the serial port:
```bash
# Linux: Add user to dialout group
sudo usermod -a -G dialout $USER
# Log out and log back in for changes to take effect
```

## Development

### Building

```bash
# Development build
maturin develop

# Release build
maturin build --release
```

### Testing

```bash
# Run examples (requires connected TROPIC01 device)
python examples/basic_usage.py
python examples/session_management.py
```

## Implementation Details

This package wraps the Rust `tropic-rs` crate using PyO3, providing:

1. **Serial Transport**: Direct implementation of the USB dongle serial protocol
2. **TropicTransport Trait**: Implements the standard transport interface
3. **High-Level API**: Wraps all `Tropic01` methods from the Rust crate
4. **Error Handling**: Converts Rust errors to Python exceptions
5. **Data Serialization**: Returns complex data structures as JSON strings

The implementation is based on the USB dongle transport from:
`tropic-examples/usb_dongle/src/serial_transport.rs`

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../LICENSE-MIT))

at your option.

## Contributing

Contributions are welcome! Please ensure:
1. Code compiles without warnings
2. Examples run successfully
3. Documentation is updated
4. Tests pass (when available)

## Troubleshooting

### "Cannot open serial port"
- Check that the device is connected
- Verify the port path is correct
- Ensure you have permissions to access the port

### "Invalid handshake" or "Communication error"
- Verify baud rate is correct (115200)
- Check USB cable and connections
- Try power cycling the device

### MicroPython Issues
- Ensure the module is compiled for your specific MicroPython platform
- Check that your platform supports native C modules
- Verify available memory (MicroPython has limited heap)

## References

- [TROPIC01 Product Page](https://tropicsquare.com/)
- [tropic-rs Repository](https://github.com/8de2fdb0/tropic-rs)
- [PyO3 Documentation](https://pyo3.rs/)
- [MicroPython Documentation](https://docs.micropython.org/)
