#!/usr/bin/env python3
"""
Example demonstrating basic usage of tropic-py with CPython.

This example shows how to connect to a TROPIC01 device via USB dongle
and retrieve basic device information.
"""

import json
from tropic_py import Tropic01


def main():
    # Connect to TROPIC01 via USB dongle
    # On Linux: /dev/ttyACM0, on macOS: /dev/tty.usbmodem*, on Windows: COM*
    PORT = "/dev/ttyACM0"
    BAUD_RATE = 115200
    
    print(f"Connecting to TROPIC01 on {PORT}...")
    
    with Tropic01(PORT, BAUD_RATE) as tropic:
        # Get chip status
        print("\n=== Chip Status ===")
        status = tropic.get_chip_status()
        print(f"Ready: {status['ready']}")
        print(f"Alarm: {status['alarm']}")
        print(f"Mode: {status['chip_mode']}")
        
        # Get chip ID
        print("\n=== Chip ID ===")
        chip_id_json = tropic.get_chip_id()
        chip_id = json.loads(chip_id_json)
        print(json.dumps(chip_id, indent=2))
        
        # Get firmware version
        print("\n=== RISC-V Firmware Version ===")
        fw_version = tropic.get_firmware_version("Riscv")
        print(f"Firmware version (hex): {fw_version}")
        
        # Get firmware boot header
        print("\n=== Firmware Boot Header (Bank 1) ===")
        boot_header_json = tropic.get_firmware_boot_header(1)
        boot_header = json.loads(boot_header_json)
        print(json.dumps(boot_header, indent=2))
        
        # Get firmware log
        print("\n=== RISC-V Firmware Log ===")
        log = tropic.get_riscv_firmware_log()
        print(log)
        
        # Get certificate store
        print("\n=== Certificate Store ===")
        cert_store_json = tropic.get_cert_store()
        cert_store = json.loads(cert_store_json)
        print(f"Retrieved certificate store with {len(cert_store)} certificates")
        
        print("\n=== Device Information Retrieved Successfully ===")


if __name__ == "__main__":
    main()
