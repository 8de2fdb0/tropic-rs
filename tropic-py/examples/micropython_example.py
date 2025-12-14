"""
MicroPython-compatible example for tropic-py.

This example is designed to run on MicroPython and demonstrates
basic device interaction.

Note: MicroPython support requires the native module to be compiled
for the target platform (e.g., Unix port, ESP32, etc.)
"""

try:
    import json
except ImportError:
    # MicroPython might use ujson
    import ujson as json

from tropic_py import Tropic01


def main():
    # Adjust port for your MicroPython platform
    # Unix port: "/dev/ttyACM0"
    # ESP32: "/dev/ttyUSB0" or similar
    PORT = "/dev/ttyACM0"
    BAUD_RATE = 115200
    
    print("Connecting to TROPIC01 on", PORT)
    
    # Note: MicroPython may not support context managers in all cases
    tropic = Tropic01(PORT, BAUD_RATE)
    
    # Get chip status
    print("\n=== Chip Status ===")
    status = tropic.get_chip_status()
    print("Ready:", status['ready'])
    print("Alarm:", status['alarm'])
    print("Mode:", status['chip_mode'])
    
    # Get chip ID
    print("\n=== Chip ID ===")
    chip_id_json = tropic.get_chip_id()
    chip_id = json.loads(chip_id_json)
    print("Chip ID retrieved")
    
    # Get firmware version
    print("\n=== RISC-V Firmware Version ===")
    fw_version = tropic.get_firmware_version("Riscv")
    print("Firmware version retrieved:", fw_version)
    
    print("\n=== Device Info Retrieved Successfully ===")


if __name__ == "__main__":
    main()
