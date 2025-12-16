#!/usr/bin/env python3
"""
Example demonstrating Bytes64 and Bytes32 usage with tropic-py.

This example shows how to:
1. Create Bytes64 from hex string or bytes
2. Get length of Bytes64
3. Create Bytes32 from hex string or bytes
4. Get length of Bytes32
"""

from tropic_py import Bytes64, Bytes32

def main():
    b16_hex = "00112233445566778899aabbccddeeff"
    b64_hex = b16_hex * 4  # 16 bytes * 4 = 64 bytes
    b64 = Bytes64.from_hex(b64_hex)
    print(f"Bytes64 value: {b64.to_hex()}")

    b64 = Bytes64(bytes(b64))
    print(f"Bytes64 length: {len(b64)}")

    b32_hex = b16_hex * 2  # 16 bytes * 2 = 32 bytes
    b32 = Bytes32.from_hex(b32_hex)
    print(f"Bytes32 value: {b32.to_hex()}")

    b32 = Bytes32(b32.to_bytes())
    print(f"Bytes32 length: {len(b32)}")

if __name__ == "__main__":
    main()