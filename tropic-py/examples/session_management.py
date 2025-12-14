#!/usr/bin/env python3
"""
Example demonstrating session management with tropic-py.

This example shows how to:
1. Get a handshake
2. Create a session
3. Perform operations within a session
4. Abort a session
"""

import json
from tropic_py import Tropic01


def main():
    PORT = "/dev/ttyACM0"
    BAUD_RATE = 115200
    PAIRING_KEY_SLOT = 0
    
    print(f"Connecting to TROPIC01 on {PORT}...")
    
    with Tropic01(PORT, BAUD_RATE) as tropic:
        # Get handshake
        print("\n=== Getting Handshake ===")
        handshake_json = tropic.get_handshake(PAIRING_KEY_SLOT)
        handshake = json.loads(handshake_json)
        print(f"ET Public Key: {handshake['et_pubkey'][:32]}...")
        print(f"Auth Tag: {handshake['auth_tag'][:32]}...")
        print(f"Static Secret: {handshake['static_secret'][:32]}...")
        
        # Note: Full session creation requires additional cryptographic operations
        # that would typically be done with the cert store and pairing keys.
        # This example shows the handshake step.
        
        print("\n=== Handshake Successful ===")
        
        # Abort any existing session
        print("\n=== Aborting Session ===")
        try:
            tropic.abort_session()
            print("Session aborted successfully")
        except Exception as e:
            print(f"No active session to abort: {e}")


if __name__ == "__main__":
    main()
