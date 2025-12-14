#!/usr/bin/env python3
"""
Example demonstrating session management with tropic-py.

This example shows how to:
1. Get a handshake
2. Create an encrypted session
3. Perform operations within a session (ping, pairing key operations, config)
4. Save and restore sessions
5. Abort a session
"""

import json
from tropic_py import Tropic01, EncSession


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
        
        # For full session creation, you would need:
        # 1. Get cert store to extract device public key
        # 2. Have a pairing key secret
        # 3. Create session with EncSession.create()
        
        # Example of creating a session (requires proper keys):
        # cert_store_json = tropic.get_cert_store()
        # cert_store = json.loads(cert_store_json)
        # st_pubkey_hex = extract_device_pubkey(cert_store)  # Would need implementation
        # sh_secret_hex = "your_pairing_key_secret_hex"
        # session = EncSession.create(tropic, PAIRING_KEY_SLOT, sh_secret_hex, st_pubkey_hex)
        
        # Once you have a session, you can:
        # - Ping: response = tropic.ping(session, b"hello")
        # - Read pairing keys: pubkey = tropic.pairing_key_read(session, slot)
        # - Write pairing keys: tropic.pairing_key_write(session, slot, pubkey_hex)
        # - Read config: config = tropic.r_config_read(session)
        # - Write config: tropic.r_config_write(session, config_json)
        
        # Save session to file
        # session_json = session.to_json()
        # with open("session.json", "w") as f:
        #     f.write(session_json)
        
        # Restore session from file
        # with open("session.json", "r") as f:
        #     session_json = f.read()
        # session = EncSession.from_json(session_json)
        
        print("\n=== Handshake Successful ===")
        print("Note: Full session creation requires proper pairing keys")
        print("      See tropic-usb-dongle examples for complete workflow")
        
        # Abort any existing session
        print("\n=== Aborting Session ===")
        try:
            tropic.abort_session()
            print("Session aborted successfully")
        except Exception as e:
            print(f"No active session to abort: {e}")


if __name__ == "__main__":
    main()
