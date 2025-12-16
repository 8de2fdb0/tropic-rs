#!/usr/bin/env python3
"""
Example demonstrating session management with tropic-py.

This example shows how to:
1. Get a handshake
2. Create an encrypted session
3. Perform operations within a session (ping, read config)
4. Abort a session
"""



import json
from tropic_py import Tropic01, EncSession


def extract_device_pubkey(cert_store):
    for certificate in cert_store.get("certificates"):
        if certificate.get("kind") == "Device":
            cert = certificate.get("cert")
            return cert.get("public_key")
    raise ValueError("Device public key not found in certificate store")

def main():
    PORT = "/dev/ttyACM0"
    BAUD_RATE = 115200
    PAIRING_KEY_SLOT = 0
    ENGINEERING_SAMPLE_SH_SECRET_HEX = "283F5A0FFC41CF5098A8E17DB6372C3CAAD1EEEEDF0F75BC3FBFCD9CAB3DE972"
    
    print(f"Connecting to TROPIC01 on {PORT}...")
    
    with Tropic01(PORT, BAUD_RATE) as tropic:
        
        
        # Get cert store to extract device public key
        print("\n=== Getting CertStore ===")
        cert_store_json = tropic.get_cert_store()
        cert_store = json.loads(cert_store_json)
        print(f"\nRetrieved certificate store with {len(cert_store)} certificates")
        st_pubkey_hex = extract_device_pubkey(cert_store)  # Would need implementation
        print(f"Extracted device public key: {st_pubkey_hex[:32]}...")
        
        # Get handshake
        print("\n=== Getting Handshake ===")
        handshake_json = tropic.get_handshake(PAIRING_KEY_SLOT)
        handshake = json.loads(handshake_json)
        print(f"ET Public Key: {handshake['et_pubkey'][:32]}...")
        print(f"Auth Tag: {handshake['auth_tag'][:32]}...")
        
        print("\n=== Handshake Successful ===")
       
        print("\n=== Creating Session ===")
        # Create session with EncSession.create()
        session = EncSession.create(tropic, PAIRING_KEY_SLOT, ENGINEERING_SAMPLE_SH_SECRET_HEX, st_pubkey_hex)
        print("\n=== Session created successfully ===")
                
        print("\n=== Running Commands with Session ===")
        # Ping: 
        print("\n--- Pinging Device ---")
        response = tropic.ping(session, b"hello")
        print(f"ping response: {response}")
        # - Read config: 
        print("\n--- Reading Config ---")
        config = tropic.r_config_read(session)
        print(f"Config: {config}")
        
        # Abort any existing session
        print("\n=== Aborting Session ===")
        try:
            tropic.abort_session()
            print("Session aborted successfully")
        except Exception as e:
            print(f"No active session to abort: {e}")


if __name__ == "__main__":
    main()
