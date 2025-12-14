"""
Python bindings for TROPIC01 secure element via USB dongle transport.

This module provides a Python interface to the TROPIC01 secure element,
compatible with both CPython and MicroPython.
"""

from ._tropic_py import PyTropic01, PyEncSession

__version__ = "0.1.0"
__all__ = ["Tropic01", "EncSession"]


class Tropic01(PyTropic01):
    """
    High-level Python interface to TROPIC01 secure element.
    
    This class wraps the native Rust implementation and provides a Pythonic
    interface to all TROPIC01 functionality via USB dongle transport.
    
    Example:
        >>> tropic = Tropic01("/dev/ttyACM0")
        >>> status = tropic.get_chip_status()
        >>> print(status)
        {'ready': True, 'alarm': False, 'chip_mode': 'Application'}
    """
    
    def __init__(self, port, baud_rate=115200):
        """
        Initialize connection to TROPIC01 via USB dongle.
        
        Args:
            port (str): Serial port path (e.g., "/dev/ttyACM0" on Linux, 
                       "COM3" on Windows)
            baud_rate (int): Serial baud rate (default: 115200)
        
        Raises:
            Exception: If connection to the device fails
        """
        super().__init__(port, baud_rate)
    
    def __enter__(self):
        """Context manager support"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager cleanup"""
        # No cleanup needed for now
        return False


class EncSession(PyEncSession):
    """
    Encrypted session wrapper for TROPIC01.
    
    This class wraps an encrypted session and provides methods
    for session management and serialization.
    
    Example:
        >>> # Create session from handshake
        >>> session = EncSession.create(tropic, 0, sh_secret_hex, st_pubkey_hex)
        >>> # Use session for operations
        >>> response = tropic.ping(session, b"hello")
        >>> # Save session
        >>> session_json = session.to_json()
        >>> # Restore session
        >>> session = EncSession.from_json(session_json)
    """
    pass
