"""
Python bindings for TROPIC01 secure element via USB dongle transport.

This module provides a Python interface to the TROPIC01 secure element,
compatible with both CPython and MicroPython.
"""

from ._tropic_py import PyTropic01

__version__ = "0.1.0"
__all__ = ["Tropic01"]


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
