"""
Python bindings for TROPIC01 secure element via USB dongle transport.

This module provides a Python interface to the TROPIC01 secure element,
compatible with both CPython and MicroPython.
"""

from ._tropic_py import Tropic01, EncSession, Bytes32, Bytes64

__version__ = "0.1.0"
__all__ = ["Tropic01", "EncSession", "Bytes32", "Bytes64"]
