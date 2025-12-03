"""XNAT IO - CLI utilities for interacting with XNAT."""

__version__ = "0.1.0"
__author__ = "XNAT IO Maintainers"
__description__ = "CLI utilities for interacting with an XNAT instance as an admin"

from .xnat_client import XNATClient
from .config import load_config, XNATConfig

__all__ = ["XNATClient", "load_config", "XNATConfig"]
