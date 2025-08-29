"""XNAT IO - CLI utilities for interacting with XNAT."""

__version__ = "0.1.0"
__author__ = "CAMH XNAT Team"
__description__ = "CLI utilities for interacting with CAMH XNAT instance as an admin"

from .xnat_client import XNATClient
from .config import load_config

__all__ = ["XNATClient", "load_config"] 