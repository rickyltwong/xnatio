from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, TypedDict

from dotenv import load_dotenv


class XNATConfig(TypedDict):
    """Configuration dictionary for XNAT connection.

    Attributes:
        server: Base URL of the XNAT server (e.g., https://xnat.example.org)
        user: XNAT username for authentication
        password: XNAT password for authentication
        verify_tls: Whether to verify TLS certificates (default True)
        http_connect_timeout: HTTP connection timeout in seconds (default 120)
        http_read_timeout: HTTP read timeout in seconds (default 604800 = 7 days)
    """

    server: str
    user: str
    password: str
    verify_tls: bool
    http_connect_timeout: int
    http_read_timeout: int


def _str_to_bool(value: Optional[str], default: bool = True) -> bool:
    if value is None:
        return default
    value_norm = value.strip().lower()
    if value_norm in {"1", "true", "yes", "y", "on"}:
        return True
    if value_norm in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _parse_int(value: Optional[str], default: int) -> int:
    """Parse a string to an integer with a fallback default."""
    if value is None:
        return default
    try:
        return int(value.strip())
    except ValueError:
        return default


# Default timeout values
DEFAULT_HTTP_CONNECT_TIMEOUT = 120  # 2 minutes
DEFAULT_HTTP_READ_TIMEOUT = 604800  # 7 days (for large DICOM uploads/downloads)


def load_config(env_path: Optional[Path] = None) -> XNATConfig:
    """Load configuration from environment variables, optionally overriding from a .env file.

    Behavior:
        - If env_path is provided, load that .env file with override=True (it overrides OS env).
        - Else, if a .env exists in the current working directory, load it with override=False.
        - Finally, read variables from the environment.

    Required variables:
        XNAT_SERVER: Base URL of the XNAT server
        XNAT_USERNAME: XNAT username for authentication
        XNAT_PASSWORD: XNAT password for authentication

    Optional variables:
        XNAT_VERIFY_TLS: Whether to verify TLS certificates (default: true)
        XNAT_HTTP_CONNECT_TIMEOUT: HTTP connection timeout in seconds (default: 120)
        XNAT_HTTP_READ_TIMEOUT: HTTP read timeout in seconds (default: 604800)
            The read timeout is set high by default to accommodate large DICOM
            uploads and downloads that may take hours to complete.

    Returns:
        XNATConfig dictionary with all configuration values.

    Raises:
        FileNotFoundError: If explicit env_path is provided but does not exist.
        RuntimeError: If required environment variables are missing.
    """
    # Explicit env file overrides current environment
    if env_path:
        p = Path(env_path).expanduser()
        if not p.exists():
            raise FileNotFoundError(f"Environment file not found: {p}")
        load_dotenv(p, override=True)
    else:
        # Load default .env from CWD if present, but do not override OS env
        default_env = Path.cwd() / ".env"
        if default_env.exists():
            load_dotenv(default_env, override=False)

    server = os.getenv("XNAT_SERVER")
    user = os.getenv("XNAT_USERNAME")
    password = os.getenv("XNAT_PASSWORD")

    if not server or not user or not password:
        missing = [
            name
            for name, val in (
                ("XNAT_SERVER", server),
                ("XNAT_USERNAME", user),
                ("XNAT_PASSWORD", password),
            )
            if not val
        ]
        raise RuntimeError(
            f"Missing required environment variables: {', '.join(missing)}"
        )

    verify_tls = _str_to_bool(os.getenv("XNAT_VERIFY_TLS"), default=True)
    connect_timeout = _parse_int(
        os.getenv("XNAT_HTTP_CONNECT_TIMEOUT"), DEFAULT_HTTP_CONNECT_TIMEOUT
    )
    read_timeout = _parse_int(
        os.getenv("XNAT_HTTP_READ_TIMEOUT"), DEFAULT_HTTP_READ_TIMEOUT
    )

    return XNATConfig(
        server=server,
        user=user,
        password=password,
        verify_tls=verify_tls,
        http_connect_timeout=connect_timeout,
        http_read_timeout=read_timeout,
    )
