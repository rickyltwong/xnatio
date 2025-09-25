import os
from pathlib import Path
from typing import Dict, Optional

from dotenv import load_dotenv


def _str_to_bool(value: Optional[str], default: bool = True) -> bool:
    if value is None:
        return default
    value_norm = value.strip().lower()
    if value_norm in {"1", "true", "yes", "y", "on"}:
        return True
    if value_norm in {"0", "false", "no", "n", "off"}:
        return False
    return default


def load_config(env_path: Optional[Path] = None) -> Dict[str, object]:
    """
    Load configuration from environment variables, optionally overriding from a .env file.

    Behavior:
    - If env_path is provided, load that .env file with override=True (it overrides OS env).
    - Else, if a .env exists in the current working directory, load it with override=False.
    - Finally, read variables from the environment.

    Required variables:
      - XNAT_SERVER
      - XNAT_USERNAME
      - XNAT_PASSWORD
    Optional variables:
      - XNAT_VERIFY_TLS (default True)
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

    return {
        "server": server,
        "user": user,
        "password": password,
        "verify_tls": verify_tls,
    }
