import os
from pathlib import Path
from typing import Dict, Optional

from dotenv import load_dotenv


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _dotenv_path(env_name: Optional[str]) -> Path:
    root = _project_root()
    if env_name and env_name.lower() in {"test", "testing"}:
        return root / ".env.test"
    if env_name and env_name.lower() in {"prod", "production"}:
        return root / ".env.prod"
    if env_name and env_name.lower() in {"dev", "development"}:
        return root / ".env.dev"
    return root / ".env"


def _str_to_bool(value: Optional[str], default: bool = True) -> bool:
    if value is None:
        return default
    value_norm = value.strip().lower()
    if value_norm in {"1", "true", "yes", "y", "on"}:
        return True
    if value_norm in {"0", "false", "no", "n", "off"}:
        return False
    return default


def load_config(env_name: Optional[str] = None) -> Dict[str, object]:
    """
    Load configuration from .env or .env.dev into a normalized dict used by the app.

    Expected variables in the .env file:
      - XNAT_SERVER
      - XNAT_USERNAME
      - XNAT_PASSWORD
      - XNAT_VERIFY_TLS (optional, default True)
    """
    # Allow environment variable to choose the env file if not provided explicitly
    env_name = env_name or os.getenv("XNATIO_ENV") or os.getenv("ENV")

    dotenv_file = _dotenv_path(env_name)
    if dotenv_file.exists():
        load_dotenv(dotenv_file)
    else:
        raise FileNotFoundError(f"Environment file not found: {dotenv_file}")

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
