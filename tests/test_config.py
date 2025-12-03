"""Tests for xnatio.config module."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Generator
from unittest import mock

import pytest

from xnatio.config import (
    XNATConfig,
    _str_to_bool,
    _parse_int,
    load_config,
    DEFAULT_HTTP_CONNECT_TIMEOUT,
    DEFAULT_HTTP_READ_TIMEOUT,
)


class TestStrToBool:
    """Tests for _str_to_bool function."""

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("1", True),
            ("true", True),
            ("True", True),
            ("TRUE", True),
            ("yes", True),
            ("Yes", True),
            ("y", True),
            ("Y", True),
            ("on", True),
            ("ON", True),
            ("0", False),
            ("false", False),
            ("False", False),
            ("FALSE", False),
            ("no", False),
            ("No", False),
            ("n", False),
            ("N", False),
            ("off", False),
            ("OFF", False),
        ],
    )
    def test_valid_values(self, value: str, expected: bool) -> None:
        """Test that valid string values are parsed correctly."""
        assert _str_to_bool(value) == expected

    def test_none_returns_default(self) -> None:
        """Test that None returns the default value."""
        assert _str_to_bool(None, default=True) is True
        assert _str_to_bool(None, default=False) is False

    def test_invalid_returns_default(self) -> None:
        """Test that invalid values return the default."""
        assert _str_to_bool("invalid", default=True) is True
        assert _str_to_bool("invalid", default=False) is False
        assert _str_to_bool("", default=True) is True

    def test_whitespace_handling(self) -> None:
        """Test that whitespace is stripped."""
        assert _str_to_bool("  true  ") is True
        assert _str_to_bool("  false  ") is False


class TestParseInt:
    """Tests for _parse_int function."""

    def test_valid_integers(self) -> None:
        """Test parsing valid integer strings."""
        assert _parse_int("123", default=0) == 123
        assert _parse_int("0", default=100) == 0
        assert _parse_int("-42", default=0) == -42

    def test_none_returns_default(self) -> None:
        """Test that None returns the default value."""
        assert _parse_int(None, default=100) == 100

    def test_invalid_returns_default(self) -> None:
        """Test that invalid values return the default."""
        assert _parse_int("not_a_number", default=50) == 50
        assert _parse_int("12.34", default=50) == 50
        assert _parse_int("", default=50) == 50

    def test_whitespace_handling(self) -> None:
        """Test that whitespace is stripped."""
        assert _parse_int("  42  ", default=0) == 42


class TestLoadConfig:
    """Tests for load_config function."""

    @pytest.fixture
    def clean_env(self) -> Generator[None, None, None]:
        """Fixture to clean XNAT environment variables."""
        env_vars = [
            "XNAT_SERVER",
            "XNAT_USERNAME",
            "XNAT_PASSWORD",
            "XNAT_VERIFY_TLS",
            "XNAT_HTTP_CONNECT_TIMEOUT",
            "XNAT_HTTP_READ_TIMEOUT",
        ]
        old_values = {k: os.environ.get(k) for k in env_vars}
        for var in env_vars:
            os.environ.pop(var, None)
        yield
        for var, val in old_values.items():
            if val is not None:
                os.environ[var] = val
            else:
                os.environ.pop(var, None)

    def test_load_from_env(self, clean_env: None) -> None:
        """Test loading config from environment variables."""
        os.environ["XNAT_SERVER"] = "https://xnat.example.com"
        os.environ["XNAT_USERNAME"] = "testuser"
        os.environ["XNAT_PASSWORD"] = "testpass"

        cfg = load_config()

        assert cfg["server"] == "https://xnat.example.com"
        assert cfg["user"] == "testuser"
        assert cfg["password"] == "testpass"
        assert cfg["verify_tls"] is True
        assert cfg["http_connect_timeout"] == DEFAULT_HTTP_CONNECT_TIMEOUT
        assert cfg["http_read_timeout"] == DEFAULT_HTTP_READ_TIMEOUT

    def test_load_with_custom_tls_and_timeouts(self, clean_env: None) -> None:
        """Test loading config with custom TLS and timeout settings."""
        os.environ["XNAT_SERVER"] = "https://xnat.example.com"
        os.environ["XNAT_USERNAME"] = "testuser"
        os.environ["XNAT_PASSWORD"] = "testpass"
        os.environ["XNAT_VERIFY_TLS"] = "false"
        os.environ["XNAT_HTTP_CONNECT_TIMEOUT"] = "60"
        os.environ["XNAT_HTTP_READ_TIMEOUT"] = "300"

        cfg = load_config()

        assert cfg["verify_tls"] is False
        assert cfg["http_connect_timeout"] == 60
        assert cfg["http_read_timeout"] == 300

    def test_missing_required_vars_raises(self, clean_env: None) -> None:
        """Test that missing required variables raise RuntimeError."""
        # Missing all required vars
        with pytest.raises(RuntimeError) as exc_info:
            load_config()
        assert "XNAT_SERVER" in str(exc_info.value)

        # Missing password
        os.environ["XNAT_SERVER"] = "https://xnat.example.com"
        os.environ["XNAT_USERNAME"] = "testuser"
        with pytest.raises(RuntimeError) as exc_info:
            load_config()
        assert "XNAT_PASSWORD" in str(exc_info.value)

    def test_load_from_env_file(self, clean_env: None) -> None:
        """Test loading config from a .env file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("XNAT_SERVER=https://file.example.com\n")
            f.write("XNAT_USERNAME=fileuser\n")
            f.write("XNAT_PASSWORD=filepass\n")
            f.write("XNAT_VERIFY_TLS=no\n")
            env_path = Path(f.name)

        try:
            cfg = load_config(env_path)
            assert cfg["server"] == "https://file.example.com"
            assert cfg["user"] == "fileuser"
            assert cfg["password"] == "filepass"
            assert cfg["verify_tls"] is False
        finally:
            env_path.unlink()

    def test_env_file_not_found_raises(self, clean_env: None) -> None:
        """Test that non-existent env file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_config(Path("/nonexistent/.env"))

    def test_xnat_config_type(self, clean_env: None) -> None:
        """Test that returned config matches XNATConfig type."""
        os.environ["XNAT_SERVER"] = "https://xnat.example.com"
        os.environ["XNAT_USERNAME"] = "testuser"
        os.environ["XNAT_PASSWORD"] = "testpass"

        cfg = load_config()

        # Check all required keys exist
        assert "server" in cfg
        assert "user" in cfg
        assert "password" in cfg
        assert "verify_tls" in cfg
        assert "http_connect_timeout" in cfg
        assert "http_read_timeout" in cfg
