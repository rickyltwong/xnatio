"""Tests for xnatio.xnat_client module."""

from __future__ import annotations

import logging
from unittest import mock

import pytest
import requests

from xnatio.xnat_client import _retry_on_network_error, XNATClient
from xnatio.config import XNATConfig


class TestRetryOnNetworkError:
    """Tests for _retry_on_network_error function."""

    def test_success_on_first_try(self) -> None:
        """Test that function returns immediately on success."""
        call_count = 0

        def fn() -> str:
            nonlocal call_count
            call_count += 1
            return "success"

        result = _retry_on_network_error(fn)
        assert result == "success"
        assert call_count == 1

    def test_retry_on_connection_error(self) -> None:
        """Test retry on ConnectionError."""
        call_count = 0

        def fn() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise requests.exceptions.ConnectionError("Connection failed")
            return "success"

        with mock.patch("time.sleep"):  # Skip actual sleep
            result = _retry_on_network_error(fn, max_retries=4, backoff_base=0.01)

        assert result == "success"
        assert call_count == 3

    def test_retry_on_timeout(self) -> None:
        """Test retry on Timeout."""
        call_count = 0

        def fn() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise requests.exceptions.Timeout("Request timed out")
            return "success"

        with mock.patch("time.sleep"):
            result = _retry_on_network_error(fn, max_retries=4, backoff_base=0.01)

        assert result == "success"
        assert call_count == 2

    def test_max_retries_exceeded(self) -> None:
        """Test that exception is raised after max retries."""

        def fn() -> str:
            raise requests.exceptions.ConnectionError("Always fails")

        with mock.patch("time.sleep"):
            with pytest.raises(requests.exceptions.ConnectionError):
                _retry_on_network_error(fn, max_retries=3, backoff_base=0.01)

    def test_non_network_error_not_retried(self) -> None:
        """Test that non-network errors are not retried."""
        call_count = 0

        def fn() -> str:
            nonlocal call_count
            call_count += 1
            raise ValueError("Not a network error")

        with pytest.raises(ValueError):
            _retry_on_network_error(fn, max_retries=3)

        assert call_count == 1  # Only one attempt

    def test_logging_on_retry(self) -> None:
        """Test that retries are logged."""
        call_count = 0
        logger = mock.Mock(spec=logging.Logger)

        def fn() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise requests.exceptions.ConnectionError("Failed")
            return "success"

        with mock.patch("time.sleep"):
            _retry_on_network_error(fn, max_retries=2, logger=logger)

        logger.warning.assert_called_once()
        assert "attempt 1" in str(logger.warning.call_args)

    def test_retry_on_os_error(self) -> None:
        """Test retry on OSError."""
        call_count = 0

        def fn() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise OSError("Network unreachable")
            return "success"

        with mock.patch("time.sleep"):
            result = _retry_on_network_error(fn, max_retries=2)

        assert result == "success"


class TestXNATClientFromConfig:
    """Tests for XNATClient.from_config method."""

    def test_from_config_basic(self) -> None:
        """Test creating client from basic config."""
        cfg: XNATConfig = {
            "server": "https://xnat.example.com",
            "user": "testuser",
            "password": "testpass",
            "verify_tls": True,
            "http_connect_timeout": 120,
            "http_read_timeout": 604800,
        }

        with mock.patch("xnatio.xnat_client.Interface"):
            client = XNATClient.from_config(cfg)

        assert client.server == "https://xnat.example.com"
        assert client.username == "testuser"
        assert client.password == "testpass"
        assert client.verify_tls is True
        assert client.http_timeouts == (120, 604800)

    def test_from_config_custom_timeouts(self) -> None:
        """Test creating client with custom timeouts."""
        cfg: XNATConfig = {
            "server": "https://xnat.example.com",
            "user": "testuser",
            "password": "testpass",
            "verify_tls": False,
            "http_connect_timeout": 60,
            "http_read_timeout": 300,
        }

        with mock.patch("xnatio.xnat_client.Interface"):
            client = XNATClient.from_config(cfg)

        assert client.verify_tls is False
        assert client.http_timeouts == (60, 300)

    def test_server_trailing_slash_stripped(self) -> None:
        """Test that trailing slash is stripped from server URL."""
        cfg: XNATConfig = {
            "server": "https://xnat.example.com/",
            "user": "testuser",
            "password": "testpass",
            "verify_tls": True,
            "http_connect_timeout": 120,
            "http_read_timeout": 604800,
        }

        with mock.patch("xnatio.xnat_client.Interface"):
            client = XNATClient.from_config(cfg)

        assert client.server == "https://xnat.example.com"


class TestXNATClientInit:
    """Tests for XNATClient initialization."""

    def test_init_creates_interface(self) -> None:
        """Test that __init__ creates an Interface."""
        with mock.patch("xnatio.xnat_client.Interface") as mock_interface:
            client = XNATClient(
                server="https://xnat.example.com",
                username="testuser",
                password="testpass",
            )

            mock_interface.assert_called_once_with(
                server="https://xnat.example.com",
                user="testuser",
                password="testpass",
                verify=True,
            )

    def test_init_with_custom_logger(self) -> None:
        """Test that custom logger is used."""
        custom_logger = logging.getLogger("custom")

        with mock.patch("xnatio.xnat_client.Interface"):
            client = XNATClient(
                server="https://xnat.example.com",
                username="testuser",
                password="testpass",
                logger=custom_logger,
            )

        assert client.log is custom_logger
