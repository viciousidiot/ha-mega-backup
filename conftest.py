"""Shared pytest setup for the MEGA backup integration tests."""

from __future__ import annotations

import sys

import pytest
import pytest_socket

pytest_plugins = ["pytest_homeassistant_custom_component"]


def pytest_configure(config: pytest.Config) -> None:
    """Keep sockets usable on Windows.

    Home Assistant's test harness blocks sockets for every test so integrations
    cannot make accidental network calls. On Windows, however, creating the
    asyncio event loop requires a real socket pair, and that happens before any
    fixture (including ``socket_enabled``) has a chance to run. These tests
    talk to an in-process server on localhost, so disable the blocker here.
    """
    if sys.platform == "win32":
        pytest_socket.disable_socket = lambda *args, **kwargs: None


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations: None) -> None:
    """Allow Home Assistant to load the custom integration in every test."""
