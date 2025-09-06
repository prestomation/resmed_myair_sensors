"""Shared pytest fixtures used across the test suite."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.resmed_myair.const import CONF_PASSWORD, CONF_REGION, CONF_USER_NAME


@pytest.fixture
def config_entry():
    """Return a MagicMock config entry with realistic default data."""
    entry = MagicMock()
    entry.data = {
        CONF_USER_NAME: "test@example.com",
        CONF_PASSWORD: "dummy_password",
        CONF_REGION: "NA",
    }
    entry.entry_id = "mock_entry_id"
    entry.title = "ResMed-CPAP"
    entry.domain = "resmed_myair"
    entry.unique_id = "unique_id_123"
    entry.options = {}
    entry.async_setup = AsyncMock(return_value=True)
    entry.async_unload = AsyncMock(return_value=True)
    entry.async_remove = AsyncMock(return_value=True)
    entry.runtime_data = None
    return entry


@pytest.fixture
def coordinator():
    """Return a simple AsyncMock used as a data update coordinator in tests."""
    return AsyncMock()


@pytest.fixture
def hass():
    """Canonical Home Assistant mock fixture with common attributes."""
    hass_instance = MagicMock()
    hass_instance.config_entries = MagicMock()
    hass_instance.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass_instance.services = MagicMock()
    return hass_instance
