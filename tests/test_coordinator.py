"""Unit tests for the coordinator that updates myAir data."""

from unittest.mock import MagicMock

import pytest

from custom_components.resmed_myair.client.myair_client import AuthenticationError, ParsingError
from custom_components.resmed_myair.coordinator import MyAirDataUpdateCoordinator
from homeassistant.exceptions import ConfigEntryAuthFailed


@pytest.mark.asyncio
async def test_async_update_data_success(hass, myair_client):
    """Coordinator returns device and sleep_records on success."""
    coordinator = MyAirDataUpdateCoordinator(hass, MagicMock(), myair_client)
    data = await coordinator._async_update_data()
    assert data["device"] == {"serial": "1234"}
    assert data["sleep_records"] == [{"totalUsage": 60}]
    myair_client.connect.assert_awaited_once()
    myair_client.get_user_device_data.assert_awaited_once()
    myair_client.get_sleep_records.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_update_data_auth_error(hass, myair_client):
    """AuthenticationError in client.connect should raise ConfigEntryAuthFailed."""
    myair_client.connect.side_effect = AuthenticationError("bad creds")
    coordinator = MyAirDataUpdateCoordinator(hass, MagicMock(), myair_client)
    # Only assert that the correct exception type is raised. The exact
    # formatting of the exception message is an implementation detail and
    # should not make the test fragile.
    with pytest.raises(ConfigEntryAuthFailed):
        await coordinator._async_update_data()
    myair_client.connect.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_update_data_parsing_error_device(hass, myair_client):
    """ParsingError during device data fetch results in empty device dict."""
    myair_client.get_user_device_data.side_effect = ParsingError("device parse fail")
    coordinator = MyAirDataUpdateCoordinator(hass, MagicMock(), myair_client)
    data = await coordinator._async_update_data()
    assert data["device"] == {}
    # Unaffected path still returns defaults
    assert data["sleep_records"] == [{"totalUsage": 60}]
    myair_client.connect.assert_awaited_once()
    myair_client.get_user_device_data.assert_awaited_once()
    myair_client.get_sleep_records.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_update_data_parsing_error_sleep_records(hass, myair_client):
    """ParsingError during sleep record fetch results in empty sleep_records list."""
    myair_client.get_sleep_records.side_effect = ParsingError("sleep parse fail")
    coordinator = MyAirDataUpdateCoordinator(hass, MagicMock(), myair_client)
    data = await coordinator._async_update_data()
    assert data["sleep_records"] == []
    assert data["device"] == {"serial": "1234"}
    myair_client.connect.assert_awaited_once()
    myair_client.get_user_device_data.assert_awaited_once()
    myair_client.get_sleep_records.assert_awaited_once()
