"""Unit tests for the coordinator that updates myAir data."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.resmed_myair.client.myair_client import AuthenticationError, ParsingError
from custom_components.resmed_myair.coordinator import MyAirDataUpdateCoordinator
from homeassistant.exceptions import ConfigEntryAuthFailed


@pytest.fixture
def myair_client():
    """Return a MagicMock configured as a myair client with default return values."""
    client = MagicMock()
    client.connect = AsyncMock()
    client.get_user_device_data = AsyncMock(return_value={"serial": "1234"})
    client.get_sleep_records = AsyncMock(return_value=[{"totalUsage": 60}])
    return client


@pytest.mark.asyncio
async def test_async_update_data_success(hass, myair_client):
    """Coordinator returns device and sleep_records on success."""
    coordinator = MyAirDataUpdateCoordinator(hass, myair_client)
    data = await coordinator._async_update_data()
    assert data["device"] == {"serial": "1234"}
    assert data["sleep_records"] == [{"totalUsage": 60}]


@pytest.mark.asyncio
async def test_async_update_data_auth_error(hass, myair_client):
    """AuthenticationError in client.connect should raise ConfigEntryAuthFailed."""
    myair_client.connect.side_effect = AuthenticationError("bad creds")
    coordinator = MyAirDataUpdateCoordinator(hass, myair_client)
    with pytest.raises(ConfigEntryAuthFailed) as excinfo:
        await coordinator._async_update_data()
    assert "Authentication Error" in str(excinfo.value)


@pytest.mark.asyncio
async def test_async_update_data_parsing_error_device(hass, myair_client):
    """ParsingError during device data fetch results in empty device dict."""
    myair_client.get_user_device_data.side_effect = ParsingError("device parse fail")
    coordinator = MyAirDataUpdateCoordinator(hass, myair_client)
    data = await coordinator._async_update_data()
    assert data["device"] == {}


@pytest.mark.asyncio
async def test_async_update_data_parsing_error_sleep_records(hass, myair_client):
    """ParsingError during sleep record fetch results in empty sleep_records list."""
    myair_client.get_sleep_records.side_effect = ParsingError("sleep parse fail")
    coordinator = MyAirDataUpdateCoordinator(hass, myair_client)
    data = await coordinator._async_update_data()
    assert data["sleep_records"] == []
