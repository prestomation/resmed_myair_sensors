"""Coordinator tests that protect refresh, auth, and parse fallbacks."""

from unittest.mock import MagicMock

from homeassistant.exceptions import ConfigEntryAuthFailed
import pytest

from custom_components.resmed_myair.client.myair_client import AuthenticationError, ParsingError
from custom_components.resmed_myair.coordinator import MyAirDataUpdateCoordinator
from custom_components.resmed_myair.models import (
    MyAirCoordinatorData,
    MyAirDevice,
    MyAirSleepRecord,
)


@pytest.mark.asyncio
async def test_async_update_data_success(hass: MagicMock, myair_client: MagicMock) -> None:
    """Successful refreshes return both device data and sleep records."""
    myair_client.get_user_device_data.return_value = MyAirDevice.from_api(
        {
            "serialNumber": "1234",
            "fgDeviceManufacturerName": "ResMed",
            "deviceType": "AirSense",
            "localizedName": "Bedroom",
        }
    )
    myair_client.get_sleep_records.return_value = [
        MyAirSleepRecord.from_api({"totalUsage": 60, "startDate": "2024-07-01"})
    ]
    coordinator = MyAirDataUpdateCoordinator(hass, MagicMock(), myair_client)
    data = await coordinator._async_update_data()
    assert isinstance(data, MyAirCoordinatorData)
    assert data.device is not None
    assert data.device.serial_number == "1234"
    assert data.sleep_records == (
        MyAirSleepRecord.from_api({"totalUsage": 60, "startDate": "2024-07-01"}),
    )
    myair_client.connect.assert_awaited_once()
    myair_client.get_user_device_data.assert_awaited_once()
    myair_client.get_sleep_records.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_update_data_auth_error(hass: MagicMock, myair_client: MagicMock) -> None:
    """Authentication failures surface as config-entry auth errors."""
    myair_client.connect.side_effect = AuthenticationError("bad creds")
    coordinator = MyAirDataUpdateCoordinator(hass, MagicMock(), myair_client)
    # Only assert that the correct exception type is raised. The exact
    # formatting of the exception message is an implementation detail and
    # should not make the test fragile.
    with pytest.raises(ConfigEntryAuthFailed):
        await coordinator._async_update_data()
    myair_client.connect.assert_awaited_once()


@pytest.mark.parametrize("failing_fetch", ["device", "sleep_records"])
@pytest.mark.asyncio
async def test_async_update_data_parsing_error_variants(
    hass: MagicMock, myair_client: MagicMock, failing_fetch: str
) -> None:
    """Parsing failures degrade only the failing payload branch."""
    expected_device = MyAirDevice.from_api(
        {"serialNumber": "1234", "fgDeviceManufacturerName": "ResMed"}
    )
    expected_records = (MyAirSleepRecord.from_api({"totalUsage": 60, "startDate": "2024-07-01"}),)
    myair_client.get_user_device_data.return_value = expected_device
    myair_client.get_sleep_records.return_value = list(expected_records)

    if failing_fetch == "device":
        myair_client.get_user_device_data.side_effect = ParsingError("device parse fail")
    else:
        myair_client.get_sleep_records.side_effect = ParsingError("sleep parse fail")

    coordinator = MyAirDataUpdateCoordinator(hass, MagicMock(), myair_client)
    data = await coordinator._async_update_data()

    if failing_fetch == "device":
        assert data.device is None
        assert data.sleep_records == expected_records
    else:
        assert data.device is expected_device
        assert data.sleep_records == ()

    myair_client.connect.assert_awaited_once()
    myair_client.get_user_device_data.assert_awaited_once()
    myair_client.get_sleep_records.assert_awaited_once()
