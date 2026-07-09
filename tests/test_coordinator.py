"""Coordinator tests that protect refresh, auth, and parse fallbacks."""

from collections.abc import Callable
import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.recorder import DATA_INSTANCE
from homeassistant.util import dt as dt_util
import pytest

from custom_components.resmed_myair.client.myair_client import AuthenticationError, ParsingError
from custom_components.resmed_myair.coordinator import (
    MyAirDataUpdateCoordinator,
    _merge_sleep_history,
)
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


def test_merge_sleep_history_preserves_existing_fields_for_partial_records() -> None:
    """Partial recorder rows should not erase details already saved for a day."""
    existing = [
        {
            "startDate": "2026-03-31",
            "totalUsage": 420,
            "ahi": 1.2,
            "maskPairCount": 1,
            "leakPercentile": 7,
            "sleepScore": 91,
        }
    ]
    latest = [{"startDate": "2026-03-31", "totalUsage": 421}]

    merged = _merge_sleep_history(existing, latest)

    assert merged == [
        {
            "startDate": "2026-03-31",
            "totalUsage": 421,
            "ahi": 1.2,
            "maskPairCount": 1,
            "leakPercentile": 7,
            "sleepScore": 91,
        }
    ]


@pytest.mark.asyncio
async def test_async_update_data_recovers_sleep_details_from_recorder(
    hass: MagicMock, myair_client: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Coordinator should recover historical details from existing recorder statistics."""
    myair_client.get_user_device_data.return_value = MyAirDevice.from_api(
        {"serialNumber": "23172442329"}
    )
    myair_client.get_sleep_records.return_value = []
    hass.data[DATA_INSTANCE] = object()
    coordinator = MyAirDataUpdateCoordinator(hass, MagicMock(), myair_client)
    coordinator._sleep_history_store.async_save = AsyncMock()  # type: ignore[method-assign]

    class DummyRecorder:
        async def async_add_executor_job(
            self, func: Callable[..., Any], *args: object
        ) -> dict[str, list[dict[str, object]]]:
            return {
                "resmed_myair:23172442329_usagehours_sum": [
                    {
                        "start": dt_util.parse_datetime("2026-02-27T08:00:00+00:00"),
                        "change": 7.33,
                    }
                ],
                "resmed_myair:23172442329_ahi": [
                    {
                        "start": dt_util.parse_datetime("2026-02-27T08:00:00+00:00"),
                        "state": 1.2,
                    }
                ],
                "resmed_myair:23172442329_maskpaircount": [
                    {
                        "start": dt_util.parse_datetime("2026-02-27T08:00:00+00:00"),
                        "state": 2.0,
                    }
                ],
                "resmed_myair:23172442329_leakpercentile": [
                    {
                        "start": dt_util.parse_datetime("2026-02-27T08:00:00+00:00"),
                        "state": 5.5,
                    }
                ],
                "resmed_myair:23172442329_sleepscore": [
                    {
                        "start": dt_util.parse_datetime("2026-02-27T08:00:00+00:00"),
                        "state": 88.0,
                    }
                ],
            }

    monkeypatch.setattr(
        "custom_components.resmed_myair.coordinator.get_instance",
        lambda hass: DummyRecorder(),
    )

    await coordinator._async_update_data()

    assert coordinator.chart_sleep_records == [
        {
            "startDate": "2026-02-27",
            "totalUsage": 440,
            "ahi": 1.2,
            "maskPairCount": 2.0,
            "leakPercentile": 5.5,
            "sleepScore": 88.0,
        }
    ]


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
    hass: MagicMock,
    myair_client: MagicMock,
    failing_fetch: str,
    caplog: pytest.LogCaptureFixture,
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
    with caplog.at_level(logging.DEBUG):
        data = await coordinator._async_update_data()

    if failing_fetch == "device":
        assert data.device is None
        assert data.sleep_records == expected_records
        assert (
            "Device data unavailable in myAir update. ParsingError: device parse fail"
            in caplog.text
        )
    else:
        assert data.device is expected_device
        assert data.sleep_records == ()
        assert (
            "Sleep record data unavailable in myAir update. ParsingError: sleep parse fail"
            in caplog.text
        )

    myair_client.connect.assert_awaited_once()
    myair_client.get_user_device_data.assert_awaited_once()
    myair_client.get_sleep_records.assert_awaited_once()
