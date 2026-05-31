"""Unit tests for the coordinator that updates myAir data."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.util import dt as dt_util
import pytest

from custom_components.resmed_myair.client.myair_client import AuthenticationError, ParsingError
from custom_components.resmed_myair.coordinator import (
    MyAirDataUpdateCoordinator,
    _merge_sleep_history,
)


@pytest.mark.asyncio
async def test_async_update_data_success(hass: MagicMock, myair_client: MagicMock) -> None:
    """Coordinator returns device and sleep_records on success."""
    coordinator = MyAirDataUpdateCoordinator(hass, MagicMock(), myair_client)
    coordinator._sleep_history_store.async_save = AsyncMock()  # type: ignore[method-assign]
    data = await coordinator._async_update_data()
    assert data["device"] == {"serial": "1234"}
    assert data["sleep_records"] == [{"totalUsage": 60}]
    assert data["sleep_records_history"] == []
    myair_client.connect.assert_awaited_once()
    myair_client.get_user_device_data.assert_awaited_once()
    myair_client.get_sleep_records.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_update_data_auth_error(hass: MagicMock, myair_client: MagicMock) -> None:
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
async def test_async_update_data_parsing_error_device(
    hass: MagicMock, myair_client: MagicMock
) -> None:
    """ParsingError during device data fetch results in empty device dict."""
    myair_client.get_user_device_data.side_effect = ParsingError("device parse fail")
    coordinator = MyAirDataUpdateCoordinator(hass, MagicMock(), myair_client)
    coordinator._sleep_history_store.async_save = AsyncMock()  # type: ignore[method-assign]
    data = await coordinator._async_update_data()
    assert data["device"] == {}
    # Unaffected path still returns defaults
    assert data["sleep_records"] == [{"totalUsage": 60}]
    assert data["sleep_records_history"] == []
    myair_client.connect.assert_awaited_once()
    myair_client.get_user_device_data.assert_awaited_once()
    myair_client.get_sleep_records.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_update_data_parsing_error_sleep_records(
    hass: MagicMock, myair_client: MagicMock
) -> None:
    """ParsingError during sleep record fetch results in empty sleep_records list."""
    myair_client.get_sleep_records.side_effect = ParsingError("sleep parse fail")
    coordinator = MyAirDataUpdateCoordinator(hass, MagicMock(), myair_client)
    coordinator._sleep_history_store.async_save = AsyncMock()  # type: ignore[method-assign]
    data = await coordinator._async_update_data()
    assert data["sleep_records"] == []
    assert data["device"] == {"serial": "1234"}
    assert data["sleep_records_history"] == []
    myair_client.connect.assert_awaited_once()
    myair_client.get_user_device_data.assert_awaited_once()
    myair_client.get_sleep_records.assert_awaited_once()


def test_merge_sleep_history_preserves_older_records() -> None:
    """Merging should keep older records that have aged out of the cloud window."""
    existing = [
        {"startDate": "2026-02-26", "totalUsage": 100},
        {"startDate": "2026-02-27", "totalUsage": 200},
        {"startDate": "2026-02-28", "totalUsage": 300},
    ]
    latest = [
        {"startDate": "2026-03-01", "totalUsage": 400},
        {"startDate": "2026-03-02", "totalUsage": 500},
    ]

    merged = _merge_sleep_history(existing, latest)

    assert [record["startDate"] for record in merged] == [
        "2026-02-26",
        "2026-02-27",
        "2026-02-28",
        "2026-03-01",
        "2026-03-02",
    ]


def test_merge_sleep_history_updates_same_day_and_trims_window() -> None:
    """Merging should replace same-day records and trim history length."""
    today = datetime.now(UTC).date()
    existing = [
        {
            "startDate": (today - timedelta(days=offset)).isoformat(),
            "totalUsage": offset,
        }
        for offset in range(500, 0, -1)
    ]
    latest = [
        {"startDate": today.isoformat(), "totalUsage": 999},
        {"startDate": (today - timedelta(days=1)).isoformat(), "totalUsage": 111},
    ]

    merged = _merge_sleep_history(existing, latest)

    assert len(merged) == 400
    assert merged[-1]["startDate"] == today.isoformat()
    assert merged[-1]["totalUsage"] == 999
    assert merged[-2]["startDate"] == (today - timedelta(days=1)).isoformat()
    assert merged[-2]["totalUsage"] == 111


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
async def test_async_update_data_merges_usage_history_from_recorder(
    hass: MagicMock, myair_client: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Coordinator should seed local history from existing recorder usage statistics."""
    myair_client.get_user_device_data.return_value = {"serialNumber": "23172442329"}
    myair_client.get_sleep_records.return_value = [
        {"startDate": "2026-03-01", "totalUsage": 420},
        {"startDate": "2026-03-02", "totalUsage": 480},
    ]
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
                    },
                    {
                        "start": dt_util.parse_datetime("2026-02-28T08:00:00+00:00"),
                        "change": 4.52,
                    },
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

    monkeypatch.setattr("custom_components.resmed_myair.coordinator.get_instance", lambda hass: DummyRecorder())

    data = await coordinator._async_update_data()

    assert [record["startDate"] for record in coordinator._usage_hours_history] == [
        "2026-02-27",
        "2026-02-28",
    ]
    assert [record["startDate"] for record in data["sleep_records_history"]] == [
        "2026-02-27",
        "2026-02-28",
        "2026-03-01",
        "2026-03-02",
    ]
    assert data["sleep_records_history"][0]["totalUsage"] == 440
    assert data["sleep_records_history"][0]["ahi"] == 1.2
    assert data["sleep_records_history"][0]["maskPairCount"] == 2.0
    assert data["sleep_records_history"][0]["leakPercentile"] == 5.5
    assert data["sleep_records_history"][0]["sleepScore"] == 88.0
    assert data["sleep_records_history"][1]["totalUsage"] == 271


@pytest.mark.asyncio
async def test_async_update_data_merges_usage_history_from_recorder_float_start(
    hass: MagicMock, myair_client: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Coordinator should handle recorder rows that return float timestamps."""
    myair_client.get_user_device_data.return_value = {"serialNumber": "23172442329"}
    myair_client.get_sleep_records.return_value = []
    coordinator = MyAirDataUpdateCoordinator(hass, MagicMock(), myair_client)
    coordinator._sleep_history_store.async_save = AsyncMock()  # type: ignore[method-assign]

    class DummyRecorder:
        async def async_add_executor_job(
            self, func: Callable[..., Any], *args: object
        ) -> dict[str, list[dict[str, object]]]:
            return {
                "resmed_myair:23172442329_usagehours_sum": [
                    {
                        "start": 1772179200.0,
                        "change": 7.33,
                    }
                ]
            }

    monkeypatch.setattr("custom_components.resmed_myair.coordinator.get_instance", lambda hass: DummyRecorder())

    data = await coordinator._async_update_data()

    assert coordinator._usage_hours_history == [
        {"startDate": "2026-02-27", "totalUsage": 440}
    ]
    assert data["sleep_records_history"] == [
        {"startDate": "2026-02-27", "totalUsage": 440}
    ]
