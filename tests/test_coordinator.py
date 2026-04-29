"""Unit tests for the coordinator that updates myAir data."""

from datetime import date, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.resmed_myair.client.myair_client import AuthenticationError, ParsingError
from custom_components.resmed_myair.coordinator import (
    MyAirDataUpdateCoordinator,
    _merge_sleep_history,
)
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.util import dt as dt_util


@pytest.mark.asyncio
async def test_async_update_data_success(hass, myair_client):
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
async def test_async_update_data_parsing_error_sleep_records(hass, myair_client):
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


def test_merge_sleep_history_preserves_older_records():
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


def test_merge_sleep_history_updates_same_day_and_trims_window():
    """Merging should replace same-day records and trim history length."""
    today = date.today()
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


@pytest.mark.asyncio
async def test_async_update_data_merges_usage_history_from_recorder(hass, myair_client, monkeypatch):
    """Coordinator should seed local history from existing recorder usage statistics."""
    myair_client.get_user_device_data.return_value = {"serialNumber": "23172442329"}
    myair_client.get_sleep_records.return_value = [
        {"startDate": "2026-03-01", "totalUsage": 420},
        {"startDate": "2026-03-02", "totalUsage": 480},
    ]
    coordinator = MyAirDataUpdateCoordinator(hass, MagicMock(), myair_client)
    coordinator._sleep_history_store.async_save = AsyncMock()  # type: ignore[method-assign]

    class DummyRecorder:
        async def async_add_executor_job(self, func, *args):
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
                ]
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
    assert data["sleep_records_history"][1]["totalUsage"] == 271


@pytest.mark.asyncio
async def test_async_update_data_merges_usage_history_from_recorder_float_start(
    hass, myair_client, monkeypatch
):
    """Coordinator should handle recorder rows that return float timestamps."""
    myair_client.get_user_device_data.return_value = {"serialNumber": "23172442329"}
    myair_client.get_sleep_records.return_value = []
    coordinator = MyAirDataUpdateCoordinator(hass, MagicMock(), myair_client)
    coordinator._sleep_history_store.async_save = AsyncMock()  # type: ignore[method-assign]

    class DummyRecorder:
        async def async_add_executor_job(self, func, *args):
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
