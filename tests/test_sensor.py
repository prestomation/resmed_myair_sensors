"""Unit tests for sensor entities in the resmed_myair integration."""

from datetime import datetime
import logging
from unittest.mock import MagicMock

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.resmed_myair.const import CONF_USER_NAME
from custom_components.resmed_myair.sensor import (
    MyAirDeviceSensor,
    MyAirFriendlyUsageTime,
    MyAirMostRecentSleepDate,
    MyAirSleepRecordSensor,
    MyAirUsageHoursAverageSensor,
    MyAirUsageHoursSensor,
    async_setup_entry,
)
from homeassistant.components.sensor import SensorDeviceClass, SensorEntityDescription
from homeassistant.util import dt as dt_util


@pytest.mark.parametrize(
    "data,sensor_key,device_class,expected_available",
    [
        ({}, "foo", None, False),  # No device
        ({"device": {}}, "foo", None, False),  # KeyError
        ({"device": {"foo": "bar"}}, "foo", None, True),  # Success, not timestamp
        (
            {"device": {"foo": "2024-07-18T12:34:56+00:00"}},
            "foo",
            SensorDeviceClass.TIMESTAMP,
            True,
        ),  # Success, timestamp
    ],
)
def test_device_sensor_all_branches(
    data, sensor_key, device_class, expected_available, monkeypatch, coordinator_factory
):
    """Parametrized tests for MyAirDeviceSensor behavior across branches."""
    # Construct description using the explicit device_class parameter so the test
    # deterministically controls whether the sensor is a timestamp sensor.
    if device_class is None:
        desc = SensorEntityDescription(key=sensor_key)
    else:
        desc = SensorEntityDescription(key=sensor_key, device_class=device_class)
    coordinator = coordinator_factory(data=data)
    sensor = MyAirDeviceSensor("Test", desc, coordinator)
    monkeypatch.setattr(sensor, "async_write_ha_state", MagicMock(return_value=None))
    sensor._handle_coordinator_update()
    assert sensor.available == expected_available


@pytest.mark.parametrize(
    "data,expected_native,expected_available",
    [
        ({}, None, False),  # No sleep_records
        ({"sleep_records": []}, None, False),  # Empty sleep_records
        ({"sleep_records": [{}]}, None, False),  # KeyError
        ({"sleep_records": [{"totalUsage": 10}]}, "0:10", True),  # Success
        ({"sleep_records": [{"totalUsage": -10}]}, "0:00", True),  # Negative usage, clamped
    ],
)
def test_friendly_usage_time_all_branches(
    data, expected_native, expected_available, monkeypatch, coordinator_factory
):
    """Parametrized tests for MyAirFriendlyUsageTime behavior across branches."""
    coordinator = coordinator_factory(data=data)
    sensor = MyAirFriendlyUsageTime(coordinator)
    monkeypatch.setattr(sensor, "async_write_ha_state", MagicMock(return_value=None))
    sensor._handle_coordinator_update()
    assert sensor.available == expected_available
    # Only check native_value if available
    if expected_available:
        assert sensor.native_value == expected_native


@pytest.mark.parametrize(
    "data,days,expected_native,expected_available",
    [
        ({}, 7, None, False),
        ({"sleep_records": []}, 7, None, False),
        (
            {
                "sleep_records": [
                    {"startDate": "2024-07-01", "totalUsage": 60},
                    {"startDate": "2024-07-02", "totalUsage": 120},
                    {"startDate": "2024-07-03", "totalUsage": 180},
                ]
            },
            7,
            2.0,
            True,
        ),
        (
            {
                "sleep_records": [
                    {"startDate": "2024-07-01", "totalUsage": 60},
                    {"startDate": "2024-07-02", "totalUsage": 120},
                    {"startDate": "2024-07-03", "totalUsage": 180},
                ]
            },
            2,
            2.5,
            True,
        ),
        (
            {
                "sleep_records": [
                    {"startDate": "2024-07-01", "totalUsage": -60},
                    {"startDate": "2024-07-02", "totalUsage": 120},
                ]
            },
            7,
            1.0,
            True,
        ),
    ],
)
def test_usage_hours_average_all_branches(
    data, days, expected_native, expected_available, monkeypatch, coordinator_factory
):
    """Parametrized tests for rolling average usage hours sensors."""
    coordinator = coordinator_factory(data=data)
    sensor = MyAirUsageHoursAverageSensor(coordinator, days=days)
    monkeypatch.setattr(sensor, "async_write_ha_state", MagicMock(return_value=None))
    sensor._handle_coordinator_update()
    assert sensor.available == expected_available
    assert sensor.native_value == expected_native


@pytest.mark.asyncio
async def test_usage_hours_imports_external_statistics(hass, monkeypatch, coordinator_factory):
    """Ensure usage hours imports dated records as external statistics."""
    coordinator = coordinator_factory(
        data={
            "device": {"serialNumber": "SN123"},
            "sleep_records": [
                {"startDate": "2024-07-01", "totalUsage": 120},
                {"startDate": "2024-07-02", "totalUsage": 180},
            ],
        }
    )
    sensor = MyAirUsageHoursSensor(coordinator)
    sensor.hass = hass

    imported: list = []

    class DummyRecorder:
        async def async_add_executor_job(self, func, *args):
            return func(*args)

    monkeypatch.setattr("custom_components.resmed_myair.sensor.get_instance", lambda hass: DummyRecorder())
    monkeypatch.setattr(
        "custom_components.resmed_myair.sensor.get_last_statistics",
        lambda *args: {},
    )
    monkeypatch.setattr(
        "custom_components.resmed_myair.sensor.async_add_external_statistics",
        lambda hass, metadata, statistics: imported.append((metadata, list(statistics))),
    )
    monkeypatch.setattr(sensor, "async_write_ha_state", MagicMock(return_value=None))

    await sensor.async_added_to_hass()
    await hass.async_block_till_done()

    assert imported
    metadata, statistics = imported[0]
    assert metadata["source"] == "resmed_myair"
    assert metadata["statistic_id"] == "resmed_myair:sn123_usagehours_sum"
    assert metadata["unit_of_measurement"] == "h"
    assert metadata["has_mean"] is False
    assert metadata["has_sum"] is True
    assert len(statistics) == 2
    assert statistics[0]["start"] == datetime(2024, 7, 1, tzinfo=dt_util.DEFAULT_TIME_ZONE)
    assert statistics[0]["sum"] == 2.0
    assert statistics[1]["sum"] == 5.0
    assert sensor.extra_state_attributes == {
        "historical_statistic_id": "resmed_myair:sn123_usagehours_sum",
        "daily_usage_hours": [
            {
                "date": "2024-07-01",
                "hours": 2.0,
                "minutes": 120,
                "ahi": None,
                "mask_on_off": None,
                "mask_leak_percent": None,
                "myair_score": None,
            },
            {
                "date": "2024-07-02",
                "hours": 3.0,
                "minutes": 180,
                "ahi": None,
                "mask_on_off": None,
                "mask_leak_percent": None,
                "myair_score": None,
            },
        ],
    }


@pytest.mark.asyncio
async def test_usage_hours_import_skips_existing_statistics(hass, monkeypatch, coordinator_factory):
    """Ensure import only adds new nightly records after the last imported date."""
    coordinator = coordinator_factory(
        data={
            "device": {"serialNumber": "SN123"},
            "sleep_records": [
                {"startDate": "2024-07-01", "totalUsage": 120},
                {"startDate": "2024-07-02", "totalUsage": 180},
            ],
        }
    )
    sensor = MyAirUsageHoursSensor(coordinator)
    sensor.hass = hass

    imported: list = []

    class DummyRecorder:
        async def async_add_executor_job(self, func, *args):
            return func(*args)

    monkeypatch.setattr("custom_components.resmed_myair.sensor.get_instance", lambda hass: DummyRecorder())
    monkeypatch.setattr(
        "custom_components.resmed_myair.sensor.get_last_statistics",
        lambda *args: {
            "resmed_myair:sn123_usagehours_sum": [
                {
                    "end": datetime(2024, 7, 1, 23, 0, tzinfo=dt_util.DEFAULT_TIME_ZONE),
                    "sum": 2.0,
                }
            ]
        },
    )
    monkeypatch.setattr(
        "custom_components.resmed_myair.sensor.async_add_external_statistics",
        lambda hass, metadata, statistics: imported.append((metadata, list(statistics))),
    )
    monkeypatch.setattr(sensor, "async_write_ha_state", MagicMock(return_value=None))

    await sensor.async_added_to_hass()
    await hass.async_block_till_done()

    assert imported
    _, statistics = imported[0]
    assert len(statistics) == 1
    assert statistics[0]["start"] == datetime(2024, 7, 2, tzinfo=dt_util.DEFAULT_TIME_ZONE)
    assert statistics[0]["sum"] == 5.0


def test_usage_hours_sensor_exposes_daily_history(monkeypatch, coordinator_factory):
    """Ensure usage hours sensor exposes daily history for custom chart cards."""
    coordinator = coordinator_factory(
        data={
            "device": {"serialNumber": "SN123"},
            "sleep_records": [
                {
                    "startDate": "2024-07-01",
                    "totalUsage": 120,
                    "ahi": 1.4,
                    "maskPairCount": 2,
                    "leakPercentile": 7,
                    "sleepScore": 88,
                },
                {
                    "startDate": "2024-07-02",
                    "totalUsage": -30,
                    "ahi": 0.9,
                    "maskPairCount": 1,
                    "leakPercentile": 3,
                    "sleepScore": 91,
                },
            ],
        }
    )
    sensor = MyAirUsageHoursSensor(coordinator)
    monkeypatch.setattr(sensor, "async_write_ha_state", MagicMock(return_value=None))

    sensor._handle_coordinator_update()

    assert sensor.extra_state_attributes == {
        "historical_statistic_id": "resmed_myair:sn123_usagehours_sum",
        "daily_usage_hours": [
            {
                "date": "2024-07-01",
                "hours": 2.0,
                "minutes": 120,
                "ahi": 1.4,
                "mask_on_off": 2,
                "mask_leak_percent": 7,
                "myair_score": 88,
            },
            {
                "date": "2024-07-02",
                "hours": 0.0,
                "minutes": 0,
                "ahi": 0.9,
                "mask_on_off": 1,
                "mask_leak_percent": 3,
                "myair_score": 91,
            },
        ],
    }


def test_usage_hours_sensor_prefers_persisted_history(monkeypatch, coordinator_factory):
    """Ensure dashboard history uses persisted sleep_records_history, not only live cloud records."""
    coordinator = coordinator_factory(
        data={
            "device": {"serialNumber": "SN123"},
            "sleep_records": [
                {"startDate": "2026-03-01", "totalUsage": 120},
            ],
            "sleep_records_history": [
                {"startDate": "2026-02-27", "totalUsage": 420},
                {"startDate": "2026-02-28", "totalUsage": 360},
                {"startDate": "2026-03-01", "totalUsage": 120},
            ],
        }
    )
    sensor = MyAirUsageHoursSensor(coordinator)
    monkeypatch.setattr(sensor, "async_write_ha_state", MagicMock(return_value=None))

    sensor._handle_coordinator_update()

    assert [entry["date"] for entry in sensor.extra_state_attributes["daily_usage_hours"]] == [
        "2026-02-27",
        "2026-02-28",
        "2026-03-01",
    ]


def test_usage_hours_sensor_merges_recorder_usage_history(monkeypatch, coordinator_factory):
    """Ensure dashboard history includes recorder-backed usage dates when persisted history is incomplete."""
    coordinator = coordinator_factory(
        data={
            "device": {"serialNumber": "SN123"},
            "sleep_records": [
                {"startDate": "2026-03-01", "totalUsage": 120},
            ],
            "sleep_records_history": [
                {"startDate": "2026-03-01", "totalUsage": 120},
            ],
        }
    )
    coordinator._usage_hours_history = [  # type: ignore[attr-defined]
        {"startDate": "2026-02-27", "totalUsage": 420},
        {"startDate": "2026-02-28", "totalUsage": 360},
    ]
    sensor = MyAirUsageHoursSensor(coordinator)
    monkeypatch.setattr(sensor, "async_write_ha_state", MagicMock(return_value=None))

    sensor._handle_coordinator_update()

    assert [entry["date"] for entry in sensor.extra_state_attributes["daily_usage_hours"]] == [
        "2026-02-27",
        "2026-02-28",
        "2026-03-01",
    ]


@pytest.mark.parametrize(
    "data,expected_native,expected_available",
    [
        ({}, None, False),  # No sleep_records
        ({"sleep_records": []}, None, False),  # Empty sleep_records
        (
            {"sleep_records": [{"totalUsage": 0, "startDate": "2024-07-15"}]},
            None,
            False,
        ),  # All zero usage
        (
            {"sleep_records": [{"totalUsage": 10, "startDate": "2024-07-16"}]},
            "2024-07-16",
            True,
        ),  # Success
        (
            {"sleep_records": [{"startDate": "2024-07-16"}]},
            None,
            False,
        ),  # KeyError
    ],
)
def test_most_recent_sleep_date_all_branches(
    data, expected_native, expected_available, monkeypatch, coordinator_factory
):
    """Parametrized tests for MyAirMostRecentSleepDate behavior across branches."""
    coordinator = coordinator_factory(data=data)
    sensor = MyAirMostRecentSleepDate(coordinator)
    monkeypatch.setattr(sensor, "async_write_ha_state", MagicMock(return_value=None))
    sensor._handle_coordinator_update()
    assert sensor.available == expected_available
    if expected_available:
        # sensor.native_value is a date object
        assert str(sensor.native_value) == expected_native


@pytest.mark.parametrize(
    "sleep_records,sensor_key,device_class,expected_value,expected_available",
    [
        (None, "foo", None, None, False),
        ([], "foo", None, None, False),
        ([{}], "foo", None, None, False),
        # For date parsing, we use a string and monkeypatch dt_util.parse_date in the test body
        ([{"foo": "2024-07-18"}], "foo", SensorDeviceClass.DATE, "2024-07-18", True),
        ([{"foo": "some string"}], "foo", None, "some string", True),
    ],
)
def test_sleep_record_sensor_handle_coordinator_update(
    sleep_records,
    sensor_key,
    device_class,
    expected_value,
    expected_available,
    monkeypatch,
    coordinator_factory,
):
    """Parametrized tests for MyAirSleepRecordSensor handling various record formats."""
    # Patch dt_util.parse_date to return a sentinel for test
    if device_class == SensorDeviceClass.DATE:
        parsed_date = object()
        monkeypatch.setattr(
            "custom_components.resmed_myair.sensor.dt_util.parse_date",
            lambda v: parsed_date,
        )
        expected_value = parsed_date

    desc = SensorEntityDescription(key=sensor_key, device_class=device_class)
    data = {}
    if sleep_records is not None:
        data["sleep_records"] = sleep_records
    coordinator = coordinator_factory(data=data)
    sensor = MyAirSleepRecordSensor("Test", desc, coordinator)
    monkeypatch.setattr(sensor, "async_write_ha_state", MagicMock(return_value=None))
    sensor._handle_coordinator_update()
    assert sensor.available == expected_available
    assert sensor.native_value == expected_value


@pytest.mark.parametrize(
    "device_data,sensor_key,device_class,expected_native,expected_available,patch_parse_datetime",
    [
        # No device in coordinator data
        (None, "foo", None, None, False, False),
        # Device present but key missing
        ({}, "foo", None, None, False, False),
        # Device present, key present, not a timestamp
        ({"foo": "bar"}, "foo", None, "bar", True, False),
        # Device present, key present, is a timestamp string, device_class is TIMESTAMP
        (
            {"foo": "2024-07-18T12:34:56+00:00"},
            "foo",
            SensorDeviceClass.TIMESTAMP,
            "parsed_dt",
            True,
            True,
        ),
        # Device present, key present, is a timestamp string, device_class is not TIMESTAMP
        (
            {"foo": "2024-07-18T12:34:56+00:00"},
            "foo",
            None,
            "2024-07-18T12:34:56+00:00",
            True,
            False,
        ),
    ],
)
def test_myair_device_sensor_parametrized(
    device_data,
    sensor_key,
    device_class,
    expected_native,
    expected_available,
    patch_parse_datetime,
    monkeypatch,
    coordinator_factory,
):
    """Combined parametrized test for MyAirDeviceSensor with optional datetime parsing."""
    # Patch dt_util.parse_datetime if needed
    if patch_parse_datetime:
        monkeypatch.setattr(
            "custom_components.resmed_myair.sensor.dt_util.parse_datetime",
            lambda v: "parsed_dt",
        )

    desc = SensorEntityDescription(key=sensor_key, device_class=device_class)
    data = {}
    if device_data is not None:
        data["device"] = device_data
    coordinator = coordinator_factory(data=data)
    sensor = MyAirDeviceSensor("Test", desc, coordinator)
    monkeypatch.setattr(sensor, "async_write_ha_state", MagicMock(return_value=None))
    sensor._handle_coordinator_update()
    assert sensor.available == expected_available
    assert sensor.native_value == expected_native


@pytest.mark.asyncio
async def test_async_setup_entry_adds_entities(
    monkeypatch, coordinator_factory, hass, config_entry
):
    """Test that sensor async_setup_entry adds the expected entities."""
    async_add_entities = MagicMock()
    coordinator = coordinator_factory(mock=True)
    # This test will create its own local MockConfigEntry (below) because
    # MockConfigEntry.data is a mappingproxy and should not be mutated in-place.

    # Patch out SLEEP_RECORD_SENSOR_DESCRIPTIONS and DEVICE_SENSOR_DESCRIPTIONS
    monkeypatch.setattr(
        "custom_components.resmed_myair.sensor.SLEEP_RECORD_SENSOR_DESCRIPTIONS",
        {"foo": MagicMock(key="foo")},
    )
    monkeypatch.setattr(
        "custom_components.resmed_myair.sensor.DEVICE_SENSOR_DESCRIPTIONS",
        {"bar": MagicMock(key="bar")},
    )
    # Patch redact_dict to just return its input
    monkeypatch.setattr("custom_components.resmed_myair.sensor.redact_dict", lambda d: d)

    # Create a local MockConfigEntry to avoid assigning into mappingproxy
    entry = MockConfigEntry(
        domain="resmed_myair",
        title="ResMed-CPAP",
        data={CONF_USER_NAME: "test.user@email.com"},
        version=2,
    )
    entry.runtime_data = coordinator
    entry.hass = hass

    await async_setup_entry(hass, entry, async_add_entities)

    # Check that async_add_entities was called with the correct number of sensors
    # 1 sleep record + 1 device + 5 synthesized = 7
    args, kwargs = async_add_entities.call_args
    sensors = args[0]
    assert len(sensors) == 7
    # Ensure update_before_add is False; default to False when key is absent.
    assert kwargs.get("update_before_add", False) is False

def test_myair_device_sensor_handle_coordinator_update_keyerror(
    caplog, coordinator_factory, monkeypatch
):
    """Ensure MyAirDeviceSensor handles missing keys and logs an error."""
    coordinator = coordinator_factory(mock=True)
    coordinator.data = {"device": {"serialNumber": "SN123"}}
    desc = SensorEntityDescription(key="missing_key")
    sensor = MyAirDeviceSensor("Test Device", desc, coordinator)
    sensor.hass = None
    # If a test runner injects hass, let the caller set sensor.hass; otherwise
    # tests that need hass should add it to the signature. This keeps behavior
    # consistent with other tests that use the shared fixture.
    sensor.entity_id = "sensor.test_device"

    # Patch async_write_ha_state so no Home Assistant internals are called
    monkeypatch.setattr(sensor, "async_write_ha_state", MagicMock(return_value=None))
    with caplog.at_level(logging.ERROR):
        sensor._handle_coordinator_update()

    # Verify
    assert not sensor.available
    assert "Unable to parse Device" in caplog.text
