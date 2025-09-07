"""Unit tests for sensor entities in the resmed_myair integration."""

import asyncio
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
    async_setup_entry,
)
from homeassistant.components.sensor import SensorDeviceClass, SensorEntityDescription


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
async def test_async_setup_entry_adds_entities_and_registers_service(
    monkeypatch, coordinator_factory, hass, config_entry, service_registry_shim
):
    """Test that async_setup_entry adds sensor entities and registers service."""
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
    # 1 sleep record + 1 device + 2 synthesized = 4
    args, kwargs = async_add_entities.call_args
    sensors = args[0]
    assert len(sensors) == 4
    # Ensure update_before_add is False; default to False when key is absent.
    assert kwargs.get("update_before_add", False) is False

    # Check that the service was registered with sanitized username
    expected_service = "force_poll_test_user_email_com"
    # Assert the service was registered using the shim API
    assert service_registry_shim.has_service("resmed_myair", expected_service)

    # Retrieve the registered service entry and its first handler
    service_entry = service_registry_shim._services["resmed_myair"][expected_service]
    func = service_entry.handlers[0]
    # The registered function should be awaitable
    assert asyncio.iscoroutinefunction(func)

    # Test that calling the registered refresh function calls coordinator.async_refresh
    await func(None)
    coordinator.async_refresh.assert_awaited_once()


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
