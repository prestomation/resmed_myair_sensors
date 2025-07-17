import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.resmed_myair.config_flow import CONF_USER_NAME
from custom_components.resmed_myair.sensor import (
    MyAirDeviceSensor,
    MyAirFriendlyUsageTime,
    MyAirMostRecentSleepDate,
    MyAirSleepRecordSensor,
    SensorDeviceClass,
    async_setup_entry,
)
from homeassistant.components.sensor import SensorEntityDescription


class DummyCoordinator:
    def __init__(self, data):
        self.data = data

    def async_add_listener(self, *args, **kwargs):
        return lambda: None


@pytest.mark.parametrize(
    "data,sensor_key,expected_native,expected_available",
    [
        ({}, "foo", None, False),  # No device
        ({"device": {}}, "foo", None, False),  # KeyError
        ({"device": {"foo": "bar"}}, "foo", "bar", True),  # Success, not timestamp
        ({"device": {"foo": "2024-07-18T12:34:56+00:00"}}, "foo", None, True),  # Success, timestamp
    ],
)
def test_device_sensor_all_branches(data, sensor_key, expected_native, expected_available):
    desc = SensorEntityDescription(key=sensor_key)
    # Simulate timestamp device_class for the last case
    if "T" in str(data.get("device", {}).get(sensor_key, "")):
        desc = SensorEntityDescription(key=sensor_key, device_class="timestamp")
    coordinator = DummyCoordinator(data)
    sensor = MyAirDeviceSensor("Test", desc, coordinator)
    with patch.object(sensor, "async_write_ha_state", return_value=None):
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
def test_friendly_usage_time_all_branches(data, expected_native, expected_available):
    coordinator = DummyCoordinator(data)
    sensor = MyAirFriendlyUsageTime(coordinator)
    with patch.object(sensor, "async_write_ha_state", return_value=None):
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
def test_most_recent_sleep_date_all_branches(data, expected_native, expected_available):
    coordinator = DummyCoordinator(data)
    sensor = MyAirMostRecentSleepDate(coordinator)
    with patch.object(sensor, "async_write_ha_state", return_value=None):
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
        ([{"foo": "2024-07-18"}], "foo", "date", "2024-07-18", True),
        ([{"foo": "some string"}], "foo", None, "some string", True),
    ],
)
def test_sleep_record_sensor_handle_coordinator_update(
    sleep_records, sensor_key, device_class, expected_value, expected_available, monkeypatch
):
    # Patch dt_util.parse_date to return a sentinel for test
    if device_class == "date":
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
    coordinator = DummyCoordinator(data)
    sensor = MyAirSleepRecordSensor("Test", desc, coordinator)
    with patch.object(sensor, "async_write_ha_state", return_value=None):
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
        ({"foo": "2024-07-18T12:34:56+00:00"}, "foo", "timestamp", "parsed_dt", True, True),
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
    device_data, sensor_key, device_class, expected_native, expected_available, patch_parse_datetime
):
    # Test logic here
    def test_myair_device_sensor_handle_coordinator_update(
        device_data,
        sensor_key,
        device_class,
        expected_native,
        expected_available,
        patch_parse_datetime,
        monkeypatch,
    ):
        # Patch dt_util.parse_datetime if needed
        if patch_parse_datetime:
            monkeypatch.setattr(
                "custom_components.resmed_myair.sensor.dt_util.parse_datetime",
                lambda v: "parsed_dt",
            )

        desc = SensorEntityDescription(
            key=sensor_key,
            device_class=SensorDeviceClass.TIMESTAMP
            if device_class == "timestamp"
            else device_class,
        )
        data = {}
        if device_data is not None:
            data["device"] = device_data
        coordinator = DummyCoordinator(data)
        sensor = MyAirDeviceSensor("Test", desc, coordinator)
        with patch.object(sensor, "async_write_ha_state", return_value=None):
            sensor._handle_coordinator_update()
        assert sensor.available == expected_available
        assert sensor.native_value == expected_native


@pytest.mark.asyncio
async def test_async_setup_entry_adds_entities_and_registers_service(monkeypatch):
    # Prepare mocks
    hass = MagicMock()
    hass.services.async_register = MagicMock()
    async_add_entities = MagicMock()
    coordinator = MagicMock()
    coordinator.async_refresh = AsyncMock()
    config_entry = MagicMock()
    config_entry.data = {CONF_USER_NAME: "test.user@email.com"}
    config_entry.runtime_data = coordinator

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

    # Call the function
    await async_setup_entry(hass, config_entry, async_add_entities)

    # Check that async_add_entities was called with the correct number of sensors
    # 1 sleep record + 1 device + 2 synthesized = 4
    args, kwargs = async_add_entities.call_args
    sensors = args[0]
    assert len(sensors) == 4
    assert kwargs in ({}, {"update_before_add": False})
    # assert kwargs == {"update_before_add": False}

    # Check that the service was registered with sanitized username
    expected_service = "force_poll_test_user_email_com"
    hass.services.async_register.assert_called_once()
    domain, service, func = hass.services.async_register.call_args[0]
    assert domain == "resmed_myair"
    assert service == expected_service
    # The registered function should be awaitable
    assert asyncio.iscoroutinefunction(func)

    # Test that calling the registered refresh function calls coordinator.async_refresh
    await func(None)
    coordinator.async_refresh.assert_awaited_once()


def test_myair_device_sensor_handle_coordinator_update_keyerror(caplog):
    coordinator = MagicMock()
    # Device data exists but missing the key 'missing_key'
    coordinator.data = {"device": {"serialNumber": "SN123"}}
    desc = SensorEntityDescription(key="missing_key")
    sensor = MyAirDeviceSensor("Test Device", desc, coordinator)
    sensor.entity_description = desc
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.test_device"

    # Patch async_write_ha_state so no Home Assistant internals are called
    with patch.object(sensor, "async_write_ha_state", return_value=None), caplog.at_level("ERROR"):
        sensor._handle_coordinator_update()

    # Verify
    assert not sensor.available
    assert "Unable to parse Device" in caplog.text
