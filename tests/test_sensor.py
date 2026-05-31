"""Sensor-entity tests that protect availability and value translation."""

import inspect
import logging
from unittest.mock import MagicMock

from homeassistant.components.sensor import SensorDeviceClass, SensorEntityDescription
from homeassistant.const import UnitOfVolumeFlowRate
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.resmed_myair.const import CONF_USER_NAME, SLEEP_RECORD_SENSOR_DESCRIPTIONS
from custom_components.resmed_myair.sensor import (
    MyAirDeviceSensor,
    MyAirFriendlyUsageTime,
    MyAirMostRecentSleepDate,
    MyAirSleepRecordSensor,
    async_setup_entry,
)
from tests.conftest import CoordinatorFactory, ServiceRegistryShimLike, coordinator_data


def test_mask_leak_sensor_uses_liters_per_minute_without_changing_raw_key(
    coordinator_factory: CoordinatorFactory,
) -> None:
    """Mask leak keeps its legacy raw key while exposing the correct flow unit."""
    description = SLEEP_RECORD_SENSOR_DESCRIPTIONS["CPAP Mask Leak"]
    coordinator = coordinator_factory(data=coordinator_data(device={"serialNumber": "SN123"}))

    sensor = MyAirSleepRecordSensor("CPAP Mask Leak", description, coordinator)

    assert description.key == "leakPercentile"
    assert description.native_unit_of_measurement == UnitOfVolumeFlowRate.LITERS_PER_MINUTE
    assert sensor.unique_id == "resmed_myair_SN123_leakPercentile"


@pytest.mark.parametrize(
    ("data", "expected_native", "expected_available"),
    [
        ({}, None, False),  # No sleep_records
        ({"sleep_records": []}, None, False),  # Empty sleep_records
        ({"sleep_records": [{}]}, None, False),  # KeyError
        ({"sleep_records": [{"totalUsage": 10}]}, "0:10", True),  # Success
        ({"sleep_records": [{"totalUsage": -10}]}, "0:00", True),  # Negative usage, clamped
    ],
)
def test_friendly_usage_time_all_branches(
    data: dict[str, object],
    expected_native: object,
    expected_available: bool,
    monkeypatch: pytest.MonkeyPatch,
    coordinator_factory: CoordinatorFactory,
) -> None:
    """Friendly usage sensors format minutes and handle missing records."""
    coordinator = coordinator_factory(data=data)
    sensor = MyAirFriendlyUsageTime(coordinator)
    monkeypatch.setattr(sensor, "async_write_ha_state", MagicMock(return_value=None))
    sensor._handle_coordinator_update()
    assert sensor.available == expected_available
    # Only check native_value if available
    if expected_available:
        assert sensor.native_value == expected_native


@pytest.mark.parametrize(
    ("data", "expected_native", "expected_available"),
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
    data: dict[str, object],
    expected_native: object,
    expected_available: bool,
    monkeypatch: pytest.MonkeyPatch,
    coordinator_factory: CoordinatorFactory,
) -> None:
    """Most-recent sleep date sensors select the latest usable record."""
    coordinator = coordinator_factory(data=data)
    sensor = MyAirMostRecentSleepDate(coordinator)
    monkeypatch.setattr(sensor, "async_write_ha_state", MagicMock(return_value=None))
    sensor._handle_coordinator_update()
    assert sensor.available == expected_available
    if expected_available:
        # sensor.native_value is a date object
        assert str(sensor.native_value) == expected_native


@pytest.mark.parametrize(
    ("sleep_records", "sensor_key", "device_class", "expected_value", "expected_available"),
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
    sleep_records: list[dict[str, object]] | None,
    sensor_key: str,
    device_class: SensorDeviceClass | None,
    expected_value: object,
    expected_available: bool,
    monkeypatch: pytest.MonkeyPatch,
    coordinator_factory: CoordinatorFactory,
) -> None:
    """Sleep-record sensors parse raw values and optional dates correctly."""
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
    ("sensor_class", "coordinator_payload"),
    [
        (MyAirSleepRecordSensor, {"sleep_records": [{"foo": None}]}),
        (MyAirDeviceSensor, {"device": {"foo": None}}),
    ],
)
def test_sensor_is_available_when_raw_key_value_is_none(
    sensor_class: type[MyAirSleepRecordSensor | MyAirDeviceSensor],
    coordinator_payload: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    coordinator_factory: CoordinatorFactory,
) -> None:
    """Raw device and sleep-record keys with null values still count as available data."""
    coordinator = coordinator_factory(data=coordinator_payload)
    sensor = sensor_class("Test", SensorEntityDescription(key="foo"), coordinator)
    monkeypatch.setattr(sensor, "async_write_ha_state", MagicMock(return_value=None))

    sensor._handle_coordinator_update()

    assert sensor.available is True
    assert sensor.native_value is None


@pytest.mark.parametrize(
    (
        "device_data",
        "sensor_key",
        "device_class",
        "expected_native",
        "expected_available",
        "patch_parse_datetime",
    ),
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
    device_data: dict[str, object] | None,
    sensor_key: str,
    device_class: SensorDeviceClass | None,
    expected_native: object,
    expected_available: bool,
    patch_parse_datetime: bool,
    monkeypatch: pytest.MonkeyPatch,
    coordinator_factory: CoordinatorFactory,
) -> None:
    """Device sensors parse datetimes only when the entity class requires it."""
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
    monkeypatch: pytest.MonkeyPatch,
    coordinator_factory: CoordinatorFactory,
    hass: MagicMock,
    config_entry: MockConfigEntry,
    service_registry_shim: ServiceRegistryShimLike,
) -> None:
    """Setup adds sensor entities and registers the force-poll service."""
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
    assert inspect.iscoroutinefunction(func)

    # Test that calling the registered refresh function calls coordinator.async_refresh
    await func(None)
    coordinator.async_refresh.assert_awaited_once()


def test_myair_device_sensor_handle_coordinator_update_keyerror(
    caplog: pytest.LogCaptureFixture,
    coordinator_factory: CoordinatorFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing device keys leave the sensor unavailable and log the failure."""
    coordinator = coordinator_factory(mock=True)
    coordinator.data = coordinator_data(device={"serialNumber": "SN123"})
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
