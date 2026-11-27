"""Sensor-entity tests that protect availability and value translation."""

import logging
from unittest.mock import AsyncMock, MagicMock

from homeassistant.components.sensor import (
    ATTR_STATE_CLASS,
    SensorDeviceClass,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    ATTR_UNIT_OF_MEASUREMENT,
    STATE_UNAVAILABLE,
    STATE_UNKNOWN,
    UnitOfVolumeFlowRate,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
import pytest

from custom_components.resmed_myair.client.rest_client import RESTClient
from custom_components.resmed_myair.const import (
    CONF_PASSWORD,
    CONF_REGION,
    CONF_USER_NAME,
    DOMAIN,
    REGION_NA,
    SLEEP_RECORD_SENSOR_DESCRIPTIONS,
)
from custom_components.resmed_myair.models import (
    MyAirCoordinatorData,
    MyAirDevice,
    MyAirSleepRecord,
)
from custom_components.resmed_myair.sensor import (
    MyAirDeviceSensor,
    MyAirFriendlyUsageTime,
    MyAirMostRecentSleepDate,
    MyAirSleepRecordSensor,
    _coordinator_data,
)
from tests.common import MockConfigEntry
from tests.conftest import CoordinatorFactory, coordinator_data


@pytest.fixture(autouse=True)
def configure_hass(enable_custom_integrations: None) -> None:
    """Use Home Assistant's real config-entry manager for sensor setup tests.

    Args:
        enable_custom_integrations (None): Enable loading the integration under test.
    """


async def test_nightly_indexes_are_opt_in_and_follow_the_latest_sleep_record(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Opt-in indexes report independent readings alongside the existing AHI sensor.

    Args:
        hass (HomeAssistant): Home Assistant instance loading the integration.
        monkeypatch (pytest.MonkeyPatch): Replace only myAir network operations.
    """
    record_fields = {"totalUsage": 120, "sleepScore": 95, "maskPairCount": 2, "leakPercentile": 4}
    older_record = MyAirSleepRecord.from_api(
        {**record_fields, "startDate": "2024-06-01", "apneaIndex": 8, "hypopneaIndex": 9, "ahi": 17}
    )
    current_record = {**record_fields, "startDate": "2024-06-02", "ahi": 1.8}
    record_requests = AsyncMock(
        return_value=[
            MyAirSleepRecord.from_api({**current_record, "apneaIndex": 0.25, "hypopneaIndex": 0.5}),
            older_record,
        ]
    )
    monkeypatch.setattr(RESTClient, "connect", AsyncMock(return_value="token"))
    monkeypatch.setattr(RESTClient, "get_sleep_records", record_requests)
    monkeypatch.setattr(
        RESTClient,
        "get_user_device_data",
        AsyncMock(
            return_value=MyAirDevice.from_api(
                {"serialNumber": "SN123", "lastSleepDataReportTime": "2024-06-02T12:00:00+00:00"}
            )
        ),
    )
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            CONF_USER_NAME: "test@example.com",
            CONF_PASSWORD: "password",
            CONF_REGION: REGION_NA,
        },
        version=2,
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    registry = er.async_get(hass)
    ahi_id = registry.async_get_entity_id("sensor", DOMAIN, "resmed_myair_SN123_ahi")
    assert ahi_id is not None
    ahi_entry = registry.async_get(ahi_id)
    assert ahi_entry is not None and ahi_entry.device_id is not None
    ahi = hass.states.get(ahi_id)
    assert ahi is not None and ahi.state == "1.8"
    assert ATTR_UNIT_OF_MEASUREMENT not in ahi.attributes

    index_ids = []
    for field, name in (
        ("apneaIndex", "CPAP Apnea Index"),
        ("hypopneaIndex", "CPAP Hypopnea Index"),
    ):
        entity_id = registry.async_get_entity_id("sensor", DOMAIN, f"resmed_myair_SN123_{field}")
        assert entity_id is not None
        entity = registry.async_get(entity_id)
        assert entity is not None
        assert entity.original_name == name
        assert entity.device_id == ahi_entry.device_id
        assert entity.disabled_by is er.RegistryEntryDisabler.INTEGRATION
        assert hass.states.get(entity_id) is None
        registry.async_update_entity(entity_id, disabled_by=None)
        index_ids.append(entity_id)

    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()
    for entity_id, expected in zip(index_ids, ("0.25", "0.5"), strict=True):
        state = hass.states.get(entity_id)
        assert state is not None and state.state == expected
        assert state.attributes[ATTR_UNIT_OF_MEASUREMENT] == "events/h"
        assert state.attributes[ATTR_STATE_CLASS] == SensorStateClass.MEASUREMENT

    for records, expected_states in (
        (
            [
                MyAirSleepRecord.from_api(
                    {**current_record, "totalUsage": 0, "apneaIndex": 0, "hypopneaIndex": None}
                ),
                older_record,
            ],
            ("0", STATE_UNKNOWN, "1.8"),
        ),
        (
            [MyAirSleepRecord.from_api({**current_record, "hypopneaIndex": 0.75}), older_record],
            (STATE_UNAVAILABLE, "0.75", "1.8"),
        ),
        (
            [
                MyAirSleepRecord.from_api(
                    {**current_record, "apneaIndex": 0.125, "hypopneaIndex": True}
                )
            ],
            ("0.125", STATE_UNKNOWN, "1.8"),
        ),
        ([], (STATE_UNAVAILABLE,) * 3),
    ):
        record_requests.return_value = records
        await hass.services.async_call(DOMAIN, "force_poll_test_example_com", blocking=True)
        for entity_id, expected in zip([*index_ids, ahi_id], expected_states, strict=True):
            state = hass.states.get(entity_id)
            assert state is not None and state.state == expected


def test_mask_leak_sensor_uses_liters_per_minute_without_changing_raw_key(
    coordinator_factory: CoordinatorFactory,
) -> None:
    """Mask leak keeps its legacy raw key while exposing the correct flow unit.

    Args:
        coordinator_factory (CoordinatorFactory): Factory creating a device-backed coordinator.
    """
    description = SLEEP_RECORD_SENSOR_DESCRIPTIONS["CPAP Mask Leak"]
    coordinator = coordinator_factory(data=coordinator_data(device={"serialNumber": "SN123"}))

    sensor = MyAirSleepRecordSensor("CPAP Mask Leak", description, coordinator)

    assert description.key == "leakPercentile"
    assert description.native_unit_of_measurement == UnitOfVolumeFlowRate.LITERS_PER_MINUTE
    assert sensor.unique_id == "resmed_myair_SN123_leakPercentile"


@pytest.mark.parametrize("raw_data", [None, {"unexpected": "payload"}])
def test_coordinator_data_uses_empty_payload_for_untyped_data(raw_data: object) -> None:
    """Untyped startup coordinator payloads collapse to empty typed data.

    Args:
        raw_data (object): Untyped coordinator value supplied during startup.
    """
    coordinator = MagicMock()
    coordinator.data = raw_data

    data = _coordinator_data(coordinator)

    assert data == MyAirCoordinatorData()


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
    """Friendly usage sensors format minutes and handle missing records.

    Args:
        data (dict[str, object]): Coordinator payload for the parameterized case.
        expected_native (object): Native value expected when the sensor is available.
        expected_available (bool): Whether the sensor should report available data.
        monkeypatch (pytest.MonkeyPatch): Pytest patch fixture for state writes.
        coordinator_factory (CoordinatorFactory): Factory creating the test coordinator.
    """
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
    """Most-recent sleep date sensors select the latest usable record.

    Args:
        data (dict[str, object]): Coordinator payload for the parameterized case.
        expected_native (object): Date string expected when a usable record exists.
        expected_available (bool): Whether the sensor should report available data.
        monkeypatch (pytest.MonkeyPatch): Pytest patch fixture for state writes.
        coordinator_factory (CoordinatorFactory): Factory creating the test coordinator.
    """
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
        ([{"leakPercentile": 12.5}], "leakPercentile", None, 12.5, True),
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
    """Sleep-record sensors parse raw values and optional dates correctly.

    Args:
        sleep_records (list[dict[str, object]] | None): Records supplied to the coordinator.
        sensor_key (str): Raw record key selected by the sensor description.
        device_class (SensorDeviceClass | None): Optional class controlling date parsing.
        expected_value (object): Native value expected after parsing the raw record.
        expected_available (bool): Whether the sensor should report available data.
        monkeypatch (pytest.MonkeyPatch): Pytest patch fixture for date parsing and state writes.
        coordinator_factory (CoordinatorFactory): Factory creating the test coordinator.
    """
    # Patch dt_util.parse_date to return a sentinel for test
    if device_class == SensorDeviceClass.DATE:
        parsed_date = object()
        monkeypatch.setattr(
            "custom_components.resmed_myair.sensor.dt_util.parse_date",
            lambda v: parsed_date,
        )
        expected_value = parsed_date

    if sensor_key == "leakPercentile":
        desc = SLEEP_RECORD_SENSOR_DESCRIPTIONS["CPAP Mask Leak"]
        assert desc.key == sensor_key
        assert desc.native_unit_of_measurement == UnitOfVolumeFlowRate.LITERS_PER_MINUTE
    else:
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
    """Raw device and sleep-record keys with null values still count as available data.

    Args:
        sensor_class (type[MyAirSleepRecordSensor | MyAirDeviceSensor]): Sensor class under test.
        coordinator_payload (dict[str, object]): Payload containing a null raw value.
        monkeypatch (pytest.MonkeyPatch): Pytest patch fixture for state writes.
        coordinator_factory (CoordinatorFactory): Factory creating the test coordinator.
    """
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
    """Device sensors parse datetimes only when the entity class requires it.

    Args:
        device_data (dict[str, object] | None): Device payload for the parameterized case.
        sensor_key (str): Raw device key selected by the sensor description.
        device_class (SensorDeviceClass | None): Optional class controlling timestamp parsing.
        expected_native (object): Native value expected after parsing the device payload.
        expected_available (bool): Whether the sensor should report available data.
        patch_parse_datetime (bool): Whether to replace the datetime parser with a sentinel.
        monkeypatch (pytest.MonkeyPatch): Pytest patch fixture for parsing and state writes.
        coordinator_factory (CoordinatorFactory): Factory creating the test coordinator.
    """
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


def test_myair_device_sensor_handle_coordinator_update_keyerror(
    caplog: pytest.LogCaptureFixture,
    coordinator_factory: CoordinatorFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing device keys leave the sensor unavailable and log the failure.

    Args:
        caplog (pytest.LogCaptureFixture): Captured log fixture used to verify the error message.
        coordinator_factory (CoordinatorFactory): Factory creating the device-backed coordinator.
        monkeypatch (pytest.MonkeyPatch): Pytest patch fixture for state writes.
    """
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
