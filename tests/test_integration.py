"""Integration-level tests for setup, unload, migration, and sensor wiring."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

import custom_components.resmed_myair as resmed_module
from custom_components.resmed_myair import (
    async_setup_entry,
    async_unload_entry,
    sensor as sensor_platform,
)
from custom_components.resmed_myair.const import (
    DEVICE_SENSOR_DESCRIPTIONS,
    PLATFORMS,
    SLEEP_RECORD_SENSOR_DESCRIPTIONS,
)
from custom_components.resmed_myair.sensor import (
    MyAirDeviceSensor,
    MyAirFriendlyUsageTime,
    MyAirMostRecentSleepDate,
    MyAirSleepRecordSensor,
)
from tests.common import MockConfigEntry, entity_device_info
from tests.conftest import CoordinatorFactory, CoordinatorLike, coordinator_data


def _coordinator_payload(
    coordinator: CoordinatorLike,
) -> tuple[dict[str, object] | None, list[dict[str, object]]]:
    """Create mutable payload copies from typed coordinator data.

    Args:
        coordinator (CoordinatorLike): Coordinator whose current payload is copied.

    Returns:
        tuple[dict[str, object] | None, list[dict[str, object]]]: Independent device and sleep-record payloads.
    """
    device = dict(coordinator.data.device.raw) if coordinator.data.device else None
    sleep_records = [dict(record.raw) for record in coordinator.data.sleep_records]
    return device, sleep_records


@pytest.mark.asyncio
async def test_async_setup_entry_refresh_failure(
    hass: MagicMock,
    config_entry: MockConfigEntry,
    session: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Setup propagates refresh failures before forwarding platforms.

    Args:
        hass (MagicMock): Home Assistant instance receiving the setup call.
        config_entry (MockConfigEntry): Integration entry being initialized.
        session (MagicMock): HTTP session returned by the patched session factory.
        monkeypatch (pytest.MonkeyPatch): Pytest patch fixture for setup dependencies.
    """
    # Replace async_create_clientsession to return the provided session
    monkeypatch.setattr(
        resmed_module, "async_create_clientsession", lambda *args, **kwargs: session
    )

    # Mock the coordinator class and capture the MagicMock for assertions
    mock_coordinator = MagicMock()
    monkeypatch.setattr(resmed_module, "MyAirDataUpdateCoordinator", mock_coordinator)
    instance = mock_coordinator.return_value
    instance.async_config_entry_first_refresh = AsyncMock(side_effect=RuntimeError("refresh fail"))

    # Replace hass.config_entries.async_forward_entry_setups with an AsyncMock and keep a ref
    monkeypatch.setattr(hass.config_entries, "async_forward_entry_setups", AsyncMock())
    fwd = hass.config_entries.async_forward_entry_setups

    with pytest.raises(RuntimeError) as exc:
        await async_setup_entry(hass, config_entry)
    assert "refresh fail" in str(exc.value)
    fwd.assert_not_awaited()


@pytest.mark.asyncio
async def test_async_setup_entry_multiple_calls(
    hass: MagicMock,
    config_entry: MockConfigEntry,
    session: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Setup supports repeated calls by forwarding and refreshing each time.

    Args:
        hass (MagicMock): Home Assistant instance receiving both setup calls.
        config_entry (MockConfigEntry): Integration entry initialized repeatedly.
        session (MagicMock): HTTP session returned by the patched session factory.
        monkeypatch (pytest.MonkeyPatch): Pytest patch fixture for setup dependencies.
    """
    monkeypatch.setattr(
        resmed_module, "async_create_clientsession", lambda *args, **kwargs: session
    )

    mock_coordinator = MagicMock()
    monkeypatch.setattr(resmed_module, "MyAirDataUpdateCoordinator", mock_coordinator)
    instance = mock_coordinator.return_value
    instance.async_config_entry_first_refresh = AsyncMock()

    monkeypatch.setattr(resmed_module, "async_migrate_mask_leak_statistics_metadata", MagicMock())
    monkeypatch.setattr(hass.config_entries, "async_forward_entry_setups", AsyncMock())
    fwd = hass.config_entries.async_forward_entry_setups

    result1 = await async_setup_entry(hass, config_entry)
    result2 = await async_setup_entry(hass, config_entry)
    assert result1 is True
    assert result2 is True
    assert fwd.await_count == 2
    fwd.assert_awaited_with(config_entry, PLATFORMS)
    assert instance.async_config_entry_first_refresh.await_count == 2


@pytest.mark.asyncio
async def test_async_setup_entry_migrates_mask_leak_statistics_metadata(
    hass: MagicMock,
    config_entry: MockConfigEntry,
    session: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Setup schedules the mask leak statistics metadata migration before platforms load.

    Args:
        hass (MagicMock): Home Assistant instance receiving the setup call.
        config_entry (MockConfigEntry): Integration entry being initialized.
        session (MagicMock): HTTP session returned by the patched session factory.
        monkeypatch (pytest.MonkeyPatch): Pytest patch fixture for setup dependencies.
    """
    monkeypatch.setattr(
        resmed_module, "async_create_clientsession", lambda *args, **kwargs: session
    )

    mock_coordinator = MagicMock()
    monkeypatch.setattr(resmed_module, "MyAirDataUpdateCoordinator", mock_coordinator)
    mock_coordinator.return_value.async_config_entry_first_refresh = AsyncMock()
    migrate_statistics = MagicMock()
    monkeypatch.setattr(
        resmed_module,
        "async_migrate_mask_leak_statistics_metadata",
        migrate_statistics,
    )

    monkeypatch.setattr(hass.config_entries, "async_forward_entry_setups", AsyncMock())

    result = await async_setup_entry(hass, config_entry)

    assert result is True
    migrate_statistics.assert_called_once_with(hass)
    hass.config_entries.async_forward_entry_setups.assert_awaited_once_with(config_entry, PLATFORMS)


@pytest.mark.asyncio
async def test_most_recent_sleep_date_sensor_with_future_date(
    hass: MagicMock, coordinator_factory: CoordinatorFactory
) -> None:
    """Most-recent sleep date sensors preserve future-dated records.

    Args:
        hass (MagicMock): Home Assistant instance attached to the sensor.
        coordinator_factory (CoordinatorFactory): Factory creating the test coordinator payload.
    """
    future = (datetime.now(UTC).date() + timedelta(days=10)).isoformat()

    coordinator = coordinator_factory(
        data={"sleep_records": [{"startDate": future, "totalUsage": 10}]}
    )
    sensor = MyAirMostRecentSleepDate(coordinator)
    sensor.hass = hass
    sensor.entity_id = "sensor.test_recent_sleep"
    sensor.async_write_ha_state = MagicMock()
    await sensor.async_added_to_hass()
    assert sensor.native_value.isoformat() == future
    assert sensor.available is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("unload_return", "initial_runtime_data", "expected_result", "expected_runtime_data"),
    [
        (True, "dummy", True, "dummy"),  # Success, runtime_data is NOT removed by integration
        (False, "dummy", False, "dummy"),  # Failure, runtime_data not removed
        (True, None, True, None),  # Success, runtime_data already None
    ],
)
async def test_async_unload_entry_variants(
    hass: MagicMock,
    config_entry: MockConfigEntry,
    unload_return: bool,
    initial_runtime_data: object,
    expected_result: object,
    expected_runtime_data: object,
) -> None:
    """Unload returns the platform result without clearing runtime data.

    Args:
        hass (MagicMock): Home Assistant instance receiving the unload calls.
        config_entry (MockConfigEntry): Integration entry whose platforms are unloaded.
        unload_return (bool): Result returned by the patched platform unload operation.
        initial_runtime_data (object): Runtime data present before unloading.
        expected_result (object): Expected result from each unload call.
        expected_runtime_data (object): Runtime data expected after unloading.
    """
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=unload_return)
    config_entry.runtime_data = initial_runtime_data
    result1 = await async_unload_entry(hass, config_entry)
    # Call a second time to check idempotency
    result2 = await async_unload_entry(hass, config_entry)
    assert result1 is expected_result
    assert result2 is expected_result
    assert config_entry.runtime_data == expected_runtime_data
    hass.config_entries.async_unload_platforms.assert_awaited_with(config_entry, PLATFORMS)
    assert hass.config_entries.async_unload_platforms.await_count == 2


@pytest.mark.asyncio
async def test_sleep_record_sensor_multiple_updates(
    hass: MagicMock, coordinator: CoordinatorLike
) -> None:
    """Sleep-record sensors follow successive coordinator payload updates.

    Args:
        hass (MagicMock): Home Assistant instance attached to the sensor.
        coordinator (CoordinatorLike): Coordinator whose sleep record is updated.
    """
    key = "CPAP Usage Minutes"
    desc = SLEEP_RECORD_SENSOR_DESCRIPTIONS[key]
    sensor = MyAirSleepRecordSensor(key, desc, coordinator)
    sensor.hass = hass
    sensor.entity_id = "sensor.test_sleep_record"
    sensor.async_write_ha_state = MagicMock()
    await sensor.async_added_to_hass()
    assert sensor.native_value == 456
    assert sensor.available is True
    # Update to a new value
    device_snapshot, sleep_records = _coordinator_payload(coordinator)
    sleep_records[-1]["totalUsage"] = 321
    coordinator.data = coordinator_data(device=device_snapshot, sleep_records=sleep_records)
    sensor._handle_coordinator_update()
    assert sensor.native_value == 321
    assert sensor.available is True
    # Update to another value
    device_snapshot, sleep_records = _coordinator_payload(coordinator)
    sleep_records[-1]["totalUsage"] = 654
    coordinator.data = coordinator_data(device=device_snapshot, sleep_records=sleep_records)
    sensor._handle_coordinator_update()
    assert sensor.native_value == 654
    assert sensor.available is True


@pytest.mark.asyncio
async def test_device_sensor_multiple_updates(
    hass: MagicMock, coordinator: CoordinatorLike
) -> None:
    """Device sensors follow successive coordinator payload updates.

    Args:
        hass (MagicMock): Home Assistant instance attached to the sensor.
        coordinator (CoordinatorLike): Coordinator whose device payload is updated.
    """
    key = "CPAP Sleep Data Last Collected"
    desc = DEVICE_SENSOR_DESCRIPTIONS[key]
    sensor = MyAirDeviceSensor(key, desc, coordinator)
    sensor.hass = hass
    sensor.entity_id = "sensor.test_device"
    sensor.async_write_ha_state = MagicMock()
    await sensor.async_added_to_hass()
    assert sensor.native_value.isoformat().startswith("2024-06-01T12:00:00")
    assert sensor.available is True
    # Update to a new datetime
    device_snapshot, sleep_records = _coordinator_payload(coordinator)
    assert device_snapshot is not None
    device_snapshot["lastSleepDataReportTime"] = "2024-06-03T09:00:00+00:00"
    coordinator.data = coordinator_data(device=device_snapshot, sleep_records=sleep_records)
    sensor._handle_coordinator_update()
    assert sensor.native_value.isoformat().startswith("2024-06-03T09:00:00")
    assert sensor.available is True
    # Update to another datetime
    device_snapshot, sleep_records = _coordinator_payload(coordinator)
    assert device_snapshot is not None
    device_snapshot["lastSleepDataReportTime"] = "2024-06-04T10:30:00+00:00"
    coordinator.data = coordinator_data(device=device_snapshot, sleep_records=sleep_records)
    sensor._handle_coordinator_update()
    assert sensor.native_value.isoformat().startswith("2024-06-04T10:30:00")
    assert sensor.available is True


@pytest.mark.asyncio
async def test_friendly_usage_time_sensor_multiple_updates(
    hass: MagicMock, coordinator: CoordinatorLike
) -> None:
    """Friendly usage sensors reformat minutes after each data change.

    Args:
        hass (MagicMock): Home Assistant instance attached to the sensor.
        coordinator (CoordinatorLike): Coordinator whose usage minutes are updated.
    """
    sensor = MyAirFriendlyUsageTime(coordinator)
    sensor.hass = hass
    sensor.entity_id = "sensor.test_friendly_usage"
    sensor.async_write_ha_state = MagicMock()
    await sensor.async_added_to_hass()
    assert sensor.native_value == "7:36"
    assert sensor.available is True
    # Update usage to 120 minutes
    device_snapshot, sleep_records = _coordinator_payload(coordinator)
    sleep_records[-1]["totalUsage"] = 120
    coordinator.data = coordinator_data(device=device_snapshot, sleep_records=sleep_records)
    sensor._handle_coordinator_update()
    assert sensor.native_value == "2:00"
    assert sensor.available is True
    # Update usage to 0 (remains available; formatted as "0:00")
    device_snapshot, sleep_records = _coordinator_payload(coordinator)
    sleep_records[-1]["totalUsage"] = 0
    coordinator.data = coordinator_data(device=device_snapshot, sleep_records=sleep_records)
    sensor._handle_coordinator_update()
    assert sensor.native_value == "0:00"
    assert sensor.available is True


@pytest.mark.asyncio
async def test_most_recent_sleep_date_sensor_multiple_updates(
    hass: MagicMock, coordinator: CoordinatorLike
) -> None:
    """Most-recent sleep date sensors advance as new usable records appear.

    Args:
        hass (MagicMock): Home Assistant instance attached to the sensor.
        coordinator (CoordinatorLike): Coordinator receiving additional sleep records.
    """
    sensor = MyAirMostRecentSleepDate(coordinator)
    sensor.hass = hass
    sensor.entity_id = "sensor.test_recent_sleep"
    sensor.async_write_ha_state = MagicMock()
    await sensor.async_added_to_hass()
    assert sensor.native_value.isoformat() == "2024-06-01"
    assert sensor.available is True
    # Add a new record with usage
    device_snapshot, sleep_records = _coordinator_payload(coordinator)
    sleep_records.append(
        {
            "startDate": "2024-06-05",
            "totalUsage": 200,
            "sleepScore": 88,
            "ahi": 1.5,
            "maskPairCount": 2,
            "leakPercentile": 3,
        }
    )
    coordinator.data = coordinator_data(device=device_snapshot, sleep_records=sleep_records)
    sensor._handle_coordinator_update()
    assert sensor.native_value.isoformat() == "2024-06-05"
    # Add a record with no usage (should not change)
    device_snapshot, sleep_records = _coordinator_payload(coordinator)
    sleep_records.append(
        {
            "startDate": "2024-06-06",
            "totalUsage": 0,
            "sleepScore": 70,
            "ahi": 3.0,
            "maskPairCount": 1,
            "leakPercentile": 7,
        }
    )
    coordinator.data = coordinator_data(device=device_snapshot, sleep_records=sleep_records)
    sensor._handle_coordinator_update()
    assert sensor.native_value.isoformat() == "2024-06-05"
    assert sensor.available is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("sensor_class", "key", "desc", "data_field", "empty_value"),
    [
        (
            MyAirSleepRecordSensor,
            "CPAP Usage Minutes",
            SLEEP_RECORD_SENSOR_DESCRIPTIONS["CPAP Usage Minutes"],
            "sleep_records",
            [],
        ),
        (
            MyAirDeviceSensor,
            "CPAP Sleep Data Last Collected",
            DEVICE_SENSOR_DESCRIPTIONS["CPAP Sleep Data Last Collected"],
            "device",
            {},
        ),
    ],
)
async def test_sensor_becomes_unavailable_on_missing_data(
    hass: MagicMock,
    coordinator: CoordinatorLike,
    sensor_class: type[object],
    key: str | None,
    desc: object,
    data_field: str,
    empty_value: object,
) -> None:
    """Entities go unavailable when the backing payload disappears.

    Args:
        hass (MagicMock): Home Assistant instance attached to the sensor.
        coordinator (CoordinatorLike): Coordinator whose payload is emptied.
        sensor_class (type[object]): Sensor class under test.
        key (str | None): Entity key passed to raw sensors, when applicable.
        desc (object): Sensor description passed to raw sensors.
        data_field (str): Coordinator field to clear during the test.
        empty_value (object): Empty replacement value for the selected field.
    """
    sensor = sensor_class(key, desc, coordinator)
    sensor.hass = hass
    sensor.entity_id = f"sensor.test_{key.replace(' ', '_').lower()}"
    sensor.async_write_ha_state = MagicMock()
    await sensor.async_added_to_hass()
    assert sensor.available
    device_snapshot, sleep_records = _coordinator_payload(coordinator)
    if data_field == "sleep_records":
        coordinator.data = coordinator_data(
            device=device_snapshot,
            sleep_records=list(empty_value) if isinstance(empty_value, list) else None,
        )
    else:
        coordinator.data = coordinator_data(
            device=empty_value if isinstance(empty_value, dict) else None,
            sleep_records=sleep_records,
        )
    sensor._handle_coordinator_update()
    assert not sensor.available


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        "sensor_class",
        "key",
        "desc",
        "coordinator_data",
        "expected_native_value",
        "expected_available",
    ),
    [
        # MyAirSleepRecordSensor with empty sleep_records
        (
            MyAirSleepRecordSensor,
            "CPAP Usage Minutes",
            SLEEP_RECORD_SENSOR_DESCRIPTIONS["CPAP Usage Minutes"],
            {"sleep_records": []},
            None,
            False,
        ),
        # MyAirDeviceSensor with empty device dict
        (
            MyAirDeviceSensor,
            "CPAP Sleep Data Last Collected",
            DEVICE_SENSOR_DESCRIPTIONS["CPAP Sleep Data Last Collected"],
            {"device": {}},
            None,
            False,
        ),
        # MyAirDeviceSensor with missing device key
        (
            MyAirDeviceSensor,
            "CPAP Sleep Data Last Collected",
            DEVICE_SENSOR_DESCRIPTIONS["CPAP Sleep Data Last Collected"],
            {},
            None,
            False,
        ),
        # MyAirFriendlyUsageTime with empty sleep_records
        (
            MyAirFriendlyUsageTime,
            None,
            None,
            {"sleep_records": []},
            None,
            False,
        ),
        # MyAirMostRecentSleepDate with all sleep_records zero usage
        (
            MyAirMostRecentSleepDate,
            None,
            None,
            {
                "sleep_records": [
                    {"startDate": "2024-06-01", "totalUsage": 0},
                    {"startDate": "2024-06-02", "totalUsage": 0},
                ]
            },
            None,
            False,
        ),
    ],
)
async def test_sensor_handles_empty_or_missing_data(
    hass: MagicMock,
    sensor_class: type[object],
    key: str | None,
    desc: object,
    coordinator_data: dict[str, object],
    expected_native_value: object,
    expected_available: bool,
    coordinator_factory: CoordinatorFactory,
) -> None:
    """Entities remain safe when their coordinator payload is empty.

    Args:
        hass (MagicMock): Home Assistant instance attached to the sensor.
        sensor_class (type[object]): Sensor class exercised by the parameter set.
        key (str | None): Entity key passed to raw sensors, when applicable.
        desc (object): Sensor description passed to raw sensors.
        coordinator_data (dict[str, object]): Empty or incomplete payload under test.
        expected_native_value (object): Native value expected from the empty payload.
        expected_available (bool): Whether the sensor should remain available.
        coordinator_factory (CoordinatorFactory): Factory creating the test coordinator.
    """
    coordinator = coordinator_factory(data=coordinator_data)
    if sensor_class in (MyAirSleepRecordSensor, MyAirDeviceSensor):
        sensor = sensor_class(key, desc, coordinator)
    else:
        sensor = sensor_class(coordinator)
    sensor.hass = hass
    sensor.entity_id = f"sensor.test_{sensor_class.__name__.lower()}"
    sensor.async_write_ha_state = MagicMock()
    await sensor.async_added_to_hass()
    assert sensor.native_value == expected_native_value
    assert sensor.available == expected_available


@pytest.mark.asyncio
async def test_sensor_unique_id_and_device_info(
    hass: MagicMock, coordinator: CoordinatorLike
) -> None:
    """Sensors expose stable unique IDs and manufacturer device metadata.

    Args:
        hass (MagicMock): Home Assistant instance attached to the sensor.
        coordinator (CoordinatorLike): Coordinator providing the sensor payload.
    """
    key = "CPAP Usage Minutes"
    desc = SLEEP_RECORD_SENSOR_DESCRIPTIONS[key]
    sensor = MyAirSleepRecordSensor(key, desc, coordinator)
    sensor.hass = hass
    sensor.entity_id = "sensor.test_sleep_record"
    sensor.async_write_ha_state = MagicMock()
    await sensor.async_added_to_hass()
    assert sensor.unique_id is not None
    assert entity_device_info(sensor.device_info).manufacturer == "ResMed"


@pytest.mark.asyncio
async def test_async_setup_entry_registers_all_sensors(
    hass: MagicMock, config_entry: MockConfigEntry, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Setup registers every device, sleep, and synthesized sensor entity.

    Args:
        hass (MagicMock): Home Assistant instance receiving platform setup.
        config_entry (MockConfigEntry): Integration entry being set up.
        monkeypatch (pytest.MonkeyPatch): Pytest patch fixture for the coordinator.
    """
    added_entities = []

    def fake_add_entities(entities: list[object], update_before_add: bool) -> None:
        """Collect entities that setup passes to Home Assistant.

        Args:
            entities (list[object]): Sensor entities created by ``async_setup_entry``.
            update_before_add (bool): Whether HA should update entities before adding them.
        """
        assert update_before_add is False
        added_entities.extend(entities)

    # Only patch the coordinator class used by the sensor platform
    mock_coordinator = MagicMock()
    monkeypatch.setattr(sensor_platform, "MyAirDataUpdateCoordinator", mock_coordinator)
    instance = mock_coordinator.return_value
    instance.data = coordinator_data(
        device={"serialNumber": "SN123"},
        sleep_records=[{"totalUsage": 100, "startDate": "2024-06-01"}],
    )
    config_entry.runtime_data = instance
    await sensor_platform.async_setup_entry(hass, config_entry, fake_add_entities)

    # Should include all device, sleep record, and synthesized sensors
    assert any(isinstance(e, MyAirSleepRecordSensor) for e in added_entities)
    assert any(isinstance(e, MyAirDeviceSensor) for e in added_entities)
    assert any(isinstance(e, MyAirFriendlyUsageTime) for e in added_entities)
    assert any(isinstance(e, MyAirMostRecentSleepDate) for e in added_entities)
    expected_count = (
        len(DEVICE_SENSOR_DESCRIPTIONS)
        + len(SLEEP_RECORD_SENSOR_DESCRIPTIONS)
        + 3  # FriendlyUsageTime + MostRecentSleepDate + TimeInApnea
    )
    assert len(added_entities) == expected_count
