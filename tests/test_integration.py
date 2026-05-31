"""Integration-level tests for setup, unload, migration, and sensor wiring."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

from homeassistant.components.sensor import SensorEntityDescription
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

import custom_components.resmed_myair as resmed_module
from custom_components.resmed_myair import (
    async_migrate_entry,
    async_setup_entry,
    async_unload_entry,
    sensor as sensor_platform,
)
from custom_components.resmed_myair.const import (
    CONF_USER_NAME,
    DEVICE_SENSOR_DESCRIPTIONS,
    DOMAIN,
    PLATFORMS,
    SLEEP_RECORD_SENSOR_DESCRIPTIONS,
)
from custom_components.resmed_myair.sensor import (
    MyAirDeviceSensor,
    MyAirFriendlyUsageTime,
    MyAirMostRecentSleepDate,
    MyAirSleepRecordSensor,
)
from tests.conftest import CoordinatorFactory, CoordinatorLike, coordinator_data


def _coordinator_payload(
    coordinator: CoordinatorLike,
) -> tuple[dict[str, object] | None, list[dict[str, object]]]:
    """Create mutable payload copies from typed coordinator data."""
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
    """Setup propagates refresh failures before forwarding platforms."""
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
    """Setup remains idempotent across repeated calls for the same entry."""
    monkeypatch.setattr(
        resmed_module, "async_create_clientsession", lambda *args, **kwargs: session
    )

    mock_coordinator = MagicMock()
    monkeypatch.setattr(resmed_module, "MyAirDataUpdateCoordinator", mock_coordinator)
    instance = mock_coordinator.return_value
    instance.async_config_entry_first_refresh = AsyncMock()

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
async def test_friendly_usage_time_sensor_with_negative_usage(
    hass: MagicMock, coordinator_factory: CoordinatorFactory
) -> None:
    """Friendly usage sensors clamp negative minutes to zero."""
    coordinator = coordinator_factory(data={"sleep_records": [{"totalUsage": -10}]})
    sensor = MyAirFriendlyUsageTime(coordinator)
    sensor.hass = hass
    sensor.entity_id = "sensor.test_friendly_usage"
    sensor.async_write_ha_state = MagicMock()
    await sensor.async_added_to_hass()
    assert sensor.native_value == "0:00"  # Negative values should be clamped to "0:00"
    assert sensor.available is True


@pytest.mark.asyncio
async def test_most_recent_sleep_date_sensor_with_future_date(
    hass: MagicMock, coordinator_factory: CoordinatorFactory
) -> None:
    """Most-recent sleep date sensors preserve future-dated records."""
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
async def test_async_migrate_entry_v2(hass: MagicMock, config_entry: MockConfigEntry) -> None:
    """Version 2 config entries skip migration updates."""
    # The shared `config_entry` fixture is already a MockConfigEntry at version 2.
    hass.config_entries.async_update_entry = MagicMock()
    result = await async_migrate_entry(hass, config_entry)
    assert result is True
    assert config_entry.version == 2
    hass.config_entries.async_update_entry.assert_not_called()


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
    """Unload returns the platform result without clearing runtime data."""
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
async def test_async_unload_entry_calls_unload_platforms(
    hass: MagicMock, config_entry: MockConfigEntry
) -> None:
    """Unload delegates to `async_unload_platforms` and returns success."""
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=True)
    config_entry.runtime_data = "dummy"
    result = await async_unload_entry(hass, config_entry)
    assert result is True
    hass.config_entries.async_unload_platforms.assert_awaited_once_with(config_entry, PLATFORMS)


@pytest.mark.asyncio
async def test_sleep_record_sensor_multiple_updates(
    hass: MagicMock, coordinator: CoordinatorLike
) -> None:
    """Sleep-record sensors follow successive coordinator payload updates."""
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
    """Device sensors follow successive coordinator payload updates."""
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
    """Friendly usage sensors reformat minutes after each data change."""
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
    """Most-recent sleep date sensors advance as new usable records appear."""
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
    """Entities go unavailable when the backing payload disappears."""
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
    """Entities remain safe when their coordinator payload is empty."""
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


# Home Assistant calls this through an AsyncMock side effect during setup tests.
async def fake_forward_entry_setups(config_entry: MockConfigEntry, platforms: list[str]) -> None:
    """Forward sensor platform setup calls using the test config entry."""
    # Use the hass from config_entry, which is set by Home Assistant during setup
    hass = config_entry.hass
    if "sensor" in platforms:
        await sensor_platform.async_setup_entry(hass, config_entry, MagicMock())


@pytest.mark.asyncio
async def test_force_poll_service_triggers_refresh(
    hass: MagicMock,
    config_entry: MockConfigEntry,
    coordinator_factory: CoordinatorFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The force-poll service directly triggers a coordinator refresh."""
    # Use the centralized factory to create a mock coordinator with the
    # attributes tests expect (async_refresh, async_config_entry_first_refresh, .data)
    dummy_coordinator = coordinator_factory(mock=True)
    dummy_coordinator.data = coordinator_data(device={"serialNumber": "SN123"}, sleep_records=[])
    config_entry.runtime_data = dummy_coordinator
    config_entry.hass = hass

    # Intercept service registration to capture the callback
    registered = {}
    domains = []

    def register(domain: str, name: str, func: object, *args: object, **kwargs: object) -> None:
        """Capture service registration arguments for force-poll assertions.

        Args:
            domain: Home Assistant service domain being registered.
            name: Service name derived from the account username.
            func: Service callback registered by the integration.
            *args: Additional Home Assistant service registration arguments.
            **kwargs: Additional Home Assistant service registration options.
        """
        registered[name] = func
        domains.append(domain)

    hass.services.async_register = register

    hass.config_entries.async_forward_entry_setups = AsyncMock(
        side_effect=fake_forward_entry_setups
    )

    # Monkeypatch coordinator classes and sensor classes to avoid full sensor setup
    monkeypatch.setattr(
        resmed_module, "MyAirDataUpdateCoordinator", lambda *a, **k: dummy_coordinator
    )
    monkeypatch.setattr(
        sensor_platform, "MyAirDataUpdateCoordinator", lambda *a, **k: dummy_coordinator
    )
    monkeypatch.setattr(sensor_platform, "MyAirSleepRecordSensor", MagicMock())
    monkeypatch.setattr(sensor_platform, "MyAirDeviceSensor", MagicMock())
    monkeypatch.setattr(sensor_platform, "MyAirFriendlyUsageTime", MagicMock())
    monkeypatch.setattr(sensor_platform, "MyAirMostRecentSleepDate", MagicMock())

    await async_setup_entry(hass, config_entry)

    # Since fake_forward_entry_setups is wired as the side effect, ensure it ran once
    assert hass.config_entries.async_forward_entry_setups.await_count == 1
    service_name = "force_poll_test_example_com"
    assert service_name in registered, "force_poll service was not registered"
    refresh_callback = registered[service_name]
    await refresh_callback(None)
    dummy_coordinator.async_refresh.assert_awaited_once()
    assert domains[-1] == "resmed_myair"


@pytest.mark.asyncio
async def test_sensor_unique_id_and_device_info(
    hass: MagicMock, coordinator: CoordinatorLike
) -> None:
    """Sensors expose stable unique IDs and manufacturer device metadata."""
    key = "CPAP Usage Minutes"
    desc = SLEEP_RECORD_SENSOR_DESCRIPTIONS[key]
    sensor = MyAirSleepRecordSensor(key, desc, coordinator)
    sensor.hass = hass
    sensor.entity_id = "sensor.test_sleep_record"
    sensor.async_write_ha_state = MagicMock()
    await sensor.async_added_to_hass()
    assert sensor.unique_id is not None
    assert sensor.device_info is not None
    assert "ResMed" in (sensor.device_info.get("manufacturer") or "")


@pytest.mark.asyncio
async def test_async_setup_entry_registers_all_sensors(
    hass: MagicMock, config_entry: MockConfigEntry, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Setup registers every device, sleep, and synthesized sensor entity."""
    added_entities = []

    def fake_add_entities(entities: list[object], update_before_add: bool) -> None:
        """Collect entities that setup passes to Home Assistant.

        Args:
            entities: Sensor entities created by ``async_setup_entry``.
            update_before_add: Whether HA should update entities before adding them.
        """
        assert isinstance(update_before_add, bool)
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
        + 2  # FriendlyUsageTime + MostRecentSleepDate
    )
    assert len(added_entities) == expected_count


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("username", "expected_service_name"),
    [
        ("test@example.com", "force_poll_test_example_com"),
        ("test+alerts@example.com", "force_poll_test_alerts_example_com"),
        ("Upper.User@example.com", "force_poll_upper_user_example_com"),
    ],
)
async def test_sensor_setup_registers_valid_force_poll_service_names(
    hass: MagicMock,
    config_entry: MockConfigEntry,
    coordinator_factory: CoordinatorFactory,
    monkeypatch: pytest.MonkeyPatch,
    username: str,
    expected_service_name: str,
) -> None:
    """Sensor setup sanitizes account usernames into valid HA service names."""
    registered_services: list[tuple[str, str, object]] = []

    def register_service(domain: str, service: str, handler: object) -> None:
        """Collect service registrations from the platform setup flow."""
        registered_services.append((domain, service, handler))

    coordinator = coordinator_factory(mock=True)
    coordinator.data = coordinator_data(device={"serialNumber": "SN123"}, sleep_records=[])
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="ResMed-CPAP",
        data={**config_entry.data, CONF_USER_NAME: username},
        entry_id=f"entry-{expected_service_name}",
        version=2,
    )
    entry.runtime_data = coordinator
    hass.services.async_register = register_service

    monkeypatch.setattr(
        sensor_platform,
        "SLEEP_RECORD_SENSOR_DESCRIPTIONS",
        {"usage": SensorEntityDescription(key="totalUsage")},
    )
    monkeypatch.setattr(
        sensor_platform,
        "DEVICE_SENSOR_DESCRIPTIONS",
        {"serial": SensorEntityDescription(key="serialNumber")},
    )

    await sensor_platform.async_setup_entry(hass, entry, MagicMock())

    assert registered_services
    assert registered_services[-1][0] == DOMAIN
    assert registered_services[-1][1] == expected_service_name
