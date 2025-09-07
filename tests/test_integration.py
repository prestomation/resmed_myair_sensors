"""Tests for the resmed_myair integration (integration-level unit tests)."""

from datetime import date, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

import custom_components.resmed_myair as resmed_module
from custom_components.resmed_myair import (
    async_migrate_entry,
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


@pytest.mark.asyncio
async def test_async_setup_entry_refresh_failure(hass, config_entry, session, monkeypatch):
    """Test integration setup entry raises if first refresh fails."""
    # Replace async_create_clientsession to return the provided session
    monkeypatch.setattr(
        resmed_module, "async_create_clientsession", lambda *args, **kwargs: session
    )

    # Mock the coordinator class and capture the MagicMock for assertions
    mock_coordinator = MagicMock()
    monkeypatch.setattr(resmed_module, "MyAirDataUpdateCoordinator", mock_coordinator)
    instance = mock_coordinator.return_value
    instance.async_config_entry_first_refresh = AsyncMock(side_effect=Exception("refresh fail"))

    # Replace hass.config_entries.async_forward_entry_setups with an AsyncMock and keep a ref
    monkeypatch.setattr(hass.config_entries, "async_forward_entry_setups", AsyncMock())
    fwd = hass.config_entries.async_forward_entry_setups

    with pytest.raises(Exception) as exc:
        await async_setup_entry(hass, config_entry)
    assert "refresh fail" in str(exc.value)
    fwd.assert_not_awaited()


@pytest.mark.asyncio
async def test_async_setup_entry_multiple_calls(hass, config_entry, session, monkeypatch):
    """Test async_setup_entry can be called multiple times without error."""
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
async def test_friendly_usage_time_sensor_with_negative_usage(hass, coordinator_factory):
    """Test MyAirFriendlyUsageTime handles negative usage values."""

    coordinator = coordinator_factory(data={"sleep_records": [{"totalUsage": -10}]})
    sensor = MyAirFriendlyUsageTime(coordinator)
    sensor.hass = hass
    sensor.entity_id = "sensor.test_friendly_usage"
    sensor.async_write_ha_state = MagicMock()
    await sensor.async_added_to_hass()
    assert sensor.native_value == "0:00"  # Negative values should be clamped to "0:00"
    assert sensor.available is True


@pytest.mark.asyncio
async def test_most_recent_sleep_date_sensor_with_future_date(hass, coordinator_factory):
    """Test MyAirMostRecentSleepDate handles future dates."""
    future = (date.today() + timedelta(days=10)).isoformat()

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
async def test_async_migrate_entry_v2(hass, config_entry):
    """Test migration does nothing for version 2."""
    # The shared `config_entry` fixture is already a MockConfigEntry at version 2.
    hass.config_entries.async_update_entry = MagicMock()
    result = await async_migrate_entry(hass, config_entry)
    assert result is True
    assert config_entry.version == 2
    hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "unload_return, initial_runtime_data, expected_result, expected_runtime_data",
    [
        (True, "dummy", True, "dummy"),  # Success, runtime_data is NOT removed by integration
        (False, "dummy", False, "dummy"),  # Failure, runtime_data not removed
        (True, None, True, None),  # Success, runtime_data already None
    ],
)
async def test_async_unload_entry_variants(
    hass, config_entry, unload_return, initial_runtime_data, expected_result, expected_runtime_data
):
    """Test async_unload_entry returns correct result and preserves runtime_data."""
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
async def test_async_unload_entry_calls_unload_platforms(hass, config_entry):
    """Test async_unload_entry calls async_unload_platforms and returns True."""
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=True)
    config_entry.runtime_data = "dummy"
    result = await async_unload_entry(hass, config_entry)
    assert result is True
    hass.config_entries.async_unload_platforms.assert_awaited_once_with(config_entry, PLATFORMS)


@pytest.mark.asyncio
async def test_sleep_record_sensor_multiple_updates(hass, coordinator):
    """Test MyAirSleepRecordSensor updates value on multiple coordinator updates."""
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
    coordinator.data["sleep_records"][-1]["totalUsage"] = 321
    sensor._handle_coordinator_update()
    assert sensor.native_value == 321
    assert sensor.available is True
    # Update to another value
    coordinator.data["sleep_records"][-1]["totalUsage"] = 654
    sensor._handle_coordinator_update()
    assert sensor.native_value == 654
    assert sensor.available is True


@pytest.mark.asyncio
async def test_device_sensor_multiple_updates(hass, coordinator):
    """Test MyAirDeviceSensor updates value on multiple coordinator updates."""
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
    coordinator.data["device"]["lastSleepDataReportTime"] = "2024-06-03T09:00:00+00:00"
    sensor._handle_coordinator_update()
    assert sensor.native_value.isoformat().startswith("2024-06-03T09:00:00")
    assert sensor.available is True
    # Update to another datetime
    coordinator.data["device"]["lastSleepDataReportTime"] = "2024-06-04T10:30:00+00:00"
    sensor._handle_coordinator_update()
    assert sensor.native_value.isoformat().startswith("2024-06-04T10:30:00")
    assert sensor.available is True


@pytest.mark.asyncio
async def test_friendly_usage_time_sensor_multiple_updates(hass, coordinator):
    """Test MyAirFriendlyUsageTime sensor updates formatted usage time on data change."""
    sensor = MyAirFriendlyUsageTime(coordinator)
    sensor.hass = hass
    sensor.entity_id = "sensor.test_friendly_usage"
    sensor.async_write_ha_state = MagicMock()
    await sensor.async_added_to_hass()
    assert sensor.native_value == "7:36"
    assert sensor.available is True
    # Update usage to 120 minutes
    coordinator.data["sleep_records"][-1]["totalUsage"] = 120
    sensor._handle_coordinator_update()
    assert sensor.native_value == "2:00"
    assert sensor.available is True
    # Update usage to 0 (remains available; formatted as "0:00")
    coordinator.data["sleep_records"][-1]["totalUsage"] = 0
    sensor._handle_coordinator_update()
    assert sensor.native_value == "0:00"
    assert sensor.available is True


@pytest.mark.asyncio
async def test_most_recent_sleep_date_sensor_multiple_updates(hass, coordinator):
    """Test MyAirMostRecentSleepDate sensor updates date as new records are added."""
    sensor = MyAirMostRecentSleepDate(coordinator)
    sensor.hass = hass
    sensor.entity_id = "sensor.test_recent_sleep"
    sensor.async_write_ha_state = MagicMock()
    await sensor.async_added_to_hass()
    assert sensor.native_value.isoformat() == "2024-06-01"
    # Add a new record with usage
    coordinator.data["sleep_records"].append(
        {
            "startDate": "2024-06-05",
            "totalUsage": 200,
            "sleepScore": 88,
            "ahi": 1.5,
            "maskPairCount": 2,
            "leakPercentile": 3,
        }
    )
    sensor._handle_coordinator_update()
    assert sensor.native_value.isoformat() == "2024-06-05"
    # Add a record with no usage (should not change)
    coordinator.data["sleep_records"].append(
        {
            "startDate": "2024-06-06",
            "totalUsage": 0,
            "sleepScore": 70,
            "ahi": 3.0,
            "maskPairCount": 1,
            "leakPercentile": 7,
        }
    )
    sensor._handle_coordinator_update()
    assert sensor.native_value.isoformat() == "2024-06-05"
    assert sensor.available is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sensor_class, key, desc, data_field, empty_value",
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
    hass, coordinator, sensor_class, key, desc, data_field, empty_value
):
    """Test sensors become unavailable when their data is missing."""
    sensor = sensor_class(key, desc, coordinator)
    sensor.hass = hass
    sensor.entity_id = f"sensor.test_{key.replace(' ', '_').lower()}"
    sensor.async_write_ha_state = MagicMock()
    await sensor.async_added_to_hass()
    assert sensor.available
    coordinator.data[data_field] = empty_value
    sensor._handle_coordinator_update()
    assert not sensor.available


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sensor_class, key, desc, coordinator_data, expected_native_value, expected_available",
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
    hass,
    sensor_class,
    key,
    desc,
    coordinator_data,
    expected_native_value,
    expected_available,
    coordinator_factory,
):
    """Test sensors handle empty or missing data gracefully."""

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


# Fix: Make fake_forward_entry_setups an AsyncMock with the correct signature
async def fake_forward_entry_setups(config_entry, platforms):
    """Forward sensor platform setups during tests using the provided config entry."""
    # Use the hass from config_entry, which is set by Home Assistant during setup
    hass = config_entry.hass
    if "sensor" in platforms:
        await sensor_platform.async_setup_entry(hass, config_entry, MagicMock())


@pytest.mark.asyncio
async def test_force_poll_service_triggers_refresh(
    hass, config_entry, coordinator_factory, monkeypatch
):
    """Test that the force_poll service calls coordinator.async_refresh()."""

    # Use the centralized factory to create a mock coordinator with the
    # attributes tests expect (async_refresh, async_config_entry_first_refresh, .data)
    dummy_coordinator = coordinator_factory(mock=True)
    dummy_coordinator.data = {"device": {"serialNumber": "SN123"}, "sleep_records": []}
    config_entry.runtime_data = dummy_coordinator
    config_entry.hass = hass

    # Intercept service registration to capture the callback
    registered = {}
    domains = []

    def register(domain, name, func, *args, **kwargs):
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
async def test_sensor_unique_id_and_device_info(hass, coordinator):
    """Test that sensors have unique_id and correct device info."""
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
async def test_async_setup_entry_registers_all_sensors(hass, config_entry, monkeypatch):
    """Test async_setup_entry adds all expected sensor entities."""
    added_entities = []

    def fake_add_entities(entities, update_before_add):
        assert isinstance(update_before_add, bool)
        added_entities.extend(entities)

    # Only patch the coordinator class used by the sensor platform
    mock_coordinator = MagicMock()
    monkeypatch.setattr(sensor_platform, "MyAirDataUpdateCoordinator", mock_coordinator)
    instance = mock_coordinator.return_value
    instance.data = {
        "device": {"serialNumber": "SN123"},
        "sleep_records": [{"totalUsage": 100, "startDate": "2024-06-01"}],
    }
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
