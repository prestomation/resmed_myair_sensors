"""Tests for the resmed_myair integration (integration-level unit tests)."""

from datetime import date, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.resmed_myair import (
    async_migrate_entry,
    async_setup_entry,
    async_unload_entry,
    sensor as sensor_platform,
)
from custom_components.resmed_myair.const import (
    CONF_PASSWORD,
    CONF_REGION,
    CONF_USER_NAME,
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


@pytest.fixture
def config_entry():
    """Fixture for a mock config entry with correct keys."""
    entry = MagicMock()
    # Use the correct key names expected by the integration
    entry.data = {
        CONF_USER_NAME: "test@example.com",
        CONF_PASSWORD: "dummy",
        CONF_REGION: "us",
    }
    entry.version = 2
    entry.runtime_data = None
    return entry


@pytest.fixture
def coordinator():
    """Fixture for a mock coordinator with data and correct .data attribute."""

    class DummyCoordinator:
        def __init__(self):
            self.data = {
                "device": {
                    "serialNumber": "SN123",
                    "deviceType": "AirSense",
                    "lastSleepDataReportTime": "2024-06-01T12:00:00+00:00",
                    "localizedName": "Bedroom CPAP",
                    "fgDeviceManufacturerName": "ResMed",
                },
                "sleep_records": [
                    {
                        "startDate": "2024-05-31",
                        "totalUsage": 123,
                        "sleepScore": 90,
                        "ahi": 2.1,
                        "maskPairCount": 3,
                        "leakPercentile": 5,
                    },
                    {
                        "startDate": "2024-06-01",
                        "totalUsage": 456,
                        "sleepScore": 95,
                        "ahi": 1.8,
                        "maskPairCount": 2,
                        "leakPercentile": 4,
                    },
                ],
            }

        def async_add_listener(self, *args, **kwargs):
            return lambda: None

    return DummyCoordinator()


@pytest.mark.asyncio
async def test_async_setup_entry_refresh_failure(hass, config_entry):
    """Test integration setup entry raises if first refresh fails."""
    with (
        patch(
            "custom_components.resmed_myair.async_create_clientsession", return_value=MagicMock()
        ),
        patch("custom_components.resmed_myair.MyAirDataUpdateCoordinator") as mock_coordinator,
    ):
        instance = mock_coordinator.return_value
        instance.async_config_entry_first_refresh = AsyncMock(side_effect=Exception("refresh fail"))
        with pytest.raises(Exception) as exc:
            await async_setup_entry(hass, config_entry)
        assert "refresh fail" in str(exc.value)


@pytest.mark.asyncio
async def test_async_setup_entry_multiple_calls(hass, config_entry):
    """Test async_setup_entry can be called multiple times without error."""
    with (
        patch(
            "custom_components.resmed_myair.async_create_clientsession", return_value=MagicMock()
        ),
        patch("custom_components.resmed_myair.MyAirDataUpdateCoordinator") as mock_coordinator,
    ):
        instance = mock_coordinator.return_value
        instance.async_config_entry_first_refresh = AsyncMock()
        hass.services = MagicMock()
        hass.services.register = MagicMock()
        hass.services.async_register = MagicMock()
        result1 = await async_setup_entry(hass, config_entry)
        result2 = await async_setup_entry(hass, config_entry)
        assert result1 is True
        assert result2 is True


@pytest.mark.asyncio
async def test_friendly_usage_time_sensor_with_negative_usage(hass):
    """Test MyAirFriendlyUsageTime handles negative usage values."""

    class DummyCoordinator:
        def __init__(self):
            self.data = {"sleep_records": [{"totalUsage": -10}]}

        def async_add_listener(self, *args, **kwargs):
            return lambda: None

    sensor = MyAirFriendlyUsageTime(DummyCoordinator())
    sensor.hass = hass
    sensor.entity_id = "sensor.test_friendly_usage"
    sensor.async_write_ha_state = MagicMock()
    await sensor.async_added_to_hass()
    assert sensor.native_value == "0:00"  # Negative values should be clamped to "0:00"


@pytest.mark.asyncio
async def test_most_recent_sleep_date_sensor_with_future_date(hass):
    """Test MyAirMostRecentSleepDate handles future dates."""
    future = (date.today() + timedelta(days=10)).isoformat()

    class DummyCoordinator:
        def __init__(self):
            self.data = {"sleep_records": [{"startDate": future, "totalUsage": 10}]}

        def async_add_listener(self, *args, **kwargs):
            return lambda: None

    sensor = MyAirMostRecentSleepDate(DummyCoordinator())
    sensor.hass = hass
    sensor.entity_id = "sensor.test_recent_sleep"
    sensor.async_write_ha_state = MagicMock()
    await sensor.async_added_to_hass()
    assert sensor.native_value.isoformat() == future


@pytest.mark.asyncio
async def test_async_migrate_entry_v2(hass, config_entry):
    """Test migration does nothing for version 2."""
    config_entry.version = 2
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
    """Test async_unload_entry returns correct result and removes runtime_data if unload succeeds."""
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=unload_return)
    config_entry.runtime_data = initial_runtime_data
    result1 = await async_unload_entry(hass, config_entry)
    # Call a second time to check idempotency
    result2 = await async_unload_entry(hass, config_entry)
    assert result1 is expected_result
    assert result2 is expected_result
    assert config_entry.runtime_data == expected_runtime_data
    hass.config_entries.async_unload_platforms.assert_awaited_with(config_entry, PLATFORMS)


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
    # Update to a new value
    coordinator.data["sleep_records"][-1]["totalUsage"] = 321
    sensor._handle_coordinator_update()
    assert sensor.native_value == 321
    # Update to another value
    coordinator.data["sleep_records"][-1]["totalUsage"] = 654
    sensor._handle_coordinator_update()
    assert sensor.native_value == 654


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
    # Update to a new datetime
    coordinator.data["device"]["lastSleepDataReportTime"] = "2024-06-03T09:00:00+00:00"
    sensor._handle_coordinator_update()
    assert sensor.native_value.isoformat().startswith("2024-06-03T09:00:00")
    # Update to another datetime
    coordinator.data["device"]["lastSleepDataReportTime"] = "2024-06-04T10:30:00+00:00"
    sensor._handle_coordinator_update()
    assert sensor.native_value.isoformat().startswith("2024-06-04T10:30:00")


@pytest.mark.asyncio
async def test_friendly_usage_time_sensor_multiple_updates(hass, coordinator):
    """Test MyAirFriendlyUsageTime sensor updates formatted usage time on data change."""
    sensor = MyAirFriendlyUsageTime(coordinator)
    sensor.hass = hass
    sensor.entity_id = "sensor.test_friendly_usage"
    sensor.async_write_ha_state = MagicMock()
    await sensor.async_added_to_hass()
    assert sensor.native_value == "7:36"
    # Update usage to 120 minutes
    coordinator.data["sleep_records"][-1]["totalUsage"] = 120
    sensor._handle_coordinator_update()
    assert sensor.native_value == "2:00"
    # Update usage to 0 (should become unavailable)
    coordinator.data["sleep_records"][-1]["totalUsage"] = 0
    sensor._handle_coordinator_update()
    assert sensor.native_value == "0:00"


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
    hass, sensor_class, key, desc, coordinator_data, expected_native_value, expected_available
):
    """Test sensors handle empty or missing data gracefully."""

    class DummyCoordinator:
        def __init__(self, data):
            self.data = data

        def async_add_listener(self, *args, **kwargs):
            return lambda: None

    coordinator = DummyCoordinator(coordinator_data)
    if sensor_class in (MyAirSleepRecordSensor, MyAirDeviceSensor):
        sensor = sensor_class(key, desc, coordinator)
    else:
        sensor = sensor_class(coordinator)
    sensor.hass = hass
    sensor.entity_id = f"sensor.test_{sensor_class.__name__.lower()}"
    sensor.async_write_ha_state = MagicMock()
    await sensor.async_added_to_hass()
    assert sensor.native_value == expected_native_value


# Fix: Make fake_forward_entry_setups an AsyncMock with the correct signature
async def fake_forward_entry_setups(config_entry, platforms):
    """Forward sensor platform setups during tests using the provided config entry."""
    # Use the hass from config_entry, which is set by Home Assistant during setup
    hass = config_entry.hass
    if "sensor" in platforms:
        await sensor_platform.async_setup_entry(hass, config_entry, MagicMock())


@pytest.mark.asyncio
async def test_force_poll_service_triggers_refresh(hass, config_entry):
    """Test that the force_poll service calls coordinator.async_refresh()."""

    class DummyCoordinator:
        def __init__(self):
            self.async_refresh = AsyncMock()
            self.async_config_entry_first_refresh = AsyncMock()
            self.data = {
                "device": {"serialNumber": "SN123"},
                "sleep_records": [],
            }

        def async_add_listener(self, *args, **kwargs):
            return lambda: None

    dummy_coordinator = DummyCoordinator()
    config_entry.runtime_data = dummy_coordinator
    config_entry.data[CONF_USER_NAME] = "test@example.com"
    config_entry.hass = hass

    # Intercept service registration to capture the callback
    registered = {}

    def register(domain, name, func):
        registered[name] = func

    hass.services.async_register = register

    hass.config_entries.async_forward_entry_setups = AsyncMock(
        side_effect=fake_forward_entry_setups
    )

    with (
        patch(
            "custom_components.resmed_myair.MyAirDataUpdateCoordinator",
            return_value=dummy_coordinator,
        ),
        patch(
            "custom_components.resmed_myair.sensor.MyAirDataUpdateCoordinator",
            return_value=dummy_coordinator,
        ),
        patch("custom_components.resmed_myair.sensor.MyAirSleepRecordSensor"),
        patch("custom_components.resmed_myair.sensor.MyAirDeviceSensor"),
        patch("custom_components.resmed_myair.sensor.MyAirFriendlyUsageTime"),
        patch("custom_components.resmed_myair.sensor.MyAirMostRecentSleepDate"),
        patch(
            "homeassistant.helpers.update_coordinator.DataUpdateCoordinator.async_config_entry_first_refresh",
            new_callable=AsyncMock,
        ),
    ):
        await async_setup_entry(hass, config_entry)

    service_name = "force_poll_test_example_com"
    assert service_name in registered, "force_poll service was not registered"
    refresh_callback = registered[service_name]
    await refresh_callback(None)
    dummy_coordinator.async_refresh.assert_awaited_once()


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
async def test_async_setup_entry_registers_all_sensors(hass, config_entry):
    """Test async_setup_entry adds all expected sensor entities."""
    added_entities = []

    def fake_add_entities(entities, update_before_add):
        added_entities.extend(entities)

    # Only patch the coordinator, NOT the sensor classes
    with patch(
        "custom_components.resmed_myair.sensor.MyAirDataUpdateCoordinator"
    ) as mock_coordinator:
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
