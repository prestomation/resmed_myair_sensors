"""Sensor entities for resmed_myair."""

from datetime import date
import logging
from typing import Any, Final, cast

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity, DataUpdateCoordinator
from homeassistant.util import dt as dt_util

from .const import (
    CONF_USER_NAME,
    DEVICE_SENSOR_DESCRIPTIONS,
    DOMAIN,
    SLEEP_RECORD_SENSOR_DESCRIPTIONS,
    VERSION,
)
from .coordinator import MyAirDataUpdateCoordinator
from .helpers import redact_dict
from .models import MyAirCoordinatorData, MyAirDevice, MyAirSleepRecord

_LOGGER: logging.Logger = logging.getLogger(__name__)


def _coordinator_data(coordinator: MyAirDataUpdateCoordinator) -> MyAirCoordinatorData:
    """Return typed coordinator data or an empty payload."""
    if isinstance(coordinator.data, MyAirCoordinatorData):
        return coordinator.data
    return MyAirCoordinatorData()


def _parse_native_value(value: Any | None, description: SensorEntityDescription) -> Any | None:
    """Parse native values for Home Assistant sensor device classes."""
    if isinstance(value, str) and description.device_class == SensorDeviceClass.DATE:
        return dt_util.parse_date(value)
    if isinstance(value, str) and description.device_class == SensorDeviceClass.TIMESTAMP:
        return dt_util.parse_datetime(value)
    return value


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up myAir sensors."""
    _LOGGER.debug(
        "[sensor async_setup_entry] config_entry.data: %s", redact_dict(config_entry.data)
    )

    coordinator: MyAirDataUpdateCoordinator = config_entry.runtime_data

    sensors: list[MyAirBaseSensor] = []

    # Some sensors come from sleep data, which is a list with an entry for each of the last 30 days
    sensors.extend(
        MyAirSleepRecordSensor(key, desc, coordinator)
        for key, desc in SLEEP_RECORD_SENSOR_DESCRIPTIONS.items()
    )
    # Some sensors come from the device. Specifically, the last time the device reported new data
    sensors.extend(
        MyAirDeviceSensor(key, desc, coordinator)
        for key, desc in DEVICE_SENSOR_DESCRIPTIONS.items()
    )

    # We have some synthesized sensors, lets add those too
    sensors.extend(
        [
            MyAirFriendlyUsageTime(coordinator=coordinator),
            MyAirMostRecentSleepDate(coordinator=coordinator),
        ]
    )

    async_add_entities(sensors, False)

    sanitized_username: str = config_entry.data[CONF_USER_NAME].replace("@", "_").replace(".", "_")

    async def refresh(_: Any) -> None:
        await coordinator.async_refresh()

    hass.services.async_register(DOMAIN, f"force_poll_{sanitized_username}", refresh)


class MyAirBaseSensor(CoordinatorEntity, SensorEntity):
    """Base sensor for ResMed myAir.

    It knows the Friendly Name and key from the API response
    for any particular sensor and keeps track of the coordinator.
    All it really does is return that key from the newest
    response that the coordinator has stored.
    """

    def __init__(
        self,
        friendly_name: str,
        sensor_desc: SensorEntityDescription,
        coordinator: MyAirDataUpdateCoordinator,
    ) -> None:
        """Create the CPAP sensors."""
        super().__init__(cast("DataUpdateCoordinator[dict[str, Any]]", coordinator))
        self.sensor_key: Final[str] = sensor_desc.key
        self.coordinator: MyAirDataUpdateCoordinator = coordinator
        device_data: MyAirDevice | None = _coordinator_data(coordinator).device
        serial_number: str = device_data.serial_number if device_data else ""
        self.entity_description: SensorEntityDescription = sensor_desc

        self._attr_name: str = friendly_name
        self._attr_unique_id: str = f"{DOMAIN}_{serial_number}_{self.sensor_key}"
        self._available: bool = False
        self._attr_device_info: DeviceInfo = DeviceInfo(
            identifiers={(DOMAIN, serial_number)},
            manufacturer=device_data.manufacturer if device_data else None,
            model=device_data.model if device_data else None,
            name=device_data.name if device_data else None,
            suggested_area="Bedroom",
            sw_version=VERSION,
        )

    @property
    def available(self) -> bool:
        """Return whether entity is available."""
        return self._available

    async def async_added_to_hass(self) -> None:
        """Run once integration has been added to HA."""
        await super().async_added_to_hass()
        self._handle_coordinator_update()


class MyAirSleepRecordSensor(MyAirBaseSensor):
    """myAir Sleep Record sensor class."""

    def __init__(
        self,
        friendly_name: str,
        sensor_desc: SensorEntityDescription,
        coordinator: MyAirDataUpdateCoordinator,
    ) -> None:
        """Initialize myAir Sleep Record sensor."""
        super().__init__(friendly_name, sensor_desc, coordinator)

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        # The API always returns the previous month of data, so the client stores this
        # We assume this is ordered temporally and grab the last one: the latest one
        latest_record: MyAirSleepRecord | None = _coordinator_data(
            self.coordinator
        ).latest_sleep_record
        if latest_record is None:
            _LOGGER.error("Sleep record data missing from coordinator data")
            value: Any | None = None
            self._available = False
        elif self.sensor_key not in latest_record.raw:
            _LOGGER.error("Unable to parse Sleep Record. %s", self.sensor_key)
            value = None
            self._available = False
        else:
            value = _parse_native_value(
                latest_record.native_value(self.sensor_key), self.entity_description
            )
            self._available = value is not None

        self._attr_native_value = value
        self.async_write_ha_state()


class MyAirDeviceSensor(MyAirBaseSensor):
    """myAir Device sensor class."""

    def __init__(
        self,
        friendly_name: str,
        sensor_desc: SensorEntityDescription,
        coordinator: MyAirDataUpdateCoordinator,
    ) -> None:
        """Initialize myAir Device sensor."""
        super().__init__(friendly_name, sensor_desc, coordinator)

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        device_data: MyAirDevice | None = _coordinator_data(self.coordinator).device
        if device_data is None:
            _LOGGER.error("Device data missing from coordinator data")
            value: Any | None = None
            self._available = False
        elif self.sensor_key not in device_data.raw:
            _LOGGER.error("Unable to parse Device. %s", self.sensor_key)
            value = None
            self._available = False
        else:
            value = _parse_native_value(
                device_data.native_value(self.sensor_key), self.entity_description
            )
            self._available = value is not None

        self._attr_native_value = value
        self.async_write_ha_state()


class MyAirFriendlyUsageTime(MyAirBaseSensor):
    """myAir Friendly Usage Time sensor class."""

    def __init__(
        self,
        coordinator: MyAirDataUpdateCoordinator,
    ) -> None:
        """Initialize myAir Friendly Usage Time sensor."""
        desc = SensorEntityDescription(key="usageTime")

        super().__init__("CPAP Usage Time", desc, coordinator)

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        latest_record: MyAirSleepRecord | None = _coordinator_data(
            self.coordinator
        ).latest_sleep_record
        if latest_record is None:
            _LOGGER.error("Sleep record data missing from coordinator data")
            value: str | None = None
            self._available = False
        else:
            value = latest_record.friendly_usage_time
            self._available = value is not None
            if value is None:
                _LOGGER.error("Unable to parse Usage Time. totalUsage")

        self._attr_native_value = value
        self.async_write_ha_state()


class MyAirMostRecentSleepDate(MyAirBaseSensor):
    """myAir Most Recent Sleep Date sensor class."""

    def __init__(
        self,
        coordinator: MyAirDataUpdateCoordinator,
    ) -> None:
        """Initialize myAir Most Recent Sleep Date sensor."""
        desc = SensorEntityDescription(
            key="mostRecentSleepDate", device_class=SensorDeviceClass.DATE
        )

        super().__init__("Most Recent Sleep Date", desc, coordinator)

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        value: date | None = _coordinator_data(self.coordinator).most_recent_sleep_date
        self._attr_native_value = value
        self._available = value is not None
        if value is None:
            _LOGGER.error("Sleep record data missing from coordinator data")

        self.async_write_ha_state()
