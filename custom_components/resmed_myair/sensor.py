"""Sensor entities for resmed_myair."""

from collections.abc import Mapping
from datetime import date
import logging
from typing import Any, Final

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from .const import (
    CONF_USER_NAME,
    DEVICE_SENSOR_DESCRIPTIONS,
    DOMAIN,
    SLEEP_RECORD_SENSOR_DESCRIPTIONS,
)
from .coordinator import MyAirDataUpdateCoordinator
from .helpers import redact_dict

_LOGGER: logging.Logger = logging.getLogger(__name__)


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
        super().__init__(coordinator)
        self.sensor_key: Final[str] = sensor_desc.key
        self.coordinator: MyAirDataUpdateCoordinator = coordinator
        device_data = self.coordinator.data.get("device", {})
        serial_number: str = device_data.get("serialNumber", "")
        self.entity_description: SensorEntityDescription = sensor_desc

        self._attr_name: str = friendly_name
        self._attr_unique_id: str = f"{DOMAIN}_{serial_number}_{self.sensor_key}"
        self._attr_device_info: DeviceInfo = DeviceInfo(
            identifiers={(DOMAIN, serial_number)},
            manufacturer=device_data.get("fgDeviceManufacturerName"),
            model=device_data.get("deviceType"),
            name=device_data.get("localizedName"),
            suggested_area="Bedroom",
        )

    @property
    def available(self) -> bool:
        """Return if sensor is available."""
        return self.coordinator.data.get("sleep_records") is not None

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
        value: Any | None = None
        if self.coordinator.data.get("sleep_records"):
            try:
                value = self.coordinator.data["sleep_records"][-1][self.sensor_key]
            except KeyError as e:
                _LOGGER.error("Unable to parse Sleep Record. %s: %s", type(e).__name__, e)
            if (
                isinstance(value, str)
                and self.entity_description.device_class == SensorDeviceClass.DATE
            ):
                value = dt_util.parse_date(value)

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
        value: Any | None = None
        if self.coordinator.data.get("device"):
            try:
                value = self.coordinator.data["device"][self.sensor_key]
            except KeyError as e:
                _LOGGER.error("Unable to parse Device. %s: %s", type(e).__name__, e)
            if (
                isinstance(value, str)
                and self.entity_description.device_class == SensorDeviceClass.TIMESTAMP
            ):
                value = dt_util.parse_datetime(value)

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
        value: str | None = None
        if self.coordinator.data.get("sleep_records"):
            try:
                usage_minutes: int = self.coordinator.data["sleep_records"][-1]["totalUsage"]
            except KeyError as e:
                _LOGGER.error("Unable to parse Usage Time. %s: %s", type(e).__name__, e)
            else:
                value = f"{usage_minutes // 60}:{(usage_minutes % 60):02}"

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
        value: date | None = None
        if self.coordinator.data.get("sleep_records"):
            try:
                # Filter out all 0-usage days
                sleep_days_with_data: list[Mapping[str, Any]] = [
                    record
                    for record in self.coordinator.data["sleep_records"]
                    if record["totalUsage"] > 0
                ]

                if sleep_days_with_data:
                    date_string: str = sleep_days_with_data[-1]["startDate"]
                    value = dt_util.parse_date(date_string)
            except KeyError as e:
                _LOGGER.error("Unable to parse Most Recent Sleep Date. %s: %s", type(e).__name__, e)

        self._attr_native_value = value
        self.async_write_ha_state()
