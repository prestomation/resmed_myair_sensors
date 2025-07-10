"""Sensor entities for resmed_myair."""

from collections.abc import MutableMapping
import logging
from typing import Any, Final

from aiohttp import DummyCookieJar

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from .client.myair_client import MyAirConfig
from .client.rest_client import RESTClient
from .const import CONF_DEVICE_TOKEN, CONF_PASSWORD, CONF_REGION, CONF_USER_NAME, DOMAIN
from .coordinator import MyAirDataUpdateCoordinator
from .helpers import redact_dict

_LOGGER: logging.Logger = logging.getLogger(__name__)


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
        serial_number: str = self.coordinator.device["serialNumber"]
        self.entity_description: SensorEntityDescription = sensor_desc

        self._attr_name: str = friendly_name
        self._attr_unique_id: str = f"{DOMAIN}_{serial_number}_{self.sensor_key}"
        self._attr_device_info: DeviceInfo = DeviceInfo(
            identifiers={(DOMAIN, serial_number)},
            manufacturer=self.coordinator.device["fgDeviceManufacturerName"],
            model=self.coordinator.device["deviceType"],
            name=self.coordinator.device["localizedName"],
            suggested_area="Bedroom",
        )

    @property
    def available(self) -> bool:
        """Return if sensor is available."""
        return self.coordinator.sleep_records is not None


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

    @property
    def native_value(self) -> Any | None:
        """Return the native value (aka. state)."""
        # The API always returns the previous month of data, so the client stores this
        # We assume this is ordered temporally and grab the last one: the latest one
        value = self.coordinator.sleep_records[-1].get(self.sensor_key, 0)
        if self.entity_description.device_class == SensorDeviceClass.DATE and isinstance(
            value, str
        ):
            value = dt_util.parse_date(value)
        return value


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

    @property
    def native_value(self) -> Any | None:
        """Return the native value (aka. state)."""
        value = self.coordinator.device[self.sensor_key]
        if self.entity_description.device_class == SensorDeviceClass.TIMESTAMP:
            value = dt_util.parse_datetime(value)
        return value


class MyAirFriendlyUsageTime(MyAirBaseSensor):
    """myAir Friendly Usage Time sensor class."""

    def __init__(
        self,
        coordinator: MyAirDataUpdateCoordinator,
    ) -> None:
        """Initialize myAir Friendly Usage Time sensor."""
        desc = SensorEntityDescription(key="usageTime")

        super().__init__("CPAP Usage Time", desc, coordinator)

    @property
    def native_value(self) -> Any | None:
        """Return the native value (aka. state)."""
        usage_minutes = self.coordinator.sleep_records[-1]["totalUsage"]
        return f"{usage_minutes // 60}:{(usage_minutes % 60):02}"


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

    @property
    def native_value(self) -> Any | None:
        """Return the native value (aka. state)."""
        # Filter out all 0-usage days
        sleep_days_with_data = list(
            filter(lambda record: record["totalUsage"] > 0, self.coordinator.sleep_records)
        )
        date_string = sleep_days_with_data[-1]["startDate"]
        return dt_util.parse_date(date_string)


# Our sensor class will prepend the serial number to the key
# These sensors pass data directly from my air
SLEEP_RECORD_SENSOR_DESCRIPTIONS: MutableMapping[str, SensorEntityDescription] = {
    "CPAP AHI Events Per Hour": SensorEntityDescription(
        key="ahi",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "CPAP Usage Minutes": SensorEntityDescription(
        key="totalUsage",
        state_class=SensorStateClass.MEASUREMENT,
        device_class=SensorDeviceClass.DURATION,
        native_unit_of_measurement=UnitOfTime.MINUTES,
    ),
    "CPAP Mask On/Off": SensorEntityDescription(
        key="maskPairCount",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "CPAP Current Data Date": SensorEntityDescription(
        key="startDate", device_class=SensorDeviceClass.DATE
    ),
    "CPAP Mask Leak %": SensorEntityDescription(
        key="leakPercentile",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
    ),
    "CPAP Total myAir Score": SensorEntityDescription(
        key="sleepScore", state_class=SensorStateClass.MEASUREMENT
    ),
}

DEVICE_SENSOR_DESCRIPTIONS: MutableMapping[str, SensorEntityDescription] = {
    "CPAP Sleep Data Last Collected": SensorEntityDescription(
        key="lastSleepDataReportTime", device_class=SensorDeviceClass.TIMESTAMP
    )
}


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up myAir sensors."""
    _LOGGER.debug(
        "[sensor async_setup_entry] config_entry.data: %s", redact_dict(config_entry.data)
    )

    client_config: MyAirConfig = MyAirConfig(
        username=config_entry.data[CONF_USER_NAME],
        password=config_entry.data[CONF_PASSWORD],
        region=config_entry.data[CONF_REGION],
        device_token=config_entry.data.get(CONF_DEVICE_TOKEN, None),
    )
    client: RESTClient = RESTClient(
        client_config,
        async_create_clientsession(hass, cookie_jar=DummyCookieJar(), raise_for_status=True),
    )

    coordinator: MyAirDataUpdateCoordinator = MyAirDataUpdateCoordinator(hass, client)

    hass.data.setdefault(DOMAIN, {})[config_entry.entry_id] = coordinator

    sensors: list[MyAirBaseSensor] = []
    await coordinator.async_config_entry_first_refresh()

    # Some sensors come from sleep data, which is a list with an entry for each of the last 30 days
    for key, desc in SLEEP_RECORD_SENSOR_DESCRIPTIONS.items():
        sensors.append(MyAirSleepRecordSensor(key, desc, coordinator))

    # Some sensors come from the device. Specifically, the last time the device reported new data
    for key, desc in DEVICE_SENSOR_DESCRIPTIONS.items():
        sensors.append(MyAirDeviceSensor(key, desc, coordinator))

    # We have some synthesized sensors, lets add those too
    sensors.extend([MyAirFriendlyUsageTime(coordinator), MyAirMostRecentSleepDate(coordinator)])

    async_add_entities(sensors, False)

    sanitized_username: str = config_entry.data[CONF_USER_NAME].replace("@", "_").replace(".", "_")

    async def refresh(_: Any) -> None:
        await coordinator.async_refresh()

    hass.services.async_register(DOMAIN, f"force_poll_{sanitized_username}", refresh)
