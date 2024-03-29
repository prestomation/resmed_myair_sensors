from typing import Dict, List
from datetime import datetime, timedelta
import logging
from dateutil import parser
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.components.sensor import SensorEntity
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.const import PERCENTAGE, UnitOfTime
from .common import CONF_PASSWORD, CONF_USER_NAME, CONF_REGION, DOMAIN
from .client.myair_client import MyAirClient, MyAirConfig
from .client import get_client


from .coordinator import MyAirDataUpdateCoordinator
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntityDescription,
    SensorStateClass,
)


_LOGGER = logging.getLogger(__name__)


class MyAirBaseSensor(CoordinatorEntity, SensorEntity):
    """The base sensor for ResMed myAir. It knows the Friendly Name and key from the API response
    for any particular sensor, and keeps track of the coordinator. All it really does is return that key from the newest
    response that the coordinator has stored."""

    coordinator: MyAirDataUpdateCoordinator
    sensor_key: str

    def __init__(
        self,
        friendly_name: str,
        sensor_desc: SensorEntityDescription,
        coordinator: MyAirDataUpdateCoordinator,
    ) -> None:
        """Create the CPAP sensors."""
        super().__init__(coordinator)
        self.sensor_key = sensor_desc.key
        self.coordinator = coordinator
        serial_number = self.coordinator.device["serialNumber"]
        self.entity_description = sensor_desc

        self._attr_name = friendly_name
        self._attr_unique_id = f"{DOMAIN}_{serial_number}_{self.sensor_key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, serial_number)},
            manufacturer=self.coordinator.device["fgDeviceManufacturerName"],
            model=self.coordinator.device["deviceType"],
            name=self.coordinator.device["localizedName"],
            suggested_area="Bedroom",
        )

    @property
    def available(self) -> bool:
        return self.coordinator.sleep_records is not None


class MyAirSleepRecordSensor(MyAirBaseSensor):
    def __init__(
        self,
        friendly_name: str,
        sensor_desc: SensorEntityDescription,
        coordinator: MyAirDataUpdateCoordinator,
    ) -> None:
        super().__init__(friendly_name, sensor_desc, coordinator)

    @property
    def native_value(self):

        # The API always returns the previous month of data, so the client stores this
        # We assume this is ordered temporally and grab the last one: the latest one
        value = self.coordinator.sleep_records[-1].get(self.sensor_key, 0)
        if self.sensor_key.endswith("Date"):
            # A bit of a hack to interpret date's as datetimes.
            value = datetime.strptime(value, "%Y-%m-%d").date()
        return value


class MyAirDeviceSensor(MyAirBaseSensor):
    def __init__(
        self,
        friendly_name: str,
        sensor_desc: SensorEntityDescription,
        coordinator: MyAirDataUpdateCoordinator,
    ) -> None:
        super().__init__(friendly_name, sensor_desc, coordinator)

    @property
    def native_value(self):

        value = self.coordinator.device[self.sensor_key]
        if self.sensor_key.endswith("Time"):
            # A bit of a hack to interpret this time as a time
            value = parser.parse(value)
        return value


class MyAirFriendlyUsageTime(MyAirBaseSensor):
    def __init__(
        self,
        coordinator: MyAirDataUpdateCoordinator,
    ) -> None:
        desc = SensorEntityDescription(
            key="usageTime"
        )

        super().__init__("CPAP Usage Time", desc, coordinator)

    @property
    def native_value(self):

        usage_minutes = self.coordinator.sleep_records[-1]["totalUsage"]
        # The split stuff is to cut off the seconds, so "07:30:00" becomes "07:30"
        return str(timedelta(minutes=float(usage_minutes)))[::-1].split(":", 1)[1][::-1]


class MyAirMostRecentSleepDate(MyAirBaseSensor):
    def __init__(
        self,
        coordinator: MyAirDataUpdateCoordinator,
    ) -> None:
        desc = SensorEntityDescription(
            key="mostRecentSleepDate", device_class=SensorDeviceClass.DATE
        )

        super().__init__("Most Recent Sleep Date", desc, coordinator)

    @property
    def native_value(self):

        # Filter out all 0-usage days
        sleep_days_with_data = list(
            filter(
                lambda record: record["totalUsage"] > 0, self.coordinator.sleep_records
            )
        )
        date_string = sleep_days_with_data[-1]["startDate"]
        return datetime.strptime(date_string, "%Y-%m-%d").date()


# Our sensor class will prepend the serial number to the key
# These sensors pass data directly from my air
SLEEP_RECORD_SENSOR_DESCRIPTIONS: Dict[str, SensorEntityDescription] = {
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

DEVICE_SENSOR_DESCRIPTIONS: Dict[str, SensorEntityDescription] = {
    "CPAP Sleep Data Last Collected": SensorEntityDescription(
        key="lastSleepDataReportTime", device_class=SensorDeviceClass.DATE
    )
}


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up myAir sensors."""
    username = config_entry.data[CONF_USER_NAME]
    password = config_entry.data[CONF_PASSWORD]
    region = config_entry.data.get(CONF_REGION, "NA")

    client_config = MyAirConfig(username=username, password=password, region=region)
    client: MyAirClient = get_client(client_config, async_create_clientsession(hass))
    coordinator = MyAirDataUpdateCoordinator(hass, client)

    hass.data.setdefault(DOMAIN, {})[config_entry.entry_id] = coordinator

    sensors: List[MyAirBaseSensor] = []
    await coordinator.async_config_entry_first_refresh()

    # Some sensors come from sleep data, which is a list with an entry for each of the last 30 days
    for key, desc in SLEEP_RECORD_SENSOR_DESCRIPTIONS.items():
        sensors.append(MyAirSleepRecordSensor(key, desc, coordinator))

    # Some sensors come from the device. Specifically, the last time the device reported new data
    if region == "NA":
        # EU gives the last sync time on the page, but is is localized both in timezone and in datestring text
        # So this data is not returned in EU.
        # We probably have enough data to calculate the right time, but let's skip it until it is asked for
        for key, desc in DEVICE_SENSOR_DESCRIPTIONS.items():
            sensors.append(MyAirDeviceSensor(key, desc, coordinator))

    # We have some synthesized sensors, lets add those too
    sensors.append(MyAirFriendlyUsageTime(coordinator))

    sensors.append(MyAirMostRecentSleepDate(coordinator))

    async_add_entities(sensors, False)

    sanitized_username = username.replace("@", "_").replace(".", "_")

    async def refresh(data):
        await coordinator.async_refresh()

    hass.services.async_register(DOMAIN, f"force_poll_{sanitized_username}", refresh)
