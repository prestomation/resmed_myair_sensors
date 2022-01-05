from typing import Dict, List
from datetime import datetime
import logging
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.components.sensor import SensorEntity
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.const import PERCENTAGE
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
        sensor_desc.key = f"myair_{serial_number}_{sensor_desc.key}"
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
    def native_value(self):

        # The API always returns the previous month of data, so the client stores this
        # We assume this is ordered temporally and grab the last one: the latest one
        value = self.coordinator.sleep_records[-1].get(self.sensor_key, 0)
        if self.sensor_key.endswith("Date"):
            # A bit of a hack to interpret date's as datetimes.
            value = datetime.strptime(value, "%Y-%m-%d")
        return value


# Our sensor class will prepend the serial number to the key
SENSOR_DESCRIPTIONS: Dict[str, SensorEntityDescription] = {
    "CPAP AHI Events Per Hour": SensorEntityDescription(
        key="ahi",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "CPAP Usage Minutes": SensorEntityDescription(
        key="totalUsage",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "CPAP Mask On/Off": SensorEntityDescription(
        key="maskPairCount",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "CPAP Last Sleep Date Recorded": SensorEntityDescription(
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
    client: MyAirClient = get_client(client_config)
    coordinator = MyAirDataUpdateCoordinator(hass, client)

    hass.data.setdefault(DOMAIN, {})[config_entry.entry_id] = coordinator

    sensors: List[MyAirBaseSensor] = []
    await coordinator.async_config_entry_first_refresh()

    for key, desc in SENSOR_DESCRIPTIONS.items():
        sensors.append(MyAirBaseSensor(key, desc, coordinator))

    async_add_entities(sensors, False)
