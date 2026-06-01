"""Home Assistant sensor entities for ResMed myAir account data."""

from datetime import date
import logging
import re
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
    VERSION,
)
from .coordinator import MyAirDataUpdateCoordinator
from .helpers import redact_dict
from .models import MyAirCoordinatorData, MyAirDevice, MyAirSleepRecord

_LOGGER: logging.Logger = logging.getLogger(__name__)
SERVICE_NAME_SANITIZER: Final[re.Pattern[str]] = re.compile(r"[^a-z0-9_]+")
_SensorPayload = MyAirDevice | MyAirSleepRecord


def _coordinator_data(coordinator: MyAirDataUpdateCoordinator) -> MyAirCoordinatorData:
    """Normalize coordinator payloads before sensors read typed fields.

    Args:
        coordinator: Integration coordinator whose data may be unset during startup.

    Returns:
        Existing typed data, or an empty payload that keeps entity updates defensive.
    """
    if isinstance(coordinator.data, MyAirCoordinatorData):
        return coordinator.data
    return MyAirCoordinatorData()


def _parse_native_value(value: Any | None, description: SensorEntityDescription) -> Any | None:
    """Convert raw API strings for Home Assistant date and timestamp sensors.

    Args:
        value: Raw value taken from a device or sleep-record payload.
        description: Entity description that declares any HA device class.

    Returns:
        Parsed date/datetime values for matching device classes; otherwise the
        original value.
    """
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
    """Create all myAir sensor entities and register the manual refresh service.

    Args:
        hass: Home Assistant instance receiving the entities and service.
        config_entry: Loaded myAir config entry with coordinator runtime data.
        async_add_entities: Home Assistant callback used to add entity instances.
    """
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

    sanitized_username: str = SERVICE_NAME_SANITIZER.sub(
        "_", config_entry.data[CONF_USER_NAME].casefold()
    ).strip("_")

    async def refresh(_: Any) -> None:
        """Refresh coordinator data when the per-account force-poll service runs.

        Args:
            _: Service call payload; unused because refresh needs no parameters.
        """
        await coordinator.async_refresh()

    hass.services.async_register(DOMAIN, f"force_poll_{sanitized_username}", refresh)


class MyAirBaseSensor(CoordinatorEntity[MyAirDataUpdateCoordinator], SensorEntity):
    """Base entity for sensors that share myAir device identity and availability."""

    _missing_source_log: str = "Sensor data missing from coordinator data"
    _parse_error_source: str = "Sensor"

    def __init__(
        self,
        friendly_name: str,
        sensor_desc: SensorEntityDescription,
        coordinator: MyAirDataUpdateCoordinator,
    ) -> None:
        """Initialize the HA entity metadata shared by all myAir sensors.

        The myAir serial number anchors the unique ID and device registry entry,
        while ``sensor_desc.key`` identifies the raw GraphQL field or synthesized
        value exposed by the concrete sensor.

        Args:
            friendly_name: Entity name shown in Home Assistant.
            sensor_desc: Home Assistant metadata and the myAir field key.
            coordinator: Data coordinator containing typed device and sleep snapshots.
        """
        super().__init__(coordinator)
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
        """Return whether the latest coordinator payload contained this sensor's data."""
        return self._available

    async def async_added_to_hass(self) -> None:
        """Publish an initial state from already-fetched coordinator data."""
        await super().async_added_to_hass()
        self._handle_coordinator_update()

    def _sensor_payload(self) -> _SensorPayload | None:
        """Return the model object that contains this sensor's raw API field.

        Returns:
            Device or sleep-record model for raw GraphQL-backed sensors, or ``None``
            when the coordinator did not receive the required payload.
        """
        raise NotImplementedError

    @callback
    def _handle_coordinator_update(self) -> None:
        """Read this sensor's key from its payload model and publish HA state.

        Subclasses select the source payload with ``_sensor_payload`` and configure
        source-specific log text; the base class owns raw-key presence checks,
        date/timestamp conversion, availability, and state writes.
        """
        payload: _SensorPayload | None = self._sensor_payload()
        if payload is None:
            _LOGGER.error(self._missing_source_log)
            value: Any | None = None
            self._available = False
        elif self.sensor_key not in payload.raw:
            _LOGGER.error("Unable to parse %s. %s", self._parse_error_source, self.sensor_key)
            value = None
            self._available = False
        else:
            value = _parse_native_value(
                payload.native_value(self.sensor_key), self.entity_description
            )
            self._available = True

        self._attr_native_value = value
        self.async_write_ha_state()


class MyAirSleepRecordSensor(MyAirBaseSensor):
    """Expose a configured GraphQL field from the newest nightly sleep record."""

    _missing_source_log = "Sleep record data missing from coordinator data"
    _parse_error_source = "Sleep Record"

    def _sensor_payload(self) -> _SensorPayload | None:
        """Select the latest dated sleep record from the coordinator snapshot.

        Returns:
            Most recent sleep record available for raw sleep metrics, or ``None``
            before the API has returned any sleep history.
        """
        # The API always returns the previous month of data, so the client stores this
        # We assume this is ordered temporally and grab the last one: the latest one
        return _coordinator_data(self.coordinator).latest_sleep_record


class MyAirDeviceSensor(MyAirBaseSensor):
    """Expose a configured GraphQL field from the assigned CPAP device payload."""

    _missing_source_log = "Device data missing from coordinator data"
    _parse_error_source = "Device"

    def _sensor_payload(self) -> _SensorPayload | None:
        """Select the device metadata payload from the coordinator snapshot.

        Returns:
            Device payload used for raw device-backed sensors, or ``None`` before
            the API has returned the account's active flow generator.
        """
        return _coordinator_data(self.coordinator).device


class MyAirFriendlyUsageTime(MyAirBaseSensor):
    """Expose latest CPAP usage minutes as user-friendly ``H:MM`` text."""

    def __init__(
        self,
        coordinator: MyAirDataUpdateCoordinator,
    ) -> None:
        """Initialize the synthesized usage-time entity.

        This sensor uses the normalized ``friendly_usage_time`` model field instead
        of a raw myAir GraphQL key, so it keeps its own update handler.

        Args:
            coordinator: Data coordinator that supplies sleep records.
        """
        desc = SensorEntityDescription(key="usageTime")

        super().__init__("CPAP Usage Time", desc, coordinator)

    @callback
    def _handle_coordinator_update(self) -> None:
        """Publish the latest sleep record's preformatted usage duration."""
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
    """Expose the newest sleep date whose record contains positive CPAP usage."""

    def __init__(
        self,
        coordinator: MyAirDataUpdateCoordinator,
    ) -> None:
        """Initialize the synthesized most-recent-sleep-date entity.

        The model filters out zero-usage records, so this date represents the
        latest night with actual CPAP use rather than the latest API row.

        Args:
            coordinator: Data coordinator that supplies sleep records.
        """
        desc = SensorEntityDescription(
            key="mostRecentSleepDate", device_class=SensorDeviceClass.DATE
        )

        super().__init__("Most Recent Sleep Date", desc, coordinator)

    @callback
    def _handle_coordinator_update(self) -> None:
        """Publish the model-derived latest date with non-zero CPAP usage."""
        value: date | None = _coordinator_data(self.coordinator).most_recent_sleep_date
        self._attr_native_value = value
        self._available = value is not None
        if value is None:
            _LOGGER.error("Sleep record data missing from coordinator data")

        self.async_write_ha_state()
