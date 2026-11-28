"""Home Assistant sensor entities for ResMed myAir account data."""

from abc import abstractmethod
from collections.abc import Mapping
from datetime import date
import logging
from typing import Any, Final

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfTime
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util
from homeassistant.util.unit_conversion import DurationConverter

from .const import (
    DEVICE_SENSOR_DESCRIPTIONS,
    DOMAIN,
    MAX_DAILY_USAGE_ATTRIBUTE_DAYS,
    NIGHTLY_TIMELINE_KEY,
    SLEEP_RECORD_INDEX_FIELDS,
    SLEEP_RECORD_SENSOR_DESCRIPTIONS,
    TIME_IN_APNEA_KEY,
    VERSION,
)
from .coordinator import MyAirDataUpdateCoordinator, sensor_unique_id
from .models import MyAirCoordinatorData, MyAirDevice, MyAirSleepRecord
from .recorder import (
    HistoricalStatisticDescription,
    async_import_historical_statistics,
    build_daily_usage_hours,
    build_sleep_record_statistic,
    historical_statistic_id,
    normalize_sleep_history,
    usage_minutes_to_hours,
)
from .redaction import redact_dict

_LOGGER: logging.Logger = logging.getLogger(__name__)
_SensorPayload = MyAirDevice | MyAirSleepRecord


def _coordinator_data(coordinator: MyAirDataUpdateCoordinator) -> MyAirCoordinatorData:
    """Normalize coordinator payloads before sensors read typed fields.

    Args:
        coordinator (MyAirDataUpdateCoordinator): Integration coordinator whose
            data may be unset during startup.

    Returns:
        MyAirCoordinatorData: Existing typed data, or an empty payload that keeps
            entity updates defensive.
    """
    if isinstance(coordinator.data, MyAirCoordinatorData):
        return coordinator.data
    return MyAirCoordinatorData()


def _parse_native_value(value: Any | None, description: SensorEntityDescription) -> Any | None:
    """Convert raw API strings for Home Assistant date and timestamp sensors.

    Args:
        value (Any | None): Raw value taken from a device or sleep-record payload.
        description (SensorEntityDescription): Entity description that declares any
            HA device class.

    Returns:
        Any | None: Parsed date/datetime values for matching device classes;
            otherwise the original value.
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
    """Create all myAir sensor entities for a config entry.

    Args:
        hass (HomeAssistant): Home Assistant instance receiving the entities.
        config_entry (ConfigEntry): Loaded myAir config entry with coordinator
            runtime data.
        async_add_entities (AddEntitiesCallback): Home Assistant callback used to
            add entity instances.
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
            MyAirUsageHoursSensor(coordinator=coordinator),
            MyAirUsageHoursAverageSensor(coordinator=coordinator, days=7),
            MyAirUsageHoursAverageSensor(coordinator=coordinator, days=30),
            MyAirMostRecentSleepDate(coordinator=coordinator),
            MyAirTimeInApnea(coordinator),
            MyAirNightlyTimeline(coordinator),
        ]
    )

    async_add_entities(sensors, False)


class MyAirBaseSensor(CoordinatorEntity[MyAirDataUpdateCoordinator], SensorEntity):
    """Base entity for sensors that share myAir device identity and availability."""

    def __init__(
        self,
        friendly_name: str,
        sensor_desc: SensorEntityDescription,
        coordinator: MyAirDataUpdateCoordinator,
    ) -> None:
        """Initialize the HA entity metadata shared by all myAir sensors.

        The Configured CPAP Device serial anchors the unique ID and device registry
        entry, while ``sensor_desc.key`` identifies the raw GraphQL field or
        synthesized value exposed by the concrete sensor.

        Args:
            friendly_name (str): Entity name shown in Home Assistant.
            sensor_desc (SensorEntityDescription): Home Assistant metadata and the
                myAir field key.
            coordinator (MyAirDataUpdateCoordinator): Data coordinator containing
                typed device and sleep snapshots.
        """
        super().__init__(coordinator)
        self.sensor_key: Final[str] = sensor_desc.key
        self.coordinator: MyAirDataUpdateCoordinator = coordinator
        self.entity_description: SensorEntityDescription = sensor_desc
        self._attr_name: str = friendly_name
        self._available: bool = False

        data = _coordinator_data(coordinator)
        serial = data.serial
        self._attr_unique_id: str = sensor_unique_id(
            coordinator.config_entry.entry_id, serial, self.sensor_key
        )
        if serial is None:
            # The coordinator moves this sensor to its serial-based unique ID later.
            return
        device = data.device
        if device is not None:
            self._attr_device_info = DeviceInfo(
                identifiers={(DOMAIN, serial)},
                suggested_area="Bedroom",
                sw_version=VERSION,
                manufacturer=device.manufacturer,
                model=device.model,
                name=device.name,
            )
        else:
            # Without a device payload, omit metadata so the device registry keeps its values.
            self._attr_device_info = DeviceInfo(
                identifiers={(DOMAIN, serial)},
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

    @property
    def _historical_statistic(self) -> HistoricalStatisticDescription | None:
        """Return the historical statistic description for this entity."""
        return None

    @property
    def _historical_statistic_id(self) -> str | None:
        """Return the recorder statistic ID for this entity's imported history."""
        statistic_desc = self._historical_statistic
        serial = _coordinator_data(self.coordinator).serial
        if statistic_desc is None or not serial:
            return None

        return historical_statistic_id(serial, self.sensor_key, statistic_desc.import_mode)

    @property
    def extra_state_attributes(self) -> Mapping[str, Any] | None:
        """Preserve sensor attributes and expose the historical statistic ID when available."""
        attributes = super().extra_state_attributes
        statistic_id = self._historical_statistic_id
        if statistic_id is None:
            return attributes
        return {**(attributes or {}), "historical_statistic_id": statistic_id}

    def _schedule_historical_statistics_import(self, data: MyAirCoordinatorData) -> None:
        """Schedule recorder import for the current sleep records and statistic.

        Args:
            data (MyAirCoordinatorData): Snapshot for the Configured CPAP Device.
        """
        if self.hass is None:
            return

        statistic_desc = self._historical_statistic
        statistic_id = self._historical_statistic_id
        if statistic_desc is None or statistic_id is None:
            return

        if not data.sleep_records:
            return

        self.hass.async_create_task(
            async_import_historical_statistics(
                self.hass, data.sleep_records, statistic_id, statistic_desc
            )
        )

    @callback
    def async_registry_entry_updated(self) -> None:
        """Keep this sensor's unique ID in step with its registry entry.

        The coordinator can move a sensor built before the serial was known onto its
        serial-based unique ID while the sensor keeps running. Home Assistant may then
        remove and re-add this object, registering whatever unique ID it still holds.
        Copying the registry's unique ID keeps the re-added entity on the adopted ID.
        """
        if self.registry_entry is not None:
            self._attr_unique_id = self.registry_entry.unique_id
        super().async_registry_entry_updated()

    @callback
    def _handle_coordinator_update(self) -> None:
        """Publish state only from data attributed to the Configured CPAP Device."""
        data = _coordinator_data(self.coordinator)
        if data.withheld:
            self._available = False
            self._attr_native_value = None
        else:
            self._update_from_data(data)
        self.async_write_ha_state()
        if not data.withheld:
            self._schedule_historical_statistics_import(data)

    @abstractmethod
    def _update_from_data(self, data: MyAirCoordinatorData) -> None:
        """Set this sensor's value and availability from an attributed snapshot.

        Args:
            data (MyAirCoordinatorData): Snapshot for the Configured CPAP Device.
        """


class MyAirTimeInApnea(MyAirBaseSensor):
    """Report the time myAir measured in apnea for the Current Data Date."""

    def __init__(self, coordinator: MyAirDataUpdateCoordinator) -> None:
        """Initialize the optional duration sensor.

        Args:
            coordinator (MyAirDataUpdateCoordinator): Coordinator supplying the sensor snapshot.
        """
        super().__init__(
            "CPAP Time in Apnea",
            SensorEntityDescription(
                key=TIME_IN_APNEA_KEY,
                device_class=SensorDeviceClass.DURATION,
                native_unit_of_measurement=UnitOfTime.SECONDS,
                entity_registry_enabled_default=False,
            ),
            coordinator,
        )

    def _update_from_data(self, data: MyAirCoordinatorData) -> None:
        """Set the current duration, with missing data represented as unknown.

        Args:
            data (MyAirCoordinatorData): Snapshot for the Configured CPAP Device.
        """
        self._available = self.coordinator.last_update_success
        timeline = data.nightly_timeline
        self._attr_native_value = timeline.total_seconds_in_apnea if timeline else None


class MyAirNightlyTimeline(MyAirBaseSensor):
    """Report the Current Data Date with that night's timeline as attributes."""

    # The event list can be long and is refetched from myAir on demand.
    _unrecorded_attributes = frozenset({"events"})

    def __init__(self, coordinator: MyAirDataUpdateCoordinator) -> None:
        """Initialize the optional timeline sensor.

        Args:
            coordinator (MyAirDataUpdateCoordinator): Coordinator supplying the sensor snapshot.
        """
        super().__init__(
            "CPAP Nightly Timeline",
            SensorEntityDescription(
                key=NIGHTLY_TIMELINE_KEY,
                device_class=SensorDeviceClass.DATE,
                icon="mdi:chart-timeline-variant",
                entity_registry_enabled_default=False,
            ),
            coordinator,
        )

    def _update_from_data(self, data: MyAirCoordinatorData) -> None:
        """Set the Current Data Date and that night's timeline, when received.

        Args:
            data (MyAirCoordinatorData): Snapshot for the Configured CPAP Device.
        """
        latest = data.latest_sleep_record
        current_date = latest.start_date if latest else None
        timeline = data.nightly_timeline
        attributes = timeline.as_dict() if timeline is not None else None
        self._available = self.coordinator.last_update_success and current_date is not None
        self._attr_native_value = current_date
        self._attr_extra_state_attributes = attributes or {}


class MyAirRawSensor(MyAirBaseSensor):
    """Base entity for sensors that read a raw API field from a model payload."""

    _missing_source_log: str = "Sensor data missing from coordinator data"
    _parse_error_source: str = "Sensor"

    @abstractmethod
    def _sensor_payload(self, data: MyAirCoordinatorData) -> _SensorPayload | None:
        """Return the model object that contains this sensor's raw API field.

        Args:
            data (MyAirCoordinatorData): Snapshot for the Configured CPAP Device.

        Returns:
            _SensorPayload | None: Device or sleep-record model for raw
                GraphQL-backed sensors, or ``None`` when the coordinator did not
                receive the required payload.
        """

    def _update_from_data(self, data: MyAirCoordinatorData) -> None:
        """Read this sensor's key from its payload model.

        Subclasses select the source payload with ``_sensor_payload`` and configure
        source-specific log text; this class owns raw-key presence checks,
        date/timestamp conversion, and availability.

        Args:
            data (MyAirCoordinatorData): Snapshot for the Configured CPAP Device.
        """
        payload: _SensorPayload | None = self._sensor_payload(data)
        if payload is None:
            _LOGGER.error(self._missing_source_log)
            value: Any | None = None
            self._available = False
        elif self.sensor_key not in payload.raw:
            log_missing = (
                _LOGGER.debug if self.sensor_key in SLEEP_RECORD_INDEX_FIELDS else _LOGGER.error
            )
            log_missing("Unable to parse %s. %s", self._parse_error_source, self.sensor_key)
            value = None
            self._available = False
        else:
            value = _parse_native_value(
                payload.native_value(self.sensor_key), self.entity_description
            )
            self._available = True

        self._attr_native_value = value


class MyAirSleepRecordSensor(MyAirRawSensor):
    """Expose a configured GraphQL field from the newest nightly sleep record."""

    _missing_source_log = "Sleep record data missing from coordinator data"
    _parse_error_source = "Sleep Record"

    def __init__(
        self,
        friendly_name: str,
        sensor_desc: SensorEntityDescription,
        coordinator: MyAirDataUpdateCoordinator,
    ) -> None:
        """Initialize a raw sleep-record sensor.

        Args:
            friendly_name (str): User-visible name for the sensor.
            sensor_desc (SensorEntityDescription): Raw myAir field definition.
            coordinator (MyAirDataUpdateCoordinator): Data coordinator that supplies
                sleep records.
        """
        super().__init__(friendly_name, sensor_desc, coordinator)
        self._historical_statistic_desc = build_sleep_record_statistic(friendly_name, sensor_desc)

    @property
    def _historical_statistic(self) -> HistoricalStatisticDescription | None:
        """Return the historical statistic description for this entity."""
        return self._historical_statistic_desc

    def _sensor_payload(self, data: MyAirCoordinatorData) -> _SensorPayload | None:
        """Select the latest dated sleep record from the coordinator snapshot.

        Args:
            data (MyAirCoordinatorData): Snapshot for the Configured CPAP Device.

        Returns:
            _SensorPayload | None: Most recent sleep record available for raw sleep
                metrics, or ``None`` before the API has returned any sleep history.
        """
        # The API always returns the previous month of data, so the client stores this
        # We assume this is ordered temporally and grab the last one: the latest one
        return data.latest_sleep_record


class MyAirDeviceSensor(MyAirRawSensor):
    """Expose a configured GraphQL field from the assigned CPAP device payload."""

    _missing_source_log = "Device data missing from coordinator data"
    _parse_error_source = "Device"

    def _sensor_payload(self, data: MyAirCoordinatorData) -> _SensorPayload | None:
        """Select the device metadata payload from the coordinator snapshot.

        Args:
            data (MyAirCoordinatorData): Snapshot for the Configured CPAP Device.

        Returns:
            _SensorPayload | None: Device payload used for raw device-backed
                sensors, or ``None`` before the API has returned the account's
                active flow generator.
        """
        return data.device


class MyAirFriendlyUsageTime(MyAirBaseSensor):
    """Expose latest CPAP usage minutes as user-friendly ``H:MM`` text."""

    def __init__(
        self,
        coordinator: MyAirDataUpdateCoordinator,
    ) -> None:
        """Initialize the synthesized usage-time entity.

        This sensor uses the normalized ``friendly_usage_time`` model field instead
        of a raw myAir GraphQL key, so it implements its own ``_update_from_data``.

        Args:
            coordinator (MyAirDataUpdateCoordinator): Data coordinator that supplies
                sleep records.
        """
        desc = SensorEntityDescription(key="usageTime")

        super().__init__("CPAP Usage Time", desc, coordinator)

    def _update_from_data(self, data: MyAirCoordinatorData) -> None:
        """Set the latest sleep record's preformatted usage duration.

        Args:
            data (MyAirCoordinatorData): Snapshot for the Configured CPAP Device.
        """
        latest_record: MyAirSleepRecord | None = data.latest_sleep_record
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


class MyAirUsageHoursSensor(MyAirBaseSensor):
    """Expose latest usage as hours and import nightly usage statistics."""

    def __init__(
        self,
        coordinator: MyAirDataUpdateCoordinator,
    ) -> None:
        """Initialize the synthesized usage-hours entity.

        Args:
            coordinator (MyAirDataUpdateCoordinator): Data coordinator that supplies
                sleep records.
        """
        desc = SensorEntityDescription(
            key="usageHours",
            device_class=SensorDeviceClass.DURATION,
            native_unit_of_measurement="h",
            state_class=SensorStateClass.MEASUREMENT,
        )

        super().__init__("CPAP Usage Hours", desc, coordinator)
        self._historical_statistic_desc = HistoricalStatisticDescription(
            name="CPAP Usage Hours",
            unit_of_measurement="h",
            value_fn=lambda record: (
                None
                if record.get("totalUsage") is None
                else usage_minutes_to_hours(record["totalUsage"])
            ),
            unit_class=DurationConverter.UNIT_CLASS,
            import_mode="sum",
            round_digits=2,
        )

    @property
    def _historical_statistic(self) -> HistoricalStatisticDescription | None:
        """Return the historical statistic description for this entity."""
        return self._historical_statistic_desc

    @property
    def extra_state_attributes(self) -> Mapping[str, Any] | None:
        """Return extra state attributes for dashboard cards."""
        attributes = dict(super().extra_state_attributes or {})
        chart_records = self.coordinator.chart_sleep_records
        attributes["daily_usage_hours"] = build_daily_usage_hours(chart_records)
        attributes["daily_usage_hours_retained_days"] = MAX_DAILY_USAGE_ATTRIBUTE_DAYS
        attributes["daily_usage_hours_available_days"] = len(chart_records)
        return attributes

    def _update_from_data(self, data: MyAirCoordinatorData) -> None:
        """Set the latest sleep record usage as decimal hours.

        Args:
            data (MyAirCoordinatorData): Snapshot for the Configured CPAP Device.
        """
        latest_record = data.latest_sleep_record
        if latest_record is None:
            _LOGGER.error("Sleep record data missing from coordinator data")
            value: float | None = None
            self._available = False
        else:
            value = (
                None
                if latest_record.total_usage_minutes is None
                else usage_minutes_to_hours(latest_record.total_usage_minutes)
            )
            self._available = value is not None
            if value is None:
                _LOGGER.error("Unable to parse Usage Hours. totalUsage")

        self._attr_native_value = value


class MyAirUsageHoursAverageSensor(MyAirBaseSensor):
    """Expose a rolling average of recent usage hours."""

    def __init__(
        self,
        coordinator: MyAirDataUpdateCoordinator,
        days: int,
    ) -> None:
        """Initialize a rolling usage-hours average entity.

        Args:
            coordinator (MyAirDataUpdateCoordinator): Data coordinator that supplies
                sleep records.
            days (int): Number of nightly records included in the average.
        """
        desc = SensorEntityDescription(
            key=f"usageHoursAverage{days}",
            device_class=SensorDeviceClass.DURATION,
            native_unit_of_measurement="h",
            state_class=SensorStateClass.MEASUREMENT,
        )

        super().__init__(f"CPAP Usage Hours {days} Day Average", desc, coordinator)
        self._days = days

    def _update_from_data(self, data: MyAirCoordinatorData) -> None:
        """Set the average usage hours over the configured trailing window.

        Args:
            data (MyAirCoordinatorData): Snapshot for the Configured CPAP Device.
        """
        normalized_records = normalize_sleep_history([record.raw for record in data.sleep_records])
        usage_hours = [
            usage_minutes_to_hours(record["totalUsage"])
            for record in normalized_records
            if record.get("totalUsage") is not None
        ]
        if not usage_hours:
            self._attr_native_value = None
            self._available = False
            return

        trailing_usage = usage_hours[-self._days :]
        self._attr_native_value = round(sum(trailing_usage) / len(trailing_usage), 2)
        self._available = True


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
            coordinator (MyAirDataUpdateCoordinator): Data coordinator that supplies
                sleep records.
        """
        desc = SensorEntityDescription(
            key="mostRecentSleepDate", device_class=SensorDeviceClass.DATE
        )

        super().__init__("Most Recent Sleep Date", desc, coordinator)

    def _update_from_data(self, data: MyAirCoordinatorData) -> None:
        """Set the model-derived latest date with non-zero CPAP usage.

        Args:
            data (MyAirCoordinatorData): Snapshot for the Configured CPAP Device.
        """
        value: date | None = data.most_recent_sleep_date
        self._attr_native_value = value
        self._available = value is not None
        if value is None:
            _LOGGER.error("Sleep record data missing from coordinator data")
