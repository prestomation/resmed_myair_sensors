"""Home Assistant sensor entities for ResMed myAir account data."""

from abc import abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import date, datetime, time
import logging
import re
from typing import Any, Final

from homeassistant.components.recorder import get_instance
from homeassistant.components.recorder.models import StatisticData, StatisticMetaData
from homeassistant.components.recorder.statistics import (
    async_add_external_statistics,
    get_last_statistics,
)
from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util, slugify

from .const import (
    CONF_USER_NAME,
    DEVICE_SENSOR_DESCRIPTIONS,
    DOMAIN,
    SLEEP_RECORD_SENSOR_DESCRIPTIONS,
    VERSION,
)
from .coordinator import MyAirDataUpdateCoordinator
from .models import MyAirCoordinatorData, MyAirDevice, MyAirSleepRecord
from .redaction import redact_dict

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


@dataclass(frozen=True)
class HistoricalStatisticDescription:
    """Description of an imported nightly statistic."""

    name: str
    unit_of_measurement: str | None
    value_fn: Callable[[Mapping[str, Any]], float | int | None]
    import_mode: str = "state"
    round_digits: int | None = None


def _round_stat_value(value: float, digits: int | None) -> float:
    """Normalize a value for recorder statistics."""
    rounded = round(float(value), digits) if digits is not None else float(value)
    return float(rounded)


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
            MyAirUsageHoursSensor(coordinator=coordinator),
            MyAirUsageHoursAverageSensor(coordinator=coordinator, days=7),
            MyAirUsageHoursAverageSensor(coordinator=coordinator, days=30),
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

    @property
    def _historical_statistic(self) -> HistoricalStatisticDescription | None:
        """Return the historical statistic description for this entity."""
        return None

    @property
    def _historical_statistic_id(self) -> str | None:
        """Return the recorder statistic ID for this entity's imported history."""
        statistic_desc = self._historical_statistic
        if statistic_desc is None:
            return None

        device = _coordinator_data(self.coordinator).device
        serial_number = device.serial_number if device else "unknown"
        suffix = (
            f"{self.sensor_key}_{statistic_desc.import_mode}"
            if statistic_desc.import_mode != "state"
            else self.sensor_key
        )
        return f"{DOMAIN}:{slugify(f'{serial_number}_{suffix}')}"

    @property
    def extra_state_attributes(self) -> Mapping[str, Any] | None:
        """Return extra state attributes."""
        statistic_id = self._historical_statistic_id
        if statistic_id is None:
            return None
        return {"historical_statistic_id": statistic_id}

    async def _async_import_historical_statistics(self) -> None:
        """Import nightly historical data into recorder statistics."""
        if self.hass is None:
            return

        statistic_desc = self._historical_statistic
        statistic_id = self._historical_statistic_id
        if statistic_desc is None or statistic_id is None:
            return

        sleep_records = _coordinator_data(self.coordinator).sleep_records
        if not sleep_records:
            return

        last_stat = await get_instance(self.hass).async_add_executor_job(
            get_last_statistics,
            self.hass,
            1,
            statistic_id,
            True,
            {"sum"} if statistic_desc.import_mode == "sum" else set(),
        )

        last_imported_date: date | None = None
        last_sum = 0.0
        if last_stat and statistic_id in last_stat and last_stat[statistic_id]:
            last_row = last_stat[statistic_id][0]
            end_ts = last_row.get("end")
            if isinstance(end_ts, datetime):
                last_imported_date = dt_util.as_local(end_ts).date()
            elif end_ts is not None:
                last_imported_date = datetime.fromtimestamp(end_ts, tz=dt_util.UTC).date()
            if statistic_desc.import_mode == "sum" and last_row.get("sum") is not None:
                last_sum = float(last_row["sum"])

        statistics: list[StatisticData] = []
        running_sum = last_sum
        for record in sleep_records:
            if record.start_date is None:
                continue
            if last_imported_date is not None and record.start_date <= last_imported_date:
                continue

            raw_value = statistic_desc.value_fn(record.raw)
            if raw_value is None:
                continue

            stat_value = _round_stat_value(raw_value, statistic_desc.round_digits)
            start = datetime.combine(record.start_date, time.min, tzinfo=dt_util.DEFAULT_TIME_ZONE)
            if statistic_desc.import_mode == "sum":
                running_sum = _round_stat_value(
                    running_sum + stat_value, statistic_desc.round_digits
                )
                statistics.append(StatisticData(start=start, sum=running_sum))
            else:
                statistics.append(StatisticData(start=start, state=stat_value))

        if not statistics:
            return

        metadata: StatisticMetaData = {
            "has_mean": False,
            "has_sum": statistic_desc.import_mode == "sum",
            "name": statistic_desc.name,
            "source": DOMAIN,
            "statistic_id": statistic_id,
            "unit_of_measurement": statistic_desc.unit_of_measurement,
        }

        _LOGGER.debug(
            "Importing %s nightly statistics entries for %s",
            len(statistics),
            statistic_id,
        )
        async_add_external_statistics(self.hass, metadata, statistics)

    def _schedule_historical_statistics_import(self) -> None:
        """Schedule a recorder statistics import if this entity supports it."""
        if self.hass is None or self._historical_statistic is None:
            return
        self.hass.async_create_task(self._async_import_historical_statistics())


class MyAirRawSensor(MyAirBaseSensor):
    """Base entity for sensors that read a raw API field from a model payload."""

    _missing_source_log: str = "Sensor data missing from coordinator data"
    _parse_error_source: str = "Sensor"

    @abstractmethod
    def _sensor_payload(self) -> _SensorPayload | None:
        """Return the model object that contains this sensor's raw API field.

        Returns:
            Device or sleep-record model for raw GraphQL-backed sensors, or ``None``
            when the coordinator did not receive the required payload.
        """

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
        self._schedule_historical_statistics_import()


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
        """Initialize a raw sleep-record sensor."""
        super().__init__(friendly_name, sensor_desc, coordinator)
        self._historical_statistic_desc = _build_sleep_record_statistic(friendly_name, sensor_desc)

    @property
    def _historical_statistic(self) -> HistoricalStatisticDescription | None:
        """Return the historical statistic description for this entity."""
        return self._historical_statistic_desc

    def _sensor_payload(self) -> _SensorPayload | None:
        """Select the latest dated sleep record from the coordinator snapshot.

        Returns:
            Most recent sleep record available for raw sleep metrics, or ``None``
            before the API has returned any sleep history.
        """
        # The API always returns the previous month of data, so the client stores this
        # We assume this is ordered temporally and grab the last one: the latest one
        return _coordinator_data(self.coordinator).latest_sleep_record


class MyAirDeviceSensor(MyAirRawSensor):
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


class MyAirUsageHoursSensor(MyAirBaseSensor):
    """Expose latest usage as hours and import nightly usage statistics."""

    def __init__(
        self,
        coordinator: MyAirDataUpdateCoordinator,
    ) -> None:
        """Initialize the synthesized usage-hours entity."""
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
                else _usage_minutes_to_hours(record["totalUsage"])
            ),
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
        attributes["daily_usage_hours"] = _build_daily_usage_hours(
            self.coordinator.chart_sleep_records
        )
        return attributes

    @callback
    def _handle_coordinator_update(self) -> None:
        """Publish the latest sleep record usage as decimal hours."""
        latest_record = _coordinator_data(self.coordinator).latest_sleep_record
        if latest_record is None:
            _LOGGER.error("Sleep record data missing from coordinator data")
            value: float | None = None
            self._available = False
        else:
            value = (
                None
                if latest_record.total_usage_minutes is None
                else _usage_minutes_to_hours(latest_record.total_usage_minutes)
            )
            self._available = value is not None
            if value is None:
                _LOGGER.error("Unable to parse Usage Hours. totalUsage")

        self._attr_native_value = value
        self.async_write_ha_state()
        self._schedule_historical_statistics_import()


class MyAirUsageHoursAverageSensor(MyAirBaseSensor):
    """Expose a rolling average of recent usage hours."""

    def __init__(
        self,
        coordinator: MyAirDataUpdateCoordinator,
        days: int,
    ) -> None:
        """Initialize a rolling usage-hours average entity."""
        desc = SensorEntityDescription(
            key=f"usageHoursAverage{days}",
            device_class=SensorDeviceClass.DURATION,
            native_unit_of_measurement="h",
            state_class=SensorStateClass.MEASUREMENT,
        )

        super().__init__(f"CPAP Usage Hours {days} Day Average", desc, coordinator)
        self._days = days

    @callback
    def _handle_coordinator_update(self) -> None:
        """Publish the average usage hours over the configured trailing window."""
        usage_hours = [
            _usage_minutes_to_hours(record.total_usage_minutes)
            for record in _coordinator_data(self.coordinator).sleep_records
            if record.total_usage_minutes is not None and record.start_date is not None
        ]
        if not usage_hours:
            self._attr_native_value = None
            self._available = False
            self.async_write_ha_state()
            return

        trailing_usage = usage_hours[-self._days :]
        self._attr_native_value = round(sum(trailing_usage) / len(trailing_usage), 2)
        self._available = True
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


def _build_sleep_record_statistic(
    friendly_name: str,
    sensor_desc: SensorEntityDescription,
) -> HistoricalStatisticDescription | None:
    """Build a recorder statistic description for nightly sleep metrics."""
    if sensor_desc.key == "ahi":
        return HistoricalStatisticDescription(
            name=friendly_name,
            unit_of_measurement=sensor_desc.native_unit_of_measurement,
            value_fn=lambda record: _coerce_stat_number(record.get("ahi")),
            round_digits=2,
        )
    if sensor_desc.key == "maskPairCount":
        return HistoricalStatisticDescription(
            name=friendly_name,
            unit_of_measurement=sensor_desc.native_unit_of_measurement,
            value_fn=lambda record: _coerce_stat_number(record.get("maskPairCount")),
        )
    if sensor_desc.key == "leakPercentile":
        return HistoricalStatisticDescription(
            name=friendly_name,
            unit_of_measurement=sensor_desc.native_unit_of_measurement,
            value_fn=lambda record: _coerce_stat_number(record.get("leakPercentile")),
            round_digits=1,
        )
    if sensor_desc.key == "sleepScore":
        return HistoricalStatisticDescription(
            name=friendly_name,
            unit_of_measurement=sensor_desc.native_unit_of_measurement,
            value_fn=lambda record: _coerce_stat_number(record.get("sleepScore")),
        )
    return None


def _coerce_stat_number(value: Any) -> float | int | None:
    """Convert a record value to a recorder-compatible number."""
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int | float):
        return value
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _build_daily_usage_hours(sleep_records: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Build daily usage history for frontend charts."""
    history: list[dict[str, Any]] = []
    for record in sleep_records:
        start_date = dt_util.parse_date(record.get("startDate"))
        usage_minutes = record.get("totalUsage")
        if start_date is None or usage_minutes is None:
            continue
        history.append(
            {
                "date": start_date.isoformat(),
                "hours": _usage_minutes_to_hours(usage_minutes),
                "minutes": max(int(usage_minutes), 0),
                "ahi": _coerce_stat_number(record.get("ahi")),
                "mask_on_off": _coerce_stat_number(record.get("maskPairCount")),
                "mask_leak_percent": _coerce_stat_number(record.get("leakPercentile")),
                "myair_score": _coerce_stat_number(record.get("sleepScore")),
            }
        )
    return history


def _usage_minutes_to_hours(usage_minutes: Any) -> float:
    """Convert usage minutes to rounded hours."""
    return round(max(float(usage_minutes), 0.0) / 60.0, 2)
