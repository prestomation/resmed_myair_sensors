"""Sensor entities for resmed_myair."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import date, datetime, time
import logging
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

from .const import DEVICE_SENSOR_DESCRIPTIONS, DOMAIN, SLEEP_RECORD_SENSOR_DESCRIPTIONS, VERSION
from .coordinator import MyAirDataUpdateCoordinator
from .helpers import redact_dict

_LOGGER: logging.Logger = logging.getLogger(__name__)


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
            MyAirUsageHoursSensor(coordinator=coordinator),
            MyAirUsageHoursAverageSensor(coordinator=coordinator, days=7),
            MyAirUsageHoursAverageSensor(coordinator=coordinator, days=30),
            MyAirMostRecentSleepDate(coordinator=coordinator),
        ]
    )

    async_add_entities(sensors, False)


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
        self._available: bool = False
        self._attr_device_info: DeviceInfo = DeviceInfo(
            identifiers={(DOMAIN, serial_number)},
            manufacturer=device_data.get("fgDeviceManufacturerName"),
            model=device_data.get("deviceType"),
            name=device_data.get("localizedName"),
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

    def _write_native_value(self, value: Any, available: bool) -> None:
        """Update the entity from parsed coordinator data."""
        self._attr_native_value = value
        self._available = available
        self.async_write_ha_state()

    def _sleep_records(self) -> list[Mapping[str, Any]] | None:
        """Return sleep records from the coordinator."""
        sleep_records = self.coordinator.data.get("sleep_records")
        if not sleep_records:
            _LOGGER.error("Sleep record data missing from coordinator data")
            return None
        return sleep_records

    def _device_data(self) -> Mapping[str, Any] | None:
        """Return device data from the coordinator."""
        device_data = self.coordinator.data.get("device")
        if not device_data:
            _LOGGER.error("Device data missing from coordinator data")
            return None
        return device_data

    def _latest_sleep_record(self) -> Mapping[str, Any] | None:
        """Return the most recent sleep record."""
        sleep_records = self._sleep_records()
        if not sleep_records:
            return None
        return sleep_records[-1]

    @property
    def _historical_statistic(self) -> HistoricalStatisticDescription | None:
        """Return the historical statistic description for this entity."""
        return None

    @property
    def _historical_statistic_id(self) -> str | None:
        """Return the recorder statistic id for this entity's imported history."""
        statistic_desc = self._historical_statistic
        if statistic_desc is None:
            return None

        serial_number = self.coordinator.data.get("device", {}).get("serialNumber", "unknown")
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

        sleep_records = self.coordinator.data.get("sleep_records", [])
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
            start_date = dt_util.parse_date(record.get("startDate"))
            if start_date is None:
                continue
            if last_imported_date is not None and start_date <= last_imported_date:
                continue

            raw_value = statistic_desc.value_fn(record)
            if raw_value is None:
                continue

            stat_value = _round_stat_value(raw_value, statistic_desc.round_digits)
            start = datetime.combine(start_date, time.min, tzinfo=dt_util.DEFAULT_TIME_ZONE)
            if statistic_desc.import_mode == "sum":
                running_sum = _round_stat_value(running_sum + stat_value, statistic_desc.round_digits)
                statistics.append(
                    StatisticData(
                        start=start,
                        sum=running_sum,
                    )
                )
            else:
                statistics.append(
                    StatisticData(
                        start=start,
                        state=stat_value,
                    )
                )

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
        if self.hass is None:
            return
        if self._historical_statistic is None:
            return
        self.hass.async_create_task(self._async_import_historical_statistics())


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
        self._historical_statistic_desc = _build_sleep_record_statistic(friendly_name, sensor_desc)

    @property
    def _historical_statistic(self) -> HistoricalStatisticDescription | None:
        """Return the historical statistic description for this entity."""
        return self._historical_statistic_desc

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        value: Any | None = None
        latest_record = self._latest_sleep_record()
        if latest_record is None:
            self._write_native_value(None, False)
            return

        try:
            value = latest_record[self.sensor_key]
        except KeyError as err:
            _LOGGER.error("Unable to parse Sleep Record. %s: %s", type(err).__name__, err)
            self._write_native_value(None, False)
            return

        if (
            isinstance(value, str)
            and self.entity_description.device_class == SensorDeviceClass.DATE
        ):
            value = dt_util.parse_date(value)

        self._write_native_value(value, True)
        self._schedule_historical_statistics_import()


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
        device_data = self._device_data()
        if device_data is None:
            self._write_native_value(None, False)
            return

        try:
            value = device_data[self.sensor_key]
        except KeyError as err:
            _LOGGER.error("Unable to parse Device. %s: %s", type(err).__name__, err)
            self._write_native_value(None, False)
            return

        if (
            isinstance(value, str)
            and self.entity_description.device_class == SensorDeviceClass.TIMESTAMP
        ):
            value = dt_util.parse_datetime(value)

        self._write_native_value(value, True)


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
        latest_record = self._latest_sleep_record()
        if latest_record is None:
            self._write_native_value(None, False)
            return

        try:
            usage_minutes = max(int(latest_record["totalUsage"]), 0)
        except KeyError as err:
            _LOGGER.error("Unable to parse Usage Time. %s: %s", type(err).__name__, err)
            self._write_native_value(None, False)
            return

        self._write_native_value(f"{usage_minutes // 60}:{usage_minutes % 60:02}", True)


class MyAirUsageHoursSensor(MyAirBaseSensor):
    """myAir usage hours sensor with imported nightly statistics."""

    def __init__(
        self,
        coordinator: MyAirDataUpdateCoordinator,
    ) -> None:
        """Initialize myAir usage hours sensor."""
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
        """Return extra state attributes."""
        attributes = dict(super().extra_state_attributes or {})
        attributes["daily_usage_hours"] = _build_daily_usage_hours(
            self.coordinator.chart_sleep_records
        )
        return attributes

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        latest_record = self._latest_sleep_record()
        if latest_record is None:
            self._write_native_value(None, False)
            return

        try:
            value = _usage_minutes_to_hours(latest_record["totalUsage"])
        except KeyError as err:
            _LOGGER.error("Unable to parse Usage Hours. %s: %s", type(err).__name__, err)
            self._write_native_value(None, False)
            return

        self._write_native_value(value, True)
        self._schedule_historical_statistics_import()


class MyAirUsageHoursAverageSensor(MyAirBaseSensor):
    """myAir rolling average usage hours sensor."""

    def __init__(
        self,
        coordinator: MyAirDataUpdateCoordinator,
        days: int,
    ) -> None:
        """Initialize myAir rolling average usage hours sensor."""
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
        """Handle updated data from the coordinator."""
        sleep_records = self._sleep_records()
        if sleep_records is None:
            self._write_native_value(None, False)
            return

        usage_hours = [
            _usage_minutes_to_hours(record["totalUsage"])
            for record in sleep_records
            if record.get("totalUsage") is not None
            and dt_util.parse_date(record.get("startDate")) is not None
        ]
        if not usage_hours:
            self._write_native_value(None, False)
            return

        trailing_usage = usage_hours[-self._days :]
        self._write_native_value(round(sum(trailing_usage) / len(trailing_usage), 2), True)


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
        sleep_records = self._sleep_records()
        if sleep_records is None:
            self._write_native_value(None, False)
            return

        try:
            sleep_days_with_data = [
                record for record in sleep_records if record["totalUsage"] > 0
            ]
        except KeyError as err:
            _LOGGER.error("Unable to parse Most Recent Sleep Date. %s: %s", type(err).__name__, err)
            self._write_native_value(None, False)
            return

        if not sleep_days_with_data:
            self._write_native_value(None, False)
            return

        self._write_native_value(dt_util.parse_date(sleep_days_with_data[-1]["startDate"]), True)


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
