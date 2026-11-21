"""Recorder platform support for resmed_myair statistics."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from typing import Any, cast

from homeassistant.components.recorder import get_instance
from homeassistant.components.recorder.models import (
    StatisticData,
    StatisticMeanType,
    StatisticMetaData,
)
from homeassistant.components.recorder.statistics import (
    async_add_external_statistics,
    async_update_statistics_metadata,
    get_last_statistics,
    statistics_during_period,
)
from homeassistant.components.sensor import SensorEntityDescription
from homeassistant.const import PERCENTAGE, UnitOfVolumeFlowRate
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.recorder import DATA_INSTANCE
from homeassistant.util import dt as dt_util, slugify
from homeassistant.util.unit_conversion import VolumeFlowRateConverter

from .const import DOMAIN, MAX_DAILY_USAGE_ATTRIBUTE_DAYS, MAX_HISTORY_DAYS, RECORDER_STATE_FIELDS
from .models import MyAirSleepRecord

_MASK_LEAK_UNIQUE_ID_SUFFIX = "_leakPercentile"


@dataclass(frozen=True)
class HistoricalStatisticDescription:
    """Description of an imported nightly statistic."""

    name: str
    unit_of_measurement: str | None
    value_fn: Callable[[Mapping[str, Any]], float | int | None]
    unit_class: str | None = None
    import_mode: str = "state"
    round_digits: int | None = None


def normalize_sleep_history(history: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Drop invalid or future-dated history entries and sort by date.

    Args:
        history (Sequence[Mapping[str, Any]]): Raw sleep history mappings from
            storage, recorder, or the API.

    Returns:
        list[dict[str, Any]]: Chronologically sorted sleep history records safe for
            charting and import.
    """
    today = dt_util.now().date()
    normalized: list[dict[str, Any]] = []
    for record in history:
        raw_start_date = record.get("startDate")
        if not isinstance(raw_start_date, str):
            continue
        start_date = dt_util.parse_date(raw_start_date)
        if start_date is None or start_date > today:
            continue
        normalized.append(dict(record))
    normalized.sort(key=lambda record: record["startDate"])
    return normalized


def historical_statistic_id(
    serial_number: str,
    sensor_key: str,
    import_mode: str = "state",
) -> str:
    """Build the recorder statistic ID for a sensor historical import.

    Args:
        serial_number (str): Flow generator serial number used in entity unique IDs.
        sensor_key (str): Sensor key or synthetic sensor key.
        import_mode (str): Recorder import mode; non-state imports get a suffix.

    Returns:
        str: Fully-qualified recorder statistic ID.
    """
    suffix = f"{sensor_key}_{import_mode}" if import_mode != "state" else sensor_key
    return f"{DOMAIN}:{slugify(f'{serial_number}_{suffix}')}"


def usage_minutes_to_hours(usage_minutes: Any) -> float:
    """Convert usage minutes to rounded hours.

    Args:
        usage_minutes (Any): Raw usage minutes from myAir or recovered recorder data.

    Returns:
        float: Non-negative decimal hours rounded for recorder statistics.
    """
    return round(max(float(usage_minutes), 0.0) / 60.0, 2)


def build_sleep_record_statistic(
    friendly_name: str,
    sensor_desc: SensorEntityDescription,
) -> HistoricalStatisticDescription | None:
    """Build a recorder statistic description for nightly sleep metrics.

    Args:
        friendly_name (str): Statistic display name.
        sensor_desc (SensorEntityDescription): Sensor description declaring the raw
            myAir field and unit.

    Returns:
        HistoricalStatisticDescription | None: Historical statistic description for
            supported fields, otherwise ``None``.
    """
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
            unit_class=VolumeFlowRateConverter.UNIT_CLASS,
            round_digits=1,
        )
    if sensor_desc.key == "sleepScore":
        return HistoricalStatisticDescription(
            name=friendly_name,
            unit_of_measurement=sensor_desc.native_unit_of_measurement,
            value_fn=lambda record: _coerce_stat_number(record.get("sleepScore")),
        )
    return None


def build_daily_usage_hours(sleep_records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Build daily usage history for frontend charts.

    Args:
        sleep_records (Sequence[Mapping[str, Any]]): Raw sleep records containing
            usage and optional detail fields.

    Returns:
        list[dict[str, Any]]: Chronological daily chart rows.
    """
    history: list[dict[str, Any]] = []
    for record in normalize_sleep_history(sleep_records)[-MAX_DAILY_USAGE_ATTRIBUTE_DAYS:]:
        start_date = dt_util.parse_date(record["startDate"])
        usage_minutes = record.get("totalUsage")
        if start_date is None or usage_minutes is None:
            continue
        history.append(
            {
                "date": start_date.isoformat(),
                "hours": usage_minutes_to_hours(usage_minutes),
                "minutes": max(int(usage_minutes), 0),
                "ahi": _coerce_stat_number(record.get("ahi")),
                "mask_on_off": _coerce_stat_number(record.get("maskPairCount")),
                "mask_leak_percent": _coerce_stat_number(record.get("leakPercentile")),
                "myair_score": _coerce_stat_number(record.get("sleepScore")),
            }
        )
    return history


async def async_import_historical_statistics(
    hass: HomeAssistant,
    sleep_records: Sequence[MyAirSleepRecord],
    statistic_id: str,
    statistic_desc: HistoricalStatisticDescription,
) -> None:
    """Import nightly historical data into recorder statistics.

    Args:
        hass (HomeAssistant): Home Assistant instance with recorder access.
        sleep_records (Sequence[MyAirSleepRecord]): Typed myAir sleep records from
            the latest API response.
        statistic_id (str): Recorder statistic ID to import into.
        statistic_desc (HistoricalStatisticDescription): Statistic value extraction
            and metadata description.
    """
    if not sleep_records:
        return

    last_stat = await get_instance(hass).async_add_executor_job(
        get_last_statistics,
        hass,
        1,
        statistic_id,
        True,
        {"sum"} if statistic_desc.import_mode == "sum" else set(),
    )

    last_imported_date: date | None = None
    last_sum = 0.0
    if last_stat and statistic_id in last_stat and last_stat[statistic_id]:
        last_row = last_stat[statistic_id][0]
        start_ts = last_row.get("start")
        if start_ts is not None:
            last_imported_date = _statistics_row_date(start_ts)
        last_sum_raw = last_row.get("sum")
        if statistic_desc.import_mode == "sum" and last_sum_raw is not None:
            last_sum = float(last_sum_raw)

    statistics: list[StatisticData] = []
    running_sum = last_sum
    for record in normalize_sleep_history([record.raw for record in sleep_records]):
        start_date = dt_util.parse_date(record["startDate"])
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
            statistics.append(StatisticData(start=start, sum=running_sum))
        else:
            statistics.append(StatisticData(start=start, state=stat_value))

    metadata = cast(
        "StatisticMetaData",
        {
            "has_mean": False,
            "has_sum": statistic_desc.import_mode == "sum",
            "mean_type": StatisticMeanType.NONE,
            "name": statistic_desc.name,
            "source": DOMAIN,
            "statistic_id": statistic_id,
            "unit_class": statistic_desc.unit_class,
            "unit_of_measurement": statistic_desc.unit_of_measurement,
        },
    )

    if statistic_desc.unit_of_measurement is not None or statistic_desc.unit_class is not None:
        async_update_statistics_metadata(
            hass,
            statistic_id,
            new_unit_class=statistic_desc.unit_class,
            new_unit_of_measurement=statistic_desc.unit_of_measurement,
        )

    if not statistics:
        return

    async_add_external_statistics(hass, metadata, statistics)


async def async_get_sleep_history_from_recorder(
    hass: HomeAssistant,
    serial_number: str | None,
) -> list[dict[str, Any]]:
    """Load sleep history recoverable from recorder statistics.

    Args:
        hass (HomeAssistant): Home Assistant instance with recorder access.
        serial_number (str | None): Flow generator serial number used in statistic
            IDs.

    Returns:
        list[dict[str, Any]]: Chronological sleep-history records reconstructed from
            recorder statistics.
    """
    if not serial_number:
        return []
    if DATA_INSTANCE not in hass.data:
        return []

    statistic_id = _usage_hours_sum_statistic_id(serial_number)
    state_statistic_ids = {
        _recorder_state_statistic_id(serial_number, sensor_key)
        for sensor_key in RECORDER_STATE_FIELDS
    }
    start_time = dt_util.now() - timedelta(days=MAX_HISTORY_DAYS)
    recorder_stats = await get_instance(hass).async_add_executor_job(
        statistics_during_period,
        hass,
        start_time,
        None,
        {statistic_id, *state_statistic_ids},
        "day",
        None,
        {"change", "state"},
    )
    records_by_date: dict[str, dict[str, Any]] = {}

    for row in recorder_stats.get(statistic_id, []):
        change = row.get("change")
        if row.get("start") is None or change is None:
            continue
        start_date = _statistics_row_date(row["start"]).isoformat()
        records_by_date.setdefault(start_date, {"startDate": start_date})["totalUsage"] = max(
            round(float(change) * 60), 0
        )

    for sensor_key, record_key in RECORDER_STATE_FIELDS.items():
        state_statistic_id = _recorder_state_statistic_id(serial_number, sensor_key)
        for row in recorder_stats.get(state_statistic_id, []):
            state = row.get("state")
            if row.get("start") is None or state is None:
                continue
            start_date = _statistics_row_date(row["start"]).isoformat()
            records_by_date.setdefault(start_date, {"startDate": start_date})[record_key] = state

    return normalize_sleep_history(list(records_by_date.values()))


def _mask_leak_entity_ids(hass: HomeAssistant) -> list[str]:
    """Return registered myAir mask leak entity IDs.

    Args:
        hass (HomeAssistant): Home Assistant instance with the entity registry.

    Returns:
        list[str]: Entity IDs for the mask leak sensor whose previous unit
            metadata may need migration.
    """
    entity_registry = er.async_get(hass)

    return [
        entry.entity_id
        for entry in entity_registry.entities.values()
        if entry.platform == DOMAIN
        and entry.unique_id.startswith(f"{DOMAIN}_")
        and entry.unique_id.endswith(_MASK_LEAK_UNIQUE_ID_SUFFIX)
    ]


@callback
def async_migrate_mask_leak_statistics_metadata(hass: HomeAssistant) -> None:
    """Relabel legacy mask leak statistics metadata to the corrected unit.

    Args:
        hass (HomeAssistant): Home Assistant instance with recorder and entity
            registry state.
    """
    if DATA_INSTANCE not in hass.data:
        return

    recorder_instance = get_instance(hass)

    for entity_id in _mask_leak_entity_ids(hass):
        recorder_instance.async_update_statistics_metadata(
            entity_id,
            new_unit_class=VolumeFlowRateConverter.UNIT_CLASS,
            new_unit_of_measurement=UnitOfVolumeFlowRate.LITERS_PER_MINUTE,
        )


@callback
def async_custom_equivalent_units(hass: HomeAssistant) -> dict[str, dict[str | None, str]]:
    """Return custom equivalent units for long-term statistics migrations.

    Args:
        hass (HomeAssistant): Home Assistant instance with the entity registry.

    Returns:
        dict[str, dict[str | None, str]]: Entity-specific mappings from the old
            mask-leak unit to the supported volume flow rate unit. The value
            conversion is 1:1.
    """
    return {
        entity_id: {PERCENTAGE: UnitOfVolumeFlowRate.LITERS_PER_MINUTE}
        for entity_id in _mask_leak_entity_ids(hass)
    }


def _round_stat_value(value: float, digits: int | None) -> float:
    """Normalize a value for recorder statistics.

    Args:
        value (float): Raw numeric statistic value.
        digits (int | None): Optional decimal places to round to.

    Returns:
        float: Value suitable for recorder statistics.
    """
    rounded = round(float(value), digits) if digits is not None else float(value)
    return float(rounded)


def _coerce_stat_number(value: Any) -> float | int | None:
    """Convert a record value to a recorder-compatible number.

    Args:
        value (Any): Raw myAir value.

    Returns:
        float | int | None: Numeric value accepted by recorder statistics, otherwise
            ``None``.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int | float):
        return value
    try:
        return float(value)
    except TypeError, ValueError:
        return None


def _usage_hours_sum_statistic_id(serial_number: str) -> str:
    """Build the recorder statistic ID for usage hours.

    Args:
        serial_number (str): Flow generator serial number.

    Returns:
        str: Usage-hours cumulative statistic ID.
    """
    return historical_statistic_id(serial_number, "usageHours", "sum")


def _recorder_state_statistic_id(serial_number: str, sensor_key: str) -> str:
    """Build the recorder statistic ID for a nightly state metric.

    Args:
        serial_number (str): Flow generator serial number.
        sensor_key (str): Sensor key used in the statistic ID.

    Returns:
        str: State statistic ID for the requested field.
    """
    return historical_statistic_id(serial_number, sensor_key)


def _statistics_row_date(value: Any) -> date:
    """Convert recorder statistics row start values to a local date.

    Args:
        value (Any): Recorder row ``start`` value as a datetime or timestamp.

    Returns:
        date: Local date represented by the recorder row.

    Raises:
        TypeError: If the row start value has an unexpected type.
    """
    if isinstance(value, datetime):
        return dt_util.as_local(value).date()
    if isinstance(value, int | float):
        return dt_util.as_local(datetime.fromtimestamp(value, tz=dt_util.UTC)).date()
    raise TypeError(f"Unsupported statistics row start value: {value!r}")
