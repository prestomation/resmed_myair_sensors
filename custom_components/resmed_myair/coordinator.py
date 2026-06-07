"""Device coordinator for resmed_myair."""

from collections.abc import Mapping
from datetime import date, datetime, timedelta
import logging
from typing import Any

from homeassistant.components.recorder import get_instance
from homeassistant.components.recorder.statistics import statistics_during_period
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.recorder import DATA_INSTANCE
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import dt as dt_util, slugify

from .client.myair_client import AuthenticationError, MyAirClient, ParsingError
from .const import DEFAULT_UPDATE_RATE_MIN, DOMAIN
from .models import MyAirCoordinatorData, MyAirDevice, MyAirSleepRecord

_LOGGER: logging.Logger = logging.getLogger(__name__)
_HISTORY_STORE_VERSION = 1
_MAX_HISTORY_DAYS = 400
_RECORDER_STATE_FIELDS = {
    "ahi": "ahi",
    "maskPairCount": "maskPairCount",
    "leakPercentile": "leakPercentile",
    "sleepScore": "sleepScore",
}


class MyAirDataUpdateCoordinator(DataUpdateCoordinator[MyAirCoordinatorData]):
    """Fetch and cache the typed myAir payload consumed by sensor entities."""

    myair_client: MyAirClient

    def __init__(
        self,
        hass: HomeAssistant,
        config_entry: ConfigEntry,
        myair_client: MyAirClient,
    ) -> None:
        """Configure periodic myAir polling for a config entry.

        Args:
            hass: Home Assistant instance running the coordinator.
            config_entry: myAir config entry associated with this coordinator.
            myair_client: Client used to authenticate and fetch myAir data.
        """
        _LOGGER.info("Initializing DataUpdateCoordinator for ResMed myAir")
        self.myair_client = myair_client
        self._serial_number: str | None = None
        self._sleep_history_store: Store[list[dict[str, Any]]] = Store(
            hass,
            _HISTORY_STORE_VERSION,
            f"{config_entry.domain}_{config_entry.entry_id}_sleep_history",
        )
        self._sleep_history: list[dict[str, Any]] = []
        self._usage_hours_history: list[dict[str, Any]] = []
        super().__init__(
            hass=hass,
            config_entry=config_entry,
            logger=_LOGGER,
            name="myAir update",
            update_interval=timedelta(minutes=DEFAULT_UPDATE_RATE_MIN),
        )

    async def async_initialize(self) -> None:
        """Load persisted sleep history before the first cloud refresh."""
        stored_history = await self._sleep_history_store.async_load()
        if stored_history is None:
            self._sleep_history = []
            return
        self._sleep_history = _normalize_sleep_history(stored_history)

    async def _async_update_data(self) -> MyAirCoordinatorData:
        """Refresh auth, device metadata, and recent sleep records.

        Returns:
            Typed coordinator payload containing any data available from myAir.

        Raises:
            ConfigEntryAuthFailed: When myAir authentication must be repaired by reauth.
        """
        _LOGGER.info("Updating from myAir")

        try:
            await self.myair_client.connect()
        except AuthenticationError as e:
            _LOGGER.error("Authentication Error while updating. %s: %s", type(e).__name__, e)
            raise ConfigEntryAuthFailed(
                f"Authentication Error while updating. {type(e).__name__}: {e}"
            ) from e

        device: MyAirDevice | None = None
        sleep_records: tuple[MyAirSleepRecord, ...] = ()

        try:
            device = await self.myair_client.get_user_device_data()
        except ParsingError as err:
            _LOGGER.debug(
                "Device data unavailable in myAir update. %s: %s",
                type(err).__name__,
                err,
            )
        if device and device.serial_number:
            self._serial_number = device.serial_number

        try:
            sleep_records = tuple(await self.myair_client.get_sleep_records())
        except ParsingError as err:
            _LOGGER.debug(
                "Sleep record data unavailable in myAir update. %s: %s",
                type(err).__name__,
                err,
            )

        self._usage_hours_history = await self._async_get_sleep_history_from_recorder(device)
        self._sleep_history = _merge_sleep_history(self._sleep_history, self._usage_hours_history)
        self._sleep_history = _merge_sleep_history(
            self._sleep_history, [record.raw for record in sleep_records]
        )
        await self._sleep_history_store.async_save(self._sleep_history)

        return MyAirCoordinatorData(device=device, sleep_records=sleep_records)

    @property
    def chart_sleep_records(self) -> list[dict[str, Any]]:
        """Return merged historical records for frontend chart attributes."""
        live_records = [record.raw for record in _coordinator_data_sleep_records(self.data)]
        history = self._sleep_history or live_records
        return _merge_sleep_history(self._usage_hours_history, history)

    async def _async_get_sleep_history_from_recorder(
        self,
        device: MyAirDevice | None,
    ) -> list[dict[str, Any]]:
        """Load sleep history recoverable from recorder statistics."""
        serial_number = device.serial_number if device else self._serial_number
        if not serial_number:
            return []
        if DATA_INSTANCE not in self.hass.data:
            return []

        statistic_id = _usage_hours_sum_statistic_id(serial_number)
        state_statistic_ids = {
            _recorder_state_statistic_id(serial_number, sensor_key)
            for sensor_key in _RECORDER_STATE_FIELDS
        }
        start_time = dt_util.now() - timedelta(days=_MAX_HISTORY_DAYS)
        recorder_stats = await get_instance(self.hass).async_add_executor_job(
            statistics_during_period,
            self.hass,
            start_time,
            None,
            {statistic_id, *state_statistic_ids},
            "day",
            None,
            {"change", "state"},
        )
        records_by_date: dict[str, dict[str, Any]] = {}

        for row in recorder_stats.get(statistic_id, []):
            if row.get("start") is None or row.get("change") is None:
                continue
            start_date = _statistics_row_date(row["start"]).isoformat()
            records_by_date.setdefault(start_date, {"startDate": start_date})[
                "totalUsage"
            ] = max(round(float(row["change"]) * 60), 0)

        for sensor_key, record_key in _RECORDER_STATE_FIELDS.items():
            state_statistic_id = _recorder_state_statistic_id(serial_number, sensor_key)
            for row in recorder_stats.get(state_statistic_id, []):
                if row.get("start") is None or row.get("state") is None:
                    continue
                start_date = _statistics_row_date(row["start"]).isoformat()
                records_by_date.setdefault(start_date, {"startDate": start_date})[
                    record_key
                ] = row["state"]

        return [records_by_date[start_date] for start_date in sorted(records_by_date)]


def _coordinator_data_sleep_records(data: Any) -> tuple[MyAirSleepRecord, ...]:
    """Return sleep records from a typed coordinator payload if available."""
    if isinstance(data, MyAirCoordinatorData):
        return data.sleep_records
    return ()


def _merge_sleep_history(
    existing_history: list[dict[str, Any]],
    latest_records: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Merge new cloud or recorder records into persisted sleep history."""
    merged_by_date: dict[str, dict[str, Any]] = {
        record["startDate"]: dict(record)
        for record in _normalize_sleep_history(existing_history)
        if record.get("startDate")
    }
    for record in latest_records:
        start_date = record.get("startDate")
        if not start_date:
            continue
        merged_by_date[start_date] = {**merged_by_date.get(start_date, {}), **dict(record)}

    sorted_dates = sorted(merged_by_date)
    if len(sorted_dates) > _MAX_HISTORY_DAYS:
        sorted_dates = sorted_dates[-_MAX_HISTORY_DAYS:]
    return [merged_by_date[start_date] for start_date in sorted_dates]


def _normalize_sleep_history(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop invalid or future-dated history entries and sort by date."""
    today = dt_util.now().date()
    normalized: list[dict[str, Any]] = []
    for record in history:
        start_date = dt_util.parse_date(record.get("startDate"))
        if start_date is None or start_date > today:
            continue
        normalized.append(dict(record))
    normalized.sort(key=lambda record: record["startDate"])
    return normalized


def _usage_hours_sum_statistic_id(serial_number: str) -> str:
    """Build the recorder statistic ID for usage hours."""
    return f"{DOMAIN}:{slugify(f'{serial_number}_usagehours_sum')}"


def _recorder_state_statistic_id(serial_number: str, sensor_key: str) -> str:
    """Build the recorder statistic ID for a nightly state metric."""
    return f"{DOMAIN}:{slugify(f'{serial_number}_{sensor_key}')}"


def _statistics_row_date(value: Any) -> date:
    """Convert recorder statistics row start values to a local date."""
    if isinstance(value, datetime):
        return dt_util.as_local(value).date()
    if isinstance(value, int | float):
        return dt_util.as_local(datetime.fromtimestamp(value, tz=dt_util.UTC)).date()
    raise TypeError(f"Unsupported statistics row start value: {value!r}")
