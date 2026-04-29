"""Coordinator for ResMed myAir data."""

from collections.abc import Mapping
from datetime import date, datetime, timedelta
import logging
from typing import Any

from homeassistant.components.recorder import get_instance
from homeassistant.components.recorder.statistics import statistics_during_period
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import dt as dt_util, slugify

from .client.myair_client import AuthenticationError, MyAirClient, ParsingError
from .const import DEFAULT_UPDATE_RATE_MIN, DOMAIN
from .helpers import redact_dict

_LOGGER: logging.Logger = logging.getLogger(__name__)
_HISTORY_STORE_VERSION = 1
_MAX_HISTORY_DAYS = 400


class MyAirDataUpdateCoordinator(DataUpdateCoordinator):
    """DataUpdateCoordinator for myAir."""

    myair_client: MyAirClient
    device: Mapping[str, Any]
    sleep_records: list[Mapping[str, Any]]

    def __init__(
        self,
        hass: HomeAssistant,
        config_entry: ConfigEntry,
        myair_client: MyAirClient,
    ) -> None:
        """Initialize DataUpdateCoordinator for ResMed myAir."""
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
        """Load persisted sleep history."""
        stored_history = await self._sleep_history_store.async_load()
        if stored_history is None:
            self._sleep_history = []
            return
        self._sleep_history = _normalize_sleep_history(stored_history)

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from the myAir client and store it in the coordinator."""
        _LOGGER.info("Updating from myAir")

        try:
            await self.myair_client.connect()
        except AuthenticationError as e:
            _LOGGER.error("Authentication Error while updating. %s: %s", type(e).__name__, e)
            raise ConfigEntryAuthFailed(
                f"Authentication Error while updating. {type(e).__name__}: {e}"
            ) from e

        data: dict[str, Any] = {}
        try:
            data["device"] = await self.myair_client.get_user_device_data()
        except ParsingError:
            data["device"] = {}
        if serial_number := data["device"].get("serialNumber"):
            self._serial_number = str(serial_number)
        _LOGGER.debug("[async_update_data] device: %s", redact_dict(data["device"]))

        try:
            data["sleep_records"] = await self.myair_client.get_sleep_records()
        except ParsingError:
            data["sleep_records"] = []
        _LOGGER.debug("[async_update_data] sleep_records: %s", redact_dict(data["sleep_records"]))

        self._usage_hours_history = await self._async_get_usage_history_from_recorder(
            data["device"],
        )
        self._sleep_history = _merge_sleep_history(self._sleep_history, self._usage_hours_history)
        self._sleep_history = _merge_sleep_history(self._sleep_history, data["sleep_records"])
        data["sleep_records_history"] = self._sleep_history
        await self._sleep_history_store.async_save(self._sleep_history)

        return data

    @property
    def chart_sleep_records(self) -> list[dict[str, Any]]:
        """Return the merged history used by frontend charts."""
        history = self.data.get("sleep_records_history")
        if not history:
            history = self.data.get("sleep_records", [])
        return _merge_sleep_history(self._usage_hours_history, history)

    async def _async_get_usage_history_from_recorder(
        self,
        device: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        """Load usage history from recorder statistics."""
        serial_number = device.get("serialNumber") or self._serial_number
        if not serial_number:
            return []

        statistic_id = _usage_hours_sum_statistic_id(serial_number)
        start_time = dt_util.now() - timedelta(days=_MAX_HISTORY_DAYS)
        recorder_stats = await get_instance(self.hass).async_add_executor_job(
            statistics_during_period,
            self.hass,
            start_time,
            None,
            {statistic_id},
            "day",
            None,
            {"change"},
        )
        rows = recorder_stats.get(statistic_id, [])
        if not rows:
            return []

        return [
            {
                "startDate": _statistics_row_date(row["start"]).isoformat(),
                "totalUsage": max(int(round(float(row["change"]) * 60)), 0),
            }
            for row in rows
            if row.get("start") is not None and row.get("change") is not None
        ]


def _merge_sleep_history(
    existing_history: list[dict[str, Any]],
    latest_records: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Merge new cloud records into persisted sleep history."""
    merged_by_date: dict[str, dict[str, Any]] = {
        record["startDate"]: dict(record)
        for record in _normalize_sleep_history(existing_history)
        if record.get("startDate")
    }
    for record in latest_records:
        start_date = record.get("startDate")
        if not start_date:
            continue
        merged_by_date[start_date] = dict(record)

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
    """Build the recorder statistic id for usage hours."""
    return f"{DOMAIN}:{slugify(f'{serial_number}_usagehours_sum')}"


def _statistics_row_date(value: Any) -> date:
    """Convert recorder statistics row start values to a local date."""
    if isinstance(value, datetime):
        return dt_util.as_local(value).date()
    if isinstance(value, int | float):
        return dt_util.as_local(datetime.fromtimestamp(value, tz=dt_util.UTC)).date()
    raise TypeError(f"Unsupported statistics row start value: {value!r}")
