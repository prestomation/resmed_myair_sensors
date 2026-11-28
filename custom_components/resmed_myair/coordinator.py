"""Device coordinator for resmed_myair."""

from asyncio import Lock, timeout
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import date, timedelta
import logging
from typing import Any

from aiohttp import ClientError
from aiohttp.http_exceptions import HttpProcessingError
from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ServiceValidationError
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .client.myair_client import (
    AuthenticationError,
    IncompleteAccountError,
    MyAirClient,
    ParsingError,
    ServiceUnavailableError,
    StaleSessionError,
)
from .const import (
    DEFAULT_UPDATE_RATE_MIN,
    DOMAIN,
    HISTORY_STORE_VERSION,
    MAX_HISTORY_DAYS,
    OUTAGE_RETRY_MARGIN_SEC,
    TIMELINE_SENSOR_KEYS,
)
from .models import MyAirCoordinatorData, MyAirDevice, MyAirNightlyTherapyTimeline, MyAirSleepRecord
from .recorder import async_get_sleep_history_from_recorder, normalize_sleep_history

_LOGGER: logging.Logger = logging.getLogger(__name__)
_TIMELINE_TIMEOUT_SECONDS = 20
TIMELINE_REQUEST_ERRORS = (
    AuthenticationError,
    ClientError,
    HttpProcessingError,
    IncompleteAccountError,
    ParsingError,
    ServiceUnavailableError,
    TimeoutError,
)


class MyAirDataUpdateCoordinator(DataUpdateCoordinator[MyAirCoordinatorData]):
    """Fetch and cache the typed myAir payload consumed by sensor entities."""

    config_entry: ConfigEntry
    myair_client: MyAirClient

    def __init__(
        self,
        hass: HomeAssistant,
        config_entry: ConfigEntry,
        myair_client: MyAirClient,
    ) -> None:
        """Configure periodic myAir polling for a config entry.

        Args:
            hass (HomeAssistant): Home Assistant instance running the coordinator.
            config_entry (ConfigEntry): myAir config entry associated with this
                coordinator.
            myair_client (MyAirClient): Client used to authenticate and fetch
                myAir data.
        """
        _LOGGER.info("Initializing DataUpdateCoordinator for ResMed myAir")
        self.myair_client = myair_client
        self._serial_number: str | None = None
        self._sleep_history_store: Store[list[dict[str, Any]]] = Store(
            hass,
            HISTORY_STORE_VERSION,
            f"{config_entry.domain}_{config_entry.entry_id}_sleep_history",
        )
        self._sleep_history: list[dict[str, Any]] = []
        self._usage_hours_history: list[dict[str, Any]] = []
        self._client_lock = Lock()
        self._timeline_serial: str | None = config_entry.unique_id
        self._timeline_identity_matches: bool = False
        self._timeline_unique_ids: dict[str, str] = {}
        super().__init__(
            hass=hass,
            config_entry=config_entry,
            logger=_LOGGER,
            name="myAir update",
            update_interval=timedelta(minutes=DEFAULT_UPDATE_RATE_MIN),
        )

    async def _async_setup(self) -> None:
        """Load persisted sleep history before the first cloud refresh."""
        stored_history = await self._sleep_history_store.async_load()
        if stored_history is None:
            self._sleep_history = []
            return
        self._sleep_history = normalize_sleep_history(stored_history)

    async def _async_update_data(self) -> MyAirCoordinatorData:
        """Refresh myAir data, reporting myAir outages as a failed update.

        Returns:
            MyAirCoordinatorData: Typed coordinator payload containing any data
                available from myAir.

        Raises:
            UpdateFailed: When myAir reports a temporary outage such as scheduled
                maintenance. If myAir gives the outage end, the next refresh waits
                until shortly after it.
        """
        try:
            async with self._client_lock:
                return await self._async_fetch_data()
        except ServiceUnavailableError as err:
            retry_after: float | None = None
            if err.outage_end is not None:
                remaining = (err.outage_end - dt_util.utcnow()).total_seconds()
                if remaining > 0:
                    retry_after = remaining + OUTAGE_RETRY_MARGIN_SEC
            raise UpdateFailed(str(err), retry_after=retry_after) from err

    async def _async_fetch_data(self) -> MyAirCoordinatorData:
        """Refresh auth, device metadata, and recent sleep records.

        Returns:
            MyAirCoordinatorData: Typed coordinator payload containing any data
                available from myAir.
        """
        _LOGGER.info("Updating from myAir")

        await self._async_connect()

        device: MyAirDevice | None = None
        sleep_records: tuple[MyAirSleepRecord, ...] = ()
        fresh_auth_used = False

        try:
            device = await self.myair_client.get_user_device_data()
        except StaleSessionError as err:
            _LOGGER.info(
                "Device payload missing after token validation. %s: %s",
                type(err).__name__,
                err,
            )
            _LOGGER.info("Retrying device data with fresh authentication")
            await self._async_connect(force=True)
            fresh_auth_used = True
            try:
                device = await self.myair_client.get_user_device_data()
            except ParsingError as retry_err:
                _LOGGER.debug(
                    "Device data unavailable after fresh authentication. %s: %s",
                    type(retry_err).__name__,
                    retry_err,
                )
        except ParsingError as err:
            _LOGGER.debug(
                "Device data unavailable in myAir update. %s: %s",
                type(err).__name__,
                err,
            )
        if device and device.serial_number:
            self._serial_number = device.serial_number

        # Keep the observed identity even if the subsequent sleep-record request fails.
        timeline_unique_ids = self._update_timeline_identity(device)

        try:
            sleep_records = tuple(await self.myair_client.get_sleep_records())
        except StaleSessionError as err:
            _LOGGER.info(
                "Sleep record payload missing after token validation. %s: %s",
                type(err).__name__,
                err,
            )
            if not fresh_auth_used:
                _LOGGER.info("Retrying sleep record data with fresh authentication")
                await self._async_connect(force=True)
                try:
                    sleep_records = tuple(await self.myair_client.get_sleep_records())
                except ParsingError as retry_err:
                    _LOGGER.debug(
                        "Sleep record data unavailable after fresh authentication. %s: %s",
                        type(retry_err).__name__,
                        retry_err,
                    )
        except ParsingError as err:
            _LOGGER.debug(
                "Sleep record data unavailable in myAir update. %s: %s",
                type(err).__name__,
                err,
            )

        serial_number = device.serial_number if device else self._serial_number
        self._usage_hours_history = await async_get_sleep_history_from_recorder(
            self.hass, serial_number
        )
        self._sleep_history = _merge_sleep_history(self._sleep_history, self._usage_hours_history)
        self._sleep_history = _merge_sleep_history(
            self._sleep_history, [record.raw for record in sleep_records]
        )
        await self._sleep_history_store.async_save(self._sleep_history)

        data = MyAirCoordinatorData(device=device, sleep_records=sleep_records)
        latest = data.latest_sleep_record
        if latest and latest.start_date and self._timeline_sensor_enabled(timeline_unique_ids):
            try:
                async with timeout(_TIMELINE_TIMEOUT_SECONDS):
                    timeline = await self.myair_client.get_nightly_therapy_timeline(
                        latest.start_date
                    )
            except TIMELINE_REQUEST_ERRORS as err:
                _LOGGER.debug("Nightly Therapy Timeline lookup failed: %s", type(err).__name__)
            else:
                if timeline is not None:
                    return replace(data, nightly_timeline=timeline)
        return data

    def _update_timeline_identity(self, device: MyAirDevice | None) -> tuple[str, ...]:
        """Bind the timeline sensors to a verified serial without losing legacy registry entries.

        Args:
            device (MyAirDevice | None): Device returned before fetching sleep records.

        Returns:
            tuple[str, ...]: The serial-based or provisional unique IDs of the timeline sensors.
        """
        config_entry = self.config_entry
        prefix = f"{DOMAIN}_"
        suffixes = {key: f"_{key}" for key in TIMELINE_SENSOR_KEYS}
        observed = device.serial_number if device is not None else None
        registry = er.async_get(self.hass)

        if not self._timeline_unique_ids and self._timeline_serial is None:
            placeholders = {
                f"{prefix}{marker}{suffix}"
                for suffix in suffixes.values()
                for marker in (f"entry-{config_entry.entry_id}", "")
            }
            for entry in er.async_entries_for_config_entry(registry, config_entry.entry_id):
                if entry.domain != "sensor" or entry.platform != DOMAIN:
                    continue
                if entry.unique_id in placeholders or not entry.unique_id.startswith(prefix):
                    continue
                suffix = next((s for s in suffixes.values() if entry.unique_id.endswith(s)), None)
                if suffix is not None:
                    self._timeline_serial = entry.unique_id[len(prefix) : -len(suffix)]
                    break

        if observed:
            if not self._timeline_serial:
                self._timeline_serial = observed
            self._timeline_identity_matches = observed == self._timeline_serial
        serial = self._timeline_serial
        for key, suffix in suffixes.items():
            provisional = f"{prefix}entry-{config_entry.entry_id}{suffix}"
            unique_id = f"{prefix}{serial}{suffix}" if serial else provisional
            if self._timeline_unique_ids.get(key) == unique_id:
                continue
            self._timeline_unique_ids[key] = unique_id
            # Promote a provisional registry entry without changing its entity ID or opt-in.
            if registry.async_get_entity_id("sensor", DOMAIN, unique_id) is None:
                for old_unique_id in (provisional, f"{prefix}{suffix}"):
                    entity_id = registry.async_get_entity_id("sensor", DOMAIN, old_unique_id)
                    registered = registry.async_get(entity_id) if entity_id else None
                    if (
                        registered is not None
                        and registered.config_entry_id == config_entry.entry_id
                    ):
                        registry.async_update_entity(registered.entity_id, new_unique_id=unique_id)
                        break
        return tuple(self._timeline_unique_ids.values())

    @property
    def timeline_serial(self) -> str | None:
        """Return the serial pinned to the timeline sensors.

        Returns:
            str | None: The configured or previously verified serial, when known.
        """
        return self._timeline_serial

    def timeline_unique_id(self, key: str) -> str | None:
        """Return the registry key resolved for a timeline sensor.

        Args:
            key (str): One of ``TIMELINE_SENSOR_KEYS``.

        Returns:
            str | None: The sensor's unique ID once the first refresh resolved it.
        """
        return self._timeline_unique_ids.get(key)

    def _timeline_sensor_enabled(self, unique_ids: tuple[str, ...]) -> bool:
        """Check the registered sensors before making an optional timeline request.

        Args:
            unique_ids (tuple[str, ...]): Timeline sensors' registry keys from the current refresh.

        Returns:
            bool: True when any of this entry's timeline sensors is enabled.
        """
        if not self._timeline_identity_matches:
            return False
        registry = er.async_get(self.hass)
        for unique_id in unique_ids:
            entity_id = registry.async_get_entity_id("sensor", DOMAIN, unique_id)
            entry = registry.async_get(entity_id) if entity_id else None
            if (
                entry is not None
                and entry.config_entry_id == self.config_entry.entry_id
                and not entry.disabled
            ):
                return True
        return False

    async def async_get_nightly_therapy_timeline(
        self, assigned_date: date
    ) -> MyAirNightlyTherapyTimeline | None:
        """Fetch a timeline on demand without changing the sensor snapshot.

        Args:
            assigned_date (date): Date assigned to the night by myAir.

        Returns:
            MyAirNightlyTherapyTimeline | None: The requested timeline if available.

        Raises:
            ClientError: An HTTP client failure while the same entry is still loaded.
            RuntimeError: A runtime error while the same entry is still loaded.
        """
        async with self._client_lock, timeout(_TIMELINE_TIMEOUT_SECONDS):
            self._require_loaded_timeline_entry()
            try:
                await self.myair_client.connect()
                self._require_loaded_timeline_entry()
                try:
                    timeline = await self.myair_client.get_nightly_therapy_timeline(assigned_date)
                except StaleSessionError:
                    self._require_loaded_timeline_entry()
                    await self.myair_client.connect(force=True)
                    self._require_loaded_timeline_entry()
                    timeline = await self.myair_client.get_nightly_therapy_timeline(assigned_date)
            except ClientError, RuntimeError:
                self._require_loaded_timeline_entry()
                raise
            self._require_loaded_timeline_entry()
            return timeline

    def _require_loaded_timeline_entry(self) -> None:
        """Reject an action if its original coordinator has been unloaded.

        Raises:
            ServiceValidationError: The entry is no longer using this coordinator.
        """
        entry = self.config_entry
        if entry.state is not ConfigEntryState.LOADED or entry.runtime_data is not self:
            raise ServiceValidationError(
                translation_domain=DOMAIN, translation_key="timeline_entry_unloaded"
            )

    async def _async_connect(self, *, force: bool = False) -> None:
        """Authenticate for a coordinator refresh and map auth failures.

        Args:
            force (bool): Whether to bypass cached-token validation and authenticate
                again.

        Raises:
            ConfigEntryAuthFailed: When myAir authentication requires user repair.
        """
        try:
            if force:
                await self.myair_client.connect(force=True)
            else:
                await self.myair_client.connect()
        except AuthenticationError as err:
            _LOGGER.error(
                "Authentication Error while updating. %s: %s",
                type(err).__name__,
                err,
            )
            raise ConfigEntryAuthFailed(
                f"Authentication Error while updating. {type(err).__name__}: {err}"
            ) from err

    @property
    def chart_sleep_records(self) -> list[dict[str, Any]]:
        """Return merged historical records for frontend chart attributes."""
        live_records = [record.raw for record in _coordinator_data_sleep_records(self.data)]
        history = self._sleep_history or live_records
        return _merge_sleep_history(self._usage_hours_history, history)


def _coordinator_data_sleep_records(data: Any) -> tuple[MyAirSleepRecord, ...]:
    """Return sleep records from a typed coordinator payload if available.

    Args:
        data (Any): Value currently held by the update coordinator.

    Returns:
        tuple[MyAirSleepRecord, ...]: Sleep records from a typed payload, or an
            empty tuple while the coordinator has no data.
    """
    if isinstance(data, MyAirCoordinatorData):
        return data.sleep_records
    return ()


def _merge_sleep_history(
    existing_history: list[dict[str, Any]],
    latest_records: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Merge new cloud or recorder records into persisted sleep history.

    Args:
        existing_history (list[dict[str, Any]]): Persisted history from prior
            coordinator updates.
        latest_records (Sequence[Mapping[str, Any]]): New cloud or recorder rows.

    Returns:
        list[dict[str, Any]]: Chronological merged history, capped to the supported
            retention window.
    """
    merged_by_date: dict[str, dict[str, Any]] = {
        record["startDate"]: dict(record)
        for record in normalize_sleep_history(existing_history)
        if record.get("startDate")
    }
    for record in normalize_sleep_history(latest_records):
        start_date = record.get("startDate")
        if not start_date:
            continue
        merged_by_date[start_date] = {**merged_by_date.get(start_date, {}), **dict(record)}

    sorted_dates = sorted(merged_by_date)
    if len(sorted_dates) > MAX_HISTORY_DAYS:
        sorted_dates = sorted_dates[-MAX_HISTORY_DAYS:]
    return [merged_by_date[start_date] for start_date in sorted_dates]
