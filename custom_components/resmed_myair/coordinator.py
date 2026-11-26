"""Device coordinator for resmed_myair."""

from asyncio import Lock, timeout
from dataclasses import replace
from datetime import date, timedelta
import logging

from aiohttp import ClientError
from aiohttp.http_exceptions import HttpProcessingError
from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ServiceValidationError
from homeassistant.helpers import entity_registry as er
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
from .const import DEFAULT_UPDATE_RATE_MIN, DOMAIN, OUTAGE_RETRY_MARGIN_SEC, TIME_IN_APNEA_KEY
from .models import MyAirCoordinatorData, MyAirDevice, MyAirNightlyTherapyTimeline, MyAirSleepRecord

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
        self._client_lock = Lock()
        self._time_in_apnea_serial: str | None = config_entry.unique_id
        self._time_in_apnea_identity_matches: bool = False
        self.time_in_apnea_unique_id: str | None = None
        super().__init__(
            hass=hass,
            config_entry=config_entry,
            logger=_LOGGER,
            name="myAir update",
            update_interval=timedelta(minutes=DEFAULT_UPDATE_RATE_MIN),
        )

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

        # Keep the observed identity even if the subsequent sleep-record request fails.
        self._update_time_in_apnea_identity(device)

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

        data = MyAirCoordinatorData(device=device, sleep_records=sleep_records)
        latest = data.latest_sleep_record
        if latest and latest.start_date and self._time_in_apnea_enabled():
            try:
                async with timeout(_TIMELINE_TIMEOUT_SECONDS):
                    timeline = await self.myair_client.get_nightly_therapy_timeline(
                        latest.start_date
                    )
            except TIMELINE_REQUEST_ERRORS as err:
                _LOGGER.debug("Time in Apnea lookup failed: %s", type(err).__name__)
            else:
                if timeline is not None:
                    return replace(data, time_in_apnea=timeline.total_seconds_in_apnea)
        return data

    def _update_time_in_apnea_identity(self, device: MyAirDevice | None) -> None:
        """Bind the sensor to a verified serial without losing a legacy registry entry.

        Args:
            device (MyAirDevice | None): Device returned before fetching sleep records.
        """
        config_entry = self.config_entry
        if config_entry is None:
            return
        prefix = f"{DOMAIN}_"
        suffix = f"_{TIME_IN_APNEA_KEY}"
        provisional = f"{prefix}entry-{config_entry.entry_id}{suffix}"
        blank = f"{prefix}{suffix}"
        observed = device.serial_number if device is not None else None
        registry = er.async_get(self.hass)

        if self.time_in_apnea_unique_id is None and self._time_in_apnea_serial is None:
            for entry in er.async_entries_for_config_entry(registry, config_entry.entry_id):
                if entry.domain != "sensor" or entry.platform != DOMAIN:
                    continue
                if not (entry.unique_id.startswith(prefix) and entry.unique_id.endswith(suffix)):
                    continue
                if entry.unique_id not in (provisional, blank):
                    self._time_in_apnea_serial = entry.unique_id[len(prefix) : -len(suffix)]
                    break

        if observed:
            if not self._time_in_apnea_serial:
                self._time_in_apnea_serial = observed
            self._time_in_apnea_identity_matches = observed == self._time_in_apnea_serial
        serial = self._time_in_apnea_serial
        unique_id = f"{prefix}{serial}{suffix}" if serial else provisional
        if unique_id == self.time_in_apnea_unique_id:
            return
        self.time_in_apnea_unique_id = unique_id
        # Promote a provisional registry entry without changing its entity ID or opt-in.
        if registry.async_get_entity_id("sensor", DOMAIN, unique_id) is None:
            for old_unique_id in (provisional, blank):
                entity_id = registry.async_get_entity_id("sensor", DOMAIN, old_unique_id)
                registered = registry.async_get(entity_id) if entity_id else None
                if registered is not None and registered.config_entry_id == config_entry.entry_id:
                    registry.async_update_entity(registered.entity_id, new_unique_id=unique_id)
                    break

    @property
    def time_in_apnea_serial(self) -> str | None:
        """Return the serial pinned to the timeline sensor.

        Returns:
            str | None: The configured or previously verified serial, when known.
        """
        return self._time_in_apnea_serial

    def _time_in_apnea_enabled(self) -> bool:
        """Check the registered sensor before making an optional timeline request.

        Returns:
            bool: True when this entry's Time in Apnea sensor is enabled.
        """
        if self.config_entry is None:
            return False
        if not self._time_in_apnea_identity_matches:
            return False
        if self.time_in_apnea_unique_id is None:
            return False
        registry = er.async_get(self.hass)
        entity_id = registry.async_get_entity_id("sensor", DOMAIN, self.time_in_apnea_unique_id)
        entry = registry.async_get(entity_id) if entity_id else None
        return (
            entry is not None
            and entry.config_entry_id == self.config_entry.entry_id
            and not entry.disabled
        )

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
        if (
            entry is None
            or entry.state is not ConfigEntryState.LOADED
            or entry.runtime_data is not self
        ):
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
