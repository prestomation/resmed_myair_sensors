"""Device coordinator for resmed_myair."""

from asyncio import Lock, timeout
from dataclasses import replace
from datetime import date, timedelta
import logging

from aiohttp import ClientError
from aiohttp.http_exceptions import HttpProcessingError
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
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
        if latest and latest.start_date and self._time_in_apnea_enabled(device):
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

    def _time_in_apnea_enabled(self, device: MyAirDevice | None) -> bool:
        """Check the registered sensor before making an optional timeline request.

        Args:
            device (MyAirDevice | None): Device returned by the current refresh, when available.

        Returns:
            bool: True when this entry's Time in Apnea sensor is enabled.
        """
        if self.config_entry is None:
            return False
        serial = (device.serial_number if device else None) or self.config_entry.unique_id
        if not serial:
            return False
        registry = er.async_get(self.hass)
        entity_id = registry.async_get_entity_id(
            "sensor", DOMAIN, f"{DOMAIN}_{serial}_{TIME_IN_APNEA_KEY}"
        )
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
        """
        async with timeout(_TIMELINE_TIMEOUT_SECONDS), self._client_lock:
            await self.myair_client.connect()
            try:
                return await self.myair_client.get_nightly_therapy_timeline(assigned_date)
            except StaleSessionError:
                await self.myair_client.connect(force=True)
                return await self.myair_client.get_nightly_therapy_timeline(assigned_date)

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
