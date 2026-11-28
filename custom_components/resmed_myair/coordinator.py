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
from homeassistant.helpers import entity_registry as er, issue_registry as ir
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
from .const import DEFAULT_UPDATE_RATE_MIN, DOMAIN, OUTAGE_RETRY_MARGIN_SEC, TIMELINE_SENSOR_KEYS
from .models import MyAirCoordinatorData, MyAirDevice, MyAirNightlyTherapyTimeline, MyAirSleepRecord

_LOGGER: logging.Logger = logging.getLogger(__name__)
_TIMELINE_TIMEOUT_SECONDS = 20
_PROVISIONAL_MARKER = "entry-"
TIMELINE_REQUEST_ERRORS = (
    AuthenticationError,
    ClientError,
    HttpProcessingError,
    IncompleteAccountError,
    ParsingError,
    ServiceUnavailableError,
    TimeoutError,
)


def sensor_unique_id(config_entry_id: str, serial: str | None, key: str) -> str:
    """Build a sensor's registry key from the Configured CPAP Device serial.

    Args:
        config_entry_id (str): Entry that owns the sensor.
        serial (str | None): Serial of the Configured CPAP Device, or ``None``
            while unknown.
        key (str): Sensor key.

    Returns:
        str: The serial-based unique ID, or a provisional one that the coordinator
            replaces once the serial is known.
    """
    marker = serial or f"{_PROVISIONAL_MARKER}{config_entry_id}"
    return f"{DOMAIN}_{marker}_{key}"


def device_mismatch_issue_id(config_entry_id: str) -> str:
    """Return the repair issue ID used when myAir reports a different CPAP device.

    Args:
        config_entry_id (str): Entry configured for the original device.

    Returns:
        str: Issue ID scoped to the entry.
    """
    return f"device_mismatch_{config_entry_id}"


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
        self._client_lock = Lock()
        self._serial: str | None = config_entry.unique_id
        self._adopted_serial: str | None = None
        self._device_mismatch: bool = False
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

        if not self._update_device_identity(device):
            return MyAirCoordinatorData(serial=self._serial, withheld=True)

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

        data = MyAirCoordinatorData(device=device, sleep_records=sleep_records, serial=self._serial)
        latest = data.latest_sleep_record
        if latest and latest.start_date and self._timeline_sensor_enabled():
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

    def _update_device_identity(self, device: MyAirDevice | None) -> bool:
        """Decide whether this refresh's myAir data belongs to the Configured CPAP Device.

        A device payload that names another serial withholds data until a later
        payload names the configured serial again. A refresh without a device
        payload keeps the previous decision from this load.

        Args:
            device (MyAirDevice | None): Device returned by this refresh, if any.

        Returns:
            bool: True when the refresh's data can be attributed to the Configured
                CPAP Device.
        """
        observed = device.serial_number if device is not None and device.serial_number else None
        if self._serial is None:
            self._serial = self._registered_serial(observed) or observed
            if self._serial is None:
                _LOGGER.debug("Withholding myAir data until the CPAP device serial is known")
                return False
        serial = self._serial
        if serial != self._adopted_serial:
            self._adopt_placeholder_entities(serial)
            self._adopted_serial = serial

        if observed is not None:
            mismatch = observed != serial
            if mismatch and not self._device_mismatch:
                _LOGGER.warning(
                    "myAir reports CPAP device %s, but this entry is configured for %s. "
                    "Withholding its data until myAir reports the configured device",
                    observed,
                    serial,
                )
            self._device_mismatch = mismatch
            issue_id = device_mismatch_issue_id(self.config_entry.entry_id)
            if mismatch:
                ir.async_create_issue(
                    self.hass,
                    DOMAIN,
                    issue_id,
                    is_fixable=False,
                    severity=ir.IssueSeverity.WARNING,
                    translation_key="device_mismatch",
                    translation_placeholders={
                        "title": self.config_entry.title,
                        "configured": serial,
                        "reported": observed,
                    },
                )
            else:
                ir.async_delete_issue(self.hass, DOMAIN, issue_id)
        return not self._device_mismatch

    def _registered_serial(self, observed: str | None) -> str | None:
        """Recover a legacy entry's serial from its registered sensors.

        Args:
            observed (str | None): Serial reported by myAir in this refresh, if any.

        Returns:
            str | None: The observed serial when it is registered for this entry,
                otherwise the first registered serial, or ``None`` if none exists.
        """
        prefix = f"{DOMAIN}_"
        registry = er.async_get(self.hass)
        serials: set[str] = set()
        for entry in er.async_entries_for_config_entry(registry, self.config_entry.entry_id):
            if entry.domain != "sensor" or entry.platform != DOMAIN:
                continue
            if not entry.unique_id.startswith(prefix):
                continue
            # Sensor keys contain no underscores, so the serial precedes the last one.
            serial, _, key = entry.unique_id[len(prefix) :].rpartition("_")
            if serial and key and not serial.startswith(_PROVISIONAL_MARKER):
                serials.add(serial)
        if observed in serials:
            return observed
        return min(serials, default=None)

    def _adopt_placeholder_entities(self, serial: str) -> None:
        """Move sensors registered before the serial was known onto serial-based unique IDs.

        Entity IDs and opt-ins are preserved. A placeholder is left alone when a
        sensor with the target unique ID is already registered.

        Args:
            serial (str): Serial of the Configured CPAP Device.
        """
        registry = er.async_get(self.hass)
        entry_id = self.config_entry.entry_id
        entries = er.async_entries_for_config_entry(registry, entry_id)
        # A provisional ID takes precedence over one registered with a blank serial.
        for placeholder in (sensor_unique_id(entry_id, None, ""), f"{DOMAIN}__"):
            for entry in entries:
                if entry.domain != "sensor" or entry.platform != DOMAIN:
                    continue
                if not entry.unique_id.startswith(placeholder):
                    continue
                key = entry.unique_id[len(placeholder) :]
                unique_id = sensor_unique_id(entry_id, serial, key)
                if registry.async_get_entity_id("sensor", DOMAIN, unique_id) is None:
                    registry.async_update_entity(entry.entity_id, new_unique_id=unique_id)

    def _timeline_sensor_enabled(self) -> bool:
        """Check the registered sensors before making an optional timeline request.

        Returns:
            bool: True when any of this entry's timeline sensors is enabled.
        """
        registry = er.async_get(self.hass)
        entry_id = self.config_entry.entry_id
        for key in TIMELINE_SENSOR_KEYS:
            unique_id = sensor_unique_id(entry_id, self._serial, key)
            entity_id = registry.async_get_entity_id("sensor", DOMAIN, unique_id)
            entry = registry.async_get(entity_id) if entity_id else None
            if entry is not None and entry.config_entry_id == entry_id and not entry.disabled:
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
            ServiceValidationError: The latest refresh withheld myAir data because
                it could not be attributed to the Configured CPAP Device.
        """
        async with self._client_lock, timeout(_TIMELINE_TIMEOUT_SECONDS):
            self._require_loaded_timeline_entry()
            if self.data.withheld:
                raise ServiceValidationError(
                    translation_domain=DOMAIN, translation_key="timeline_device_unverified"
                )
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
