"""Device coordinator for resmed_myair."""

from datetime import timedelta
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .client.myair_client import AuthenticationError, MyAirClient, ParsingError
from .const import DEFAULT_UPDATE_RATE_MIN
from .models import MyAirCoordinatorData, MyAirDevice, MyAirSleepRecord

_LOGGER: logging.Logger = logging.getLogger(__name__)


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
        super().__init__(
            hass=hass,
            config_entry=config_entry,
            logger=_LOGGER,
            name="myAir update",
            update_interval=timedelta(minutes=DEFAULT_UPDATE_RATE_MIN),
        )

    async def _async_update_data(self) -> MyAirCoordinatorData:
        """Refresh auth, device metadata, and recent sleep records.

        Returns:
            MyAirCoordinatorData: Typed coordinator payload containing any data
                available from myAir.
        """
        _LOGGER.info("Updating from myAir")

        await self._async_connect()

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
            _LOGGER.info(
                "Device payload missing after token validation; retrying with fresh authentication"
            )
            await self._async_connect(force=True)
            try:
                device = await self.myair_client.get_user_device_data()
            except ParsingError as retry_err:
                _LOGGER.debug(
                    "Device data unavailable after fresh authentication. %s: %s",
                    type(retry_err).__name__,
                    retry_err,
                )

        try:
            sleep_records = tuple(await self.myair_client.get_sleep_records())
        except ParsingError as err:
            _LOGGER.debug(
                "Sleep record data unavailable in myAir update. %s: %s",
                type(err).__name__,
                err,
            )

        return MyAirCoordinatorData(device=device, sleep_records=sleep_records)

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
