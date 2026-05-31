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
    """DataUpdateCoordinator for myAir."""

    myair_client: MyAirClient

    def __init__(
        self,
        hass: HomeAssistant,
        config_entry: ConfigEntry,
        myair_client: MyAirClient,
    ) -> None:
        """Initialize DataUpdateCoordinator for ResMed myAir."""
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
        """Fetch data from the myAir client and store it in the coordinator."""
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
        except ParsingError:
            _LOGGER.debug("Device data unavailable in myAir update")

        try:
            sleep_records = tuple(await self.myair_client.get_sleep_records())
        except ParsingError:
            _LOGGER.debug("Sleep record data unavailable in myAir update")

        return MyAirCoordinatorData(device=device, sleep_records=sleep_records)
