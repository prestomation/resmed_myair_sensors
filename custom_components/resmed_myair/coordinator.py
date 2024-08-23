from datetime import timedelta
import logging
from typing import List

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .client.myair_client import MyAirClient, MyAirDevice, SleepRecord
from .common import DEFAULT_UPDATE_RATE_MIN

_LOGGER = logging.getLogger(__name__)


class MyAirDataUpdateCoordinator(DataUpdateCoordinator):
    """DataUpdateCoordinator for MyAir."""

    myair_client: MyAirClient
    device: MyAirDevice
    sleep_records: List[SleepRecord]

    def __init__(
        self,
        hass: HomeAssistant,
        myair_client: MyAirClient,
    ) -> None:
        """Initialize DataUpdateCoordinator for ResMed myAir."""
        _LOGGER.debug("Initializing DataUpdateCoordinator for ResMed myAir")
        self.myair_client = myair_client
        super().__init__(
            hass,
            _LOGGER,
            name="myAir update",
            update_interval=timedelta(minutes=DEFAULT_UPDATE_RATE_MIN),
        )

    async def _async_update_data(self) -> None:
        """Fetch data from from the myAir client and store it in the coordinator."""
        _LOGGER.info("Updating from myAir")
        await self.myair_client.connect()
        self.device = await self.myair_client.get_user_device_data()
        self.sleep_records = await self.myair_client.get_sleep_records()

        return
