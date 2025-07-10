"""Device coordinator for resmed_myair."""

from collections.abc import Mapping
from datetime import timedelta
import logging
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .client.myair_client import AuthenticationError, MyAirClient
from .const import DEFAULT_UPDATE_RATE_MIN
from .helpers import redact_dict

_LOGGER: logging.Logger = logging.getLogger(__name__)


class MyAirDataUpdateCoordinator(DataUpdateCoordinator):
    """DataUpdateCoordinator for myAir."""

    myair_client: MyAirClient
    device: Mapping[str, Any]
    sleep_records: list[Mapping[str, Any]]

    def __init__(
        self,
        hass: HomeAssistant,
        myair_client: MyAirClient,
    ) -> None:
        """Initialize DataUpdateCoordinator for ResMed myAir."""
        _LOGGER.info("Initializing DataUpdateCoordinator for ResMed myAir")
        self.myair_client = myair_client
        super().__init__(
            hass,
            _LOGGER,
            name="myAir update",
            update_interval=timedelta(minutes=DEFAULT_UPDATE_RATE_MIN),
        )

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from from the myAir client and store it in the coordinator."""
        _LOGGER.info("Updating from myAir")
        try:
            await self.myair_client.connect()
            self.device = await self.myair_client.get_user_device_data()
            _LOGGER.debug("[async_update_data] device: %s", redact_dict(self.device))
            self.sleep_records = await self.myair_client.get_sleep_records()
            _LOGGER.debug("[async_update_data] sleep_records: %s", redact_dict(self.sleep_records))
        except AuthenticationError as e:
            _LOGGER.error("Authentication Error while updating. %s: %s", type(e).__name__, e)
            raise ConfigEntryAuthFailed(
                "Authentication Error while updating. %s: %s", type(e).__name__, e
            ) from e
        except Exception as e:
            _LOGGER.error("Error while updating data. %s: %s", type(e).__name__, e)
            raise UpdateFailed("Error while updating data. %s: %s", type(e).__name__, e) from e
        else:
            return {}
