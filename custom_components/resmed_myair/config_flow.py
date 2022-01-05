from homeassistant import config_entries
from .common import (
    DOMAIN,
    DEFAULT_PREFIX,
    CONF_USER_NAME,
    CONF_PASSWORD,
    CONF_REGION,
    REGION_NA,
    REGION_EU,
)
import voluptuous as vol
import homeassistant.helpers.config_validation as cv
import logging

from .client.myair_client import (
    MyAirConfig,
    MyAirDevice,
    AuthenticationError,
)
from .client import get_client


_LOGGER = logging.getLogger(__name__)


async def get_device(username, password, region) -> MyAirDevice:
    config = MyAirConfig(username=username, password=password, region=region)
    client = get_client(config)
    await client.connect()
    device = await client.get_user_device_data()
    return device


class MyAirConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):

    # For future migration support
    VERSION = 2

    def __init__(self) -> None:
        """Initialize flow."""
        self._prefix = DEFAULT_PREFIX

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}
        user_input = user_input or {}
        if user_input:
            try:
                region = user_input.get(CONF_REGION, "NA")
                device: MyAirDevice = await get_device(
                    user_input[CONF_USER_NAME], user_input[CONF_PASSWORD], region
                )

                serial_number = device["serialNumber"]
                _LOGGER.info(
                    f"ResMed MyAir: Found device with serial number {serial_number}"
                )

                await self.async_set_unique_id(serial_number)
                self._abort_if_unique_id_configured()

                return self.async_create_entry(
                    title=f"{device['fgDeviceManufacturerName']}-{device['localizedName']}",
                    data=user_input,
                )
            except AuthenticationError:
                errors["base"] = "authentication_error"

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USER_NAME): cv.string,
                    vol.Required(CONF_PASSWORD): cv.string,
                    vol.Required(CONF_REGION, default=REGION_NA): vol.In(
                        {REGION_NA: "North America", REGION_EU: "EU(Experimental)"}
                    ),
                }
            ),
            errors=errors,
        )
