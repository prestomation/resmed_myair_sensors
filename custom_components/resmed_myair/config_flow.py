import logging

from homeassistant import config_entries
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_create_clientsession
import voluptuous as vol

from .client import get_client
from .client.myair_client import AuthenticationError, MyAirConfig, MyAirDevice
from .common import (
    CONF_PASSWORD,
    CONF_REGION,
    CONF_USER_NAME,
    CONF_VERIFICATION_CODE,
    DEFAULT_PREFIX,
    DOMAIN,
    REGION_EU,
    REGION_NA,
)
from .const import VERSION

_LOGGER = logging.getLogger(__name__)


async def get_na_device(hass, username, password, region) -> MyAirDevice:
    config = MyAirConfig(username=username, password=password, region=region)
    client = get_client(config, async_create_clientsession(hass))
    await client.connect()
    device = await client.get_user_device_data()
    return device


async def eu_trigger_2fa(hass, username, password, region) -> MyAirDevice:
    config = MyAirConfig(username=username, password=password, region=region)
    client = get_client(config, async_create_clientsession(hass))
    await client.get_state_token_and_trigger_2fa()
    return client


async def get_eu_device(client, verification_code) -> MyAirDevice:
    await client.verify_2fa_and_get_access_token(verification_code)
    device = await client.get_user_device_data()
    return device


class MyAirConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):

    # For future migration support
    VERSION = 2

    def __init__(self) -> None:
        """Initialize flow."""
        self._client = None
        self._prefix = DEFAULT_PREFIX
        self._user_input = {}

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}
        user_input = user_input or {}
        if user_input:
            self._user_input = user_input
            region = user_input.get(CONF_REGION, "NA")
            if region == "EU":
                try:
                    self._client = await eu_trigger_2fa(
                        self.hass,
                        user_input[CONF_USER_NAME],
                        user_input[CONF_PASSWORD],
                        region,
                    )
                except AuthenticationError:
                    errors["base"] = "authentication_error"
                return await self.async_step_eu_details()
            try:
                device: MyAirDevice = await get_na_device(
                    self.hass,
                    user_input[CONF_USER_NAME],
                    user_input[CONF_PASSWORD],
                    region,
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

        _LOGGER.info(f"Setting up ResMed myAir Integration Version: {VERSION}")
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USER_NAME): selector.TextSelector(
                        selector.TextSelectorConfig(type="text")
                    ),
                    vol.Required(CONF_PASSWORD): selector.TextSelector(
                        selector.TextSelectorConfig(type="password")
                    ),
                    vol.Required(CONF_REGION, default=REGION_NA): vol.In(
                        {REGION_NA: "North America", REGION_EU: "EU (Email 2FA)"}
                    ),
                }
            ),
            errors=errors,
        )

    async def async_step_eu_details(self, user_input=None):
        errors = {}
        user_input = user_input or {}
        if user_input:
            self._user_input.update(user_input)
            try:
                device: MyAirDevice = await get_eu_device(
                    self._client, self._user_input.get(CONF_VERIFICATION_CODE, "")
                )

                serial_number = device["serialNumber"]
                _LOGGER.info(
                    f"ResMed MyAir: Found device with serial number {serial_number}"
                )

                await self.async_set_unique_id(serial_number)
                self._abort_if_unique_id_configured()

                return self.async_create_entry(
                    title=f"{device['fgDeviceManufacturerName']}-{device['localizedName']}",
                    data=self._user_input,
                )
            except AuthenticationError:
                errors["base"] = "authentication_error"

        return self.async_show_form(
            step_id="eu_details",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_VERIFICATION_CODE): selector.TextSelector(
                        selector.TextSelectorConfig(type="text")
                    ),
                }
            ),
            description_placeholders={
                "username": self._user_input.get(CONF_USER_NAME, "your email address"),
            },
            errors=errors,
        )
