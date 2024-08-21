import logging

from homeassistant import config_entries
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_create_clientsession
import voluptuous as vol

from .client import get_client
from .client.myair_client import (
    AuthenticationError,
    MyAirConfig,
    MyAirDevice,
    MyAirEUConfig,
)
from .common import (
    CONF_BEARER_TOKEN,
    CONF_COUNTRY_CODE,
    CONF_PASSWORD,
    CONF_REGION,
    CONF_USER_NAME,
    DEFAULT_PREFIX,
    DOMAIN,
    REGION_EU,
    REGION_NA,
)

_LOGGER = logging.getLogger(__name__)


async def get_device(
    hass, username, password, region, country_code=None, bearer_token=None
) -> MyAirDevice:
    if region == "NA":
        config = MyAirConfig(username=username, password=password, region=region)
    else:
        config = MyAirEUConfig(
            username=username,
            password=password,
            region=region,
            country_code=country_code,
            bearer_token=bearer_token,
        )
    client = get_client(config, async_create_clientsession(hass))
    await client.connect()
    device = await client.get_user_device_data()
    return device


class MyAirConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):

    # For future migration support
    VERSION = 2

    def __init__(self) -> None:
        """Initialize flow."""
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
                return await self.async_step_eu_details()
            try:
                device: MyAirDevice = await get_device(
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
                        {REGION_NA: "North America", REGION_EU: "EU (Experimental)"}
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
                device: MyAirDevice = await get_device(
                    self.hass,
                    self._user_input[CONF_USER_NAME],
                    self._user_input[CONF_PASSWORD],
                    self._user_input.get(CONF_REGION),
                    self._user_input.get(CONF_COUNTRY_CODE),
                    self._user_input.get(CONF_BEARER_TOKEN),
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
                    vol.Required(CONF_COUNTRY_CODE): vol.In(
                        {
                            "AT": "Austria",
                            "BE": "Belgium",
                            "CY": "Cyprus",
                            "CZ": "Czech Republic",
                            "DK": "Denmark",
                            "FI": "Finland",
                            "FR": "France",
                            "DE": "Germany",
                            "EL": "Greece",
                            "IS": "Iceland",
                            "IE": "Ireland",
                            "IT": "Italy",
                            "LU": "Luxembourg",
                            "MT": "Malta",
                            "NL": "Netherlands",
                            "NO": "Norway",
                            "PL": "Poland",
                            "PT": "Portugal",
                            "ZA": "South Africa",
                            "ES": "Spain",
                            "SE": "Sweden",
                            "CH": "Switzerland",
                            "UK": "United Kingdom",
                        }
                    ),
                    vol.Required(CONF_BEARER_TOKEN): selector.TextSelector(
                        selector.TextSelectorConfig(
                            multiline=True, prefix="Bearer ", type="text"
                        )
                    ),
                }
            ),
            errors=errors,
        )
