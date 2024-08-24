import logging

from aiohttp.client_exceptions import ClientResponseError
from aiohttp.http_exceptions import HttpProcessingError
from homeassistant import config_entries
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.helpers.redact import async_redact_data
import voluptuous as vol

from .client import get_client
from .client.myair_client import (
    AuthenticationError,
    IncompleteAccountError,
    MyAirConfig,
    MyAirDevice,
    ParsingError,
)
from .common import (
    CONF_ACCESS_TOKEN,
    CONF_COUNTRY_CODE,
    CONF_PASSWORD,
    CONF_REGION,
    CONF_USER_NAME,
    CONF_VERIFICATION_CODE,
    DEFAULT_PREFIX,
    DOMAIN,
    KEYS_TO_REDACT,
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
                        self._user_input[CONF_USER_NAME],
                        self._user_input[CONF_PASSWORD],
                        region,
                    )
                    return await self.async_step_eu_details()
                except (
                    AuthenticationError,
                    HttpProcessingError,
                    ClientResponseError,
                ) as e:
                    _LOGGER.error(
                        f"Connection Error with eu_trigger_2fa. {e.__class__.__qualname__}: {e}"
                    )
                    errors["base"] = "authentication_error"
                except IncompleteAccountError as e:
                    _LOGGER.error(
                        f"myAir Account Setup Incomplete with eu_trigger_2fa. {e.__class__.__qualname__}: {e}"
                    )
                    return self.async_abort(reason="incomplete_account")

            try:
                device: MyAirDevice = await get_na_device(
                    self.hass,
                    self._user_input[CONF_USER_NAME],
                    self._user_input[CONF_PASSWORD],
                    region,
                )
                _LOGGER.debug(f"[async_step_user] device: {device}")
                if "serialNumber" not in device:
                    raise ParsingError(f"Unable to get Serial Number from Device Data")
                serial_number = device["serialNumber"]
                _LOGGER.info(
                    f"ResMed MyAir: Found device with serial number {serial_number}"
                )

                await self.async_set_unique_id(serial_number)
                self._abort_if_unique_id_configured()
                self._user_input.update(
                    {CONF_COUNTRY_CODE: device.get(CONF_COUNTRY_CODE, None)}
                )
                _LOGGER.debug(
                    f"[async_step_user] user_input: {async_redact_data(self._user_input, KEYS_TO_REDACT)}"
                )
                return self.async_create_entry(
                    title=f"{device['fgDeviceManufacturerName']}-{device['localizedName']}",
                    data=self._user_input,
                )
            except (
                AuthenticationError,
                HttpProcessingError,
                ClientResponseError,
                ParsingError,
            ) as e:
                _LOGGER.error(
                    f"Connection Error with get_na_device. {e.__class__.__qualname__}: {e}"
                )
                errors["base"] = "authentication_error"
            except IncompleteAccountError as e:
                _LOGGER.error(
                    f"myAir Account Setup Incomplete with get_na_device. {e.__class__.__qualname__}: {e}"
                )
                return self.async_abort(reason="incomplete_account")
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
                _LOGGER.debug(f"[async_step_eu_details] device: {device}")

                if "serialNumber" not in device:
                    raise ParsingError(f"Unable to get Serial Number from Device Data")
                serial_number = device["serialNumber"]
                _LOGGER.info(
                    f"ResMed MyAir: Found device with serial number {serial_number}"
                )

                await self.async_set_unique_id(serial_number)
                self._abort_if_unique_id_configured()
                self._user_input.pop(CONF_VERIFICATION_CODE)
                self._user_input.update(
                    {CONF_ACCESS_TOKEN: device.get(CONF_ACCESS_TOKEN, None)}
                )
                self._user_input.update(
                    {CONF_COUNTRY_CODE: device.get(CONF_COUNTRY_CODE, None)}
                )
                _LOGGER.debug(
                    f"[async_step_eu_details] user_input: {async_redact_data(self._user_input, KEYS_TO_REDACT)}"
                )
                return self.async_create_entry(
                    title=f"{device['fgDeviceManufacturerName']}-{device['localizedName']}",
                    data=self._user_input,
                )
            except (
                AuthenticationError,
                HttpProcessingError,
                ClientResponseError,
                ParsingError,
            ) as e:
                _LOGGER.error(
                    f"Connection Error with get_eu_device. {e.__class__.__qualname__}: {e}"
                )
                errors["base"] = "2fa_error"
            except IncompleteAccountError as e:
                _LOGGER.error(
                    f"myAir Account Setup Incomplete with get_eu_device. {e.__class__.__qualname__}: {e}"
                )
                return self.async_abort(reason="incomplete_account")
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
