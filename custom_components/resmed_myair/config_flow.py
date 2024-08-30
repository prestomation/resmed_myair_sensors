from collections.abc import Mapping
import logging
from typing import Any

from aiohttp import DummyCookieJar
from aiohttp.client_exceptions import ClientResponseError
from aiohttp.http_exceptions import HttpProcessingError
from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.helpers.redact import async_redact_data
import voluptuous as vol

from .client import get_client
from .client.myair_client import (
    AuthenticationError,
    IncompleteAccountError,
    MyAirConfig,
    ParsingError,
)
from .const import (
    AUTHN_SUCCESS,
    CONF_DEVICE_TOKEN,
    CONF_PASSWORD,
    CONF_REGION,
    CONF_USER_NAME,
    CONF_VERIFICATION_CODE,
    DOMAIN,
    KEYS_TO_REDACT,
    REGION_EU,
    REGION_NA,
    VERSION,
)

_LOGGER = logging.getLogger(__name__)


async def get_device(hass, username, password, region):
    _LOGGER.debug("[get_device] Starting")
    config = MyAirConfig(username=username, password=password, region=region)
    client = get_client(
        config,
        async_create_clientsession(
            hass, cookie_jar=DummyCookieJar(), raise_for_status=True
        ),
    )
    status = await client.connect(initial=True)
    device = None
    if status == AUTHN_SUCCESS:
        device = await client.get_user_device_data()
    return status, device, client


async def get_mfa_device(client, verification_code):
    _LOGGER.debug("[get_mfa_device] Starting")
    status = await client.verify_mfa_and_get_access_token(verification_code)
    device = await client.get_user_device_data()
    return status, device


class MyAirConfigFlow(ConfigFlow, domain=DOMAIN):

    # For future migration support
    VERSION = 2

    def __init__(self) -> None:
        """Initialize flow."""
        self._client = None
        self._entry: ConfigEntry
        self._data = {}

    async def async_step_user(self, user_input=None) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        user_input: dict[str, Any] | None = user_input or {}
        if user_input:
            self._data = user_input
            try:
                status, device, self._client = await get_device(
                    self.hass,
                    self._data[CONF_USER_NAME],
                    self._data[CONF_PASSWORD],
                    self._data[CONF_REGION],
                )
                if status == AUTHN_SUCCESS:
                    _LOGGER.debug(
                        f"[async_step_user] device: {async_redact_data(device, KEYS_TO_REDACT)}"
                    )
                    if "serialNumber" not in device:
                        raise ParsingError(
                            f"Unable to get Serial Number from Device Data"
                        )
                    serial_number = device["serialNumber"]
                    _LOGGER.info(f"Found device with serial number {serial_number}")

                    await self.async_set_unique_id(serial_number)
                    self._abort_if_unique_id_configured()
                    self._data.update({CONF_DEVICE_TOKEN: self._client.device_token})
                    _LOGGER.debug(
                        f"[async_step_user] data: {async_redact_data(self._data, KEYS_TO_REDACT)}"
                    )

                    return self.async_create_entry(
                        title=f"{device['fgDeviceManufacturerName']}-{device['localizedName']}",
                        data=self._data,
                    )
                else:
                    return await self.async_step_verify_mfa()
            except (
                AuthenticationError,
                HttpProcessingError,
                ClientResponseError,
                ParsingError,
            ) as e:
                _LOGGER.error(
                    f"Connection Error at async_step_user. {e.__class__.__qualname__}: {e}"
                )
                errors["base"] = "authentication_error"
            except IncompleteAccountError as e:
                if self._client:
                    try:
                        if not (await self._client.is_email_verified()):
                            _LOGGER.error(
                                f"Account Setup Incomplete at async_step_user. Email Address not verified. {e.__class__.__qualname__}: {e}"
                            )
                            return self.async_abort(
                                reason="incomplete_account_verify_email"
                            )
                    except Exception:
                        pass
                _LOGGER.error(
                    f"Account Setup Incomplete at async_step_user. {e.__class__.__qualname__}: {e}"
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
                        {REGION_NA: "North America", REGION_EU: "EU (Email MFA)"}
                    ),
                }
            ),
            errors=errors,
        )

    async def async_step_verify_mfa(self, user_input=None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        user_input: dict[str, Any] | None = user_input or {}
        if user_input:
            self._data.update(user_input)
            try:
                status, device = await get_mfa_device(
                    self._client,
                    self._data.get(CONF_VERIFICATION_CODE, ""),
                )
                if status == AUTHN_SUCCESS:
                    self._data.pop(CONF_VERIFICATION_CODE, None)
                    self._data.update({CONF_DEVICE_TOKEN: self._client.device_token})
                    _LOGGER.debug(
                        f"[async_step_verify_mfa] user_input: {async_redact_data(self._data, KEYS_TO_REDACT)}"
                    )
                    return self.async_create_entry(
                        title=f"{device['fgDeviceManufacturerName']}-{device['localizedName']}",
                        data=self._data,
                    )
                else:
                    _LOGGER.error(f"Issue verifying MFA. Status: {status}")
                    errors["base"] = "mfa_error"
            except (
                AuthenticationError,
                HttpProcessingError,
                ClientResponseError,
                ParsingError,
            ) as e:
                _LOGGER.error(
                    f"Connection Error at verify_mfa. {e.__class__.__qualname__}: {e}"
                )
                errors["base"] = "mfa_error"
            except IncompleteAccountError as e:
                if self._client:
                    try:
                        if not (await self._client.is_email_verified()):
                            _LOGGER.error(
                                f"Account Setup Incomplete at verify_mfa. Email Address not verified. {e.__class__.__qualname__}: {e}"
                            )
                            return self.async_abort(
                                reason="incomplete_account_verify_email"
                            )
                    except Exception:
                        pass
                _LOGGER.error(
                    f"Account Setup Incomplete at verify_mfa. {e.__class__.__qualname__}: {e}"
                )
                return self.async_abort(reason="incomplete_account")

        _LOGGER.info("Showing Verify MFA Form")
        return self.async_show_form(
            step_id="verify_mfa",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_VERIFICATION_CODE): selector.TextSelector(
                        selector.TextSelectorConfig(type="text")
                    ),
                }
            ),
            description_placeholders={
                "username": self._data.get(CONF_USER_NAME, "your email address"),
            },
            errors=errors,
        )

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Handle configuration by re-auth."""
        _LOGGER.info("Starting Reauthorization")
        if entry := self.hass.config_entries.async_get_entry(self.context["entry_id"]):
            self._entry = entry
        _LOGGER.debug(
            f"[async_step_reauth] entry: {async_redact_data(self._entry, KEYS_TO_REDACT)}"
        )
        _LOGGER.debug(
            f"[async_step_reauth] entry_data: {async_redact_data(entry_data, KEYS_TO_REDACT)}"
        )
        self._data.update(entry_data)
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Dialog that informs the user that reauth is required."""
        errors: dict[str, str] = {}

        if user_input:
            self._data.update(user_input)
            try:
                status, device, self._client = await get_device(
                    self.hass,
                    self._data[CONF_USER_NAME],
                    self._data[CONF_PASSWORD],
                    self._data[CONF_REGION],
                )
                if status == AUTHN_SUCCESS:
                    _LOGGER.debug(
                        f"[async_step_reauth_confirm] device: {async_redact_data(device, KEYS_TO_REDACT)}"
                    )
                    if "serialNumber" not in device:
                        raise ParsingError(
                            f"Unable to get Serial Number from Device Data"
                        )
                    serial_number = device["serialNumber"]
                    _LOGGER.info(f"Found device with serial number {serial_number}")
                    # await self.async_set_unique_id(serial_number)
                    # self._abort_if_unique_id_configured()
                    self._data.update({CONF_DEVICE_TOKEN: self._client.device_token})
                    _LOGGER.debug(
                        f"[async_step_reauth_confirm] data: {async_redact_data(self._data, KEYS_TO_REDACT)}"
                    )

                    self.hass.config_entries.async_update_entry(
                        self._entry, data={**self._data}
                    )
                    await self.hass.config_entries.async_reload(self._entry.entry_id)
                    return self.async_abort(reason="reauth_successful")
                else:
                    return await self.async_step_reauth_verify_mfa()
            except (
                AuthenticationError,
                HttpProcessingError,
                ClientResponseError,
                ParsingError,
            ) as e:
                _LOGGER.error(
                    f"Connection Error at reauth_confirm. {e.__class__.__qualname__}: {e}"
                )
                errors["base"] = "authentication_error"
            except IncompleteAccountError as e:
                if self._client:
                    try:
                        if not (await self._client.is_email_verified()):
                            _LOGGER.error(
                                f"Account Setup Incomplete at reauth_confirm. Email Address not verified. {e.__class__.__qualname__}: {e}"
                            )
                            return self.async_abort(
                                reason="incomplete_account_verify_email"
                            )
                    except Exception:
                        pass
                _LOGGER.error(
                    f"Account Setup Incomplete at reauth_confirm. {e.__class__.__qualname__}: {e}"
                )
                return self.async_abort(reason="incomplete_account")

        _LOGGER.info("Showing Reauth Confirm Form")
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USER_NAME): selector.TextSelector(
                        selector.TextSelectorConfig(type="text")
                    ),
                    vol.Required(CONF_PASSWORD): selector.TextSelector(
                        selector.TextSelectorConfig(type="password")
                    ),
                }
            ),
            errors=errors,
        )

    async def async_step_reauth_verify_mfa(self, user_input=None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        user_input: dict[str, Any] | None = user_input or {}

        if user_input:
            self._data.update(user_input)

            try:
                status, _ = await get_mfa_device(
                    self._client,
                    self._data.get(CONF_VERIFICATION_CODE, ""),
                )
                if status == AUTHN_SUCCESS:
                    self._data.pop(CONF_VERIFICATION_CODE, None)
                    self._data.update({CONF_DEVICE_TOKEN: self._client.device_token})
                    _LOGGER.debug(
                        f"[async_step_reauth_verify_mfa] user_input: {async_redact_data(self._data, KEYS_TO_REDACT)}"
                    )

                    self.hass.config_entries.async_update_entry(
                        self._entry, data={**self._data}
                    )
                    await self.hass.config_entries.async_reload(self._entry.entry_id)
                    return self.async_abort(reason="reauth_successful")
                else:
                    _LOGGER.error(f"Issue verifying MFA. Status: {status}")
                    errors["base"] = "mfa_error"
            except (
                AuthenticationError,
                HttpProcessingError,
                ClientResponseError,
                ParsingError,
            ) as e:
                _LOGGER.error(
                    f"Connection Error at reauth_verify_mfa. {e.__class__.__qualname__}: {e}"
                )
                errors["base"] = "mfa_error"
            except IncompleteAccountError as e:
                if self._client:
                    try:
                        if not (await self._client.is_email_verified()):
                            _LOGGER.error(
                                f"Account Setup Incomplete at reauth_verify_mfa. Email Address not verified. {e.__class__.__qualname__}: {e}"
                            )
                            return self.async_abort(
                                reason="incomplete_account_verify_email"
                            )
                    except Exception:
                        pass
                _LOGGER.error(
                    f"Account Setup Incomplete at reauth_verify_mfa. {e.__class__.__qualname__}: {e}"
                )
                return self.async_abort(reason="incomplete_account")

        _LOGGER.info("Showing Reauth Verify MFA Form")
        return self.async_show_form(
            step_id="reauth_verify_mfa",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_VERIFICATION_CODE): selector.TextSelector(
                        selector.TextSelectorConfig(type="text")
                    ),
                }
            ),
            description_placeholders={
                "username": self._data.get(CONF_USER_NAME, "your email address"),
            },
            errors=errors,
        )
