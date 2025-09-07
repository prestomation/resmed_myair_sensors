"""Config flow for resmed_myair."""

from collections.abc import Mapping, MutableMapping
import logging
from typing import Any

from aiohttp import DummyCookieJar
from aiohttp.client_exceptions import ClientResponseError
from aiohttp.http_exceptions import HttpProcessingError
import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, UnknownEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_create_clientsession

from .client.myair_client import (
    AuthenticationError,
    IncompleteAccountError,
    MyAirConfig,
    ParsingError,
)
from .client.rest_client import RESTClient
from .const import (
    AUTHN_SUCCESS,
    CONF_DEVICE_TOKEN,
    CONF_PASSWORD,
    CONF_REGION,
    CONF_USER_NAME,
    CONF_VERIFICATION_CODE,
    DOMAIN,
    REGION_EU,
    REGION_NA,
    VERSION,
)
from .helpers import redact_dict

_LOGGER = logging.getLogger(__name__)


async def get_device(
    hass: HomeAssistant,
    username: str,
    password: str,
    region: str,
    device_token: str | None = None,
) -> tuple[str, Mapping[str, Any] | None, RESTClient]:
    """Login and get user device data from ResMed servers."""
    _LOGGER.debug("[get_device] Starting")
    config = MyAirConfig(
        username=username, password=password, region=region, device_token=device_token
    )
    client: RESTClient = RESTClient(
        config,
        async_create_clientsession(hass, cookie_jar=DummyCookieJar(), raise_for_status=True),
    )
    status: str = await client.connect(initial=True)
    if status == AUTHN_SUCCESS:
        device: Mapping[str, Any] = await client.get_user_device_data(initial=True)
        return status, device, client
    return status, None, client


async def get_mfa_device(
    client: RESTClient, verification_code: str
) -> tuple[str, Mapping[str, Any]]:
    """Get access token and user device data."""
    _LOGGER.debug("[get_mfa_device] Starting")
    status: str = await client.verify_mfa_and_get_access_token(verification_code)
    device: Mapping[str, Any] = await client.get_user_device_data(initial=True)
    return status, device


class MyAirConfigFlow(ConfigFlow, domain=DOMAIN):
    """Config flow for resmed_myair."""

    # For future migration support
    VERSION = 2

    def __init__(self) -> None:
        """Initialize flow."""
        self._client: RESTClient | None = None
        self._entry: ConfigEntry
        self._data: MutableMapping[str, Any] = {}

    async def async_step_user(
        self, user_input: MutableMapping[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        user_input = user_input or {}
        if user_input:
            self._data = user_input
            try:
                status, device, self._client = await get_device(
                    self.hass,
                    self._data[CONF_USER_NAME],
                    self._data[CONF_PASSWORD],
                    self._data[CONF_REGION],
                )
                if device and status == AUTHN_SUCCESS:
                    _LOGGER.debug("[async_step_user] device: %s", redact_dict(device))
                    if "serialNumber" not in device:
                        raise ParsingError("Unable to get Serial Number from Device Data")  # noqa: TRY301
                    serial_number: str = device["serialNumber"]
                    _LOGGER.info("Found device with serial number %s", serial_number)

                    await self.async_set_unique_id(serial_number)
                    self._abort_if_unique_id_configured()
                    self._data.update({CONF_DEVICE_TOKEN: self._client.device_token})
                    _LOGGER.debug("[async_step_user] data: %s", redact_dict(self._data))

                    return self.async_create_entry(
                        title=f"{device['fgDeviceManufacturerName']}-{device['localizedName']}",
                        data=self._data,
                    )
                return await self.async_step_verify_mfa()
            except (
                AuthenticationError,
                HttpProcessingError,
                ClientResponseError,
                ParsingError,
            ) as e:
                _LOGGER.error("Connection Error at async_step_user. %s: %s", type(e).__name__, e)
                errors["base"] = "authentication_error"
            except IncompleteAccountError as e:
                if self._client:
                    try:
                        if not (await self._client.is_email_verified()):
                            _LOGGER.error(
                                "Account Setup Incomplete at async_step_user. Email Address not verified. %s: %s",
                                type(e).__name__,
                                e,
                            )
                            return self.async_abort(reason="incomplete_account_verify_email")
                    except Exception:  # noqa: BLE001
                        pass
                _LOGGER.error(
                    "Account Setup Incomplete at async_step_user. %s: %s",
                    type(e).__name__,
                    e,
                )
                return self.async_abort(reason="incomplete_account")

        _LOGGER.info("Setting up ResMed myAir Integration Version: %s", VERSION)
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USER_NAME): selector.TextSelector(
                        selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)
                    ),
                    vol.Required(CONF_PASSWORD): selector.TextSelector(
                        selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
                    ),
                    vol.Required(CONF_REGION, default=REGION_NA): vol.In(
                        {
                            REGION_NA: "North America and Australia",
                            REGION_EU: "Europe (Email MFA)",
                        }
                    ),
                }
            ),
            errors=errors,
        )

    async def async_step_verify_mfa(
        self, user_input: MutableMapping[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Verify active MFA."""
        errors: dict[str, str] = {}
        user_input = user_input or {}
        if user_input and isinstance(self._client, RESTClient):
            # _LOGGER.debug("[async_step_verify_mfa] user_input: %s", redact_dict(user_input))
            self._data.update(user_input)
            try:
                status, device = await get_mfa_device(
                    self._client,
                    self._data.get(CONF_VERIFICATION_CODE, ""),
                )
                if status == AUTHN_SUCCESS:
                    self._data.pop(CONF_VERIFICATION_CODE, None)
                    self._data.update({CONF_DEVICE_TOKEN: self._client.device_token})
                    _LOGGER.debug("[async_step_verify_mfa] user_input: %s", redact_dict(self._data))
                    return self.async_create_entry(
                        title=f"{device['fgDeviceManufacturerName']}-{device['localizedName']}",
                        data=self._data,
                    )
                _LOGGER.error("Issue verifying MFA. Status: %s", status)
                errors["base"] = "mfa_error"
            except (
                AuthenticationError,
                HttpProcessingError,
                ClientResponseError,
                ParsingError,
            ) as e:
                _LOGGER.error("Connection Error at verify_mfa. %s: %s", type(e).__name__, e)
                errors["base"] = "mfa_error"
            except IncompleteAccountError as e:
                try:
                    if not (await self._client.is_email_verified()):
                        _LOGGER.error(
                            "Account Setup Incomplete at verify_mfa. Email Address not verified. %s: %s",
                            type(e).__name__,
                            e,
                        )
                        return self.async_abort(reason="incomplete_account_verify_email")
                except Exception:  # noqa: BLE001
                    pass
                _LOGGER.error("Account Setup Incomplete at verify_mfa. %s: %s", type(e).__name__, e)
                return self.async_abort(reason="incomplete_account")

        _LOGGER.info("Showing Verify MFA Form")
        return self.async_show_form(
            step_id="verify_mfa",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_VERIFICATION_CODE): selector.TextSelector(
                        selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)
                    ),
                }
            ),
            description_placeholders={
                "username": self._data.get(CONF_USER_NAME, "your email address"),
            },
            errors=errors,
        )

    async def async_step_reauth(self, entry_data: MutableMapping[str, Any]) -> ConfigFlowResult:
        """Handle configuration by re-auth."""
        _LOGGER.info("Starting Reauthorization")
        entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        if entry:
            self._entry = entry
        else:
            _LOGGER.error("No entry found for reauthorization")
            raise UnknownEntry(self.context["entry_id"])
        _LOGGER.debug("[async_step_reauth] entry: %s", redact_dict(self._entry))
        _LOGGER.debug("[async_step_reauth] entry_data: %s", redact_dict(entry_data))
        self._data.update(entry_data)
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: MutableMapping[str, Any] | None = None
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
                    self._data.get(CONF_DEVICE_TOKEN, None),
                )
                if device and status == AUTHN_SUCCESS:
                    _LOGGER.debug("[async_step_reauth_confirm] device: %s", redact_dict(device))
                    if "serialNumber" not in device:
                        raise ParsingError("Unable to get Serial Number from Device Data")  # noqa: TRY301
                    serial_number: str = device["serialNumber"]
                    _LOGGER.info("Found device with serial number %s", serial_number)
                    # await self.async_set_unique_id(serial_number)
                    # self._abort_if_unique_id_configured()
                    self._data.update({CONF_DEVICE_TOKEN: self._client.device_token})
                    _LOGGER.debug("[async_step_reauth_confirm] data: %s", redact_dict(self._data))

                    self.hass.config_entries.async_update_entry(self._entry, data={**self._data})
                    await self.hass.config_entries.async_reload(self._entry.entry_id)
                    return self.async_abort(reason="reauth_successful")
                return await self.async_step_reauth_verify_mfa()
            except (
                AuthenticationError,
                HttpProcessingError,
                ClientResponseError,
                ParsingError,
            ) as e:
                _LOGGER.error("Connection Error at reauth_confirm. %s: %s", type(e).__name__, e)
                errors["base"] = "authentication_error"
            except IncompleteAccountError as e:
                if self._client:
                    try:
                        if not (await self._client.is_email_verified()):
                            _LOGGER.error(
                                "Account Setup Incomplete at reauth_confirm. Email Address not verified. %s: %s",
                                type(e).__name__,
                                e,
                            )
                            return self.async_abort(reason="incomplete_account_verify_email")
                    except Exception:  # noqa: BLE001
                        pass
                _LOGGER.error(
                    "Account Setup Incomplete at reauth_confirm. %s: %s",
                    type(e).__name__,
                    e,
                )
                return self.async_abort(reason="incomplete_account")

        _LOGGER.debug("[async_step_reauth_confirm] initial data: %s", redact_dict(self._data))
        _LOGGER.info("Showing Reauth Confirm Form")
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_USER_NAME, default=self._data.get(CONF_USER_NAME, None)
                    ): selector.TextSelector(
                        selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)
                    ),
                    vol.Required(
                        CONF_PASSWORD, default=self._data.get(CONF_PASSWORD, None)
                    ): selector.TextSelector(
                        selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
                    ),
                }
            ),
            errors=errors,
        )

    async def async_step_reauth_verify_mfa(
        self, user_input: MutableMapping[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Reauthorize access to ResMed myAir."""
        errors: dict[str, str] = {}
        user_input = user_input or {}

        if user_input and isinstance(self._client, RESTClient):
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
                        "[async_step_reauth_verify_mfa] user_input: %s", redact_dict(self._data)
                    )

                    self.hass.config_entries.async_update_entry(self._entry, data={**self._data})
                    await self.hass.config_entries.async_reload(self._entry.entry_id)
                    return self.async_abort(reason="reauth_successful")
                _LOGGER.error("Issue verifying MFA. Status: %s", status)
                errors["base"] = "mfa_error"
            except (
                AuthenticationError,
                HttpProcessingError,
                ClientResponseError,
                ParsingError,
            ) as e:
                _LOGGER.error("Connection Error at reauth_verify_mfa. %s: %s", type(e).__name__, e)
                errors["base"] = "mfa_error"
            except IncompleteAccountError as e:
                try:
                    if not (await self._client.is_email_verified()):
                        _LOGGER.error(
                            "Account Setup Incomplete at reauth_verify_mfa. Email Address not verified. %s: %s",
                            type(e).__name__,
                            e,
                        )
                        return self.async_abort(reason="incomplete_account_verify_email")
                except Exception:  # noqa: BLE001
                    pass
                _LOGGER.error(
                    "Account Setup Incomplete at reauth_verify_mfa. %s: %s",
                    type(e).__name__,
                    e,
                )
                return self.async_abort(reason="incomplete_account")

        _LOGGER.info("Showing Reauth Verify MFA Form")
        return self.async_show_form(
            step_id="reauth_verify_mfa",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_VERIFICATION_CODE): selector.TextSelector(
                        selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)
                    ),
                }
            ),
            description_placeholders={
                "username": self._data.get(CONF_USER_NAME, "your email address"),
            },
            errors=errors,
        )
