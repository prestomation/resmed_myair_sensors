"""Config flow for resmed_myair."""

from collections.abc import Mapping, MutableMapping
import logging
from typing import Any

from aiohttp import DummyCookieJar
from aiohttp.client_exceptions import ClientError, ClientResponseError
from aiohttp.http_exceptions import HttpProcessingError
from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, UnknownEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_create_clientsession
import voluptuous as vol

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
from .models import MyAirDevice
from .redaction import redact_dict

_LOGGER = logging.getLogger(__name__)
EMAIL_VERIFICATION_ERRORS: tuple[type[Exception], ...] = (
    AuthenticationError,
    HttpProcessingError,
    ClientError,
    ClientResponseError,
    ParsingError,
    TimeoutError,
    ValueError,
)


async def get_device(
    hass: HomeAssistant,
    username: str,
    password: str,
    region: str,
    device_token: str | None = None,
) -> tuple[str, MyAirDevice | None, RESTClient]:
    """Authenticate with myAir and fetch device data when login is complete.

    Args:
        hass: Home Assistant instance used to create the aiohttp session.
        username: myAir account username.
        password: myAir account password.
        region: myAir region code selected by the user.
        device_token: Optional remembered-device token from a previous setup.

    Returns:
        Auth status, optional device data, and the client carrying auth state.
    """
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
        device = await client.get_user_device_data(initial=True)
        return status, device, client
    return status, None, client


async def get_mfa_device(client: RESTClient, verification_code: str) -> tuple[str, MyAirDevice]:
    """Complete MFA and fetch device data with the authenticated client.

    Args:
        client: REST client already holding an active MFA challenge.
        verification_code: Email MFA code entered by the user.

    Returns:
        Auth success status and the account's assigned device.
    """
    _LOGGER.debug("[get_mfa_device] Starting")
    status: str = await client.verify_mfa_and_get_access_token(verification_code)
    device = await client.get_user_device_data(initial=True)
    return status, device


class MyAirConfigFlow(ConfigFlow, domain=DOMAIN):
    """Drive initial setup, MFA, and reauth for a myAir account."""

    # For future migration support
    VERSION = 2

    def __init__(self) -> None:
        """Initialize per-flow client and form data state."""
        self._client: RESTClient | None = None
        self._entry: ConfigEntry
        self._data: MutableMapping[str, Any] = {}

    async def _async_login_and_get_device(
        self,
        device_token: str | None = None,
    ) -> tuple[str, MyAirDevice | None]:
        """Attempt login using collected form data.

        Args:
            device_token: Optional remembered-device token to reuse during reauth.

        Returns:
            Auth status and device data when auth completed without MFA.
        """
        status, device, self._client = await get_device(
            self.hass,
            self._data[CONF_USER_NAME],
            self._data[CONF_PASSWORD],
            self._data[CONF_REGION],
            device_token,
        )
        return status, device

    async def _async_verify_mfa_and_get_device(self) -> tuple[str, MyAirDevice]:
        """Verify the submitted MFA code using the active REST client.

        Returns:
            Auth status and device data after MFA succeeds.

        Raises:
            AuthenticationError: When the flow reaches MFA without an initialized client.
        """
        if not isinstance(self._client, RESTClient):
            raise AuthenticationError("MFA client is not initialized")
        return await get_mfa_device(
            self._client,
            self._data.get(CONF_VERIFICATION_CODE, ""),
        )

    def _store_device_token(self) -> None:
        """Persist the latest remembered-device token into the config payload."""
        if self._client:
            self._data.update({CONF_DEVICE_TOKEN: self._client.device_token})

    def _credentials_schema(
        self, defaults: Mapping[str, Any] | None = None, *, include_region: bool
    ) -> vol.Schema:
        """Build the shared credential form schema.

        Args:
            defaults: Existing values to prefill in the form.
            include_region: Whether the caller can change the myAir region.

        Returns:
            Voluptuous schema for Home Assistant's config-flow form.
        """
        defaults = defaults or {}
        schema: dict[vol.Marker, object] = {
            vol.Required(
                CONF_USER_NAME, default=defaults.get(CONF_USER_NAME, None)
            ): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)
            ),
            vol.Required(
                CONF_PASSWORD, default=defaults.get(CONF_PASSWORD, None)
            ): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
            ),
        }
        if include_region:
            schema[vol.Required(CONF_REGION, default=defaults.get(CONF_REGION, REGION_NA))] = (
                vol.In(
                    {
                        REGION_NA: "North America and Australia",
                        REGION_EU: "Europe (Email MFA)",
                    }
                )
            )
        return vol.Schema(schema)

    def _mfa_schema(self) -> vol.Schema:
        """Build the shared MFA verification code schema.

        Returns:
            Voluptuous schema for Home Assistant's MFA form.
        """
        return vol.Schema(
            {
                vol.Required(CONF_VERIFICATION_CODE): selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)
                ),
            }
        )

    def _entry_title(self, device: MyAirDevice) -> str:
        """Build a stable Home Assistant entry title from device metadata.

        Args:
            device: Typed myAir device returned by the API.

        Returns:
            Manufacturer and localized name joined for display.
        """
        manufacturer = device.manufacturer or "ResMed"
        name = device.name or "myAir"
        return f"{manufacturer}-{name}"

    def _abort_if_reauth_device_mismatch(self, device: MyAirDevice) -> ConfigFlowResult | None:
        """Abort reauth when credentials belong to a different configured device.

        Args:
            device: Typed myAir device returned by the API.

        Returns:
            Abort result when the serial number conflicts with the entry being
            repaired, otherwise `None`.

        Raises:
            ParsingError: When device data does not include a serial number.
        """
        if not device.serial_number:
            raise ParsingError("Unable to get Serial Number from Device Data")
        if not self._entry.unique_id:
            _LOGGER.info(
                "Reauth will backfill missing legacy entry unique ID with device serial number %s",
                device.serial_number,
            )
            return None
        if device.serial_number != self._entry.unique_id:
            _LOGGER.error(
                "Reauth device serial number %s does not match existing entry unique ID %s",
                device.serial_number,
                self._entry.unique_id,
            )
            return self.async_abort(reason="wrong_account")
        return None

    async def _async_reconfigure_unique_id_update(
        self, entry: ConfigEntry, device: MyAirDevice
    ) -> tuple[ConfigFlowResult | None, str | None]:
        """Validate reconfigure device identity and identify unique ID updates.

        Args:
            entry: Config entry being reconfigured.
            device: Typed myAir device returned by the API.

        Returns:
            Abort result when reconfigure should stop, plus the device serial
            number when a legacy entry needs unique ID backfill.

        Raises:
            ParsingError: When device data does not include a serial number.
        """
        if not device.serial_number:
            raise ParsingError("Unable to get Serial Number from Device Data")
        await self.async_set_unique_id(device.serial_number)
        if not entry.unique_id:
            _LOGGER.info(
                "Reconfigure will backfill missing legacy entry unique ID with device serial "
                "number %s",
                device.serial_number,
            )
            if self.hass.config_entries.async_entry_for_domain_unique_id(
                self.handler,
                device.serial_number,
            ):
                return self.async_abort(reason="already_configured"), None
            return None, device.serial_number
        if entry.unique_id != device.serial_number:
            _LOGGER.error(
                "Reconfigure device serial number %s does not match existing entry unique ID %s",
                device.serial_number,
                entry.unique_id,
            )
            return self.async_abort(reason="wrong_account"), None
        return None, None

    def _update_reload_and_abort(
        self,
        entry: ConfigEntry,
        *,
        data_updates: Mapping[str, Any],
        unique_id: str | None = None,
    ) -> ConfigFlowResult:
        """Update a config entry, schedule reload, and finish the flow.

        Args:
            entry: Config entry being updated.
            data_updates: Config-entry data values to merge into existing data.
            unique_id: Optional unique ID to backfill on legacy entries.

        Returns:
            Home Assistant config-flow abort result with source-specific reason.
        """
        kwargs: dict[str, Any] = {"data_updates": data_updates}
        if unique_id is not None:
            kwargs["unique_id"] = unique_id
        return self.async_update_reload_and_abort(entry, **kwargs)

    async def _async_abort_incomplete_account(
        self, step: str, error: IncompleteAccountError
    ) -> ConfigFlowResult:
        """Abort setup with the most specific incomplete-account reason available.

        Args:
            step: Flow step where myAir reported incomplete account setup.
            error: Original incomplete-account exception from the client.

        Returns:
            Config-flow abort result for Home Assistant.
        """
        if self._client:
            try:
                if not (await self._client.is_email_verified()):
                    _LOGGER.error(
                        "Account Setup Incomplete at %s. Email Address not verified. %s: %s",
                        step,
                        type(error).__name__,
                        error,
                    )
                    return self.async_abort(reason="incomplete_account_verify_email")
            except EMAIL_VERIFICATION_ERRORS as email_error:
                _LOGGER.debug(
                    "Unable to check email verification at %s. %s: %s",
                    step,
                    type(email_error).__name__,
                    email_error,
                )
        _LOGGER.error(
            "Account Setup Incomplete at %s. %s: %s",
            step,
            type(error).__name__,
            error,
        )
        return self.async_abort(reason="incomplete_account")

    async def async_step_user(
        self, user_input: MutableMapping[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Collect credentials, validate the account, and branch to MFA if needed.

        Args:
            user_input: Submitted username, password, and region values.

        Returns:
            Form, MFA step, abort, or created-entry result for Home Assistant.
        """
        errors: dict[str, str] = {}
        user_input = user_input or {}
        if user_input:
            self._data = user_input
            try:
                status, device = await self._async_login_and_get_device()
                if device and status == AUTHN_SUCCESS:
                    _LOGGER.debug("[async_step_user] device: %s", redact_dict(device.raw))
                    if not device.serial_number:
                        raise ParsingError("Unable to get Serial Number from Device Data")
                    serial_number: str = device.serial_number
                    _LOGGER.info("Found device with serial number %s", serial_number)

                    await self.async_set_unique_id(serial_number)
                    self._abort_if_unique_id_configured()
                    self._store_device_token()
                    _LOGGER.debug("[async_step_user] data: %s", redact_dict(self._data))

                    return self.async_create_entry(
                        title=self._entry_title(device),
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
                return await self._async_abort_incomplete_account("async_step_user", e)

        _LOGGER.info("Setting up ResMed myAir Integration Version: %s", VERSION)
        return self.async_show_form(
            step_id="user",
            data_schema=self._credentials_schema(include_region=True),
            errors=errors,
        )

    async def async_step_verify_mfa(
        self, user_input: MutableMapping[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Verify MFA during initial setup and create the config entry.

        Args:
            user_input: Submitted verification code from the MFA form.

        Returns:
            MFA form, abort, or created-entry result for Home Assistant.
        """
        errors: dict[str, str] = {}
        user_input = user_input or {}
        if user_input and isinstance(self._client, RESTClient):
            self._data.update(user_input)
            try:
                status, device = await self._async_verify_mfa_and_get_device()
                if status == AUTHN_SUCCESS:
                    if not device.serial_number:
                        raise ParsingError("Unable to get Serial Number from Device Data")
                    serial_number: str = device.serial_number
                    _LOGGER.info("Found device with serial number %s", serial_number)

                    await self.async_set_unique_id(serial_number)
                    self._abort_if_unique_id_configured()
                    self._data.pop(CONF_VERIFICATION_CODE, None)
                    self._store_device_token()
                    _LOGGER.debug("[async_step_verify_mfa] user_input: %s", redact_dict(self._data))
                    return self.async_create_entry(
                        title=self._entry_title(device),
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
                return await self._async_abort_incomplete_account("verify_mfa", e)

        _LOGGER.info("Showing Verify MFA Form")
        return self.async_show_form(
            step_id="verify_mfa",
            data_schema=self._mfa_schema(),
            description_placeholders={
                "username": self._data.get(CONF_USER_NAME, "your email address"),
            },
            errors=errors,
        )

    async def async_step_reauth(self, entry_data: MutableMapping[str, Any]) -> ConfigFlowResult:
        """Load the existing config entry before prompting for new credentials.

        Args:
            entry_data: Current config-entry data supplied by Home Assistant.

        Returns:
            Next reauth flow step.

        Raises:
            UnknownEntry: When Home Assistant no longer has the reauth entry.
        """
        _LOGGER.info("Starting Reauthorization")
        try:
            self._entry = self._get_reauth_entry()
        except UnknownEntry:
            _LOGGER.error("No entry found for reauthorization")
            raise
        _LOGGER.debug("[async_step_reauth] entry: %s", redact_dict(self._entry))
        _LOGGER.debug("[async_step_reauth] entry_data: %s", redact_dict(entry_data))
        self._data.update(entry_data)
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: MutableMapping[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Collect replacement credentials and update the entry after validation.

        Args:
            user_input: Submitted username and password values.

        Returns:
            Reauth form, MFA step, abort, or successful-reauth abort result.
        """
        errors: dict[str, str] = {}

        if user_input:
            self._data.update(user_input)
            try:
                status, device = await self._async_login_and_get_device(
                    self._data.get(CONF_DEVICE_TOKEN, None),
                )
                if device and status == AUTHN_SUCCESS:
                    _LOGGER.debug("[async_step_reauth_confirm] device: %s", redact_dict(device.raw))
                    if mismatch_abort := self._abort_if_reauth_device_mismatch(device):
                        return mismatch_abort
                    serial_number: str = device.serial_number
                    _LOGGER.info("Found device with serial number %s", serial_number)
                    self._store_device_token()
                    _LOGGER.debug("[async_step_reauth_confirm] data: %s", redact_dict(self._data))

                    unique_id = device.serial_number if not self._entry.unique_id else None
                    return self._update_reload_and_abort(
                        self._entry,
                        data_updates={**self._data},
                        unique_id=unique_id,
                    )
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
                return await self._async_abort_incomplete_account("reauth_confirm", e)

        _LOGGER.debug("[async_step_reauth_confirm] initial data: %s", redact_dict(self._data))
        _LOGGER.info("Showing Reauth Confirm Form")
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=self._credentials_schema(self._data, include_region=False),
            errors=errors,
        )

    async def async_step_reauth_verify_mfa(
        self, user_input: MutableMapping[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Complete MFA during reauth and reload the repaired config entry.

        Args:
            user_input: Submitted verification code from the reauth MFA form.

        Returns:
            Reauth MFA form, abort, or successful-reauth abort result.
        """
        errors: dict[str, str] = {}
        user_input = user_input or {}

        if user_input and isinstance(self._client, RESTClient):
            self._data.update(user_input)

            try:
                status, device = await self._async_verify_mfa_and_get_device()
                if status == AUTHN_SUCCESS:
                    if mismatch_abort := self._abort_if_reauth_device_mismatch(device):
                        return mismatch_abort
                    self._data.pop(CONF_VERIFICATION_CODE, None)
                    self._store_device_token()
                    _LOGGER.debug(
                        "[async_step_reauth_verify_mfa] user_input: %s", redact_dict(self._data)
                    )

                    unique_id = device.serial_number if not self._entry.unique_id else None
                    return self._update_reload_and_abort(
                        self._entry,
                        data_updates={**self._data},
                        unique_id=unique_id,
                    )
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
                return await self._async_abort_incomplete_account("reauth_verify_mfa", e)

        _LOGGER.info("Showing Reauth Verify MFA Form")
        return self.async_show_form(
            step_id="reauth_verify_mfa",
            data_schema=self._mfa_schema(),
            description_placeholders={
                "username": self._data.get(CONF_USER_NAME, "your email address"),
            },
            errors=errors,
        )

    async def async_step_reconfigure(
        self, user_input: MutableMapping[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Collect updated setup data and validate it against the same device.

        Args:
            user_input: Submitted username, password, and region values.

        Returns:
            Reconfigure form, MFA step, abort, or successful update result.
        """
        errors: dict[str, str] = {}
        entry = self._get_reconfigure_entry()

        if not self._data:
            self._data.update(entry.data)

        if user_input:
            self._data.update(user_input)
            try:
                status, device = await self._async_login_and_get_device(
                    self._data.get(CONF_DEVICE_TOKEN, None),
                )
                if device and status == AUTHN_SUCCESS:
                    identity_abort, unique_id = await self._async_reconfigure_unique_id_update(
                        entry, device
                    )
                    if identity_abort:
                        return identity_abort
                    self._store_device_token()
                    _LOGGER.debug("[async_step_reconfigure] data: %s", redact_dict(self._data))
                    return self._update_reload_and_abort(
                        entry,
                        data_updates={**self._data},
                        unique_id=unique_id,
                    )
                return await self.async_step_reconfigure_verify_mfa()
            except (
                AuthenticationError,
                HttpProcessingError,
                ClientResponseError,
                ParsingError,
            ) as e:
                _LOGGER.error("Connection Error at reconfigure. %s: %s", type(e).__name__, e)
                errors["base"] = "authentication_error"
            except IncompleteAccountError as e:
                return await self._async_abort_incomplete_account("reconfigure", e)

        _LOGGER.info("Showing Reconfigure Form")
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=self._credentials_schema(self._data, include_region=True),
            errors=errors,
        )

    async def async_step_reconfigure_verify_mfa(
        self, user_input: MutableMapping[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Complete MFA during reconfigure and reload the updated config entry.

        Args:
            user_input: Submitted verification code from the reconfigure MFA form.

        Returns:
            Reconfigure MFA form, abort, or successful update result.
        """
        errors: dict[str, str] = {}
        user_input = user_input or {}
        entry = self._get_reconfigure_entry()

        if user_input and isinstance(self._client, RESTClient):
            self._data.update(user_input)
            try:
                status, device = await self._async_verify_mfa_and_get_device()
                if status == AUTHN_SUCCESS:
                    identity_abort, unique_id = await self._async_reconfigure_unique_id_update(
                        entry, device
                    )
                    if identity_abort:
                        return identity_abort
                    self._data.pop(CONF_VERIFICATION_CODE, None)
                    self._store_device_token()
                    _LOGGER.debug(
                        "[async_step_reconfigure_verify_mfa] data: %s",
                        redact_dict(self._data),
                    )
                    return self._update_reload_and_abort(
                        entry,
                        data_updates={**self._data},
                        unique_id=unique_id,
                    )
                _LOGGER.error("Issue verifying MFA. Status: %s", status)
                errors["base"] = "mfa_error"
            except (
                AuthenticationError,
                HttpProcessingError,
                ClientResponseError,
                ParsingError,
            ) as e:
                _LOGGER.error(
                    "Connection Error at reconfigure_verify_mfa. %s: %s",
                    type(e).__name__,
                    e,
                )
                errors["base"] = "mfa_error"
            except IncompleteAccountError as e:
                return await self._async_abort_incomplete_account("reconfigure_verify_mfa", e)

        _LOGGER.info("Showing Reconfigure Verify MFA Form")
        return self.async_show_form(
            step_id="reconfigure_verify_mfa",
            data_schema=self._mfa_schema(),
            description_placeholders={
                "username": self._data.get(CONF_USER_NAME, "your email address"),
            },
            errors=errors,
        )
