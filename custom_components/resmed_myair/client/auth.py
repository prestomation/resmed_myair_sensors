"""Authentication session state and flow helpers for ResMed myAir."""

from __future__ import annotations

import base64
from collections.abc import Awaitable, Callable, Mapping, MutableMapping
import hashlib
from http.cookies import SimpleCookie
import logging
import os
import re
from typing import Any
from urllib.parse import DefragResult, parse_qs, urldefrag

from aiohttp import ClientResponse, ClientSession
from aiohttp.http_exceptions import HttpProcessingError
from multidict import CIMultiDict

from .const import AUTH_NEEDS_MFA, AUTHN_SUCCESS
from .helpers import redact_dict
from .myair_client import AuthenticationError, IncompleteAccountError, MyAirConfig, ParsingError
from .regions import RegionConfig, get_region_config

_LOGGER: logging.Logger = logging.getLogger(__name__)

_AsyncAuthBool = Callable[[], Awaitable[bool]]
_AsyncAuthStatus = Callable[[], Awaitable[str]]
_AsyncAuthVerify = Callable[[str], Awaitable[str]]
_AsyncNoArgs = Callable[[], Awaitable[None]]
_ErrorCheck = Callable[
    [str, ClientResponse, MutableMapping[str, Any], bool | None], Awaitable[None]
]
_CookieUpdate = Callable[[list], Awaitable[None]]
_AUTH_LOG_SECRET_KEYS: frozenset[str] = frozenset(
    {
        "Authorization",
        "access_token",
        "code",
        "code_verifier",
        "id_token",
        "passCode",
        "sessionToken",
        "stateToken",
        "token",
    }
)


def _safe_auth_log_payload(data: Any) -> Any:
    """Remove auth-flow-only secret keys before debug logging.

    Args:
        data: Payload that may contain Okta or OAuth credentials.

    Returns:
        A copy with known secret-bearing fields omitted recursively.
    """
    if isinstance(data, Mapping):
        return {
            key: _safe_auth_log_payload(value)
            for key, value in data.items()
            if key not in _AUTH_LOG_SECRET_KEYS
        }
    if isinstance(data, list):
        return [_safe_auth_log_payload(value) for value in data]
    return data


class MyAirAuthSession:
    """Encapsulate authentication/session concerns for the myAir REST flow."""

    def __init__(self, config: MyAirConfig, session: ClientSession) -> None:
        """Initialize auth session state.

        Args:
            config: Parsed user config.
            session: Shared aiohttp client session.
        """
        self._config: MyAirConfig = config
        self._session: ClientSession = session
        self._json_headers: dict[str, Any] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self._country_code: str | None = None
        self._access_token: str | None = None
        self._id_token: str | None = None
        self._state_token: str | None = None
        self._session_token: str | None = None
        self._cookie_dt: str | None = self._config.device_token
        self._cookie_sid: str | None = None
        self._uses_mfa: bool = False
        self._region_config: RegionConfig = get_region_config(self._config.region)
        self._email_factor_id: str = self._region_config.email_factor_id
        self._mfa_url: str = self._region_config.mfa_url(self._email_factor_id)
        self._resmed_error_checker: _ErrorCheck = self._resmed_response_error_check

    @property
    def access_token(self) -> str | None:
        """Return the active access token."""
        return self._access_token

    @access_token.setter
    def access_token(self, value: str | None) -> None:
        self._access_token = value

    @property
    def id_token(self) -> str | None:
        """Return the active id token."""
        return self._id_token

    @id_token.setter
    def id_token(self, value: str | None) -> None:
        self._id_token = value

    @property
    def state_token(self) -> str | None:
        """Return the current state token."""
        return self._state_token

    @state_token.setter
    def state_token(self, value: str | None) -> None:
        self._state_token = value

    @property
    def session_token(self) -> str | None:
        """Return the current session token."""
        return self._session_token

    @session_token.setter
    def session_token(self, value: str | None) -> None:
        self._session_token = value

    @property
    def device_token(self) -> str | None:
        """Return the DT cookie value."""
        return self._cookie_dt

    @device_token.setter
    def device_token(self, value: str | None) -> None:
        self._cookie_dt = value

    @property
    def _cookies(self) -> dict[str, Any]:
        """Build cookie map with DT and sid entries."""
        cookies: dict[str, Any] = {}
        if self._cookie_dt:
            cookies["DT"] = self._cookie_dt
        if self._cookie_sid:
            cookies["sid"] = self._cookie_sid
        return cookies

    @property
    def region_config(self) -> RegionConfig:
        """Access region settings."""
        return self._region_config

    @region_config.setter
    def region_config(self, value: RegionConfig) -> None:
        self._region_config = value

    @property
    def email_factor_id(self) -> str:
        """Access MFA email factor id."""
        return self._email_factor_id

    @email_factor_id.setter
    def email_factor_id(self, value: str) -> None:
        self._email_factor_id = value

    @property
    def mfa_url(self) -> str:
        """Access MFA verification URL."""
        return self._mfa_url

    @mfa_url.setter
    def mfa_url(self, value: str) -> None:
        self._mfa_url = value

    @property
    def cookie_sid(self) -> str | None:
        """Access sid cookie."""
        return self._cookie_sid

    @cookie_sid.setter
    def cookie_sid(self, value: str | None) -> None:
        self._cookie_sid = value

    @property
    def uses_mfa(self) -> bool:
        """Access whether MFA is currently required."""
        return self._uses_mfa

    @uses_mfa.setter
    def uses_mfa(self, value: bool) -> None:
        self._uses_mfa = value

    @property
    def cookies(self) -> dict[str, Any]:
        """Compatibility cookie map."""
        return self._cookies

    def set_error_checker(self, checker: _ErrorCheck) -> None:
        """Set the error-check callback used by auth REST calls."""
        self._resmed_error_checker = checker

    @property
    def country_code(self) -> str | None:
        """Return the last resolved country code from token decoding."""
        return self._country_code

    @country_code.setter
    def country_code(self, value: str | None) -> None:
        self._country_code = value

    @property
    def json_headers(self) -> dict[str, Any]:
        """Access request headers used for JSON payloads."""
        return self._json_headers

    @json_headers.setter
    def json_headers(self, value: Mapping[str, Any]) -> None:
        self._json_headers = dict(value)

    @property
    def cookie_dt(self) -> str | None:
        """Expose DT cookie for compatibility."""
        return self._cookie_dt

    @cookie_dt.setter
    def cookie_dt(self, value: str | None) -> None:
        self._cookie_dt = value

    @staticmethod
    async def resmed_response_error_check(
        step: str,
        response: ClientResponse,
        resp_dict: MutableMapping[str, Any],
        initial: bool | None = False,
    ) -> None:
        """Public alias for shared response error handling."""
        return await MyAirAuthSession._resmed_response_error_check(
            step, response, resp_dict, initial
        )

    async def _run_error_check(
        self,
        step: str,
        response: ClientResponse,
        resp_dict: MutableMapping[str, Any],
        initial: bool | None = False,
    ) -> None:
        """Run configured error check implementation."""
        await self._resmed_error_checker(step, response, resp_dict, initial)

    async def connect(
        self,
        initial: bool | None = False,
        *,
        get_initial_dt: _AsyncNoArgs | None = None,
        is_access_token_active: _AsyncAuthBool | None = None,
        authn_check: _AsyncAuthStatus | None = None,
        trigger_mfa: _AsyncNoArgs | None = None,
        get_access_token: _AsyncNoArgs | None = None,
    ) -> str:
        """Run the initial auth/connect logic."""
        _get_initial_dt = get_initial_dt or self._get_initial_dt
        _is_access_token_active = is_access_token_active or self._is_access_token_active
        _authn_check = authn_check or self._authn_check
        _trigger_mfa = trigger_mfa or self._trigger_mfa
        _get_access_token = get_access_token or self._get_access_token

        if self._cookie_dt is None:
            await _get_initial_dt()
        if self._cookie_dt is None and self._uses_mfa:
            _LOGGER.warning("Device Token isn't set. This will require frequent reauthentication.")
        if self._access_token and await _is_access_token_active():
            return AUTHN_SUCCESS
        _LOGGER.info("Starting Authentication")
        status: str = await _authn_check()
        if status == AUTH_NEEDS_MFA:
            self._uses_mfa = True
            if initial:
                await _trigger_mfa()
            else:
                raise AuthenticationError("Need to Re-Verify MFA")
        else:
            await _get_access_token()
        return status

    async def verify_mfa_and_get_access_token(
        self,
        verification_code: str,
        *,
        verify_mfa: _AsyncAuthVerify | None = None,
        get_access_token: _AsyncNoArgs | None = None,
    ) -> str:
        """Confirm valid MFA and obtain access token."""
        _verify_mfa = verify_mfa or self._verify_mfa
        _get_access_token = get_access_token or self._get_access_token
        status: str = await _verify_mfa(verification_code)
        if status == AUTHN_SUCCESS:
            await _get_access_token()
        else:
            raise AuthenticationError(f"Issue verifying MFA. Status: {status}")
        return status

    async def is_email_verified(self) -> bool:
        """Check if email address is marked as verified."""
        userinfo_url: str = self._region_config.userinfo_url
        headers: dict[str, Any] = {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        _LOGGER.debug("[is_email_verified] authorize_url: %s", userinfo_url)
        _LOGGER.debug("[is_email_verified] headers: %s", redact_dict(headers))

        async with self._session.get(
            userinfo_url,
            headers=headers,
            allow_redirects=False,
        ) as userinfo_res:
            _LOGGER.debug("[is_email_verified] userinfo_res: %s", userinfo_res)
            userinfo_dict: MutableMapping[str, Any] = await userinfo_res.json()
            _LOGGER.debug("[is_email_verified] introspect_dict: %s", redact_dict(userinfo_dict))
            await self._run_error_check("userinfo_query", userinfo_res, userinfo_dict)
        if userinfo_dict.get("email_verified") is True:
            return True
        return False

    async def _extract_and_update_cookies(self, cookie_headers: list) -> None:
        """Parse DT and sid cookies from Set-Cookie values."""
        cookies: dict[str, Any] = {}
        for header in cookie_headers:
            cookie = SimpleCookie(header)
            for key, morsel in cookie.items():
                k = key.lower()
                if k in {"dt", "sid"}:
                    norm = "DT" if k == "dt" else "sid"
                    cookies[norm] = morsel.value
        _LOGGER.debug(
            "Extracted ResMed auth cookies: DT=%s, sid=%s",
            bool(cookies.get("DT")),
            bool(cookies.get("sid")),
        )

        if cookies.get("DT") and cookies.get("DT") != self._cookie_dt:
            if self._cookie_dt is not None:
                _LOGGER.warning("Changing Device Token")
            self._cookie_dt = cookies.get("DT", self._cookie_dt)
        if cookies.get("sid") and cookies.get("sid") != self._cookie_sid:
            if self._cookie_sid is not None:
                _LOGGER.info("Updating to new sid cookie")
            self._cookie_sid = cookies.get("sid", self._cookie_sid)
        _LOGGER.debug(
            "Updated ResMed auth cookie state: DT=%s, sid=%s",
            bool(self._cookie_dt),
            bool(self._cookie_sid),
        )

    async def extract_and_update_cookies(self, cookie_headers: list) -> None:
        """Public compatibility delegate for cookie extraction."""
        await self._extract_and_update_cookies(cookie_headers)

    async def _get_initial_dt(self, extract_cookies: _CookieUpdate | None = None) -> None:
        """Fetch initial authorize response to capture DT cookie."""
        _extract_cookies = extract_cookies or self._extract_and_update_cookies
        initial_dt_url: str = self._region_config.authorize_url
        _LOGGER.debug("[get_initial_dt] initial_dt_url: %s", initial_dt_url)
        _LOGGER.debug("[get_initial_dt] headers: %s", redact_dict(self._json_headers))

        async with self._session.get(
            initial_dt_url,
            headers=self._json_headers,
            # This will likely return a 400 which is ok. Just need the device token.
            raise_for_status=False,
            allow_redirects=False,
        ) as initial_dt_res:
            _LOGGER.debug("[get_initial_dt] initial_dt_res: %s", initial_dt_res)

        await _extract_cookies(initial_dt_res.headers.getall("set-cookie", []))

    async def get_initial_dt(self, extract_cookies: _CookieUpdate | None = None) -> None:
        """Public compatibility delegate for initial DT retrieval."""
        await self._get_initial_dt(extract_cookies)

    async def _is_access_token_active(self) -> bool:
        """Check whether current access token still reports active."""
        introspect_url: str = self._region_config.introspect_url
        headers: dict[str, Any] = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        introspect_query: dict[str, Any] = {
            "client_id": self._region_config.authorize_client_id,
            "token_type_hint": "access_token",
            "token": self._access_token,
        }
        _LOGGER.debug("[is_access_token_active] introspect_url: %s", introspect_url)
        _LOGGER.debug("[is_access_token_active] headers: %s", redact_dict(headers))
        _LOGGER.debug(
            "[is_access_token_active] introspect_query: %s", redact_dict(introspect_query)
        )

        async with self._session.post(
            introspect_url, headers=headers, data=introspect_query, cookies=self._cookies
        ) as introspect_res:
            _LOGGER.debug("[is_access_token_active] introspect_res: %s", introspect_res)
            introspect_dict: MutableMapping[str, Any] = await introspect_res.json()
            _LOGGER.debug(
                "[is_access_token_active] introspect_dict: %s", redact_dict(introspect_dict)
            )
            await self._run_error_check("introspect_query", introspect_res, introspect_dict)

        if introspect_dict.get("active") is True:
            _LOGGER.info("Existing Access Token is already active. Reusing")
            return True
        return False

    async def is_access_token_active(self) -> bool:
        """Public compatibility delegate for access-token activity check."""
        return await self._is_access_token_active()

    @staticmethod
    async def _resmed_response_error_check(
        step: str,
        response: ClientResponse,
        resp_dict: MutableMapping[str, Any],
        initial: bool | None = False,
    ) -> None:
        """Raise typed exceptions for ResMed error responses."""
        if "errors" in resp_dict:
            try:
                if "errorInfo" in resp_dict["errors"][0]:
                    error_message: str = (
                        f"{resp_dict['errors'][0]['errorInfo']['errorType']}: "
                        f"{resp_dict['errors'][0]['errorInfo']['errorCode']}"
                    )
                    if resp_dict["errors"][0]["errorInfo"]["errorType"] == "unauthorized":
                        if step == "gql_query" and not initial:
                            raise ParsingError(
                                f"Getting unauthorized error on {step} step. {error_message}"
                            )
                        raise AuthenticationError(
                            f"Getting unauthorized error on {step} step. {error_message}"
                        )
                    if resp_dict["errors"][0]["errorInfo"][
                        "errorType"
                    ] == "badRequest" and resp_dict["errors"][0]["errorInfo"]["errorCode"] in {
                        "onboardingFlowInProgress",
                        "equipmentNotAssigned",
                    }:
                        raise IncompleteAccountError(f"{error_message}")
                elif "message" in resp_dict["errors"][0]:
                    error_message = resp_dict["errors"][0]["message"]
                else:
                    error_message = str(resp_dict["errors"][0])
            except (TypeError, KeyError) as e:
                error_message = f"Unable to parse error message. {type(e).__name__}: {e}"
            raise HttpProcessingError(
                code=response.status,
                message=f"{step} step: {error_message}. {resp_dict}",
                headers=CIMultiDict(response.headers),
            )

    async def _authn_check(self) -> str:
        """Validate primary username/password credentials with Okta."""
        authn_url: str = self._region_config.authn_url
        json_query: dict[str, Any] = {
            "username": self._config.username,
            "password": self._config.password,
        }
        _LOGGER.debug("[authn_check] authn_url: %s", authn_url)
        _LOGGER.debug("[authn_check] headers: %s", redact_dict(self._json_headers))
        _LOGGER.debug("[authn_check] json_query: %s", redact_dict(json_query))

        async with self._session.post(
            authn_url,
            headers=self._json_headers,
            json=json_query,
            cookies=self._cookies,
        ) as authn_res:
            _LOGGER.debug("[authn_check] authn_res: %s", authn_res)
            authn_dict: MutableMapping[str, Any] = await authn_res.json()
            _LOGGER.debug("[authn_check] authn_dict: %s", _safe_auth_log_payload(authn_dict))
            await self._run_error_check("authn", authn_res, authn_dict)
        if "status" not in authn_dict:
            raise AuthenticationError("Cannot get status in authn step")
        status: str = authn_dict["status"]
        if status == AUTH_NEEDS_MFA:
            if "stateToken" not in authn_dict:
                raise AuthenticationError("Cannot get stateToken in authn step")
            self._state_token = authn_dict["stateToken"]
            try:
                self._email_factor_id = authn_dict["_embedded"]["factors"][0]["id"]
            except KeyError, TypeError:
                self._email_factor_id = self._region_config.email_factor_id
            _LOGGER.debug("[authn_check] email_factor_id: %s", self._email_factor_id)
            try:
                self._mfa_url = (
                    f"{authn_dict['_embedded']['factors'][0]['_links']['verify']['href']}?"
                    "rememberDevice=true"
                )
            except KeyError, TypeError:
                self._mfa_url = self._region_config.mfa_url(self._email_factor_id)
            _LOGGER.debug("[authn_check] mfa_url: %s", self._mfa_url)
            _LOGGER.info("Initial Auth Completed. Needs MFA")
        elif status == AUTHN_SUCCESS:
            if "sessionToken" not in authn_dict:
                raise AuthenticationError("Cannot get sessionToken in authn step")
            self._session_token = authn_dict["sessionToken"]
            _LOGGER.info("Initial Auth Completed. Does not need MFA")
        else:
            raise AuthenticationError(f"Unknown status in authn step: {status}")
        return status

    async def authn_check(self) -> str:
        """Public compatibility delegate for authn check."""
        return await self._authn_check()

    async def _trigger_mfa(self) -> None:
        """Trigger the MFA email flow."""
        json_query: dict[str, Any] = {"passCode": "", "stateToken": self._state_token}
        _LOGGER.debug("[trigger_mfa] mfa_url: %s", self._mfa_url)
        _LOGGER.debug("[trigger_mfa] headers: %s", redact_dict(self._json_headers))
        _LOGGER.debug("[trigger_mfa] json payload prepared")

        async with self._session.post(
            self._mfa_url,
            headers=self._json_headers,
            json=json_query,
            cookies=self._cookies,
        ) as trigger_mfa_res:
            _LOGGER.debug("[trigger_mfa] trigger_mfa_res: %s", trigger_mfa_res)
            trigger_mfa_dict: MutableMapping[str, Any] = await trigger_mfa_res.json()
            _LOGGER.debug(
                "[trigger_mfa] trigger_mfa_dict: %s",
                _safe_auth_log_payload(trigger_mfa_dict),
            )
            await self._run_error_check("trigger_mfa", trigger_mfa_res, trigger_mfa_dict)
        _LOGGER.info("Triggered MFA Email")

    async def trigger_mfa(self) -> None:
        """Public compatibility delegate for MFA trigger."""
        await self._trigger_mfa()

    async def _verify_mfa(self, verification_code: str) -> str:
        """Verify MFA code and update session token."""
        json_query: dict[str, Any] = {
            "passCode": verification_code,
            "stateToken": self._state_token,
        }
        _LOGGER.debug("[verify_mfa] mfa_url: %s", self._mfa_url)
        _LOGGER.debug("[verify_mfa] headers: %s", redact_dict(self._json_headers))
        _LOGGER.debug("[verify_mfa] json payload prepared")

        async with self._session.post(
            self._mfa_url,
            headers=self._json_headers,
            json=json_query,
            cookies=self._cookies,
        ) as verify_mfa_res:
            _LOGGER.debug("[verify_mfa] verify_mfa_res: %s", verify_mfa_res)
            verify_mfa_dict: MutableMapping[str, Any] = await verify_mfa_res.json()
            _LOGGER.debug(
                "[verify_mfa] verify_mfa_dict: %s",
                _safe_auth_log_payload(verify_mfa_dict),
            )
            await self._run_error_check("verify_mfa", verify_mfa_res, verify_mfa_dict)
        if "status" not in verify_mfa_dict:
            raise AuthenticationError("Cannot get status in verify_mfa step")
        status: str = verify_mfa_dict["status"]
        if status == AUTHN_SUCCESS:
            # We've exchanged our user/pass for a session token
            if "sessionToken" not in verify_mfa_dict:
                raise AuthenticationError("Cannot get sessionToken in verify_mfa step")
            _LOGGER.info("MFA Verified")
            self._session_token = verify_mfa_dict["sessionToken"]
        else:
            raise AuthenticationError(f"Unknown status in verify_mfa step: {status}")
        return status

    async def verify_mfa(self, verification_code: str) -> str:
        """Public compatibility delegate for MFA verification."""
        return await self._verify_mfa(verification_code)

    async def _get_access_token(
        self,
        extract_cookies: _CookieUpdate | None = None,
    ) -> None:
        """Exchange session token for an access and id token."""
        _extract_cookies = extract_cookies or self._extract_and_update_cookies
        # myAir uses Authorization Code with PKCE, so we generate our verifier here
        code_verifier: str = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8")
        code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)

        code_challenge_digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge: str = base64.urlsafe_b64encode(code_challenge_digest).decode("utf-8")
        code_challenge = code_challenge.replace("=", "")
        _LOGGER.debug("[get_access_token] code_challenge: %s", code_challenge)

        # We use that sessionToken and exchange for an oauth code, using PKCE
        authorize_url: str = self._region_config.authorize_url
        params_query: dict[str, Any] = {
            "client_id": self._region_config.authorize_client_id,
            # For PKCE
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "prompt": "none",
            "redirect_uri": self._region_config.oauth_redirect_url,
            "response_mode": "fragment",
            "response_type": "code",
            "sessionToken": self._session_token,
            "scope": "openid profile email",
            "state": "abcdef",
        }
        _LOGGER.debug("[get_access_token code] authorize_url: %s", authorize_url)
        _LOGGER.debug("[get_access_token code] headers: %s", redact_dict(self._json_headers))
        _LOGGER.debug(
            "[get_access_token code] params_query: %s",
            _safe_auth_log_payload(params_query),
        )

        async with self._session.get(
            authorize_url,
            headers=self._json_headers,
            allow_redirects=False,
            params=params_query,
            cookies=self._cookies,
        ) as code_res:
            _LOGGER.debug("[get_access_token] code_res: %s", code_res)
            location = code_res.headers.get("location")
            if location is None:
                raise ParsingError("Unable to get location from code_res")
        fragment: DefragResult = urldefrag(location)
        # Pull the code out of the location header fragment
        code_values: list[str] = parse_qs(fragment.fragment).get("code", [])
        if not code_values:
            _LOGGER.error(
                "[get_access_token] authorization code missing from redirect fragment: %s",
                fragment.fragment,
            )
            raise ParsingError("Authorization code missing from redirect fragment")
        code: str = code_values[0]
        _LOGGER.debug("[get_access_token] received authorization code")

        await _extract_cookies(code_res.headers.getall("set-cookie", []))

        # Now we change the code for an access token
        # requests defaults to forms, which is what /token needs,
        # so we don't use our api_session from above
        token_query: dict[str, Any] = {
            "client_id": self._region_config.authorize_client_id,
            "redirect_uri": self._region_config.oauth_redirect_url,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
            "code": code,
        }
        headers: dict[str, Any] = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        token_url: str = self._region_config.token_url
        _LOGGER.debug("[get_access_token token] token_url: %s", token_url)
        _LOGGER.debug("[get_access_token token] headers: %s", redact_dict(headers))
        _LOGGER.debug(
            "[get_access_token token] token_query: %s",
            _safe_auth_log_payload(token_query),
        )

        async with self._session.post(
            token_url,
            headers=headers,
            data=token_query,
            allow_redirects=False,
            cookies=self._cookies,
        ) as token_res:
            _LOGGER.debug("[get_access_token] token_res: %s", token_res)
            token_dict: MutableMapping[str, Any] = await token_res.json()
            _LOGGER.debug("[get_access_token] token_dict: %s", redact_dict(token_dict))
            await self._run_error_check("get_access_token", token_res, token_dict)
            if "access_token" not in token_dict:
                raise ParsingError("access_token not in token_dict")
            if "id_token" not in token_dict:
                raise ParsingError("id_token not in token_dict")
            self._id_token = token_dict["id_token"]
            access_token = token_dict.get("access_token")
            if access_token and self._access_token != access_token:
                if self._access_token is not None:
                    _LOGGER.info("Obtained new access token")
                self._access_token = access_token

    async def get_access_token(self, extract_cookies: _CookieUpdate | None = None) -> None:
        """Public compatibility delegate for token exchange."""
        await self._get_access_token(extract_cookies)
