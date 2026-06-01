"""Authentication session state and flow helpers for ResMed myAir."""

from __future__ import annotations

import base64
from collections.abc import Mapping, MutableMapping
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

from custom_components.resmed_myair.const import AUTH_NEEDS_MFA, AUTHN_SUCCESS
from custom_components.resmed_myair.redaction import redact_dict

from .myair_client import AuthenticationError, IncompleteAccountError, MyAirConfig, ParsingError
from .regions import RegionConfig, get_region_config

_LOGGER: logging.Logger = logging.getLogger(__name__)

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
    """Maintain Okta, OAuth, cookie, and token state for the myAir REST flow."""

    def __init__(self, config: MyAirConfig, session: ClientSession) -> None:
        """Prepare regional endpoints and mutable credential state for login.

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

    @property
    def access_token(self) -> str | None:
        """Expose the bearer token used for AppSync and userinfo requests."""
        return self._access_token

    @access_token.setter
    def access_token(self, value: str | None) -> None:
        """Replace the bearer token after an OAuth exchange or test setup.

        Args:
            value: New access token, or ``None`` to clear cached auth state.
        """
        self._access_token = value

    @property
    def id_token(self) -> str | None:
        """Expose the ID token that contains myAir region claims."""
        return self._id_token

    @id_token.setter
    def id_token(self, value: str | None) -> None:
        """Replace the ID token used to derive GraphQL country headers.

        Args:
            value: New ID token, or ``None`` when token exchange has not completed.
        """
        self._id_token = value

    @property
    def state_token(self) -> str | None:
        """Expose the Okta state token needed to continue MFA verification."""
        return self._state_token

    @state_token.setter
    def state_token(self, value: str | None) -> None:
        """Store the Okta state token returned by primary authentication.

        Args:
            value: State token from Okta authn, or ``None`` to reset MFA state.
        """
        self._state_token = value

    @property
    def session_token(self) -> str | None:
        """Expose the Okta session token exchanged for OAuth tokens."""
        return self._session_token

    @session_token.setter
    def session_token(self, value: str | None) -> None:
        """Store the Okta session token produced by password or MFA auth.

        Args:
            value: Session token from Okta, or ``None`` before auth succeeds.
        """
        self._session_token = value

    @property
    def device_token(self) -> str | None:
        """Expose the remembered-device DT cookie used to reduce MFA prompts."""
        return self._cookie_dt

    @device_token.setter
    def device_token(self, value: str | None) -> None:
        """Persist the remembered-device DT cookie from Okta responses.

        Args:
            value: DT cookie value, or ``None`` when no remembered device is available.
        """
        self._cookie_dt = value

    @property
    def _cookies(self) -> dict[str, Any]:
        """Build the auth cookie map expected by Okta requests."""
        cookies: dict[str, Any] = {}
        if self._cookie_dt:
            cookies["DT"] = self._cookie_dt
        if self._cookie_sid:
            cookies["sid"] = self._cookie_sid
        return cookies

    @property
    def region_config(self) -> RegionConfig:
        """Expose endpoint and client IDs for the configured myAir region."""
        return self._region_config

    @region_config.setter
    def region_config(self, value: RegionConfig) -> None:
        """Override regional endpoint settings.

        Args:
            value: Region configuration to use for subsequent auth requests.
        """
        self._region_config = value

    @property
    def email_factor_id(self) -> str:
        """Expose the Okta email factor used when triggering MFA."""
        return self._email_factor_id

    @email_factor_id.setter
    def email_factor_id(self, value: str) -> None:
        """Store the MFA factor discovered from Okta authn metadata.

        Args:
            value: Email factor ID to use for MFA verification requests.
        """
        self._email_factor_id = value

    @property
    def mfa_url(self) -> str:
        """Expose the Okta endpoint for the active MFA challenge."""
        return self._mfa_url

    @mfa_url.setter
    def mfa_url(self, value: str) -> None:
        """Store the verification URL advertised by the current MFA challenge.

        Args:
            value: Fully qualified Okta factor verification URL.
        """
        self._mfa_url = value

    @property
    def cookie_sid(self) -> str | None:
        """Expose the Okta session cookie captured during auth redirects."""
        return self._cookie_sid

    @cookie_sid.setter
    def cookie_sid(self, value: str | None) -> None:
        """Store the Okta ``sid`` cookie for subsequent auth calls.

        Args:
            value: Session cookie value, or ``None`` when unavailable.
        """
        self._cookie_sid = value

    @property
    def uses_mfa(self) -> bool:
        """Expose whether the current account required MFA during authn."""
        return self._uses_mfa

    @uses_mfa.setter
    def uses_mfa(self, value: bool) -> None:
        """Record whether the active auth flow is waiting for MFA.

        Args:
            value: ``True`` when Okta returned ``MFA_REQUIRED``.
        """
        self._uses_mfa = value

    @property
    def cookies(self) -> dict[str, Any]:
        """Expose the current Okta cookies without allowing direct mutation."""
        return self._cookies

    @property
    def json_headers(self) -> dict[str, Any]:
        """Expose the JSON headers sent to Okta auth endpoints."""
        return self._json_headers

    @json_headers.setter
    def json_headers(self, value: Mapping[str, Any]) -> None:
        """Replace JSON headers while preserving an owned mutable copy.

        Args:
            value: Header mapping used for subsequent JSON requests.
        """
        self._json_headers = dict(value)

    async def connect(self, initial: bool | None = False) -> str:
        """Authenticate or reuse existing credentials for a myAir session.

        Args:
            initial: Whether this is the first config-flow attempt, when MFA may be
                triggered instead of reported as a reauth failure.

        Returns:
            Okta auth status, such as ``SUCCESS`` or ``MFA_REQUIRED``.
        """
        if self._cookie_dt is None:
            await self._get_initial_dt()
        if self._cookie_dt is None and self._uses_mfa:
            _LOGGER.warning("Device Token isn't set. This will require frequent reauthentication.")
        if self._access_token and await self._is_access_token_active():
            return AUTHN_SUCCESS
        _LOGGER.info("Starting Authentication")
        status: str = await self._authn_check()
        if status == AUTH_NEEDS_MFA:
            self._uses_mfa = True
            if initial:
                await self._trigger_mfa()
            else:
                raise AuthenticationError("Need to Re-Verify MFA")
        else:
            await self._get_access_token()
        return status

    async def verify_mfa_and_get_access_token(self, verification_code: str) -> str:
        """Complete an MFA challenge and exchange the resulting session token.

        Args:
            verification_code: Email MFA code entered by the user.

        Returns:
            Okta success status after MFA verification.
        """
        status: str = await self._verify_mfa(verification_code)
        if status == AUTHN_SUCCESS:
            await self._get_access_token()
        else:
            raise AuthenticationError(f"Issue verifying MFA. Status: {status}")
        return status

    async def is_email_verified(self) -> bool:
        """Check Okta userinfo for the account email-verification flag.

        Returns:
            ``True`` when Okta reports the email address has been verified.
        """
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
            await self.resmed_response_error_check("userinfo_query", userinfo_res, userinfo_dict)
        if userinfo_dict.get("email_verified") is True:
            return True
        return False

    async def _extract_and_update_cookies(self, cookie_headers: list) -> None:
        """Parse remembered-device and session cookies from response headers.

        Args:
            cookie_headers: Raw ``Set-Cookie`` header values from Okta responses.
        """
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

    async def _get_initial_dt(self) -> None:
        """Prime the auth session with the remembered-device cookie."""
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

        await self._extract_and_update_cookies(initial_dt_res.headers.getall("set-cookie", []))

    async def _is_access_token_active(self) -> bool:
        """Ask Okta introspection whether the cached access token is reusable.

        Returns:
            ``True`` when Okta marks the cached access token active.
        """
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
            await self.resmed_response_error_check(
                "introspect_query", introspect_res, introspect_dict
            )

        if introspect_dict.get("active") is True:
            _LOGGER.info("Existing Access Token is already active. Reusing")
            return True
        return False

    @staticmethod
    async def resmed_response_error_check(
        step: str,
        response: ClientResponse,
        resp_dict: MutableMapping[str, Any],
        initial: bool | None = False,
    ) -> None:
        """Map ResMed and Okta error payloads to integration exceptions.

        Args:
            step: Human-readable auth or GraphQL step name for diagnostics.
            response: aiohttp response object associated with the payload.
            resp_dict: Decoded response payload to inspect.
            initial: Whether a GraphQL unauthorized response occurred during setup.

        Raises:
            AuthenticationError: When credentials or auth state are rejected.
            IncompleteAccountError: When myAir reports account setup is incomplete.
            ParsingError: When a non-initial GraphQL request becomes unauthorized.
            HttpProcessingError: When a structured error exists but has no typed mapping.
        """
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
        """Submit username and password to Okta and capture next auth state.

        Returns:
            Okta status indicating success or that MFA is required.

        Raises:
            AuthenticationError: When the authn payload is missing required state.
        """
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
            await self.resmed_response_error_check("authn", authn_res, authn_dict)
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

    async def _trigger_mfa(self) -> None:
        """Ask Okta to send the email MFA challenge for the current state token."""
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
            await self.resmed_response_error_check("trigger_mfa", trigger_mfa_res, trigger_mfa_dict)
        _LOGGER.info("Triggered MFA Email")

    async def _verify_mfa(self, verification_code: str) -> str:
        """Submit an email MFA code and store the returned session token.

        Args:
            verification_code: MFA code supplied by the user.

        Returns:
            Okta status after code verification.

        Raises:
            AuthenticationError: When Okta omits expected status or session data.
        """
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
            await self.resmed_response_error_check("verify_mfa", verify_mfa_res, verify_mfa_dict)
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

    async def _get_access_token(self) -> None:
        """Exchange the Okta session token for OAuth access and ID tokens.

        Raises:
            ParsingError: When Okta redirects or token payloads omit required fields.
        """
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

        await self._extract_and_update_cookies(code_res.headers.getall("set-cookie", []))

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
            await self.resmed_response_error_check("get_access_token", token_res, token_dict)
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
