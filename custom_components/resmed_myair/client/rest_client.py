"""REST Client for ResMed myAir Client."""

import base64
from collections.abc import Mapping, MutableMapping
import datetime
import hashlib
from http.cookies import SimpleCookie
import logging
import os
import re
from typing import Any
from urllib.parse import DefragResult, parse_qs, urldefrag

from aiohttp import ClientResponse, ClientSession
from aiohttp.http_exceptions import HttpProcessingError
import jwt
from multidict import CIMultiDict

from .const import AUTH_NEEDS_MFA, AUTHN_SUCCESS, REGION_NA
from .helpers import redact_dict
from .myair_client import (
    AuthenticationError,
    IncompleteAccountError,
    MyAirClient,
    MyAirConfig,
    ParsingError,
)

_LOGGER: logging.Logger = logging.getLogger(__name__)

EU_CONFIG: Mapping[str, Any] = {
    # The name used in various queries
    "product": "myAir EU",
    # The regionalized URL for Okta authentication queries
    "okta_url": "id.resmed.eu",
    # This is the ID that refers to the Email MFA Factor
    "email_factor_id": "emfg9cmjqxEPr52cT417",
    # This is the server ID that is designated by Okta for myAir used in authentication urls
    "auth_server_id": "aus2uznux2sYKTsEg417",
    # This is the ID that is designated by Okta for myAir that appears in request bodies during login
    "authorize_client_id": "0oa2uz04d2Pks2NgR417",
    # Used as the x-api-key header for the AppSync GraphQL API
    "myair_api_key": "da2-o66oo6xdnfh5hlfuw5yw5g2dtm",
    # The AppSync URL that accepts the access token to return Sleep Records
    "graphql_url": "https://graphql.hyperdrive.resmed.eu/graphql",
    # Redirect url for browser to go to once authentication is complete. Must be the same as what is defined by Okta
    "oauth_redirect_url": "https://myair.resmed.eu",
}

NA_CONFIG: Mapping[str, Any] = {
    # The name used in various queries
    "product": "myAir",
    # The regionalized URL for Okta authentication queries
    "okta_url": "resmed-ext-1.okta.com",
    # This is the ID that refers to the Email MFA Factor. Not currently setup/used in NA
    "email_factor_id": "xxx",
    # This is the server ID that is designated by Okta for myAir used in authentication urls
    "auth_server_id": "aus4ccsxvnidQgLmA297",
    # This is the ID that is designated by Okta for myAir that appears in request bodies during login
    "authorize_client_id": "0oa4ccq1v413ypROi297",
    # Used as the x-api-key header for the AppSync GraphQL API
    "myair_api_key": "da2-cenztfjrezhwphdqtwtbpqvzui",
    # The AppSync URL that accepts the access token to return Sleep Records
    "graphql_url": "https://graphql.myair-prd.dht.live/graphql",
    # Redirect url for browser to go to once authentication is complete. Must be the same as what is defined by Okta
    "oauth_redirect_url": "https://myair.resmed.com",
}

OAUTH_URLS: Mapping[str, Any] = {
    # The Initial Auth Okta Endpoint where the username/password goes.
    # If MFA not needed, will give sessionToken. If MFA, will give stateToken
    "authn_url": "https://{okta_url}/api/v1/authn",
    # The url to trigger and verify the Email MFA passcode. Uses stateToken from authn.
    # Gives sessionToken once verified
    "mfa_url": "https://{okta_url}/api/v1/authn/factors/{email_factor_id}/verify?rememberDevice=true",
    # Authorization endpoint to send sessionToken to in order to get 'code'.
    "authorize_url": "https://{okta_url}/oauth2/{auth_server_id}/v1/authorize",
    # The endpoint that the 'code' is sent to get an access token
    "token_url": "https://{okta_url}/oauth2/{auth_server_id}/v1/token",
    # Checks the access token to see if it is still active or not
    "introspect_url": "https://{okta_url}/oauth2/{auth_server_id}/v1/introspect",
    # Uses the access token to return ResMed user info
    "userinfo_url": "https://{okta_url}/oauth2/{auth_server_id}/v1/userinfo",
}


class RESTClient(MyAirClient):
    """myAir uses oauth on Okta and AWS AppSync GraphQL."""

    def __init__(self, config: MyAirConfig, session: ClientSession) -> None:
        """Initialize REST Client."""
        _LOGGER.debug("[RESTClient init] config: %s", redact_dict(config._asdict()))
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
        if self._config.region == REGION_NA:
            self._region_config: Mapping[str, Any] = NA_CONFIG
        else:
            self._region_config = EU_CONFIG
        self._email_factor_id: str = self._region_config["email_factor_id"]
        self._mfa_url: str = OAUTH_URLS["mfa_url"].format(
            okta_url=self._region_config["okta_url"],
            email_factor_id=self._email_factor_id,
        )

    @property
    def device_token(self) -> str | None:
        """Return the device token."""
        return self._cookie_dt

    @property
    def _cookies(self) -> dict[str, Any]:
        cookies: dict[str, Any] = {}
        if self._cookie_dt:
            cookies["DT"] = self._cookie_dt
        if self._cookie_sid:
            cookies["sid"] = self._cookie_sid
        # _LOGGER.debug(f"[cookies] returning cookies: {cookies}")
        return cookies

    async def connect(self, initial: bool | None = False) -> str:
        """Check authn and connect to ResMed servers."""
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
        """Confirm valid MFA and obtain access token."""
        status: str = await self._verify_mfa(verification_code)
        if status == AUTHN_SUCCESS:
            await self._get_access_token()
        else:
            raise AuthenticationError(f"Issue verifying MFA. Status: {status}")
        return status

    async def is_email_verified(self) -> bool:
        """Check if email address is verified."""
        userinfo_url: str = OAUTH_URLS["userinfo_url"].format(
            okta_url=self._region_config["okta_url"],
            auth_server_id=self._region_config["auth_server_id"],
        )

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
            await RESTClient._resmed_response_error_check(
                "userinfo_query", userinfo_res, userinfo_dict
            )

        if userinfo_dict.get("email_verified") is True:
            return True
        return False

    async def _extract_and_update_cookies(self, cookie_headers: list) -> None:
        cookies: dict[str, Any] = {}
        for header in cookie_headers:
            cookie = SimpleCookie(header)
            for key, morsel in cookie.items():
                if key.lower() in {"dt", "sid"}:
                    cookies[key] = morsel.value
        _LOGGER.debug("[extract_and_update_cookies] extracted cookies: %s", cookies)

        if cookies.get("DT") and cookies.get("DT") != self._cookie_dt:
            if self._cookie_dt is not None:
                _LOGGER.warning(
                    "Changing Device Token from: %s, to: %s", self._cookie_dt, cookies.get("DT")
                )
            self._cookie_dt = cookies.get("DT", self._cookie_dt)
        if cookies.get("sid") and cookies.get("sid") != self._cookie_sid:
            if self._cookie_sid is not None:
                _LOGGER.info("Updating to new sid cookie")
            self._cookie_sid = cookies.get("sid", self._cookie_sid)
        _LOGGER.debug("[extract_and_update_cookies] updated cookies: %s", self._cookies)

    async def _get_initial_dt(self) -> None:
        initial_dt_url: str = OAUTH_URLS["authorize_url"].format(
            okta_url=self._region_config["okta_url"],
            auth_server_id=self._region_config["auth_server_id"],
        )
        _LOGGER.debug("[get_initial_dt] initial_dt_url: %s", initial_dt_url)
        _LOGGER.debug("[get_initial_dt] headers: %s", redact_dict(self._json_headers))

        async with (
            self._session.get(
                initial_dt_url,
                headers=self._json_headers,
                raise_for_status=False,  # This will likely return a 400 which is ok. Just need the device token.
                allow_redirects=False,
            ) as initial_dt_res
        ):
            _LOGGER.debug("[get_initial_dt] initial_dt_res: %s", initial_dt_res)

        await self._extract_and_update_cookies(initial_dt_res.headers.getall("set-cookie", []))

    async def _is_access_token_active(self) -> bool:
        introspect_url: str = OAUTH_URLS["introspect_url"].format(
            okta_url=self._region_config["okta_url"],
            auth_server_id=self._region_config["auth_server_id"],
        )

        headers: dict[str, Any] = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        introspect_query: dict[str, Any] = {
            "client_id": self._region_config["authorize_client_id"],
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
            await RESTClient._resmed_response_error_check(
                "introspect_query", introspect_res, introspect_dict
            )
        if introspect_dict.get("active") is True:
            _LOGGER.info("Existing Access Token is already active. Reusing")
            return True
        return False

    @staticmethod
    async def _resmed_response_error_check(
        step: str,
        response: ClientResponse,
        resp_dict: MutableMapping[str, Any],
        initial: bool | None = False,
    ) -> None:
        if "errors" in resp_dict:
            try:
                error_message: str = f"{resp_dict['errors'][0]['errorInfo']['errorType']}: {resp_dict['errors'][0]['errorInfo']['errorCode']}"
                if resp_dict["errors"][0]["errorInfo"]["errorType"] == "unauthorized":
                    if step == "gql_query" and not initial:
                        raise ParsingError(
                            f"Getting unauthorized error on {step} step. {error_message}"
                        )
                    raise AuthenticationError(
                        f"Getting unauthorized error on {step} step. {error_message}"
                    )
                if resp_dict["errors"][0]["errorInfo"]["errorType"] == "badRequest" and resp_dict[
                    "errors"
                ][0]["errorInfo"]["errorCode"] in {
                    "onboardingFlowInProgress",
                    "equipmentNotAssigned",
                }:
                    raise IncompleteAccountError(f"{error_message}")
            except TypeError:
                error_message = "Error"
            raise HttpProcessingError(
                code=response.status,
                message=f"{step} step: {error_message}. {resp_dict})",
                headers=CIMultiDict(response.headers),
            )

    async def _authn_check(self) -> str:
        authn_url: str = OAUTH_URLS["authn_url"].format(okta_url=self._region_config["okta_url"])
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
            _LOGGER.debug("[authn_check] authn_dict: %s", redact_dict(authn_dict))
            await RESTClient._resmed_response_error_check("authn", authn_res, authn_dict)
        if "status" not in authn_dict:
            raise AuthenticationError("Cannot get status in authn step")
        status: str = authn_dict["status"]
        if status == AUTH_NEEDS_MFA:
            if "stateToken" not in authn_dict:
                raise AuthenticationError("Cannot get stateToken in authn step")
            self._state_token = authn_dict["stateToken"]
            try:
                self._email_factor_id = authn_dict["_embedded"]["factors"][0]["id"]
            except (KeyError, TypeError):
                self._email_factor_id = self._region_config["email_factor_id"]
            _LOGGER.debug("[authn_check] email_factor_id: %s", self._email_factor_id)
            try:
                self._mfa_url = f"{authn_dict['_embedded']['factors'][0]['_links']['verify']['href']}?rememberDevice=true"
            except (KeyError, TypeError):
                self._mfa_url = OAUTH_URLS["mfa_url"].format(
                    okta_url=self._region_config["okta_url"],
                    email_factor_id=self._email_factor_id,
                )
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
        json_query: dict[str, Any] = {"passCode": "", "stateToken": self._state_token}
        _LOGGER.debug("[trigger_mfa] mfa_url: %s", self._mfa_url)
        _LOGGER.debug("[trigger_mfa] headers: %s", redact_dict(self._json_headers))
        _LOGGER.debug("[trigger_mfa] json_query: %s", redact_dict(json_query))

        async with self._session.post(
            self._mfa_url,
            headers=self._json_headers,
            json=json_query,
            cookies=self._cookies,
        ) as trigger_mfa_res:
            _LOGGER.debug("[trigger_mfa] trigger_mfa_res: %s", trigger_mfa_res)
            trigger_mfa_dict: MutableMapping[str, Any] = await trigger_mfa_res.json()
            _LOGGER.debug("[trigger_mfa] trigger_mfa_dict: %s", redact_dict(trigger_mfa_dict))
            await RESTClient._resmed_response_error_check(
                "trigger_mfa", trigger_mfa_res, trigger_mfa_dict
            )
        _LOGGER.info("Triggered MFA Email")

    async def _verify_mfa(self, verification_code: str) -> str:
        _LOGGER.debug("[verify_mfa] verification_code: %s", verification_code)

        json_query: dict[str, Any] = {
            "passCode": verification_code,
            "stateToken": self._state_token,
        }
        _LOGGER.debug("[verify_mfa] mfa_url: %s", self._mfa_url)
        _LOGGER.debug("[verify_mfa] headers: %s", redact_dict(self._json_headers))
        _LOGGER.debug("[verify_mfa] json_query: %s", json_query)

        async with self._session.post(
            self._mfa_url,
            headers=self._json_headers,
            json=json_query,
            cookies=self._cookies,
        ) as verify_mfa_res:
            _LOGGER.debug("[verify_mfa] verify_mfa_res: %s", verify_mfa_res)
            verify_mfa_dict: MutableMapping[str, Any] = await verify_mfa_res.json()
            _LOGGER.debug("[verify_mfa] verify_mfa_dict: %s", redact_dict(verify_mfa_dict))
            await RESTClient._resmed_response_error_check(
                "verify_mfa", verify_mfa_res, verify_mfa_dict
            )
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
        # myAir uses Authorization Code with PKCE, so we generate our verifier here
        code_verifier: str = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8")
        code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)
        _LOGGER.debug("[get_access_token] code_verifier: %s", code_verifier)

        code_challenge_digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge: str = base64.urlsafe_b64encode(code_challenge_digest).decode("utf-8")
        code_challenge = code_challenge.replace("=", "")
        _LOGGER.debug("[get_access_token] code_challenge: %s", code_challenge)

        # We use that sessionToken and exchange for an oauth code, using PKCE
        authorize_url: str = OAUTH_URLS["authorize_url"].format(
            okta_url=self._region_config["okta_url"],
            auth_server_id=self._region_config["auth_server_id"],
        )
        params_query: dict[str, Any] = {
            "client_id": self._region_config["authorize_client_id"],
            # For PKCE
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "prompt": "none",
            "redirect_uri": self._region_config["oauth_redirect_url"],
            "response_mode": "fragment",
            "response_type": "code",
            "sessionToken": self._session_token,
            "scope": "openid profile email",
            "state": "abcdef",
        }
        _LOGGER.debug("[get_access_token code] authorize_url: %s", authorize_url)
        _LOGGER.debug("[get_access_token code] headers: %s", redact_dict(self._json_headers))
        _LOGGER.debug("[get_access_token code] params_query: %s", redact_dict(params_query))

        async with self._session.get(
            authorize_url,
            headers=self._json_headers,
            allow_redirects=False,
            params=params_query,
            cookies=self._cookies,
        ) as code_res:
            _LOGGER.debug("[get_access_token] code_res: %s", code_res)
            _LOGGER.debug("[get_access_token] code_res.headers: %s", code_res.headers)
            location = code_res.headers.get("location")
            if location is None:
                raise ParsingError("Unable to get location from code_res")
        fragment: DefragResult = urldefrag(location)
        _LOGGER.debug("[get_access_token code] fragment: %s", fragment)
        # Pull the code out of the location header fragment
        code: list[str] = parse_qs(fragment.fragment)["code"]
        _LOGGER.debug("[get_access_token] code: %s", code)

        await self._extract_and_update_cookies(code_res.headers.getall("set-cookie", []))

        # Now we change the code for an access token
        # requests defaults to forms, which is what /token needs, so we don't use our api_session from above
        token_query: dict[str, Any] = {
            "client_id": self._region_config["authorize_client_id"],
            "redirect_uri": self._region_config["oauth_redirect_url"],
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
            "code": code,
        }
        headers: dict[str, Any] = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        token_url: str = OAUTH_URLS["token_url"].format(
            okta_url=self._region_config["okta_url"],
            auth_server_id=self._region_config["auth_server_id"],
        )
        _LOGGER.debug("[get_access_token token] token_url: %s", token_url)
        _LOGGER.debug("[get_access_token token] headers: %s", redact_dict(headers))
        _LOGGER.debug("[get_access_token token] token_query: %s", redact_dict(token_query))

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
            await RESTClient._resmed_response_error_check("get_access_token", token_res, token_dict)
            if "access_token" not in token_dict:
                raise ParsingError("access_token not in token_dict")
            if "id_token" not in token_dict:
                raise ParsingError("id_token not in token_dict")
            self._id_token = token_dict["id_token"]
            if token_dict.get("access_token") and self._access_token != token_dict.get(
                "access_token"
            ):
                if self._access_token is not None:
                    _LOGGER.info("Obtained new access token")
                self._access_token = token_dict.get("access_token", self._access_token)

    async def _gql_query(
        self, operation_name: str, query: str, initial: bool | None = False
    ) -> MutableMapping[str, Any]:
        _LOGGER.debug("[gql_query] operation_name: %s, query: %s", operation_name, query)
        authz_header: str = f"Bearer {self._access_token}"
        # _LOGGER.debug(f"[gql_query] authz_header: {authz_header}")

        if not self._country_code and self._id_token:
            # We trust this JWT because it is myAir giving it to us
            # So we can pull the middle piece out, which is the payload, and turn it to json
            try:
                jwt_data: MutableMapping[str, Any] = jwt.decode(
                    self._id_token, options={"verify_signature": False}
                )
            except Exception as e:
                _LOGGER.error("Error decoding id_token into jwt_data. %s: %s", type(e).__name__, e)
                raise ParsingError("Unable to decode id_token into jwt_data") from e
            _LOGGER.debug("[gql_query] jwt_data: %s", redact_dict(jwt_data))

            # The graphql API only works properly if we provide the expected country code
            # The rest of the parameters are required, but don't seem to be further validated
            if "myAirCountryId" not in jwt_data:
                _LOGGER.error("myAirCountryId not found in jwt_data")
                raise ParsingError("myAirCountryId not found in jwt_data")
            self._country_code = jwt_data["myAirCountryId"]
            _LOGGER.info("Country Code: %s", self._country_code)
        if not self._country_code:
            _LOGGER.error("country_code not defined and id_token not present to identify it")
            raise ParsingError("country_code not defined and id_token not present to identify it")
        _LOGGER.debug("[gql_query] country_code: %s", self._country_code)

        graphql_url: str = self._region_config["graphql_url"]
        headers: dict[str, Any] = {
            "x-api-key": self._region_config["myair_api_key"],
            "Authorization": authz_header,
            # There are a bunch of resmed headers sent to this API that seem to be required
            # Unsure if this is ever validated/can break things if these values change
            "rmdhandsetid": "02c1c662-c289-41fd-a9ae-196ff15b5166",
            "rmdlanguage": "en",
            "rmdhandsetmodel": "Chrome",
            "rmdhandsetosversion": "127.0.6533.119",
            "rmdproduct": self._region_config["product"],
            "rmdappversion": "1.0.0",
            "rmdhandsetplatform": "Web",
            "rmdcountry": self._country_code,
            "accept-language": "en-US,en;q=0.9",
        }
        json_query: dict[str, Any] = {
            "operationName": operation_name,
            "variables": {},
            "query": query,
        }
        _LOGGER.debug("[gql_query] graphql_url: %s", graphql_url)
        _LOGGER.debug("[gql_query] headers: %s", redact_dict(headers))
        _LOGGER.debug("[gql_query] json_query: %s", redact_dict(json_query))

        async with self._session.post(
            graphql_url,
            headers=headers,
            json=json_query,
        ) as records_res:
            _LOGGER.debug("[gql_query] records_res: %s", records_res)
            records_dict: MutableMapping[str, Any] = await records_res.json()
            _LOGGER.debug("[gql_query] records_dict: %s", redact_dict(records_dict))
            await RESTClient._resmed_response_error_check(
                "gql_query", records_res, records_dict, initial
            )

        return records_dict

    async def get_sleep_records(self, initial: bool | None = False) -> list[Mapping[str, Any]]:
        """Get sleep records from ResMed servers."""
        today: str = datetime.datetime.now().strftime("%Y-%m-%d")
        one_month_ago: str = (datetime.datetime.now() - datetime.timedelta(days=30)).strftime(
            "%Y-%m-%d"
        )

        query: str = """query GetPatientSleepRecords {
            getPatientWrapper {
                patient {
                    firstName
                }
                sleepRecords(startMonth: \"ONE_MONTH_AGO\", endMonth: \"DATE\")
                {
                    items {
                        startDate
                        totalUsage
                        sleepScore
                        usageScore
                        ahiScore
                        maskScore
                        leakScore
                        ahi
                        maskPairCount
                        leakPercentile
                        sleepRecordPatientId
                        __typename
                    }
                    __typename
                }
            __typename
            }
        }
        """.replace("ONE_MONTH_AGO", one_month_ago).replace("DATE", today)

        _LOGGER.info("Getting Sleep Records")
        records_dict: MutableMapping[str, Any] = await self._gql_query(
            "GetPatientSleepRecords", query, initial
        )
        _LOGGER.debug("[get_sleep_records] records_dict: %s", redact_dict(records_dict))
        try:
            records: list[Mapping[str, Any]] = records_dict["data"]["getPatientWrapper"][
                "sleepRecords"
            ]["items"]
        except Exception as e:
            _LOGGER.error("Error getting Patient Sleep Records. %s: %s", type(e).__name__, e)
            raise ParsingError("Error getting Patient Sleep Records") from e
        if not isinstance(records, list):
            _LOGGER.error("Error getting Patient Sleep Records. Returned records is not a list")
            raise ParsingError(
                "Error getting Patient Sleep Records. Returned records is not a list"
            )
        _LOGGER.debug("[get_sleep_records] records: %s", redact_dict(records))
        return records

    async def get_user_device_data(self, initial: bool | None = False) -> Mapping[str, Any]:
        """Get user device data from ResMed servers."""
        query: str = """
        query getPatientWrapper {
            getPatientWrapper {
                fgDevices {
                    serialNumber
                    deviceType
                    lastSleepDataReportTime
                    localizedName
                    fgDeviceManufacturerName
                    fgDevicePatientId
                    __typename
                }
            }
        }
        """

        _LOGGER.info("Getting User Device Data")
        records_dict: MutableMapping[str, Any] = await self._gql_query(
            "getPatientWrapper", query, initial
        )
        _LOGGER.debug("[get_user_device_data] records_dict: %s", redact_dict(records_dict))
        try:
            device: Mapping[str, Any] = records_dict["data"]["getPatientWrapper"]["fgDevices"][0]
        except Exception as e:
            _LOGGER.error("Error getting User Device Data. %s: %s", type(e).__name__, e)
            raise ParsingError("Error getting User Device Data") from e
        if not isinstance(device, dict):
            _LOGGER.error("Error getting User Device Data. Returned data is not a dict")
            raise ParsingError("Error getting User Device Data. Returned data is not a dict")
        _LOGGER.debug("[get_user_device_data] device: %s", redact_dict(device))
        return device
