import base64
import datetime
import hashlib
import logging
import os
import re
from typing import Any, List
from urllib.parse import parse_qs, urldefrag

from aiohttp import ClientResponse, ClientSession
from aiohttp.client_exceptions import ClientResponseError
from aiohttp.http_exceptions import HttpProcessingError
from homeassistant.helpers.redact import async_redact_data
import jwt

from custom_components.resmed_myair.common import CONF_COUNTRY_CODE, KEYS_TO_REDACT

from .myair_client import (
    AuthenticationError,
    IncompleteAccountError,
    MyAirClient,
    MyAirConfig,
    MyAirDevice,
    ParsingError,
    SleepRecord,
)

_LOGGER = logging.getLogger(__name__)

NA_CONFIG = {
    # This is the clientId that appears in Okta URLs
    "authn_client_id": "aus4ccsxvnidQgLmA297",
    # This is the clientId that appears in request bodies during login
    "authorize_client_id": "0oa4ccq1v413ypROi297",
    # Used as the x-api-key header for the AppSync GraphQL API
    "myair_api_key": "da2-cenztfjrezhwphdqtwtbpqvzui",
    # The Okta Endpoint where the creds go
    "authn_url": "https://resmed-ext-1.okta.com/api/v1/authn",
    # When specifying token_url and authorize_url, add {authn_client_id} and your authn_client_id will be substituted in
    # Or you can put the entire URL here if you want, but your authn_client_id will be ignored
    "authorize_url": "https://resmed-ext-1.okta.com/oauth2/{authn_client_id}/v1/authorize",
    # The endpoint that the 'code' is sent to get an authorization token
    "token_url": "https://resmed-ext-1.okta.com/oauth2/{authn_client_id}/v1/token",
    # The AppSync URL that accepts your token + the API key to return Sleep Records
    "appsync_url": "https://graphql.myair-prd.dht.live/graphql",
    # Unsure if this needs to be regionalized, it is almost certainly something that is configured inside of an Okta allowlist
    "oauth_redirect_url": "https://myair.resmed.com",
}


class RESTNAClient(MyAirClient):
    """
    This client is currently used in the US.
    In the US, myAir uses oauth on Okta and AWS AppSync GraphQL
    """

    def __init__(self, config: MyAirConfig, session: ClientSession):
        assert (
            config.region == "NA"
        ), "REST client used outside NA, this should not happen. Please file a bug"
        self._json_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self._config: MyAirConfig = config
        self._session: ClientSession = session
        self._country_code = (
            self._config.country_code if self._config.country_code else None
        )
        self._access_token = None
        self._id_token = None
        self._config = config
        self._session = session

    async def connect(self):
        # for connect, let's login and store the access token
        await self.get_access_token()

    async def _resmed_response_error_check(
        self, step: str, response: ClientResponse, resp_dict: dict
    ):
        if "errors" in resp_dict:
            try:
                error_message = f"{resp_dict['errors'][0]['errorInfo']['errorType']}: {resp_dict['errors'][0]['errorInfo']['errorCode']}"
                if resp_dict["errors"][0]["errorInfo"]["errorType"] == "unauthorized":
                    raise AuthenticationError(
                        f"Getting unauthorized error on {step} step. {error_message}"
                    )
                if (
                    resp_dict["errors"][0]["errorInfo"]["errorType"] == "badRequest"
                    and resp_dict["errors"][0]["errorInfo"]["errorCode"]
                    == "onboardingFlowInProgress"
                ):
                    raise IncompleteAccountError(f"{error_message}")
            except TypeError:
                error_message = "Error"
                pass
            raise HttpProcessingError(
                code=response.status,
                message=f"{step} step: {error_message}. {resp_dict})",
                headers=response.headers,
            )

    async def get_access_token(self) -> str:
        """
        Call this to refresh the access token
        """
        authn_url = NA_CONFIG["authn_url"]
        json_query = {
            "username": self._config.username,
            "password": self._config.password,
        }

        _LOGGER.debug(f"[get_access_token authn] authn_url: {authn_url}")
        _LOGGER.debug(
            f"[get_access_token authn] headers: {async_redact_data(self._json_headers, KEYS_TO_REDACT)}"
        )
        _LOGGER.debug(
            f"[get_access_token authn] json_query: {async_redact_data(json_query, KEYS_TO_REDACT)}"
        )

        async with self._session.post(
            authn_url,
            headers=self._json_headers,
            json=json_query,
        ) as authn_res:
            _LOGGER.debug(f"[get_access_token] authn_res: {authn_res}")
            authn_dict = await authn_res.json()
            _LOGGER.debug(
                f"[get_access_token] authn_dict: {async_redact_data(authn_dict, KEYS_TO_REDACT)}"
            )

        # We've exchanged our user/pass for a session token
        if "sessionToken" not in authn_dict:
            raise AuthenticationError("Cannot get sessionToken in authn step")
        session_token = authn_dict["sessionToken"]
        # expires_at = authn_dict["expiresAt"]

        # myAir uses Authorization Code with PKCE, so we generate our verifier here
        code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8")
        code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)

        code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
        code_challenge = code_challenge.replace("=", "")

        # We use that sessionToken and exchange for an oauth code, using PKCE
        authorize_url = NA_CONFIG["authorize_url"].format(
            authn_client_id=NA_CONFIG["authn_client_id"]
        )

        params_query = {
            "client_id": NA_CONFIG["authorize_client_id"],
            # For PKCE
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "prompt": "none",
            "redirect_uri": NA_CONFIG["oauth_redirect_url"],
            "response_mode": "fragment",
            "response_type": "code",
            "sessionToken": session_token,
            "scope": "openid profile email",
            "state": "abcdef",
        }

        _LOGGER.debug(f"[get_access_token code] authorize_url: {authorize_url}")
        _LOGGER.debug(
            f"[get_access_token code] headers: {async_redact_data(self._json_headers, KEYS_TO_REDACT)}"
        )
        _LOGGER.debug(
            f"[get_access_token code] params_query: {async_redact_data(params_query, KEYS_TO_REDACT)}"
        )

        async with self._session.get(
            authorize_url,
            headers=self._json_headers,
            allow_redirects=False,
            params=params_query,
        ) as code_res:
            _LOGGER.debug(f"[get_access_token] code_res: {code_res}")
            location = code_res.headers["location"]
            _LOGGER.debug(f"[get_access_token] location: {location}")
        fragment = urldefrag(location)
        _LOGGER.debug(f"[get_access_token] fragment: {fragment}")
        # Pull the code out of the location header fragment
        code = parse_qs(fragment.fragment)["code"]
        _LOGGER.debug(f"[get_access_token] code: {code}")

        # Now we change the code for an access token
        # requests defaults to forms, which is what /token needs, so we don't use our api_session from above
        token_query = {
            "client_id": NA_CONFIG["authorize_client_id"],
            "redirect_uri": NA_CONFIG["oauth_redirect_url"],
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
            "code": code,
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        token_url = NA_CONFIG["token_url"].format(
            authn_client_id=NA_CONFIG["authn_client_id"]
        )

        _LOGGER.debug(f"[get_access_token token] token_url: {token_url}")
        _LOGGER.debug(
            f"[get_access_token token] headers: {async_redact_data(headers, KEYS_TO_REDACT)}"
        )
        _LOGGER.debug(
            f"[get_access_token token] token_query: {async_redact_data(token_query, KEYS_TO_REDACT)}"
        )

        async with self._session.post(
            token_url,
            headers=headers,
            data=token_query,
            allow_redirects=False,
        ) as token_res:
            if token_res.ok:
                _LOGGER.debug(f"[get_access_token] token_res: {token_res}")
                token_dict = await token_res.json()
                _LOGGER.debug(
                    f"[get_access_token] token_dict: {async_redact_data(token_dict, KEYS_TO_REDACT)}"
                )
                await self._resmed_response_error_check(
                    "get_access_token", token_res, token_dict
                )
                if "access_token" not in token_dict:
                    raise ParsingError("access_token not in token_dict")
                if "id_token" not in token_dict:
                    raise ParsingError("id_token not in token_dict")
                self._access_token = token_dict["access_token"]
                self._id_token = token_dict["id_token"]
                # _LOGGER.debug(f"[get_access_token] access_token: {self._access_token}")
                # _LOGGER.debug(f"[get_access_token] id_token: {self._id_token}")
            else:
                raise ClientResponseError(
                    f"Get Access Token Connection Issue. Status {token_res.status} {token_res.message}"
                )

    async def gql_query(self, operation_name: str, query: str) -> Any:
        _LOGGER.debug(f"[gql_query] operation_name: {operation_name}, query: {query}")
        authz_header = f"Bearer {self._access_token}"
        # _LOGGER.debug(f"[gql_query] authz_header: {authz_header}")

        if not self._country_code and self._id_token:
            # We trust this JWT because it is myAir giving it to us
            # So we can pull the middle piece out, which is the payload, and turn it to json
            try:
                jwt_data = jwt.decode(
                    self._id_token, options={"verify_signature": False}
                )
            except Exception as e:
                _LOGGER.error(
                    f"Error decoding id_token into jwt_data. {e.__class__.__qualname__}: {e}"
                )
                raise ParsingError("Unable to decode id_token into jwt_data") from e
            _LOGGER.debug(
                f"[gql_query] jwt_data: {async_redact_data(jwt_data, KEYS_TO_REDACT)}"
            )

            # The graphql API only works properly if we provide the expected country code
            # The rest of the paramters are required, but don't seem to be further validated
            if "myAirCountryId" not in jwt_data:
                raise ParsingError("myAirCountryId not found in jwt_data")
            self._country_code = jwt_data["myAirCountryId"]
            _LOGGER.info(f"Country Code: {self._country_code}")
        if not self._country_code:
            raise ParsingError(
                "country_code not defined and id_token not present to identify it"
            )
        _LOGGER.debug(f"[gql_query] country_code: {self._country_code}")

        appsync_url = NA_CONFIG["appsync_url"]
        headers = {
            "x-api-key": NA_CONFIG["myair_api_key"],
            "Authorization": authz_header,
            # There are a bunch of resmed headers sent to this API that seem to be required
            # Unsure if this is ever validated/can break things if these values change
            "rmdhandsetid": "02c1c662-c289-41fd-a9ae-196ff15b5166",
            "rmdlanguage": "en",
            "rmdhandsetmodel": "Chrome",
            "rmdhandsetosversion": "127.0.6533.119",
            "rmdproduct": "myAir",
            "rmdappversion": "2.0.0",
            "rmdhandsetplatform": "Web",
            "rmdcountry": self._country_code,
            "accept-language": "en-US,en;q=0.9",
        }
        json_query = {
            "operationName": operation_name,
            "variables": {},
            "query": query,
        }
        _LOGGER.debug(f"[gql_query] appsync_url: {appsync_url}")
        _LOGGER.debug(
            f"[gql_query] headers: {async_redact_data(headers, KEYS_TO_REDACT)}"
        )
        _LOGGER.debug(
            f"[gql_query] json_query: {async_redact_data(json_query, KEYS_TO_REDACT)}"
        )

        async with self._session.post(
            appsync_url,
            headers=headers,
            json=json_query,
        ) as records_res:
            if records_res.ok:
                _LOGGER.debug(f"[gql_query] records_res: {records_res}")
                records_dict = await records_res.json()
                _LOGGER.debug(
                    f"[gql_query] records_dict: {async_redact_data(records_dict, KEYS_TO_REDACT)}"
                )
                await self._resmed_response_error_check(
                    "gql_query", records_res, records_dict
                )
            else:
                raise ClientResponseError(
                    f"GraphQL Connection Issue. Status {records_res.status} {records_res.message}"
                )
        return records_dict

    async def get_sleep_records(self) -> List[SleepRecord]:

        today = datetime.datetime.now().strftime("%Y-%m-%d")
        one_month_ago = (
            datetime.datetime.now() - datetime.timedelta(days=30)
        ).strftime("%Y-%m-%d")

        query = """query GetPatientSleepRecords {
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
        """.replace(
            "ONE_MONTH_AGO", one_month_ago
        ).replace(
            "DATE", today
        )

        _LOGGER.debug(f"[get_sleep_records] Starting Query")
        records_dict = await self.gql_query("GetPatientSleepRecords", query)
        _LOGGER.debug(
            f"[get_sleep_records] records_dict: {async_redact_data(records_dict, KEYS_TO_REDACT)}"
        )
        try:
            records = records_dict["data"]["getPatientWrapper"]["sleepRecords"]["items"]
        except Exception as e:
            _LOGGER.error(
                f"Error getting Patient Sleep Records. {e.__class__.__qualname__}: {e}"
            )
            raise ParsingError("Error getting Patient Sleep Records") from e
        _LOGGER.debug(
            f"[get_sleep_records] records: {async_redact_data(records, KEYS_TO_REDACT)}"
        )
        return records

    async def get_user_device_data(self) -> MyAirDevice:
        query = """
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

        _LOGGER.debug(f"[get_user_device_data] Starting Query")
        records_dict = await self.gql_query("getPatientWrapper", query)
        _LOGGER.debug(
            f"[get_user_device_data] records_dict: {async_redact_data(records_dict, KEYS_TO_REDACT)}"
        )
        try:
            device = records_dict["data"]["getPatientWrapper"]["fgDevices"][0]
        except Exception as e:
            _LOGGER.error(
                f"Error getting User Device Data. {e.__class__.__qualname__}: {e}"
            )
            raise ParsingError("Error getting User Device Data") from e
        device.update({CONF_COUNTRY_CODE: self._country_code})
        _LOGGER.debug(
            f"[get_user_device_data] device: {async_redact_data(device, KEYS_TO_REDACT)}"
        )
        return device
