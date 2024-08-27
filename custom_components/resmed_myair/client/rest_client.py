import base64
import datetime
import hashlib
import logging
import os
import re
from typing import Any, List
from urllib.parse import parse_qs, urldefrag

from aiohttp import ClientResponse, ClientSession
from aiohttp.http_exceptions import HttpProcessingError
from homeassistant.helpers.redact import async_redact_data
import jwt
from yarl import URL

from custom_components.resmed_myair.const import (
    AUTH_NEEDS_2FA,
    AUTHN_SUCCESS,
    KEYS_TO_REDACT,
    REGION_NA,
)

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

EU_CONFIG = {
    "product": "myAir EU",
    "base_url": "id.resmed.eu",
    # This is the clientId that appears in Okta URLs
    "authn_client_id": "emfg9cmjqxEPr52cT417",
    "oauth2_client_id": "aus2uznux2sYKTsEg417",
    # This is the clientId that appears in request bodies during login
    "authorize_client_id": "0oa2uz04d2Pks2NgR417",
    # Used as the x-api-key header for the AppSync GraphQL API
    "myair_api_key": "da2-o66oo6xdnfh5hlfuw5yw5g2dtm",
    # The Okta Endpoint where the creds go
    "authn_url": "https://id.resmed.eu/api/v1/authn",
    "2fa_url": "https://id.resmed.eu/api/v1/authn/factors/{authn_client_id}/verify?rememberDevice=true",
    # When specifying token_url and authorize_url, add {authn_client_id} and your authn_client_id will be substituted in
    # Or you can put the entire URL here if you want, but your authn_client_id will be ignored
    "authorize_url": "https://id.resmed.eu/oauth2/{oauth2_client_id}/v1/authorize",
    # The endpoint that the 'code' is sent to get an authorization token
    "token_url": "https://id.resmed.eu/oauth2/{oauth2_client_id}/v1/token",
    # The AppSync URL that accepts your token + the API key to return Sleep Records
    "graphql_url": "https://graphql.hyperdrive.resmed.eu/graphql",
    # Unsure if this needs to be regionalized, it is almost certainly something that is configured inside of an Okta allowlist
    "oauth_redirect_url": "https://myair.resmed.eu",
}

NA_CONFIG = {
    "product": "myAir",
    "base_url": "resmed-ext-1.okta.com",
    # This is the clientId that appears in Okta URLs
    "authn_client_id": "aus4ccsxvnidQgLmA297",
    "oauth2_client_id": "aus4ccsxvnidQgLmA297",
    # This is the clientId that appears in request bodies during login
    "authorize_client_id": "0oa4ccq1v413ypROi297",
    # Used as the x-api-key header for the AppSync GraphQL API
    "myair_api_key": "da2-cenztfjrezhwphdqtwtbpqvzui",
    # The Okta Endpoint where the creds go
    "authn_url": "https://resmed-ext-1.okta.com/api/v1/authn",
    "2fa_url": "https://resmed-ext-1.okta.com/api/v1/authn/factors/{authn_client_id}/verify?rememberDevice=true",
    # When specifying token_url and authorize_url, add {authn_client_id} and your authn_client_id will be substituted in
    # Or you can put the entire URL here if you want, but your authn_client_id will be ignored
    "authorize_url": "https://resmed-ext-1.okta.com/oauth2/{oauth2_client_id}/v1/authorize",
    # The endpoint that the 'code' is sent to get an authorization token
    "token_url": "https://resmed-ext-1.okta.com/oauth2/{oauth2_client_id}/v1/token",
    # The AppSync URL that accepts your token + the API key to return Sleep Records
    "graphql_url": "https://graphql.myair-prd.dht.live/graphql",
    # Unsure if this needs to be regionalized, it is almost certainly something that is configured inside of an Okta allowlist
    "oauth_redirect_url": "https://myair.resmed.com",
}


class RESTClient(MyAirClient):
    """
    This client is currently used in the EU.
    In the EU, myAir uses oauth on Okta and AWS AppSync GraphQL
    """

    def __init__(self, config: MyAirConfig, session: ClientSession):
        _LOGGER.debug(
            f"[RESTClient init] config: {async_redact_data(config._asdict(), KEYS_TO_REDACT)}"
        )
        self._config: MyAirConfig = config
        self._session: ClientSession = session
        self._json_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self._country_code = None
        self._access_token = None
        self._id_token = None
        self._state_token = None
        self._session_token = None
        self._cookies = None
        if self._config.region == REGION_NA:
            self._static_config = NA_CONFIG
        else:
            self._static_config = EU_CONFIG
        self._authn_client_id = self._static_config["authn_client_id"]
        self._2fa_url = self._static_config["2fa_url"].format(
            authn_client_id=self._authn_client_id
        )

    @property
    def cookies(self):
        return self._cookies

    async def load_cookies(self, cookies):
        self._cookies = cookies
        _LOGGER.debug(f"[load_cookies] cookies to load: {self._cookies}")
        cookie_url = URL(f"https://{self._static_config['base_url']}")
        self._session.cookie_jar.update_cookies(self._cookies)
        _LOGGER.debug("[load_cookies] All Loaded Cookies:")
        for cookie in self._session.cookie_jar:
            _LOGGER.debug(f"{cookie}")
        _LOGGER.debug(
            f"[load_cookies] loaded cookies for {cookie_url}: {self._session.cookie_jar.filter_cookies(cookie_url)}"
        )

    async def connect(self, initial=False):
        # Thought process:
        # Check authn
        #     if success:
        #         use sessionToken to get_acces_token
        #     if mfa_required:
        #         use stateToken
        #         if initial setup:
        #             trigger 2FA
        #             return that 2FA required
        #         elseif update:
        #             trigger reauth

        # ToDo:
        # - Keep client from config_flow to coordinator - Not working
        # - Save cookies even across restart (save in config_entry)

        status = await self.authn_check()
        if status == AUTH_NEEDS_2FA:
            if initial:
                await self.trigger_2fa()
            else:
                raise AuthenticationError(f"Need to Re-Verify 2FA")
        else:
            await self.get_access_token()
        return status

    async def verify_2fa_and_get_access_token(self, verification_code) -> str:
        status = await self.verify_2fa(verification_code)
        if status == AUTHN_SUCCESS:
            await self.get_access_token()
        else:
            raise AuthenticationError(f"Issue verifying 2FA. Status: {status}")
        return status

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

    async def authn_check(self) -> str:
        authn_url = self._static_config["authn_url"]
        json_query = {
            "username": self._config.username,
            "password": self._config.password,
        }
        _LOGGER.debug(f"[authn_check] authn_url: {authn_url}")
        _LOGGER.debug(
            f"[authn_check] headers: {async_redact_data(self._json_headers, KEYS_TO_REDACT)}"
        )
        _LOGGER.debug(
            f"[authn_check] json_query: {async_redact_data(json_query, KEYS_TO_REDACT)}"
        )

        async with self._session.post(
            authn_url,
            headers=self._json_headers,
            json=json_query,
            cookies=self._cookies,
        ) as authn_res:
            _LOGGER.debug(f"[authn_check] authn_res: {authn_res}")
            authn_dict = await authn_res.json()
            _LOGGER.debug(
                f"[authn_check] authn_dict: {async_redact_data(authn_dict, KEYS_TO_REDACT)}"
            )
            await self._resmed_response_error_check("authn", authn_res, authn_dict)
        if "status" not in authn_dict:
            raise AuthenticationError("Cannot get status in authn step")
        status = authn_dict["status"]
        if status == AUTH_NEEDS_2FA:
            if "stateToken" not in authn_dict:
                raise AuthenticationError("Cannot get stateToken in authn step")
            self._state_token = authn_dict["stateToken"]
            try:
                self._authn_client_id = authn_dict["_embedded"]["factors"][0]["id"]
            except Exception:
                self._authn_client_id = self._static_config["authn_client_id"]
            _LOGGER.debug(f"[authn_check] authn_client_id: {self._authn_client_id}")
            try:
                self._2fa_url = f"{authn_dict['_embedded']['factors'][0]['_links']['verify']['href']}?rememberDevice=true"
            except Exception:
                self._2fa_url = self._static_config["2fa_url"].format(
                    authn_client_id=self._authn_client_id
                )
            _LOGGER.debug(f"[authn_check] 2fa_url: {self._2fa_url}")
        elif status == AUTHN_SUCCESS:
            if "sessionToken" not in authn_dict:
                raise AuthenticationError("Cannot get sessionToken in authn step")
            self._session_token = authn_dict["sessionToken"]
        else:
            raise AuthenticationError(f"Unknown status in authn step: {status}")
        return status

    async def trigger_2fa(self):
        json_query = {"passCode": "", "stateToken": self._state_token}
        _LOGGER.debug(f"[trigger_2fa] 2fa_url: {self._2fa_url}")
        _LOGGER.debug(
            f"[trigger_2fa] headers: {async_redact_data(self._json_headers, KEYS_TO_REDACT)}"
        )
        _LOGGER.debug(
            f"[trigger_2fa] json_query: {async_redact_data(json_query, KEYS_TO_REDACT)}"
        )

        async with self._session.post(
            self._2fa_url,
            headers=self._json_headers,
            json=json_query,
            cookies=self._cookies,
        ) as trigger_2fa_res:
            _LOGGER.debug(f"[trigger_2fa] trigger_2fa_res: {trigger_2fa_res}")
            trigger_2fa_dict = await trigger_2fa_res.json()
            _LOGGER.debug(
                f"[trigger_2fa] trigger_2fa_dict: {async_redact_data(trigger_2fa_dict, KEYS_TO_REDACT)}"
            )
            await self._resmed_response_error_check(
                "trigger_2fa", trigger_2fa_res, trigger_2fa_dict
            )

    async def verify_2fa(self, verification_code: str) -> str:
        _LOGGER.debug(f"[verify_2fa] verification_code: {verification_code}")

        json_query = {"passCode": verification_code, "stateToken": self._state_token}
        _LOGGER.debug(f"[verify_2fa] 2fa_url: {self._2fa_url}")
        _LOGGER.debug(
            f"[verify_2fa] headers: {async_redact_data(self._json_headers, KEYS_TO_REDACT)}"
        )
        _LOGGER.debug(f"[verify_2fa] json_query: {json_query}")

        async with self._session.post(
            self._2fa_url,
            headers=self._json_headers,
            json=json_query,
            cookies=self._cookies,
        ) as verify_2fa_res:
            _LOGGER.debug(f"[verify_2fa] verify_2fa_res: {verify_2fa_res}")
            verify_2fa_dict = await verify_2fa_res.json()
            _LOGGER.debug(
                f"[verify_2fa] verify_2fa_dict: {async_redact_data(verify_2fa_dict, KEYS_TO_REDACT)}"
            )
            await self._resmed_response_error_check(
                "verify_2fa", verify_2fa_res, verify_2fa_dict
            )
        if "status" not in verify_2fa_dict:
            raise AuthenticationError("Cannot get status in authn step")
        status = verify_2fa_dict["status"]
        if status == AUTHN_SUCCESS:
            # We've exchanged our user/pass for a session token
            if "sessionToken" not in verify_2fa_dict:
                raise AuthenticationError("Cannot get sessionToken in verify_2fa step")
            self._session_token = verify_2fa_dict["sessionToken"]
        else:
            raise AuthenticationError(f"Unknown status in authn step: {status}")
        return status

    async def get_access_token(self) -> str:

        # myAir uses Authorization Code with PKCE, so we generate our verifier here
        code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8")
        code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)
        _LOGGER.debug(f"[get_access_token] code_verifier: {code_verifier}")

        code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
        code_challenge = code_challenge.replace("=", "")
        _LOGGER.debug(f"[get_access_token] code_challenge: {code_challenge}")

        # We use that sessionToken and exchange for an oauth code, using PKCE
        authorize_url = self._static_config["authorize_url"].format(
            oauth2_client_id=self._static_config["oauth2_client_id"]
        )
        params_query = {
            "client_id": self._static_config["authorize_client_id"],
            # For PKCE
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "prompt": "none",
            "redirect_uri": self._static_config["oauth_redirect_url"],
            "response_mode": "fragment",
            "response_type": "code",
            "sessionToken": self._session_token,
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
            cookies=self._cookies,
        ) as code_res:
            _LOGGER.debug(f"[get_access_token] code_res: {code_res}")
            if "location" not in code_res.headers:
                raise ParsingError("Unable to get location from code_res")
            location = code_res.headers["location"]
            _LOGGER.debug(f"[get_access_token code] location: {location}")

        fragment = urldefrag(location)
        _LOGGER.debug(f"[get_access_token code] fragment: {fragment}")
        # Pull the code out of the location header fragment
        code = parse_qs(fragment.fragment)["code"]
        _LOGGER.debug(f"[get_access_token] code: {code}")

        # Now we change the code for an access token
        # requests defaults to forms, which is what /token needs, so we don't use our api_session from above
        token_query = {
            "client_id": self._static_config["authorize_client_id"],
            "redirect_uri": self._static_config["oauth_redirect_url"],
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
            "code": code,
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        token_url = self._static_config["token_url"].format(
            oauth2_client_id=self._static_config["oauth2_client_id"]
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
            cookies=self._cookies,
        ) as token_res:
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

        cookie_dict = {}
        for cookie in self._session.cookie_jar:
            cookie_dict.update({cookie.key: cookie.value})
        _LOGGER.debug(f"[get_access_token token] post-token cookie_dict: {cookie_dict}")
        if self._cookies is None:
            cookie_dict.pop("JSESSIONID", None)
            cookie_dict.pop("t", None)
            _LOGGER.debug(
                f"[get_access_token token] post-token cookie_dict post-cleanup: {cookie_dict}"
            )
            _LOGGER.info("Setting saved cookies")
            self._cookies = cookie_dict
        else:
            _LOGGER.info("Cookies alreay set, not updating")
            _LOGGER.debug(
                f"[get_access_token token] set DT: {self._cookies.get('DT')}, new DT: {cookie_dict.get('DT')}"
            )
            _LOGGER.debug(
                f"[get_access_token token] set sid: {self._cookies.get('sid')}, new sid: {cookie_dict.get('sid')}"
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
                _LOGGER.error(f"myAirCountryId not found in jwt_data")
                raise ParsingError("myAirCountryId not found in jwt_data")
            self._country_code = jwt_data["myAirCountryId"]
            _LOGGER.info(f"Country Code: {self._country_code}")
        if not self._country_code:
            _LOGGER.error(
                "country_code not defined and id_token not present to identify it"
            )
            raise ParsingError(
                "country_code not defined and id_token not present to identify it"
            )
        _LOGGER.debug(f"[gql_query] country_code: {self._country_code}")

        graphql_url = self._static_config["graphql_url"]
        headers = {
            "x-api-key": self._static_config["myair_api_key"],
            "Authorization": authz_header,
            # There are a bunch of resmed headers sent to this API that seem to be required
            # Unsure if this is ever validated/can break things if these values change
            "rmdhandsetid": "02c1c662-c289-41fd-a9ae-196ff15b5166",
            "rmdlanguage": "en",
            "rmdhandsetmodel": "Chrome",
            "rmdhandsetosversion": "127.0.6533.119",
            "rmdproduct": self._static_config["product"],
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
        _LOGGER.debug(f"[gql_query] graphql_url: {graphql_url}")
        _LOGGER.debug(
            f"[gql_query] headers: {async_redact_data(headers, KEYS_TO_REDACT)}"
        )
        _LOGGER.debug(
            f"[gql_query] json_query: {async_redact_data(json_query, KEYS_TO_REDACT)}"
        )

        async with self._session.post(
            graphql_url,
            headers=headers,
            json=json_query,
        ) as records_res:
            _LOGGER.debug(f"[gql_query] records_res: {records_res}")
            records_dict = await records_res.json()
            _LOGGER.debug(
                f"[gql_query] records_dict: {async_redact_data(records_dict, KEYS_TO_REDACT)}"
            )
            await self._resmed_response_error_check(
                "gql_query", records_res, records_dict
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
        _LOGGER.debug(
            f"[get_user_device_data] device: {async_redact_data(device, KEYS_TO_REDACT)}"
        )
        return device
