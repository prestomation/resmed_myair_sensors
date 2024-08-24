import base64
import datetime
import hashlib
import logging
import os
import re
from typing import Any, List
from urllib.parse import parse_qs, urldefrag

from aiohttp import ClientSession
from aiohttp.client_exceptions import ClientResponseError
from aiohttp.http_exceptions import HttpProcessingError
import jwt

from custom_components.resmed_myair.common import CONF_ACCESS_TOKEN

from .myair_client import (
    AuthenticationError,
    MyAirClient,
    MyAirConfig,
    MyAirDevice,
    SleepRecord,
)

_LOGGER = logging.getLogger(__name__)

EU_CONFIG = {
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
    "appsync_url": "https://graphql.hyperdrive.resmed.eu/graphql",
    # Unsure if this needs to be regionalized, it is almost certainly something that is configured inside of an Okta allowlist
    "oauth_redirect_url": "https://myair.resmed.eu",
}


class RESTEUClient(MyAirClient):
    """
    This client is currently used in the EU.
    In the EU, myAir uses oauth on Okta and AWS AppSync GraphQL
    """

    def __init__(self, config: MyAirConfig, session: ClientSession):
        self._config: MyAirConfig = config
        self._session: ClientSession = session
        self._json_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self._authn_client_id = EU_CONFIG["authn_client_id"]
        self._2fa_url = EU_CONFIG["2fa_url"].format(
            authn_client_id=self._authn_client_id
        )

        self._access_token = (
            self._config.access_token if self._config.access_token else None
        )
        self._id_token = None
        self._state_token = None
        self._session_token = None

    async def connect(self):
        # We will use the existing access token
        return

    async def get_state_token_and_trigger_2fa(self):
        await self.get_state_token()
        await self.trigger_2fa()

    async def verify_2fa_and_get_access_token(self, verification_code):
        await self.verify_2fa(verification_code)
        await self.get_access_token()

    async def get_state_token(self) -> str:
        authn_url = EU_CONFIG["authn_url"]
        json_query = {
            "username": self._config.username,
            "password": self._config.password,
        }
        _LOGGER.debug(f"[get_state_token] authn_url: {authn_url}")
        _LOGGER.debug(f"[get_state_token] headers: {self._json_headers}")
        _LOGGER.debug(f"[get_state_token] json_query: {json_query}")

        async with self._session.post(
            authn_url,
            headers=self._json_headers,
            json=json_query,
        ) as authn_res:
            if authn_res.ok:
                _LOGGER.debug(f"[get_state_token] authn_res: {authn_res}")
                authn_json = await authn_res.json()
                _LOGGER.debug(f"[get_state_token] authn_json: {authn_json}")
                if "errors" in authn_json:
                    try:
                        if (
                            authn_json["errors"][0]["errorInfo"]["errorType"]
                            == "unauthorized"
                        ):
                            raise AuthenticationError(
                                "Getting unauthorized error on authn step"
                            )
                    except TypeError:
                        pass
                    raise HttpProcessingError(
                        code=authn_res.status,
                        message=str(authn_json),
                        headers=authn_res.headers,
                    )
            else:
                raise ClientResponseError(
                    f"authn Connection Issue. Status {authn_res.status} {authn_res.message}"
                )

        if "stateToken" not in authn_json:
            raise AuthenticationError("Cannot get stateToken in authn step")
        self._state_token = authn_json["stateToken"]

        try:
            self._authn_client_id = authn_json["_embedded"]["factors"][0]["id"]
        except Exception:
            self._authn_client_id = EU_CONFIG["authn_client_id"]
        _LOGGER.debug(f"[get_state_token] authn_client_id: {self._authn_client_id}")

        try:
            self._2fa_url = f"{authn_json['_embedded']['factors'][0]['_links']['verify']['href']}?rememberDevice=true"
        except Exception:
            self._2fa_url = EU_CONFIG["2fa_url"].format(
                authn_client_id=self._authn_client_id
            )
        _LOGGER.debug(f"[get_state_token] 2fa_url: {self._2fa_url}")

    async def trigger_2fa(self):
        json_query = {"passCode": "", "stateToken": self._state_token}
        _LOGGER.debug(f"[trigger_2fa] 2fa_url: {self._2fa_url}")
        _LOGGER.debug(f"[trigger_2fa] headers: {self._json_headers}")
        _LOGGER.debug(f"[trigger_2fa] json_query: {json_query}")

        async with self._session.post(
            self._2fa_url,
            headers=self._json_headers,
            json=json_query,
        ) as trigger_2fa_res:
            if trigger_2fa_res.ok:
                _LOGGER.debug(f"[trigger_2fa] trigger_2fa_res: {trigger_2fa_res}")
                trigger_2fa_json = await trigger_2fa_res.json()
                _LOGGER.debug(f"[trigger_2fa] trigger_2fa_json: {trigger_2fa_json}")
                if "errors" in trigger_2fa_json:
                    try:
                        if (
                            trigger_2fa_json["errors"][0]["errorInfo"]["errorType"]
                            == "unauthorized"
                        ):
                            raise AuthenticationError(
                                "Getting unauthorized error on trigger_2fa step"
                            )
                    except TypeError:
                        pass
                    raise HttpProcessingError(
                        code=trigger_2fa_res.status,
                        message=str(trigger_2fa_json),
                        headers=trigger_2fa_res.headers,
                    )
            else:
                raise ClientResponseError(
                    f"Trigger 2FA Connection Issue. Status {trigger_2fa_res.status} {trigger_2fa_res.message}"
                )

    async def verify_2fa(self, verification_code: str) -> str:
        _LOGGER.debug(f"[verify_2fa] verification_code: {verification_code}")

        json_query = {"passCode": verification_code, "stateToken": self._state_token}
        _LOGGER.debug(f"[verify_2fa] 2fa_url: {self._2fa_url}")
        _LOGGER.debug(f"[verify_2fa] headers: {self._json_headers}")
        _LOGGER.debug(f"[verify_2fa] json_query: {json_query}")

        async with self._session.post(
            self._2fa_url,
            headers=self._json_headers,
            json=json_query,
        ) as verify_2fa_res:
            if verify_2fa_res.ok:
                _LOGGER.debug(f"[verify_2fa] verify_2fa_res: {verify_2fa_res}")
                verify_2fa_json = await verify_2fa_res.json()
                _LOGGER.debug(f"[verify_2fa] verify_2fa_json: {verify_2fa_json}")
                if "errors" in verify_2fa_json:
                    try:
                        if (
                            verify_2fa_json["errors"][0]["errorInfo"]["errorType"]
                            == "unauthorized"
                        ):
                            raise AuthenticationError(
                                "Getting unauthorized error on verify_2fa step"
                            )
                    except TypeError:
                        pass
                    raise HttpProcessingError(
                        code=verify_2fa_res.status,
                        message=str(verify_2fa_json),
                        headers=verify_2fa_res.headers,
                    )
            else:
                raise ClientResponseError(
                    f"Verify 2FA Connection Issue. Status {verify_2fa_res.status} {verify_2fa_res.message}"
                )

        # We've exchanged our user/pass for a session token
        if "sessionToken" not in verify_2fa_json:
            raise AuthenticationError("Cannot get sessionToken in verify_2fa step")
        self._session_token = verify_2fa_json["sessionToken"]

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
        authorize_url = EU_CONFIG["authorize_url"].format(
            oauth2_client_id=EU_CONFIG["oauth2_client_id"]
        )
        params_query = {
            "client_id": EU_CONFIG["authorize_client_id"],
            # For PKCE
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "prompt": "none",
            "redirect_uri": EU_CONFIG["oauth_redirect_url"],
            "response_mode": "fragment",
            "response_type": "code",
            "sessionToken": self._session_token,
            "scope": "openid profile email",
            "state": "abcdef",
        }
        _LOGGER.debug(f"[get_access_token code_res] authorize_url: {authorize_url}")
        _LOGGER.debug(f"[get_access_token code_res] headers: {self._json_headers}")
        _LOGGER.debug(f"[get_access_token code_res] params_query: {params_query}")

        async with self._session.get(
            authorize_url,
            headers=self._json_headers,
            allow_redirects=False,
            params=params_query,
        ) as code_res:
            if code_res.ok:
                _LOGGER.debug(f"[get_access_token] code_res: {code_res}")
                location = code_res.headers["location"]
                _LOGGER.debug(f"[get_access_token] location: {location}")
            else:
                raise ClientResponseError(
                    f"Get Code Connection Issue. Status {code_res.status} {code_res.message}"
                )
        fragment = urldefrag(location)
        _LOGGER.debug(f"[get_access_token] fragment: {fragment}")
        # Pull the code out of the location header fragment
        code = parse_qs(fragment.fragment)["code"]
        _LOGGER.debug(f"[get_access_token] code: {code}")

        # Now we change the code for an access token
        # requests defaults to forms, which is what /token needs, so we don't use our api_session from above
        token_query = {
            "client_id": EU_CONFIG["authorize_client_id"],
            "redirect_uri": EU_CONFIG["oauth_redirect_url"],
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
            "code": code,
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        token_url = EU_CONFIG["token_url"].format(
            oauth2_client_id=EU_CONFIG["oauth2_client_id"]
        )
        _LOGGER.debug(f"[get_access_token token_res] token_url: {token_url}")
        _LOGGER.debug(f"[get_access_token token_res] headers: {headers}")
        _LOGGER.debug(f"[get_access_token token_res] token_query: {token_query}")

        async with self._session.post(
            token_url,
            headers=headers,
            data=token_query,
            allow_redirects=False,
        ) as token_res:
            if token_res.ok:
                _LOGGER.debug(f"[get_access_token] token_res: {token_res}")
                token_json = await token_res.json()
                _LOGGER.debug(f"[get_access_token] token_json: {token_json}")
                if "errors" in token_json:
                    try:
                        if (
                            token_json["errors"][0]["errorInfo"]["errorType"]
                            == "unauthorized"
                        ):
                            raise AuthenticationError(
                                "Getting unauthorized error on get_access_token step"
                            )
                    except TypeError:
                        pass
                    raise HttpProcessingError(
                        token=token_res.status,
                        message=str(token_json),
                        headers=token_res.headers,
                    )
                self._access_token = token_json["access_token"]
                self._id_token = token_json["id_token"]
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

        # We trust this JWT because it is myAir giving it to us
        # So we can pull the middle piece out, which is the payload, and turn it to json
        jwt_data = jwt.decode(self._id_token, options={"verify_signature": False})
        _LOGGER.debug(f"[gql_query] jwt_data: {jwt_data}")

        # The graphql API only works properly if we provide the expected country code
        # The rest of the paramters are required, but don't seem to be further validated
        country_code = jwt_data["myAirCountryId"]

        appsync_url = EU_CONFIG["appsync_url"]
        headers = {
            "x-api-key": EU_CONFIG["myair_api_key"],
            "Authorization": authz_header,
            # There are a bunch of resmed headers sent to this API that seem to be required
            # Unsure if this is ever validated/can break things if these values change
            "rmdhandsetid": "02c1c662-c289-41fd-a9ae-196ff15b5166",
            "rmdlanguage": "en",
            "rmdhandsetmodel": "Chrome",
            "rmdhandsetosversion": "127.0.6533.119",
            "rmdproduct": "myAir EU",
            "rmdappversion": "2.0.0",
            "rmdhandsetplatform": "Web",
            "rmdcountry": country_code,
            "accept-language": "en-US,en;q=0.9",
        }
        json_query = {
            "operationName": operation_name,
            "variables": {},
            "query": query,
        }
        _LOGGER.debug(f"[gql_query] appsync_url: {appsync_url}")
        _LOGGER.debug(f"[gql_query] headers: {headers}")
        _LOGGER.debug(f"[gql_query] json_query: {json_query}")

        async with self._session.post(
            appsync_url,
            headers=headers,
            json=json_query,
        ) as records_response:
            _LOGGER.debug(f"[gql_query] records_response: {records_response}")
            records_json = await records_response.json()
            _LOGGER.debug(f"[gql_query] records_json: {records_json}")
            if "errors" in records_json:
                try:
                    if (
                        records_json["errors"][0]["errorInfo"]["errorType"]
                        == "unauthorized"
                    ):
                        raise AuthenticationError(
                            "Getting unauthorized error on ggl_query step"
                        )
                except TypeError:
                    pass
                raise HttpProcessingError(
                    code=records_response.status,
                    message=str(records_json),
                    headers=records_response.headers,
                )
        return records_json

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

        records_json = await self.gql_query("GetPatientSleepRecords", query)
        _LOGGER.debug(f"[get_sleep_records] {records_json}")
        records = records_json["data"]["getPatientWrapper"]["sleepRecords"]["items"]
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

        records_json = await self.gql_query("getPatientWrapper", query)
        records_json.update({CONF_ACCESS_TOKEN: self._access_token})
        _LOGGER.debug(f"[get_user_device_data] {records_json}")
        device = records_json["data"]["getPatientWrapper"]["fgDevices"][0]
        return device
