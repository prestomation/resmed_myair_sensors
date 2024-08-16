import base64

# import requests
import datetime
import hashlib
import logging
import os
import re
from typing import Any, List
from urllib.parse import parse_qs, urldefrag

from aiohttp import ClientSession
import jwt

from .myair_client import (
    AuthenticationError,
    MyAirClient,
    MyAirConfig,
    MyAirDevice,
    SleepRecord,
)

_LOGGER = logging.getLogger(__name__)

US_CONFIG = {
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
    "oauth_redirect_url": "https://myair2.resmed.com",
}


class RESTClient(MyAirClient):
    """
    This client is currently used in the US.
    In the US, myAir uses oauth on Okta and AWS AppSync GraphQL
    """

    config: MyAirConfig
    access_token: str
    session: ClientSession

    def __init__(self, config: MyAirConfig, session: ClientSession):
        assert (
            config.region == "NA"
        ), "REST client used outside NA, this should not happen. Please file a bug"
        self.config = config
        self.session = session

    async def connect(self):
        # for connect, let's login and store the access token
        await self.get_access_token()

    async def get_access_token(self) -> str:
        """
        Call this to refresh the access token
        """
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        async with self.session.post(
            US_CONFIG["authn_url"],
            headers=headers,
            json={
                "username": self.config.username,
                "password": self.config.password,
            },
        ) as authn_res:
            authn_json = await authn_res.json()
            _LOGGER.debug(f"[get_access_token] authn_json: {authn_json}")

        # We've exchanged our user/pass for a session token
        if "sessionToken" not in authn_json:
            raise AuthenticationError()
        session_token = authn_json["sessionToken"]
        # expires_at = authn_json["expiresAt"]

        # myAir uses Authorization Code with PKCE, so we generate our verifier here
        code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8")
        code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)

        code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
        code_challenge = code_challenge.replace("=", "")

        # We use that sessionToken and exchange for an oauth code, using PKCE
        authorize_url = US_CONFIG["authorize_url"].format(
            authn_client_id=US_CONFIG["authn_client_id"]
        )
        async with self.session.get(
            authorize_url,
            headers=headers,
            allow_redirects=False,
            params={
                "client_id": US_CONFIG["authorize_client_id"],
                # For PKCE
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "prompt": "none",
                "redirect_uri": US_CONFIG["oauth_redirect_url"],
                "response_mode": "fragment",
                "response_type": "code",
                "sessionToken": session_token,
                "scope": "openid profile email",
                "state": "abcdef",
            },
        ) as code_res:
            _LOGGER.debug(f"[get_access_token] code_res: {code_res}")
            location = code_res.headers["location"]
        fragment = urldefrag(location)
        # Pull the code out of the location header fragment
        code = parse_qs(fragment.fragment)["code"]

        # Now we change the code for an access token
        # requests defaults to forms, which is what /token needs, so we don't use our api_session from above
        token_form = {
            "client_id": US_CONFIG["authorize_client_id"],
            "redirect_uri": US_CONFIG["oauth_redirect_url"],
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
            "code": code,
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        async with self.session.post(
            US_CONFIG["token_url"].format(authn_client_id=US_CONFIG["authn_client_id"]),
            headers=headers,
            data=token_form,
            allow_redirects=False,
        ) as token_res:
            d = await token_res.json()
            _LOGGER.debug(f"[get_access_token] token_res: {d}")
            self.access_token = d["access_token"]
            self.id_token = d["id_token"]
            _LOGGER.debug(f"[get_access_token] access_token: {self.access_token}")
            _LOGGER.debug(f"[get_access_token] id_token: {self.id_token}")
            return self.access_token

    async def gql_query(self, operation_name: str, query: str) -> Any:
        _LOGGER.debug(f"[gql_query] operation_name: {operation_name}, query: {query}")
        authz_header = f"bearer {self.access_token}"
        _LOGGER.debug(f"[gql_query] authz_header: {authz_header}")

        # We trust this JWT because it is myAir giving it to us
        # So we can pull the middle piece out, which is the payload, and turn it to json
        jwt_data = jwt.decode(self.id_token, options={"verify_signature": False})
        _LOGGER.debug(f"[gql_query] jwt_data: {jwt_data}")

        # The graphql API only works properly if we provide the expected country code
        # The rest of the paramters are required, but don't seem to be further validated
        country_code = jwt_data["myAirCountryId"]

        headers = {
            "x-api-key": US_CONFIG["myair_api_key"],
            "Authorization": authz_header,
            # There are a bunch of resmed headeers sent to this API that seem to be required
            # Unsure if this is ever validated/can break things if these values change
            "rmdhandsetid": "02c1c662-c289-41fd-a9ae-196ff15b5166",
            "rmdlanguage": "en",
            "rmdhandsetmodel": "Chrome",
            "rmdhandsetosversion": "127.0.6533.119",
            "rmdproduct": "myAir",
            "rmdappversion": "2.0.0",
            "rmdhandsetplatform": "Web",
            "rmdcountry": country_code,
            "accept-language": "en-US,en;q=0.9",
        }
        _LOGGER.debug(f"[gql_query] headers: {headers}")
        _LOGGER.debug(f"[gql_query] appsync_url: {US_CONFIG['appsync_url']}")

        async with self.session.post(
            US_CONFIG["appsync_url"],
            headers=headers,
            json={
                "operationName": operation_name,
                "variables": {},
                "query": query,
            },
        ) as records_response:
            _LOGGER.debug(f"[gql_query] records_response: {records_response}")
            records_json = await records_response.json()
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
        _LOGGER.debug(f"[GetPatientSleepRecords] {records_json}")
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
        _LOGGER.debug(f"[getPatientWrapper] {records_json}")
        device = records_json["data"]["getPatientWrapper"]["fgDevices"][0]
        return device
