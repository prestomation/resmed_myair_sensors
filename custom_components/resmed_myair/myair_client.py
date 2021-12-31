from typing import NamedTuple, TypedDict, List, Any

# import requests
import datetime
import base64
import os
import re
import hashlib
from urllib.parse import urldefrag, parse_qs
import aiohttp


class AuthenticationError(Exception):
    """This error is thrown when Authentication fails, which can mean the username/password or domain is incorrect"""

    pass


class MyAirConfig(NamedTuple):
    """
    This is our config for logging into MyAir
    If you are in North America, you only need to set the username/password
    If you are in a different region, you will likely need to override these values.
    To do so, you will need to examine the network traffic during login to find the right values

    """

    # If you are in NA, you only need to set these
    username: str
    password: str

    # This is the clientId that appears in Okta URLs
    authn_client_id: str = "aus4ccsxvnidQgLmA297"

    # This is the clientId that appears in request bodies during login
    authorize_client_id: str = "0oa4ccq1v413ypROi297"

    # Used as the x-api-key header for the AppSync GraphQL API
    myair_api_key: str = "da2-cenztfjrezhwphdqtwtbpqvzui"

    # The Okta Endpoint where the creds go
    authn_url: str = "https://resmed-ext-1.okta.com/api/v1/authn"

    # When specifying token_url and authorize_url, add {authn_client_id} and your authn_client_id will be substituted in
    # Or you can put the entire URL here if you want, but your authn_client_id will be ignored
    authorize_url: str = (
        "https://resmed-ext-1.okta.com/oauth2/{authn_client_id}/v1/authorize"
    )

    # The endpoint that the 'code' is sent to get an authorization token
    token_url: str = "https://resmed-ext-1.okta.com/oauth2/{authn_client_id}/v1/token"

    # The AppSync URL that accepts your token + the API key to return Sleep Recors
    appsync_url: str = (
        "https://bs2diezuffgt5mfns4ucyz2vea.appsync-api.us-west-2.amazonaws.com/graphql"
    )

    # Unsure if this needs to be regionalized, it is almost certainly something that is configured inside of an Okta allowlist
    oauth_redirect_url: str = "https://myair2.resmed.com"


class SleepRecord(TypedDict):
    """
    This data is what is returned by the API and shown on the myAir dashboard
    No processing is performed
    """

    # myAir returns this in the format %Y-%m-%d, at daily precision
    startDate: str
    totalUsage: int
    sleepScore: int
    usageScore: int
    ahiScore: int
    maskScore: int
    leakScore: int
    ahi: float
    maskPairCount: int
    leakPercentile: float
    sleepRecordPatientId: str


class MyAirDevice(TypedDict):
    serialNumber: str
    deviceType: str
    lastSleepDataReportTime: str
    localizedName: str
    fgDeviceManufacturerName: str
    fgDevicePatientId: str


class MyAirClient:

    config: MyAirConfig
    access_token: str

    def __init__(self, config: MyAirConfig):
        self.config = config

    async def connect(self):
        await self.get_access_token()

    async def get_access_token(self) -> str:
        """
        Call this to refresh the access token
        """
        async with aiohttp.ClientSession(
            headers={"Content-Type": "application/json", "Accept": "application/json"}
        ) as authn_session:
            # authn_session = requests.Session()

            async with authn_session.post(
                self.config.authn_url,
                json={
                    "username": self.config.username,
                    "password": self.config.password,
                },
            ) as authn_res:
                authn_json = await authn_res.json()

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
            authorize_url = self.config.authorize_url.format(
                authn_client_id=self.config.authn_client_id
            )
            async with authn_session.get(
                authorize_url,
                allow_redirects=False,
                params={
                    "client_id": self.config.authorize_client_id,
                    # For PKCE
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                    "prompt": "none",
                    "redirect_uri": self.config.oauth_redirect_url,
                    "response_mode": "fragment",
                    "response_type": "code",
                    "sessionToken": session_token,
                    "scope": "openid profile email",
                    "state": "abcdef",
                },
            ) as code_res:
                location = code_res.headers["location"]
            fragment = urldefrag(location)
            # Pull the code out of the location header fragment
            code = parse_qs(fragment.fragment)["code"]

            # Now we change the code for an access token
            # requests defaults to forms, which is what /token needs, so we don't use our api_session from above
            token_form = {
                "client_id": self.config.authorize_client_id,
                "redirect_uri": self.config.oauth_redirect_url,
                "grant_type": "authorization_code",
                "code_verifier": code_verifier,
                "code": code,
            }
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            }
            async with authn_session.post(
                self.config.token_url.format(
                    authn_client_id=self.config.authn_client_id
                ),
                data=token_form,
                allow_redirects=False,
                headers=headers,
            ) as token_res:
                d = await token_res.json()
                self.access_token = d["access_token"]
                return self.access_token

    async def gql_query(self, operation_name: str, query: str) -> Any:

        authz_header = f"bearer {self.access_token}"

        headers = {
            "x-api-key": self.config.myair_api_key,
            "Authorization": authz_header,
            # There are a bunch of resmed headeers sent to this API that seem to be required
            # Unsure if this is ever validated/can break things if these values change
            "rmdhandsetid": "02c1c662-c289-41fd-a9ae-196ff15b5166",
            "rmdlanguage": "en",
            "rmdhandsetmodel": "Chrome",
            "rmdhandsetosversion": "96.0.4664.110",
            "rmdproduct": "myAir",
            "rmdappversion": "1.0",
            "rmdhandsetplatform": "Web",
            "rmdcountry": "US",
            "accept-language": "en-US,en;q=0.9",
        }
        async with aiohttp.ClientSession(headers=headers) as api_session:

            async with api_session.post(
                self.config.appsync_url,
                json={
                    "operationName": operation_name,
                    "variables": {},
                    "query": query,
                },
            ) as records_response:
                records_json = await records_response.json()
                return records_json

    async def get_sleep_records(self) -> List[SleepRecord]:

        today = datetime.datetime.now().strftime("%Y-%m-%d")

        query = """query GetPatientSleepRecords {
            getPatientWrapper {
                patient {
                    firstName
                }
                sleepRecords(startMonth: \"DATE\", endMonth: \"DATE\")
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
            "DATE", today
        )

        records_json = await self.gql_query("GetPatientSleepRecords", query)
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
        device = records_json["data"]["getPatientWrapper"]["fgDevices"][0]
        return device
