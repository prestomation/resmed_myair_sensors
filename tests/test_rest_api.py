"""Tests for integration_blueprint api."""
import re
import asyncio
import aiohttp
import json
import base64
import jwt
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from custom_components.resmed_myair.client import MyAirConfig
from custom_components.resmed_myair.client.new_client import RESTClient, US_CONFIG

# Let's create something that looks like a production JWT for our tests

id_token_payload = {
    "sub": "abce",
    "name": "A Person",
    "email": "someone@gmail.com",
    "ver": 1,
    "iss": "https://resmed-ext-1.okta.com/oauth2/aus4ccsxvnidQgLmA297",
    "aud": "0oa4ccq1v413ypROi297",
    "iat": 1643517745,
    "exp": 1643521345,
    "jti": "ID.m1UuL1OM7ALHSXX5B1MA5v4Ds-720kJoajA8",
    "amr": ["pwd"],
    "idp": "00ot2fmzvw4k8C296",
    "nonce": "CJ6SPuK1qQTyMTXErNYckUjHKpTjgiB37vXluPSnuqhvJZW4569jgyojra6q",
    "preferred_username": "someone@mail.com",
    "auth_time": 1643517745,
    "at_hash": "sCNNXTE0EtvwoWe_dZv-0w",
    "myAirAnalyticsId": "",
    "myAirAnalyticsMode": "anonymous",
    "countryCode": "AU",
    "myAirCountryId": "AU",
}
au_id_token = jwt.encode(id_token_payload, "secret")


async def test_api(hass, aioclient_mock, caplog):

    config = MyAirConfig(username="usern", password="passw", region="NA")
    api = RESTClient(config, async_get_clientsession(hass))

    aioclient_mock.post(
        US_CONFIG["authn_url"],
        json={"sessionToken": "aToken"},
    )

    aioclient_mock.get(
        re.compile(".*"),
        headers={"location": "https://aToken.com?abc=def#code=aCode"},
    )
    aioclient_mock.post(
        "https://resmed-ext-1.okta.com/oauth2/aus4ccsxvnidQgLmA297/v1/token",
        data={"A": "B"},
        json={"access_token": "a_token", "id_token": au_id_token},
    )
    await api.connect()
    assert api.access_token == "a_token"
    assert api.id_token == au_id_token

    aioclient_mock.post(
        "https://bs2diezuffgt5mfns4ucyz2vea.appsync-api.us-west-2.amazonaws.com/graphql",
        json={
            "data": {
                "getPatientWrapper": {
                    "fgDevices": [
                        {
                            "serialNumber": "aSerial",
                            "deviceType": "myDevice",
                            "lastSleepDataReportTime": "2022-01-07T14:31:19.000+00:00",
                            "localizedName": "My Cool Device",
                            "fgDeviceManufacturerName": "ResMed",
                            "fgDevicePatientId": "abc123",
                        }
                    ]
                }
            }
        },
    )
    device = await api.get_user_device_data()
    assert device == {
        "deviceType": "myDevice",
        "fgDeviceManufacturerName": "ResMed",
        "fgDevicePatientId": "abc123",
        "lastSleepDataReportTime": "2022-01-07T14:31:19.000+00:00",
        "localizedName": "My Cool Device",
        "serialNumber": "aSerial",
    }
    # Each graphql operation is the same method/path, so let's make sure this dumb mock doesn't get confused

    aioclient_mock.clear_requests()

    records = [
        {
            "startDate": "2021-01-01",
            "totalUsage": 5,
            "sleepScore": 55,
            "usageScore": 40,
            "ahiScore": 30,
            "maskScore": 20,
            "leakScore": 10,
            "ahi": 5.5,
            "maskPairCount": 2,
            "leakPercentile": 65,
        },
        {
            "startDate": "2021-01-02",
            "totalUsage": 4,
            "sleepScore": 54,
            "usageScore": 41,
            "ahiScore": 31,
            "maskScore": 21,
            "leakScore": 11,
            "ahi": 5.4,
            "maskPairCount": 3,
            "leakPercentile": 61,
        },
    ]

    aioclient_mock.post(
        "https://bs2diezuffgt5mfns4ucyz2vea.appsync-api.us-west-2.amazonaws.com/graphql",
        json={"data": {"getPatientWrapper": {"sleepRecords": {"items": records}}}},
    )

    sleep_records = await api.get_sleep_records()
    assert sleep_records == records
