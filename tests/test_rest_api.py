"""Tests for integration_blueprint api."""
import re
import asyncio
import aiohttp
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from custom_components.resmed_myair.client import MyAirConfig
from custom_components.resmed_myair.client.new_client import RESTClient, US_CONFIG


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
        json={"access_token": "a_token"},
    )
    await api.connect()
    assert api.access_token == "a_token"

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
