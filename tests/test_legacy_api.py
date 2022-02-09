"""Tests for integration_blueprint api."""
import re
import asyncio
import aiohttp
from io import StringIO
from pytest_homeassistant_custom_component.common import load_fixture
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from custom_components.resmed_myair.client import MyAirConfig
from custom_components.resmed_myair.client.legacy_client import LegacyClient, EU_CONFIG


async def test_api(hass, aioclient_mock, caplog):

    config = MyAirConfig(username="usern", password="passw", region="EU")
    api = LegacyClient(config, async_get_clientsession(hass))

    aioclient_mock.post(EU_CONFIG["authn_url"], json={"sessionids": "aSessionId"})

    aioclient_mock.get(
        re.compile(".*"),
        headers={"location": "https://aToken.com?abc=def#code=aCode"},
    )
    # aioclient_mock.post(
    #     "https://resmed-ext-1.okta.com/oauth2/aus4ccsxvnidQgLmA297/v1/token",
    #     data={"A": "B"},
    #     json={"access_token": "a_token"},
    # )
    await api.connect()
    aioclient_mock.clear_requests()

    aioclient_mock.get(
        EU_CONFIG["dashboard_url"], text=load_fixture("legacy_page_1.html")
    )
    device = await api.get_user_device_data()

    assert device == {
        "deviceType": "AirSense 10 AutoSet",
        "fgDeviceManufacturerName": "ResMed",
        "fgDevicePatientId": "Unknown",
        "lastSleepDataReportTime": "Unknown",
        "localizedName": "ResMed AirSense 10 AutoSet",
        "serialNumber": "usern",
    }

    records = await api.get_sleep_records()

    assert records[-1] == {
        "ahi": 0,
        "ahiScore": 5,
        "leakScore": 20,
        "maskPairCount": 1,
        "maskScore": 5,
        "sleepScore": 37,
        "startDate": "2022-01-03",
        "totalUsage": 42.0,
        "usageScore": 7,
    }


async def test_api_2(hass, aioclient_mock, caplog):

    config = MyAirConfig(username="usern", password="passw", region="EU")
    api = LegacyClient(config, async_get_clientsession(hass))

    aioclient_mock.post(EU_CONFIG["authn_url"], json={"sessionids": "aSessionId"})

    aioclient_mock.get(
        re.compile(".*"),
        headers={"location": "https://aToken.com?abc=def#code=aCode"},
    )
    # aioclient_mock.post(
    #     "https://resmed-ext-1.okta.com/oauth2/aus4ccsxvnidQgLmA297/v1/token",
    #     data={"A": "B"},
    #     json={"access_token": "a_token"},
    # )
    await api.connect()
    aioclient_mock.clear_requests()

    aioclient_mock.get(
        EU_CONFIG["dashboard_url"], text=load_fixture("legacy_page_2.html")
    )
    device = await api.get_user_device_data()

    assert device == {
        "deviceType": "AirSense 10 AutoSet",
        "fgDeviceManufacturerName": "ResMed",
        "fgDevicePatientId": "Unknown",
        "lastSleepDataReportTime": "Unknown",
        "localizedName": "ResMed AirSense 10 AutoSet",
        "serialNumber": "usern",
    }

    records = await api.get_sleep_records()

    assert records[-1] == {
        "ahi": 1.2,
        "ahiScore": 5,
        "leakScore": 20,
        "maskPairCount": 5.0,
        "maskScore": 1.0,
        "sleepScore": 57.0,
        "startDate": "2022-02-07",
        "totalUsage": 186.0,
        "usageScore": 31.0,
    }