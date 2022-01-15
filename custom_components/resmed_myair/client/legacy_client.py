from typing import List, Any
import aiohttp
import datetime
import json
import re
from bs4 import BeautifulSoup
from .myair_client import (
    MyAirDevice,
    MyAirClient,
    MyAirConfig,
    SleepRecord,
    AuthenticationError,
)


EU_CONFIG = {
    "authn_url": "https://myair.resmed.eu/authenticationids/externalwebservices/restotprequestselect.php",
    "dashboard_url": "https://myair.resmed.eu/Dashboard.aspx",
    "device_url": "https://myair.resmed.eu/myAccountDevice.aspx",
}


def generate_sleep_records(scores: Any) -> List[SleepRecord]:
    records: List[SleepRecord] = []

    def as_float(d, key):
        try:
            return float(d.get(key, 0))
        except ValueError:
            return 0

    for score in scores:
        record: SleepRecord = {}
        month_num = datetime.datetime.strptime(score["MonthNameAbrv"], "%b").month
        # This API doesn't give us a year, so we will guess!
        # If it's in the future, we assume it was from last year and subtract a year
        # Super-hacky but myAir does not give us a year
        year = datetime.datetime.now().year
        start_date = datetime.datetime.strptime(
            f"{year}-{month_num}-{score['DayNumber']}", "%Y-%M-%d"
        )
        record["startDate"] = start_date.strftime("%Y-%M-%d")

        # Usage is in hours, but we expose minutes
        record["totalUsage"] = as_float(score, "Usage") * 60
        record["sleepScore"] = as_float(score, "Score")
        record["usageScore"] = as_float(score, "UsageScore")
        record["ahiScore"] = as_float(score, "EventsScore")
        record["maskScore"] = as_float(score, "MaskScore")
        record["leakScore"] = as_float(score, "LeakScore")
        record["ahi"] = as_float(score, "Events")
        record["maskPairCount"] = as_float(score, "Mask")
        # record["leakPercentile"] = ?
        # record["sleepRecordPatienId"] =  ?

        records.append(record)

    # We are currently relying on myAir to return data sorted by date, e.g. the last record will be the latest record
    return records


class LegacyClient(MyAirClient):

    config: MyAirConfig
    client: aiohttp.ClientSession

    def __init__(self, config: MyAirConfig, client: aiohttp.ClientSession):
        assert config.region == "EU"
        self.config = config
        self.client = client

    async def connect(self):

        async with self.client.post(
            EU_CONFIG["authn_url"],
            json={
                "authentifier": self.config.username,
                "password": self.config.password,
            },
        ) as authn_res:
            authn_json = await authn_res.json()

            if authn_json["sessionids"] is None:
                raise AuthenticationError("Invalid username or password")

    async def get_user_device_data(self) -> MyAirDevice:
        page = await self.get_dashboard_html()
        soup = BeautifulSoup(page, features="html.parser")

        equipment = soup.select("h6.c-equipment-label")
        manufacturer, device_name = (
            equipment[1].renderContents().decode("utf8").split(" ", 1)
        )
        device: MyAirDevice = {
            "serialNumber": self.config.username,
            "deviceType": device_name,
            "lastSleepDataReportTime": "Unknown",
            "localizedName": f"{manufacturer} {device_name}",
            "fgDeviceManufacturerName": manufacturer,
            "fgDevicePatientId": "Unknown",
        }
        return device

    async def get_dashboard_html(self) -> str:

        async with self.client.get(EU_CONFIG["dashboard_url"]) as dashboard_res:
            page = await dashboard_res.text()
            return page

    async def get_sleep_records(self) -> List[SleepRecord]:
        page = await self.get_dashboard_html()
        soup = BeautifulSoup(page, features="html.parser")

        scripts = soup.find_all("script")
        scores_script = [
            x.renderContents().decode("utf8")
            for x in scripts
            if "myScores" in x.renderContents().decode("utf8")
        ][0]
        matches = re.search(".+(\[.+?\]).+", scores_script).groups()[0]
        my_scores = json.loads(matches)
        return generate_sleep_records(my_scores)
