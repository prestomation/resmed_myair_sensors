from typing import List
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


class LegacyClient(MyAirClient):

    config: MyAirConfig
    cookie_jar: aiohttp.CookieJar

    def __init__(self, config: MyAirConfig):
        assert config.region == "EU"
        self.config = config

    async def connect(self):

        async with aiohttp.ClientSession() as authn_session:
            async with authn_session.post(
                EU_CONFIG["authn_url"],
                json={
                    "authentifier": self.config.username,
                    "password": self.config.password,
                },
            ) as authn_res:
                authn_json = await authn_res.json()

                if authn_json["sessionids"] is None:
                    raise AuthenticationError("Invalid username or password")
                self.cookie_jar = authn_session.cookie_jar

    async def get_user_device_data(self) -> MyAirDevice:
        page = await self.get_dashboard_html()
        soup = BeautifulSoup(page, features="html.parser")
        equipment = soup.select("h6.c-equipment-label")
        manufacturer, device_name = (
            equipment[1].renderContents().decode("utf8").split(" ", 1)
        )
        device: MyAirDevice = {
            "serialNumber": "Unknown",
            "deviceType": device_name,
            "lastSleepDataReportTime": "Unknown",
            "localizedName": f"{manufacturer} {device_name}",
            "fgDeviceManufacturerName": manufacturer,
            "fgDevicePatientId": "Unknown",
        }
        return device

    async def get_dashboard_html(self) -> str:
        async with aiohttp.ClientSession(cookie_jar=self.cookie_jar) as authn_session:
            async with authn_session.get(EU_CONFIG["dashboard_url"]) as dashboard_res:
                page = await dashboard_res.content.read()
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
        records: List[SleepRecord] = []
        for score in my_scores:
            record: SleepRecord = {}
            month_num = datetime.datetime.strptime(score["MonthNameAbrv"], "%b").month
            # This API doesn't give us a year, so we will guess!
            year = datetime.datetime.now().year
            record["startDate"] = f"{year}-{month_num}-{score['DayNumber']}"
            record["totalUsage"] = score.get("Usage", 0)
            record["sleepScore"] = score.get("Score", 0)
            record["usageScore"] = score.get("UsageScore", 0)
            record["ahiScore"] = score.get("EventsScore", 0)
            record["maskScore"] = score.get("MaskScore", 0)
            record["leakScore"] = score.get("LeakScore", 0)
            record["ahi"] = score.get("Events", 0)
            record["maskPairCount"] = score.get("Mask", 0)
            # record["leakPercentile"] = ?
            # record["sleepRecordPatienId"] =  ?

            records.append(record)
        # Let's make sure we're sorted by date
        records.sort(key=lambda r: r["startDate"])
        return records
