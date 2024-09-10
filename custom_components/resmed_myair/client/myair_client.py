from abc import ABC
from typing import NamedTuple, NotRequired, TypedDict


class AuthenticationError(Exception):
    """This error is thrown when Authentication fails.
    This could mean the username/password or domain is incorrect or the MFA was incorrect.
    """

    pass


class IncompleteAccountError(Exception):
    """This error is thrown when ResMed reports that the account is not fully setup"""

    pass


class ParsingError(Exception):
    """This error is thrown when the expected data is not found in the result"""

    pass


class MyAirConfig(NamedTuple):
    """
    This is our config for logging into MyAir
    """

    username: str
    password: str
    region: str
    device_token: str | None = None


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

    # URI on the domain: https://static.myair-prd.dht.live/
    imagePath: NotRequired[str]


class MyAirClient(ABC):
    async def connect(self):
        raise NotImplementedError()

    async def get_user_device_data(self) -> MyAirDevice:
        raise NotImplementedError()

    async def get_sleep_records(self) -> list[SleepRecord]:
        raise NotImplementedError()
