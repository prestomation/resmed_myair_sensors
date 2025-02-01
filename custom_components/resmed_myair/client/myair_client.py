"""Base classes for myAir Client."""

from abc import ABC
from typing import NamedTuple, NotRequired, TypedDict


class AuthenticationError(Exception):
    """Error thrown when Authentication fails.

    This could mean the username/password or domain is incorrect or the MFA was incorrect.
    """


class IncompleteAccountError(Exception):
    """Error thrown when ResMed reports that the account is not fully setup."""


class ParsingError(Exception):
    """Error is thrown when the expected data is not found in the result."""


class MyAirConfig(NamedTuple):
    """Config for logging into myAir."""

    username: str
    password: str
    region: str
    device_token: str | None = None


class SleepRecord(TypedDict):
    """Components of what is returned by the API and shown on the myAir dashboard. No processing is performed."""

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
    """Components of myAir Device."""

    serialNumber: str
    deviceType: str
    lastSleepDataReportTime: str
    localizedName: str
    fgDeviceManufacturerName: str
    fgDevicePatientId: str

    # URI on the domain: https://static.myair-prd.dht.live/
    imagePath: NotRequired[str]


class MyAirClient(ABC):
    """Basic myAir Client Class."""

    async def connect(self) -> str:
        """Connect to ResMed myAir."""
        raise NotImplementedError

    async def get_user_device_data(self) -> MyAirDevice:
        """Get user device data from ResMed servers."""
        raise NotImplementedError

    async def get_sleep_records(self) -> list[SleepRecord]:
        """Get sleep records from ResMed servers."""
        raise NotImplementedError
