"""Base classes for myAir Client."""

from abc import ABC, abstractmethod
from typing import NamedTuple

from custom_components.resmed_myair.models import MyAirDevice, MyAirSleepRecord


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


class MyAirClient(ABC):
    """Basic myAir Client Class."""

    @abstractmethod
    async def connect(self) -> str:
        """Connect to ResMed myAir."""

    @abstractmethod
    async def get_user_device_data(self) -> MyAirDevice:
        """Get user device data from ResMed servers."""

    @abstractmethod
    async def get_sleep_records(self) -> list[MyAirSleepRecord]:
        """Get sleep records from ResMed servers."""
