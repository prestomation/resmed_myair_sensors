"""Base classes for myAir Client."""

from abc import ABC
from collections.abc import Mapping
from typing import Any, NamedTuple


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

    async def connect(self) -> str:
        """Connect to ResMed myAir."""
        raise NotImplementedError

    async def get_user_device_data(self) -> Mapping[str, Any]:
        """Get user device data from ResMed servers."""
        raise NotImplementedError

    async def get_sleep_records(self) -> list[Mapping[str, Any]]:
        """Get sleep records from ResMed servers."""
        raise NotImplementedError
