"""Client contracts and exceptions shared by myAir transport implementations."""

from abc import ABC, abstractmethod
from typing import NamedTuple

from custom_components.resmed_myair.models import MyAirDevice, MyAirSleepRecord


class AuthenticationError(Exception):
    """Authentication failure that should surface as setup or reauth repair."""


class IncompleteAccountError(Exception):
    """myAir account state prevents API access until the user completes setup."""


class ParsingError(Exception):
    """Remote payload shape does not match the fields this integration requires."""


class MyAirConfig(NamedTuple):
    """Credentials and regional context needed to authenticate with myAir."""

    username: str
    password: str
    region: str
    device_token: str | None = None


class MyAirClient(ABC):
    """Abstract async contract consumed by the Home Assistant coordinator."""

    @abstractmethod
    async def connect(self) -> str:
        """Authenticate or validate cached credentials before data fetches.

        Returns:
            Provider-specific auth status string.
        """

    @abstractmethod
    async def get_user_device_data(self, initial: bool = False) -> MyAirDevice:
        """Fetch the account's assigned flow-generator device.

        Args:
            initial: Whether the fetch is part of initial setup rather than polling.

        Returns:
            Typed device metadata used for entity identity and device info.
        """

    @abstractmethod
    async def get_sleep_records(self, initial: bool = False) -> list[MyAirSleepRecord]:
        """Fetch recent nightly therapy records for sensor state.

        Args:
            initial: Whether the fetch is part of initial setup rather than polling.

        Returns:
            Typed sleep records ordered as returned by the transport implementation.
        """
