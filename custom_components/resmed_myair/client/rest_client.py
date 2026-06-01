"""REST Client for ResMed myAir Client."""

from collections.abc import Mapping, MutableMapping
import datetime
import logging
from typing import Any

from aiohttp import ClientSession

from custom_components.resmed_myair.models import MyAirDevice, MyAirSleepRecord
from custom_components.resmed_myair.redaction import redact_dict

from .auth import MyAirAuthSession
from .graphql import MyAirGraphQLClient
from .myair_client import MyAirClient, MyAirConfig, ParsingError

_LOGGER: logging.Logger = logging.getLogger(__name__)


def _required_mapping(value: Any, message: str) -> Mapping[str, Any]:
    """Validate that a decoded GraphQL payload member is a mapping.

    Args:
        value: Payload member to validate.
        message: Parsing error message to raise when validation fails.

    Returns:
        The original value typed as a mapping.

    Raises:
        ParsingError: When the payload member is not a mapping.
    """
    if not isinstance(value, Mapping):
        raise ParsingError(message)
    return value


def _required_list(value: Any, message: str) -> list[Any]:
    """Validate that a decoded GraphQL payload member is a JSON array.

    Args:
        value: Payload member to validate.
        message: Parsing error message to raise when validation fails.

    Returns:
        The original value typed as a list.

    Raises:
        ParsingError: When the payload member is not a list.
    """
    if not isinstance(value, list):
        raise ParsingError(message)
    return value


class RESTClient(MyAirClient):
    """Coordinate myAir authentication and AppSync GraphQL data access."""

    def __init__(self, config: MyAirConfig, session: ClientSession) -> None:
        """Create auth and GraphQL helpers around a shared aiohttp session.

        Args:
            config: User credentials, region, and optional remembered-device token.
            session: Home Assistant-managed aiohttp session.
        """
        _LOGGER.debug("[RESTClient init] config: %s", redact_dict(config._asdict()))
        self._config: MyAirConfig = config
        self._session: ClientSession = session
        self._auth = MyAirAuthSession(config, session)
        self._graphql = MyAirGraphQLClient(
            session=self._session,
            auth=self._auth,
            region_config=self._auth.region_config,
        )

    @property
    def device_token(self) -> str | None:
        """Expose the remembered-device token that should be saved in config entries."""
        return self._auth.device_token

    async def connect(self, initial: bool | None = False) -> str:
        """Authenticate with myAir or reuse an active OAuth token.

        Args:
            initial: Whether the call is part of config setup, where MFA can be
                triggered and surfaced to the user.

        Returns:
            Okta authentication status.
        """
        return await self._auth.connect(initial=initial)

    async def verify_mfa_and_get_access_token(self, verification_code: str) -> str:
        """Complete an MFA challenge and cache OAuth tokens.

        Args:
            verification_code: Email MFA code supplied by the user.

        Returns:
            Okta authentication status after MFA verification.
        """
        return await self._auth.verify_mfa_and_get_access_token(verification_code)

    async def is_email_verified(self) -> bool:
        """Return whether Okta userinfo reports a verified email address."""
        return await self._auth.is_email_verified()

    async def _gql_query(
        self, operation_name: str, query: str, initial: bool | None = False
    ) -> dict[str, Any]:
        """Execute a myAir AppSync operation with the current auth state.

        Args:
            operation_name: GraphQL operation name sent to AppSync.
            query: GraphQL document to execute.
            initial: Whether the query is part of config setup.

        Returns:
            Decoded GraphQL response payload.
        """
        return await self._graphql.query(operation_name, query, initial=bool(initial))

    async def get_sleep_records(self, initial: bool = False) -> list[MyAirSleepRecord]:
        """Fetch and normalize the recent nightly sleep records.

        Args:
            initial: Whether this fetch is part of config setup.

        Returns:
            Typed records returned by myAir for the last 30 days.
        """
        today_date: datetime.date = datetime.datetime.now(datetime.UTC).astimezone().date()
        today: str = today_date.isoformat()
        one_month_ago: str = (today_date - datetime.timedelta(days=30)).isoformat()

        query: str = """query GetPatientSleepRecords {
            getPatientWrapper {
                patient {
                    firstName
                }
                sleepRecords(startMonth: \"ONE_MONTH_AGO\", endMonth: \"DATE\")
                {
                    items {
                        startDate
                        totalUsage
                        sleepScore
                        usageScore
                        ahiScore
                        maskScore
                        leakScore
                        ahi
                        maskPairCount
                        leakPercentile
                        sleepRecordPatientId
                        __typename
                    }
                    __typename
                }
            __typename
            }
        }
        """.replace("ONE_MONTH_AGO", one_month_ago).replace("DATE", today)

        _LOGGER.info("Getting Sleep Records")
        records_dict: MutableMapping[str, Any] = await self._gql_query(
            "GetPatientSleepRecords", query, initial
        )
        _LOGGER.debug("[get_sleep_records] records_dict: %s", redact_dict(records_dict))
        data = _required_mapping(records_dict.get("data"), "Error getting Patient Sleep Records")
        patient_wrapper = _required_mapping(
            data.get("getPatientWrapper"), "Error getting Patient Sleep Records"
        )
        sleep_records = _required_mapping(
            patient_wrapper.get("sleepRecords"), "Error getting Patient Sleep Records"
        )
        records = _required_list(
            sleep_records.get("items"),
            "Error getting Patient Sleep Records. Returned records is not a list",
        )
        _LOGGER.debug("[get_sleep_records] records: %s", redact_dict(records))
        typed_records: list[MyAirSleepRecord] = []
        for record in records:
            if not isinstance(record, Mapping):
                _LOGGER.error(
                    "Error getting Patient Sleep Records. Returned record item is not a mapping"
                )
                raise ParsingError(
                    "Error getting Patient Sleep Records. Returned record item is not a mapping"
                )
            typed_records.append(MyAirSleepRecord.from_api(record))
        return typed_records

    async def get_user_device_data(self, initial: bool = False) -> MyAirDevice:
        """Fetch and normalize the account's assigned flow-generator device.

        Args:
            initial: Whether this fetch is part of config setup.

        Returns:
            Typed device data enriched with the first mask code when available.
        """
        query: str = """
        query getPatientWrapper {
            getPatientWrapper {
                masks {
                    maskCode
                }
                fgDevices {
                    serialNumber
                    localizedName
                    deviceSeries
                    deviceFamily
                    lastSleepDataReportTime
                    fgDeviceManufacturerName
                    fgDevicePatientId
                }
            }
        }
        """

        _LOGGER.info("Getting User Device Data")
        records_dict: MutableMapping[str, Any] = await self._gql_query(
            "getPatientWrapper", query, initial
        )
        _LOGGER.debug("[get_user_device_data] records_dict: %s", redact_dict(records_dict))
        data = _required_mapping(records_dict.get("data"), "Error getting User Device Data")
        patient_wrapper = _required_mapping(
            data.get("getPatientWrapper"), "Error getting User Device Data"
        )
        devices = _required_list(patient_wrapper.get("fgDevices"), "Error getting User Device Data")
        if not devices:
            raise ParsingError("Error getting User Device Data")
        device = dict(
            _required_mapping(
                devices[0], "Error getting User Device Data. Returned data is not a dict"
            )
        )
        mask_code: str | None = None
        try:
            mask_code = patient_wrapper["masks"][0]["maskCode"]
        except (KeyError, IndexError, TypeError) as e:
            _LOGGER.warning("Error getting User Mask Data. %s: %s", type(e).__name__, e)
        else:
            if mask_code:
                device["maskCode"] = mask_code
        _LOGGER.debug("[get_user_device_data] device: %s", redact_dict(device))
        return MyAirDevice.from_api(device)
