"""REST Client for ResMed myAir Client."""

from collections.abc import Mapping, MutableMapping
import datetime
import logging
from typing import Any

from aiohttp import ClientResponse, ClientSession

from custom_components.resmed_myair.models import MyAirDevice, MyAirSleepRecord

from .auth import MyAirAuthSession
from .const import (
    AUTH_NEEDS_MFA as _AUTH_NEEDS_MFA,
    AUTHN_SUCCESS as _AUTHN_SUCCESS,
    REGION_NA as _REGION_NA,
)
from .graphql import MyAirGraphQLClient
from .helpers import redact_dict
from .myair_client import MyAirClient, MyAirConfig, ParsingError
from .regions import EU_CONFIG as _EU_CONFIG, NA_CONFIG as _NA_CONFIG, RegionConfig

_LOGGER: logging.Logger = logging.getLogger(__name__)

REGION_NA: str = _REGION_NA
NA_CONFIG: RegionConfig = _NA_CONFIG
EU_CONFIG: RegionConfig = _EU_CONFIG
AUTH_NEEDS_MFA: str = _AUTH_NEEDS_MFA
AUTHN_SUCCESS: str = _AUTHN_SUCCESS


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
            region_config=self._region_config,
        )

    @property
    def _country_code(self) -> str | None:
        """Expose the GraphQL country-code cache for legacy tests."""
        return self._graphql._country_code  # noqa: SLF001

    @_country_code.setter
    def _country_code(self, value: str | None) -> None:
        """Set the GraphQL country-code cache for compatibility.

        Args:
            value: myAir country code, or ``None`` to force token decoding later.
        """
        self._graphql._country_code = value  # noqa: SLF001

    @property
    def device_token(self) -> str | None:
        """Expose the remembered-device token that should be saved in config entries."""
        return self._auth.device_token

    @property
    def _cookies(self) -> dict[str, Any]:
        """Expose Okta cookies through the legacy private RESTClient attribute."""
        return self._auth.cookies

    @property
    def _json_headers(self) -> dict[str, Any]:
        """Expose JSON auth headers through the legacy private attribute."""
        return self._auth.json_headers

    @_json_headers.setter
    def _json_headers(self, value: Mapping[str, Any]) -> None:
        """Replace JSON auth headers through the legacy private attribute.

        Args:
            value: Header mapping used for subsequent Okta JSON requests.
        """
        self._auth.json_headers = value

    @property
    def _region_config(self) -> RegionConfig:
        """Expose regional endpoint settings through the legacy attribute."""
        return self._auth.region_config

    @_region_config.setter
    def _region_config(self, value: RegionConfig) -> None:
        """Replace regional endpoint settings through the legacy attribute.

        Args:
            value: Region configuration used by future auth calls.
        """
        self._auth.region_config = value

    @property
    def _email_factor_id(self) -> str:
        """Expose the active Okta email factor ID through the legacy attribute."""
        return self._auth.email_factor_id

    @_email_factor_id.setter
    def _email_factor_id(self, value: str) -> None:
        """Store the active Okta email factor ID through the legacy attribute.

        Args:
            value: MFA email factor ID to use for verification.
        """
        self._auth.email_factor_id = value

    @property
    def _mfa_url(self) -> str:
        """Expose the active Okta MFA verification URL through the legacy attribute."""
        return self._auth.mfa_url

    @_mfa_url.setter
    def _mfa_url(self, value: str) -> None:
        """Store the active Okta MFA verification URL through the legacy attribute.

        Args:
            value: Fully qualified Okta MFA verification URL.
        """
        self._auth.mfa_url = value

    @property
    def _cookie_dt(self) -> str | None:
        """Expose the remembered-device cookie through the legacy attribute."""
        return self._auth.device_token

    @_cookie_dt.setter
    def _cookie_dt(self, value: str | None) -> None:
        """Store the remembered-device cookie through the legacy attribute.

        Args:
            value: DT cookie value, or ``None`` to clear it.
        """
        self._auth.device_token = value

    @property
    def _cookie_sid(self) -> str | None:
        """Expose the Okta session cookie through the legacy attribute."""
        return self._auth.cookie_sid

    @_cookie_sid.setter
    def _cookie_sid(self, value: str | None) -> None:
        """Store the Okta session cookie through the legacy attribute.

        Args:
            value: ``sid`` cookie value, or ``None`` to clear it.
        """
        self._auth.cookie_sid = value

    @property
    def _uses_mfa(self) -> bool:
        """Expose whether Okta required MFA through the legacy attribute."""
        return self._auth.uses_mfa

    @_uses_mfa.setter
    def _uses_mfa(self, value: bool) -> None:
        """Store whether Okta required MFA through the legacy attribute.

        Args:
            value: ``True`` when the current auth flow is waiting for MFA.
        """
        self._auth.uses_mfa = value

    @property
    def _access_token(self) -> str | None:
        """Expose the OAuth bearer token through the legacy attribute."""
        return self._auth.access_token

    @_access_token.setter
    def _access_token(self, value: str | None) -> None:
        """Store the OAuth bearer token through the legacy attribute.

        Args:
            value: Access token, or ``None`` before auth succeeds.
        """
        self._auth.access_token = value

    @property
    def _id_token(self) -> str | None:
        """Expose the OAuth ID token through the legacy attribute."""
        return self._auth.id_token

    @_id_token.setter
    def _id_token(self, value: str | None) -> None:
        """Store the OAuth ID token through the legacy attribute.

        Args:
            value: ID token, or ``None`` before token exchange succeeds.
        """
        self._auth.id_token = value

    @property
    def _state_token(self) -> str | None:
        """Expose the Okta MFA state token through the legacy attribute."""
        return self._auth.state_token

    @_state_token.setter
    def _state_token(self, value: str | None) -> None:
        """Store the Okta MFA state token through the legacy attribute.

        Args:
            value: State token, or ``None`` when no MFA flow is active.
        """
        self._auth.state_token = value

    @property
    def _session_token(self) -> str | None:
        """Expose the Okta session token through the legacy attribute."""
        return self._auth.session_token

    @_session_token.setter
    def _session_token(self, value: str | None) -> None:
        """Store the Okta session token through the legacy attribute.

        Args:
            value: Session token, or ``None`` before auth succeeds.
        """
        self._auth.session_token = value

    def _refresh_auth_error_checker(self) -> None:
        """Route auth helper validation through RESTClient's compatibility wrapper."""
        self._auth.set_error_checker(self._resmed_response_error_check)

    async def connect(self, initial: bool | None = False) -> str:
        """Authenticate with myAir or reuse an active OAuth token.

        Args:
            initial: Whether the call is part of config setup, where MFA can be
                triggered and surfaced to the user.

        Returns:
            Okta authentication status.
        """
        self._refresh_auth_error_checker()
        return await self._auth.connect(
            initial=initial,
            get_initial_dt=self._get_initial_dt,
            is_access_token_active=self._is_access_token_active,
            authn_check=self._authn_check,
            trigger_mfa=self._trigger_mfa,
            get_access_token=self._get_access_token,
        )

    async def verify_mfa_and_get_access_token(self, verification_code: str) -> str:
        """Complete an MFA challenge and cache OAuth tokens.

        Args:
            verification_code: Email MFA code supplied by the user.

        Returns:
            Okta authentication status after MFA verification.
        """
        self._refresh_auth_error_checker()
        return await self._auth.verify_mfa_and_get_access_token(
            verification_code,
            verify_mfa=self._verify_mfa,
            get_access_token=self._get_access_token,
        )

    async def is_email_verified(self) -> bool:
        """Return whether Okta userinfo reports a verified email address."""
        self._refresh_auth_error_checker()
        return await self._auth.is_email_verified()

    @staticmethod
    async def _resmed_response_error_check(
        step: str,
        response: ClientResponse,
        resp_dict: MutableMapping[str, Any],
        initial: bool | None = False,
    ) -> None:
        """Validate ResMed responses through the legacy static helper.

        Args:
            step: Human-readable auth or GraphQL step name for diagnostics.
            response: aiohttp response object associated with the payload.
            resp_dict: Decoded response payload to inspect.
            initial: Whether the request belongs to initial config setup.
        """
        return await MyAirAuthSession.resmed_response_error_check(
            step, response, resp_dict, initial
        )

    async def _extract_and_update_cookies(self, cookie_headers: list) -> None:
        """Update remembered-device and session cookies from Okta headers.

        Args:
            cookie_headers: Raw ``Set-Cookie`` header values from Okta responses.
        """
        self._refresh_auth_error_checker()
        await self._auth.extract_and_update_cookies(cookie_headers)

    async def _get_initial_dt(self) -> None:
        """Bootstrap the remembered-device cookie before primary authentication."""
        self._refresh_auth_error_checker()
        await self._auth.get_initial_dt(self._extract_and_update_cookies)

    async def _is_access_token_active(self) -> bool:
        """Check if the cached OAuth token can be reused.

        Returns:
            ``True`` when Okta introspection marks the token active.
        """
        self._refresh_auth_error_checker()
        return await self._auth.is_access_token_active()

    async def _authn_check(self) -> str:
        """Run primary Okta username/password authentication.

        Returns:
            Okta status indicating success or an MFA requirement.
        """
        self._refresh_auth_error_checker()
        return await self._auth.authn_check()

    async def _trigger_mfa(self) -> None:
        """Send an email MFA challenge for the active Okta state token."""
        self._refresh_auth_error_checker()
        return await self._auth.trigger_mfa()

    async def _verify_mfa(self, verification_code: str) -> str:
        """Submit an email MFA code and capture the resulting session token.

        Args:
            verification_code: MFA code supplied by the user.

        Returns:
            Okta status after verification.
        """
        self._refresh_auth_error_checker()
        return await self._auth.verify_mfa(verification_code)

    async def _get_access_token(self) -> None:
        """Exchange the Okta session token for OAuth access and ID tokens."""
        self._refresh_auth_error_checker()
        await self._auth.get_access_token(self._extract_and_update_cookies)

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
        try:
            records: list[Mapping[str, Any]] = records_dict["data"]["getPatientWrapper"][
                "sleepRecords"
            ]["items"]
        except Exception as e:
            _LOGGER.error("Error getting Patient Sleep Records. %s: %s", type(e).__name__, e)
            raise ParsingError("Error getting Patient Sleep Records") from e
        if not isinstance(records, list):
            _LOGGER.error("Error getting Patient Sleep Records. Returned records is not a list")
            raise ParsingError(
                "Error getting Patient Sleep Records. Returned records is not a list"
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
        try:
            device: dict[str, Any] = records_dict["data"]["getPatientWrapper"]["fgDevices"][0]
        except Exception as e:
            _LOGGER.error("Error getting User Device Data. %s: %s", type(e).__name__, e)
            raise ParsingError("Error getting User Device Data") from e
        mask_code: str | None = None
        try:
            mask_code = records_dict["data"]["getPatientWrapper"]["masks"][0]["maskCode"]
        except (KeyError, IndexError, TypeError) as e:
            _LOGGER.warning("Error getting User Mask Data. %s: %s", type(e).__name__, e)
        else:
            if mask_code:
                device["maskCode"] = mask_code
        if not isinstance(device, dict):
            _LOGGER.error("Error getting User Device Data. Returned data is not a dict")
            raise ParsingError("Error getting User Device Data. Returned data is not a dict")
        _LOGGER.debug("[get_user_device_data] device: %s", redact_dict(device))
        return MyAirDevice.from_api(device)
