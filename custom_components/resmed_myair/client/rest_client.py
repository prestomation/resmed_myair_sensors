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
    """myAir uses oauth on Okta and AWS AppSync GraphQL."""

    def __init__(self, config: MyAirConfig, session: ClientSession) -> None:
        """Initialize REST Client."""
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
        """Compatibility alias for GraphQL country code cache."""
        return self._graphql._country_code  # noqa: SLF001

    @_country_code.setter
    def _country_code(self, value: str | None) -> None:
        self._graphql._country_code = value  # noqa: SLF001

    @property
    def device_token(self) -> str | None:
        """Return the device token."""
        return self._auth.device_token

    @property
    def _cookies(self) -> dict[str, Any]:
        """Compatibility cookie mapping."""
        return self._auth.cookies

    @property
    def _json_headers(self) -> dict[str, Any]:
        """Compatibility JSON header mapping."""
        return self._auth.json_headers

    @_json_headers.setter
    def _json_headers(self, value: Mapping[str, Any]) -> None:
        self._auth.json_headers = value

    @property
    def _region_config(self) -> RegionConfig:
        """Return region config from auth session."""
        return self._auth.region_config

    @_region_config.setter
    def _region_config(self, value: RegionConfig) -> None:
        self._auth.region_config = value

    @property
    def _email_factor_id(self) -> str:
        """Return MFA factor ID from auth session."""
        return self._auth.email_factor_id

    @_email_factor_id.setter
    def _email_factor_id(self, value: str) -> None:
        self._auth.email_factor_id = value

    @property
    def _mfa_url(self) -> str:
        """Return MFA verification URL from auth session."""
        return self._auth.mfa_url

    @_mfa_url.setter
    def _mfa_url(self, value: str) -> None:
        self._auth.mfa_url = value

    @property
    def _cookie_dt(self) -> str | None:
        """Return DT cookie from auth session."""
        return self._auth.device_token

    @_cookie_dt.setter
    def _cookie_dt(self, value: str | None) -> None:
        self._auth.device_token = value

    @property
    def _cookie_sid(self) -> str | None:
        """Return sid cookie from auth session."""
        return self._auth.cookie_sid

    @_cookie_sid.setter
    def _cookie_sid(self, value: str | None) -> None:
        self._auth.cookie_sid = value

    @property
    def _uses_mfa(self) -> bool:
        """Return MFA-needed marker from auth session."""
        return self._auth.uses_mfa

    @_uses_mfa.setter
    def _uses_mfa(self, value: bool) -> None:
        self._auth.uses_mfa = value

    @property
    def _access_token(self) -> str | None:
        """Compatibility alias for access token."""
        return self._auth.access_token

    @_access_token.setter
    def _access_token(self, value: str | None) -> None:
        self._auth.access_token = value

    @property
    def _id_token(self) -> str | None:
        """Compatibility alias for ID token."""
        return self._auth.id_token

    @_id_token.setter
    def _id_token(self, value: str | None) -> None:
        self._auth.id_token = value

    @property
    def _state_token(self) -> str | None:
        """Compatibility alias for state token."""
        return self._auth.state_token

    @_state_token.setter
    def _state_token(self, value: str | None) -> None:
        self._auth.state_token = value

    @property
    def _session_token(self) -> str | None:
        """Compatibility alias for session token."""
        return self._auth.session_token

    @_session_token.setter
    def _session_token(self, value: str | None) -> None:
        self._auth.session_token = value

    def _refresh_auth_error_checker(self) -> None:
        """Keep auth error checks aligned with the public wrapper."""
        self._auth.set_error_checker(self._resmed_response_error_check)

    async def connect(self, initial: bool | None = False) -> str:
        """Check authn and connect to ResMed servers."""
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
        """Confirm valid MFA and obtain access token."""
        self._refresh_auth_error_checker()
        return await self._auth.verify_mfa_and_get_access_token(
            verification_code,
            verify_mfa=self._verify_mfa,
            get_access_token=self._get_access_token,
        )

    async def is_email_verified(self) -> bool:
        """Check if email address is verified."""
        self._refresh_auth_error_checker()
        return await self._auth.is_email_verified()

    @staticmethod
    async def _resmed_response_error_check(
        step: str,
        response: ClientResponse,
        resp_dict: MutableMapping[str, Any],
        initial: bool | None = False,
    ) -> None:
        """Compatibility wrapper over MyAirAuthSession error handling."""
        return await MyAirAuthSession.resmed_response_error_check(
            step, response, resp_dict, initial
        )

    async def _extract_and_update_cookies(self, cookie_headers: list) -> None:
        """Compatibility wrapper for auth session cookie extraction."""
        self._refresh_auth_error_checker()
        await self._auth.extract_and_update_cookies(cookie_headers)

    async def _get_initial_dt(self) -> None:
        """Compatibility wrapper for auth initial DT retrieval."""
        self._refresh_auth_error_checker()
        await self._auth.get_initial_dt(self._extract_and_update_cookies)

    async def _is_access_token_active(self) -> bool:
        """Compatibility wrapper for access token status check."""
        self._refresh_auth_error_checker()
        return await self._auth.is_access_token_active()

    async def _authn_check(self) -> str:
        """Compatibility wrapper for authn check."""
        self._refresh_auth_error_checker()
        return await self._auth.authn_check()

    async def _trigger_mfa(self) -> None:
        """Compatibility wrapper for MFA trigger."""
        self._refresh_auth_error_checker()
        return await self._auth.trigger_mfa()

    async def _verify_mfa(self, verification_code: str) -> str:
        """Compatibility wrapper for MFA verification."""
        self._refresh_auth_error_checker()
        return await self._auth.verify_mfa(verification_code)

    async def _get_access_token(self) -> None:
        """Compatibility wrapper for token exchange."""
        self._refresh_auth_error_checker()
        await self._auth.get_access_token(self._extract_and_update_cookies)

    async def _gql_query(
        self, operation_name: str, query: str, initial: bool | None = False
    ) -> dict[str, Any]:
        """Run a GraphQL query through the transport client."""
        return await self._graphql.query(operation_name, query, initial=bool(initial))

    async def get_sleep_records(self, initial: bool | None = False) -> list[MyAirSleepRecord]:
        """Get sleep records from ResMed servers."""
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
        return [MyAirSleepRecord.from_api(record) for record in records]

    async def get_user_device_data(self, initial: bool | None = False) -> MyAirDevice:
        """Get user device data from ResMed servers."""
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
        except Exception as e:  # noqa: BLE001
            _LOGGER.warning("Error getting User Mask Data. %s: %s", type(e).__name__, e)
        else:
            if mask_code:
                device["maskCode"] = mask_code
        if not isinstance(device, dict):
            _LOGGER.error("Error getting User Device Data. Returned data is not a dict")
            raise ParsingError("Error getting User Device Data. Returned data is not a dict")
        _LOGGER.debug("[get_user_device_data] device: %s", redact_dict(device))
        return MyAirDevice.from_api(device)
