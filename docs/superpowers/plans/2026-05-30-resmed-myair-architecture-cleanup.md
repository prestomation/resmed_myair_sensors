# ResMed myAir Architecture Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor the ResMed myAir integration into focused, typed, testable units while preserving existing Home Assistant config entries, entities, services, and sensor behavior.

**Architecture:** Keep `RESTClient` as the public `MyAirClient` facade, but move auth/session state, GraphQL transport, response parsing, and typed domain data into focused modules. The coordinator will own typed `MyAirCoordinatorData`; sensors and config flow will consume stable model properties instead of raw nested dictionaries.

**Tech Stack:** Home Assistant custom integration, Python 3.14, aiohttp, PyJWT, pytest, pytest-homeassistant-custom-component, ruff, mypy, prek.

---

## File Structure

- Create `custom_components/resmed_myair/client/regions.py`: region-specific Okta/OAuth/AppSync settings and URL builders.
- Create `custom_components/resmed_myair/client/auth.py`: Okta authn, MFA, cookie, token exchange, token introspection, and email verification.
- Create `custom_components/resmed_myair/client/graphql.py`: AppSync GraphQL POST wrapper, country-code derivation, and GraphQL error mapping.
- Create `custom_components/resmed_myair/models.py`: typed `MyAirDevice`, `MyAirSleepRecord`, and `MyAirCoordinatorData` domain objects.
- Create `custom_components/resmed_myair/redaction.py`: single redaction implementation used by integration and client modules.
- Modify `custom_components/resmed_myair/client/rest_client.py`: reduce to a facade that composes `MyAirAuthSession` and `MyAirGraphQLClient`.
- Modify `custom_components/resmed_myair/client/myair_client.py`: update protocol return types to typed models.
- Modify `custom_components/resmed_myair/coordinator.py`: return typed coordinator data and keep auth failure semantics.
- Modify `custom_components/resmed_myair/sensor.py`: read typed coordinator data through shared extraction helpers while preserving unique IDs and native values.
- Modify `custom_components/resmed_myair/config_flow.py`: share login/MFA/device validation helpers across setup and reauth.
- Modify `custom_components/resmed_myair/helpers.py` and `custom_components/resmed_myair/client/helpers.py`: import redaction from the new shared module.
- Test files to update or add:
  - `tests/test_oauth_helper_spike.py`
  - `tests/test_models.py`
  - `tests/test_redaction.py`
  - `tests/test_rest_client.py`
  - `tests/test_coordinator.py`
  - `tests/test_sensor.py`
  - `tests/test_config_flow.py`

## Task 1: Record OAuth Helper Feasibility Decision

**Files:**
- Create: `tests/test_oauth_helper_spike.py`
- Create: `docs/superpowers/oauth-helper-spike.md`

- [ ] **Step 1: Write the characterization test**

Add `tests/test_oauth_helper_spike.py`:

```python
"""Tests documenting OAuth helper feasibility for ResMed myAir."""

from custom_components.resmed_myair.client.rest_client import EU_CONFIG, NA_CONFIG


def test_resmed_registered_redirect_urls_are_external() -> None:
    """ResMed's app redirect URLs are not Home Assistant callback URLs."""
    redirect_urls = {
        NA_CONFIG["oauth_redirect_url"],
        EU_CONFIG["oauth_redirect_url"],
    }

    assert redirect_urls == {
        "https://myair.resmed.com",
        "https://myair.resmed.eu",
    }
    assert all("/auth/external/callback" not in url for url in redirect_urls)
```

- [ ] **Step 2: Run the characterization test**

Run:

```bash
./.venv/bin/pytest tests/test_oauth_helper_spike.py -q
```

Expected: PASS. This confirms the current constants encode ResMed-owned redirect URLs.

- [ ] **Step 3: Add the spike note**

Create `docs/superpowers/oauth-helper-spike.md`:

```markdown
# ResMed OAuth Helper Feasibility Spike

The current integration cannot assume Home Assistant's OAuth2 helper can replace
the custom auth flow because the reverse-engineered ResMed Okta application uses
ResMed-owned redirect URLs:

- North America: `https://myair.resmed.com`
- Europe: `https://myair.resmed.eu`

Home Assistant's OAuth2 helper is still worth revisiting if ResMed exposes a
client that accepts a Home Assistant callback URL. Until then, this cleanup keeps
custom auth but isolates it behind `MyAirAuthSession` so the implementation can
be replaced later without changing sensors, coordinator, or config-flow logic.
```

- [ ] **Step 4: Run the characterization test again**

Run:

```bash
./.venv/bin/pytest tests/test_oauth_helper_spike.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add docs/superpowers/oauth-helper-spike.md tests/test_oauth_helper_spike.py
git commit -m "docs: record ResMed OAuth helper feasibility"
```

## Task 2: Consolidate Redaction

**Files:**
- Create: `custom_components/resmed_myair/redaction.py`
- Modify: `custom_components/resmed_myair/helpers.py`
- Modify: `custom_components/resmed_myair/client/helpers.py`
- Test: `tests/test_redaction.py`
- Test: `tests/test_helpers.py`

- [ ] **Step 1: Write the shared redaction tests**

Add `tests/test_redaction.py`:

```python
"""Tests for shared ResMed myAir redaction helpers."""

from custom_components.resmed_myair.redaction import REDACTED, redact_dict


def test_redact_dict_redacts_nested_sensitive_values() -> None:
    """Sensitive keys are redacted inside mappings and lists."""
    data = {
        "Username": "person@example.com",
        "nested": [{"access_token": "token-value"}, {"safe": "value"}],
        "safe": "visible",
    }

    assert redact_dict(data) == {
        "Username": REDACTED,
        "nested": [{"access_token": REDACTED}, {"safe": "value"}],
        "safe": "visible",
    }


def test_redact_dict_returns_non_collection_values_unchanged() -> None:
    """Scalar values are returned unchanged."""
    assert redact_dict("plain") == "plain"
    assert redact_dict(None) is None
```

- [ ] **Step 2: Run the new tests and confirm the module is missing**

Run:

```bash
./.venv/bin/pytest tests/test_redaction.py -q
```

Expected: FAIL with `ModuleNotFoundError: No module named 'custom_components.resmed_myair.redaction'`.

- [ ] **Step 3: Add the shared redaction module**

Create `custom_components/resmed_myair/redaction.py`:

```python
"""Shared redaction helpers for ResMed myAir logs."""

from collections.abc import Mapping, MutableMapping
from typing import Any

from .const import KEYS_TO_REDACT

REDACTED = "**REDACTED**"


def redact_dict(data: Any | None) -> Any | None:
    """Redact sensitive values from nested dictionaries and lists.

    Args:
        data: Value to redact.

    Returns:
        A redacted copy of mappings/lists, or the original scalar value.
    """
    if not isinstance(data, Mapping | list):
        return data

    if isinstance(data, list):
        return [redact_dict(value) for value in data]

    redacted: MutableMapping[str, Any] = {**data}
    for key, value in redacted.items():
        if value is None or (isinstance(value, str) and not value):
            continue
        if key in KEYS_TO_REDACT:
            redacted[key] = REDACTED
        elif isinstance(value, MutableMapping):
            redacted[key] = redact_dict(value)
        elif isinstance(value, list):
            redacted[key] = [redact_dict(item) for item in value]
    return redacted
```

- [ ] **Step 4: Replace duplicate helper implementations with imports**

Replace the contents of `custom_components/resmed_myair/helpers.py` with:

```python
"""Helper functions for Home Assistant resmed_myair."""

from .redaction import REDACTED, redact_dict

__all__ = ["REDACTED", "redact_dict"]
```

Replace the contents of `custom_components/resmed_myair/client/helpers.py` with:

```python
"""Helper functions for ResMed myAir Client."""

from ..redaction import REDACTED, redact_dict

__all__ = ["REDACTED", "redact_dict"]
```

- [ ] **Step 5: Run redaction and existing helper tests**

Run:

```bash
./.venv/bin/pytest tests/test_redaction.py tests/test_helpers.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit**

Run:

```bash
git add custom_components/resmed_myair/redaction.py custom_components/resmed_myair/helpers.py custom_components/resmed_myair/client/helpers.py tests/test_redaction.py tests/test_helpers.py
git commit -m "refactor: consolidate redaction helpers"
```

## Task 3: Add Typed Domain Models

**Files:**
- Create: `custom_components/resmed_myair/models.py`
- Test: `tests/test_models.py`

- [ ] **Step 1: Write model tests**

Add `tests/test_models.py`:

```python
"""Tests for typed ResMed myAir domain models."""

from datetime import date

from custom_components.resmed_myair.models import (
    MyAirCoordinatorData,
    MyAirDevice,
    MyAirSleepRecord,
)


def test_device_preserves_raw_values_and_device_info_fields() -> None:
    """Device model exposes stable fields while preserving raw API data."""
    device = MyAirDevice.from_api(
        {
            "serialNumber": "123",
            "localizedName": "AirSense",
            "deviceType": "CPAP",
            "fgDeviceManufacturerName": "ResMed",
            "lastSleepDataReportTime": "2024-07-18T12:00:00+00:00",
            "maskCode": "M1",
        }
    )

    assert device.serial_number == "123"
    assert device.native_value("maskCode") == "M1"
    assert device.native_value("missing") is None


def test_sleep_record_parses_usage_and_start_date() -> None:
    """Sleep record model exposes typed convenience values."""
    record = MyAirSleepRecord.from_api(
        {
            "startDate": "2024-07-18",
            "totalUsage": 125,
            "ahi": 1.2,
        }
    )

    assert record.start_date == date(2024, 7, 18)
    assert record.total_usage_minutes == 125
    assert record.friendly_usage_time == "2:05"
    assert record.native_value("ahi") == 1.2


def test_negative_usage_is_clamped_for_friendly_display() -> None:
    """Negative usage values display as zero usage."""
    record = MyAirSleepRecord.from_api({"startDate": "2024-07-18", "totalUsage": -5})

    assert record.friendly_usage_time == "0:00"


def test_coordinator_data_exposes_latest_and_most_recent_used_date() -> None:
    """Coordinator data exposes the latest record and most recent used date."""
    data = MyAirCoordinatorData(
        device=MyAirDevice.from_api({"serialNumber": "123"}),
        sleep_records=(
            MyAirSleepRecord.from_api({"startDate": "2024-07-17", "totalUsage": 0}),
            MyAirSleepRecord.from_api({"startDate": "2024-07-18", "totalUsage": 30}),
        ),
    )

    assert data.latest_sleep_record is not None
    assert data.latest_sleep_record.start_date == date(2024, 7, 18)
    assert data.most_recent_sleep_date == date(2024, 7, 18)
```

- [ ] **Step 2: Run model tests and confirm the module is missing**

Run:

```bash
./.venv/bin/pytest tests/test_models.py -q
```

Expected: FAIL with `ModuleNotFoundError: No module named 'custom_components.resmed_myair.models'`.

- [ ] **Step 3: Implement the typed models**

Create `custom_components/resmed_myair/models.py`:

```python
"""Typed domain models for ResMed myAir data."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Self

from homeassistant.util import dt as dt_util


@dataclass(frozen=True, slots=True)
class MyAirDevice:
    """Typed view of a ResMed device payload."""

    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_api(cls, data: Mapping[str, Any] | None) -> Self:
        """Build a device model from API data.

        Args:
            data: Raw device mapping returned by ResMed.

        Returns:
            A typed device wrapper.
        """
        return cls(raw=dict(data or {}))

    @property
    def serial_number(self) -> str:
        """Return the device serial number."""
        value = self.raw.get("serialNumber")
        return value if isinstance(value, str) else ""

    @property
    def manufacturer(self) -> str | None:
        """Return the device manufacturer name."""
        value = self.raw.get("fgDeviceManufacturerName")
        return value if isinstance(value, str) else None

    @property
    def model(self) -> str | None:
        """Return the device model."""
        value = self.raw.get("deviceType")
        return value if isinstance(value, str) else None

    @property
    def name(self) -> str | None:
        """Return the localized device name."""
        value = self.raw.get("localizedName")
        return value if isinstance(value, str) else None

    def native_value(self, key: str) -> Any | None:
        """Return a raw value by API key.

        Args:
            key: API key to read.

        Returns:
            The raw value, or `None` when absent.
        """
        return self.raw.get(key)


@dataclass(frozen=True, slots=True)
class MyAirSleepRecord:
    """Typed view of a ResMed sleep record payload."""

    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_api(cls, data: Mapping[str, Any] | None) -> Self:
        """Build a sleep-record model from API data.

        Args:
            data: Raw sleep record mapping returned by ResMed.

        Returns:
            A typed sleep-record wrapper.
        """
        return cls(raw=dict(data or {}))

    @property
    def start_date(self) -> date | None:
        """Return the parsed sleep record start date."""
        value = self.raw.get("startDate")
        if not isinstance(value, str):
            return None
        return dt_util.parse_date(value)

    @property
    def total_usage_minutes(self) -> int | None:
        """Return total usage minutes."""
        value = self.raw.get("totalUsage")
        return value if isinstance(value, int) else None

    @property
    def friendly_usage_time(self) -> str | None:
        """Return usage minutes formatted as H:MM."""
        if self.total_usage_minutes is None:
            return None
        usage_minutes = max(self.total_usage_minutes, 0)
        return f"{usage_minutes // 60}:{(usage_minutes % 60):02}"

    @property
    def has_usage(self) -> bool:
        """Return whether this record contains positive machine usage."""
        return self.total_usage_minutes is not None and self.total_usage_minutes > 0

    def native_value(self, key: str) -> Any | None:
        """Return a raw value by API key.

        Args:
            key: API key to read.

        Returns:
            The raw value, or `None` when absent.
        """
        return self.raw.get(key)


@dataclass(frozen=True, slots=True)
class MyAirCoordinatorData:
    """Typed data payload stored by the update coordinator."""

    device: MyAirDevice | None = None
    sleep_records: tuple[MyAirSleepRecord, ...] = ()

    @property
    def latest_sleep_record(self) -> MyAirSleepRecord | None:
        """Return the latest sleep record from the API order."""
        return self.sleep_records[-1] if self.sleep_records else None

    @property
    def most_recent_sleep_date(self) -> date | None:
        """Return the most recent date with positive usage."""
        records_with_usage = [record for record in self.sleep_records if record.has_usage]
        if not records_with_usage:
            return None
        return records_with_usage[-1].start_date
```

- [ ] **Step 4: Run model tests**

Run:

```bash
./.venv/bin/pytest tests/test_models.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add custom_components/resmed_myair/models.py tests/test_models.py
git commit -m "feat: add typed myAir domain models"
```

## Task 4: Move Region Configuration

**Files:**
- Create: `custom_components/resmed_myair/client/regions.py`
- Modify: `custom_components/resmed_myair/client/rest_client.py`
- Test: `tests/test_rest_client.py`

- [ ] **Step 1: Add tests for region lookup**

Append to `tests/test_rest_client.py`:

```python
from custom_components.resmed_myair.client.regions import RegionConfig, get_region_config
from custom_components.resmed_myair.const import REGION_EU, REGION_NA


def test_get_region_config_returns_na_settings() -> None:
    """NA region lookup returns the existing ResMed endpoints."""
    config = get_region_config(REGION_NA)

    assert isinstance(config, RegionConfig)
    assert config.product == "myAir"
    assert config.oauth_redirect_url == "https://myair.resmed.com"
    assert config.authn_url == "https://resmed-ext-1.okta.com/api/v1/authn"


def test_get_region_config_returns_eu_settings() -> None:
    """EU region lookup returns the existing ResMed endpoints."""
    config = get_region_config(REGION_EU)

    assert config.product == "myAir EU"
    assert config.oauth_redirect_url == "https://myair.resmed.eu"
    assert config.authn_url == "https://id.resmed.eu/api/v1/authn"
```

- [ ] **Step 2: Run the targeted tests and confirm the module is missing**

Run:

```bash
./.venv/bin/pytest tests/test_rest_client.py::test_get_region_config_returns_na_settings tests/test_rest_client.py::test_get_region_config_returns_eu_settings -q
```

Expected: FAIL with `ModuleNotFoundError: No module named 'custom_components.resmed_myair.client.regions'`.

- [ ] **Step 3: Implement region configuration**

Create `custom_components/resmed_myair/client/regions.py`:

```python
"""Region-specific ResMed myAir endpoint configuration."""

from dataclasses import dataclass
from typing import Self

from ..const import REGION_NA


@dataclass(frozen=True, slots=True)
class RegionConfig:
    """Endpoint and client settings for a ResMed myAir region."""

    product: str
    okta_url: str
    email_factor_id: str
    auth_server_id: str
    authorize_client_id: str
    myair_api_key: str
    graphql_url: str
    oauth_redirect_url: str

    @classmethod
    def from_mapping(cls, data: dict[str, str]) -> Self:
        """Build a region config from a string mapping.

        Args:
            data: Region configuration mapping.

        Returns:
            A typed region configuration.
        """
        return cls(**data)

    @property
    def authn_url(self) -> str:
        """Return the Okta authn URL."""
        return f"https://{self.okta_url}/api/v1/authn"

    @property
    def authorize_url(self) -> str:
        """Return the Okta authorize URL."""
        return f"https://{self.okta_url}/oauth2/{self.auth_server_id}/v1/authorize"

    @property
    def token_url(self) -> str:
        """Return the Okta token URL."""
        return f"https://{self.okta_url}/oauth2/{self.auth_server_id}/v1/token"

    @property
    def introspect_url(self) -> str:
        """Return the Okta token introspection URL."""
        return f"https://{self.okta_url}/oauth2/{self.auth_server_id}/v1/introspect"

    @property
    def userinfo_url(self) -> str:
        """Return the Okta userinfo URL."""
        return f"https://{self.okta_url}/oauth2/{self.auth_server_id}/v1/userinfo"

    def mfa_url(self, email_factor_id: str | None = None) -> str:
        """Return the Okta MFA verification URL.

        Args:
            email_factor_id: Optional factor ID discovered from authn.

        Returns:
            The MFA verification URL.
        """
        factor_id = email_factor_id or self.email_factor_id
        return (
            f"https://{self.okta_url}/api/v1/authn/factors/{factor_id}"
            "/verify?rememberDevice=true"
        )


NA_CONFIG = RegionConfig(
    product="myAir",
    okta_url="resmed-ext-1.okta.com",
    email_factor_id="xxx",
    auth_server_id="aus4ccsxvnidQgLmA297",
    authorize_client_id="0oa4ccq1v413ypROi297",
    myair_api_key="da2-cenztfjrezhwphdqtwtbpqvzui",
    graphql_url="https://graphql.myair-prd.dht.live/graphql",
    oauth_redirect_url="https://myair.resmed.com",
)

EU_CONFIG = RegionConfig(
    product="myAir EU",
    okta_url="id.resmed.eu",
    email_factor_id="emfg9cmjqxEPr52cT417",
    auth_server_id="aus2uznux2sYKTsEg417",
    authorize_client_id="0oa2uz04d2Pks2NgR417",
    myair_api_key="da2-o66oo6xdnfh5hlfuw5yw5g2dtm",
    graphql_url="https://graphql.hyperdrive.resmed.eu/graphql",
    oauth_redirect_url="https://myair.resmed.eu",
)


def get_region_config(region: str) -> RegionConfig:
    """Return endpoint configuration for a region.

    Args:
        region: Config-entry region value.

    Returns:
        Region endpoint configuration.
    """
    return NA_CONFIG if region == REGION_NA else EU_CONFIG
```

- [ ] **Step 4: Keep backward-compatible imports during the split**

At the top of `custom_components/resmed_myair/client/rest_client.py`, import:

```python
from .regions import EU_CONFIG, NA_CONFIG, RegionConfig, get_region_config
```

Then replace region selection in `RESTClient.__init__` with:

```python
self._region_config: RegionConfig = get_region_config(self._config.region)
self._email_factor_id: str = self._region_config.email_factor_id
self._mfa_url: str = self._region_config.mfa_url(self._email_factor_id)
```

Replace dictionary access in `rest_client.py` with attribute access:

```python
self._region_config.authn_url
self._region_config.authorize_url
self._region_config.token_url
self._region_config.introspect_url
self._region_config.userinfo_url
self._region_config.authorize_client_id
self._region_config.oauth_redirect_url
self._region_config.graphql_url
self._region_config.myair_api_key
self._region_config.product
```

Keep `EU_CONFIG` and `NA_CONFIG` importable from `rest_client.py` for existing tests by leaving the imported names at module scope.

- [ ] **Step 5: Run REST client tests**

Run:

```bash
./.venv/bin/pytest tests/test_rest_client.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit**

Run:

```bash
git add custom_components/resmed_myair/client/regions.py custom_components/resmed_myair/client/rest_client.py tests/test_rest_client.py
git commit -m "refactor: move ResMed region configuration"
```

## Task 5: Split Auth Session from REST Client

**Files:**
- Create: `custom_components/resmed_myair/client/auth.py`
- Modify: `custom_components/resmed_myair/client/rest_client.py`
- Test: `tests/test_rest_client.py`

- [ ] **Step 1: Add tests for auth session composition**

Append to `tests/test_rest_client.py`:

```python
from custom_components.resmed_myair.client.auth import MyAirAuthSession


def test_rest_client_owns_auth_session(myair_config, aiohttp_client_session) -> None:
    """RESTClient composes a dedicated auth session."""
    client = RESTClient(myair_config, aiohttp_client_session)

    assert isinstance(client._auth, MyAirAuthSession)
    assert client.device_token == myair_config.device_token
```

- [ ] **Step 2: Run the targeted test and confirm the module is missing**

Run:

```bash
./.venv/bin/pytest tests/test_rest_client.py::test_rest_client_owns_auth_session -q
```

Expected: FAIL with `ModuleNotFoundError: No module named 'custom_components.resmed_myair.client.auth'`.

- [ ] **Step 3: Move auth state and methods into `MyAirAuthSession`**

Create `custom_components/resmed_myair/client/auth.py` by moving these methods and state from `RESTClient`:

```python
"""Authentication and token handling for ResMed myAir."""

import base64
from http.cookies import SimpleCookie
import logging
import os
import re
from typing import Any
from urllib.parse import DefragResult, parse_qs, urldefrag

from aiohttp import ClientResponse, ClientSession
from aiohttp.http_exceptions import HttpProcessingError
from multidict import CIMultiDict

from ..const import AUTH_NEEDS_MFA, AUTHN_SUCCESS
from ..redaction import redact_dict
from .myair_client import AuthenticationError, IncompleteAccountError, MyAirConfig, ParsingError
from .regions import RegionConfig, get_region_config

_LOGGER: logging.Logger = logging.getLogger(__name__)


class MyAirAuthSession:
    """Manage Okta authentication, MFA, cookies, and OAuth tokens."""

    def __init__(self, config: MyAirConfig, session: ClientSession) -> None:
        """Initialize the auth session.

        Args:
            config: myAir login configuration.
            session: Shared aiohttp client session.
        """
        self._config = config
        self._session = session
        self._region_config: RegionConfig = get_region_config(config.region)
        self._json_headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self._access_token: str | None = None
        self._id_token: str | None = None
        self._state_token: str | None = None
        self._session_token: str | None = None
        self._cookie_dt: str | None = config.device_token
        self._cookie_sid: str | None = None
        self._uses_mfa = False
        self._email_factor_id = self._region_config.email_factor_id
        self._mfa_url = self._region_config.mfa_url(self._email_factor_id)

    @property
    def access_token(self) -> str | None:
        """Return the current access token."""
        return self._access_token

    @property
    def id_token(self) -> str | None:
        """Return the current ID token."""
        return self._id_token

    @property
    def device_token(self) -> str | None:
        """Return the current Okta device token."""
        return self._cookie_dt

    @property
    def cookies(self) -> dict[str, str]:
        """Return active Okta cookies."""
        cookies: dict[str, str] = {}
        if self._cookie_dt:
            cookies["DT"] = self._cookie_dt
        if self._cookie_sid:
            cookies["sid"] = self._cookie_sid
        return cookies

    async def connect(self, initial: bool = False) -> str:
        """Authenticate with ResMed and ensure an access token exists.

        Args:
            initial: Whether this is an initial config-flow login.

        Returns:
            Okta auth status.
        """
        if self._cookie_dt is None:
            await self._get_initial_dt()
        if self._cookie_dt is None and self._uses_mfa:
            _LOGGER.warning("Device Token is not set; MFA may be required more often")
        if self._access_token and await self._is_access_token_active():
            return AUTHN_SUCCESS
        _LOGGER.info("Starting ResMed myAir authentication")
        status = await self._authn_check()
        if status == AUTH_NEEDS_MFA:
            self._uses_mfa = True
            if initial:
                await self._trigger_mfa()
            else:
                raise AuthenticationError("Need to Re-Verify MFA")
        else:
            await self._get_access_token()
        return status

    async def verify_mfa_and_get_access_token(self, verification_code: str) -> str:
        """Verify MFA and obtain an access token.

        Args:
            verification_code: MFA verification code from email.

        Returns:
            Okta auth status.
        """
        status = await self._verify_mfa(verification_code)
        if status != AUTHN_SUCCESS:
            raise AuthenticationError(f"Issue verifying MFA. Status: {status}")
        await self._get_access_token()
        return status

    async def is_email_verified(self) -> bool:
        """Return whether the ResMed account email is verified."""
        headers = {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        async with self._session.get(
            self._region_config.userinfo_url,
            headers=headers,
            allow_redirects=False,
        ) as userinfo_res:
            userinfo_dict = await userinfo_res.json()
            await self._resmed_response_error_check("userinfo_query", userinfo_res, userinfo_dict)
        return userinfo_dict.get("email_verified") is True

    async def _extract_and_update_cookies(self, cookie_headers: list[str]) -> None:
        """Extract DT and sid cookies from Set-Cookie headers."""
        cookies: dict[str, str] = {}
        for header in cookie_headers:
            cookie = SimpleCookie(header)
            for key, morsel in cookie.items():
                normalized = key.lower()
                if normalized in {"dt", "sid"}:
                    cookies["DT" if normalized == "dt" else "sid"] = morsel.value
        if cookies.get("DT") and cookies["DT"] != self._cookie_dt:
            if self._cookie_dt is not None:
                _LOGGER.debug("Updating ResMed device token")
            self._cookie_dt = cookies["DT"]
        if cookies.get("sid") and cookies["sid"] != self._cookie_sid:
            self._cookie_sid = cookies["sid"]

    async def _get_initial_dt(self) -> None:
        """Fetch an initial Okta device token cookie."""
        async with self._session.get(
            self._region_config.authorize_url,
            headers=self._json_headers,
            raise_for_status=False,
            allow_redirects=False,
        ) as initial_dt_res:
            cookie_headers = initial_dt_res.headers.getall("set-cookie", [])
        await self._extract_and_update_cookies(cookie_headers)

    async def _is_access_token_active(self) -> bool:
        """Return whether the current access token is active."""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        query = {
            "client_id": self._region_config.authorize_client_id,
            "token_type_hint": "access_token",
            "token": self._access_token,
        }
        async with self._session.post(
            self._region_config.introspect_url,
            headers=headers,
            data=query,
            cookies=self.cookies,
        ) as introspect_res:
            introspect_dict = await introspect_res.json()
            await self._resmed_response_error_check(
                "introspect_query", introspect_res, introspect_dict
            )
        return introspect_dict.get("active") is True

    async def _authn_check(self) -> str:
        """Run the Okta authn username/password step."""
        query = {"username": self._config.username, "password": self._config.password}
        _LOGGER.debug("[authn_check] json_query: %s", redact_dict(query))
        async with self._session.post(
            self._region_config.authn_url,
            headers=self._json_headers,
            json=query,
            cookies=self.cookies,
        ) as authn_res:
            authn_dict = await authn_res.json()
            await self._resmed_response_error_check("authn", authn_res, authn_dict)
        if "status" not in authn_dict:
            raise AuthenticationError("Cannot get status in authn step")
        status = authn_dict["status"]
        if status == AUTH_NEEDS_MFA:
            if "stateToken" not in authn_dict:
                raise AuthenticationError("Cannot get stateToken in authn step")
            self._state_token = authn_dict["stateToken"]
            factor = authn_dict.get("_embedded", {}).get("factors", [{}])[0]
            self._email_factor_id = factor.get("id", self._region_config.email_factor_id)
            self._mfa_url = factor.get("_links", {}).get("verify", {}).get(
                "href", self._region_config.mfa_url(self._email_factor_id)
            )
            if "rememberDevice=true" not in self._mfa_url:
                self._mfa_url = f"{self._mfa_url}?rememberDevice=true"
        elif status == AUTHN_SUCCESS:
            if "sessionToken" not in authn_dict:
                raise AuthenticationError("Cannot get sessionToken in authn step")
            self._session_token = authn_dict["sessionToken"]
        else:
            raise AuthenticationError(f"Unknown status in authn step: {status}")
        return status

    async def _trigger_mfa(self) -> None:
        """Trigger MFA email delivery."""
        query = {"passCode": "", "stateToken": self._state_token}
        async with self._session.post(
            self._mfa_url,
            headers=self._json_headers,
            json=query,
            cookies=self.cookies,
        ) as trigger_mfa_res:
            trigger_mfa_dict = await trigger_mfa_res.json()
            await self._resmed_response_error_check(
                "trigger_mfa", trigger_mfa_res, trigger_mfa_dict
            )

    async def _verify_mfa(self, verification_code: str) -> str:
        """Verify an MFA code."""
        query = {"passCode": verification_code, "stateToken": self._state_token}
        async with self._session.post(
            self._mfa_url,
            headers=self._json_headers,
            json=query,
            cookies=self.cookies,
        ) as verify_mfa_res:
            verify_mfa_dict = await verify_mfa_res.json()
            await self._resmed_response_error_check(
                "verify_mfa", verify_mfa_res, verify_mfa_dict
            )
        if "status" not in verify_mfa_dict:
            raise AuthenticationError("Cannot get status in verify_mfa step")
        status = verify_mfa_dict["status"]
        if status != AUTHN_SUCCESS:
            raise AuthenticationError(f"Unknown status in verify_mfa step: {status}")
        if "sessionToken" not in verify_mfa_dict:
            raise AuthenticationError("Cannot get sessionToken in verify_mfa step")
        self._session_token = verify_mfa_dict["sessionToken"]
        return status

    async def _get_access_token(self) -> None:
        """Exchange the Okta session token for OAuth tokens."""
        code_verifier = re.sub(
            "[^a-zA-Z0-9]+",
            "",
            base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8"),
        )
        challenge_digest = __import__("hashlib").sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = base64.urlsafe_b64encode(challenge_digest).decode("utf-8").replace("=", "")
        params = {
            "client_id": self._region_config.authorize_client_id,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "prompt": "none",
            "redirect_uri": self._region_config.oauth_redirect_url,
            "response_mode": "fragment",
            "response_type": "code",
            "sessionToken": self._session_token,
            "scope": "openid profile email",
            "state": "abcdef",
        }
        async with self._session.get(
            self._region_config.authorize_url,
            headers=self._json_headers,
            allow_redirects=False,
            params=params,
            cookies=self.cookies,
        ) as code_res:
            location = code_res.headers.get("location")
            cookie_headers = code_res.headers.getall("set-cookie", [])
        if location is None:
            raise ParsingError("Unable to get location from code_res")
        fragment: DefragResult = urldefrag(location)
        code = parse_qs(fragment.fragment)["code"]
        await self._extract_and_update_cookies(cookie_headers)
        token_query = {
            "client_id": self._region_config.authorize_client_id,
            "redirect_uri": self._region_config.oauth_redirect_url,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
            "code": code,
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        async with self._session.post(
            self._region_config.token_url,
            headers=headers,
            data=token_query,
            allow_redirects=False,
            cookies=self.cookies,
        ) as token_res:
            token_dict = await token_res.json()
            await self._resmed_response_error_check("get_access_token", token_res, token_dict)
        if "access_token" not in token_dict or "id_token" not in token_dict:
            raise ParsingError("access_token or id_token not in token response")
        self._id_token = token_dict["id_token"]
        self._access_token = token_dict["access_token"]

    @staticmethod
    async def _resmed_response_error_check(
        step: str,
        response: ClientResponse,
        resp_dict: dict[str, Any],
        initial: bool = False,
    ) -> None:
        """Raise integration exceptions for ResMed error payloads."""
        if "errors" not in resp_dict:
            return
        try:
            error = resp_dict["errors"][0]
            if "errorInfo" in error:
                error_info = error["errorInfo"]
                error_message = f"{error_info['errorType']}: {error_info['errorCode']}"
                if error_info["errorType"] == "unauthorized":
                    if step == "gql_query" and not initial:
                        raise ParsingError(f"Getting unauthorized error on {step} step. {error_message}")
                    raise AuthenticationError(f"Getting unauthorized error on {step} step. {error_message}")
                if error_info["errorType"] == "badRequest" and error_info["errorCode"] in {
                    "onboardingFlowInProgress",
                    "equipmentNotAssigned",
                }:
                    raise IncompleteAccountError(error_message)
            elif "message" in error:
                error_message = error["message"]
            else:
                error_message = str(error)
        except (TypeError, KeyError) as err:
            error_message = f"Unable to parse error message. {type(err).__name__}: {err}"
        raise HttpProcessingError(
            code=response.status,
            message=f"{step} step: {error_message}. {resp_dict}",
            headers=CIMultiDict(response.headers),
        )
```

- [ ] **Step 4: Update `RESTClient` to delegate auth**

In `custom_components/resmed_myair/client/rest_client.py`, make `RESTClient.__init__` create `self._auth = MyAirAuthSession(config, session)`.

Replace these public methods with delegating methods:

```python
@property
def device_token(self) -> str | None:
    """Return the device token."""
    return self._auth.device_token


async def connect(self, initial: bool | None = False) -> str:
    """Check authn and connect to ResMed servers."""
    return await self._auth.connect(initial=bool(initial))


async def verify_mfa_and_get_access_token(self, verification_code: str) -> str:
    """Confirm valid MFA and obtain access token."""
    return await self._auth.verify_mfa_and_get_access_token(verification_code)


async def is_email_verified(self) -> bool:
    """Check if email address is verified."""
    return await self._auth.is_email_verified()
```

Keep `_gql_query`, `get_sleep_records`, and `get_user_device_data` in `RESTClient` for this task. Change `_gql_query` to use:

```python
authz_header: str = f"Bearer {self._auth.access_token}"
id_token = self._auth.id_token
```

- [ ] **Step 5: Run REST client tests**

Run:

```bash
./.venv/bin/pytest tests/test_rest_client.py -q
```

Expected: PASS.

- [ ] **Step 6: Run type and lint checks for touched modules**

Run:

```bash
./.venv/bin/prek run ruff --files custom_components/resmed_myair/client/auth.py custom_components/resmed_myair/client/rest_client.py
./.venv/bin/prek run mypy --files custom_components/resmed_myair/client/auth.py custom_components/resmed_myair/client/rest_client.py
```

Expected: PASS.

- [ ] **Step 7: Commit**

Run:

```bash
git add custom_components/resmed_myair/client/auth.py custom_components/resmed_myair/client/rest_client.py tests/test_rest_client.py
git commit -m "refactor: split myAir auth session"
```

## Task 6: Split GraphQL Transport from REST Client

**Files:**
- Create: `custom_components/resmed_myair/client/graphql.py`
- Modify: `custom_components/resmed_myair/client/rest_client.py`
- Test: `tests/test_rest_client.py`

- [ ] **Step 1: Add tests for GraphQL composition**

Append to `tests/test_rest_client.py`:

```python
from custom_components.resmed_myair.client.graphql import MyAirGraphQLClient


def test_rest_client_owns_graphql_client(myair_config, aiohttp_client_session) -> None:
    """RESTClient composes a dedicated GraphQL client."""
    client = RESTClient(myair_config, aiohttp_client_session)

    assert isinstance(client._graphql, MyAirGraphQLClient)
```

- [ ] **Step 2: Run the targeted test and confirm the module is missing**

Run:

```bash
./.venv/bin/pytest tests/test_rest_client.py::test_rest_client_owns_graphql_client -q
```

Expected: FAIL with `ModuleNotFoundError: No module named 'custom_components.resmed_myair.client.graphql'`.

- [ ] **Step 3: Implement GraphQL client**

Create `custom_components/resmed_myair/client/graphql.py`:

```python
"""GraphQL transport for ResMed myAir."""

import logging
from typing import Any

from aiohttp import ClientSession
import jwt

from ..redaction import redact_dict
from .auth import MyAirAuthSession
from .myair_client import ParsingError
from .regions import RegionConfig

_LOGGER: logging.Logger = logging.getLogger(__name__)


class MyAirGraphQLClient:
    """Execute ResMed AppSync GraphQL operations."""

    def __init__(
        self,
        session: ClientSession,
        auth: MyAirAuthSession,
        region_config: RegionConfig,
    ) -> None:
        """Initialize the GraphQL client.

        Args:
            session: Shared aiohttp client session.
            auth: Auth session that owns tokens.
            region_config: Region endpoint configuration.
        """
        self._session = session
        self._auth = auth
        self._region_config = region_config
        self._country_code: str | None = None

    async def query(
        self,
        operation_name: str,
        query: str,
        initial: bool = False,
    ) -> dict[str, Any]:
        """Run a GraphQL query.

        Args:
            operation_name: GraphQL operation name.
            query: GraphQL query text.
            initial: Whether this query is part of initial config flow.

        Returns:
            Decoded JSON response.
        """
        headers = await self._headers()
        json_query = {
            "operationName": operation_name,
            "variables": {},
            "query": query,
        }
        _LOGGER.debug("[gql_query] json_query: %s", redact_dict(json_query))
        async with self._session.post(
            self._region_config.graphql_url,
            headers=headers,
            json=json_query,
        ) as records_res:
            records_dict = await records_res.json()
            await MyAirAuthSession._resmed_response_error_check(
                "gql_query", records_res, records_dict, initial
            )
        return dict(records_dict)

    async def _headers(self) -> dict[str, str]:
        """Return headers required by ResMed AppSync."""
        country_code = self._country_code or self._country_code_from_id_token()
        if not country_code:
            raise ParsingError("country_code not defined and id_token not present to identify it")
        self._country_code = country_code
        return {
            "x-api-key": self._region_config.myair_api_key,
            "Authorization": f"Bearer {self._auth.access_token}",
            "rmdhandsetid": "02c1c662-c289-41fd-a9ae-196ff15b5166",
            "rmdlanguage": "en",
            "rmdhandsetmodel": "Chrome",
            "rmdhandsetosversion": "127.0.6533.119",
            "rmdproduct": self._region_config.product,
            "rmdappversion": "1.0.0",
            "rmdhandsetplatform": "Web",
            "rmdcountry": country_code,
            "accept-language": "en-US,en;q=0.9",
        }

    def _country_code_from_id_token(self) -> str | None:
        """Derive the myAir country code from the ID token."""
        if not self._auth.id_token:
            return None
        try:
            jwt_data = jwt.decode(self._auth.id_token, options={"verify_signature": False})
        except jwt.PyJWTError as err:
            raise ParsingError("Unable to decode id_token into jwt_data") from err
        country_code = jwt_data.get("myAirCountryId")
        if not isinstance(country_code, str):
            raise ParsingError("myAirCountryId not found in jwt_data")
        return country_code
```

- [ ] **Step 4: Update `RESTClient` to delegate GraphQL**

In `RESTClient.__init__`, create:

```python
self._graphql = MyAirGraphQLClient(
    session=self._session,
    auth=self._auth,
    region_config=self._region_config,
)
```

Replace `_gql_query` with:

```python
async def _gql_query(
    self, operation_name: str, query: str, initial: bool | None = False
) -> dict[str, Any]:
    """Run a GraphQL query through the transport client."""
    return await self._graphql.query(operation_name, query, initial=bool(initial))
```

- [ ] **Step 5: Run REST client tests**

Run:

```bash
./.venv/bin/pytest tests/test_rest_client.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit**

Run:

```bash
git add custom_components/resmed_myair/client/graphql.py custom_components/resmed_myair/client/rest_client.py tests/test_rest_client.py
git commit -m "refactor: split myAir GraphQL transport"
```

## Task 7: Return Typed Models from the Client and Coordinator

**Files:**
- Modify: `custom_components/resmed_myair/client/myair_client.py`
- Modify: `custom_components/resmed_myair/client/rest_client.py`
- Modify: `custom_components/resmed_myair/coordinator.py`
- Test: `tests/test_rest_client.py`
- Test: `tests/test_coordinator.py`

- [ ] **Step 1: Update client/coordinator tests for typed data**

In `tests/test_coordinator.py`, change the success assertion to:

```python
from custom_components.resmed_myair.models import MyAirCoordinatorData, MyAirDevice, MyAirSleepRecord


@pytest.mark.asyncio
async def test_async_update_data_success(hass: MagicMock, myair_client: MagicMock) -> None:
    """Coordinator returns typed device and sleep record data on success."""
    myair_client.get_user_device_data.return_value = MyAirDevice.from_api({"serialNumber": "1234"})
    myair_client.get_sleep_records.return_value = [MyAirSleepRecord.from_api({"totalUsage": 60})]
    coordinator = MyAirDataUpdateCoordinator(hass, MagicMock(), myair_client)

    data = await coordinator._async_update_data()

    assert isinstance(data, MyAirCoordinatorData)
    assert data.device is not None
    assert data.device.serial_number == "1234"
    assert data.latest_sleep_record is not None
    assert data.latest_sleep_record.total_usage_minutes == 60
    myair_client.connect.assert_awaited_once()
    myair_client.get_user_device_data.assert_awaited_once()
    myair_client.get_sleep_records.assert_awaited_once()
```

In parsing-error coordinator tests, assert:

```python
assert data.device is None
assert data.sleep_records == ()
```

- [ ] **Step 2: Run coordinator tests and confirm typed expectations fail**

Run:

```bash
./.venv/bin/pytest tests/test_coordinator.py -q
```

Expected: FAIL because `_async_update_data` still returns a dictionary.

- [ ] **Step 3: Update `MyAirClient` abstract return types**

Change `custom_components/resmed_myair/client/myair_client.py` imports and abstract methods:

```python
from ..models import MyAirDevice, MyAirSleepRecord


class MyAirClient(ABC):
    """Basic myAir Client Class."""

    @abstractmethod
    async def connect(self) -> str:
        """Connect to ResMed myAir."""

    @abstractmethod
    async def get_user_device_data(self, initial: bool | None = False) -> MyAirDevice:
        """Get user device data from ResMed servers."""

    @abstractmethod
    async def get_sleep_records(self, initial: bool | None = False) -> list[MyAirSleepRecord]:
        """Get sleep records from ResMed servers."""
```

- [ ] **Step 4: Update `RESTClient` to return models**

In `custom_components/resmed_myair/client/rest_client.py`, import:

```python
from ..models import MyAirDevice, MyAirSleepRecord
```

Change `get_sleep_records` to return models:

```python
return [MyAirSleepRecord.from_api(record) for record in records]
```

Change `get_user_device_data` to return a model:

```python
return MyAirDevice.from_api(device)
```

Keep all existing parsing checks before model construction.

- [ ] **Step 5: Update coordinator to store typed data**

Replace `_async_update_data` in `custom_components/resmed_myair/coordinator.py` with:

```python
async def _async_update_data(self) -> MyAirCoordinatorData:
    """Fetch data from the myAir client and store it in the coordinator."""
    _LOGGER.info("Updating from myAir")

    try:
        await self.myair_client.connect()
    except AuthenticationError as err:
        _LOGGER.error("Authentication Error while updating. %s: %s", type(err).__name__, err)
        raise ConfigEntryAuthFailed(
            f"Authentication Error while updating. {type(err).__name__}: {err}"
        ) from err

    device: MyAirDevice | None = None
    sleep_records: tuple[MyAirSleepRecord, ...] = ()

    try:
        device = await self.myair_client.get_user_device_data()
    except ParsingError:
        _LOGGER.debug("Device data unavailable in myAir update")

    try:
        sleep_records = tuple(await self.myair_client.get_sleep_records())
    except ParsingError:
        _LOGGER.debug("Sleep record data unavailable in myAir update")

    return MyAirCoordinatorData(device=device, sleep_records=sleep_records)
```

Add imports:

```python
from .models import MyAirCoordinatorData, MyAirDevice, MyAirSleepRecord
```

- [ ] **Step 6: Run client and coordinator tests**

Run:

```bash
./.venv/bin/pytest tests/test_rest_client.py tests/test_coordinator.py -q
```

Expected: PASS after updating `tests/test_rest_client.py` assertions that expected raw dictionaries to inspect `.raw`, `.serial_number`, or `.total_usage_minutes`.

- [ ] **Step 7: Commit**

Run:

```bash
git add custom_components/resmed_myair/client/myair_client.py custom_components/resmed_myair/client/rest_client.py custom_components/resmed_myair/coordinator.py tests/test_rest_client.py tests/test_coordinator.py
git commit -m "refactor: return typed myAir coordinator data"
```

## Task 8: Refactor Sensors to Typed Coordinator Data

**Files:**
- Modify: `custom_components/resmed_myair/sensor.py`
- Test: `tests/test_sensor.py`
- Test: `tests/test_integration.py`

- [ ] **Step 1: Update sensor tests to use typed coordinator data**

In `tests/test_sensor.py`, add helper builders:

```python
from custom_components.resmed_myair.models import MyAirCoordinatorData, MyAirDevice, MyAirSleepRecord


def coordinator_data(
    device: dict[str, object] | None = None,
    sleep_records: list[dict[str, object]] | None = None,
) -> MyAirCoordinatorData:
    """Build typed coordinator data for sensor tests."""
    return MyAirCoordinatorData(
        device=MyAirDevice.from_api(device) if device is not None else None,
        sleep_records=tuple(MyAirSleepRecord.from_api(record) for record in (sleep_records or [])),
    )
```

Update test setup calls from raw dictionaries to `coordinator_data(...)`, for example:

```python
coordinator = coordinator_factory(data=coordinator_data(device={"foo": "bar"}))
```

and:

```python
coordinator = coordinator_factory(
    data=coordinator_data(sleep_records=[{"totalUsage": 10, "startDate": "2024-07-16"}])
)
```

- [ ] **Step 2: Run sensor tests and confirm typed data is unsupported**

Run:

```bash
./.venv/bin/pytest tests/test_sensor.py -q
```

Expected: FAIL because sensors still call dictionary methods on coordinator data.

- [ ] **Step 3: Update base sensor device info**

In `MyAirBaseSensor.__init__`, replace dictionary reads with typed reads:

```python
data = self.coordinator.data
device = data.device if data else None
serial_number = device.serial_number if device else ""
```

Update device info:

```python
self._attr_device_info: DeviceInfo = DeviceInfo(
    identifiers={(DOMAIN, serial_number)},
    manufacturer=device.manufacturer if device else None,
    model=device.model if device else None,
    name=device.name if device else None,
    suggested_area="Bedroom",
    sw_version=VERSION,
)
```

- [ ] **Step 4: Add shared sensor value helpers**

Add these functions near the top of `sensor.py`:

```python
def _coordinator_data(coordinator: MyAirDataUpdateCoordinator) -> MyAirCoordinatorData:
    """Return typed coordinator data or an empty payload."""
    return coordinator.data or MyAirCoordinatorData()


def _parse_native_value(value: Any | None, description: SensorEntityDescription) -> Any | None:
    """Parse native values for Home Assistant sensor device classes."""
    if isinstance(value, str) and description.device_class == SensorDeviceClass.DATE:
        return dt_util.parse_date(value)
    if isinstance(value, str) and description.device_class == SensorDeviceClass.TIMESTAMP:
        return dt_util.parse_datetime(value)
    return value
```

Import `MyAirCoordinatorData` from `.models`.

- [ ] **Step 5: Update record and device sensor handlers**

Replace `MyAirSleepRecordSensor._handle_coordinator_update` with:

```python
@callback
def _handle_coordinator_update(self) -> None:
    """Handle updated data from the coordinator."""
    record = _coordinator_data(self.coordinator).latest_sleep_record
    value = record.native_value(self.sensor_key) if record else None
    self._available = value is not None
    self._attr_native_value = _parse_native_value(value, self.entity_description)
    self.async_write_ha_state()
```

Replace `MyAirDeviceSensor._handle_coordinator_update` with:

```python
@callback
def _handle_coordinator_update(self) -> None:
    """Handle updated data from the coordinator."""
    device = _coordinator_data(self.coordinator).device
    value = device.native_value(self.sensor_key) if device else None
    self._available = value is not None
    self._attr_native_value = _parse_native_value(value, self.entity_description)
    self.async_write_ha_state()
```

- [ ] **Step 6: Update synthesized sensor handlers**

Replace `MyAirFriendlyUsageTime._handle_coordinator_update` with:

```python
@callback
def _handle_coordinator_update(self) -> None:
    """Handle updated data from the coordinator."""
    record = _coordinator_data(self.coordinator).latest_sleep_record
    value = record.friendly_usage_time if record else None
    self._available = value is not None
    self._attr_native_value = value
    self.async_write_ha_state()
```

Replace `MyAirMostRecentSleepDate._handle_coordinator_update` with:

```python
@callback
def _handle_coordinator_update(self) -> None:
    """Handle updated data from the coordinator."""
    value = _coordinator_data(self.coordinator).most_recent_sleep_date
    self._available = value is not None
    self._attr_native_value = value
    self.async_write_ha_state()
```

- [ ] **Step 7: Run sensor and integration tests**

Run:

```bash
./.venv/bin/pytest tests/test_sensor.py tests/test_integration.py -q
```

Expected: PASS with preserved entity values, availability, unique IDs, and service registration.

- [ ] **Step 8: Commit**

Run:

```bash
git add custom_components/resmed_myair/sensor.py tests/test_sensor.py tests/test_integration.py
git commit -m "refactor: simplify sensors with typed coordinator data"
```

## Task 9: Share Config Flow Login and MFA Logic

**Files:**
- Modify: `custom_components/resmed_myair/config_flow.py`
- Test: `tests/test_config_flow.py`

- [ ] **Step 1: Add/adjust config-flow tests for shared behavior**

Add these assertions to existing successful user and reauth tests in `tests/test_config_flow.py`:

```python
assert result["type"] in {"create_entry", "abort"}
assert CONF_VERIFICATION_CODE not in result.get("data", {})
```

For create-entry success tests, update device field reads from dictionaries to model properties if mocks now return `MyAirDevice`.

- [ ] **Step 2: Run config-flow tests before refactor**

Run:

```bash
./.venv/bin/pytest tests/test_config_flow.py -q
```

Expected: PASS before structural changes.

- [ ] **Step 3: Add shared helper methods inside `MyAirConfigFlow`**

Add these private methods to `MyAirConfigFlow`:

```python
async def _async_login_and_get_device(
    self,
    device_token: str | None = None,
) -> tuple[str, MyAirDevice | None]:
    """Login with stored flow data and fetch the user device."""
    status, device, self._client = await get_device(
        self.hass,
        self._data[CONF_USER_NAME],
        self._data[CONF_PASSWORD],
        self._data[CONF_REGION],
        device_token,
    )
    return status, device


async def _async_verify_mfa_and_get_device(self) -> tuple[str, MyAirDevice]:
    """Verify MFA with stored flow data and fetch the user device."""
    if not isinstance(self._client, RESTClient):
        raise AuthenticationError("MFA client is not initialized")
    return await get_mfa_device(
        self._client,
        self._data.get(CONF_VERIFICATION_CODE, ""),
    )


def _store_device_token(self) -> None:
    """Store the current client device token in flow data."""
    if self._client:
        self._data.update({CONF_DEVICE_TOKEN: self._client.device_token})


def _entry_title(self, device: MyAirDevice) -> str:
    """Return the config entry title for a device."""
    manufacturer = device.manufacturer or "ResMed"
    name = device.name or "myAir"
    return f"{manufacturer}-{name}"
```

Import `MyAirDevice` from `.models`.

- [ ] **Step 4: Use helpers in user setup**

In `async_step_user`, replace direct `get_device(...)` handling with:

```python
status, device = await self._async_login_and_get_device()
if device and status == AUTHN_SUCCESS:
    if not device.serial_number:
        raise ParsingError("Unable to get Serial Number from Device Data")
    await self.async_set_unique_id(device.serial_number)
    self._abort_if_unique_id_configured()
    self._store_device_token()
    return self.async_create_entry(title=self._entry_title(device), data=self._data)
return await self.async_step_verify_mfa()
```

- [ ] **Step 5: Use helpers in MFA setup**

In `async_step_verify_mfa`, replace direct `get_mfa_device(...)` handling with:

```python
status, device = await self._async_verify_mfa_and_get_device()
if status == AUTHN_SUCCESS:
    self._data.pop(CONF_VERIFICATION_CODE, None)
    self._store_device_token()
    return self.async_create_entry(title=self._entry_title(device), data=self._data)
```

- [ ] **Step 6: Use helpers in reauth**

In `async_step_reauth_confirm`, replace direct `get_device(...)` handling with:

```python
status, device = await self._async_login_and_get_device(
    self._data.get(CONF_DEVICE_TOKEN, None)
)
if device and status == AUTHN_SUCCESS:
    if not device.serial_number:
        raise ParsingError("Unable to get Serial Number from Device Data")
    self._store_device_token()
    self.hass.config_entries.async_update_entry(self._entry, data={**self._data})
    await self.hass.config_entries.async_reload(self._entry.entry_id)
    return self.async_abort(reason="reauth_successful")
return await self.async_step_reauth_verify_mfa()
```

In `async_step_reauth_verify_mfa`, replace direct `get_mfa_device(...)` handling with:

```python
status, _device = await self._async_verify_mfa_and_get_device()
if status == AUTHN_SUCCESS:
    self._data.pop(CONF_VERIFICATION_CODE, None)
    self._store_device_token()
    self.hass.config_entries.async_update_entry(self._entry, data={**self._data})
    await self.hass.config_entries.async_reload(self._entry.entry_id)
    return self.async_abort(reason="reauth_successful")
```

- [ ] **Step 7: Run config-flow tests**

Run:

```bash
./.venv/bin/pytest tests/test_config_flow.py -q
```

Expected: PASS.

- [ ] **Step 8: Commit**

Run:

```bash
git add custom_components/resmed_myair/config_flow.py tests/test_config_flow.py
git commit -m "refactor: share myAir config flow auth paths"
```

## Task 10: Full Verification and Cleanup

**Files:**
- Modify only files with lint/type/test failures from this branch.

- [ ] **Step 1: Run full tests**

Run:

```bash
./.venv/bin/pytest
```

Expected: PASS.

- [ ] **Step 2: Run full prek**

Run:

```bash
./.venv/bin/prek run --all-files
```

Expected: PASS.

- [ ] **Step 3: Inspect the branch diff**

Run:

```bash
git diff --stat Change-from-pre-commit-to-prek...HEAD
git diff --check
```

Expected: `git diff --check` exits 0. The stat should show focused changes in client/auth/graphql/models/sensor/config-flow/tests/docs.

- [ ] **Step 4: Verify Home Assistant compatibility claims**

Run:

```bash
./.venv/bin/pytest tests/test_sensor.py tests/test_config_flow.py tests/test_integration.py -q
```

Expected: PASS. These tests are the compatibility gate for entity values, unique IDs, config entry creation, reauth, and service registration.

- [ ] **Step 5: Commit any verification fixes**

If Step 1, 2, 3, or 4 required fixes, run:

```bash
git add custom_components/resmed_myair tests docs/superpowers
git commit -m "test: verify myAir architecture cleanup"
```

If no fixes were required, do not create an empty commit.

## Self-Review Notes

- Spec coverage: branch creation, OAuth-helper spike, client split, typed coordinator data, sensor compatibility, config flow cleanup, redaction consolidation, logging/noise reduction, and full verification are covered.
- Compatibility boundary: existing config entries, entity unique IDs, entity names, service name shape, sensor values, and reauth flow are preserved by targeted tests.
- Placeholder scan: the plan uses concrete file paths, code snippets, commands, and expected outcomes.
- Type consistency: `MyAirDevice`, `MyAirSleepRecord`, and `MyAirCoordinatorData` are introduced before client, coordinator, sensor, and config-flow tasks depend on them.
