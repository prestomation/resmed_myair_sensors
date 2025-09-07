"""Shared pytest fixtures used across the test suite."""

from typing import Any
from unittest.mock import AsyncMock, MagicMock

from aiohttp import ClientResponse, ClientSession
from multidict import CIMultiDict
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.resmed_myair.client.myair_client import MyAirConfig
from custom_components.resmed_myair.client.rest_client import RESTClient
from custom_components.resmed_myair.const import (
    CONF_PASSWORD,
    CONF_REGION,
    CONF_USER_NAME,
    REGION_EU,
    REGION_NA,
)


def _ensure_config_entries_helpers(hass: Any) -> None:
    """Ensure `hass.config_entries` exists and provides mockable helpers.

    This centralizes the logic so tests and fixtures can call it without
    duplicating guarded assignments that may clobber upstream mocks.
    """
    if not hasattr(hass, "config_entries") or hass.config_entries is None:
        hass.config_entries = MagicMock()
        # Provide the async_forward_entry_setups helper as awaitable
        hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)

        # Do not create a bare async_get_entry here; explicitly set it to None
        # so that test fixtures (for example `config_entry`) can create a
        # MagicMock with a controlled return_value.
        hass.config_entries.async_get_entry = None
        hass.config_entries.async_update_entry = MagicMock()
        # async_reload is expected to be awaitable
        hass.config_entries.async_reload = AsyncMock()
        hass.config_entries.async_entry_for_domain_unique_id = MagicMock()
    else:
        # Preserve the existing config_entries object; only add helpers if
        # missing or not already the expected Mock/AsyncMock types so we do
        # not clobber mocks provided by upstream fixtures.
        if not hasattr(hass.config_entries, "async_forward_entry_setups") or not isinstance(
            hass.config_entries.async_forward_entry_setups, AsyncMock
        ):
            hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)

        if not hasattr(hass.config_entries, "async_get_entry") or not isinstance(
            hass.config_entries.async_get_entry, MagicMock | AsyncMock
        ):
            hass.config_entries.async_get_entry = MagicMock()

        if not hasattr(hass.config_entries, "async_update_entry") or not isinstance(
            hass.config_entries.async_update_entry, MagicMock
        ):
            hass.config_entries.async_update_entry = MagicMock()

        # async_reload is expected to be awaitable
        if not hasattr(hass.config_entries, "async_reload") or not isinstance(
            hass.config_entries.async_reload, AsyncMock
        ):
            hass.config_entries.async_reload = AsyncMock()

        if not hasattr(hass.config_entries, "async_entry_for_domain_unique_id") or not isinstance(
            hass.config_entries.async_entry_for_domain_unique_id, MagicMock
        ):
            hass.config_entries.async_entry_for_domain_unique_id = MagicMock()


def make_mock_aiohttp_response(json_value=None, headers=None, status: int = 200):
    """Create a MagicMock that mimics an aiohttp response used in tests.

    The returned object has async .json(), .headers and .status attributes.
    """
    mock_res = MagicMock(spec=ClientResponse)
    mock_res.json = AsyncMock(return_value=json_value)

    # aiohttp response headers expose .get and .getall (CIMultiDict-like).
    # Tests may pass a plain dict which lacks getall and can raise AttributeError
    # when code under test calls headers.getall. Use a real CIMultiDict for
    # accurate behavior (case-insensitive keys, get/getall semantics).
    hdrs: Any
    if headers is None:
        hdrs = CIMultiDict()
    elif isinstance(headers, dict):
        hdrs = CIMultiDict(headers)
    else:
        # If caller supplied an object that already implements get/getall,
        # use it as-is.
        hdrs = headers

    mock_res.headers = hdrs
    mock_res.status = status
    return mock_res


def make_mock_aiohttp_context_manager(json_value=None, headers=None, status: int = 200):
    """Return an async context manager that yields a mock aiohttp response.

    Useful for assigning to session.get/post return values in tests:
        session.post.return_value = make_mock_aiohttp_context_manager({...})
    """
    # If caller passed a prebuilt MagicMock response, return a context manager that yields it.
    if isinstance(json_value, MagicMock):
        mock_res = json_value
    else:
        mock_res = make_mock_aiohttp_response(json_value=json_value, headers=headers, status=status)

    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(return_value=mock_res)
    cm.__aexit__ = AsyncMock(return_value=None)
    return cm


@pytest.fixture
def session() -> MagicMock:
    """Return a MagicMock that can be used as an aiohttp ClientSession in tests."""
    return MagicMock(spec=ClientSession)


@pytest.fixture
def config_entry(hass: Any) -> MockConfigEntry:
    """Return a MockConfigEntry configured with realistic default data and attach it to hass."""
    data = {
        CONF_USER_NAME: "test@example.com",
        CONF_PASSWORD: "dummy_password",
        CONF_REGION: REGION_NA,
    }
    entry = MockConfigEntry(
        domain="resmed_myair", title="ResMed-CPAP", data=data, entry_id="mock_entry_id", version=2
    )
    entry.runtime_data = None

    # Ensure the hass fixture has the config_entries helpers we rely on.
    _ensure_config_entries_helpers(hass)

    # Wire the entry into hass.config_entries.async_get_entry in a guarded
    # fashion so we don't clobber mocks supplied by upstream fixtures.
    existing_get = getattr(hass.config_entries, "async_get_entry", None)
    if isinstance(existing_get, MagicMock | AsyncMock):
        if existing_get.return_value is not entry:
            existing_get.return_value = entry
    else:
        hass.config_entries.async_get_entry = MagicMock(return_value=entry)

    # Ensure async_entry_for_domain_unique_id has a sensible default when
    # missing so tests can patch/override as needed.
    if not hasattr(hass.config_entries, "async_entry_for_domain_unique_id"):
        hass.config_entries.async_entry_for_domain_unique_id = MagicMock(return_value=None)

    return entry


@pytest.fixture(autouse=True)
def configure_hass(hass: Any) -> None:
    """Ensure the phcc-provided `hass` fixture has the attributes tests expect.

    Many tests assume `hass.config_entries.async_forward_entry_setups` is
    awaitable and returns True, and that `hass.services` exists. This
    autouse fixture mutates the real `hass` fixture (provided by pytest-
    homeassistant-custom-component) so those expectations hold without
    replacing the full Home Assistant test harness.
    """
    # Centralize and reuse the guarded setup logic.
    _ensure_config_entries_helpers(hass)

    # Replace services with a MagicMock so tests can patch/assign async_register
    # and other service registration helpers without hitting read-only attrs on
    # the real ServiceRegistry.
    hass.services = MagicMock()


@pytest.fixture
def service_registry_shim(hass: Any, monkeypatch) -> Any:
    """Provide a lightweight ServiceRegistry shim mounted at ``hass.services``.

    The shim implements a minimal subset of Home Assistant's ServiceRegistry
    API used by tests:
      - ``has_service(domain, service) -> bool``
      - ``async_register(domain, service, func, schema=None, ...)``

    Registered handlers are stored in ``shim._services[domain][service].handlers``
    which mirrors the structure tests inspect in the original code.

    The fixture monkeypatches ``hass.services`` with the shim and returns the
    shim object so tests may directly inspect or reuse it.
    """

    class _ServiceEntry:
        def __init__(self) -> None:
            self.handlers: list = []

    class _ServiceRegistryShim:
        def __init__(self) -> None:
            self._services: dict[str, dict[str, _ServiceEntry]] = {}

        def has_service(self, domain: str, service: str) -> bool:
            return domain in self._services and service in self._services[domain]

        def async_register(self, domain: str, service: str, func, schema=None, *a, **kw):
            domain_map = self._services.setdefault(domain, {})
            entry = domain_map.get(service)
            if entry is None:
                entry = _ServiceEntry()
                domain_map[service] = entry
            entry.handlers.append(func)

    shim = _ServiceRegistryShim()
    monkeypatch.setattr(hass, "services", shim, raising=False)
    return shim


@pytest.fixture
def myair_client() -> MagicMock:
    """Return a MagicMock that mimics the myAir client used by coordinators.

    It provides AsyncMock implementations for the common async methods used in tests.
    """
    # Use spec=RESTClient so tests that isinstance-check against RESTClient continue to work
    client = MagicMock(spec=RESTClient)
    client.connect = AsyncMock()
    client.get_user_device_data = AsyncMock(return_value={"serial": "1234"})
    client.get_sleep_records = AsyncMock(return_value=[{"totalUsage": 60}])
    return client


@pytest.fixture
def config_na() -> MyAirConfig:
    """Return a MyAirConfig for the NA region used by REST client tests."""
    return MyAirConfig(username="user", password="pass", region=REGION_NA, device_token="token")


@pytest.fixture
def config_eu() -> MyAirConfig:
    """Return a MyAirConfig for the EU region used by REST client tests."""
    return MyAirConfig(username="user", password="pass", region=REGION_EU, device_token="token")


@pytest.fixture
def coordinator(coordinator_factory) -> Any:
    """Return the default dataful coordinator via the factory (convenience wrapper)."""
    return coordinator_factory()


@pytest.fixture
def coordinator_mock(coordinator_factory):
    """Return an AsyncMock coordinator via the factory (convenience wrapper)."""
    return coordinator_factory(mock=True)


@pytest.fixture
def coordinator_factory():
    """Factory fixture that produces coordinator objects.

    Usage:
      - coordinator_factory() -> dataful DummyCoordinator (default)
      - coordinator_factory(mock=True) -> AsyncMock coordinator
      - coordinator_factory(data=...) -> DummyCoordinator with custom data
    """

    def _make(mock: bool = False, data: dict | None = None):
        if mock:
            m = MagicMock()
            m.async_refresh = AsyncMock()
            m.async_config_entry_first_refresh = AsyncMock()
            # Provide a data attribute so callers can set/read coordinator.data
            m.data = {}
            return m

        # default data used by many tests
        if data is None:
            data = {
                "device": {
                    "serialNumber": "SN123",
                    "deviceType": "AirSense",
                    "lastSleepDataReportTime": "2024-06-01T12:00:00+00:00",
                    "localizedName": "Bedroom CPAP",
                    "fgDeviceManufacturerName": "ResMed",
                },
                "sleep_records": [
                    {
                        "startDate": "2024-05-31",
                        "totalUsage": 123,
                        "sleepScore": 90,
                        "ahi": 2.1,
                        "maskPairCount": 3,
                        "leakPercentile": 5,
                    },
                    {
                        "startDate": "2024-06-01",
                        "totalUsage": 456,
                        "sleepScore": 95,
                        "ahi": 1.8,
                        "maskPairCount": 2,
                        "leakPercentile": 4,
                    },
                ],
            }

        class DummyCoordinator:
            def __init__(self, d: dict):
                self.data = d

            def async_add_listener(self, *args, **kwargs):
                return lambda: None

        return DummyCoordinator(data)

    return _make
