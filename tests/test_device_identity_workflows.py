"""Home Assistant workflow tests for the Configured CPAP Device identity."""

from collections.abc import Iterator
from unittest.mock import AsyncMock, patch

from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import ATTR_CONFIG_ENTRY_ID, STATE_UNAVAILABLE
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import device_registry as dr, entity_registry as er, issue_registry as ir
import pytest

from custom_components.resmed_myair.client.graphql import MyAirGraphQLClient
from custom_components.resmed_myair.client.myair_client import ParsingError
from custom_components.resmed_myair.client.rest_client import RESTClient
from custom_components.resmed_myair.const import (
    CONF_PASSWORD,
    CONF_REGION,
    CONF_USER_NAME,
    DOMAIN,
    NIGHTLY_TIMELINE_KEY,
    REGION_NA,
)
from custom_components.resmed_myair.models import MyAirDevice, MyAirSleepRecord
from tests.common import MockConfigEntry

_ORIGINAL = "SN123"
_REPLACEMENT = "SN456"
_DATE = "2026-01-08"
_DATA = {CONF_USER_NAME: "test@example.com", CONF_PASSWORD: "dummy", CONF_REGION: REGION_NA}
_RECORDS = [MyAirSleepRecord.from_api({"startDate": _DATE, "ahi": 0.6, "totalUsage": 420})]
_TIMELINE = {
    "data": {"getPatientWrapper": {"dailyTherapyData": [{"date": _DATE, "totalSecondsInApnea": 8}]}}
}


@pytest.fixture(autouse=True)
def configure_hass(enable_custom_integrations: None) -> None:
    """Use the real Home Assistant config-entry manager and registries.

    Args:
        enable_custom_integrations (None): Allow loading the custom component.
    """


class _MyAir:
    """Simulated myAir account whose reported CPAP device can change."""

    def __init__(self) -> None:
        """Start with the original device, Sleep Records, and a timeline."""
        self.device: MyAirDevice | ParsingError = _device(_ORIGINAL)
        self.sleep_records = AsyncMock(return_value=_RECORDS)
        self.timeline = AsyncMock(return_value=_TIMELINE)

    async def get_device(self) -> MyAirDevice:
        """Return the currently reported device, or fail to parse it.

        Returns:
            MyAirDevice: The device payload.

        Raises:
            ParsingError: myAir returned no usable device payload.
        """
        if isinstance(self.device, ParsingError):
            raise ParsingError(str(self.device))
        return self.device


def _device(serial: str) -> MyAirDevice:
    """Build a device payload with distinguishable metadata.

    Args:
        serial (str): Device serial number.

    Returns:
        MyAirDevice: The device payload.
    """
    return MyAirDevice.from_api(
        {
            "serialNumber": serial,
            "localizedName": f"CPAP {serial}",
            "fgDeviceManufacturerName": "ResMed",
            "lastSleepDataReportTime": "2026-01-09T06:00:00+00:00",
        }
    )


@pytest.fixture
def myair() -> Iterator[_MyAir]:
    """Patch the myAir client behind real config-entry setup.

    Yields:
        _MyAir: The simulated account.
    """
    account = _MyAir()
    with (
        patch.object(RESTClient, "connect", return_value="SUCCESS"),
        patch.object(RESTClient, "get_user_device_data", side_effect=account.get_device),
        patch.object(RESTClient, "get_sleep_records", account.sleep_records),
        patch.object(MyAirGraphQLClient, "query", account.timeline),
    ):
        yield account


def _entry(hass: HomeAssistant, unique_id: str | None = _ORIGINAL) -> MockConfigEntry:
    """Add a myAir entry to Home Assistant.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        unique_id (str | None): Configured CPAP Device serial, or ``None`` for a legacy entry.

    Returns:
        MockConfigEntry: The added entry.
    """
    entry = MockConfigEntry(domain=DOMAIN, data=_DATA, unique_id=unique_id, version=2)
    entry.add_to_hass(hass)
    return entry


async def _setup(hass: HomeAssistant, entry: MockConfigEntry) -> None:
    """Set up or reload an entry through Home Assistant.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        entry (MockConfigEntry): Entry to load.
    """
    if entry.state is ConfigEntryState.LOADED:
        assert await hass.config_entries.async_reload(entry.entry_id)
    else:
        assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()


def _sensors(hass: HomeAssistant, entry: MockConfigEntry) -> dict[str, str]:
    """Map each of the entry's registered sensors from unique ID to entity ID.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        entry (MockConfigEntry): Entry that owns the sensors.

    Returns:
        dict[str, str]: Entity IDs keyed by unique ID.
    """
    return {
        item.unique_id: item.entity_id
        for item in er.async_entries_for_config_entry(er.async_get(hass), entry.entry_id)
    }


def _state(hass: HomeAssistant, entry: MockConfigEntry, key: str) -> str:
    """Return the state of the entry's sensor for the original device.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        entry (MockConfigEntry): Entry that owns the sensor.
        key (str): Sensor key.

    Returns:
        str: The sensor's state.
    """
    state = hass.states.get(_sensors(hass, entry)[f"{DOMAIN}_{_ORIGINAL}_{key}"])
    assert state is not None
    return state.state


def _mismatch_issue(hass: HomeAssistant, entry: MockConfigEntry) -> ir.IssueEntry | None:
    """Return the entry's device-mismatch repair issue, if raised.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        entry (MockConfigEntry): Entry configured for the original device.

    Returns:
        ir.IssueEntry | None: The repair issue.
    """
    return ir.async_get(hass).async_get_issue(DOMAIN, f"device_mismatch_{entry.entry_id}")


async def test_replacement_device_withholds_every_sensor_until_the_configured_device_returns(
    hass: HomeAssistant, myair: _MyAir
) -> None:
    """Keep a replacement device's data off every sensor, the registries, and the action.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        myair (_MyAir): Simulated myAir account.
    """
    entry = _entry(hass)
    await _setup(hass, entry)
    registry = er.async_get(hass)
    sensors = _sensors(hass, entry)
    registry.async_update_entity(
        sensors[f"{DOMAIN}_{_ORIGINAL}_{NIGHTLY_TIMELINE_KEY}"], disabled_by=None
    )
    await _setup(hass, entry)
    assert _state(hass, entry, NIGHTLY_TIMELINE_KEY) == _DATE
    assert _state(hass, entry, "ahi") == "0.6"
    myair.sleep_records.reset_mock()
    myair.timeline.reset_mock()

    myair.device = _device(_REPLACEMENT)
    await entry.runtime_data.async_refresh()
    await hass.async_block_till_done()

    states = [hass.states.get(entity_id) for entity_id in sensors.values()]
    # Disabled-by-default sensors have no state; every enabled sensor is unavailable.
    assert {state.state for state in states if state is not None} == {STATE_UNAVAILABLE}
    myair.sleep_records.assert_not_awaited()
    myair.timeline.assert_not_awaited()
    issue = _mismatch_issue(hass, entry)
    assert issue is not None
    assert issue.translation_placeholders == {
        "title": entry.title,
        "configured": _ORIGINAL,
        "reported": _REPLACEMENT,
    }
    with pytest.raises(ServiceValidationError) as err:
        await hass.services.async_call(
            DOMAIN,
            "get_nightly_timeline",
            {ATTR_CONFIG_ENTRY_ID: entry.entry_id, "date": _DATE},
            blocking=True,
            return_response=True,
        )
    assert err.value.translation_key == "timeline_device_unverified"

    # A missing device payload keeps the replacement device's data withheld.
    myair.device = ParsingError("Device unavailable")
    await entry.runtime_data.async_refresh()
    assert _state(hass, entry, "ahi") == STATE_UNAVAILABLE

    # A restart while myAir reports the replacement device registers nothing for it.
    myair.device = _device(_REPLACEMENT)
    await _setup(hass, entry)
    assert _sensors(hass, entry) == sensors
    assert _state(hass, entry, "startDate") == STATE_UNAVAILABLE
    assert [
        device.identifiers
        for device in dr.async_entries_for_config_entry(dr.async_get(hass), entry.entry_id)
    ] == [{(DOMAIN, _ORIGINAL)}]

    # A reload whose first refresh has no device payload keeps the open mismatch in effect.
    myair.device = ParsingError("Device unavailable")
    await _setup(hass, entry)
    assert _state(hass, entry, "ahi") == STATE_UNAVAILABLE
    assert _state(hass, entry, NIGHTLY_TIMELINE_KEY) == STATE_UNAVAILABLE
    myair.sleep_records.assert_not_awaited()
    myair.timeline.assert_not_awaited()
    assert _mismatch_issue(hass, entry) is not None

    myair.device = _device(_ORIGINAL)
    await entry.runtime_data.async_refresh()
    await hass.async_block_till_done()
    assert _state(hass, entry, "ahi") == "0.6"
    assert _state(hass, entry, "lastSleepDataReportTime") == "2026-01-09T06:00:00+00:00"
    assert _state(hass, entry, NIGHTLY_TIMELINE_KEY) == _DATE
    assert _mismatch_issue(hass, entry) is None


async def test_missing_device_payload_keeps_sleep_sensors_on_the_configured_serial(
    hass: HomeAssistant, myair: _MyAir
) -> None:
    """Publish Sleep Record sensors under the configured serial without a device payload.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        myair (_MyAir): Simulated myAir account.
    """
    myair.device = ParsingError("Device unavailable")
    entry = _entry(hass)
    await _setup(hass, entry)

    assert _state(hass, entry, "ahi") == "0.6"
    assert _state(hass, entry, "lastSleepDataReportTime") == STATE_UNAVAILABLE
    assert all(f"_{_ORIGINAL}_" in unique_id for unique_id in _sensors(hass, entry))
    assert _mismatch_issue(hass, entry) is None


async def test_blank_serial_sensor_moves_to_the_configured_serial(
    hass: HomeAssistant, myair: _MyAir
) -> None:
    """Adopt a sensor registered with a blank serial, keeping its entity ID and opt-in.

    A blank-serial sensor is left alone when its serial-based sensor already exists.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        myair (_MyAir): Simulated myAir account.
    """
    entry = _entry(hass)
    registry = er.async_get(hass)
    registered = registry.async_get_or_create(
        "sensor",
        DOMAIN,
        f"{DOMAIN}__ahi",
        config_entry=entry,
        suggested_object_id="my_ahi",
    )
    for serial in ("", _ORIGINAL):
        registry.async_get_or_create(
            "sensor", DOMAIN, f"{DOMAIN}_{serial}_startDate", config_entry=entry
        )
    await _setup(hass, entry)

    sensors = _sensors(hass, entry)
    assert sensors[f"{DOMAIN}_{_ORIGINAL}_ahi"] == registered.entity_id
    assert f"{DOMAIN}__ahi" not in sensors
    assert f"{DOMAIN}__startDate" in sensors
    assert hass.states.get(registered.entity_id).state == "0.6"


async def test_legacy_entry_keeps_its_registered_serial(hass: HomeAssistant, myair: _MyAir) -> None:
    """Pin a legacy entry to the serial its sensors were registered under.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        myair (_MyAir): Simulated myAir account.
    """
    entry = _entry(hass, unique_id=None)
    await _setup(hass, entry)
    sensors = _sensors(hass, entry)
    assert _state(hass, entry, "ahi") == "0.6"

    myair.device = _device(_REPLACEMENT)
    await _setup(hass, entry)

    assert _sensors(hass, entry) == sensors
    assert _state(hass, entry, "ahi") == STATE_UNAVAILABLE
    assert _mismatch_issue(hass, entry) is not None


async def test_legacy_entry_with_both_serials_follows_the_reported_device(
    hass: HomeAssistant, myair: _MyAir
) -> None:
    """Keep the sensors a legacy entry already moved to its replacement device.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        myair (_MyAir): Simulated myAir account.
    """
    entry = _entry(hass, unique_id=None)
    registry = er.async_get(hass)
    for serial in (_ORIGINAL, _REPLACEMENT):
        registry.async_get_or_create("sensor", DOMAIN, f"{DOMAIN}_{serial}_ahi", config_entry=entry)
    myair.device = _device(_REPLACEMENT)
    await _setup(hass, entry)

    state = hass.states.get(_sensors(hass, entry)[f"{DOMAIN}_{_REPLACEMENT}_ahi"])
    assert state is not None and state.state == "0.6"
    assert _mismatch_issue(hass, entry) is None


async def test_legacy_entry_without_a_known_serial_adopts_the_first_reported_device(
    hass: HomeAssistant, myair: _MyAir
) -> None:
    """Withhold data until a legacy entry learns its serial, then keep entity IDs.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        myair (_MyAir): Simulated myAir account.
    """
    myair.device = ParsingError("Device unavailable")
    entry = _entry(hass, unique_id=None)
    await _setup(hass, entry)
    provisional = _sensors(hass, entry)
    ahi_id = provisional[f"{DOMAIN}_entry-{entry.entry_id}_ahi"]
    assert hass.states.get(ahi_id).state == STATE_UNAVAILABLE
    myair.sleep_records.assert_not_awaited()

    myair.device = _device(_ORIGINAL)
    await entry.runtime_data.async_refresh()
    await _setup(hass, entry)

    sensors = _sensors(hass, entry)
    assert sorted(sensors.values()) == sorted(provisional.values())
    assert sensors[f"{DOMAIN}_{_ORIGINAL}_ahi"] == ahi_id
    assert hass.states.get(ahi_id).state == "0.6"


async def test_renamed_adopted_sensor_keeps_its_serial_unique_id(
    hass: HomeAssistant, myair: _MyAir
) -> None:
    """Keep a sensor renamed after adoption on its serial-based unique ID.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        myair (_MyAir): Simulated myAir account.
    """
    myair.device = ParsingError("Device unavailable")
    entry = _entry(hass, unique_id=None)
    await _setup(hass, entry)
    ahi_id = _sensors(hass, entry)[f"{DOMAIN}_entry-{entry.entry_id}_ahi"]

    myair.device = _device(_ORIGINAL)
    await entry.runtime_data.async_refresh()
    await hass.async_block_till_done()
    er.async_get(hass).async_update_entity(ahi_id, new_entity_id="sensor.renamed_ahi")
    await hass.async_block_till_done()

    sensors = _sensors(hass, entry)
    assert not any("entry-" in unique_id for unique_id in sensors)
    assert sensors[f"{DOMAIN}_{_ORIGINAL}_ahi"] == "sensor.renamed_ahi"
    assert hass.states.get("sensor.renamed_ahi").state == "0.6"


async def test_entry_for_replacement_device_adopts_its_existing_sensors(
    hass: HomeAssistant, myair: _MyAir
) -> None:
    """Let a new entry for the replacement device take over its earlier sensors.

    Before the Configured CPAP Device was enforced, a replacement device could
    register sensors under the original entry. Adding the replacement device as
    its own entry keeps those entity IDs.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        myair (_MyAir): Simulated myAir account.
    """
    original = _entry(hass)
    earlier = er.async_get(hass).async_get_or_create(
        "sensor", DOMAIN, f"{DOMAIN}_{_REPLACEMENT}_ahi", config_entry=original
    )
    myair.device = _device(_REPLACEMENT)
    await _setup(hass, original)
    assert _mismatch_issue(hass, original) is not None

    replacement = _entry(hass, unique_id=_REPLACEMENT)
    await _setup(hass, replacement)

    assert _sensors(hass, replacement)[f"{DOMAIN}_{_REPLACEMENT}_ahi"] == earlier.entity_id
    assert hass.states.get(earlier.entity_id).state == "0.6"

    assert await hass.config_entries.async_remove(original.entry_id)
    assert _mismatch_issue(hass, original) is None
