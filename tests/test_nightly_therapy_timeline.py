"""Test the timeline action and Time in Apnea sensor through Home Assistant."""

from collections.abc import Iterator
from unittest.mock import AsyncMock, patch

from homeassistant.const import ATTR_CONFIG_ENTRY_ID, STATE_UNKNOWN
from homeassistant.core import HomeAssistant, ServiceResponse
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import entity_registry as er
import pytest
from pytest_homeassistant.common import MockConfigEntry

from custom_components.resmed_myair.client.graphql import MyAirGraphQLClient
from custom_components.resmed_myair.client.myair_client import ServiceUnavailableError
from custom_components.resmed_myair.client.rest_client import RESTClient
from custom_components.resmed_myair.const import (
    CONF_PASSWORD,
    CONF_REGION,
    CONF_USER_NAME,
    DOMAIN,
    REGION_NA,
    TIME_IN_APNEA_KEY,
)
from custom_components.resmed_myair.models import MyAirDevice, MyAirSleepRecord

_ACTION = "get_nightly_therapy_timeline"
_SERIAL = "SN123"
_DATE = "2026-01-08"


@pytest.fixture(autouse=True)
def configure_hass(enable_custom_integrations: None) -> None:
    """Use the real Home Assistant config-entry manager.

    Args:
        enable_custom_integrations (None): Allow loading the custom component.
    """


@pytest.fixture
def config_entry() -> MockConfigEntry:
    """Create an entry that can be loaded through the real config entry manager.

    Returns:
        MockConfigEntry: The configured myAir entry.
    """
    return MockConfigEntry(
        domain=DOMAIN,
        data={CONF_USER_NAME: "test@example.com", CONF_PASSWORD: "dummy", CONF_REGION: REGION_NA},
        unique_id=_SERIAL,
        version=2,
    )


@pytest.fixture
def sleep_records() -> list[MyAirSleepRecord]:
    """Return mutable records to simulate changes in the Current Data Date.

    Returns:
        list[MyAirSleepRecord]: The daily records made available to the integration.
    """
    return [MyAirSleepRecord.from_api({"startDate": _DATE, "ahi": 0.6, "totalUsage": 420})]


@pytest.fixture
def timeline_query(sleep_records: list[MyAirSleepRecord]) -> Iterator[AsyncMock]:
    """Provide a simulated myAir API behind real entry setup and action handling.

    Args:
        sleep_records (list[MyAirSleepRecord]): Records returned by future refreshes.

    Yields:
        AsyncMock: The mock for the timeline GraphQL operation.
    """
    with (
        patch.object(RESTClient, "connect", return_value="SUCCESS"),
        patch.object(
            RESTClient,
            "get_user_device_data",
            return_value=MyAirDevice.from_api({"serialNumber": _SERIAL}),
        ),
        patch.object(RESTClient, "get_sleep_records", return_value=sleep_records),
        patch.object(MyAirGraphQLClient, "query") as query,
    ):
        yield query


def _payload(records: list[dict[str, object]] | None) -> dict[str, object]:
    """Wrap dated records in the GraphQL response shape.

    Args:
        records (list[dict[str, object]] | None): Records returned for the requested date.

    Returns:
        dict[str, object]: A GraphQL response containing those records.
    """
    return {"data": {"getPatientWrapper": {"dailyTherapyData": records}}}


async def _load(hass: HomeAssistant, config_entry: MockConfigEntry) -> str:
    """Set up the integration and find its Time in Apnea registry entry.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        config_entry (MockConfigEntry): The myAir config entry used by the test.

    Returns:
        str: The Time in Apnea entity ID.
    """
    config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()
    entity_id = er.async_get(hass).async_get_entity_id(
        "sensor", DOMAIN, f"{DOMAIN}_{_SERIAL}_{TIME_IN_APNEA_KEY}"
    )
    assert entity_id is not None
    return entity_id


async def _get_timeline(hass: HomeAssistant, config_entry: MockConfigEntry) -> ServiceResponse:
    """Call the response action for the selected night.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        config_entry (MockConfigEntry): Entry targeted by the action.

    Returns:
        ServiceResponse: The Home Assistant service response.
    """
    return await hass.services.async_call(
        DOMAIN,
        _ACTION,
        {ATTR_CONFIG_ENTRY_ID: config_entry.entry_id, "date": _DATE},
        blocking=True,
        return_response=True,
    )


async def test_action_returns_ordered_events_while_sensor_is_disabled(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    timeline_query: AsyncMock,
    sleep_records: list[MyAirSleepRecord],
) -> None:
    """Fetch a requested night with offsets, durations, and point events.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        config_entry (MockConfigEntry): Entry targeted by the action.
        timeline_query (AsyncMock): myAir timeline query double.
        sleep_records (list[MyAirSleepRecord]): Daily records returned during refresh.
    """
    sleep_records.append(MyAirSleepRecord.from_api({"startDate": "2026-01-09"}))
    timeline_query.return_value = _payload(
        [
            {
                "date": _DATE,
                "ahi": 0.6,
                "totalSecondsInApnea": 12,
                "totalUsageHours": 7,
                "respiratoryEvents": [
                    {"eventType": "hypopnea", "endDate": "2026-01-09T05:30:00Z"},
                    {
                        "eventType": "obstructiveApnea",
                        "startDate": "2026-01-09T01:00:00-05:00",
                        "endDate": "2026-01-09T01:00:12-05:00",
                        "durationSeconds": 12,
                    },
                ],
                "therapyStatusEvents": [
                    {"eventType": "maskOn", "date": "2026-01-08T23:00:00-05:00"},
                    {"eventType": "powerOff", "date": "2026-01-09T08:30:00Z"},
                ],
            }
        ]
    )
    entity_id = await _load(hass, config_entry)
    assert hass.states.get(entity_id) is None
    timeline_query.assert_not_awaited()

    assert await _get_timeline(hass, config_entry) == {
        "date": _DATE,
        "ahi": 0.6,
        "total_seconds_in_apnea": 12,
        "total_usage_hours": 7.0,
        "events": [
            {"type": "maskOn", "timestamp": "2026-01-08T23:00:00-05:00"},
            {"type": "hypopnea", "timestamp": "2026-01-09T05:30:00+00:00"},
            {
                "type": "obstructiveApnea",
                "timestamp": "2026-01-09T01:00:00-05:00",
                "end_timestamp": "2026-01-09T01:00:12-05:00",
                "duration_seconds": 12,
            },
            {"type": "powerOff", "timestamp": "2026-01-09T08:30:00+00:00"},
        ],
    }
    assert timeline_query.await_args.kwargs["variables"] == {"startDate": _DATE, "endDate": _DATE}
    assert hass.states.get(entity_id) is None


async def test_action_distinguishes_empty_missing_and_failed_timelines(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    timeline_query: AsyncMock,
) -> None:
    """Return genuine empty timelines and reject unavailable data.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        config_entry (MockConfigEntry): Entry targeted by the action.
        timeline_query (AsyncMock): myAir timeline query double.
    """
    await _load(hass, config_entry)
    timeline_query.return_value = _payload(
        [
            {
                "date": _DATE,
                "totalSecondsInApnea": 0,
                "respiratoryEvents": [],
                "therapyStatusEvents": [],
            }
        ]
    )
    response = await _get_timeline(hass, config_entry)
    assert response is not None
    assert response["events"] == []
    assert response["total_seconds_in_apnea"] == 0
    for missing in (
        None,
        [],
        [{"date": "2026-01-07"}],
        [{"date": _DATE, "respiratoryEvents": None}],
    ):
        timeline_query.return_value = _payload(missing)
        with pytest.raises(HomeAssistantError) as err:
            await _get_timeline(hass, config_entry)
        assert err.value.translation_key == "timeline_unavailable"

    timeline_query.side_effect = ServiceUnavailableError("Timeline outage")
    with pytest.raises(HomeAssistantError) as err:
        await _get_timeline(hass, config_entry)
    assert err.value.translation_key == "timeline_request_failed"

    assert await hass.config_entries.async_unload(config_entry.entry_id)
    with pytest.raises(ServiceValidationError):
        await _get_timeline(hass, config_entry)


async def test_time_in_apnea_stays_aligned_with_daily_sensors(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    timeline_query: AsyncMock,
    sleep_records: list[MyAirSleepRecord],
) -> None:
    """Recheck late values and keep daily sensors usable after a timeline failure.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        config_entry (MockConfigEntry): Entry owning the sensor.
        timeline_query (AsyncMock): myAir timeline query double.
        sleep_records (list[MyAirSleepRecord]): Daily records returned during refresh.
    """
    entity_id = await _load(hass, config_entry)
    er.async_get(hass).async_update_entity(entity_id, disabled_by=None)
    timeline_query.return_value = _payload([{"date": _DATE, "totalSecondsInApnea": 12}])
    assert await hass.config_entries.async_reload(config_entry.entry_id)
    await hass.async_block_till_done()
    state = hass.states.get(entity_id)
    assert state is not None
    assert float(state.state) == 12
    assert state.attributes["unit_of_measurement"] == "s"

    timeline_query.return_value = _payload([{"date": _DATE, "totalSecondsInApnea": 17}])
    await config_entry.runtime_data.async_refresh()
    assert float(hass.states.get(entity_id).state) == 17
    assert timeline_query.await_args.kwargs["variables"]["startDate"] == _DATE

    sleep_records.append(
        MyAirSleepRecord.from_api({"startDate": "2026-01-09", "ahi": 0, "totalUsage": 0})
    )
    timeline_query.return_value = _payload(None)
    await config_entry.runtime_data.async_refresh()
    assert hass.states.get(entity_id).state == STATE_UNKNOWN
    assert timeline_query.await_args.kwargs["variables"]["startDate"] == "2026-01-09"

    timeline_query.return_value = _payload([{"date": "2026-01-09", "totalSecondsInApnea": 0}])
    await config_entry.runtime_data.async_refresh()
    assert float(hass.states.get(entity_id).state) == 0

    timeline_query.side_effect = ServiceUnavailableError("Timeline outage")
    await config_entry.runtime_data.async_refresh()
    assert hass.states.get(entity_id).state == STATE_UNKNOWN
    registry = er.async_get(hass)
    date_id = registry.async_get_entity_id("sensor", DOMAIN, f"{DOMAIN}_{_SERIAL}_startDate")
    ahi_id = registry.async_get_entity_id("sensor", DOMAIN, f"{DOMAIN}_{_SERIAL}_ahi")
    assert hass.states.get(date_id).state == "2026-01-09"
    assert float(hass.states.get(ahi_id).state) == 0
