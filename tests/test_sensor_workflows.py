"""Home Assistant workflow tests for nightly myAir Score Components."""

from unittest.mock import AsyncMock

from homeassistant.const import STATE_UNAVAILABLE, STATE_UNKNOWN
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
import pytest

from custom_components.resmed_myair.client.rest_client import RESTClient
from custom_components.resmed_myair.const import (
    CONF_PASSWORD,
    CONF_REGION,
    CONF_USER_NAME,
    DOMAIN,
    REGION_NA,
)
from tests.common import MockConfigEntry


@pytest.fixture
def configure_hass() -> None:
    """Keep the real Home Assistant config entries and services for this workflow."""


@pytest.mark.usefixtures("enable_custom_integrations")
async def test_score_sensors_opt_in_and_follow_current_data_date(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify score registration, opt-in, and refresh through Home Assistant.

    Args:
        hass (HomeAssistant): Home Assistant instance that owns the registry and sensor states.
        monkeypatch (pytest.MonkeyPatch): Patch manager for the myAir responses.
    """
    records = [
        {
            "startDate": "2026-06-01",
            "totalUsage": 396,
            "sleepScore": 90,
            "usageScore": 66,
            "leakScore": 17,
            "ahiScore": 3,
            "maskScore": 4,
            "ahi": 2.1,
            "maskPairCount": 2,
            "leakPercentile": 3,
        }
    ]
    response = {
        "data": {
            "getPatientWrapper": {
                "fgDevices": [
                    {
                        "serialNumber": "SN123",
                        "localizedName": "Bedroom CPAP",
                        "lastSleepDataReportTime": "2026-06-02T12:00:00+00:00",
                    }
                ],
                "masks": [{"maskCode": "M1"}],
                "sleepRecords": {"items": records},
            }
        }
    }
    monkeypatch.setattr(RESTClient, "connect", AsyncMock())
    monkeypatch.setattr(RESTClient, "_gql_query", AsyncMock(return_value=response))
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        unique_id="SN123",
        data={CONF_USER_NAME: "test@example.com", CONF_PASSWORD: "dummy", CONF_REGION: REGION_NA},
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    registry = er.async_get(hass)
    total_id = registry.async_get_entity_id("sensor", DOMAIN, "resmed_myair_SN123_sleepScore")
    assert total_id is not None
    total = registry.async_get(total_id)
    assert total is not None and total.device_id is not None and total.disabled_by is None
    component_ids: list[str] = []
    for key in ("usageScore", "leakScore", "ahiScore", "maskScore"):
        entity_id = registry.async_get_entity_id("sensor", DOMAIN, f"resmed_myair_SN123_{key}")
        assert entity_id is not None
        component = registry.async_get(entity_id)
        assert component is not None and component.device_id == total.device_id
        assert component.disabled_by == er.RegistryEntryDisabler.INTEGRATION
        assert hass.states.get(entity_id) is None
        component_ids.append(entity_id)

    for entity_id in component_ids:
        registry.async_update_entity(entity_id, disabled_by=None)
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()

    for entity_id, expected in zip(component_ids, ("66", "17", "3", "4"), strict=True):
        state = hass.states.get(entity_id)
        assert state is not None and state.state == expected
        assert "unit_of_measurement" not in state.attributes
        assert state.attributes["state_class"] == "measurement"

    records.insert(
        0,
        {
            "startDate": "2026-06-02",
            "totalUsage": 0,
            "sleepScore": 0,
            "usageScore": 0,
            "ahiScore": None,
            "maskScore": True,
            "ahi": 0,
            "maskPairCount": 0,
            "leakPercentile": 0,
        },
    )
    await hass.services.async_call(DOMAIN, "force_poll_test_example_com", blocking=True)
    await hass.async_block_till_done()

    date_id = registry.async_get_entity_id("sensor", DOMAIN, "resmed_myair_SN123_startDate")
    assert date_id is not None
    current_date = hass.states.get(date_id)
    assert current_date is not None and current_date.state == "2026-06-02"
    for entity_id, expected in zip(
        [total_id, *component_ids],
        ("0", "0", STATE_UNAVAILABLE, STATE_UNKNOWN, STATE_UNKNOWN),
        strict=True,
    ):
        state = hass.states.get(entity_id)
        assert state is not None and state.state == expected
