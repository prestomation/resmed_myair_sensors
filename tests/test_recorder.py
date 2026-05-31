"""Recorder platform tests for statistics unit migrations."""

from types import SimpleNamespace
from typing import Any

from homeassistant.const import PERCENTAGE, UnitOfVolumeFlowRate

from custom_components.resmed_myair import recorder


def test_async_custom_equivalent_units_maps_mask_leak_entities(
    monkeypatch: Any,
) -> None:
    """Mask leak statistics migrate from percent to liters per minute."""
    registry = SimpleNamespace(
        entities={
            "sensor.cpap_mask_leak": SimpleNamespace(
                entity_id="sensor.cpap_mask_leak",
                platform="resmed_myair",
                unique_id="resmed_myair_SN123_leakPercentile",
            ),
            "sensor.cpap_usage_minutes": SimpleNamespace(
                entity_id="sensor.cpap_usage_minutes",
                platform="resmed_myair",
                unique_id="resmed_myair_SN123_totalUsage",
            ),
            "sensor.other_mask_leak": SimpleNamespace(
                entity_id="sensor.other_mask_leak",
                platform="other",
                unique_id="other_SN123_leakPercentile",
            ),
        }
    )
    monkeypatch.setattr(recorder.er, "async_get", lambda hass: registry)

    assert recorder.async_custom_equivalent_units(SimpleNamespace()) == {
        "sensor.cpap_mask_leak": {
            PERCENTAGE: UnitOfVolumeFlowRate.LITERS_PER_MINUTE,
        },
    }
