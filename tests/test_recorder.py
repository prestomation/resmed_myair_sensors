"""Recorder platform tests for statistics unit migrations."""

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

from homeassistant.const import PERCENTAGE, UnitOfVolumeFlowRate
from homeassistant.util.unit_conversion import VolumeFlowRateConverter

from custom_components.resmed_myair import recorder

MANIFEST_PATH = Path(__file__).parents[1] / "custom_components/resmed_myair/manifest.json"


def test_manifest_loads_after_recorder_when_available() -> None:
    """Recorder support is optional but ordered before myAir when available."""
    manifest = json.loads(MANIFEST_PATH.read_text())

    assert "recorder" in manifest["after_dependencies"]
    assert "recorder" not in manifest["dependencies"]


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


def test_async_migrate_mask_leak_statistics_metadata_updates_recorder(
    monkeypatch: Any,
) -> None:
    """Mask leak statistics metadata is relabeled to the new flow-rate unit."""
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
        }
    )
    recorder_instance = SimpleNamespace(async_update_statistics_metadata=MagicMock())
    monkeypatch.setattr(recorder.er, "async_get", lambda hass: registry)
    monkeypatch.setattr(recorder, "get_instance", lambda hass: recorder_instance)

    recorder.async_migrate_mask_leak_statistics_metadata(
        SimpleNamespace(data={recorder.DATA_INSTANCE: recorder_instance})
    )

    recorder_instance.async_update_statistics_metadata.assert_called_once_with(
        "sensor.cpap_mask_leak",
        new_unit_class=VolumeFlowRateConverter.UNIT_CLASS,
        new_unit_of_measurement=UnitOfVolumeFlowRate.LITERS_PER_MINUTE,
    )


def test_async_migrate_mask_leak_statistics_metadata_skips_without_recorder(
    monkeypatch: Any,
) -> None:
    """Mask leak metadata migration does not block setup when recorder is absent."""
    recorder_instance = SimpleNamespace(async_update_statistics_metadata=MagicMock())
    monkeypatch.setattr(recorder, "get_instance", lambda hass: recorder_instance)

    recorder.async_migrate_mask_leak_statistics_metadata(SimpleNamespace(data={}))

    recorder_instance.async_update_statistics_metadata.assert_not_called()
