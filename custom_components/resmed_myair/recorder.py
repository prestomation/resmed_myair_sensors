"""Recorder platform support for resmed_myair statistics migrations."""

from homeassistant.components.recorder import get_instance
from homeassistant.const import PERCENTAGE, UnitOfVolumeFlowRate
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er
from homeassistant.util.unit_conversion import VolumeFlowRateConverter

from .const import DOMAIN

_MASK_LEAK_UNIQUE_ID_SUFFIX = "_leakPercentile"


def _mask_leak_entity_ids(hass: HomeAssistant) -> list[str]:
    """Return registered myAir mask leak entity IDs.

    Args:
        hass: Home Assistant instance with the entity registry.

    Returns:
        Entity IDs for the mask leak sensor whose previous unit metadata may
        need migration.
    """
    entity_registry = er.async_get(hass)

    return [
        entry.entity_id
        for entry in entity_registry.entities.values()
        if entry.platform == DOMAIN
        and entry.unique_id.startswith(f"{DOMAIN}_")
        and entry.unique_id.endswith(_MASK_LEAK_UNIQUE_ID_SUFFIX)
    ]


@callback
def async_migrate_mask_leak_statistics_metadata(hass: HomeAssistant) -> None:
    """Relabel legacy mask leak statistics metadata to the corrected unit.

    Args:
        hass: Home Assistant instance with recorder and entity registry state.
    """
    recorder_instance = get_instance(hass)

    for entity_id in _mask_leak_entity_ids(hass):
        recorder_instance.async_update_statistics_metadata(
            entity_id,
            new_unit_class=VolumeFlowRateConverter.UNIT_CLASS,
            new_unit_of_measurement=UnitOfVolumeFlowRate.LITERS_PER_MINUTE,
        )


@callback
def async_custom_equivalent_units(hass: HomeAssistant) -> dict[str, dict[str | None, str]]:
    """Return custom equivalent units for long-term statistics migrations.

    Args:
        hass: Home Assistant instance with the entity registry.

    Returns:
        Entity-specific mappings from the old mask-leak unit to the supported
        volume flow rate unit. The value conversion is 1:1.
    """
    return {
        entity_id: {PERCENTAGE: UnitOfVolumeFlowRate.LITERS_PER_MINUTE}
        for entity_id in _mask_leak_entity_ids(hass)
    }
