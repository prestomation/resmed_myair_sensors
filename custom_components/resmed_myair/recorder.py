"""Recorder platform support for resmed_myair statistics migrations."""

from homeassistant.const import PERCENTAGE, UnitOfVolumeFlowRate
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er

from .const import DOMAIN

_MASK_LEAK_UNIQUE_ID_SUFFIX = "_leakPercentile"


@callback
def async_custom_equivalent_units(hass: HomeAssistant) -> dict[str, dict[str | None, str]]:
    """Return custom equivalent units for long-term statistics migrations.

    Args:
        hass: Home Assistant instance with the entity registry.

    Returns:
        Entity-specific mappings from the old mask-leak unit to the supported
        volume flow rate unit. The value conversion is 1:1.
    """
    entity_registry = er.async_get(hass)

    return {
        entry.entity_id: {PERCENTAGE: UnitOfVolumeFlowRate.LITERS_PER_MINUTE}
        for entry in entity_registry.entities.values()
        if entry.platform == DOMAIN
        and entry.unique_id.startswith(f"{DOMAIN}_")
        and entry.unique_id.endswith(_MASK_LEAK_UNIQUE_ID_SUFFIX)
    }
