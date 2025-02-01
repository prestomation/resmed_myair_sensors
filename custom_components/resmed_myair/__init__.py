"""Home Assistant Custom Component for ResMed myAir devices.

It uses the myair_client which is standalone and can be used outside Home Assistant
myair_client is a reverse engineering and can break at anytime.
"""

from collections.abc import MutableMapping
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .const import CONF_REGION, DOMAIN, REGION_NA, VERSION
from .helpers import redact_dict

_LOGGER: logging.Logger = logging.getLogger(__name__)
PLATFORMS: list[str] = [Platform.SENSOR]


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Set up from a config entry."""
    _LOGGER.info("Starting ResMed myAir Integration Version: %s", VERSION)
    _LOGGER.debug("[init async_setup_entry] config_entry.data: %s", redact_dict(config_entry.data))
    hass.data.setdefault(DOMAIN, {})
    hass_data: MutableMapping[str, Any] = dict(config_entry.data)
    hass.data[DOMAIN][config_entry.entry_id] = hass_data
    await hass.config_entries.async_forward_entry_setups(config_entry, PLATFORMS)

    return True


async def async_migrate_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Migrate old entry."""
    _LOGGER.debug("Migrating from version %s", config_entry.version)

    if config_entry.version == 1:
        new: MutableMapping[str, Any] = {**config_entry.data}
        # v1 only supported NA by its implicit nature, so lets set it here
        new[CONF_REGION] = REGION_NA

        config_entry.version = 2
        hass.config_entries.async_update_entry(config_entry, data=new)

    _LOGGER.info("Migration to version %s successful", config_entry.version)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    _LOGGER.info("Unloading: %s", redact_dict(entry.data))
    unload_ok: bool = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)

    return unload_ok
