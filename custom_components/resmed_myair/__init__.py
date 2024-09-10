"""
This is a HomeAssistant Custom Component for ResMed myAir devices

It uses the myair_client which is standalone and can be used outside HomeAssistant
myair_client is a reverse engineering and can break at anytime.
"""

import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.redact import async_redact_data

from .const import CONF_REGION, DOMAIN, KEYS_TO_REDACT, REGION_NA, VERSION

_LOGGER: logging.Logger = logging.getLogger(__name__)
PLATFORMS: list[str] = [Platform.SENSOR]


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Set up from a config entry."""
    _LOGGER.info(f"Starting ResMed myAir Integration Version: {VERSION}")
    _LOGGER.debug(
        f"[init async_setup_entry] config_entry.data: {async_redact_data(config_entry.data, KEYS_TO_REDACT)}"
    )
    hass.data.setdefault(DOMAIN, {})
    hass_data: dict[str, Any] = dict(config_entry.data)
    hass.data[DOMAIN][config_entry.entry_id] = hass_data
    await hass.config_entries.async_forward_entry_setups(config_entry, PLATFORMS)

    return True


async def async_migrate_entry(hass, config_entry: ConfigEntry) -> bool:
    """Migrate old entry."""
    _LOGGER.debug("Migrating from version %s", config_entry.version)

    if config_entry.version == 1:

        new: dict[str, Any] = {**config_entry.data}
        # v1 only supported NA by its implicit nature, so lets set it here
        new[CONF_REGION] = REGION_NA

        config_entry.version = 2
        hass.config_entries.async_update_entry(config_entry, data=new)

    _LOGGER.info("Migration to version %s successful", config_entry.version)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    _LOGGER.info(f"Unloading: {async_redact_data(entry.data, KEYS_TO_REDACT)}")
    unload_ok: bool = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)

    return unload_ok
