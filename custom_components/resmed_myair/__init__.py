"""
This is a HomeAssistant Custom Component for ResMed myAir devices

It uses the myair_client which is standalone and can be used outside HomeAssistant
myair_client is a reverse engineering and can break at anytime.
"""

import logging
from typing import List

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .common import CONF_REGION, DOMAIN

_LOGGER = logging.getLogger(__name__)
PLATFORMS: List[str] = ["sensor"]


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Set up from a config entry."""

    _LOGGER.debug(f"[init async_setup_entry] entry: {config_entry.data}")
    hass.data.setdefault(DOMAIN, {})
    hass_data = dict(config_entry.data)
    hass.data[DOMAIN][config_entry.entry_id] = hass_data
    await hass.config_entries.async_forward_entry_setups(config_entry, PLATFORMS)

    return True


# @service
# def poll_resmed_myair(action=None, id=None):
#     """yaml
# name: Poll CPAP data from Resmed myAir
# description: Create sensor data for all your CPAP data from myAir
# """

#     log.info(f"resmed poll service invoked")
#     emit_myair_sensors()


# # We run every 30 min. This really only needs to run once a day
# # @time_trigger('*/30 * * * *')
# async def emit_myair_sensors(config):
#     config = get_config()

#     client_config = MyAirConfig(username=config['username'], password=config['password'])
#     client = MyAirClient(client_config)
#     await client.connect()
#     records = await client.get_sleep_records()
#     # We are assuming that these are sorted by time, so we just take the last records
#     # This API always gives us the trailing month
#     records[0][]


async def async_migrate_entry(hass, config_entry: ConfigEntry):
    """Migrate old entry."""
    _LOGGER.debug("Migrating from version %s", config_entry.version)

    if config_entry.version == 1:

        new = {**config_entry.data}
        # v1 only supported NA by its implicit nature, so lets set it here
        new[CONF_REGION] = "NA"

        config_entry.version = 2
        hass.config_entries.async_update_entry(config_entry, data=new)

    _LOGGER.info("Migration to version %s successful", config_entry.version)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    _LOGGER.info(f"Unloading: {entry.data}")
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok
