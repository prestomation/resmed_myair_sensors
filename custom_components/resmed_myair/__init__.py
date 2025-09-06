"""Home Assistant Custom Component for ResMed myAir devices.

It uses the myair_client which is standalone and can be used outside Home Assistant
myair_client is a reverse engineering and can break at anytime.
"""

from collections.abc import MutableMapping
import logging
from typing import Any

from aiohttp import DummyCookieJar

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_create_clientsession

from .client.myair_client import MyAirConfig
from .client.rest_client import RESTClient
from .const import (
    CONF_DEVICE_TOKEN,
    CONF_PASSWORD,
    CONF_REGION,
    CONF_USER_NAME,
    PLATFORMS,
    REGION_NA,
    VERSION,
)
from .coordinator import MyAirDataUpdateCoordinator
from .helpers import redact_dict

_LOGGER: logging.Logger = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Set up from a config entry."""
    _LOGGER.info("Starting ResMed myAir Integration Version: %s", VERSION)
    _LOGGER.debug("[init async_setup_entry] config_entry.data: %s", redact_dict(config_entry.data))

    client_config: MyAirConfig = MyAirConfig(
        username=config_entry.data[CONF_USER_NAME],
        password=config_entry.data[CONF_PASSWORD],
        region=config_entry.data[CONF_REGION],
        device_token=config_entry.data.get(CONF_DEVICE_TOKEN, None),
    )
    client: RESTClient = RESTClient(
        client_config,
        async_create_clientsession(hass=hass, cookie_jar=DummyCookieJar(), raise_for_status=True),
    )

    coordinator: MyAirDataUpdateCoordinator = MyAirDataUpdateCoordinator(
        hass=hass, config_entry=config_entry, myair_client=client
    )

    config_entry.runtime_data = coordinator

    await coordinator.async_config_entry_first_refresh()

    await hass.config_entries.async_forward_entry_setups(config_entry, PLATFORMS)
    return True


async def async_migrate_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Migrate old entry."""
    _LOGGER.debug("Migrating from version %s", config_entry.version)

    if config_entry.version == 1:
        new: MutableMapping[str, Any] = {**config_entry.data}
        # v1 only supported NA by its implicit nature, so lets set it here
        new[CONF_REGION] = REGION_NA

        hass.config_entries.async_update_entry(config_entry, data=new, version=2)

        _LOGGER.info("Migration to version 2 successful")

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    _LOGGER.info("Unloading: %s", redact_dict(entry.data))
    unload_ok: bool = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    return unload_ok
