"""
This is a HomeAssistant Custom Component for ResMed myAir devices

It uses the myair_client which is standalone and can be used outside HomeAssistant
myair_client is a reverse engineering and can break at anytime.
"""

from typing import List, Dict

from .myair_client import MyAirClient, MyAirConfig
from homeassistant.config_entries import ConfigEntry

from homeassistant.components.sensor import (
    SensorEntityDescription,
    SensorStateClass,
)

from homeassistant.core import HomeAssistant
from .common import CONF_PASSWORD, CONF_USER_NAME, DOMAIN
import logging


_LOGGER = logging.getLogger(__name__)
PLATFORMS: List[str] = ["sensor"]


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry):
    hass.config_entries.async_setup_platforms(config_entry, PLATFORMS)

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
