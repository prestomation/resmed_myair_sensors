import logging

from aiohttp import ClientSession

from .legacy_client import LegacyClient
from .myair_client import MyAirConfig
from .new_client import RESTClient

_LOGGER = logging.getLogger(__name__)


def get_client(config: MyAirConfig, session: ClientSession):
    if config.region == "NA":
        return RESTClient(config, session)
    elif config.region == "EU":
        return LegacyClient(config, session)
    assert False, "Region must be NA or EU"
