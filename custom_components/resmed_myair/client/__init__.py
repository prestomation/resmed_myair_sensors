from aiohttp import ClientSession
from .legacy_client import LegacyClient
from .new_client import RESTClient
from .myair_client import MyAirConfig


def get_client(config: MyAirConfig, session: ClientSession):
    if config.region == "NA":
        return RESTClient(config, session)
    elif config.region == "EU":
        return LegacyClient(config, session)
    assert False, "Region must be NA or EU"
