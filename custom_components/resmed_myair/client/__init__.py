from aiohttp import ClientSession

from .eu_client import RESTEUClient
from .myair_client import MyAirConfig, MyAirEUConfig

# from .legacy_client import LegacyClient
from .new_client import RESTClient


def get_client(config: MyAirConfig | MyAirEUConfig, session: ClientSession):
    if config.region == "NA":
        return RESTClient(config, session)
    elif config.region == "EU":
        return RESTEUClient(config, session)
    assert False, "Region must be NA or EU"
