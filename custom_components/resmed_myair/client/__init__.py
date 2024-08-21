from aiohttp import ClientSession

from .eu_client import RESTEUClient
from .myair_client import MyAirConfig
from .na_client import RESTNAClient


def get_client(config: MyAirConfig, session: ClientSession):
    if config.region == "NA":
        return RESTNAClient(config, session)
    elif config.region == "EU":
        return RESTEUClient(config, session)
    assert False, "Region must be NA or EU"
