from aiohttp import ClientSession

from .myair_client import MyAirConfig
from .rest_client import RESTClient


# May be able to remove this entire file and just use RESTClient directly
def get_client(config: MyAirConfig, session: ClientSession):
    return RESTClient(config, session)
