from aiohttp import ClientSession

from .myair_client import MyAirConfig
from .rest_client import RESTClient


def get_client(config: MyAirConfig, session: ClientSession):
    return RESTClient(config, session)
