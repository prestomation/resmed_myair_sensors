from aiohttp import ClientSession

# from .eu_client import RESTEUClient
# from .na_client import RESTNAClient
from .myair_client import MyAirConfig
from .rest_client import RESTClient


def get_client(config: MyAirConfig, session: ClientSession):
    return RESTClient(config, session)
    # if config.region == "NA":
    #     return RESTNAClient(config, session)
    # elif config.region == "EU":
    #     return RESTEUClient(config, session)
    # assert False, "Region must be NA or EU"
