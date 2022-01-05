from .legacy_client import LegacyClient
from .new_client import RESTClient
from .myair_client import MyAirConfig


def get_client(config: MyAirConfig):
    if config.region == "NA":
        return RESTClient(config)
    elif config.region == "EU":
        return LegacyClient(config)
    assert False, "Region must be NA or EU"
