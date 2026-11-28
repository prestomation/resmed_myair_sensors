"""Home Assistant compatibility helpers shared across the test suite.

``pytest-homeassistant`` covers Home Assistant 2026.11 and later. Older supported
versions are only covered by its predecessor,
``pytest-homeassistant-custom-component``. Import plugin helpers from here so the
same tests run against either package.
"""

from types import SimpleNamespace
from typing import Any

from homeassistant.helpers.device_registry import DeviceInfo

try:
    from pytest_homeassistant.common import MockConfigEntry
except ModuleNotFoundError:
    from pytest_homeassistant_custom_component.common import MockConfigEntry

__all__ = ["MockConfigEntry", "device_info_view"]


def device_info_view(device_info: DeviceInfo | None) -> Any:
    """Return an entity's device info with attribute access on every supported release.

    ``DeviceInfo`` is a dataclass from Home Assistant 2026.12 and a ``TypedDict``
    before it. Delete this helper and read the attributes directly once the minimum
    supported release reaches 2026.12.

    Args:
        device_info (DeviceInfo | None): Device info returned by an entity.

    Returns:
        Any: The dataclass itself, or the older mapping's fields as attributes.
    """
    assert device_info is not None
    if isinstance(device_info, dict):
        return SimpleNamespace(**device_info)
    return device_info
