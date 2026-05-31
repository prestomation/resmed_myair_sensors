"""Package-initialization tests that protect config-entry migration behavior."""

from unittest.mock import MagicMock

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.resmed_myair.__init__ import async_migrate_entry
from custom_components.resmed_myair.const import CONF_REGION, REGION_NA


@pytest.mark.parametrize(
    ("version", "expected_update"),
    [
        (1, {"foo": "bar", CONF_REGION: REGION_NA}),
        (2, None),
    ],
)
@pytest.mark.asyncio
async def test_async_migrate_entry_versions(
    hass: MagicMock,
    version: int,
    expected_update: dict[str, object] | None,
) -> None:
    """Config-entry migration only updates entries that need a default region."""
    entry = MockConfigEntry(
        domain="resmed_myair", title="ResMed-CPAP", data={"foo": "bar"}, version=version
    )
    hass.config_entries.async_update_entry = MagicMock()

    result = await async_migrate_entry(hass, entry)

    assert result is True
    if expected_update is None:
        hass.config_entries.async_update_entry.assert_not_called()
    else:
        hass.config_entries.async_update_entry.assert_called_once_with(
            entry,
            data=expected_update,
            version=2,
        )
