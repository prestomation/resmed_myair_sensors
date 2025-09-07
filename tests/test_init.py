"""Tests for package initialization logic, including migration helpers."""

from unittest.mock import MagicMock

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.resmed_myair.__init__ import async_migrate_entry
from custom_components.resmed_myair.const import CONF_REGION, REGION_NA


@pytest.mark.asyncio
async def test_async_migrate_entry_version_1(hass):
    """Migrate from version 1 should add CONF_REGION and update entry."""
    # Create a MockConfigEntry at version 1 to exercise migration logic
    entry = MockConfigEntry(
        domain="resmed_myair", title="ResMed-CPAP", data={"foo": "bar"}, version=1
    )

    # Track calls to async_update_entry
    hass.config_entries.async_update_entry = MagicMock()

    result = await async_migrate_entry(hass, entry)

    # Should return True and call async_update_entry with the updated data
    assert result is True
    hass.config_entries.async_update_entry.assert_called_once_with(
        entry,
        data={"foo": "bar", CONF_REGION: REGION_NA},
        version=2,
    )


@pytest.mark.asyncio
async def test_async_migrate_entry_version_2_noop(hass):
    """Migrate from version 2 should be a no-op and not call async_update_entry."""
    entry = MockConfigEntry(
        domain="resmed_myair", title="ResMed-CPAP", data={"foo": "bar"}, version=2
    )
    hass.config_entries.async_update_entry = MagicMock()
    result = await async_migrate_entry(hass, entry)
    assert result is True
    hass.config_entries.async_update_entry.assert_not_called()
