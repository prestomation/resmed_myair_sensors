from unittest.mock import MagicMock

import pytest

from custom_components.resmed_myair.__init__ import async_migrate_entry


from custom_components.resmed_myair.const import CONF_REGION, REGION_NA

@pytest.mark.asyncio
async def test_async_migrate_entry_version_1(hass, config_entry):
    config_entry.version = 1
    config_entry.data = {"foo": "bar"}

    # Track calls to async_update_entry
    hass.config_entries.async_update_entry = MagicMock()

    result = await async_migrate_entry(hass, config_entry)

    # Should update version and add CONF_REGION
    assert result is True
    assert config_entry.version == 2
    hass.config_entries.async_update_entry.assert_called_once()
    args, kwargs = hass.config_entries.async_update_entry.call_args
    assert args[0] is config_entry
    # Verify that CONF_REGION was added to the data
    assert kwargs["data"][CONF_REGION] == REGION_NA
    assert kwargs["data"]["foo"] == "bar"  # Original data preserved
