"""Workflow-level config-flow tests for setup and reauth paths."""

from unittest.mock import AsyncMock, MagicMock

from homeassistant.config_entries import SOURCE_REAUTH, SOURCE_RECONFIGURE
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.resmed_myair import config_flow
from custom_components.resmed_myair.client.rest_client import RESTClient
from custom_components.resmed_myair.config_flow import (
    AUTHN_SUCCESS,
    CONF_DEVICE_TOKEN,
    CONF_PASSWORD,
    CONF_REGION,
    CONF_USER_NAME,
    CONF_VERIFICATION_CODE,
    REGION_EU,
    REGION_NA,
    MyAirConfigFlow,
)
from custom_components.resmed_myair.models import MyAirDevice


def _device(serial_number: str = "SN123") -> MyAirDevice:
    """Return a typed myAir device for config-flow workflow tests.

    Args:
        serial_number: Device serial number returned by the fake myAir API.

    Returns:
        Device model used by setup and reauth flow assertions.
    """
    return MyAirDevice.from_api(
        {
            "serialNumber": serial_number,
            "fgDeviceManufacturerName": "ResMed",
            "localizedName": "Bedroom CPAP",
        }
    )


def _flow(hass: MagicMock, context: dict[str, str] | None = None) -> MyAirConfigFlow:
    """Create a config flow bound to the test Home Assistant instance.

    Args:
        hass: Test Home Assistant instance.
        context: Optional config-flow context.

    Returns:
        Configured myAir config flow.
    """
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow.context = context or {}
    return flow


@pytest.mark.asyncio
async def test_initial_setup_mfa_workflow_sets_unique_id_and_persists_token(
    hass: MagicMock,
    myair_client: RESTClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Initial setup carries state from login to MFA and registers the device serial."""
    myair_client.device_token = "remembered-device-token"
    get_device = AsyncMock(return_value=("MFA_REQUIRED", None, myair_client))
    get_mfa_device = AsyncMock(return_value=(AUTHN_SUCCESS, _device()))
    monkeypatch.setattr(config_flow, "get_device", get_device)
    monkeypatch.setattr(config_flow, "get_mfa_device", get_mfa_device)
    hass.config_entries.async_entry_for_domain_unique_id = MagicMock(return_value=None)
    flow = _flow(hass)
    flow.async_set_unique_id = AsyncMock(wraps=flow.async_set_unique_id)

    mfa_form = await flow.async_step_user(
        {
            CONF_USER_NAME: "user@example.com",
            CONF_PASSWORD: "initial-password",
            CONF_REGION: REGION_EU,
        }
    )
    result = await flow.async_step_verify_mfa({CONF_VERIFICATION_CODE: "123456"})

    assert mfa_form["type"] == "form"
    assert mfa_form["step_id"] == "verify_mfa"
    assert result["type"] == "create_entry"
    assert result["title"] == "ResMed-Bedroom CPAP"
    assert result["data"] == {
        CONF_USER_NAME: "user@example.com",
        CONF_PASSWORD: "initial-password",
        CONF_REGION: REGION_EU,
        CONF_DEVICE_TOKEN: "remembered-device-token",
    }
    get_device.assert_awaited_once_with(
        hass,
        "user@example.com",
        "initial-password",
        REGION_EU,
        None,
    )
    get_mfa_device.assert_awaited_once_with(myair_client, "123456")
    flow.async_set_unique_id.assert_awaited_once_with("SN123")


@pytest.mark.asyncio
async def test_reauth_mfa_workflow_updates_entry_and_reloads(
    hass: MagicMock,
    myair_client: RESTClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reauth carries stored data through confirm, MFA, update, and reload."""
    entry_data = {
        CONF_USER_NAME: "old@example.com",
        CONF_PASSWORD: "old-password",
        CONF_REGION: REGION_NA,
        CONF_DEVICE_TOKEN: "old-token",
    }
    config_entry = MockConfigEntry(
        domain="resmed_myair",
        title="ResMed-Bedroom CPAP",
        data=entry_data,
        entry_id="existing-entry",
        unique_id="SN123",
        version=2,
    )
    myair_client.device_token = "new-token"
    get_device = AsyncMock(return_value=("MFA_REQUIRED", None, myair_client))
    get_mfa_device = AsyncMock(return_value=(AUTHN_SUCCESS, _device()))
    monkeypatch.setattr(config_flow, "get_device", get_device)
    monkeypatch.setattr(config_flow, "get_mfa_device", get_mfa_device)
    hass.config_entries.async_get_known_entry = MagicMock(return_value=config_entry)
    hass.config_entries.async_update_entry = MagicMock()
    hass.config_entries.async_schedule_reload = MagicMock()
    flow = _flow(hass, {"source": SOURCE_REAUTH, "entry_id": config_entry.entry_id})

    confirm_form = await flow.async_step_reauth(dict(entry_data))
    mfa_form = await flow.async_step_reauth_confirm(
        {
            CONF_USER_NAME: "new@example.com",
            CONF_PASSWORD: "new-password",
        }
    )
    result = await flow.async_step_reauth_verify_mfa({CONF_VERIFICATION_CODE: "654321"})

    assert confirm_form["type"] == "form"
    assert confirm_form["step_id"] == "reauth_confirm"
    assert mfa_form["type"] == "form"
    assert mfa_form["step_id"] == "reauth_verify_mfa"
    assert result["type"] == "abort"
    assert result["reason"] == "reauth_successful"
    get_device.assert_awaited_once_with(
        hass,
        "new@example.com",
        "new-password",
        REGION_NA,
        "old-token",
    )
    get_mfa_device.assert_awaited_once_with(myair_client, "654321")
    _, kwargs = hass.config_entries.async_update_entry.call_args
    assert kwargs["entry"] is config_entry
    assert kwargs["data"] == {
        CONF_USER_NAME: "new@example.com",
        CONF_PASSWORD: "new-password",
        CONF_REGION: REGION_NA,
        CONF_DEVICE_TOKEN: "new-token",
    }
    hass.config_entries.async_schedule_reload.assert_called_once_with("existing-entry")


@pytest.mark.asyncio
async def test_reconfigure_mfa_workflow_updates_entry_and_reloads(
    hass: MagicMock,
    myair_client: RESTClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reconfigure carries updated setup data through MFA, update, and reload."""
    entry_data = {
        CONF_USER_NAME: "old@example.com",
        CONF_PASSWORD: "old-password",
        CONF_REGION: REGION_NA,
        CONF_DEVICE_TOKEN: "old-token",
    }
    config_entry = MockConfigEntry(
        domain="resmed_myair",
        title="ResMed-Bedroom CPAP",
        data=entry_data,
        entry_id="existing-entry",
        unique_id="SN123",
        version=2,
    )
    myair_client.device_token = "new-token"
    get_device = AsyncMock(return_value=("MFA_REQUIRED", None, myair_client))
    get_mfa_device = AsyncMock(return_value=(AUTHN_SUCCESS, _device()))
    monkeypatch.setattr(config_flow, "get_device", get_device)
    monkeypatch.setattr(config_flow, "get_mfa_device", get_mfa_device)
    hass.config_entries.async_get_known_entry = MagicMock(return_value=config_entry)
    hass.config_entries.async_update_entry = MagicMock()
    hass.config_entries.async_schedule_reload = MagicMock()
    flow = _flow(hass, {"source": SOURCE_RECONFIGURE, "entry_id": config_entry.entry_id})

    mfa_form = await flow.async_step_reconfigure(
        {
            CONF_USER_NAME: "new@example.com",
            CONF_PASSWORD: "new-password",
            CONF_REGION: REGION_EU,
        }
    )
    result = await flow.async_step_reconfigure_verify_mfa({CONF_VERIFICATION_CODE: "654321"})

    assert mfa_form["type"] == "form"
    assert mfa_form["step_id"] == "reconfigure_verify_mfa"
    assert result["type"] == "abort"
    assert result["reason"] == "reconfigure_successful"
    get_device.assert_awaited_once_with(
        hass,
        "new@example.com",
        "new-password",
        REGION_EU,
        "old-token",
    )
    get_mfa_device.assert_awaited_once_with(myair_client, "654321")
    _, kwargs = hass.config_entries.async_update_entry.call_args
    assert kwargs["entry"] is config_entry
    assert kwargs["data"] == {
        CONF_USER_NAME: "new@example.com",
        CONF_PASSWORD: "new-password",
        CONF_REGION: REGION_EU,
        CONF_DEVICE_TOKEN: "new-token",
    }
    hass.config_entries.async_schedule_reload.assert_called_once_with("existing-entry")
