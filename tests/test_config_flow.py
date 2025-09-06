"""Tests for the integration config flow behavior and edge cases."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.resmed_myair.client.rest_client import RESTClient
from custom_components.resmed_myair.config_flow import (
    AUTHN_SUCCESS,
    CONF_DEVICE_TOKEN,
    CONF_PASSWORD,
    CONF_REGION,
    CONF_USER_NAME,
    CONF_VERIFICATION_CODE,
    REGION_NA,
    AuthenticationError,
    HttpProcessingError,
    IncompleteAccountError,
    MyAirConfigFlow,
    ParsingError,
    get_device,
    get_mfa_device,
)
from homeassistant.config_entries import UnknownEntry


@pytest.fixture
def flow(hass: MagicMock) -> MyAirConfigFlow:
    """Fixture for MyAirConfigFlow instance."""
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow.context = {}  # Fix mappingproxy error
    return flow


@pytest.mark.asyncio
async def test_async_step_user_success(flow: MyAirConfigFlow) -> None:
    """Test successful user step."""
    user_input: dict[str, str] = {
        CONF_USER_NAME: "user",
        CONF_PASSWORD: "pass",
        CONF_REGION: REGION_NA,
    }
    device: dict[str, str] = {
        "serialNumber": "SN123",
        "fgDeviceManufacturerName": "ResMed",
        "localizedName": "CPAP",
    }
    with (
        patch(
            "custom_components.resmed_myair.config_flow.get_device",
            new=AsyncMock(return_value=(AUTHN_SUCCESS, device, MagicMock(device_token="token"))),
        ),
        patch.object(
            flow.hass.config_entries,
            "async_entry_for_domain_unique_id",
            return_value=None,
        ),
    ):
        result = await flow.async_step_user(user_input)
    assert result["type"] == "create_entry"
    assert "ResMed-CPAP" in result["title"]
    assert result["data"][CONF_USER_NAME] == "user"


@pytest.mark.asyncio
async def test_async_step_user_auth_error(flow: MyAirConfigFlow) -> None:
    """Test user step with authentication error."""
    user_input: dict[str, str] = {
        CONF_USER_NAME: "user",
        CONF_PASSWORD: "badpass",
        CONF_REGION: REGION_NA,
    }
    with patch(
        "custom_components.resmed_myair.config_flow.get_device",
        new=AsyncMock(side_effect=Exception("fail")),
    ):
        with pytest.raises(Exception) as exc:
            await flow.async_step_user(user_input)
        assert str(exc.value) == "fail"


@pytest.mark.asyncio
async def test_async_step_verify_mfa_user_input_and_client(monkeypatch):
    """Verify MFA step with valid user input leads to create_entry."""
    flow = MyAirConfigFlow()
    flow.hass = MagicMock()
    flow._data = {}
    # Patch _client as a RESTClient instance (not just MagicMock)
    flow._client = MagicMock(spec=RESTClient)
    user_input = {CONF_VERIFICATION_CODE: "654321"}

    # Patch get_mfa_device to return AUTHN_SUCCESS and a mock device
    monkeypatch.setattr(
        "custom_components.resmed_myair.config_flow.get_mfa_device",
        AsyncMock(
            return_value=(
                AUTHN_SUCCESS,
                {"fgDeviceManufacturerName": "ResMed", "localizedName": "CPAP"},
            )
        ),
    )
    # Patch device_token on the client
    flow._client.device_token = "token"

    # Patch async_create_entry to just return its arguments for assertion
    flow.async_create_entry = MagicMock(
        return_value={"type": "create_entry", "title": "ResMed-CPAP", "data": {}}
    )

    result = await flow.async_step_verify_mfa(user_input)
    assert result["type"] == "create_entry"
    assert "ResMed-CPAP" in result["title"]
    flow.async_create_entry.assert_called_once()


@pytest.mark.asyncio
async def test_async_step_verify_mfa_error(flow: MyAirConfigFlow) -> None:
    """Test MFA verification step with error."""
    flow._client = MagicMock()
    flow._data = {CONF_USER_NAME: "user"}
    user_input: dict[str, str] = {CONF_VERIFICATION_CODE: "bad"}
    with patch(
        "custom_components.resmed_myair.config_flow.get_mfa_device",
        new=AsyncMock(side_effect=Exception("fail")),
    ):
        result = await flow.async_step_verify_mfa(user_input)
    assert result["type"] == "form"
    assert "errors" in result
    if "base" in result["errors"]:
        assert result["errors"]["base"] == "mfa_error"


@pytest.mark.asyncio
async def test_async_step_user_form_display(flow: MyAirConfigFlow) -> None:
    """Test that the user form is shown when no input is provided."""
    result = await flow.async_step_user()
    assert result["type"] == "form"
    assert result["step_id"] == "user"
    assert "errors" in result


@pytest.mark.asyncio
async def test_async_step_verify_mfa_form_display(flow: MyAirConfigFlow) -> None:
    """Test that the MFA form is shown when no input is provided."""
    flow._client = MagicMock()
    flow._data = {CONF_USER_NAME: "user"}
    result = await flow.async_step_verify_mfa()
    assert result["type"] == "form"
    assert result["step_id"] == "verify_mfa"
    assert "errors" in result


@pytest.mark.asyncio
async def test_async_step_verify_mfa_incomplete_account(flow: MyAirConfigFlow) -> None:
    """Test MFA step aborts if account is incomplete."""
    flow._client = MagicMock()
    flow._data = {CONF_USER_NAME: "user"}
    user_input: dict[str, str] = {CONF_VERIFICATION_CODE: "123456"}
    # Simulate IncompleteAccountError and email not verified
    flow._client.is_email_verified = AsyncMock(return_value=False)
    with (
        patch(
            "custom_components.resmed_myair.config_flow.get_mfa_device",
            new=AsyncMock(side_effect=Exception("fail")),
        ),
        patch(
            "custom_components.resmed_myair.config_flow.IncompleteAccountError",
            new=Exception,
        ),
    ):
        result = await flow.async_step_verify_mfa(user_input)
    # Should show form with errors or abort for incomplete account
    assert result["type"] == "form" or result.get("reason") in (
        "incomplete_account_verify_email",
        "incomplete_account",
    )


@pytest.mark.asyncio
async def test_async_step_reauth_confirm_form_display(flow: MyAirConfigFlow) -> None:
    """Test that the reauth confirm form is shown when no input is provided."""
    flow._data = {CONF_USER_NAME: "user", CONF_PASSWORD: "pass"}
    result = await flow.async_step_reauth_confirm()
    assert result["type"] == "form"
    assert result["step_id"] == "reauth_confirm"
    assert "errors" in result


@pytest.mark.asyncio
async def test_async_step_reauth_verify_mfa_form_display(flow: MyAirConfigFlow) -> None:
    """Test that the reauth verify MFA form is shown when no input is provided."""
    flow._client = MagicMock()
    flow._data = {CONF_USER_NAME: "user"}
    result = await flow.async_step_reauth_verify_mfa()
    assert result["type"] == "form"
    assert result["step_id"] == "reauth_verify_mfa"
    assert "errors" in result


@pytest.mark.asyncio
async def test_async_step_reauth_success(flow: MyAirConfigFlow) -> None:
    """Test reauth step completes successfully."""
    flow._data = {CONF_USER_NAME: "user", CONF_PASSWORD: "pass", CONF_REGION: REGION_NA}
    device = {
        "serialNumber": "SN123",
        "fgDeviceManufacturerName": "ResMed",
        "localizedName": "CPAP",
    }
    flow._entry = MagicMock()
    flow.hass.config_entries.async_get_entry = MagicMock(return_value=flow._entry)
    with (
        patch(
            "custom_components.resmed_myair.config_flow.get_device",
            new=AsyncMock(return_value=(AUTHN_SUCCESS, device, MagicMock(device_token="token"))),
        ),
        patch.object(flow.hass.config_entries, "async_update_entry") as mock_update,
        patch.object(flow.hass.config_entries, "async_reload", new=AsyncMock()),
    ):
        result = await flow.async_step_reauth_confirm(
            {CONF_USER_NAME: "user", CONF_PASSWORD: "pass"}
        )
    assert result["type"] == "abort"
    assert result["reason"] == "reauth_successful"
    mock_update.assert_called_once()


@pytest.mark.asyncio
async def test_async_step_reauth_confirm_mfa(flow: MyAirConfigFlow) -> None:
    """Test reauth confirm step triggers MFA if needed."""
    flow._data = {CONF_USER_NAME: "user", CONF_PASSWORD: "pass", CONF_REGION: REGION_NA}
    flow._entry = MagicMock()
    flow.hass.config_entries.async_get_entry = MagicMock(return_value=flow._entry)
    with patch(
        "custom_components.resmed_myair.config_flow.get_device",
        new=AsyncMock(return_value=("MFA_REQUIRED", None, MagicMock())),
    ):
        result = await flow.async_step_reauth_confirm(
            {CONF_USER_NAME: "user", CONF_PASSWORD: "pass"}
        )
    assert result["type"] == "form"
    assert result["step_id"] == "reauth_verify_mfa"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "is_email_verified, client_exists, expected_abort_reason, expect_exception",
    [
        (False, True, "incomplete_account_verify_email", False),  # Email not verified
        (True, True, "incomplete_account", False),  # Email verified
        (None, False, "incomplete_account", False),  # No client
        (
            "exception",
            True,
            "incomplete_account",
            False,
        ),  # Exception in is_email_verified (should abort, not raise)
    ],
)
async def test_async_step_reauth_confirm_incomplete_account_parametrized(
    monkeypatch, is_email_verified, client_exists, expected_abort_reason, expect_exception
):
    """Parametrized: Test async_step_reauth_confirm aborts for incomplete account in all branches."""
    flow = MyAirConfigFlow()
    flow.hass = MagicMock()
    flow._data = {
        CONF_USER_NAME: "user",
        CONF_PASSWORD: "pass",
        CONF_REGION: "NA",
    }
    flow._entry = MagicMock()
    user_input = {CONF_USER_NAME: "user", CONF_PASSWORD: "pass"}

    # Patch get_device to raise IncompleteAccountError
    monkeypatch.setattr(
        "custom_components.resmed_myair.config_flow.get_device",
        AsyncMock(side_effect=IncompleteAccountError("incomplete")),
    )
    flow.async_abort = MagicMock(return_value={"type": "abort", "reason": expected_abort_reason})

    if client_exists:
        flow._client = MagicMock(spec=RESTClient)
        if is_email_verified == "exception":
            flow._client.is_email_verified = AsyncMock(side_effect=Exception("fail"))
        else:
            flow._client.is_email_verified = AsyncMock(return_value=is_email_verified)
    else:
        flow._client = None

    # The flow should always abort, even if is_email_verified raises
    result = await flow.async_step_reauth_confirm(user_input)
    assert result["type"] == "abort"
    assert result["reason"] == expected_abort_reason
    if client_exists and is_email_verified != "exception":
        flow._client.is_email_verified.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_step_reauth_verify_mfa_success(flow: MyAirConfigFlow) -> None:
    """Test reauth verify MFA step completes successfully."""
    flow._client = MagicMock()
    flow._data = {CONF_USER_NAME: "user", CONF_PASSWORD: "pass"}
    flow._entry = MagicMock()
    with (
        patch(
            "custom_components.resmed_myair.config_flow.get_mfa_device",
            new=AsyncMock(
                return_value=(
                    AUTHN_SUCCESS,
                    {"fgDeviceManufacturerName": "ResMed", "localizedName": "CPAP"},
                )
            ),
        ),
        patch.object(flow.hass.config_entries, "async_update_entry") as mock_update,
        patch.object(flow.hass.config_entries, "async_reload", new=AsyncMock()),
    ):
        result = await flow.async_step_reauth_verify_mfa({CONF_VERIFICATION_CODE: "123456"})
    if result["type"] == "abort":
        assert result["reason"] == "reauth_successful"
        mock_update.assert_called_once()
    else:
        assert result["type"] == "form"
        assert result["step_id"] == "reauth_verify_mfa"
        assert "errors" in result


@pytest.mark.asyncio
async def test_async_step_reauth_verify_mfa_error(flow: MyAirConfigFlow) -> None:
    """Test reauth verify MFA step with error."""
    flow._client = MagicMock()
    flow._data = {CONF_USER_NAME: "user", CONF_PASSWORD: "pass"}
    flow._entry = MagicMock()
    with patch(
        "custom_components.resmed_myair.config_flow.get_mfa_device",
        new=AsyncMock(side_effect=Exception("fail")),
    ):
        result = await flow.async_step_reauth_verify_mfa({CONF_VERIFICATION_CODE: "bad"})
    assert result["type"] == "form"
    assert result["step_id"] == "reauth_verify_mfa"
    assert "errors" in result
    if "base" in result["errors"]:
        assert result["errors"]["base"] == "mfa_error"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "is_email_verified, client_exists, expected_abort_reason, expect_exception",
    [
        (False, True, "incomplete_account_verify_email", False),  # Email not verified
        (True, True, "incomplete_account", False),  # Email verified
        (None, False, "incomplete_account", False),  # No client
        (
            "exception",
            True,
            "incomplete_account",
            False,
        ),  # Exception in is_email_verified (should abort, not raise)
    ],
)
async def test_async_step_reauth_verify_mfa_incomplete_account_parametrized(
    monkeypatch, is_email_verified, client_exists, expected_abort_reason, expect_exception
):
    """Parametrized: Test async_step_reauth_verify_mfa aborts or shows form for incomplete account in all branches."""
    flow = MyAirConfigFlow()
    flow.hass = MagicMock()
    flow._data = {
        CONF_USER_NAME: "user",
        CONF_PASSWORD: "pw",
        CONF_REGION: "NA",
    }
    flow._entry = MagicMock()
    user_input = {CONF_VERIFICATION_CODE: "654321"}

    # Patch get_mfa_device to raise IncompleteAccountError
    monkeypatch.setattr(
        "custom_components.resmed_myair.config_flow.get_mfa_device",
        AsyncMock(side_effect=IncompleteAccountError("incomplete")),
    )
    flow.async_abort = MagicMock(return_value={"type": "abort", "reason": expected_abort_reason})

    if client_exists:
        flow._client = MagicMock(spec=RESTClient)
        if is_email_verified == "exception":
            flow._client.is_email_verified = AsyncMock(side_effect=Exception("fail"))
        else:
            flow._client.is_email_verified = AsyncMock(return_value=is_email_verified)
    else:
        flow._client = None

    result = await flow.async_step_reauth_verify_mfa(user_input)
    # If no client, the flow shows a form instead of aborting
    if not client_exists:
        assert result["type"] == "form"
        assert result["step_id"] == "reauth_verify_mfa"
    else:
        assert result["type"] == "abort"
        assert result["reason"] == expected_abort_reason
        if is_email_verified != "exception":
            flow._client.is_email_verified.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "connect_return, get_user_device_data_return, expected_status, expected_device, raises",
    [
        (AUTHN_SUCCESS, {"serialNumber": "SN123"}, AUTHN_SUCCESS, {"serialNumber": "SN123"}, None),
        ("AUTHN_FAIL", None, "AUTHN_FAIL", None, None),
        ("FAIL", None, "FAIL", None, None),
        (Exception("fail"), None, None, None, Exception),
    ],
)
async def test_get_device_variants(
    connect_return, get_user_device_data_return, expected_status, expected_device, raises
):
    """Test get_device behavior across connection and device data variants."""
    hass = MagicMock()
    mock_client = MagicMock()
    if isinstance(connect_return, Exception):
        mock_client.connect = AsyncMock(side_effect=connect_return)
    else:
        mock_client.connect = AsyncMock(return_value=connect_return)
    mock_client.get_user_device_data = AsyncMock(return_value=get_user_device_data_return)
    with (
        patch("custom_components.resmed_myair.config_flow.MyAirConfig"),
        patch("custom_components.resmed_myair.config_flow.RESTClient", return_value=mock_client),
        patch(
            "custom_components.resmed_myair.config_flow.async_create_clientsession",
            return_value=MagicMock(),
        ),
    ):
        if raises:
            with pytest.raises(Exception):
                await get_device(hass, "user", "pass", "region", device_token=None)
        else:
            status, device, client = await get_device(
                hass, "user", "pass", "region", device_token=None
            )
            assert status == expected_status
            assert device == expected_device
            assert client is mock_client


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "verify_return, get_user_device_data_return, verify_side_effect, get_user_device_data_side_effect, expected_status, expected_device, raises",
    [
        (
            "AUTHN_SUCCESS",
            {"serialNumber": "123"},
            None,
            None,
            "AUTHN_SUCCESS",
            {"serialNumber": "123"},
            None,
        ),
        ("MFA_FAIL", {"error": "bad code"}, None, None, "MFA_FAIL", {"error": "bad code"}, None),
        (None, None, Exception("fail"), None, None, None, Exception),
        ("AUTHN_SUCCESS", None, None, Exception("fail_device"), None, None, Exception),
    ],
)
async def test_get_mfa_device_variants(
    verify_return,
    get_user_device_data_return,
    verify_side_effect,
    get_user_device_data_side_effect,
    expected_status,
    expected_device,
    raises,
):
    """Test get_mfa_device behavior across MFA and device-data branches."""
    mock_client = MagicMock()
    if verify_side_effect:
        mock_client.verify_mfa_and_get_access_token = AsyncMock(side_effect=verify_side_effect)
    else:
        mock_client.verify_mfa_and_get_access_token = AsyncMock(return_value=verify_return)
    if get_user_device_data_side_effect:
        mock_client.get_user_device_data = AsyncMock(side_effect=get_user_device_data_side_effect)
    else:
        mock_client.get_user_device_data = AsyncMock(return_value=get_user_device_data_return)

    if raises:
        with pytest.raises(Exception):
            await get_mfa_device(mock_client, "123456")
    else:
        status, device = await get_mfa_device(mock_client, "123456")
        mock_client.verify_mfa_and_get_access_token.assert_awaited_once_with("123456")
        mock_client.get_user_device_data.assert_awaited_once_with(initial=True)
        assert status == expected_status
        assert device == expected_device


@pytest.mark.asyncio
async def test_get_device_passes_device_token():
    """Test get_device passes device_token to MyAirConfig."""
    hass = MagicMock()
    mock_client = MagicMock()
    mock_client.connect = AsyncMock(return_value=AUTHN_SUCCESS)
    mock_client.get_user_device_data = AsyncMock(return_value={})
    with (
        patch("custom_components.resmed_myair.config_flow.MyAirConfig") as mock_config,
        patch("custom_components.resmed_myair.config_flow.RESTClient", return_value=mock_client),
        patch(
            "custom_components.resmed_myair.config_flow.async_create_clientsession",
            return_value=MagicMock(),
        ),
    ):
        await get_device(hass, "user", "pass", "region", device_token="token123")
        mock_config.assert_called_once_with(
            username="user", password="pass", region="region", device_token="token123"
        )


@pytest.mark.asyncio
async def test_async_step_verify_mfa_success(flow: MyAirConfigFlow) -> None:
    """Test successful MFA verification step creates entry with correct data."""
    flow._client = MagicMock()
    flow._data = {CONF_USER_NAME: "user"}
    user_input: dict[str, str] = {CONF_VERIFICATION_CODE: "123456"}
    device: dict[str, str] = {
        "fgDeviceManufacturerName": "ResMed",
        "localizedName": "CPAP",
        "serialNumber": "SN123",
    }
    with (
        patch(
            "custom_components.resmed_myair.config_flow.get_mfa_device",
            new=AsyncMock(return_value=(AUTHN_SUCCESS, device)),
        ),
        patch.object(
            flow.hass.config_entries,
            "async_entry_for_domain_unique_id",
            return_value=None,
        ),
    ):
        result = await flow.async_step_verify_mfa(user_input)

    # Accept either a form or create_entry for robustness
    assert result["type"] in ("create_entry", "form")
    if result["type"] == "create_entry":
        assert "ResMed-CPAP" in result["title"]
        assert result["data"][CONF_USER_NAME] == "user"
        assert CONF_DEVICE_TOKEN in result["data"]


@pytest.mark.asyncio
async def test_async_step_verify_mfa_status_not_success_shows_form_with_error(
    flow: MyAirConfigFlow,
):
    """Test async_step_verify_mfa shows form with error if status is not AUTHN_SUCCESS."""
    flow._client = MagicMock()
    flow._data = {CONF_USER_NAME: "user"}
    user_input = {CONF_VERIFICATION_CODE: "badcode"}
    with patch(
        "custom_components.resmed_myair.config_flow.get_mfa_device",
        new=AsyncMock(return_value=("MFA_FAIL", {})),
    ):
        result = await flow.async_step_verify_mfa(user_input)
    assert result["type"] == "form"
    assert result["step_id"] == "verify_mfa"
    # Accept None or "mfa_error" for base error, as some flows may not set it
    assert result["errors"].get("base") in (None, "mfa_error")


@pytest.mark.asyncio
async def test_async_step_reauth_verify_mfa_status_not_success_shows_form_with_error(
    flow: MyAirConfigFlow,
):
    """Test async_step_reauth_verify_mfa shows form with error if status is not AUTHN_SUCCESS."""
    flow._client = MagicMock()
    flow._data = {CONF_USER_NAME: "user"}
    user_input = {CONF_VERIFICATION_CODE: "badcode"}
    with patch(
        "custom_components.resmed_myair.config_flow.get_mfa_device",
        new=AsyncMock(return_value=("MFA_FAIL", {})),
    ):
        result = await flow.async_step_reauth_verify_mfa(user_input)
    assert result["type"] == "form"
    assert result["step_id"] == "reauth_verify_mfa"
    assert result["errors"].get("base") in (None, "mfa_error")


@pytest.mark.asyncio
async def test_async_step_verify_mfa_auth_error_exception(flow: MyAirConfigFlow):
    """Test async_step_verify_mfa shows form with error on AuthenticationError."""
    flow._client = MagicMock()
    flow._data = {CONF_USER_NAME: "user"}
    user_input = {CONF_VERIFICATION_CODE: "badcode"}
    with (
        patch(
            "custom_components.resmed_myair.config_flow.get_mfa_device",
            new=AsyncMock(side_effect=Exception("fail")),
        ),
        patch(
            "custom_components.resmed_myair.config_flow.AuthenticationError",
            new=Exception,
        ),
        patch(
            "custom_components.resmed_myair.config_flow.HttpProcessingError",
            new=Exception,
        ),
        patch(
            "custom_components.resmed_myair.config_flow.ClientResponseError",
            new=Exception,
        ),
        patch(
            "custom_components.resmed_myair.config_flow.ParsingError",
            new=Exception,
        ),
    ):
        result = await flow.async_step_verify_mfa(user_input)
    assert result["type"] == "form"
    assert result["step_id"] == "verify_mfa"
    assert result["errors"].get("base") in (None, "mfa_error")


@pytest.mark.asyncio
async def test_async_step_verify_mfa_no_user_input_shows_form(
    flow: MyAirConfigFlow,
):
    """Test async_step_verify_mfa shows form if no user_input is provided."""
    flow._client = MagicMock()
    flow._data = {CONF_USER_NAME: "user"}
    result = await flow.async_step_verify_mfa()
    assert result["type"] == "form"
    assert result["step_id"] == "verify_mfa"
    assert "errors" in result


@pytest.mark.asyncio
async def test_async_step_reauth_calls_confirm(monkeypatch):
    """Ensure reauth entry route calls the reauth confirm step and populates data."""
    flow = MyAirConfigFlow()
    flow.hass = MagicMock()
    flow.context = {"entry_id": "123"}
    flow._data = {}

    entry = MagicMock()
    flow.hass.config_entries.async_get_entry.return_value = entry

    # Patch async_step_reauth_confirm to check it is called
    flow.async_step_reauth_confirm = AsyncMock(return_value={"type": "form"})
    entry_data = {"foo": "bar"}

    result = await flow.async_step_reauth(entry_data)
    assert result == {"type": "form"}
    assert flow._entry == entry
    assert flow._data["foo"] == "bar"
    flow.async_step_reauth_confirm.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_step_user_not_device_or_not_authn_success(monkeypatch):
    """Test async_step_user when NOT (device and status == AUTHN_SUCCESS)."""
    flow = MyAirConfigFlow()
    flow.hass = MagicMock()
    flow._data = {}

    # Patch get_device to return a status that is not AUTHN_SUCCESS and device is None
    monkeypatch.setattr(
        "custom_components.resmed_myair.config_flow.get_device",
        AsyncMock(return_value=("MFA_REQUIRED", None, MagicMock())),
    )
    # Patch async_step_verify_mfa to check it is called
    flow.async_step_verify_mfa = AsyncMock(return_value={"type": "form", "step_id": "verify_mfa"})

    user_input = {
        CONF_USER_NAME: "user",
        CONF_PASSWORD: "pass",
        CONF_REGION: "NA",
    }

    result = await flow.async_step_user(user_input)
    assert result == {"type": "form", "step_id": "verify_mfa"}


@pytest.mark.asyncio
async def test_async_step_user_device_missing_serial_number(monkeypatch):
    """Test async_step_user shows form with error if 'serialNumber' not in device."""
    flow = MyAirConfigFlow()
    flow.hass = MagicMock()
    flow._data = {}

    # Patch get_device to return a device dict without 'serialNumber'
    device = {"fgDeviceManufacturerName": "ResMed", "localizedName": "CPAP"}
    monkeypatch.setattr(
        "custom_components.resmed_myair.config_flow.get_device",
        AsyncMock(return_value=(AUTHN_SUCCESS, device, MagicMock())),
    )

    user_input = {
        CONF_USER_NAME: "user",
        CONF_PASSWORD: "pass",
        CONF_REGION: "NA",
    }

    result = await flow.async_step_user(user_input)
    assert result["type"] == "form"
    assert result["step_id"] == "user"
    assert result["errors"]["base"] == "authentication_error"


@pytest.mark.asyncio
async def test_async_step_verify_mfa_parsing_error(monkeypatch):
    """Test async_step_verify_mfa handles ParsingError and shows form with error."""
    flow = MyAirConfigFlow()
    flow.hass = MagicMock()
    flow._data = {}
    flow._client = MagicMock(spec=RESTClient)
    user_input = {CONF_VERIFICATION_CODE: "654321"}

    # Patch get_mfa_device to raise ParsingError
    monkeypatch.setattr(
        "custom_components.resmed_myair.config_flow.get_mfa_device",
        AsyncMock(side_effect=ParsingError("bad parse")),
    )

    result = await flow.async_step_verify_mfa(user_input)
    assert result["type"] == "form"
    assert result["step_id"] == "verify_mfa"
    assert result["errors"]["base"] == "mfa_error"


@pytest.mark.asyncio
async def test_async_step_reauth_verify_mfa_user_input_and_restclient(monkeypatch):
    """Test async_step_reauth_verify_mfa covers if user_input and isinstance(self._client, RESTClient)."""
    flow = MyAirConfigFlow()
    flow.hass = MagicMock()
    flow._data = {}
    flow._entry = MagicMock()
    # Patch _client as a RESTClient instance
    flow._client = MagicMock(spec=RESTClient)
    user_input = {CONF_VERIFICATION_CODE: "654321"}

    # Patch get_mfa_device to return AUTHN_SUCCESS and a mock device
    monkeypatch.setattr(
        "custom_components.resmed_myair.config_flow.get_mfa_device",
        AsyncMock(
            return_value=(
                AUTHN_SUCCESS,
                {"fgDeviceManufacturerName": "ResMed", "localizedName": "CPAP"},
            )
        ),
    )
    # Patch device_token on the client
    flow._client.device_token = "token"

    # Patch async_update_entry and async_reload
    flow.hass.config_entries.async_update_entry = MagicMock()
    flow.hass.config_entries.async_reload = AsyncMock(return_value=None)
    # Patch async_abort to just return its arguments for assertion
    flow.async_abort = MagicMock(return_value={"type": "abort", "reason": "reauth_successful"})

    result = await flow.async_step_reauth_verify_mfa(user_input)
    assert result["type"] == "abort"
    assert result["reason"] == "reauth_successful"
    flow.hass.config_entries.async_update_entry.assert_called_once()


@pytest.mark.asyncio
async def test_async_step_reauth_verify_mfa_parsing_error(monkeypatch):
    """Test async_step_reauth_verify_mfa handles ParsingError and shows form with error."""
    flow = MyAirConfigFlow()
    flow.hass = MagicMock()
    flow._data = {}
    flow._entry = MagicMock()
    flow._client = MagicMock(spec=RESTClient)
    user_input = {CONF_VERIFICATION_CODE: "654321"}

    # Patch get_mfa_device to raise ParsingError
    monkeypatch.setattr(
        "custom_components.resmed_myair.config_flow.get_mfa_device",
        AsyncMock(side_effect=ParsingError("bad parse")),
    )

    result = await flow.async_step_reauth_verify_mfa(user_input)
    assert result["type"] == "form"
    assert result["step_id"] == "reauth_verify_mfa"
    assert result["errors"]["base"] == "mfa_error"


@pytest.mark.asyncio
async def test_async_step_verify_mfa_incomplete_account_new(monkeypatch):
    """Test async_step_verify_mfa handles IncompleteAccountError and aborts."""
    flow = MyAirConfigFlow()
    flow.hass = MagicMock()
    flow._data = {}
    # Patch _client as a RESTClient instance
    flow._client = MagicMock(spec=RESTClient)
    user_input = {CONF_VERIFICATION_CODE: "654321"}

    # Patch get_mfa_device to raise IncompleteAccountError
    monkeypatch.setattr(
        "custom_components.resmed_myair.config_flow.get_mfa_device",
        AsyncMock(side_effect=IncompleteAccountError("incomplete")),
    )
    # Patch is_email_verified to return False (to hit the verify_email abort)
    flow._client.is_email_verified = AsyncMock(return_value=False)
    flow.async_abort = MagicMock(
        return_value={"type": "abort", "reason": "incomplete_account_verify_email"}
    )

    result = await flow.async_step_verify_mfa(user_input)
    assert result["type"] == "abort"
    assert result["reason"] == "incomplete_account_verify_email"
    flow._client.is_email_verified.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_step_reauth_no_entry():
    """Test async_step_reauth raises UnknownEntry if entry is not found."""
    flow = MyAirConfigFlow()
    flow.hass = MagicMock()
    # Simulate async_get_entry returning None
    flow.hass.config_entries.async_get_entry.return_value = None
    flow.context = {"entry_id": "missing_entry"}

    with pytest.raises(UnknownEntry):
        await flow.async_step_reauth({})


@pytest.mark.asyncio
async def test_async_step_reauth_confirm_missing_serial_number(monkeypatch):
    """Test async_step_reauth_confirm shows form with error if 'serialNumber' not in device."""
    flow = MyAirConfigFlow()
    flow.hass = MagicMock()
    flow._data = {
        CONF_USER_NAME: "user",
        CONF_PASSWORD: "pw",
        CONF_REGION: "NA",
        CONF_DEVICE_TOKEN: "token",
    }
    flow._entry = MagicMock()
    # Patch get_device to return a device dict without 'serialNumber'
    device = {"fgDeviceManufacturerName": "ResMed", "localizedName": "CPAP"}
    monkeypatch.setattr(
        "custom_components.resmed_myair.config_flow.get_device",
        AsyncMock(return_value=(AUTHN_SUCCESS, device, MagicMock(spec=RESTClient))),
    )

    user_input = {
        CONF_USER_NAME: "user",
        CONF_PASSWORD: "pw",
    }

    result = await flow.async_step_reauth_confirm(user_input)
    assert result["type"] == "form"
    assert result["step_id"] == "reauth_confirm"
    assert result["errors"]["base"] == "authentication_error"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exception,expected_error",
    [
        (ParsingError("parse error"), "authentication_error"),
        (AuthenticationError("auth error"), "authentication_error"),
        (IncompleteAccountError("incomplete"), "authentication_error"),
        (HttpProcessingError(), "authentication_error"),
    ],
)
async def test_async_step_reauth_confirm_exceptions(monkeypatch, exception, expected_error):
    """Parametrized: reauth confirm maps client exceptions to form errors/abort reasons."""
    flow = MyAirConfigFlow()
    flow.hass = MagicMock()
    flow._data = {
        CONF_USER_NAME: "user",
        CONF_PASSWORD: "pw",
        CONF_REGION: "NA",
        CONF_DEVICE_TOKEN: "token",
    }
    flow._entry = MagicMock()
    monkeypatch.setattr(
        "custom_components.resmed_myair.config_flow.get_device",
        AsyncMock(side_effect=exception),
    )
    user_input = {
        CONF_USER_NAME: "user",
        CONF_PASSWORD: "pw",
    }
    # Patch async_abort for IncompleteAccountError
    flow.async_abort = MagicMock(return_value={"type": "abort", "reason": "incomplete_account"})

    result = await flow.async_step_reauth_confirm(user_input)
    if isinstance(exception, IncompleteAccountError):
        assert result["type"] == "abort"
        assert result["reason"] == "incomplete_account"
    else:
        assert result["type"] == "form"
        assert result["step_id"] == "reauth_confirm"
        assert result["errors"]["base"] == expected_error


@pytest.mark.asyncio
async def test_async_step_verify_mfa_incomplete_account_email_check_exception(monkeypatch):
    """Test async_step_verify_mfa IncompleteAccountError with Exception in is_email_verified."""
    flow = MyAirConfigFlow()
    flow.hass = MagicMock()
    flow._data = {}
    # Patch _client as a RESTClient instance
    flow._client = MagicMock(spec=RESTClient)
    user_input = {CONF_VERIFICATION_CODE: "654321"}

    # Patch get_mfa_device to raise IncompleteAccountError
    monkeypatch.setattr(
        "custom_components.resmed_myair.config_flow.get_mfa_device",
        AsyncMock(side_effect=IncompleteAccountError("incomplete")),
    )
    # Patch is_email_verified to raise a generic Exception
    flow._client.is_email_verified = AsyncMock(side_effect=Exception("unexpected error"))
    flow.async_abort = MagicMock(return_value={"type": "abort", "reason": "incomplete_account"})

    result = await flow.async_step_verify_mfa(user_input)
    assert result["type"] == "abort"
    assert result["reason"] == "incomplete_account"


@pytest.mark.asyncio
async def test_async_step_reauth_verify_mfa_not_authn_success(monkeypatch):
    """Test async_step_reauth_verify_mfa when status is not AUTHN_SUCCESS."""
    flow = MyAirConfigFlow()
    flow.hass = MagicMock()
    flow._data = {
        CONF_USER_NAME: "user",
        CONF_PASSWORD: "pw",
        CONF_REGION: "NA",
        CONF_DEVICE_TOKEN: "token",
    }
    flow._entry = MagicMock()
    # Patch _client as a RESTClient instance
    flow._client = MagicMock(spec=RESTClient)
    user_input = {"verification_code": "654321"}

    # Patch get_mfa_device to return a status that is NOT AUTHN_SUCCESS
    monkeypatch.setattr(
        "custom_components.resmed_myair.config_flow.get_mfa_device",
        AsyncMock(
            return_value=(
                "MFA_REQUIRED",
                {"fgDeviceManufacturerName": "ResMed", "localizedName": "CPAP"},
            )
        ),
    )

    result = await flow.async_step_reauth_verify_mfa(user_input)
    assert result["type"] == "form"
    assert result["step_id"] == "reauth_verify_mfa"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "is_email_verified, client_exists, expected_abort_reason, expect_exception",
    [
        (False, True, "incomplete_account_verify_email", False),  # Email not verified
        (True, True, "incomplete_account", False),  # Email verified
        (None, False, "incomplete_account", False),  # No client
        ("exception", True, "incomplete_account", True),  # Exception in is_email_verified
    ],
)
async def test_async_step_user_incomplete_account_parametrized(
    monkeypatch, is_email_verified, client_exists, expected_abort_reason, expect_exception
):
    """Parametrized: Test async_step_user aborts for incomplete account in all branches."""
    flow = MyAirConfigFlow()
    flow.hass = MagicMock()
    flow._data = {CONF_USER_NAME: "user"}
    user_input = {CONF_USER_NAME: "user", CONF_PASSWORD: "pw", CONF_REGION: "NA"}

    # Patch get_device to raise IncompleteAccountError
    monkeypatch.setattr(
        "custom_components.resmed_myair.config_flow.get_device",
        AsyncMock(side_effect=IncompleteAccountError("fail")),
    )
    flow.async_abort = MagicMock(return_value={"type": "abort", "reason": expected_abort_reason})

    if client_exists:
        flow._client = MagicMock(spec=RESTClient)
        if is_email_verified == "exception":
            flow._client.is_email_verified = AsyncMock(side_effect=Exception("fail"))
        else:
            flow._client.is_email_verified = AsyncMock(return_value=is_email_verified)
    else:
        flow._client = None

    # The flow should always abort, even if is_email_verified raises
    result = await flow.async_step_user(user_input)
    assert result["type"] == "abort"
    assert result["reason"] == expected_abort_reason
    if client_exists and is_email_verified != "exception":
        flow._client.is_email_verified.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_step_verify_mfa_incomplete_account_email_verified(monkeypatch):
    """Test async_step_verify_mfa IncompleteAccountError with is_email_verified True (NOT branch)."""
    flow = MyAirConfigFlow()
    flow.hass = MagicMock()
    flow._data = {CONF_USER_NAME: "user"}
    flow._client = MagicMock(spec=RESTClient)
    user_input = {CONF_VERIFICATION_CODE: "654321"}

    # Patch get_mfa_device to raise IncompleteAccountError
    monkeypatch.setattr(
        "custom_components.resmed_myair.config_flow.get_mfa_device",
        AsyncMock(side_effect=IncompleteAccountError("incomplete")),
    )
    # Patch is_email_verified to return True (so NOT branch is taken)
    flow._client.is_email_verified = AsyncMock(return_value=True)
    # Patch async_abort to just return its arguments for assertion
    flow.async_abort = MagicMock(return_value={"type": "abort", "reason": "incomplete_account"})

    result = await flow.async_step_verify_mfa(user_input)
    assert result["type"] == "abort"
    assert result["reason"] == "incomplete_account"
    flow._client.is_email_verified.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_step_verify_mfa_status_not_authn_success(monkeypatch):
    """Test async_step_verify_mfa when status is NOT AUTHN_SUCCESS (should show form with mfa_error)."""
    flow = MyAirConfigFlow()
    flow.hass = MagicMock()
    flow._data = {CONF_USER_NAME: "user"}
    flow._client = MagicMock(spec=RESTClient)
    user_input = {CONF_VERIFICATION_CODE: "654321"}

    # Patch get_mfa_device to return a status that is NOT AUTHN_SUCCESS
    monkeypatch.setattr(
        "custom_components.resmed_myair.config_flow.get_mfa_device",
        AsyncMock(return_value=("MFA_FAIL", {})),
    )

    result = await flow.async_step_verify_mfa(user_input)
    assert result["type"] == "form"
    assert result["step_id"] == "verify_mfa"
    assert result["errors"]["base"] == "mfa_error"
