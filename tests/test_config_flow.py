"""Tests for the integration config flow behavior and edge cases."""

from unittest.mock import AsyncMock, MagicMock

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
    flow.context = {}
    return flow


@pytest.mark.asyncio
async def test_async_step_user_success(flow: MyAirConfigFlow, myair_client, monkeypatch) -> None:
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
    # Patch get_device to return a successful auth and device
    monkeypatch.setattr(
        config_flow,
        "get_device",
        AsyncMock(return_value=(AUTHN_SUCCESS, device, myair_client)),
    )
    # Ensure domain-unique-id lookup returns no existing entry for this test
    flow.hass.config_entries.async_entry_for_domain_unique_id = MagicMock(return_value=None)
    result = await flow.async_step_user(user_input)
    assert result["type"] == "create_entry"
    assert "ResMed-CPAP" in result["title"]
    assert result["data"][CONF_USER_NAME] == "user"


@pytest.mark.asyncio
async def test_async_step_user_auth_error(flow: MyAirConfigFlow, monkeypatch) -> None:
    """Test user step with authentication error."""
    user_input: dict[str, str] = {
        CONF_USER_NAME: "user",
        CONF_PASSWORD: "badpass",
        CONF_REGION: REGION_NA,
    }
    monkeypatch.setattr(
        config_flow,
        "get_device",
        AsyncMock(side_effect=AuthenticationError("fail")),
    )
    result = await flow.async_step_user(user_input)

    assert result["type"] == "form"
    assert result["errors"]["base"] == "authentication_error"


@pytest.mark.asyncio
async def test_async_step_verify_mfa_user_input_and_client(monkeypatch, hass, myair_client):
    """Verify MFA step with valid user input leads to create_entry."""
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow._data = {}
    flow._client = myair_client
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
    # Ensure device_token from client is persisted
    _, kwargs = flow.async_create_entry.call_args
    assert kwargs["data"][CONF_DEVICE_TOKEN] == "token"


@pytest.mark.asyncio
@pytest.mark.parametrize("is_restclient", [True, False])
async def test_async_step_verify_mfa_error(
    flow: MyAirConfigFlow, myair_client: RESTClient, monkeypatch, is_restclient: bool
) -> None:
    """Test MFA verification step with error for RESTClient and non-RESTClient clients."""
    # Use a real RESTClient instance for one case, and a non-spec MagicMock for the other
    flow._client = myair_client if is_restclient else MagicMock()
    flow._data = {CONF_USER_NAME: "user"}
    user_input: dict[str, str] = {CONF_VERIFICATION_CODE: "bad"}
    monkeypatch.setattr(
        config_flow,
        "get_mfa_device",
        AsyncMock(side_effect=AuthenticationError("fail")),
    )
    result = await flow.async_step_verify_mfa(user_input)
    assert result["type"] == "form"
    assert "errors" in result
    # RESTClient path should set a specific 'base' error; non-RESTClient may only return a generic errors dict
    if is_restclient:
        assert result["errors"].get("base") == "mfa_error"
    else:
        assert "base" not in result["errors"]


@pytest.mark.asyncio
async def test_async_step_user_form_display(flow: MyAirConfigFlow) -> None:
    """Test that the user form is shown when no input is provided."""
    result = await flow.async_step_user()
    assert result["type"] == "form"
    assert result["step_id"] == "user"
    assert "errors" in result


@pytest.mark.asyncio
async def test_async_step_verify_mfa_form_display(flow: MyAirConfigFlow, myair_client) -> None:
    """Test that the MFA form is shown when no input is provided."""
    flow._client = myair_client
    flow._data = {CONF_USER_NAME: "user"}
    result = await flow.async_step_verify_mfa()
    assert result["type"] == "form"
    assert result["step_id"] == "verify_mfa"
    assert "errors" in result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "step_name,pre_setup,expected_step_id",
    [
        ("async_step_user", False, "user"),
        ("async_step_verify_mfa", True, "verify_mfa"),
    ],
)
async def test_async_step_forms_display_parametrized(
    flow: MyAirConfigFlow, step_name: str, pre_setup: bool, expected_step_id: str, myair_client
) -> None:
    """Parametrized: form display checks for multiple steps."""
    if pre_setup:
        flow._client = myair_client
        flow._data = {CONF_USER_NAME: "user"}

    result = await getattr(flow, step_name)()
    assert result["type"] == "form"
    assert result["step_id"] == expected_step_id
    assert "errors" in result


@pytest.mark.asyncio
async def test_async_step_verify_mfa_incomplete_account(
    flow: MyAirConfigFlow, myair_client, monkeypatch
) -> None:
    """Test MFA step aborts if account is incomplete."""
    flow._client = myair_client
    flow._data = {CONF_USER_NAME: "user"}
    user_input: dict[str, str] = {CONF_VERIFICATION_CODE: "123456"}
    # Simulate IncompleteAccountError and email not verified
    flow._client.is_email_verified = AsyncMock(return_value=False)
    monkeypatch.setattr(
        config_flow,
        "get_mfa_device",
        AsyncMock(side_effect=IncompleteAccountError("account incomplete")),
    )
    result = await flow.async_step_verify_mfa(user_input)
    assert result["type"] == "abort"
    assert result["reason"] == "incomplete_account_verify_email"


@pytest.mark.asyncio
async def test_async_step_reauth_confirm_form_display(flow: MyAirConfigFlow) -> None:
    """Test that the reauth confirm form is shown when no input is provided."""
    flow._data = {CONF_USER_NAME: "user", CONF_PASSWORD: "pass"}
    result = await flow.async_step_reauth_confirm()
    assert result["type"] == "form"
    assert result["step_id"] == "reauth_confirm"
    assert "errors" in result


@pytest.mark.asyncio
async def test_async_step_reauth_verify_mfa_form_display(
    flow: MyAirConfigFlow, myair_client
) -> None:
    """Test that the reauth verify MFA form is shown when no input is provided."""
    flow._client = myair_client
    flow._data = {CONF_USER_NAME: "user"}
    result = await flow.async_step_reauth_verify_mfa()
    assert result["type"] == "form"
    assert result["step_id"] == "reauth_verify_mfa"
    assert "errors" in result


@pytest.mark.asyncio
async def test_async_step_reauth_success(
    flow: MyAirConfigFlow, config_entry: MockConfigEntry, myair_client, monkeypatch
) -> None:
    """Test reauth step completes successfully."""
    flow._data = {CONF_USER_NAME: "user", CONF_PASSWORD: "pass", CONF_REGION: REGION_NA}
    device = {
        "serialNumber": "SN123",
        "fgDeviceManufacturerName": "ResMed",
        "localizedName": "CPAP",
    }
    flow._entry = config_entry
    monkeypatch.setattr(
        config_flow,
        "get_device",
        AsyncMock(return_value=(AUTHN_SUCCESS, device, myair_client)),
    )
    # Ensure the client reports a deterministic device token that should be persisted
    myair_client.device_token = "device_token_abc"
    result = await flow.async_step_reauth_confirm({CONF_USER_NAME: "user", CONF_PASSWORD: "pass"})
    assert result["type"] == "abort"
    assert result["reason"] == "reauth_successful"
    mock_update = flow.hass.config_entries.async_update_entry
    assert isinstance(mock_update, MagicMock)
    mock_update.assert_called_once()
    # Device token should be written to entry data
    _, kwargs = mock_update.call_args
    assert CONF_DEVICE_TOKEN in kwargs["data"]
    assert kwargs["data"][CONF_DEVICE_TOKEN] == "device_token_abc"


@pytest.mark.asyncio
async def test_async_step_reauth_confirm_mfa(
    flow: MyAirConfigFlow, config_entry: MockConfigEntry, monkeypatch
) -> None:
    """Test reauth confirm step triggers MFA if needed."""
    flow._data = {CONF_USER_NAME: "user", CONF_PASSWORD: "pass", CONF_REGION: REGION_NA}
    flow._entry = config_entry
    monkeypatch.setattr(
        config_flow,
        "get_device",
        AsyncMock(return_value=("MFA_REQUIRED", None, MagicMock(spec=RESTClient))),
    )
    result = await flow.async_step_reauth_confirm({CONF_USER_NAME: "user", CONF_PASSWORD: "pass"})
    assert result["type"] == "form"
    assert result["step_id"] == "reauth_verify_mfa"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "step_name,is_email_verified,client_exists,expected_abort_reason,no_client_shows_form",
    [
        # reauth_confirm: always aborts
        ("async_step_reauth_confirm", False, True, "incomplete_account_verify_email", False),
        ("async_step_reauth_confirm", True, True, "incomplete_account", False),
        ("async_step_reauth_confirm", None, False, "incomplete_account", False),
        ("async_step_reauth_confirm", "exception", True, "incomplete_account", False),
        # reauth_verify_mfa: if no client, shows form instead of abort
        ("async_step_reauth_verify_mfa", False, True, "incomplete_account_verify_email", True),
        ("async_step_reauth_verify_mfa", True, True, "incomplete_account", True),
        ("async_step_reauth_verify_mfa", None, False, "incomplete_account", True),
        ("async_step_reauth_verify_mfa", "exception", True, "incomplete_account", True),
    ],
)
async def test_async_step_reauth_incomplete_account_parametrized(
    monkeypatch,
    step_name,
    is_email_verified,
    client_exists,
    expected_abort_reason,
    no_client_shows_form,
    hass,
    config_entry: MockConfigEntry,
    myair_client,
):
    """Parametrized test covering incomplete-account behavior for reauth steps.

    Depending on the step, the flow uses either `get_device` or `get_mfa_device`.
    This single test exercises both `async_step_reauth_confirm` and
    `async_step_reauth_verify_mfa` branches with the combinations used
    previously in two separate tests.
    """
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow._data = {CONF_USER_NAME: "user", CONF_PASSWORD: "pass", CONF_REGION: REGION_NA}
    flow._entry = config_entry

    # Choose which helper to patch based on the step
    if step_name == "async_step_reauth_confirm":
        # reauth_confirm takes a username/password input
        user_input = {CONF_USER_NAME: "user", CONF_PASSWORD: "pass"}
        monkeypatch.setattr(
            "custom_components.resmed_myair.config_flow.get_device",
            AsyncMock(side_effect=IncompleteAccountError("incomplete")),
        )
    else:
        # reauth_verify_mfa takes a verification code
        user_input = {CONF_VERIFICATION_CODE: "654321"}
        monkeypatch.setattr(
            "custom_components.resmed_myair.config_flow.get_mfa_device",
            AsyncMock(side_effect=IncompleteAccountError("incomplete")),
        )

    flow.async_abort = MagicMock(return_value={"type": "abort", "reason": expected_abort_reason})

    if client_exists:
        flow._client = myair_client
        if is_email_verified == "exception":
            flow._client.is_email_verified = AsyncMock(side_effect=Exception("fail"))
        else:
            flow._client.is_email_verified = AsyncMock(return_value=is_email_verified)
    else:
        flow._client = None

    result = await getattr(flow, step_name)(user_input)

    # Determine expectation: for verify_mfa, no-client shows form; for confirm, always abort
    if not client_exists and no_client_shows_form:
        assert result["type"] == "form"
        assert result["step_id"] == (
            "reauth_verify_mfa" if step_name == "async_step_reauth_verify_mfa" else "reauth_confirm"
        )
    else:
        assert result["type"] == "abort"
        assert result["reason"] == expected_abort_reason

    if client_exists and is_email_verified != "exception":
        flow._client.is_email_verified.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_step_reauth_verify_mfa_success(
    flow: MyAirConfigFlow, config_entry: MockConfigEntry, myair_client: MagicMock, monkeypatch
) -> None:
    """Test reauth verify MFA step completes successfully."""
    flow._client = myair_client
    flow._data = {CONF_USER_NAME: "user", CONF_PASSWORD: "pass"}
    flow._entry = config_entry
    monkeypatch.setattr(
        config_flow,
        "get_mfa_device",
        AsyncMock(
            return_value=(
                AUTHN_SUCCESS,
                {"fgDeviceManufacturerName": "ResMed", "localizedName": "CPAP"},
            )
        ),
    )
    result = await flow.async_step_reauth_verify_mfa({CONF_VERIFICATION_CODE: "123456"})
    assert result["type"] == "abort"
    assert result["reason"] == "reauth_successful"
    mock_update = flow.hass.config_entries.async_update_entry
    assert isinstance(mock_update, MagicMock)
    mock_update.assert_called_once()


@pytest.mark.asyncio
async def test_async_step_reauth_verify_mfa_error(
    flow: MyAirConfigFlow, config_entry: MockConfigEntry, myair_client: MagicMock, monkeypatch
) -> None:
    """Test reauth verify MFA step with error."""
    flow._client = myair_client
    flow._data = {CONF_USER_NAME: "user", CONF_PASSWORD: "pass"}
    flow._entry = config_entry
    monkeypatch.setattr(
        config_flow,
        "get_mfa_device",
        AsyncMock(side_effect=AuthenticationError("fail")),
    )
    result = await flow.async_step_reauth_verify_mfa({CONF_VERIFICATION_CODE: "bad"})
    assert result["type"] == "form"
    assert result["step_id"] == "reauth_verify_mfa"
    assert "errors" in result
    assert result["errors"]["base"] == "mfa_error"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "is_email_verified, client_exists, expected_abort_reason",
    [
        (False, True, "incomplete_account_verify_email"),  # Email not verified
        (True, True, "incomplete_account"),  # Email verified
        (None, False, "incomplete_account"),  # No client
        (
            "exception",
            True,
            "incomplete_account",
        ),  # Exception in is_email_verified (should abort, not raise)
    ],
)
async def test_async_step_reauth_verify_mfa_incomplete_account_parametrized(
    monkeypatch,
    is_email_verified,
    client_exists,
    expected_abort_reason,
    hass,
    config_entry: MockConfigEntry,
    myair_client,
):
    """Parametrized: Test async_step_reauth_verify_mfa aborts or shows form for incomplete account in all branches."""
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow._data = {
        CONF_USER_NAME: "user",
        CONF_PASSWORD: "pw",
        CONF_REGION: REGION_NA,
    }
    flow._entry = config_entry
    user_input = {CONF_VERIFICATION_CODE: "654321"}

    # Patch get_mfa_device to raise IncompleteAccountError
    monkeypatch.setattr(
        "custom_components.resmed_myair.config_flow.get_mfa_device",
        AsyncMock(side_effect=IncompleteAccountError("incomplete")),
    )
    flow.async_abort = MagicMock(return_value={"type": "abort", "reason": expected_abort_reason})

    if client_exists:
        flow._client = myair_client
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
    connect_return,
    get_user_device_data_return,
    expected_status,
    expected_device,
    raises,
    hass,
    session,
    myair_client,
    monkeypatch,
):
    """Test get_device behavior across connection and device data variants."""
    mock_client = myair_client
    if isinstance(connect_return, Exception):
        mock_client.connect = AsyncMock(side_effect=connect_return)
    else:
        mock_client.connect = AsyncMock(return_value=connect_return)
    mock_client.get_user_device_data = AsyncMock(return_value=get_user_device_data_return)
    # Patch module-level collaborators using monkeypatch
    monkeypatch.setattr(config_flow, "MyAirConfig", MagicMock())
    monkeypatch.setattr(config_flow, "RESTClient", lambda *a, **k: mock_client)
    monkeypatch.setattr(config_flow, "async_create_clientsession", lambda *a, **k: session)

    if raises:
        with pytest.raises(Exception):
            await get_device(hass, "user", "pass", "region", device_token=None)
    else:
        status, device, client = await get_device(hass, "user", "pass", "region", device_token=None)
        assert status == expected_status
        assert device == expected_device
        assert client is mock_client


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "verify_return, get_user_device_data_return, verify_side_effect, get_user_device_data_side_effect, expected_status, expected_device, raises",
    [
        (
            AUTHN_SUCCESS,
            {"serialNumber": "123"},
            None,
            None,
            AUTHN_SUCCESS,
            {"serialNumber": "123"},
            None,
        ),
        ("MFA_FAIL", {"error": "bad code"}, None, None, "MFA_FAIL", {"error": "bad code"}, None),
        (None, None, Exception("fail"), None, None, None, Exception),
        (AUTHN_SUCCESS, None, None, Exception("fail_device"), None, None, Exception),
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
    myair_client,
):
    """Test get_mfa_device behavior across MFA and device-data branches."""
    mock_client = myair_client
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
async def test_get_device_passes_device_token(hass, myair_client, monkeypatch):
    """Test get_device passes device_token to MyAirConfig."""
    mock_client = myair_client
    mock_client.connect = AsyncMock(return_value=AUTHN_SUCCESS)
    mock_client.get_user_device_data = AsyncMock(return_value={})
    mock_config = MagicMock()
    monkeypatch.setattr(config_flow, "MyAirConfig", mock_config)
    monkeypatch.setattr(config_flow, "RESTClient", lambda *a, **k: mock_client)
    monkeypatch.setattr(config_flow, "async_create_clientsession", lambda *a, **k: MagicMock())

    await get_device(hass, "user", "pass", "region", device_token="token123")
    mock_config.assert_called_once_with(
        username="user", password="pass", region="region", device_token="token123"
    )


@pytest.mark.asyncio
async def test_async_step_verify_mfa_success(
    flow: MyAirConfigFlow, myair_client: RESTClient, monkeypatch
) -> None:
    """Test successful MFA verification step creates entry with correct data."""
    flow._client = myair_client
    flow._data = {CONF_USER_NAME: "user"}
    user_input: dict[str, str] = {CONF_VERIFICATION_CODE: "123456"}
    device: dict[str, str] = {
        "fgDeviceManufacturerName": "ResMed",
        "localizedName": "CPAP",
        "serialNumber": "SN123",
    }
    monkeypatch.setattr(
        config_flow,
        "get_mfa_device",
        AsyncMock(return_value=(AUTHN_SUCCESS, device)),
    )
    result = await flow.async_step_verify_mfa(user_input)

    # Expect create_entry for the RESTClient successful MFA path
    assert result["type"] == "create_entry"
    assert "ResMed-CPAP" in result["title"]
    assert result["data"][CONF_USER_NAME] == "user"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "step_name,expected_step_id",
    [
        ("async_step_verify_mfa", "verify_mfa"),
        ("async_step_reauth_verify_mfa", "reauth_verify_mfa"),
    ],
)
async def test_async_step_verify_mfa_status_variants(
    flow: MyAirConfigFlow, step_name: str, expected_step_id: str, myair_client, monkeypatch
) -> None:
    """Parametrized: verify that when MFA status is not AUTHN_SUCCESS the flow shows the correct form and error."""
    flow._client = myair_client
    flow._data = {CONF_USER_NAME: "user"}
    user_input = {CONF_VERIFICATION_CODE: "badcode"}
    monkeypatch.setattr(
        config_flow,
        "get_mfa_device",
        AsyncMock(return_value=("MFA_FAIL", {})),
    )
    result = await getattr(flow, step_name)(user_input)

    assert result["type"] == "form"
    assert result["step_id"] == expected_step_id
    # Require explicit mfa_error for non-success MFA status to avoid masking regressions
    assert "base" in result["errors"]
    assert result["errors"]["base"] == "mfa_error"


@pytest.mark.asyncio
async def test_async_step_verify_mfa_auth_error_exception(
    flow: MyAirConfigFlow, myair_client: RESTClient, monkeypatch
):
    """Test async_step_verify_mfa shows form with error on AuthenticationError."""
    flow._client = myair_client
    flow._data = {CONF_USER_NAME: "user"}
    user_input = {CONF_VERIFICATION_CODE: "badcode"}
    monkeypatch.setattr(
        config_flow,
        "get_mfa_device",
        AsyncMock(side_effect=AuthenticationError("fail")),
    )
    result = await flow.async_step_verify_mfa(user_input)

    assert result["type"] == "form"
    assert result["step_id"] == "verify_mfa"
    assert result["errors"]["base"] == "mfa_error"


@pytest.mark.asyncio
async def test_async_step_verify_mfa_no_user_input_shows_form(
    flow: MyAirConfigFlow,
):
    """Test async_step_verify_mfa shows form if no user_input is provided."""
    # Intentionally use a non-spec MagicMock here so the flow treats the
    # client as NOT an instance of RESTClient (forces the non-RESTClient path).
    flow._client = MagicMock()
    flow._data = {CONF_USER_NAME: "user"}
    result = await flow.async_step_verify_mfa()
    assert result["type"] == "form"
    assert result["step_id"] == "verify_mfa"
    assert "errors" in result


@pytest.mark.asyncio
async def test_async_step_reauth_calls_confirm(hass, config_entry: MockConfigEntry):
    """Ensure reauth entry route calls the reauth confirm step and populates data."""
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow.context = {"entry_id": "123"}
    flow._data = {}
    # Ensure the entry lookup returns the expected entry
    flow.hass.config_entries.async_get_entry = MagicMock(return_value=config_entry)

    # Patch async_step_reauth_confirm to check it is called
    flow.async_step_reauth_confirm = AsyncMock(return_value={"type": "form"})
    entry_data = {"foo": "bar"}

    result = await flow.async_step_reauth(entry_data)
    assert result == {"type": "form"}
    assert flow._entry == config_entry
    assert flow._data["foo"] == "bar"
    flow.async_step_reauth_confirm.assert_awaited_once()
    flow.hass.config_entries.async_get_entry.assert_called_once_with("123")


@pytest.mark.asyncio
async def test_async_step_user_not_device_or_not_authn_success(monkeypatch, hass):
    """Test async_step_user when NOT (device and status == AUTHN_SUCCESS)."""
    flow = MyAirConfigFlow()
    flow.hass = hass
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
        CONF_REGION: REGION_NA,
    }

    result = await flow.async_step_user(user_input)
    assert result == {"type": "form", "step_id": "verify_mfa"}
    flow.async_step_verify_mfa.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_step_user_device_missing_serial_number(monkeypatch, hass):
    """Test async_step_user shows form with error if 'serialNumber' not in device."""
    flow = MyAirConfigFlow()
    flow.hass = hass
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
        CONF_REGION: REGION_NA,
    }

    result = await flow.async_step_user(user_input)
    assert result["type"] == "form"
    assert result["step_id"] == "user"
    assert result["errors"]["base"] == "authentication_error"


@pytest.mark.asyncio
async def test_async_step_verify_mfa_parsing_error(monkeypatch, hass, myair_client):
    """Test async_step_verify_mfa handles ParsingError and shows form with error."""
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow._data = {}
    flow._client = myair_client
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
async def test_async_step_reauth_verify_mfa_user_input_and_restclient(
    monkeypatch, hass, config_entry: MockConfigEntry, myair_client: MagicMock
):
    """Test async_step_reauth_verify_mfa covers if user_input and isinstance(self._client, RESTClient)."""
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow._data = {}
    flow._entry = config_entry
    flow._client = myair_client
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
    # Patch device_token() on the client to return a token
    flow._client.device_token.return_value = "token"

    # Patch async_abort to just return its arguments for assertion
    flow.async_abort = MagicMock(return_value={"type": "abort", "reason": "reauth_successful"})

    result = await flow.async_step_reauth_verify_mfa(user_input)
    assert result["type"] == "abort"
    assert result["reason"] == "reauth_successful"
    flow.hass.config_entries.async_update_entry.assert_called_once()  # type: ignore[attr-defined]
    # Ensure device_token persisted to entry data
    _, kwargs = flow.hass.config_entries.async_update_entry.call_args  # type: ignore[attr-defined]
    assert CONF_DEVICE_TOKEN in kwargs["data"]


@pytest.mark.asyncio
async def test_async_step_reauth_verify_mfa_parsing_error(
    monkeypatch, hass, config_entry: MockConfigEntry, myair_client: MagicMock
):
    """Test async_step_reauth_verify_mfa handles ParsingError and shows form with error."""
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow._data = {}
    flow._entry = config_entry
    flow._client = myair_client
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
async def test_async_step_verify_mfa_incomplete_account_new(
    monkeypatch, hass, myair_client: MagicMock
):
    """Test async_step_verify_mfa handles IncompleteAccountError and aborts."""
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow._data = {}
    flow._client = myair_client
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
async def test_async_step_reauth_no_entry(hass):
    """Test async_step_reauth raises UnknownEntry if entry is not found."""
    flow = MyAirConfigFlow()
    flow.hass = hass
    # Simulate async_get_entry returning None
    flow.hass.config_entries.async_get_entry.return_value = None
    flow.context = {"entry_id": "missing_entry"}

    with pytest.raises(UnknownEntry):
        await flow.async_step_reauth({})
    flow.hass.config_entries.async_get_entry.assert_called_once_with("missing_entry")


@pytest.mark.asyncio
async def test_async_step_reauth_confirm_missing_serial_number(
    monkeypatch, hass, config_entry: MockConfigEntry
):
    """Test async_step_reauth_confirm shows form with error if 'serialNumber' not in device."""
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow._data = {
        CONF_USER_NAME: "user",
        CONF_PASSWORD: "pw",
        CONF_REGION: REGION_NA,
        CONF_DEVICE_TOKEN: "token",
    }
    flow._entry = config_entry
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
async def test_async_step_reauth_confirm_exceptions(
    monkeypatch, exception, expected_error, hass, config_entry: MockConfigEntry
):
    """Parametrized: reauth confirm maps client exceptions to form errors/abort reasons."""
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow._data = {
        CONF_PASSWORD: "pw",
        CONF_REGION: REGION_NA,
        CONF_DEVICE_TOKEN: "token",
    }
    flow._entry = config_entry
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
async def test_async_step_verify_mfa_incomplete_account_email_check_exception(
    monkeypatch, hass, myair_client: MagicMock
):
    """Test async_step_verify_mfa IncompleteAccountError with Exception in is_email_verified."""
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow._data = {}
    flow._client = myair_client
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
@pytest.mark.parametrize(
    "is_email_verified, client_exists, expected_abort_reason",
    [
        (False, True, "incomplete_account_verify_email"),  # Email not verified
        (True, True, "incomplete_account"),  # Email verified
        (None, False, "incomplete_account"),  # No client
        ("exception", True, "incomplete_account"),  # Exception in is_email_verified
    ],
)
async def test_async_step_user_incomplete_account_parametrized(
    monkeypatch,
    is_email_verified,
    client_exists,
    expected_abort_reason,
    hass,
    myair_client,
):
    """Parametrized: Test async_step_user aborts for incomplete account in all branches."""
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow._data = {CONF_USER_NAME: "user"}
    user_input = {CONF_USER_NAME: "user", CONF_PASSWORD: "pw", CONF_REGION: REGION_NA}

    # Patch get_device to raise IncompleteAccountError
    monkeypatch.setattr(
        "custom_components.resmed_myair.config_flow.get_device",
        AsyncMock(side_effect=IncompleteAccountError("fail")),
    )
    flow.async_abort = MagicMock(return_value={"type": "abort", "reason": expected_abort_reason})

    if client_exists:
        flow._client = myair_client
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
async def test_async_step_verify_mfa_incomplete_account_email_verified(
    monkeypatch, hass, myair_client
):
    """Test async_step_verify_mfa IncompleteAccountError with is_email_verified True (NOT branch)."""
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow._data = {CONF_USER_NAME: "user"}
    flow._client = myair_client
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
async def test_async_step_verify_mfa_status_not_authn_success(monkeypatch, hass, myair_client):
    """Test async_step_verify_mfa when status is NOT AUTHN_SUCCESS (should show form with mfa_error)."""
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow._data = {CONF_USER_NAME: "user"}
    flow._client = myair_client
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
