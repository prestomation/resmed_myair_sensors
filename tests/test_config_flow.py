"""Config-flow tests that protect setup, MFA, and reauth state transitions."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from aiohttp import ClientError
from homeassistant.config_entries import UnknownEntry
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
from custom_components.resmed_myair.models import MyAirDevice

REPO_ROOT = Path(__file__).resolve().parents[1]
TRANSLATION_LANGUAGES = ("en", "fr")
CONFIG_FLOW_ABORT_REASONS = (
    "already_configured",
    "incomplete_account",
    "incomplete_account_verify_email",
    "reauth_successful",
    "wrong_account",
)


@pytest.fixture
def flow(hass: MagicMock) -> MyAirConfigFlow:
    """Return a configured `MyAirConfigFlow` bound to the test Home Assistant."""
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow.context = {}
    return flow


@pytest.mark.parametrize("language", TRANSLATION_LANGUAGES)
def test_config_flow_abort_reasons_have_translations(language: str) -> None:
    """All config-flow abort reasons have localized strings."""
    translation_path = (
        REPO_ROOT / "custom_components/resmed_myair/translations" / f"{language}.json"
    )
    abort_translations = json.loads(translation_path.read_text())["config"]["abort"]

    for reason in CONFIG_FLOW_ABORT_REASONS:
        assert abort_translations[reason]


@pytest.mark.asyncio
async def test_async_step_user_success(
    flow: MyAirConfigFlow, myair_client: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A successful user step creates an entry with the discovered device."""
    user_input: dict[str, str] = {
        CONF_USER_NAME: "user",
        CONF_PASSWORD: "pass",
        CONF_REGION: REGION_NA,
    }
    device = MyAirDevice.from_api(
        {
            "serialNumber": "SN123",
            "fgDeviceManufacturerName": "ResMed",
            "localizedName": "CPAP",
        }
    )
    monkeypatch.setattr(
        config_flow,
        "get_device",
        AsyncMock(return_value=(AUTHN_SUCCESS, device, myair_client)),
    )
    flow.hass.config_entries.async_entry_for_domain_unique_id = MagicMock(return_value=None)
    result = await flow.async_step_user(user_input)
    assert result["type"] == "create_entry"
    assert "ResMed-CPAP" in result["title"]
    assert result["data"][CONF_USER_NAME] == "user"


@pytest.mark.asyncio
async def test_async_step_user_auth_error(
    flow: MyAirConfigFlow, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Authentication failures keep the user step on the form with an error."""
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
@pytest.mark.parametrize("is_restclient", [True, False])
async def test_async_step_verify_mfa_error(
    flow: MyAirConfigFlow,
    myair_client: RESTClient,
    monkeypatch: pytest.MonkeyPatch,
    is_restclient: bool,
) -> None:
    """MFA failures map to the correct form error for client types."""
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
        assert result["step_id"] == "verify_mfa"
    else:
        assert "base" not in result["errors"]
        assert result["step_id"] == "verify_mfa"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("step_name", "pre_setup", "expected_step_id"),
    [
        ("async_step_user", False, "user"),
        ("async_step_verify_mfa", True, "verify_mfa"),
        ("async_step_reauth_confirm", True, "reauth_confirm"),
        ("async_step_reauth_verify_mfa", True, "reauth_verify_mfa"),
    ],
)
async def test_async_step_forms_display_parametrized(
    flow: MyAirConfigFlow,
    step_name: str,
    pre_setup: bool,
    expected_step_id: str,
    myair_client: MagicMock,
) -> None:
    """User and MFA steps both render their forms when called without input."""
    if pre_setup:
        flow._client = myair_client
        flow._data = {CONF_USER_NAME: "user", CONF_PASSWORD: "pass"}

    result = await getattr(flow, step_name)()
    assert result["type"] == "form"
    assert result["step_id"] == expected_step_id
    assert "errors" in result


@pytest.mark.asyncio
async def test_async_step_reauth_success(
    flow: MyAirConfigFlow,
    myair_client: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Successful reauth updates the stored credentials and completes."""
    config_entry = MockConfigEntry(
        domain="resmed_myair",
        title="ResMed-CPAP",
        data={CONF_USER_NAME: "user", CONF_PASSWORD: "pass", CONF_REGION: REGION_NA},
        entry_id="mock_entry_id",
        unique_id="SN123",
        version=2,
    )
    flow._data = {CONF_USER_NAME: "user", CONF_PASSWORD: "pass", CONF_REGION: REGION_NA}
    device = MyAirDevice.from_api(
        {
            "serialNumber": "SN123",
            "fgDeviceManufacturerName": "ResMed",
            "localizedName": "CPAP",
        }
    )
    flow._entry = config_entry
    monkeypatch.setattr(
        config_flow,
        "get_device",
        AsyncMock(return_value=(AUTHN_SUCCESS, device, myair_client)),
    )
    myair_client.device_token = "device_token_abc"
    result = await flow.async_step_reauth_confirm({CONF_USER_NAME: "user", CONF_PASSWORD: "pass"})
    assert result["type"] == "abort"
    assert result["reason"] == "reauth_successful"
    mock_update = flow.hass.config_entries.async_update_entry
    assert isinstance(mock_update, MagicMock)
    mock_update.assert_called_once()
    _, kwargs = mock_update.call_args
    assert CONF_DEVICE_TOKEN in kwargs["data"]
    assert kwargs["data"][CONF_DEVICE_TOKEN] == "device_token_abc"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("entry_unique_id", "device_serial_number", "step_name", "helper_name", "user_input"),
    [
        (
            "SN123",
            "SN999",
            "async_step_reauth_confirm",
            "get_device",
            {CONF_USER_NAME: "user", CONF_PASSWORD: "pass"},
        ),
        (
            "SN123",
            "SN999",
            "async_step_reauth_verify_mfa",
            "get_mfa_device",
            {CONF_VERIFICATION_CODE: "654321"},
        ),
        (
            None,
            "SN123",
            "async_step_reauth_confirm",
            "get_device",
            {CONF_USER_NAME: "user", CONF_PASSWORD: "pass"},
        ),
        (
            None,
            "SN123",
            "async_step_reauth_verify_mfa",
            "get_mfa_device",
            {CONF_VERIFICATION_CODE: "654321"},
        ),
    ],
)
async def test_async_step_reauth_aborts_on_unverified_device_identity(
    flow: MyAirConfigFlow,
    myair_client: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    entry_unique_id: str | None,
    device_serial_number: str,
    step_name: str,
    helper_name: str,
    user_input: dict[str, str],
) -> None:
    """Reauth refuses to update an entry when device identity is unverified."""
    config_entry = MockConfigEntry(
        domain="resmed_myair",
        title="ResMed-CPAP",
        data={CONF_USER_NAME: "user", CONF_PASSWORD: "pass", CONF_REGION: REGION_NA},
        entry_id="mock_entry_id",
        unique_id=entry_unique_id,
        version=2,
    )
    flow._entry = config_entry
    flow._client = myair_client
    flow._data = {CONF_USER_NAME: "user", CONF_PASSWORD: "pass", CONF_REGION: REGION_NA}
    mismatched_device = MyAirDevice.from_api(
        {
            "serialNumber": device_serial_number,
            "fgDeviceManufacturerName": "ResMed",
            "localizedName": "Guest CPAP",
        }
    )
    helper_result = (
        (AUTHN_SUCCESS, mismatched_device, myair_client)
        if helper_name == "get_device"
        else (AUTHN_SUCCESS, mismatched_device)
    )
    monkeypatch.setattr(config_flow, helper_name, AsyncMock(return_value=helper_result))

    result = await getattr(flow, step_name)(user_input)

    assert result["type"] == "abort"
    assert result["reason"] == "wrong_account"
    flow.hass.config_entries.async_update_entry.assert_not_called()
    flow.hass.config_entries.async_reload.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        "step_name",
        "is_email_verified",
        "client_exists",
        "expected_abort_reason",
        "no_client_shows_form",
    ),
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
    monkeypatch: pytest.MonkeyPatch,
    step_name: str,
    is_email_verified: bool | str | None,
    client_exists: bool,
    expected_abort_reason: str,
    no_client_shows_form: bool,
    hass: MagicMock,
    config_entry: MockConfigEntry,
    myair_client: MagicMock,
) -> None:
    """Reauth steps abort or surface MFA prompts for incomplete accounts.

    Depending on the step, the flow uses either `get_device` or `get_mfa_device`.
    This single test exercises both `async_step_reauth_confirm` and
    `async_step_reauth_verify_mfa` branches with the combinations used
    previously in two separate tests.
    """
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow._data = {CONF_USER_NAME: "user", CONF_PASSWORD: "pass", CONF_REGION: REGION_NA}
    flow._entry = config_entry

    if step_name == "async_step_reauth_confirm":
        user_input = {CONF_USER_NAME: "user", CONF_PASSWORD: "pass"}
        monkeypatch.setattr(
            "custom_components.resmed_myair.config_flow.get_device",
            AsyncMock(side_effect=IncompleteAccountError("incomplete")),
        )
    else:
        user_input = {CONF_VERIFICATION_CODE: "654321"}
        monkeypatch.setattr(
            "custom_components.resmed_myair.config_flow.get_mfa_device",
            AsyncMock(side_effect=IncompleteAccountError("incomplete")),
        )

    flow.async_abort = MagicMock(return_value={"type": "abort", "reason": expected_abort_reason})

    if client_exists:
        flow._client = myair_client
        if is_email_verified == "exception":
            flow._client.is_email_verified = AsyncMock(side_effect=ParsingError("fail"))
        else:
            flow._client.is_email_verified = AsyncMock(return_value=is_email_verified)
    else:
        flow._client = None

    result = await getattr(flow, step_name)(user_input)

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
async def test_async_step_reauth_verify_mfa_error(
    flow: MyAirConfigFlow,
    config_entry: MockConfigEntry,
    myair_client: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reauth MFA failures return the form with an MFA error."""
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
    (
        "connect_return",
        "get_user_device_data_return",
        "expected_status",
        "expected_device",
        "raises",
    ),
    [
        (AUTHN_SUCCESS, {"serialNumber": "SN123"}, AUTHN_SUCCESS, {"serialNumber": "SN123"}, None),
        ("AUTHN_FAIL", None, "AUTHN_FAIL", None, None),
        ("FAIL", None, "FAIL", None, None),
        (Exception("fail"), None, None, None, Exception),
    ],
)
async def test_get_device_variants(
    connect_return: str | None,
    get_user_device_data_return: dict[str, object] | None,
    expected_status: str | None,
    expected_device: dict[str, object] | None,
    raises: type[BaseException] | None,
    hass: MagicMock,
    session: MagicMock,
    myair_client: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`get_device` handles connection outcomes and device payload variants."""
    mock_client = myair_client
    if isinstance(connect_return, Exception):
        mock_client.connect = AsyncMock(side_effect=connect_return)
    else:
        mock_client.connect = AsyncMock(return_value=connect_return)
    if get_user_device_data_return is None:
        mock_client.get_user_device_data = AsyncMock(return_value=None)
    else:
        mock_client.get_user_device_data = AsyncMock(
            return_value=MyAirDevice.from_api(get_user_device_data_return)
        )
    monkeypatch.setattr(config_flow, "MyAirConfig", MagicMock())
    monkeypatch.setattr(config_flow, "RESTClient", lambda *a, **k: mock_client)
    monkeypatch.setattr(config_flow, "async_create_clientsession", lambda *a, **k: session)

    if raises:
        with pytest.raises(raises):
            await get_device(hass, "user", "pass", "region", device_token=None)
    else:
        status, device, client = await get_device(hass, "user", "pass", "region", device_token=None)
        assert status == expected_status
        if expected_device is None:
            assert device is expected_device
        else:
            assert device == MyAirDevice.from_api(expected_device)
        assert client is mock_client


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        "verify_return",
        "get_user_device_data_return",
        "verify_side_effect",
        "get_user_device_data_side_effect",
        "expected_status",
        "expected_device",
        "raises",
    ),
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
    verify_return: str,
    get_user_device_data_return: dict[str, object] | None,
    verify_side_effect: type[BaseException] | None,
    get_user_device_data_side_effect: type[BaseException] | None,
    expected_status: str | None,
    expected_device: dict[str, object] | None,
    raises: type[BaseException] | None,
    myair_client: MagicMock,
) -> None:
    """`get_mfa_device` handles MFA outcomes and follow-up device fetches."""
    mock_client = myair_client
    if verify_side_effect:
        mock_client.verify_mfa_and_get_access_token = AsyncMock(side_effect=verify_side_effect)
    else:
        mock_client.verify_mfa_and_get_access_token = AsyncMock(return_value=verify_return)
    if get_user_device_data_side_effect:
        mock_client.get_user_device_data = AsyncMock(side_effect=get_user_device_data_side_effect)
    elif get_user_device_data_return is None:
        mock_client.get_user_device_data = AsyncMock(return_value=None)
    else:
        mock_client.get_user_device_data = AsyncMock(
            return_value=MyAirDevice.from_api(get_user_device_data_return)
        )

    if raises:
        with pytest.raises(raises):
            await get_mfa_device(mock_client, "123456")
    else:
        status, device = await get_mfa_device(mock_client, "123456")
        mock_client.verify_mfa_and_get_access_token.assert_awaited_once_with("123456")
        mock_client.get_user_device_data.assert_awaited_once_with(initial=True)
        assert status == expected_status
        if expected_device is None:
            assert device is expected_device
        else:
            assert device == MyAirDevice.from_api(expected_device)


@pytest.mark.asyncio
async def test_get_device_passes_device_token(
    hass: MagicMock, myair_client: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`get_device` forwards the device token into `MyAirConfig`."""
    mock_client = myair_client
    mock_client.connect = AsyncMock(return_value=AUTHN_SUCCESS)
    mock_client.get_user_device_data = AsyncMock(return_value=MyAirDevice.from_api({}))
    mock_config = MagicMock()
    monkeypatch.setattr(config_flow, "MyAirConfig", mock_config)
    monkeypatch.setattr(config_flow, "RESTClient", lambda *a, **k: mock_client)
    monkeypatch.setattr(config_flow, "async_create_clientsession", lambda *a, **k: MagicMock())

    await get_device(hass, "user", "pass", "region", device_token="token123")
    mock_config.assert_called_once_with(
        username="user", password="pass", region="region", device_token="token123"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("step_name", "expected_step_id"),
    [
        ("async_step_verify_mfa", "verify_mfa"),
        ("async_step_reauth_verify_mfa", "reauth_verify_mfa"),
    ],
)
async def test_async_step_verify_mfa_status_variants(
    flow: MyAirConfigFlow,
    step_name: str,
    expected_step_id: str,
    myair_client: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-success MFA statuses keep the flow on the correct error form."""
    flow._client = myair_client
    flow._data = {CONF_USER_NAME: "user"}
    user_input = {CONF_VERIFICATION_CODE: "badcode"}
    monkeypatch.setattr(
        config_flow,
        "get_mfa_device",
        AsyncMock(return_value=("MFA_FAIL", MyAirDevice.from_api({}))),
    )
    result = await getattr(flow, step_name)(user_input)

    assert result["type"] == "form"
    assert result["step_id"] == expected_step_id
    # Require explicit mfa_error for non-success MFA status to avoid masking regressions
    assert "base" in result["errors"]
    assert result["errors"]["base"] == "mfa_error"


@pytest.mark.asyncio
async def test_async_step_reauth_calls_confirm(
    hass: MagicMock, config_entry: MockConfigEntry
) -> None:
    """The reauth entry route loads entry data before calling confirm."""
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow.context = {"entry_id": "123"}
    flow._data = {}
    flow.hass.config_entries.async_get_entry = MagicMock(return_value=config_entry)

    flow.async_step_reauth_confirm = AsyncMock(return_value={"type": "form"})
    entry_data = {"foo": "bar"}

    result = await flow.async_step_reauth(entry_data)
    assert result == {"type": "form"}
    assert flow._entry == config_entry
    assert flow._data["foo"] == "bar"
    flow.async_step_reauth_confirm.assert_awaited_once()
    flow.hass.config_entries.async_get_entry.assert_called_once_with("123")


@pytest.mark.asyncio
async def test_async_step_user_not_device_or_not_authn_success(
    monkeypatch: pytest.MonkeyPatch, hass: MagicMock
) -> None:
    """A non-success device lookup advances the flow to MFA verification."""
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow._data = {}

    monkeypatch.setattr(
        "custom_components.resmed_myair.config_flow.get_device",
        AsyncMock(return_value=("MFA_REQUIRED", None, MagicMock())),
    )
    flow.async_step_verify_mfa = AsyncMock(return_value={"type": "form", "step_id": "verify_mfa"})

    user_input = {
        CONF_USER_NAME: "user",
        CONF_PASSWORD: "pass",
        CONF_REGION: REGION_NA,
    }

    result = await flow.async_step_user(user_input)
    assert result == {"type": "form", "step_id": "verify_mfa"}
    flow.async_step_verify_mfa.assert_awaited_once()


@pytest.mark.parametrize(
    ("step_name", "expected_step_id", "needs_entry"),
    [
        ("async_step_verify_mfa", "verify_mfa", False),
        ("async_step_reauth_verify_mfa", "reauth_verify_mfa", True),
    ],
)
@pytest.mark.asyncio
async def test_async_step_verify_mfa_parsing_error_variants(
    flow: MyAirConfigFlow,
    monkeypatch: pytest.MonkeyPatch,
    config_entry: MockConfigEntry,
    myair_client: MagicMock,
    step_name: str,
    expected_step_id: str,
    needs_entry: bool,
) -> None:
    """Parsing errors keep MFA verification on the active form."""
    flow._data = {}
    flow._client = myair_client
    if needs_entry:
        flow._entry = config_entry

    monkeypatch.setattr(
        config_flow,
        "get_mfa_device",
        AsyncMock(side_effect=ParsingError("bad parse")),
    )

    result = await getattr(flow, step_name)({CONF_VERIFICATION_CODE: "654321"})

    assert result["type"] == "form"
    assert result["step_id"] == expected_step_id
    assert result["errors"]["base"] == "mfa_error"


@pytest.mark.asyncio
async def test_async_step_reauth_no_entry(hass: MagicMock) -> None:
    """Reauth aborts when the referenced config entry no longer exists."""
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow.hass.config_entries.async_get_entry.return_value = None
    flow.context = {"entry_id": "missing_entry"}

    with pytest.raises(UnknownEntry):
        await flow.async_step_reauth({})
    flow.hass.config_entries.async_get_entry.assert_called_once_with("missing_entry")


@pytest.mark.parametrize(
    ("step_name", "user_input", "flow_data", "expected_step_id", "needs_entry"),
    [
        (
            "async_step_user",
            {
                CONF_USER_NAME: "user",
                CONF_PASSWORD: "pass",
                CONF_REGION: REGION_NA,
            },
            {},
            "user",
            False,
        ),
        (
            "async_step_reauth_confirm",
            {
                CONF_USER_NAME: "user",
                CONF_PASSWORD: "pw",
            },
            {
                CONF_USER_NAME: "user",
                CONF_PASSWORD: "pw",
                CONF_REGION: REGION_NA,
                CONF_DEVICE_TOKEN: "token",
            },
            "reauth_confirm",
            True,
        ),
    ],
)
@pytest.mark.asyncio
async def test_async_step_device_missing_serial_number_variants(
    flow: MyAirConfigFlow,
    monkeypatch: pytest.MonkeyPatch,
    config_entry: MockConfigEntry,
    step_name: str,
    user_input: dict[str, str],
    flow_data: dict[str, str],
    expected_step_id: str,
    needs_entry: bool,
) -> None:
    """Missing device serial numbers keep the active auth form open."""
    flow._data = flow_data
    if needs_entry:
        flow._entry = config_entry
    device = MyAirDevice.from_api({"fgDeviceManufacturerName": "ResMed", "localizedName": "CPAP"})
    monkeypatch.setattr(
        config_flow,
        "get_device",
        AsyncMock(return_value=(AUTHN_SUCCESS, device, MagicMock(spec=RESTClient))),
    )

    result = await getattr(flow, step_name)(user_input)

    assert result["type"] == "form"
    assert result["step_id"] == expected_step_id
    assert result["errors"]["base"] == "authentication_error"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("exception", "expected_error"),
    [
        (ParsingError("parse error"), "authentication_error"),
        (AuthenticationError("auth error"), "authentication_error"),
        (IncompleteAccountError("incomplete"), "authentication_error"),
        (HttpProcessingError(), "authentication_error"),
    ],
)
async def test_async_step_reauth_confirm_exceptions(
    monkeypatch: pytest.MonkeyPatch,
    exception: object,
    expected_error: object,
    hass: MagicMock,
    config_entry: MockConfigEntry,
) -> None:
    """Reauth confirm maps client exceptions to the expected error path."""
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
@pytest.mark.parametrize(
    (
        "step_name",
        "helper_path",
        "user_input",
        "flow_data",
        "is_email_verified",
        "client_exists",
        "expected_abort_reason",
    ),
    [
        pytest.param(
            "async_step_user",
            "custom_components.resmed_myair.config_flow.get_device",
            {CONF_USER_NAME: "user", CONF_PASSWORD: "pw", CONF_REGION: REGION_NA},
            {CONF_USER_NAME: "user"},
            False,
            True,
            "incomplete_account_verify_email",
            id="user-email-unverified",
        ),
        pytest.param(
            "async_step_user",
            "custom_components.resmed_myair.config_flow.get_device",
            {CONF_USER_NAME: "user", CONF_PASSWORD: "pw", CONF_REGION: REGION_NA},
            {CONF_USER_NAME: "user"},
            True,
            True,
            "incomplete_account",
            id="user-email-verified",
        ),
        pytest.param(
            "async_step_user",
            "custom_components.resmed_myair.config_flow.get_device",
            {CONF_USER_NAME: "user", CONF_PASSWORD: "pw", CONF_REGION: REGION_NA},
            {CONF_USER_NAME: "user"},
            None,
            False,
            "incomplete_account",
            id="user-no-client",
        ),
        pytest.param(
            "async_step_user",
            "custom_components.resmed_myair.config_flow.get_device",
            {CONF_USER_NAME: "user", CONF_PASSWORD: "pw", CONF_REGION: REGION_NA},
            {CONF_USER_NAME: "user"},
            "exception",
            True,
            "incomplete_account",
            id="user-email-check-parse-error",
        ),
        pytest.param(
            "async_step_verify_mfa",
            "custom_components.resmed_myair.config_flow.get_mfa_device",
            {CONF_VERIFICATION_CODE: "654321"},
            {},
            False,
            True,
            "incomplete_account_verify_email",
            id="verify-mfa-email-unverified",
        ),
        pytest.param(
            "async_step_verify_mfa",
            "custom_components.resmed_myair.config_flow.get_mfa_device",
            {CONF_VERIFICATION_CODE: "654321"},
            {},
            True,
            True,
            "incomplete_account",
            id="verify-mfa-email-verified",
        ),
        pytest.param(
            "async_step_verify_mfa",
            "custom_components.resmed_myair.config_flow.get_mfa_device",
            {CONF_VERIFICATION_CODE: "654321"},
            {},
            "exception",
            True,
            "incomplete_account",
            id="verify-mfa-email-check-parse-error",
        ),
    ],
)
async def test_async_step_initial_incomplete_account_abort_variants(
    monkeypatch: pytest.MonkeyPatch,
    step_name: str,
    helper_path: str,
    user_input: dict[str, str],
    flow_data: dict[str, str],
    is_email_verified: bool | str | None,
    client_exists: bool,
    expected_abort_reason: str,
    hass: MagicMock,
    myair_client: MagicMock,
) -> None:
    """Initial auth and MFA incomplete-account branches converge on abort reasons."""
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow._data = flow_data
    monkeypatch.setattr(helper_path, AsyncMock(side_effect=IncompleteAccountError("fail")))
    flow.async_abort = MagicMock(return_value={"type": "abort", "reason": expected_abort_reason})

    if client_exists:
        flow._client = myair_client
        if is_email_verified == "exception":
            flow._client.is_email_verified = AsyncMock(side_effect=ParsingError("fail"))
        else:
            flow._client.is_email_verified = AsyncMock(return_value=is_email_verified)
    else:
        flow._client = None

    result = await getattr(flow, step_name)(user_input)

    assert result["type"] == "abort"
    assert result["reason"] == expected_abort_reason
    if client_exists and is_email_verified != "exception":
        flow._client.is_email_verified.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "email_error",
    [
        ClientError("transport failure"),
        TimeoutError("request timed out"),
    ],
)
async def test_async_step_user_incomplete_account_email_check_transport_error(
    monkeypatch: pytest.MonkeyPatch,
    hass: MagicMock,
    myair_client: MagicMock,
    email_error: Exception,
) -> None:
    """Transient email-check transport failures still preserve the abort."""
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow._data = {CONF_USER_NAME: "user"}
    flow._client = myair_client
    user_input = {CONF_USER_NAME: "user", CONF_PASSWORD: "pw", CONF_REGION: REGION_NA}
    monkeypatch.setattr(
        "custom_components.resmed_myair.config_flow.get_device",
        AsyncMock(side_effect=IncompleteAccountError("fail")),
    )
    flow._client.is_email_verified = AsyncMock(side_effect=email_error)
    flow.async_abort = MagicMock(return_value={"type": "abort", "reason": "incomplete_account"})

    result = await flow.async_step_user(user_input)

    assert result["type"] == "abort"
    assert result["reason"] == "incomplete_account"
    flow._client.is_email_verified.assert_awaited_once()
