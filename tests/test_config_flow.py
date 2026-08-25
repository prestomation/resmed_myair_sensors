"""Config-flow tests that protect setup, MFA, and reauth state transitions."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from aiohttp import ClientError
from homeassistant.config_entries import SOURCE_REAUTH, SOURCE_RECONFIGURE, UnknownEntry
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
TRANSLATION_LANGUAGES = ("de", "en", "es", "fr")
CONFIG_FLOW_ABORT_REASONS = (
    "already_configured",
    "incomplete_account",
    "incomplete_account_verify_email",
    "reauth_successful",
    "reconfigure_successful",
    "wrong_account",
)


@pytest.fixture
def flow(hass: MagicMock) -> MyAirConfigFlow:
    """Return a configured `MyAirConfigFlow` bound to the test Home Assistant.

    Args:
        hass (MagicMock): Home Assistant double used as the flow's runtime.

    Returns:
        MyAirConfigFlow: Flow with the Home Assistant instance and empty context attached.
    """
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow.context = {}
    return flow


def _credential_data(
    username: str,
    password: str,
    region: str,
    device_token: str | None = None,
) -> dict[str, str]:
    """Return config-entry credential data for tests.

    Args:
        username (str): myAir account username stored in the entry.
        password (str): myAir account password stored in the entry.
        region (str): myAir region code stored in the entry.
        device_token (str | None): Optional remembered-device token to include.

    Returns:
        dict[str, str]: Credential data shaped like a config-entry payload.
    """
    data = {
        CONF_USER_NAME: username,
        CONF_PASSWORD: password,
        CONF_REGION: region,
    }
    if device_token is not None:
        data[CONF_DEVICE_TOKEN] = device_token
    return data


def _reconfigure_entry(
    unique_id: str | None = "SN123",
    *,
    entry_id: str = "mock_entry_id",
    title: str = "ResMed-CPAP",
    username: str = "old@example.com",
) -> MockConfigEntry:
    """Return a config entry shaped for reconfigure flow tests.

    Args:
        unique_id (str | None): Existing config-entry unique ID, or `None` for legacy entries.
        entry_id (str): Config-entry ID to expose through flow context.
        title (str): Config-entry title shown by the test entry.
        username (str): Stored myAir account username.

    Returns:
        MockConfigEntry: Config entry with myAir credential data.
    """
    return MockConfigEntry(
        domain="resmed_myair",
        title=title,
        data=_credential_data(username, "old-password", REGION_NA, "old-token"),
        entry_id=entry_id,
        unique_id=unique_id,
        version=2,
    )


def _prepare_reconfigure_flow(
    flow: MyAirConfigFlow,
    config_entry: MockConfigEntry,
    myair_client: MagicMock,
    *,
    existing_unique_id_entry: MockConfigEntry | None = None,
    flow_data: dict[str, str] | None = None,
) -> None:
    """Wire a config flow to an entry for reconfigure tests.

    Args:
        flow (MyAirConfigFlow): Config flow under test.
        config_entry (MockConfigEntry): Entry returned by Home Assistant's known-entry lookup.
        myair_client (MagicMock): REST client double held by the flow.
        existing_unique_id_entry (MockConfigEntry | None): Optional entry returned for duplicate
            unique ID lookup.
        flow_data (dict[str, str] | None): Optional transient flow data to preload.
    """
    flow.context = {"source": SOURCE_RECONFIGURE, "entry_id": config_entry.entry_id}
    flow._client = myair_client
    flow.hass.config_entries.async_get_known_entry = MagicMock(return_value=config_entry)
    flow.hass.config_entries.async_entry_for_domain_unique_id = MagicMock(
        return_value=existing_unique_id_entry
    )
    flow.hass.config_entries.async_schedule_reload = MagicMock()
    if flow_data is not None:
        flow._data = flow_data


@pytest.mark.parametrize("language", TRANSLATION_LANGUAGES)
def test_config_flow_abort_reasons_have_translations(language: str) -> None:
    """Verify every supported abort reason is translated for the selected language.

    Args:
        language (str): Translation language code selected by the parameterized case.
    """
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
    """Verify a successful user step creates an entry with the discovered device.

    Args:
        flow (MyAirConfigFlow): Config flow receiving the successful credentials.
        myair_client (MagicMock): Client returned after successful device discovery.
        monkeypatch (pytest.MonkeyPatch): Patch manager for the device lookup helper.
    """
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
    """Verify authentication failures keep the user step on the form with an error.

    Args:
        flow (MyAirConfigFlow): Config flow receiving invalid credentials.
        monkeypatch (pytest.MonkeyPatch): Patch manager for the failing device lookup helper.
    """
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
    """Verify MFA failures map to the correct form error for each client type.

    Args:
        flow (MyAirConfigFlow): Config flow handling the MFA submission.
        myair_client (RESTClient): Real-client-shaped double for the REST branch case.
        monkeypatch (pytest.MonkeyPatch): Patch manager for the failing MFA helper.
        is_restclient (bool): Whether this parameter case supplies a `RESTClient` instance.
    """
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
    ("step_name", "pre_setup", "expected_step_id", "source"),
    [
        ("async_step_user", False, "user", None),
        ("async_step_verify_mfa", True, "verify_mfa", None),
        ("async_step_reauth_confirm", True, "reauth_confirm", None),
        ("async_step_reauth_verify_mfa", True, "reauth_verify_mfa", None),
        ("async_step_reconfigure", False, "reconfigure", SOURCE_RECONFIGURE),
        ("async_step_reconfigure", True, "reconfigure", SOURCE_RECONFIGURE),
        ("async_step_reconfigure_verify_mfa", True, "reconfigure_verify_mfa", SOURCE_RECONFIGURE),
    ],
)
async def test_async_step_forms_display_parametrized(
    flow: MyAirConfigFlow,
    step_name: str,
    pre_setup: bool,
    expected_step_id: str,
    source: str | None,
    myair_client: MagicMock,
    config_entry: MockConfigEntry,
) -> None:
    """Verify each selected user or MFA step renders its form without input.

    Args:
        flow (MyAirConfigFlow): Config flow whose selected step is exercised.
        step_name (str): Config-flow method name used by this parameter case.
        pre_setup (bool): Whether this case preloads client and credential state.
        expected_step_id (str): Form step ID expected for the selected method.
        source (str | None): Optional flow source, set for reconfigure cases.
        myair_client (MagicMock): Client used when the case requires preloaded state.
        config_entry (MockConfigEntry): Existing entry used by reconfigure cases.
    """
    if source == SOURCE_RECONFIGURE:
        flow.context = {"source": SOURCE_RECONFIGURE, "entry_id": config_entry.entry_id}
        flow.hass.config_entries.async_get_known_entry = MagicMock(return_value=config_entry)
    if pre_setup:
        flow._client = myair_client
        flow._data = {CONF_USER_NAME: "user", CONF_PASSWORD: "pass"}

    result = await getattr(flow, step_name)()
    assert result["type"] == "form"
    assert result["step_id"] == expected_step_id
    assert "errors" in result


@pytest.mark.asyncio
async def test_config_flow_private_auth_helpers_handle_missing_state(
    flow: MyAirConfigFlow,
) -> None:
    """Verify auth helpers handle missing transient client state safely.

    Args:
        flow (MyAirConfigFlow): Flow whose empty client and data state is exercised.
    """
    flow._client = None
    flow._data = {}

    with pytest.raises(AuthenticationError):
        await flow._async_verify_mfa_and_get_device()

    flow._store_device_token()

    assert CONF_DEVICE_TOKEN not in flow._data


@pytest.mark.asyncio
async def test_async_step_reauth_success(
    flow: MyAirConfigFlow,
    myair_client: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify successful reauth updates stored credentials and completes.

    Args:
        flow (MyAirConfigFlow): Config flow performing the reauthentication.
        myair_client (MagicMock): Authenticated client carrying the replacement token.
        monkeypatch (pytest.MonkeyPatch): Patch manager for successful device lookup.
    """
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
    """Verify reauth refuses to update an entry with an unverified device identity.

    Args:
        flow (MyAirConfigFlow): Config flow performing the reauthentication.
        myair_client (MagicMock): Client associated with the existing entry.
        monkeypatch (pytest.MonkeyPatch): Patch manager for the selected auth helper.
        entry_unique_id (str | None): Existing entry serial used for identity comparison.
        device_serial_number (str): Serial returned by the mismatched account case.
        step_name (str): Reauth step method selected by this parameter case.
        helper_name (str): Auth helper patched for the selected step.
        user_input (dict[str, str]): Credentials or MFA code submitted by the case.
    """
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
    flow.hass.config_entries.async_schedule_reload = MagicMock()
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
    flow.hass.config_entries.async_schedule_reload.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("step_name", "helper_name", "user_input"),
    [
        (
            "async_step_reauth_confirm",
            "get_device",
            {CONF_USER_NAME: "user", CONF_PASSWORD: "pass"},
        ),
        (
            "async_step_reauth_verify_mfa",
            "get_mfa_device",
            {CONF_VERIFICATION_CODE: "654321"},
        ),
    ],
)
async def test_async_step_reauth_backfills_legacy_entry_unique_id(
    flow: MyAirConfigFlow,
    myair_client: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    step_name: str,
    helper_name: str,
    user_input: dict[str, str],
) -> None:
    """Verify reauth backfills a missing unique ID on a legacy entry.

    Args:
        flow (MyAirConfigFlow): Config flow performing the reauthentication.
        myair_client (MagicMock): Client carrying the refreshed device token.
        monkeypatch (pytest.MonkeyPatch): Patch manager for the selected auth helper.
        step_name (str): Reauth step method selected by this parameter case.
        helper_name (str): Auth helper patched for the selected step.
        user_input (dict[str, str]): Credentials or MFA code submitted by the case.
    """
    config_entry = MockConfigEntry(
        domain="resmed_myair",
        title="ResMed-CPAP",
        data={CONF_USER_NAME: "user", CONF_PASSWORD: "pass", CONF_REGION: REGION_NA},
        entry_id="mock_entry_id",
        unique_id=None,
        version=2,
    )
    flow._entry = config_entry
    flow._client = myair_client
    flow.hass.config_entries.async_schedule_reload = MagicMock()
    myair_client.device_token = "updated-token"
    flow._data = {CONF_USER_NAME: "user", CONF_PASSWORD: "pass", CONF_REGION: REGION_NA}
    device = MyAirDevice.from_api(
        {
            "serialNumber": "SN123",
            "fgDeviceManufacturerName": "ResMed",
            "localizedName": "CPAP",
        }
    )
    helper_result = (
        (AUTHN_SUCCESS, device, myair_client)
        if helper_name == "get_device"
        else (AUTHN_SUCCESS, device)
    )
    monkeypatch.setattr(config_flow, helper_name, AsyncMock(return_value=helper_result))

    result = await getattr(flow, step_name)(user_input)

    assert result["type"] == "abort"
    assert result["reason"] == "reauth_successful"
    _, kwargs = flow.hass.config_entries.async_update_entry.call_args
    assert kwargs["entry"] is config_entry
    assert kwargs["data"] == {
        CONF_USER_NAME: "user",
        CONF_PASSWORD: "pass",
        CONF_REGION: REGION_NA,
        CONF_DEVICE_TOKEN: "updated-token",
    }
    assert kwargs["unique_id"] == "SN123"
    flow.hass.config_entries.async_schedule_reload.assert_called_once_with("mock_entry_id")


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

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch manager for the selected auth helper.
        step_name (str): Reauth step method selected by this parameter case.
        is_email_verified (bool | str | None): Email-check result, including parse-error case.
        client_exists (bool): Whether the case supplies an authenticated client.
        expected_abort_reason (str): Abort reason expected for the account state.
        no_client_shows_form (bool): Whether a missing client should leave the form displayed.
        hass (MagicMock): Home Assistant double attached to the temporary flow.
        config_entry (MockConfigEntry): Existing entry used by the reauth flow.
        myair_client (MagicMock): Client double used by cases that check email verification.
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
    """Verify reauth MFA failures return the form with an MFA error.

    Args:
        flow (MyAirConfigFlow): Config flow handling the reauth MFA submission.
        config_entry (MockConfigEntry): Existing entry attached to the flow.
        myair_client (MagicMock): Client holding the failed MFA challenge.
        monkeypatch (pytest.MonkeyPatch): Patch manager for the failing MFA helper.
    """
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
    """Verify `get_device` handles connection outcomes and device payload variants.

    Args:
        connect_return (str | None): Connection status returned by the client case.
        get_user_device_data_return (dict[str, object] | None): Device payload returned after
            successful authentication, or `None` for no device.
        expected_status (str | None): Status expected from `get_device` for the case.
        expected_device (dict[str, object] | None): Device payload expected in the result.
        raises (type[BaseException] | None): Exception type expected for the failure case.
        hass (MagicMock): Home Assistant double passed to client-session creation.
        session (MagicMock): Client session returned by the patched session factory.
        myair_client (MagicMock): REST client double configured for this case.
        monkeypatch (pytest.MonkeyPatch): Patch manager for client construction dependencies.
    """
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
    """Verify `get_mfa_device` handles MFA outcomes and follow-up device fetches.

    Args:
        verify_return (str): MFA status returned by the client in the success path.
        get_user_device_data_return (dict[str, object] | None): Device payload returned after
            MFA, or `None` for a missing device.
        verify_side_effect (type[BaseException] | None): Exception type raised during MFA, if any.
        get_user_device_data_side_effect (type[BaseException] | None): Exception type raised
            while fetching the device, if any.
        expected_status (str | None): Status expected from `get_mfa_device` for the case.
        expected_device (dict[str, object] | None): Device payload expected in the result.
        raises (type[BaseException] | None): Exception type expected for the failure case.
        myair_client (MagicMock): REST client double configured for this case.
    """
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
    """Verify `get_device` forwards the remembered token into `MyAirConfig`.

    Args:
        hass (MagicMock): Home Assistant double passed to `get_device`.
        myair_client (MagicMock): Client returned after constructing the config.
        monkeypatch (pytest.MonkeyPatch): Patch manager for config and client factories.
    """
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
    ("step_name", "expected_step_id", "source"),
    [
        ("async_step_verify_mfa", "verify_mfa", None),
        ("async_step_reauth_verify_mfa", "reauth_verify_mfa", None),
        ("async_step_reconfigure_verify_mfa", "reconfigure_verify_mfa", SOURCE_RECONFIGURE),
    ],
)
async def test_async_step_verify_mfa_status_variants(
    flow: MyAirConfigFlow,
    step_name: str,
    expected_step_id: str,
    source: str | None,
    myair_client: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    config_entry: MockConfigEntry,
) -> None:
    """Verify non-success MFA statuses keep each selected flow on its error form.

    Args:
        flow (MyAirConfigFlow): Config flow handling the MFA status.
        step_name (str): MFA step method selected by this parameter case.
        expected_step_id (str): Form step ID expected for the selected method.
        source (str | None): Optional flow source, set for reconfigure cases.
        myair_client (MagicMock): Client double receiving the failed MFA response.
        monkeypatch (pytest.MonkeyPatch): Patch manager for the MFA helper.
        config_entry (MockConfigEntry): Existing entry used by reauth or reconfigure cases.
    """
    flow._client = myair_client
    flow._data = {CONF_USER_NAME: "user"}
    if source == SOURCE_RECONFIGURE:
        flow.context = {"source": SOURCE_RECONFIGURE, "entry_id": config_entry.entry_id}
        flow.hass.config_entries.async_get_known_entry = MagicMock(return_value=config_entry)
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
    """Verify the reauth route loads entry data before calling confirm.

    Args:
        hass (MagicMock): Home Assistant double used for entry lookup.
        config_entry (MockConfigEntry): Existing entry returned by the lookup.
    """
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow.context = {"source": SOURCE_REAUTH, "entry_id": "123"}
    flow._data = {}
    flow.hass.config_entries.async_get_known_entry = MagicMock(return_value=config_entry)

    flow.async_step_reauth_confirm = AsyncMock(return_value={"type": "form"})
    entry_data = {"foo": "bar"}

    result = await flow.async_step_reauth(entry_data)
    assert result == {"type": "form"}
    assert flow._entry == config_entry
    assert flow._data["foo"] == "bar"
    flow.async_step_reauth_confirm.assert_awaited_once()
    flow.hass.config_entries.async_get_known_entry.assert_called_once_with("123")


@pytest.mark.asyncio
async def test_async_step_reconfigure_success_updates_entry_and_schedules_reload(
    flow: MyAirConfigFlow,
    myair_client: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify reconfigure validates the same device before updating setup data.

    Args:
        flow (MyAirConfigFlow): Config flow performing the reconfiguration.
        myair_client (MagicMock): Client carrying the refreshed device token.
        monkeypatch (pytest.MonkeyPatch): Patch manager for successful device lookup.
    """
    config_entry = _reconfigure_entry()
    device = MyAirDevice.from_api(
        {
            "serialNumber": "SN123",
            "fgDeviceManufacturerName": "ResMed",
            "localizedName": "CPAP",
        }
    )
    myair_client.device_token = "new-token"
    monkeypatch.setattr(
        config_flow,
        "get_device",
        AsyncMock(return_value=(AUTHN_SUCCESS, device, myair_client)),
    )
    _prepare_reconfigure_flow(flow, config_entry, myair_client)

    result = await flow.async_step_reconfigure(
        {
            CONF_USER_NAME: "new@example.com",
            CONF_PASSWORD: "new-password",
            CONF_REGION: REGION_EU,
        }
    )

    assert result["type"] == "abort"
    assert result["reason"] == "reconfigure_successful"
    get_device_mock = config_flow.get_device
    assert isinstance(get_device_mock, AsyncMock)
    get_device_mock.assert_awaited_once_with(
        flow.hass,
        "new@example.com",
        "new-password",
        REGION_EU,
        "old-token",
    )
    flow.hass.config_entries.async_get_known_entry.assert_any_call("mock_entry_id")
    _, kwargs = flow.hass.config_entries.async_update_entry.call_args
    assert kwargs["entry"] is config_entry
    assert kwargs["data"] == _credential_data(
        "new@example.com", "new-password", REGION_EU, "new-token"
    )
    flow.hass.config_entries.async_schedule_reload.assert_called_once_with("mock_entry_id")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("step_name", "helper_name", "user_input"),
    [
        (
            "async_step_reconfigure",
            "get_device",
            {
                CONF_USER_NAME: "new@example.com",
                CONF_PASSWORD: "new-password",
                CONF_REGION: REGION_EU,
            },
        ),
        (
            "async_step_reconfigure_verify_mfa",
            "get_mfa_device",
            {CONF_VERIFICATION_CODE: "654321"},
        ),
    ],
)
async def test_async_step_reconfigure_backfills_legacy_entry_unique_id(
    flow: MyAirConfigFlow,
    myair_client: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    step_name: str,
    helper_name: str,
    user_input: dict[str, str],
) -> None:
    """Verify reconfigure backfills a missing unique ID on a legacy entry.

    Args:
        flow (MyAirConfigFlow): Config flow performing the reconfiguration.
        myair_client (MagicMock): Client carrying the refreshed device token.
        monkeypatch (pytest.MonkeyPatch): Patch manager for the selected auth helper.
        step_name (str): Reconfigure step method selected by this parameter case.
        helper_name (str): Auth helper patched for the selected step.
        user_input (dict[str, str]): Updated credentials or MFA code submitted by the case.
    """
    flow_data = (
        _credential_data("new@example.com", "new-password", REGION_EU, "old-token")
        if step_name == "async_step_reconfigure_verify_mfa"
        else None
    )
    config_entry = _reconfigure_entry(unique_id=None)
    _prepare_reconfigure_flow(flow, config_entry, myair_client, flow_data=flow_data)
    myair_client.device_token = "updated-token"
    device = MyAirDevice.from_api(
        {
            "serialNumber": "SN123",
            "fgDeviceManufacturerName": "ResMed",
            "localizedName": "CPAP",
        }
    )
    helper_result = (
        (AUTHN_SUCCESS, device, myair_client)
        if helper_name == "get_device"
        else (AUTHN_SUCCESS, device)
    )
    monkeypatch.setattr(config_flow, helper_name, AsyncMock(return_value=helper_result))

    result = await getattr(flow, step_name)(user_input)

    assert result["type"] == "abort"
    assert result["reason"] == "reconfigure_successful"
    _, kwargs = flow.hass.config_entries.async_update_entry.call_args
    assert kwargs["entry"] is config_entry
    assert kwargs["data"] == _credential_data(
        "new@example.com", "new-password", REGION_EU, "updated-token"
    )
    assert kwargs["unique_id"] == "SN123"
    flow.hass.config_entries.async_schedule_reload.assert_called_once_with("mock_entry_id")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("step_name", "helper_name", "user_input"),
    [
        (
            "async_step_reconfigure",
            "get_device",
            {
                CONF_USER_NAME: "new@example.com",
                CONF_PASSWORD: "new-password",
                CONF_REGION: REGION_EU,
            },
        ),
        (
            "async_step_reconfigure_verify_mfa",
            "get_mfa_device",
            {CONF_VERIFICATION_CODE: "654321"},
        ),
    ],
)
async def test_async_step_reconfigure_aborts_on_unverified_device_identity(
    flow: MyAirConfigFlow,
    myair_client: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    step_name: str,
    helper_name: str,
    user_input: dict[str, str],
) -> None:
    """Verify reconfigure refuses to update an entry when device identity changes.

    Args:
        flow (MyAirConfigFlow): Config flow performing the reconfiguration.
        myair_client (MagicMock): Client associated with the existing entry.
        monkeypatch (pytest.MonkeyPatch): Patch manager for the selected auth helper.
        step_name (str): Reconfigure step method selected by this parameter case.
        helper_name (str): Auth helper patched for the selected step.
        user_input (dict[str, str]): Updated credentials or MFA code submitted by the case.
    """
    flow_data = (
        _credential_data("new@example.com", "new-password", REGION_EU, "old-token")
        if step_name == "async_step_reconfigure_verify_mfa"
        else None
    )
    config_entry = _reconfigure_entry()
    _prepare_reconfigure_flow(flow, config_entry, myair_client, flow_data=flow_data)
    mismatched_device = MyAirDevice.from_api(
        {
            "serialNumber": "SN999",
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


@pytest.mark.asyncio
async def test_async_step_reconfigure_legacy_backfill_aborts_on_duplicate_unique_id(
    flow: MyAirConfigFlow,
    myair_client: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify legacy reconfigure refuses a serial already used by another entry.

    Args:
        flow (MyAirConfigFlow): Config flow performing the reconfiguration.
        myair_client (MagicMock): Client carrying the refreshed device token.
        monkeypatch (pytest.MonkeyPatch): Patch manager for successful device lookup.
    """
    legacy_entry = _reconfigure_entry(
        unique_id=None,
        entry_id="legacy_entry",
        title="Legacy ResMed-CPAP",
    )
    existing_entry = _reconfigure_entry(
        entry_id="existing_entry",
        title="Existing ResMed-CPAP",
        username="existing@example.com",
    )
    _prepare_reconfigure_flow(
        flow,
        legacy_entry,
        myair_client,
        existing_unique_id_entry=existing_entry,
    )
    myair_client.device_token = "updated-token"
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

    result = await flow.async_step_reconfigure(
        {
            CONF_USER_NAME: "new@example.com",
            CONF_PASSWORD: "new-password",
            CONF_REGION: REGION_EU,
        }
    )

    assert result["type"] == "abort"
    assert result["reason"] == "already_configured"
    flow.hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("step_name", "helper_name", "user_input", "is_email_verified", "expected_abort_reason"),
    [
        (
            "async_step_reconfigure",
            "get_device",
            {
                CONF_USER_NAME: "new@example.com",
                CONF_PASSWORD: "new-password",
                CONF_REGION: REGION_EU,
            },
            False,
            "incomplete_account_verify_email",
        ),
        (
            "async_step_reconfigure",
            "get_device",
            {
                CONF_USER_NAME: "new@example.com",
                CONF_PASSWORD: "new-password",
                CONF_REGION: REGION_EU,
            },
            True,
            "incomplete_account",
        ),
        (
            "async_step_reconfigure_verify_mfa",
            "get_mfa_device",
            {CONF_VERIFICATION_CODE: "654321"},
            False,
            "incomplete_account_verify_email",
        ),
        (
            "async_step_reconfigure_verify_mfa",
            "get_mfa_device",
            {CONF_VERIFICATION_CODE: "654321"},
            True,
            "incomplete_account",
        ),
    ],
)
async def test_async_step_reconfigure_incomplete_account_abort_variants(
    flow: MyAirConfigFlow,
    myair_client: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    step_name: str,
    helper_name: str,
    user_input: dict[str, str],
    is_email_verified: bool,
    expected_abort_reason: str,
) -> None:
    """Verify reconfigure steps preserve incomplete-account abort handling.

    Args:
        flow (MyAirConfigFlow): Config flow performing the reconfiguration.
        myair_client (MagicMock): Client whose email-verification result drives the case.
        monkeypatch (pytest.MonkeyPatch): Patch manager for the selected failing auth helper.
        step_name (str): Reconfigure step method selected by this parameter case.
        helper_name (str): Auth helper patched to raise an incomplete-account error.
        user_input (dict[str, str]): Updated credentials or MFA code submitted by the case.
        is_email_verified (bool): Email-verification result used to choose the abort reason.
        expected_abort_reason (str): Abort reason expected for the account state.
    """
    flow_data = (
        _credential_data("new@example.com", "new-password", REGION_EU, "old-token")
        if step_name == "async_step_reconfigure_verify_mfa"
        else None
    )
    config_entry = _reconfigure_entry()
    _prepare_reconfigure_flow(flow, config_entry, myair_client, flow_data=flow_data)
    flow._client.is_email_verified = AsyncMock(return_value=is_email_verified)
    monkeypatch.setattr(
        config_flow,
        helper_name,
        AsyncMock(side_effect=IncompleteAccountError("incomplete")),
    )

    result = await getattr(flow, step_name)(user_input)

    assert result["type"] == "abort"
    assert result["reason"] == expected_abort_reason
    flow._client.is_email_verified.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_step_user_not_device_or_not_authn_success(
    monkeypatch: pytest.MonkeyPatch, hass: MagicMock
) -> None:
    """Verify a non-success device lookup advances the flow to MFA verification.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch manager for the device lookup helper.
        hass (MagicMock): Home Assistant double attached to the temporary flow.
    """
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
    ("step_name", "expected_step_id", "source", "needs_entry"),
    [
        ("async_step_verify_mfa", "verify_mfa", None, False),
        ("async_step_reauth_verify_mfa", "reauth_verify_mfa", None, True),
        (
            "async_step_reconfigure_verify_mfa",
            "reconfigure_verify_mfa",
            SOURCE_RECONFIGURE,
            True,
        ),
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
    source: str | None,
    needs_entry: bool,
) -> None:
    """Verify parsing errors keep MFA verification on the active form.

    Args:
        flow (MyAirConfigFlow): Config flow handling the MFA submission.
        monkeypatch (pytest.MonkeyPatch): Patch manager for the failing MFA helper.
        config_entry (MockConfigEntry): Existing entry for reauth and reconfigure cases.
        myair_client (MagicMock): Client holding the active MFA challenge.
        step_name (str): MFA step method selected by this parameter case.
        expected_step_id (str): Form step ID expected for the selected method.
        source (str | None): Optional flow source, set for reconfigure cases.
        needs_entry (bool): Whether the selected case needs an existing entry attached.
    """
    flow._data = {}
    flow._client = myair_client
    if needs_entry:
        flow._entry = config_entry
    if source == SOURCE_RECONFIGURE:
        flow.context = {"source": SOURCE_RECONFIGURE, "entry_id": config_entry.entry_id}
        flow.hass.config_entries.async_get_known_entry = MagicMock(return_value=config_entry)

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
    """Verify reauth raises when the referenced config entry no longer exists.

    Args:
        hass (MagicMock): Home Assistant double configured to report a missing entry.
    """
    flow = MyAirConfigFlow()
    flow.hass = hass
    flow.hass.config_entries.async_get_known_entry = MagicMock(
        side_effect=UnknownEntry("missing_entry")
    )
    flow.context = {"source": SOURCE_REAUTH, "entry_id": "missing_entry"}

    with pytest.raises(UnknownEntry):
        await flow.async_step_reauth({})
    flow.hass.config_entries.async_get_known_entry.assert_called_once_with("missing_entry")


@pytest.mark.parametrize(
    ("step_name", "user_input", "flow_data", "expected_step_id", "expected_error", "needs_entry"),
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
            "authentication_error",
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
            "authentication_error",
            True,
        ),
        (
            "async_step_verify_mfa",
            {CONF_VERIFICATION_CODE: "654321"},
            {},
            "verify_mfa",
            "mfa_error",
            False,
        ),
        (
            "async_step_reconfigure",
            {
                CONF_USER_NAME: "user",
                CONF_PASSWORD: "pw",
                CONF_REGION: REGION_EU,
            },
            {},
            "reconfigure",
            "authentication_error",
            True,
        ),
        (
            "async_step_reconfigure_verify_mfa",
            {CONF_VERIFICATION_CODE: "654321"},
            {
                CONF_USER_NAME: "user",
                CONF_PASSWORD: "pw",
                CONF_REGION: REGION_EU,
                CONF_DEVICE_TOKEN: "token",
            },
            "reconfigure_verify_mfa",
            "mfa_error",
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
    expected_error: str,
    needs_entry: bool,
) -> None:
    """Verify missing device serial numbers keep the active auth form open.

    Args:
        flow (MyAirConfigFlow): Config flow handling the selected auth step.
        monkeypatch (pytest.MonkeyPatch): Patch manager for the selected auth helper.
        config_entry (MockConfigEntry): Existing entry for reauth and reconfigure cases.
        step_name (str): Auth step method selected by this parameter case.
        user_input (dict[str, str]): Credentials or MFA code submitted by the case.
        flow_data (dict[str, str]): Transient flow data preloaded before the step.
        expected_step_id (str): Form step ID expected for the selected method.
        expected_error (str): Form error expected when the serial is absent.
        needs_entry (bool): Whether the selected case needs an existing entry attached.
    """
    flow._data = flow_data
    if needs_entry:
        flow._entry = config_entry
    if step_name.startswith("async_step_reconfigure"):
        flow.context = {"source": SOURCE_RECONFIGURE, "entry_id": config_entry.entry_id}
        flow.hass.config_entries.async_get_known_entry = MagicMock(return_value=config_entry)
    device = MyAirDevice.from_api({"fgDeviceManufacturerName": "ResMed", "localizedName": "CPAP"})
    if "verify_mfa" in step_name:
        flow._client = MagicMock(spec=RESTClient)
        monkeypatch.setattr(
            config_flow,
            "get_mfa_device",
            AsyncMock(return_value=(AUTHN_SUCCESS, device)),
        )
    else:
        monkeypatch.setattr(
            config_flow,
            "get_device",
            AsyncMock(return_value=(AUTHN_SUCCESS, device, MagicMock(spec=RESTClient))),
        )

    result = await getattr(flow, step_name)(user_input)

    assert result["type"] == "form"
    assert result["step_id"] == expected_step_id
    assert result["errors"]["base"] == expected_error


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
    """Verify reauth confirm maps each client exception to the expected error path.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch manager for the failing device helper.
        exception (object): Exception instance supplied by the parameterized case.
        expected_error (object): Form error expected for the exception case.
        hass (MagicMock): Home Assistant double attached to the flow.
        config_entry (MockConfigEntry): Existing entry being reauthenticated.
    """
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
    """Verify initial auth and MFA incomplete-account branches converge on abort reasons.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch manager for the selected auth helper.
        step_name (str): Initial auth step method selected by this parameter case.
        helper_path (str): Import path of the helper patched to raise the account error.
        user_input (dict[str, str]): Credentials or MFA code submitted by the case.
        flow_data (dict[str, str]): Transient data preloaded before the step.
        is_email_verified (bool | str | None): Email-check result, including parse-error case.
        client_exists (bool): Whether the case supplies an authenticated client.
        expected_abort_reason (str): Abort reason expected for the account state.
        hass (MagicMock): Home Assistant double attached to the temporary flow.
        myair_client (MagicMock): Client double used by cases that check email verification.
    """
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
    """Verify transient email-check transport failures still preserve the abort.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch manager for the device lookup helper.
        hass (MagicMock): Home Assistant double attached to the flow.
        myair_client (MagicMock): Client whose email check raises the transport error.
        email_error (Exception): Transport exception supplied by this parameterized case.
    """
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
