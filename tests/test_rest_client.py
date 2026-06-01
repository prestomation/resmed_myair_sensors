"""REST client tests that protect auth, GraphQL, and parsing behavior."""

import datetime
import logging
from typing import Never
from unittest.mock import AsyncMock, MagicMock

from aiohttp import ClientResponse
from aiohttp.http_exceptions import HttpProcessingError
from multidict import CIMultiDict
import pytest

from custom_components.resmed_myair.client import rest_client as rest_client_module
from custom_components.resmed_myair.client.auth import MyAirAuthSession
from custom_components.resmed_myair.client.graphql import MyAirGraphQLClient
from custom_components.resmed_myair.client.myair_client import (
    AuthenticationError,
    IncompleteAccountError,
    MyAirConfig,
)
from custom_components.resmed_myair.client.regions import (
    EU_CONFIG,
    NA_CONFIG,
    RegionConfig,
    get_region_config,
)
from custom_components.resmed_myair.client.rest_client import ParsingError, RESTClient
from custom_components.resmed_myair.const import AUTH_NEEDS_MFA, AUTHN_SUCCESS, REGION_EU, REGION_NA
from custom_components.resmed_myair.models import MyAirDevice, MyAirSleepRecord
from tests.conftest import make_mock_aiohttp_context_manager, make_mock_aiohttp_response


@pytest.mark.parametrize(
    ("region", "expected_product", "expected_redirect_url", "expected_authn_url"),
    [
        (
            REGION_NA,
            "myAir",
            "https://myair.resmed.com",
            "https://resmed-ext-1.okta.com/api/v1/authn",
        ),
        (
            REGION_EU,
            "myAir EU",
            "https://myair.resmed.eu",
            "https://id.resmed.eu/api/v1/authn",
        ),
    ],
)
def test_get_region_config_returns_expected_settings(
    region: str,
    expected_product: str,
    expected_redirect_url: str,
    expected_authn_url: str,
) -> None:
    """Region lookups return the expected ResMed endpoint set."""
    config = get_region_config(region)

    assert isinstance(config, RegionConfig)
    assert config.product == expected_product
    assert config.oauth_redirect_url == expected_redirect_url
    assert config.authn_url == expected_authn_url


def test_get_region_config_raises_for_unknown_region() -> None:
    """Unknown region values fail instead of silently selecting another region."""
    with pytest.raises(ValueError, match="Unsupported myAir region"):
        get_region_config("unexpected")


@pytest.mark.parametrize(
    ("attribute_name", "expected_type"),
    [
        ("_auth", MyAirAuthSession),
        ("_graphql", MyAirGraphQLClient),
    ],
)
def test_rest_client_owns_collaborator_wrappers(
    config_na: MyAirConfig,
    session: MagicMock,
    attribute_name: str,
    expected_type: type[object],
) -> None:
    """RESTClient builds dedicated auth and GraphQL wrappers."""
    client = RESTClient(config_na, session)

    assert isinstance(getattr(client, attribute_name), expected_type)
    assert client.device_token == config_na.device_token


@pytest.mark.parametrize(
    ("region", "expected_config"), [(REGION_NA, NA_CONFIG), (REGION_EU, EU_CONFIG)]
)
def test_rest_client_init_region(
    region: str, expected_config: RegionConfig, session: MagicMock
) -> None:
    """RESTClient initialization selects the expected regional settings."""
    config = MyAirConfig(username="user", password="pass", region=region, device_token="token")
    client = RESTClient(config, session)
    assert client._auth.region_config == expected_config
    assert client._auth.email_factor_id == expected_config.email_factor_id
    assert client._auth.mfa_url.startswith("https://")


@pytest.mark.parametrize(
    ("property_name", "new_value"),
    [
        ("json_headers", {"Accept": "application/json"}),
    ],
)
def test_auth_session_property_variants(
    config_na: MyAirConfig,
    session: MagicMock,
    property_name: str,
    new_value: object,
) -> None:
    """Auth session properties expose owned mutable request state."""
    auth = MyAirAuthSession(config_na, session)

    setattr(auth, property_name, new_value)

    assert getattr(auth, property_name) == new_value


@pytest.mark.parametrize("case", ["device_token", "cookies"])
def test_properties_variants(case: str, config_na: MyAirConfig, session: MagicMock) -> None:
    """Device-token and cookie properties mirror the client state."""
    client = RESTClient(config_na, session)
    if case == "device_token":
        assert client.device_token == "token"
    else:
        client._auth.device_token = "dt"
        client._auth.cookie_sid = "sid"
        cookies = client._auth.cookies
        assert cookies["DT"] == "dt"
        assert cookies["sid"] == "sid"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("initial_dt", "initial_sid", "cookie_headers", "expected_dt", "expected_sid", "expect_warn"),
    [
        # Sets both DT and sid
        (None, None, ["DT=abc; Path=/", "sid=xyz; Path=/"], "abc", "xyz", False),
        # No change if cookies are the same
        ("abc", "xyz", ["DT=abc; Path=/", "sid=xyz; Path=/"], "abc", "xyz", False),
        # Case-insensitive cookie names should work too
        (None, None, ["dt=abc; Path=/", "SID=xyz; Path=/"], "abc", "xyz", False),
        # DT was None, should update DT
        (None, "xyz", ["DT=abc; Path=/", "sid=xyz; Path=/"], "abc", "xyz", False),
        # SID changes
        ("abc", "xyz", ["DT=abc; Path=/", "sid=def; Path=/"], "abc", "def", False),
        # Not DT or sid, should not update
        (None, None, ["othercookie=othervalue; Path=/; HttpOnly"], None, None, False),
        # DT changes and initial_dt is not None, should warn without logging token values
        (
            "oldtoken",
            "oldsid",
            ["DT=newtoken; Path=/", "sid=sidvalue; Path=/"],
            "newtoken",
            "sidvalue",
            True,
        ),
    ],
)
async def test_extract_and_update_cookies_variants(
    initial_dt: str | None,
    initial_sid: str | None,
    cookie_headers: list[str],
    expected_dt: str | None,
    expected_sid: str | None,
    expect_warn: bool,
    caplog: pytest.LogCaptureFixture,
    config_na: MyAirConfig,
    session: MagicMock,
) -> None:
    """Cookie extraction updates state, handles casing, and logs rotations safely."""
    # MyAirConfig is a NamedTuple (immutable) so use _replace to change device_token
    config = config_na._replace(device_token=None)
    client = RESTClient(config, session)
    client._auth.device_token = initial_dt
    client._auth.cookie_sid = initial_sid

    with caplog.at_level(logging.DEBUG):
        await client._auth._extract_and_update_cookies(cookie_headers)
    assert client._auth.device_token == expected_dt
    assert client._auth.cookie_sid == expected_sid
    if expect_warn:
        assert "Changing Device Token" in caplog.text
        assert "oldtoken" not in caplog.text
        assert "newtoken" not in caplog.text
        assert "sidvalue" not in caplog.text
    else:
        assert "Changing Device Token" not in caplog.text

    # Check sid update logging when sid changed from a non-None value
    if initial_sid is not None and expected_sid is not None and initial_sid != expected_sid:
        assert "Updating to new sid cookie" in caplog.text
    else:
        assert "Updating to new sid cookie" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "resp_dict", "expected_exception"),
    [
        (
            401,
            {"errors": [{"errorInfo": {"errorType": "unauthorized", "errorCode": "401"}}]},
            AuthenticationError,
        ),
        (
            400,
            {
                "errors": [
                    {
                        "errorInfo": {
                            "errorType": "badRequest",
                            "errorCode": "onboardingFlowInProgress",
                        }
                    }
                ]
            },
            IncompleteAccountError,
        ),
        (400, {"errors": [None]}, HttpProcessingError),
    ],
)
async def test_resmed_response_error_check_variants(
    status: int, resp_dict: dict[str, object], expected_exception: type[BaseException]
) -> None:
    """Response error parsing maps auth and incomplete-account failures correctly."""
    response = MagicMock(spec=ClientResponse)
    response.status = status
    response.headers = CIMultiDict()
    with pytest.raises(expected_exception):
        await MyAirAuthSession.resmed_response_error_check("authn", response, resp_dict)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        "json_value",
        "expected_status",
        "expect_session_token",
        "expect_state_token",
        "expect_email_factor_id",
        "expect_mfa_url_prefix",
    ),
    [
        (
            {"status": "SUCCESS", "sessionToken": "abc"},
            "SUCCESS",
            "abc",
            None,
            None,
            None,
        ),
        (
            {
                "status": "MFA_REQUIRED",
                "stateToken": "state",
                "_embedded": {
                    "factors": [
                        {"id": "factorid", "_links": {"verify": {"href": "https://verify"}}}
                    ]
                },
            },
            "MFA_REQUIRED",
            None,
            "state",
            "factorid",
            "https://verify",
        ),
    ],
)
async def test_authn_check_variants(
    config_na: MyAirConfig,
    session: MagicMock,
    json_value: dict[str, object],
    expected_status: str | None,
    expect_session_token: str | None,
    expect_state_token: str | None,
    expect_email_factor_id: str | None,
    expect_mfa_url_prefix: str | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Auth checks handle success and MFA-required payloads."""
    client = RESTClient(config_na, session)
    mock_response = make_mock_aiohttp_response(json_value=json_value)
    session.post.return_value = make_mock_aiohttp_context_manager(mock_response)
    monkeypatch.setattr(MyAirAuthSession, "resmed_response_error_check", AsyncMock())
    status = await client._auth._authn_check()

    assert status == expected_status
    if expect_session_token is not None:
        assert client._auth.session_token == expect_session_token
    if expect_state_token is not None:
        assert client._auth.state_token == expect_state_token
    if expect_email_factor_id is not None:
        assert client._auth.email_factor_id == expect_email_factor_id
    if expect_mfa_url_prefix is not None:
        assert client._auth.mfa_url.startswith(expect_mfa_url_prefix)


@pytest.mark.asyncio
@pytest.mark.parametrize("json_value", [{}, {"status": "UNKNOWN"}])
async def test_authn_check_invalid_status_raises(
    config_na: MyAirConfig,
    session: MagicMock,
    json_value: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid auth status payloads raise `AuthenticationError`."""
    client = RESTClient(config_na, session)
    mock_response = make_mock_aiohttp_response(json_value=json_value)
    session.post.return_value = make_mock_aiohttp_context_manager(mock_response)
    monkeypatch.setattr(MyAirAuthSession, "resmed_response_error_check", AsyncMock())
    with pytest.raises(AuthenticationError):
        await client._auth._authn_check()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("verify_return", "expect_exception", "expected_status"),
    [
        ("SUCCESS", False, "SUCCESS"),
        ("FAIL", True, None),
    ],
)
async def test_verify_mfa_and_get_access_token_variants(
    config_na: MyAirConfig,
    session: MagicMock,
    verify_return: str,
    expect_exception: bool,
    expected_status: str | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MFA verification either returns the status or raises on failure."""
    client = RESTClient(config_na, session)
    # use monkeypatch to replace instance methods
    client_verify = AsyncMock(return_value=verify_return)
    client_get_access = AsyncMock()
    monkeypatch.setattr(client._auth, "_verify_mfa", client_verify)
    monkeypatch.setattr(client._auth, "_get_access_token", client_get_access)
    if expect_exception:
        with pytest.raises(AuthenticationError):
            await client.verify_mfa_and_get_access_token("123456")
    else:
        status = await client.verify_mfa_and_get_access_token("123456")
        assert status == expected_status


@pytest.mark.asyncio
@pytest.mark.parametrize("cookie_dt", ["dt", "cookie"])
async def test_connect_access_token_active_variants(
    config_na: MyAirConfig, session: MagicMock, cookie_dt: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Active access tokens short-circuit connect to `AUTHN_SUCCESS`."""
    client = RESTClient(config_na, session)
    client._auth.device_token = cookie_dt
    client._auth.access_token = "token"
    # use monkeypatch to replace instance methods
    monkeypatch.setattr(client._auth, "_is_access_token_active", AsyncMock(return_value=True))
    monkeypatch.setattr(client._auth, "_authn_check", AsyncMock())
    monkeypatch.setattr(client._auth, "_get_access_token", AsyncMock())
    result = await client.connect()
    assert result == AUTHN_SUCCESS


@pytest.mark.asyncio
async def test_connect_authn_success(
    config_na: MyAirConfig, session: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Connect performs auth checks before requesting a new access token."""
    client = RESTClient(config_na, session)
    client._auth.device_token = "dt"
    client._auth.access_token = None
    monkeypatch.setattr(client._auth, "_is_access_token_active", AsyncMock(return_value=False))
    monkeypatch.setattr(client._auth, "_authn_check", AsyncMock(return_value="SUCCESS"))
    get_access_token_mock = AsyncMock()
    monkeypatch.setattr(client._auth, "_get_access_token", get_access_token_mock)
    result = await client.connect()
    get_access_token_mock.assert_called_once()
    assert result == "SUCCESS"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("initial", "expect_trigger", "expect_result", "expect_raises"),
    [
        (True, True, "MFA_REQUIRED", False),
        (False, False, None, True),
    ],
)
async def test_connect_needs_mfa_parametrized(
    config_na: MyAirConfig,
    session: MagicMock,
    initial: bool,
    expect_trigger: bool,
    expect_result: object,
    expect_raises: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Connect triggers MFA only on the initial auth path that requires it."""
    client = RESTClient(config_na, session)
    client._auth.device_token = "dt"
    client._auth.access_token = None
    monkeypatch.setattr(client._auth, "_is_access_token_active", AsyncMock(return_value=False))
    monkeypatch.setattr(client._auth, "_authn_check", AsyncMock(return_value="MFA_REQUIRED"))
    trigger_mfa_mock = AsyncMock()
    monkeypatch.setattr(client._auth, "_trigger_mfa", trigger_mfa_mock)
    monkeypatch.setattr(client._auth, "_get_access_token", AsyncMock())

    if expect_raises:
        with pytest.raises(AuthenticationError):
            await client.connect(initial=initial)
    else:
        result = await client.connect(initial=initial)
        assert result == expect_result

    # trigger_mfa should be awaited only when expected
    if expect_trigger:
        trigger_mfa_mock.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("uses_mfa", "expect_warn"),
    [
        (False, False),
        (True, True),
    ],
)
async def test_connect_initial_dt_and_warning_variants(
    config_na: MyAirConfig,
    session: MagicMock,
    caplog: pytest.LogCaptureFixture,
    uses_mfa: bool,
    expect_warn: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Connect fetches an initial DT cookie and warns when MFA is active."""
    client = RESTClient(config_na, session)
    client._auth.device_token = None
    client._auth.uses_mfa = uses_mfa
    client._auth.access_token = None
    get_initial_dt_mock = AsyncMock()
    monkeypatch.setattr(client._auth, "_get_initial_dt", get_initial_dt_mock)
    monkeypatch.setattr(client._auth, "_is_access_token_active", AsyncMock(return_value=False))
    monkeypatch.setattr(client._auth, "_authn_check", AsyncMock(return_value="SUCCESS"))
    monkeypatch.setattr(client._auth, "_get_access_token", AsyncMock())
    with caplog.at_level(logging.WARNING):
        await client.connect()

    get_initial_dt_mock.assert_called_once()
    if expect_warn:
        assert "Device Token isn't set" in caplog.text
    else:
        assert "Device Token isn't set" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("initial", "expect_trigger", "expect_result", "expect_raises"),
    [
        (True, True, AUTH_NEEDS_MFA, False),
        (False, False, None, True),
    ],
)
async def test_connect_status_needs_mfa_parametrized(
    config_na: MyAirConfig,
    session: MagicMock,
    initial: bool,
    expect_trigger: bool,
    expect_result: object,
    expect_raises: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Connect handles `AUTH_NEEDS_MFA` consistently across initial and refresh paths."""
    client = RESTClient(config_na, session)
    client._auth.device_token = "cookie"
    client._auth.access_token = None
    monkeypatch.setattr(client._auth, "_is_access_token_active", AsyncMock(return_value=False))
    monkeypatch.setattr(client._auth, "_authn_check", AsyncMock(return_value=AUTH_NEEDS_MFA))
    trigger_mfa_mock = AsyncMock()
    monkeypatch.setattr(client._auth, "_trigger_mfa", trigger_mfa_mock)
    monkeypatch.setattr(client._auth, "_get_access_token", AsyncMock())

    if expect_raises:
        with pytest.raises(AuthenticationError):
            await client.connect(initial=initial)
    else:
        status = await client.connect(initial=initial)
        assert status == expect_result

    if expect_trigger:
        trigger_mfa_mock.assert_awaited_once()

    assert client._auth.uses_mfa is True


@pytest.mark.asyncio
async def test_resmed_response_error_check_gql_query_not_initial_raises_parsing_error() -> None:
    """Unauthorized GraphQL errors during refresh raise `ParsingError`."""
    # Prepare a fake response and error dict
    response = MagicMock(spec=ClientResponse)
    response.status = 401
    response.headers = CIMultiDict()

    resp_dict = {"errors": [{"errorInfo": {"errorType": "unauthorized", "errorCode": "401"}}]}

    with pytest.raises(ParsingError) as exc:
        await MyAirAuthSession.resmed_response_error_check(
            step="gql_query", response=response, resp_dict=resp_dict, initial=False
        )
    assert "Getting unauthorized error on gql_query step" in str(exc.value)


@pytest.mark.asyncio
async def test_resmed_response_error_check_no_errors_key() -> None:
    """Responses without an `errors` key pass through the checker unchanged."""
    response = MagicMock(spec=ClientResponse)
    response.status = 200
    response.headers = {}

    resp_dict = {"data": {"some": "value"}}

    # Should not raise any exception
    await MyAirAuthSession.resmed_response_error_check(
        step="any_step", response=response, resp_dict=resp_dict, initial=False
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("json_value", "match"),
    [
        (
            {
                "status": AUTH_NEEDS_MFA,
                "_embedded": {
                    "factors": [{"id": "some_id", "_links": {"verify": {"href": "url"}}}]
                },
            },
            "Cannot get stateToken in authn step",
        ),
        (
            {"status": AUTHN_SUCCESS},
            "Cannot get sessionToken in authn step",
        ),
    ],
)
async def test_authn_check_raises_variants(
    config_na: MyAirConfig,
    session: MagicMock,
    json_value: dict[str, object],
    match: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Auth payloads missing required tokens raise `AuthenticationError`."""
    client = RESTClient(config_na, session)

    mock_response = make_mock_aiohttp_response(json_value=json_value)

    # Patch session.post and resmed_response_error_check to not raise
    session.post.return_value = make_mock_aiohttp_context_manager(mock_response)
    monkeypatch.setattr(MyAirAuthSession, "resmed_response_error_check", AsyncMock())
    with pytest.raises(AuthenticationError, match=match):
        await client._auth._authn_check()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "resp_json", "call_arg", "post_assert", "expected"),
    [
        ("_trigger_mfa", {"status": "MFA_CHALLENGE_SENT"}, None, True, None),
        (
            "_verify_mfa",
            {"status": AUTHN_SUCCESS, "sessionToken": "dummy_session_token"},
            "123456",
            False,
            AUTHN_SUCCESS,
        ),
    ],
)
async def test_mfa_methods_success_variants(
    config_na: MyAirConfig,
    session: MagicMock,
    method: object,
    resp_json: object,
    call_arg: object,
    post_assert: object,
    expected: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MFA trigger and verification helpers succeed on valid payloads."""
    client = RESTClient(config_na, session)
    client._auth.state_token = "dummy_state_token"
    client._auth.mfa_url = "https://example.com/mfa"
    client._auth.json_headers = {"Content-Type": "application/json"}
    client._auth.device_token = None
    client._auth.cookie_sid = None

    mock_response = make_mock_aiohttp_response(json_value=resp_json)

    session.post.return_value = make_mock_aiohttp_context_manager(mock_response)
    monkeypatch.setattr(MyAirAuthSession, "resmed_response_error_check", AsyncMock())
    # execute
    if call_arg is None:
        # _trigger_mfa
        await client._auth._trigger_mfa()
        if post_assert:
            session.post.assert_called_once()
            mock_response.json.assert_awaited_once()
    else:
        # _verify_mfa
        status = await client._auth._verify_mfa(call_arg)
        assert status == expected
        assert client._auth.session_token == resp_json.get("sessionToken")


@pytest.mark.asyncio
async def test_json_headers_assignment_forwards_to_auth_trigger_mfa(
    config_na: MyAirConfig,
    session: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Setting RESTClient._json_headers updates delegated auth request headers."""
    client = RESTClient(config_na, session)
    client._auth.state_token = "dummy_state_token"
    client._auth.mfa_url = "https://example.com/mfa"
    client._auth.json_headers = {"Content-Type": "application/json"}
    mock_response = make_mock_aiohttp_response(json_value={"status": "MFA_CHALLENGE_SENT"})
    session.post.return_value = make_mock_aiohttp_context_manager(mock_response)
    monkeypatch.setattr(MyAirAuthSession, "resmed_response_error_check", AsyncMock())

    await client._auth._trigger_mfa()

    assert client._auth.json_headers == {"Content-Type": "application/json"}
    assert session.post.call_args.kwargs["headers"] == {"Content-Type": "application/json"}


@pytest.mark.asyncio
async def test_verify_mfa_debug_logs_do_not_expose_mfa_secrets(
    config_na: MyAirConfig,
    session: MagicMock,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MFA debug logging avoids verification code and state token values."""
    client = RESTClient(config_na, session)
    client._auth.state_token = "dummy_state_token"
    client._auth.mfa_url = "https://example.com/mfa"
    mock_response = make_mock_aiohttp_response(
        json_value={"status": AUTHN_SUCCESS, "sessionToken": "dummy_session_token"}
    )
    session.post.return_value = make_mock_aiohttp_context_manager(mock_response)
    monkeypatch.setattr(MyAirAuthSession, "resmed_response_error_check", AsyncMock())

    with caplog.at_level(logging.DEBUG):
        await client._auth._verify_mfa("654321")

    assert "654321" not in caplog.text
    assert "dummy_state_token" not in caplog.text


@pytest.mark.asyncio
async def test_trigger_mfa_debug_logs_do_not_expose_auth_flow_secrets(
    config_na: MyAirConfig,
    session: MagicMock,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MFA trigger debug logging avoids state, session, and passcode values."""
    client = RESTClient(config_na, session)
    client._auth.state_token = "dummy_state_token"
    client._auth.mfa_url = "https://example.com/mfa"
    mock_response = make_mock_aiohttp_response(
        json_value={
            "status": "MFA_CHALLENGE_SENT",
            "stateToken": "response_state_token",
            "sessionToken": "response_session_token",
            "_embedded": {"verification": {"passCode": "nested_pass_code"}},
        }
    )
    session.post.return_value = make_mock_aiohttp_context_manager(mock_response)
    error_check = AsyncMock()
    monkeypatch.setattr(MyAirAuthSession, "resmed_response_error_check", error_check)

    with caplog.at_level(logging.DEBUG):
        await client._auth._trigger_mfa()

    mock_response.json.assert_awaited_once()
    error_check.assert_awaited_once_with(
        "trigger_mfa",
        mock_response,
        {
            "status": "MFA_CHALLENGE_SENT",
            "stateToken": "response_state_token",
            "sessionToken": "response_session_token",
            "_embedded": {"verification": {"passCode": "nested_pass_code"}},
        },
    )
    assert "response_state_token" not in caplog.text
    assert "response_session_token" not in caplog.text
    assert "nested_pass_code" not in caplog.text


@pytest.mark.asyncio
async def test_get_access_token_debug_logs_do_not_expose_oauth_secrets(
    config_na: MyAirConfig,
    session: MagicMock,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OAuth debug logging avoids session token, auth code, and verifier values."""
    client = RESTClient(config_na, session)
    client._auth.session_token = "dummy_session_token"

    mock_code_res = make_mock_aiohttp_response()
    mock_code_res.headers = MagicMock()
    mock_code_res.headers.getall = MagicMock(return_value=[])
    mock_code_res.headers.get = MagicMock(return_value="https://redirect#code=secret_auth_code")
    mock_token_res = make_mock_aiohttp_response(
        json_value={"access_token": "access_token_value", "id_token": "id_token_value"}
    )
    session.get.return_value = make_mock_aiohttp_context_manager(mock_code_res)
    session.post.return_value = make_mock_aiohttp_context_manager(mock_token_res)
    monkeypatch.setattr(
        "custom_components.resmed_myair.client.auth.urldefrag",
        lambda *a, **k: MagicMock(fragment="code=secret_auth_code"),
    )
    monkeypatch.setattr(
        "custom_components.resmed_myair.client.auth.parse_qs",
        lambda *a, **k: {"code": ["secret_auth_code"]},
    )
    monkeypatch.setattr(client._auth, "_extract_and_update_cookies", AsyncMock())
    monkeypatch.setattr(MyAirAuthSession, "resmed_response_error_check", AsyncMock())

    with caplog.at_level(logging.DEBUG):
        await client._auth._get_access_token()

    assert "dummy_session_token" not in caplog.text
    assert "secret_auth_code" not in caplog.text
    assert "code_verifier" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("json_value", "match"),
    [
        ({}, "Cannot get status in verify_mfa step"),
        ({"status": AUTHN_SUCCESS}, "Cannot get sessionToken in verify_mfa step"),
        ({"status": "FAIL"}, "Unknown status in verify_mfa step: FAIL"),
    ],
)
async def test_verify_mfa_raises_variants(
    config_na: MyAirConfig,
    session: MagicMock,
    json_value: dict[str, object],
    match: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid MFA verification responses raise `AuthenticationError`."""
    client = RESTClient(config_na, session)
    client._auth.state_token = "dummy_state_token"
    client._auth.mfa_url = "https://example.com/mfa"
    client._auth.json_headers = {"Content-Type": "application/json"}
    client._auth.device_token = None
    client._auth.cookie_sid = None

    mock_response = make_mock_aiohttp_response(json_value=json_value)

    session.post.return_value = make_mock_aiohttp_context_manager(mock_response)
    monkeypatch.setattr(MyAirAuthSession, "resmed_response_error_check", AsyncMock())
    with pytest.raises(AuthenticationError, match=match):
        await client._auth._verify_mfa("123456")


@pytest.mark.asyncio
async def test_get_access_token_success(
    config_na: MyAirConfig, session: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Successful token exchange stores the access and ID tokens."""
    client = RESTClient(config_na, session)
    client._auth.session_token = "dummy_session_token"
    client._auth.json_headers = {"Content-Type": "application/json"}
    client._auth.device_token = None
    client._auth.cookie_sid = None

    # Mock the GET authorize response (with location header behavior) and POST token response
    mock_code_res = make_mock_aiohttp_response()
    # give headers behavior expected by the code under test
    mock_code_res.headers = MagicMock()
    mock_code_res.headers.getall = MagicMock(return_value=["https://redirect#code=abc123"])
    mock_code_res.headers.get = MagicMock(return_value="https://redirect#code=abc123")

    mock_token_res = make_mock_aiohttp_response(
        json_value={"access_token": "access_token_value", "id_token": "id_token_value"}
    )

    # Patch urldefrag and parse_qs to simulate code extraction
    session.get.return_value = make_mock_aiohttp_context_manager(mock_code_res)
    session.post.return_value = make_mock_aiohttp_context_manager(mock_token_res)
    monkeypatch.setattr(
        "custom_components.resmed_myair.client.auth.urldefrag",
        lambda *a, **k: MagicMock(fragment="code=abc123"),
    )
    monkeypatch.setattr(
        "custom_components.resmed_myair.client.auth.parse_qs",
        lambda *a, **k: {"code": ["the_code"]},
    )
    mock_extract = AsyncMock()
    monkeypatch.setattr(client._auth, "_extract_and_update_cookies", mock_extract)
    monkeypatch.setattr(MyAirAuthSession, "resmed_response_error_check", AsyncMock())

    await client._auth._get_access_token()
    mock_extract.assert_awaited_once()
    assert client._auth.access_token == "access_token_value"
    assert client._auth.id_token == "id_token_value"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("redirect_location", "fragment", "parsed_fragment", "match_msg"),
    [
        (None, "", {}, "Unable to get location from code_res"),
        (
            "https://redirect#error=access_denied",
            "error=access_denied",
            {"error": ["access_denied"]},
            "Authorization code missing",
        ),
    ],
)
async def test_get_access_token_raises_on_invalid_authorization_redirect(
    config_na: MyAirConfig,
    session: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    redirect_location: str | None,
    fragment: str,
    parsed_fragment: dict[str, list[str]],
    match_msg: str,
) -> None:
    """Invalid authorization redirects raise `ParsingError` before token exchange."""
    client = RESTClient(config_na, session)
    client._auth.session_token = "dummy_session_token"
    client._auth.json_headers = {"Content-Type": "application/json"}

    mock_code_res = make_mock_aiohttp_response()
    mock_code_res.headers = MagicMock()
    mock_code_res.headers.getall = MagicMock(return_value=[])
    mock_code_res.headers.get = MagicMock(return_value=redirect_location)

    session.get.return_value = make_mock_aiohttp_context_manager(mock_code_res)
    monkeypatch.setattr(
        "custom_components.resmed_myair.client.auth.urldefrag",
        lambda *a, **k: MagicMock(fragment=fragment),
    )
    monkeypatch.setattr(
        "custom_components.resmed_myair.client.auth.parse_qs",
        lambda *a, **k: parsed_fragment,
    )
    monkeypatch.setattr(client._auth, "_extract_and_update_cookies", AsyncMock())
    monkeypatch.setattr(MyAirAuthSession, "resmed_response_error_check", AsyncMock())

    with pytest.raises(ParsingError, match=match_msg):
        await client._auth._get_access_token()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("token_json", "match_msg"),
    [
        ({"id_token": "id_token_value"}, "access_token not in token_dict"),
        ({"access_token": "access_token_value"}, "id_token not in token_dict"),
    ],
)
async def test_get_access_token_raises_on_missing_token_variants(
    config_na: MyAirConfig,
    session: MagicMock,
    token_json: object,
    match_msg: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Token responses missing required keys raise `ParsingError`."""
    client = RESTClient(config_na, session)
    client._auth.session_token = "dummy_session_token"
    client._auth.json_headers = {"Content-Type": "application/json"}
    client._auth.device_token = None
    client._auth.cookie_sid = None

    mock_code_res = make_mock_aiohttp_response()
    # Provide headers with location behavior expected by code under test
    mock_code_res.headers = MagicMock()
    # Provide header accessors used by production code
    mock_code_res.headers.getall = MagicMock(return_value=["https://redirect#code=abc123"])
    mock_code_res.headers.get = MagicMock(return_value="https://redirect#code=abc123")
    mock_code_res.json = AsyncMock()

    mock_token_res = make_mock_aiohttp_response(json_value=token_json)

    session.get.return_value = make_mock_aiohttp_context_manager(mock_code_res)
    monkeypatch.setattr(
        session, "post", lambda *args, **kwargs: make_mock_aiohttp_context_manager(mock_token_res)
    )
    monkeypatch.setattr(
        "custom_components.resmed_myair.client.auth.urldefrag",
        lambda *a, **k: MagicMock(fragment="code=abc123"),
    )
    monkeypatch.setattr(
        "custom_components.resmed_myair.client.auth.parse_qs",
        lambda *a, **k: {"code": ["the_code"]},
    )
    monkeypatch.setattr(client._auth, "_extract_and_update_cookies", AsyncMock())
    monkeypatch.setattr(MyAirAuthSession, "resmed_response_error_check", AsyncMock())
    with pytest.raises(ParsingError, match=match_msg):
        await client._auth._get_access_token()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("jwt_behavior", "post_json", "expect_exception", "expected_country"),
    [
        ("valid", {"data": {"foo": "bar"}}, False, "US"),
        ("invalid", None, True, None),
    ],
)
async def test_gql_query_variants(
    config_na: MyAirConfig,
    session: MagicMock,
    jwt_behavior: object,
    post_json: object,
    expect_exception: bool,
    expected_country: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GraphQL queries decode country data and surface JWT failures."""
    client = RESTClient(config_na, session)
    client._auth.access_token = "access"
    client._auth.id_token = "idtoken"
    client._graphql.country_code = None

    if jwt_behavior == "valid":
        # jwt.decode returns a payload including myAirCountryId
        monkeypatch.setattr(
            "custom_components.resmed_myair.client.graphql.jwt.decode",
            lambda *a, **k: {"myAirCountryId": expected_country},
        )
        monkeypatch.setattr(
            session,
            "post",
            lambda *args, **kwargs: make_mock_aiohttp_context_manager(
                MagicMock(json=AsyncMock(return_value=post_json))
            ),
        )
        monkeypatch.setattr(MyAirAuthSession, "resmed_response_error_check", AsyncMock())
        result = await client._gql_query("op", "query")
        assert result == post_json
        assert client._graphql.country_code == expected_country
    else:

        def bad_decode(*a: object, **k: object) -> Never:
            """Simulate a JWT decoder failure while preserving monkeypatch signature.

            Args:
                *a: Positional arguments passed by the GraphQL client.
                **k: Keyword arguments passed by the GraphQL client.

            Raises:
                ValueError: Always raised to drive the parsing-error branch.
            """
            raise ValueError("bad jwt")

        monkeypatch.setattr(
            "custom_components.resmed_myair.client.graphql.jwt.decode",
            bad_decode,
        )
        with pytest.raises(ParsingError, match="Unable to decode id_token into jwt_data"):
            await client._gql_query("op", "query")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("id_token", "jwt_behavior", "match"),
    [
        (
            "idtoken",
            {"side_effect": ValueError("bad jwt")},
            "Unable to decode id_token into jwt_data",
        ),
        ("idtoken", {"return_value": {}}, "myAirCountryId not found in jwt_data"),
        (None, None, "country_code not defined and id_token not present to identify it"),
    ],
)
async def test_gql_query_failure_variants(
    config_na: MyAirConfig,
    session: MagicMock,
    id_token: object,
    jwt_behavior: object,
    match: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GraphQL query failures cover JWT decode, missing country, and missing ID token."""
    client = RESTClient(config_na, session)
    client._auth.access_token = "access"
    client._auth.id_token = id_token
    client._graphql.country_code = None

    if id_token is not None and jwt_behavior is not None:
        # Configure jwt.decode according to jwt_behavior dict
        if "side_effect" in jwt_behavior:

            def side(*a: object, **k: object) -> Never:
                """Raise the configured JWT decode error for this parameter set.

                Args:
                    *a: Positional arguments passed by the GraphQL client.
                    **k: Keyword arguments passed by the GraphQL client.

                Raises:
                    Exception: The specific side effect supplied by the test case.
                """
                raise jwt_behavior["side_effect"]

            monkeypatch.setattr(
                "custom_components.resmed_myair.client.graphql.jwt.decode",
                side,
            )
            with pytest.raises(ParsingError, match=match):
                await client._gql_query("op", "query")
        else:
            monkeypatch.setattr(
                "custom_components.resmed_myair.client.graphql.jwt.decode",
                lambda *a, **k: jwt_behavior.get("return_value", {}),
            )
            with pytest.raises(ParsingError, match=match):
                await client._gql_query("op", "query")
    else:
        # No id_token provided -> immediate failure
        with pytest.raises(ParsingError, match=match):
            await client._gql_query("op", "query")


@pytest.mark.asyncio
async def test_gql_query_graphql_error(config_na: MyAirConfig, session: MagicMock) -> None:
    """GraphQL unauthorized responses map to `ParsingError`."""
    client = RESTClient(config_na, session)
    client._auth.access_token = "access"
    client._auth.id_token = None
    client._graphql.country_code = "US"

    mock_res = MagicMock(spec=ClientResponse)
    mock_res.json = AsyncMock(
        return_value={"errors": [{"errorInfo": {"errorType": "unauthorized", "errorCode": "401"}}]}
    )

    session.post.return_value = make_mock_aiohttp_context_manager(mock_res)
    with pytest.raises(ParsingError, match="unauthorized: 401"):
        await client._gql_query("op", "query")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method_name", "mock_response", "expected"),
    [
        (
            "get_sleep_records",
            {
                "data": {
                    "getPatientWrapper": {
                        "sleepRecords": {
                            "items": [
                                {
                                    "startDate": "2024-07-01",
                                    "totalUsage": 123,
                                    "sleepScore": 90,
                                    "usageScore": 80,
                                    "ahiScore": 70,
                                    "maskScore": 60,
                                    "leakScore": 50,
                                    "ahi": 1.2,
                                    "maskPairCount": 1,
                                    "leakPercentile": 5,
                                    "sleepRecordPatientId": "abc",
                                    "__typename": "SleepRecord",
                                }
                            ]
                        }
                    }
                }
            },
            [
                {
                    "startDate": "2024-07-01",
                    "totalUsage": 123,
                    "sleepScore": 90,
                    "usageScore": 80,
                    "ahiScore": 70,
                    "maskScore": 60,
                    "leakScore": 50,
                    "ahi": 1.2,
                    "maskPairCount": 1,
                    "leakPercentile": 5,
                    "sleepRecordPatientId": "abc",
                    "__typename": "SleepRecord",
                }
            ],
        ),
        (
            "get_user_device_data",
            {
                "data": {
                    "getPatientWrapper": {
                        "fgDevices": [
                            {
                                "serialNumber": "12345",
                                "deviceType": "CPAP",
                                "lastSleepDataReportTime": "2024-07-01T00:00:00Z",
                                "localizedName": "My CPAP",
                                "fgDeviceManufacturerName": "ResMed",
                                "fgDevicePatientId": "abc",
                                "__typename": "FgDevice",
                            }
                        ]
                    }
                }
            },
            {
                "serialNumber": "12345",
                "deviceType": "CPAP",
                "lastSleepDataReportTime": "2024-07-01T00:00:00Z",
                "localizedName": "My CPAP",
                "fgDeviceManufacturerName": "ResMed",
                "fgDevicePatientId": "abc",
                "__typename": "FgDevice",
            },
        ),
    ],
)
async def test_data_fetch_success_variants(
    config_na: MyAirConfig,
    session: MagicMock,
    method_name: object,
    mock_response: object,
    expected: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Data fetch helpers return typed models for sleep records and device data."""
    client = RESTClient(config_na, session)
    client._auth.access_token = "access"
    client._graphql.country_code = "US"
    monkeypatch.setattr(client, "_gql_query", AsyncMock(return_value=mock_response))
    target = client._auth if method_name == "_is_access_token_active" else client
    result = await getattr(target, method_name)()
    if method_name == "get_sleep_records":
        assert isinstance(result, list)
        assert isinstance(result[0], MyAirSleepRecord)
        assert result[0].total_usage_minutes == expected[0]["totalUsage"]  # type: ignore[index]
        assert result[0].raw == expected[0]
    else:
        assert isinstance(result, MyAirDevice)
        assert result.raw == expected
        assert result.serial_number == expected.get("serialNumber")
        assert result.native_value("serialNumber") == expected.get("serialNumber")


@pytest.mark.asyncio
async def test_get_sleep_records_uses_local_date_range(
    config_na: MyAirConfig, session: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sleep-record queries use the local month window."""

    class FixedDateTime(datetime.datetime):
        """DateTime class with deterministic now() for query-window assertions."""

        @classmethod
        def now(cls, tz: datetime.tzinfo | None = None) -> datetime.datetime:
            """Return a fixed timezone-aware timestamp for the date window."""
            return cls(2024, 7, 31, 12, tzinfo=tz)

    client = RESTClient(config_na, session)
    monkeypatch.setattr(rest_client_module.datetime, "datetime", FixedDateTime)
    gql_query = AsyncMock(
        return_value={"data": {"getPatientWrapper": {"sleepRecords": {"items": []}}}}
    )
    monkeypatch.setattr(client, "_gql_query", gql_query)

    await client.get_sleep_records()

    gql_query.assert_awaited_once()
    query = gql_query.await_args.args[1]
    assert 'sleepRecords(startMonth: "2024-07-01", endMonth: "2024-07-31")' in query


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mock_response", "match_msg"),
    [
        ({"data": {"getPatientWrapper": {}}}, "Error getting Patient Sleep Records"),
        (
            {"data": {"getPatientWrapper": {"sleepRecords": {"items": "notalist"}}}},
            "Returned records is not a list",
        ),
    ],
)
async def test_get_sleep_records_failure_variants(
    config_na: MyAirConfig,
    session: MagicMock,
    mock_response: object,
    match_msg: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sleep-record fetches raise `ParsingError` for malformed payloads."""
    client = RESTClient(config_na, session)
    client._auth.access_token = "access"
    client._graphql.country_code = "US"
    monkeypatch.setattr(client, "_gql_query", AsyncMock(return_value=mock_response))
    with pytest.raises(ParsingError, match=match_msg):
        await client.get_sleep_records()


@pytest.mark.asyncio
async def test_get_sleep_records_raises_parsing_error_for_non_mapping_items(
    config_na: MyAirConfig,
    session: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sleep-record list items must be mappings before model parsing."""
    client = RESTClient(config_na, session)
    mock_response = {"data": {"getPatientWrapper": {"sleepRecords": {"items": [123]}}}}
    monkeypatch.setattr(client, "_gql_query", AsyncMock(return_value=mock_response))

    with pytest.raises(ParsingError, match="Returned record item is not a mapping"):
        await client.get_sleep_records()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mock_response", "match_msg"),
    [
        ({"data": {"getPatientWrapper": {}}}, "Error getting User Device Data"),
        (
            {"data": {"getPatientWrapper": {"fgDevices": []}}},
            "Error getting User Device Data",
        ),
        (
            {"data": {"getPatientWrapper": {"fgDevices": ["notadict"]}}},
            "Returned data is not a dict",
        ),
        (
            {
                "data": {
                    "getPatientWrapper": {
                        "fgDevices": ["notadict"],
                        "masks": [{"maskCode": "MASK123"}],
                    }
                }
            },
            "Returned data is not a dict",
        ),
    ],
)
async def test_get_user_device_data_failure_variants(
    config_na: MyAirConfig,
    session: MagicMock,
    mock_response: object,
    match_msg: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Device-data fetches raise `ParsingError` for malformed payloads."""
    client = RESTClient(config_na, session)
    client._auth.access_token = "access"
    client._graphql.country_code = "US"
    monkeypatch.setattr(client, "_gql_query", AsyncMock(return_value=mock_response))
    with pytest.raises(ParsingError, match=match_msg):
        await client.get_user_device_data()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("masks", "expect_warning", "expected_mask"),
    [
        ([{"maskCode": "MASK123"}], False, "MASK123"),
        ([{"maskCode": ""}], False, None),
        ([], True, None),
        ("not-a-list", True, None),
        ([123], True, None),
        ([{}], True, None),
        ([{"maskCode": 123}], True, None),
    ],
)
async def test_get_user_device_data_masks_variants(
    config_na: MyAirConfig,
    session: MagicMock,
    masks: object,
    expect_warning: object,
    expected_mask: object,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Device-data mask handling preserves valid masks and warns on misses."""
    client = RESTClient(config_na, session)
    client._auth.access_token = "access"
    client._graphql.country_code = "US"

    device = {"serialNumber": "12345"}
    mock_response = {"data": {"getPatientWrapper": {"fgDevices": [device], "masks": masks}}}
    monkeypatch.setattr(client, "_gql_query", AsyncMock(return_value=mock_response))

    with caplog.at_level(logging.WARNING):
        result = await client.get_user_device_data()

    if expect_warning:
        assert "Error getting User Mask Data" in caplog.text
    else:
        assert "Error getting User Mask Data" not in caplog.text

    if expected_mask:
        assert result.raw["maskCode"] == expected_mask
    else:
        assert "maskCode" not in result.raw


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("cookie_headers", "expected_extract_arg"),
    [
        (["DT=token; Path=/;"], ["DT=token; Path=/;"]),
        ([], []),
    ],
)
async def test_get_initial_dt_variants(
    config_na: MyAirConfig,
    session: MagicMock,
    cookie_headers: list[str],
    expected_extract_arg: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Initial DT extraction handles present and missing cookie headers."""
    client = RESTClient(config_na, session)
    mock_headers = MagicMock()
    mock_headers.getall = MagicMock(return_value=cookie_headers)
    mock_response = MagicMock()
    mock_response.headers = mock_headers

    session.get.return_value = make_mock_aiohttp_context_manager(mock_response)
    mock_extract = AsyncMock()
    monkeypatch.setattr(client._auth, "_extract_and_update_cookies", mock_extract)
    await client._auth._get_initial_dt()
    session.get.assert_called_once()
    mock_extract.assert_called_once_with(expected_extract_arg)


@pytest.mark.asyncio
async def test_resmed_response_error_check_not_bad_request() -> None:
    """Non-matching response errors do not become incomplete-account failures."""
    # Prepare a fake response and error dict
    resp_dict = {
        "errors": [{"errorInfo": {"errorType": "someOtherType", "errorCode": "someOtherCode"}}]
    }
    response = MagicMock(spec=ClientResponse)
    response.status = 400
    response.headers = CIMultiDict()

    # Should raise HttpProcessingError, not IncompleteAccountError
    with pytest.raises(HttpProcessingError) as exc:
        await MyAirAuthSession.resmed_response_error_check("gql_query", response, resp_dict)
    # Ensure the error message does not mention onboardingFlowInProgress or equipmentNotAssigned
    assert "onboardingFlowInProgress" not in str(exc.value)
    assert "equipmentNotAssigned" not in str(exc.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "authn_dict",
    [
        # KeyError: _embedded missing
        {
            "status": "MFA_REQUIRED",
            "stateToken": "token123",
            # '_embedded' missing
        },
        # TypeError: _embedded is not subscriptable
        {
            "status": "MFA_REQUIRED",
            "stateToken": "token123",
            "_embedded": None,
        },
    ],
)
async def test_authn_check_email_factor_id_exceptions(
    authn_dict: object, session: MagicMock, config_na: MyAirConfig
) -> None:
    """Auth checks fall back to the region email-factor ID on lookup errors."""
    # MyAirConfig is a NamedTuple (immutable) so use _replace to change device_token
    config = config_na._replace(device_token=None)
    client = RESTClient(config, session)

    # Patch session.post to return a mock response with .json() returning authn_dict
    mock_response = make_mock_aiohttp_response(json_value=authn_dict)
    session.post.return_value = make_mock_aiohttp_context_manager(mock_response)

    # Should NOT raise, but should set _email_factor_id to region_config.email_factor_id
    result = await client._auth._authn_check()
    assert client._auth.email_factor_id == client._auth.region_config.email_factor_id
    assert result == "MFA_REQUIRED"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("returned_token", "expect_log", "expect_change"),
    [
        ("abc123", False, False),
        ("newtoken456", True, True),
    ],
)
async def test_get_access_token_token_change_and_logging(
    config_na: MyAirConfig,
    session: MagicMock,
    caplog: pytest.LogCaptureFixture,
    returned_token: object,
    expect_log: object,
    expect_change: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Token rotation logging distinguishes unchanged and updated access tokens."""
    # MyAirConfig is a NamedTuple (immutable) so create a modified copy
    config = config_na._replace(device_token=None)
    client = RESTClient(config, session)

    # Set up the client with an existing access token
    client._auth.access_token = "abc123"

    # Patch the GET to authorize_url to return a location header with a code
    headers = MagicMock()
    headers.get.return_value = "https://redirect#code=thecode"
    headers.getall.return_value = []
    mock_code_res = make_mock_aiohttp_response(json_value=None, headers=headers)
    session.get.return_value = make_mock_aiohttp_context_manager(mock_code_res)

    # Patch the POST to token_url to return a token_dict with the parametrized access_token
    mock_token_res = make_mock_aiohttp_response(
        json_value={"access_token": returned_token, "id_token": "idtoken"}
    )
    session.post.return_value = make_mock_aiohttp_context_manager(mock_token_res)

    # Patch error check to do nothing and always capture INFO logs
    monkeypatch.setattr(MyAirAuthSession, "resmed_response_error_check", AsyncMock())
    with caplog.at_level(logging.INFO):
        await client._auth._get_access_token()

    # Assert token updated only when expected
    expected_token = "abc123" if not expect_change else returned_token
    assert client._auth.access_token == expected_token

    # Ensure logging behavior matches expectation
    if expect_log:
        assert "Obtained new access token" in caplog.text
    else:
        assert "Obtained new access token" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method_name", "session_method", "response_json", "expected"),
    [
        ("_is_access_token_active", "post", {"active": True}, True),
        ("_is_access_token_active", "post", {"active": False}, False),
        ("is_email_verified", "get", {"email_verified": True}, True),
        ("is_email_verified", "get", {"email_verified": False}, False),
    ],
)
async def test_status_helpers_variants(
    config_na: MyAirConfig,
    session: MagicMock,
    method_name: object,
    session_method: object,
    response_json: object,
    expected: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Small auth endpoint helpers return the expected boolean states."""
    client = RESTClient(config_na, session)
    client._auth.access_token = "token"
    mock_res = make_mock_aiohttp_response(json_value=response_json, headers={})
    mock_res.status = 200
    # Attach the context manager as the return value of the appropriate session method
    if session_method == "post":
        session.post.return_value = make_mock_aiohttp_context_manager(mock_res)
    else:
        session.get.return_value = make_mock_aiohttp_context_manager(mock_res)
    monkeypatch.setattr(MyAirAuthSession, "resmed_response_error_check", AsyncMock())
    target = client._auth if method_name == "_is_access_token_active" else client
    result = await getattr(target, method_name)()
    assert result is expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("resp_dict", "expected_substring"),
    [
        ({"errors": [{"message": "custom error message"}]}, "custom error message"),
        ({"errors": [{"foo": "bar"}]}, "'foo': 'bar'"),
        ({"errors": [{"errorInfo": None}]}, "Unable to parse error message"),
    ],
)
async def test_resmed_response_error_check_parsing_variants(
    resp_dict: dict[str, object], expected_substring: object
) -> None:
    """Response-error parsing falls back cleanly across malformed payloads."""
    response = MagicMock(spec=ClientResponse)
    response.status = 400
    response.headers = CIMultiDict()

    with pytest.raises(HttpProcessingError) as exc:
        await MyAirAuthSession.resmed_response_error_check("any_step", response, resp_dict)
    assert expected_substring in str(exc.value)
