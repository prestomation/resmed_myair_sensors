"""Unit tests for the REST client used by the resmed_myair integration."""

import logging
from unittest.mock import AsyncMock, MagicMock

from aiohttp import ClientResponse
from aiohttp.http_exceptions import HttpProcessingError
from multidict import CIMultiDict
import pytest

from custom_components.resmed_myair.client.myair_client import (
    AuthenticationError,
    IncompleteAccountError,
    MyAirConfig,
)
from custom_components.resmed_myair.client.rest_client import (
    AUTH_NEEDS_MFA,
    AUTHN_SUCCESS,
    EU_CONFIG,
    NA_CONFIG,
    ParsingError,
    RESTClient,
)
from tests.conftest import make_mock_aiohttp_context_manager, make_mock_aiohttp_response


@pytest.mark.parametrize("region,expected_config", [("NA", NA_CONFIG), ("EU", EU_CONFIG)])
def test_rest_client_init_region(region, expected_config, session):
    """Test RESTClient initialization for both NA and EU regions."""
    config = MyAirConfig(username="user", password="pass", region=region, device_token="token")
    client = RESTClient(config, session)
    assert client._region_config == expected_config
    assert client._email_factor_id == expected_config["email_factor_id"]
    assert client._mfa_url.startswith("https://")


@pytest.mark.parametrize("case", ["device_token", "cookies"])
def test_properties_variants(case, config_na, session):
    """Parametrized: small property checks for device_token and _cookies."""
    client = RESTClient(config_na, session)
    if case == "device_token":
        assert client.device_token == "token"
    else:
        client._cookie_dt = "dt"
        client._cookie_sid = "sid"
        cookies = client._cookies
        assert cookies["DT"] == "dt"
        assert cookies["sid"] == "sid"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "initial_dt, initial_sid, cookie_headers, expected_dt, expected_sid, expect_warn",
    [
        # Sets both DT and sid
        (None, None, ["DT=abc; Path=/", "sid=xyz; Path=/"], "abc", "xyz", False),
        # No change if cookies are the same
        ("abc", "xyz", ["DT=abc; Path=/", "sid=xyz; Path=/"], "abc", "xyz", False),
        # DT was None, should update DT
        (None, "xyz", ["DT=abc; Path=/", "sid=xyz; Path=/"], "abc", "xyz", False),
        # SID changes
        ("abc", "xyz", ["DT=abc; Path=/", "sid=def; Path=/"], "abc", "def", False),
        # Not DT or sid, should not update
        (None, None, ["othercookie=othervalue; Path=/; HttpOnly"], None, None, False),
        # DT changes and initial_dt is not None, should warn
        ("oldtoken", None, ["DT=newtoken; Path=/"], "newtoken", None, True),
    ],
)
async def test_extract_and_update_cookies_variants(
    initial_dt,
    initial_sid,
    cookie_headers,
    expected_dt,
    expected_sid,
    expect_warn,
    caplog,
    config_na,
    session,
):
    """Parametrized test for _extract_and_update_cookies covering all branches, including warning."""
    # MyAirConfig is a NamedTuple (immutable) so use _replace to change device_token
    config = config_na._replace(device_token=None)
    client = RESTClient(config, session)
    client._cookie_dt = initial_dt
    client._cookie_sid = initial_sid

    with caplog.at_level(logging.WARNING):
        await client._extract_and_update_cookies(cookie_headers)
    assert client._cookie_dt == expected_dt
    assert client._cookie_sid == expected_sid
    if expect_warn:
        assert (
            "Changing Device Token" in caplog.text
            and "oldtoken" in caplog.text
            and "newtoken" in caplog.text
        )
    else:
        assert "Changing Device Token" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,resp_dict,expected_exception",
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
async def test_resmed_response_error_check_variants(status, resp_dict, expected_exception):
    """Parametrized tests for various error responses in _resmed_response_error_check."""
    response = MagicMock(spec=ClientResponse)
    response.status = status
    response.headers = {}
    with pytest.raises(expected_exception):
        await RESTClient._resmed_response_error_check("authn", response, resp_dict)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "json_value,expected_status,expect_session_token,expect_state_token,expect_email_factor_id,expect_mfa_url_prefix",
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
    config_na,
    session,
    json_value,
    expected_status,
    expect_session_token,
    expect_state_token,
    expect_email_factor_id,
    expect_mfa_url_prefix,
    monkeypatch,
):
    """Parametrized tests for _authn_check success and MFA_REQUIRED paths."""
    client = RESTClient(config_na, session)
    mock_response = make_mock_aiohttp_response(json_value=json_value)
    session.post.return_value = make_mock_aiohttp_context_manager(mock_response)
    monkeypatch.setattr(RESTClient, "_resmed_response_error_check", AsyncMock())
    status = await client._authn_check()

    assert status == expected_status
    if expect_session_token is not None:
        assert client._session_token == expect_session_token
    if expect_state_token is not None:
        assert client._state_token == expect_state_token
    if expect_email_factor_id is not None:
        assert client._email_factor_id == expect_email_factor_id
    if expect_mfa_url_prefix is not None:
        assert client._mfa_url.startswith(expect_mfa_url_prefix)


@pytest.mark.asyncio
@pytest.mark.parametrize("json_value", [{}, {"status": "UNKNOWN"}])
async def test_authn_check_invalid_status_raises(config_na, session, json_value, monkeypatch):
    """Parametrized: _authn_check should raise AuthenticationError for invalid status payloads."""
    client = RESTClient(config_na, session)
    mock_response = make_mock_aiohttp_response(json_value=json_value)
    session.post.return_value = make_mock_aiohttp_context_manager(mock_response)
    monkeypatch.setattr(RESTClient, "_resmed_response_error_check", AsyncMock())
    with pytest.raises(AuthenticationError):
        await client._authn_check()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "verify_return,expect_exception,expected_status",
    [
        ("SUCCESS", False, "SUCCESS"),
        ("FAIL", True, None),
    ],
)
async def test_verify_mfa_and_get_access_token_variants(
    config_na, session, verify_return, expect_exception, expected_status, monkeypatch
):
    """Parametrized: verify_mfa_and_get_access_token success and failure paths."""
    client = RESTClient(config_na, session)
    # use monkeypatch to replace instance methods
    client_verify = AsyncMock(return_value=verify_return)
    client_get_access = AsyncMock()
    monkeypatch.setattr(client, "_verify_mfa", client_verify)
    monkeypatch.setattr(client, "_get_access_token", client_get_access)
    if expect_exception:
        with pytest.raises(AuthenticationError):
            await client.verify_mfa_and_get_access_token("123456")
    else:
        status = await client.verify_mfa_and_get_access_token("123456")
        assert status == expected_status


@pytest.mark.asyncio
@pytest.mark.parametrize("cookie_dt", ["dt", "cookie"])
async def test_connect_access_token_active_variants(config_na, session, cookie_dt, monkeypatch):
    """Parametrized: connect returns AUTHN_SUCCESS when access token is active (different cookie values)."""
    client = RESTClient(config_na, session)
    client._cookie_dt = cookie_dt
    client._access_token = "token"
    # use monkeypatch to replace instance methods
    monkeypatch.setattr(client, "_is_access_token_active", AsyncMock(return_value=True))
    monkeypatch.setattr(client, "_authn_check", AsyncMock())
    monkeypatch.setattr(client, "_get_access_token", AsyncMock())
    result = await client.connect()
    assert result == AUTHN_SUCCESS


@pytest.mark.asyncio
async def test_connect_authn_success(config_na, session, monkeypatch):
    """Test connect calls _authn_check and _get_access_token on success."""
    client = RESTClient(config_na, session)
    client._cookie_dt = "dt"
    client._access_token = None
    monkeypatch.setattr(client, "_is_access_token_active", AsyncMock(return_value=False))
    monkeypatch.setattr(client, "_authn_check", AsyncMock(return_value="SUCCESS"))
    get_access_token_mock = AsyncMock()
    monkeypatch.setattr(client, "_get_access_token", get_access_token_mock)
    result = await client.connect()
    get_access_token_mock.assert_called_once()
    assert result == "SUCCESS"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "initial,expect_trigger,expect_result,expect_raises",
    [
        (True, True, "MFA_REQUIRED", False),
        (False, False, None, True),
    ],
)
async def test_connect_needs_mfa_parametrized(
    config_na, session, initial, expect_trigger, expect_result, expect_raises, monkeypatch
):
    """Parametrized: connect behavior when MFA is required for initial True/False."""
    client = RESTClient(config_na, session)
    client._cookie_dt = "dt"
    client._access_token = None
    monkeypatch.setattr(client, "_is_access_token_active", AsyncMock(return_value=False))
    monkeypatch.setattr(client, "_authn_check", AsyncMock(return_value="MFA_REQUIRED"))
    trigger_mfa_mock = AsyncMock()
    monkeypatch.setattr(client, "_trigger_mfa", trigger_mfa_mock)
    monkeypatch.setattr(client, "_get_access_token", AsyncMock())

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
    "uses_mfa,expect_warn",
    [
        (False, False),
        (True, True),
    ],
)
async def test_connect_initial_dt_and_warning_variants(
    config_na, session, caplog, uses_mfa, expect_warn, monkeypatch
):
    """Parametrized: when _cookie_dt is None the client should call _get_initial_dt; when _uses_mfa is True it logs a warning."""
    client = RESTClient(config_na, session)
    client._cookie_dt = None
    client._uses_mfa = uses_mfa
    client._access_token = None
    get_initial_dt_mock = AsyncMock()
    monkeypatch.setattr(client, "_get_initial_dt", get_initial_dt_mock)
    monkeypatch.setattr(client, "_is_access_token_active", AsyncMock(return_value=False))
    monkeypatch.setattr(client, "_authn_check", AsyncMock(return_value="SUCCESS"))
    monkeypatch.setattr(client, "_get_access_token", AsyncMock())
    with caplog.at_level(logging.WARNING):
        await client.connect()

    get_initial_dt_mock.assert_called_once()
    if expect_warn:
        assert "Device Token isn't set" in caplog.text
    else:
        assert "Device Token isn't set" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "initial,expect_trigger,expect_result,expect_raises",
    [
        (True, True, AUTH_NEEDS_MFA, False),
        (False, False, None, True),
    ],
)
async def test_connect_status_needs_mfa_parametrized(
    config_na, session, initial, expect_trigger, expect_result, expect_raises, monkeypatch
):
    """Parametrized: connect behavior when _authn_check returns AUTH_NEEDS_MFA for initial True/False."""
    client = RESTClient(config_na, session)
    client._cookie_dt = "cookie"
    client._access_token = None
    monkeypatch.setattr(client, "_is_access_token_active", AsyncMock(return_value=False))
    monkeypatch.setattr(client, "_authn_check", AsyncMock(return_value=AUTH_NEEDS_MFA))
    trigger_mfa_mock = AsyncMock()
    monkeypatch.setattr(client, "_trigger_mfa", trigger_mfa_mock)
    monkeypatch.setattr(client, "_get_access_token", AsyncMock())

    if expect_raises:
        with pytest.raises(AuthenticationError):
            await client.connect(initial=initial)
    else:
        status = await client.connect(initial=initial)
        assert status == expect_result

    if expect_trigger:
        trigger_mfa_mock.assert_awaited_once()

    assert client._uses_mfa is True


@pytest.mark.asyncio
async def test_resmed_response_error_check_gql_query_not_initial_raises_parsing_error():
    """Test that ParsingError is raised if step == 'gql_query' and not initial and unauthorized error."""
    # Prepare a fake response and error dict
    response = MagicMock(spec=ClientResponse)
    response.status = 401
    response.headers = {}

    resp_dict = {"errors": [{"errorInfo": {"errorType": "unauthorized", "errorCode": "401"}}]}

    with pytest.raises(ParsingError) as exc:
        await RESTClient._resmed_response_error_check(
            step="gql_query", response=response, resp_dict=resp_dict, initial=False
        )
    assert "Getting unauthorized error on gql_query step" in str(exc.value)


@pytest.mark.asyncio
async def test_resmed_response_error_check_no_errors_key():
    """Test _resmed_response_error_check does nothing if 'errors' not in resp_dict."""
    response = MagicMock(spec=ClientResponse)
    response.status = 200
    response.headers = {}

    resp_dict = {"data": {"some": "value"}}

    # Should not raise any exception
    await RESTClient._resmed_response_error_check(
        step="any_step", response=response, resp_dict=resp_dict, initial=False
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "json_value,match",
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
async def test_authn_check_raises_variants(config_na, session, json_value, match, monkeypatch):
    """Parametrized: _authn_check raises AuthenticationError for missing stateToken or sessionToken cases."""
    client = RESTClient(config_na, session)

    mock_response = make_mock_aiohttp_response(json_value=json_value)

    # Patch session.post and _resmed_response_error_check to not raise
    session.post.return_value = make_mock_aiohttp_context_manager(mock_response)
    monkeypatch.setattr(RESTClient, "_resmed_response_error_check", AsyncMock())
    with pytest.raises(AuthenticationError, match=match):
        await client._authn_check()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method,resp_json,call_arg,post_assert,expected",
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
    config_na, session, method, resp_json, call_arg, post_assert, expected, monkeypatch
):
    """Parametrized: covers _trigger_mfa and _verify_mfa success paths."""
    client = RESTClient(config_na, session)
    client._state_token = "dummy_state_token"
    client._mfa_url = "https://example.com/mfa"
    client._json_headers = {"Content-Type": "application/json"}
    client._cookie_dt = None
    client._cookie_sid = None

    mock_response = make_mock_aiohttp_response(json_value=resp_json)

    session.post.return_value = make_mock_aiohttp_context_manager(mock_response)
    monkeypatch.setattr(RESTClient, "_resmed_response_error_check", AsyncMock())
    # execute
    if call_arg is None:
        # _trigger_mfa
        await client._trigger_mfa()
        if post_assert:
            session.post.assert_called_once()
            mock_response.json.assert_awaited_once()
    else:
        # _verify_mfa
        status = await client._verify_mfa(call_arg)
        assert status == expected
        assert client._session_token == resp_json.get("sessionToken")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "json_value,match",
    [
        ({}, "Cannot get status in verify_mfa step"),
        ({"status": AUTHN_SUCCESS}, "Cannot get sessionToken in verify_mfa step"),
        ({"status": "FAIL"}, "Unknown status in verify_mfa step: FAIL"),
    ],
)
async def test_verify_mfa_raises_variants(config_na, session, json_value, match, monkeypatch):
    """Parametrized: Test _verify_mfa raises AuthenticationError for several failure responses."""
    client = RESTClient(config_na, session)
    client._state_token = "dummy_state_token"
    client._mfa_url = "https://example.com/mfa"
    client._json_headers = {"Content-Type": "application/json"}
    client._cookie_dt = None
    client._cookie_sid = None

    mock_response = make_mock_aiohttp_response(json_value=json_value)

    session.post.return_value = make_mock_aiohttp_context_manager(mock_response)
    monkeypatch.setattr(RESTClient, "_resmed_response_error_check", AsyncMock())
    with pytest.raises(AuthenticationError, match=match):
        await client._verify_mfa("123456")


@pytest.mark.asyncio
async def test_get_access_token_success(config_na, session, monkeypatch):
    """Test _get_access_token sets tokens on success."""
    client = RESTClient(config_na, session)
    client._session_token = "dummy_session_token"
    client._json_headers = {"Content-Type": "application/json"}
    client._cookie_dt = None
    client._cookie_sid = None

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
        "custom_components.resmed_myair.client.rest_client.urldefrag",
        lambda *a, **k: MagicMock(fragment="code=abc123"),
    )
    monkeypatch.setattr(
        "custom_components.resmed_myair.client.rest_client.parse_qs",
        lambda *a, **k: {"code": ["the_code"]},
    )
    mock_extract = AsyncMock()
    monkeypatch.setattr(RESTClient, "_extract_and_update_cookies", mock_extract)
    monkeypatch.setattr(RESTClient, "_resmed_response_error_check", AsyncMock())

    await client._get_access_token()
    mock_extract.assert_awaited_once()
    assert client._access_token == "access_token_value"
    assert client._id_token == "id_token_value"


@pytest.mark.asyncio
async def test_get_access_token_raises_on_missing_location(config_na, session, monkeypatch):
    """Test _get_access_token raises ParsingError if location header is missing."""
    client = RESTClient(config_na, session)
    client._session_token = "dummy_session_token"
    client._json_headers = {"Content-Type": "application/json"}

    mock_code_res = make_mock_aiohttp_response(json_value=None)

    session.get.return_value = make_mock_aiohttp_context_manager(mock_code_res)
    monkeypatch.setattr(RESTClient, "_extract_and_update_cookies", AsyncMock())
    monkeypatch.setattr(RESTClient, "_resmed_response_error_check", AsyncMock())
    with pytest.raises(ParsingError, match="Unable to get location from code_res"):
        await client._get_access_token()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "token_json,match_msg",
    [
        ({"id_token": "id_token_value"}, "access_token not in token_dict"),
        ({"access_token": "access_token_value"}, "id_token not in token_dict"),
    ],
)
async def test_get_access_token_raises_on_missing_token_variants(
    config_na, session, token_json, match_msg, monkeypatch
):
    """Parametrized: Test _get_access_token raises ParsingError when token response lacks required keys."""
    client = RESTClient(config_na, session)
    client._session_token = "dummy_session_token"
    client._json_headers = {"Content-Type": "application/json"}
    client._cookie_dt = None
    client._cookie_sid = None

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
        "custom_components.resmed_myair.client.rest_client.urldefrag",
        lambda *a, **k: MagicMock(fragment="code=abc123"),
    )
    monkeypatch.setattr(
        "custom_components.resmed_myair.client.rest_client.parse_qs",
        lambda *a, **k: {"code": ["the_code"]},
    )
    monkeypatch.setattr(RESTClient, "_extract_and_update_cookies", AsyncMock())
    monkeypatch.setattr(RESTClient, "_resmed_response_error_check", AsyncMock())
    with pytest.raises(ParsingError, match=match_msg):
        await client._get_access_token()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "jwt_behavior,post_json,expect_exception,expected_country",
    [
        ("valid", {"data": {"foo": "bar"}}, False, "US"),
        ("invalid", None, True, None),
    ],
)
async def test_gql_query_variants(
    config_na, session, jwt_behavior, post_json, expect_exception, expected_country, monkeypatch
):
    """Parametrized: gql_query success (extract country from id_token) and jwt decode error cases."""
    client = RESTClient(config_na, session)
    client._access_token = "access"
    client._id_token = "idtoken"
    client._country_code = None

    if jwt_behavior == "valid":
        # jwt.decode returns a payload including myAirCountryId
        monkeypatch.setattr(
            "custom_components.resmed_myair.client.rest_client.jwt.decode",
            lambda *a, **k: {"myAirCountryId": expected_country},
        )
        monkeypatch.setattr(
            session,
            "post",
            lambda *args, **kwargs: make_mock_aiohttp_context_manager(
                MagicMock(json=AsyncMock(return_value=post_json))
            ),
        )
        monkeypatch.setattr(RESTClient, "_resmed_response_error_check", AsyncMock())
        result = await client._gql_query("op", "query")
        assert result == post_json
        assert client._country_code == expected_country
    else:

        def bad_decode(*a, **k):
            raise ValueError("bad jwt")

        monkeypatch.setattr(
            "custom_components.resmed_myair.client.rest_client.jwt.decode",
            bad_decode,
        )
        with pytest.raises(ParsingError, match="Unable to decode id_token into jwt_data"):
            await client._gql_query("op", "query")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "id_token,jwt_behavior,match",
    [
        (
            "idtoken",
            {"side_effect": Exception("bad jwt")},
            "Unable to decode id_token into jwt_data",
        ),
        ("idtoken", {"return_value": {}}, "myAirCountryId not found in jwt_data"),
        (None, None, "country_code not defined and id_token not present to identify it"),
    ],
)
async def test_gql_query_failure_variants(
    config_na, session, id_token, jwt_behavior, match, monkeypatch
):
    """Parametrized: _gql_query failure modes for JWT decoding, missing key, and missing id_token."""
    client = RESTClient(config_na, session)
    client._access_token = "access"
    client._id_token = id_token
    client._country_code = None

    if id_token is not None and jwt_behavior is not None:
        # Configure jwt.decode according to jwt_behavior dict
        if "side_effect" in jwt_behavior:

            def side(*a, **k):
                raise jwt_behavior["side_effect"]

            monkeypatch.setattr(
                "custom_components.resmed_myair.client.rest_client.jwt.decode",
                side,
            )
            with pytest.raises(ParsingError, match=match):
                await client._gql_query("op", "query")
        else:
            monkeypatch.setattr(
                "custom_components.resmed_myair.client.rest_client.jwt.decode",
                lambda *a, **k: jwt_behavior.get("return_value", {}),
            )
            with pytest.raises(ParsingError, match=match):
                await client._gql_query("op", "query")
    else:
        # No id_token provided -> immediate failure
        with pytest.raises(ParsingError, match=match):
            await client._gql_query("op", "query")


@pytest.mark.asyncio
async def test_gql_query_graphql_error(config_na, session, monkeypatch):
    """Ensure gql_query raises AuthenticationError on GraphQL auth errors."""
    client = RESTClient(config_na, session)
    client._access_token = "access"
    client._id_token = None
    client._country_code = "US"

    mock_res = MagicMock(spec=ClientResponse)
    mock_res.json = AsyncMock(
        return_value={"errors": [{"errorInfo": {"errorType": "unauthorized", "errorCode": "401"}}]}
    )

    session.post.return_value = make_mock_aiohttp_context_manager(mock_res)
    monkeypatch.setattr(
        RESTClient,
        "_resmed_response_error_check",
        AsyncMock(side_effect=AuthenticationError("unauthorized")),
    )
    with pytest.raises(AuthenticationError, match="unauthorized"):
        await client._gql_query("op", "query")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method_name,mock_response,expected",
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
    config_na, session, method_name, mock_response, expected, monkeypatch
):
    """Parametrized: success paths for data-fetching helpers (sleep records and device data)."""
    client = RESTClient(config_na, session)
    client._access_token = "access"
    client._country_code = "US"
    monkeypatch.setattr(client, "_gql_query", AsyncMock(return_value=mock_response))
    result = await getattr(client, method_name)()
    assert result == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mock_response,match_msg",
    [
        ({"data": {"getPatientWrapper": {}}}, "Error getting Patient Sleep Records"),
        (
            {"data": {"getPatientWrapper": {"sleepRecords": {"items": "notalist"}}}},
            "Returned records is not a list",
        ),
    ],
)
async def test_get_sleep_records_failure_variants(
    config_na, session, mock_response, match_msg, monkeypatch
):
    """Parametrized: get_sleep_records raises ParsingError for missing keys and non-list items."""
    client = RESTClient(config_na, session)
    client._access_token = "access"
    client._country_code = "US"
    monkeypatch.setattr(client, "_gql_query", AsyncMock(return_value=mock_response))
    with pytest.raises(ParsingError, match=match_msg):
        await client.get_sleep_records()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mock_response,match_msg",
    [
        ({"data": {"getPatientWrapper": {}}}, "Error getting User Device Data"),
        (
            {"data": {"getPatientWrapper": {"fgDevices": ["notadict"]}}},
            "Returned data is not a dict",
        ),
    ],
)
async def test_get_user_device_data_failure_variants(
    config_na, session, mock_response, match_msg, monkeypatch
):
    """Parametrized: get_user_device_data raises ParsingError for missing keys and invalid response types."""
    client = RESTClient(config_na, session)
    client._access_token = "access"
    client._country_code = "US"
    monkeypatch.setattr(client, "_gql_query", AsyncMock(return_value=mock_response))
    with pytest.raises(ParsingError, match=match_msg):
        await client.get_user_device_data()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cookie_headers, expected_extract_arg",
    [
        (["DT=token; Path=/;"], ["DT=token; Path=/;"]),
        ([], []),
    ],
)
async def test_get_initial_dt_variants(
    config_na, session, cookie_headers, expected_extract_arg, monkeypatch
):
    """Parametrized checks for _get_initial_dt with different cookie headers."""
    client = RESTClient(config_na, session)
    mock_headers = MagicMock()
    mock_headers.getall = MagicMock(return_value=cookie_headers)
    mock_response = MagicMock()
    mock_response.headers = mock_headers

    session.get.return_value = make_mock_aiohttp_context_manager(mock_response)
    mock_extract = AsyncMock()
    monkeypatch.setattr(client, "_extract_and_update_cookies", mock_extract)
    await client._get_initial_dt()
    session.get.assert_called_once()
    mock_extract.assert_called_once_with(expected_extract_arg)


@pytest.mark.asyncio
async def test_resmed_response_error_check_not_bad_request():
    """Test _resmed_response_error_check does NOT raise IncompleteAccountError if errorType is not 'badRequest' or errorCode not in set."""
    # Prepare a fake response and error dict
    resp_dict = {
        "errors": [{"errorInfo": {"errorType": "someOtherType", "errorCode": "someOtherCode"}}]
    }
    response = MagicMock(spec=ClientResponse)
    response.status = 400
    response.headers = CIMultiDict()

    # Should raise HttpProcessingError, not IncompleteAccountError
    with pytest.raises(HttpProcessingError) as exc:
        await RESTClient._resmed_response_error_check("gql_query", response, resp_dict)
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
async def test_authn_check_email_factor_id_exceptions(authn_dict, session, config_na):
    """Test RESTClient._authn_check falls back to region_config['email_factor_id'] on KeyError/TypeError."""
    # MyAirConfig is a NamedTuple (immutable) so use _replace to change device_token
    config = config_na._replace(device_token=None)
    client = RESTClient(config, session)

    # Patch session.post to return a mock response with .json() returning authn_dict
    mock_response = make_mock_aiohttp_response(json_value=authn_dict)
    session.post.return_value = make_mock_aiohttp_context_manager(mock_response)

    # Should NOT raise, but should set _email_factor_id to region_config["email_factor_id"]
    result = await client._authn_check()
    assert client._email_factor_id == client._region_config["email_factor_id"]
    assert result == "MFA_REQUIRED"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "returned_token,expect_log,expect_change",
    [
        ("abc123", False, False),
        ("newtoken456", True, True),
    ],
)
async def test_get_access_token_token_change_and_logging(
    config_na, session, caplog, returned_token, expect_log, expect_change, monkeypatch
):
    """Parametrized: test token equality vs new token and logging behavior for _get_access_token."""
    # MyAirConfig is a NamedTuple (immutable) so create a modified copy
    config = config_na._replace(device_token=None)
    client = RESTClient(config, session)

    # Set up the client with an existing access token
    client._access_token = "abc123"

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
    monkeypatch.setattr(RESTClient, "_resmed_response_error_check", AsyncMock())
    with caplog.at_level(logging.INFO):
        await client._get_access_token()

    # Assert token updated only when expected
    expected_token = "abc123" if not expect_change else returned_token
    assert client._access_token == expected_token

    # Ensure logging behavior matches expectation
    if expect_log:
        assert "Obtained new access token" in caplog.text
    else:
        assert "Obtained new access token" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method_name,session_method,response_json,expected",
    [
        ("_is_access_token_active", "post", {"active": True}, True),
        ("_is_access_token_active", "post", {"active": False}, False),
        ("is_email_verified", "get", {"email_verified": True}, True),
        ("is_email_verified", "get", {"email_verified": False}, False),
    ],
)
async def test_status_helpers_variants(
    config_na, session, method_name, session_method, response_json, expected, monkeypatch
):
    """Parametrized test covering small boolean helper methods that hit the auth endpoints."""
    client = RESTClient(config_na, session)
    client._access_token = "token"
    mock_res = make_mock_aiohttp_response(json_value=response_json, headers={})
    mock_res.status = 200
    # Attach the context manager as the return value of the appropriate session method
    if session_method == "post":
        session.post.return_value = make_mock_aiohttp_context_manager(mock_res)
    else:
        session.get.return_value = make_mock_aiohttp_context_manager(mock_res)
    monkeypatch.setattr(RESTClient, "_resmed_response_error_check", AsyncMock())
    result = await getattr(client, method_name)()
    assert result is expected
