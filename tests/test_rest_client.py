from collections import defaultdict
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp import ClientResponse, ClientSession
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


@pytest.fixture
def config_na():
    """Fixture for NA region config."""
    return MyAirConfig(username="user", password="pass", region="NA", device_token="token")


@pytest.fixture
def config_eu():
    """Fixture for EU region config."""
    return MyAirConfig(username="user", password="pass", region="EU", device_token="token")


@pytest.fixture
def session():
    """Fixture for aiohttp ClientSession mock."""
    return MagicMock(spec=ClientSession)


def test_rest_client_init_na(config_na, session):
    """Test RESTClient initialization for NA region."""
    client = RESTClient(config_na, session)
    assert client._region_config == NA_CONFIG
    assert client._email_factor_id == NA_CONFIG["email_factor_id"]
    assert client._mfa_url.startswith("https://")


def test_rest_client_init_eu(config_eu, session):
    """Test RESTClient initialization for EU region."""
    client = RESTClient(config_eu, session)
    assert client._region_config == EU_CONFIG
    assert client._email_factor_id == EU_CONFIG["email_factor_id"]
    assert client._mfa_url.startswith("https://")


def test_device_token_property(config_na, session):
    """Test device_token property."""
    client = RESTClient(config_na, session)
    assert client.device_token == "token"


def test_cookies_property(config_na, session):
    """Test _cookies property."""
    client = RESTClient(config_na, session)
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
    initial_dt, initial_sid, cookie_headers, expected_dt, expected_sid, expect_warn, caplog
):
    """Parametrized test for _extract_and_update_cookies covering all branches, including warning."""
    config = MagicMock(spec=MyAirConfig)
    config.region = "NA"
    config.username = "user"
    config.password = "pw"
    config.device_token = None
    session = MagicMock()
    client = RESTClient(config, session)
    client._cookie_dt = initial_dt
    client._cookie_sid = initial_sid

    with caplog.at_level("WARNING"):
        await client._extract_and_update_cookies(cookie_headers)
    assert client._cookie_dt == expected_dt
    assert client._cookie_sid == expected_sid
    if expect_warn:
        assert "Changing Device Token from: oldtoken, to: newtoken" in caplog.text
    else:
        assert "Changing Device Token from: oldtoken, to: newtoken" not in caplog.text


@pytest.mark.asyncio
async def test_resmed_response_error_check_unauthorized():
    """Test _resmed_response_error_check raises AuthenticationError on unauthorized."""
    response = MagicMock()
    response.status = 401
    response.headers = {}
    resp_dict = {"errors": [{"errorInfo": {"errorType": "unauthorized", "errorCode": "401"}}]}
    with pytest.raises(AuthenticationError):
        await RESTClient._resmed_response_error_check("authn", response, resp_dict)


@pytest.mark.asyncio
async def test_resmed_response_error_check_bad_request():
    """Test _resmed_response_error_check raises IncompleteAccountError on onboardingFlowInProgress."""
    response = MagicMock()
    response.status = 400
    response.headers = {}
    resp_dict = {
        "errors": [
            {"errorInfo": {"errorType": "badRequest", "errorCode": "onboardingFlowInProgress"}}
        ]
    }
    with pytest.raises(IncompleteAccountError):  # Assert the specific exception type
        await RESTClient._resmed_response_error_check("authn", response, resp_dict)


@pytest.mark.asyncio
async def test_resmed_response_error_check_type_error():
    """Test _resmed_response_error_check raises HttpProcessingError on TypeError."""
    response = MagicMock()
    response.status = 400
    response.headers = {}
    resp_dict = {"errors": [None]}

    with pytest.raises(HttpProcessingError):
        await RESTClient._resmed_response_error_check("authn", response, resp_dict)


@pytest.mark.asyncio
async def test_authn_check_success(config_na, session):
    """Test _authn_check returns AUTHN_SUCCESS and sets session_token."""
    client = RESTClient(config_na, session)
    session.post.return_value.__aenter__.return_value.json = AsyncMock(
        return_value={"status": "SUCCESS", "sessionToken": "abc"}
    )
    session.post.return_value.__aenter__.return_value.headers = {}
    session.post.return_value.__aenter__.return_value.status = 200
    with patch.object(RESTClient, "_resmed_response_error_check", new=AsyncMock()):
        status = await client._authn_check()
    assert status == "SUCCESS"
    assert client._session_token == "abc"


@pytest.mark.asyncio
async def test_authn_check_mfa(config_na, session):
    """Test _authn_check returns AUTH_NEEDS_MFA and sets state_token and mfa_url."""
    client = RESTClient(config_na, session)
    session.post.return_value.__aenter__.return_value.json = AsyncMock(
        return_value={
            "status": "MFA_REQUIRED",
            "stateToken": "state",
            "_embedded": {
                "factors": [{"id": "factorid", "_links": {"verify": {"href": "https://verify"}}}]
            },
        }
    )
    session.post.return_value.__aenter__.return_value.headers = {}
    session.post.return_value.__aenter__.return_value.status = 200
    with patch.object(RESTClient, "_resmed_response_error_check", new=AsyncMock()):
        status = await client._authn_check()
    assert status == "MFA_REQUIRED"
    assert client._state_token == "state"
    assert client._email_factor_id == "factorid"
    assert client._mfa_url.startswith("https://verify")


@pytest.mark.asyncio
async def test_authn_check_missing_status(config_na, session):
    """Test _authn_check raises AuthenticationError if status missing."""
    client = RESTClient(config_na, session)
    session.post.return_value.__aenter__.return_value.json = AsyncMock(return_value={})
    session.post.return_value.__aenter__.return_value.headers = {}
    session.post.return_value.__aenter__.return_value.status = 200
    with (
        patch.object(RESTClient, "_resmed_response_error_check", new=AsyncMock()),
        pytest.raises(AuthenticationError),
    ):
        await client._authn_check()


@pytest.mark.asyncio
async def test_authn_check_unknown_status(config_na, session):
    """Test _authn_check raises AuthenticationError for unknown status."""
    client = RESTClient(config_na, session)
    session.post.return_value.__aenter__.return_value.json = AsyncMock(
        return_value={"status": "UNKNOWN"}
    )
    session.post.return_value.__aenter__.return_value.headers = {}
    session.post.return_value.__aenter__.return_value.status = 200
    with (
        patch.object(RESTClient, "_resmed_response_error_check", new=AsyncMock()),
        pytest.raises(AuthenticationError),
    ):
        await client._authn_check()


@pytest.mark.asyncio
async def test_verify_mfa_and_get_access_token_success(config_na, session):
    """Test verify_mfa_and_get_access_token returns AUTHN_SUCCESS."""
    client = RESTClient(config_na, session)
    with (
        patch.object(client, "_verify_mfa", new=AsyncMock(return_value="SUCCESS")),
        patch.object(client, "_get_access_token", new=AsyncMock()),
    ):
        status = await client.verify_mfa_and_get_access_token("123456")
    assert status == "SUCCESS"


@pytest.mark.asyncio
async def test_verify_mfa_and_get_access_token_fail(config_na, session):
    """Test verify_mfa_and_get_access_token raises AuthenticationError on failure."""
    client = RESTClient(config_na, session)
    with (
        patch.object(client, "_verify_mfa", new=AsyncMock(return_value="FAIL")),
        patch.object(client, "_get_access_token", new=AsyncMock()),
        pytest.raises(AuthenticationError),
    ):
        await client.verify_mfa_and_get_access_token("123456")


@pytest.mark.asyncio
async def test_connect_access_token_active(config_na, session):
    """Test connect returns AUTHN_SUCCESS if access token is active."""
    client = RESTClient(config_na, session)
    client._cookie_dt = "dt"
    client._access_token = "token"
    with (
        patch.object(client, "_is_access_token_active", new=AsyncMock(return_value=True)),
        patch.object(client, "_authn_check", new=AsyncMock()),
        patch.object(client, "_get_access_token", new=AsyncMock()),
    ):
        result = await client.connect()
    assert result == "SUCCESS"


@pytest.mark.asyncio
async def test_connect_authn_success(config_na, session):
    """Test connect calls _authn_check and _get_access_token on success."""
    client = RESTClient(config_na, session)
    client._cookie_dt = "dt"
    client._access_token = None
    with (
        patch.object(client, "_is_access_token_active", new=AsyncMock(return_value=False)),
        patch.object(client, "_authn_check", new=AsyncMock(return_value="SUCCESS")),
        patch.object(client, "_get_access_token", new=AsyncMock()) as get_access_token_mock,
    ):
        result = await client.connect()
    get_access_token_mock.assert_called_once()
    assert result == "SUCCESS"


@pytest.mark.asyncio
async def test_connect_needs_mfa_initial_true(config_na, session):
    """Test connect triggers MFA if needed and initial is True."""
    client = RESTClient(config_na, session)
    client._cookie_dt = "dt"
    client._access_token = None
    with (
        patch.object(client, "_is_access_token_active", new=AsyncMock(return_value=False)),
        patch.object(client, "_authn_check", new=AsyncMock(return_value="MFA_REQUIRED")),
        patch.object(client, "_trigger_mfa", new=AsyncMock()) as trigger_mfa_mock,
        patch.object(client, "_get_access_token", new=AsyncMock()),
    ):
        result = await client.connect(initial=True)
    trigger_mfa_mock.assert_called_once()
    assert result == "MFA_REQUIRED"
    assert client._uses_mfa is True


@pytest.mark.asyncio
async def test_connect_needs_mfa_initial_false_raises(config_na, session):
    """Test connect raises AuthenticationError if MFA required and initial is False."""
    client = RESTClient(config_na, session)
    client._cookie_dt = "dt"
    client._access_token = None
    with (
        patch.object(client, "_is_access_token_active", new=AsyncMock(return_value=False)),
        patch.object(client, "_authn_check", new=AsyncMock(return_value="MFA_REQUIRED")),
        patch.object(client, "_trigger_mfa", new=AsyncMock()),
        patch.object(client, "_get_access_token", new=AsyncMock()),
        pytest.raises(AuthenticationError),
    ):
        await client.connect(initial=False)


@pytest.mark.asyncio
async def test_connect_calls_get_initial_dt_if_cookie_dt_none(config_na, session):
    """Test connect calls _get_initial_dt if _cookie_dt is None."""
    client = RESTClient(config_na, session)
    client._cookie_dt = None
    client._access_token = None
    with (
        patch.object(client, "_get_initial_dt", new=AsyncMock()) as get_initial_dt_mock,
        patch.object(client, "_is_access_token_active", new=AsyncMock(return_value=False)),
        patch.object(client, "_authn_check", new=AsyncMock(return_value="SUCCESS")),
        patch.object(client, "_get_access_token", new=AsyncMock()),
    ):
        await client.connect()
    get_initial_dt_mock.assert_called_once()


@pytest.mark.asyncio
async def test_connect_warns_if_cookie_dt_none_and_uses_mfa(config_na, session, caplog):
    """Test connect logs a warning if _cookie_dt is None and _uses_mfa is True."""
    client = RESTClient(config_na, session)
    client._cookie_dt = None
    client._uses_mfa = True
    client._access_token = None
    with (
        patch.object(client, "_get_initial_dt", new=AsyncMock()),
        patch.object(client, "_is_access_token_active", new=AsyncMock(return_value=False)),
        patch.object(client, "_authn_check", new=AsyncMock(return_value="SUCCESS")),
        patch.object(client, "_get_access_token", new=AsyncMock()),
        caplog.at_level("WARNING"),
    ):
        await client.connect()
    assert "Device Token isn't set. This will require frequent reauthentication." in caplog.text


@pytest.mark.asyncio
async def test_connect_status_needs_mfa_initial_triggers_mfa(config_na, session):
    """Test connect triggers MFA if status == AUTH_NEEDS_MFA and initial=True."""
    client = RESTClient(config_na, session)
    client._cookie_dt = "cookie"
    client._access_token = None
    with (
        patch.object(client, "_is_access_token_active", new=AsyncMock(return_value=False)),
        patch.object(client, "_authn_check", new=AsyncMock(return_value=AUTH_NEEDS_MFA)),
        patch.object(client, "_trigger_mfa", new=AsyncMock()) as trigger_mfa_mock,
        patch.object(client, "_get_access_token", new=AsyncMock()),
    ):
        status = await client.connect(initial=True)
    trigger_mfa_mock.assert_awaited_once()
    assert status == AUTH_NEEDS_MFA
    assert client._uses_mfa is True


@pytest.mark.asyncio
async def test_connect_status_needs_mfa_not_initial_raises(config_na, session):
    """Test connect raises AuthenticationError if status == AUTH_NEEDS_MFA and initial=False."""
    client = RESTClient(config_na, session)
    client._cookie_dt = "cookie"
    client._access_token = None
    with (
        patch.object(client, "_is_access_token_active", new=AsyncMock(return_value=False)),
        patch.object(client, "_authn_check", new=AsyncMock(return_value=AUTH_NEEDS_MFA)),
        patch.object(client, "_trigger_mfa", new=AsyncMock()),
        patch.object(client, "_get_access_token", new=AsyncMock()),
        pytest.raises(AuthenticationError),
    ):
        await client.connect(initial=False)
    assert client._uses_mfa is True


@pytest.mark.asyncio
async def test_connect_returns_success_if_access_token_active(config_na, session):
    """Test connect returns AUTHN_SUCCESS if self._access_token is set and is active."""
    client = RESTClient(config_na, session)
    client._access_token = "token"
    client._cookie_dt = "cookie"
    with patch.object(client, "_is_access_token_active", new=AsyncMock(return_value=True)):
        result = await client.connect()
    assert result == AUTHN_SUCCESS


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
async def test_authn_check_raises_if_state_token_missing(config_na, session):
    """Test _authn_check raises AuthenticationError if status == AUTH_NEEDS_MFA and stateToken is missing."""
    client = RESTClient(config_na, session)

    # Mock the session.post context manager and response
    mock_response = MagicMock(spec=ClientResponse)
    mock_response.json = AsyncMock(
        return_value={
            "status": AUTH_NEEDS_MFA,
            # "stateToken" intentionally missing
            "_embedded": {"factors": [{"id": "some_id", "_links": {"verify": {"href": "url"}}}]},
        }
    )

    # Patch _resmed_response_error_check to do nothing
    with (
        patch.object(
            session,
            "post",
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_response),
                __aexit__=AsyncMock(return_value=None),
            ),
        ),
        patch.object(RESTClient, "_resmed_response_error_check", new=AsyncMock()),
        pytest.raises(AuthenticationError, match="Cannot get stateToken in authn step"),
    ):
        await client._authn_check()


@pytest.mark.asyncio
async def test_authn_check_raises_if_session_token_missing(config_na, session):
    """Test _authn_check raises AuthenticationError if status == AUTHN_SUCCESS and sessionToken is missing."""
    client = RESTClient(config_na, session)

    # Mock the session.post context manager and response
    mock_response = MagicMock(spec=ClientResponse)
    mock_response.json = AsyncMock(
        return_value={
            "status": AUTHN_SUCCESS,
            # "sessionToken" intentionally missing
        }
    )

    # Patch _resmed_response_error_check to do nothing
    with (
        patch.object(
            session,
            "post",
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_response),
                __aexit__=AsyncMock(return_value=None),
            ),
        ),
        patch.object(RESTClient, "_resmed_response_error_check", new=AsyncMock()),
        pytest.raises(AuthenticationError, match="Cannot get sessionToken in authn step"),
    ):
        await client._authn_check()


@pytest.mark.asyncio
async def test_trigger_mfa_success(config_na, session):
    """Test _trigger_mfa sends correct request and processes response."""
    client = RESTClient(config_na, session)
    client._state_token = "dummy_state_token"
    client._mfa_url = "https://example.com/mfa"
    client._json_headers = {"Content-Type": "application/json"}
    client._cookie_dt = None
    client._cookie_sid = None

    # Mock response from the MFA endpoint
    mock_response = MagicMock(spec=ClientResponse)
    mock_response.json = AsyncMock(return_value={"status": "MFA_CHALLENGE_SENT"})

    # Patch session.post to return the mock response
    with (
        patch.object(
            session,
            "post",
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_response),
                __aexit__=AsyncMock(return_value=None),
            ),
        ),
        patch.object(
            RESTClient, "_resmed_response_error_check", new=AsyncMock()
        ) as error_check_mock,
    ):
        await client._trigger_mfa()
        session.post.assert_called_once()
        mock_response.json.assert_awaited_once()
        error_check_mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_verify_mfa_success(config_na, session):
    """Test _verify_mfa returns AUTHN_SUCCESS and sets session_token on success."""
    client = RESTClient(config_na, session)
    client._state_token = "dummy_state_token"
    client._mfa_url = "https://example.com/mfa"
    client._json_headers = {"Content-Type": "application/json"}
    client._cookie_dt = None
    client._cookie_sid = None

    # Mock response from the MFA verification endpoint
    mock_response = MagicMock(spec=ClientResponse)
    mock_response.json = AsyncMock(
        return_value={"status": AUTHN_SUCCESS, "sessionToken": "dummy_session_token"}
    )

    with (
        patch.object(
            session,
            "post",
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_response),
                __aexit__=AsyncMock(return_value=None),
            ),
        ),
        patch.object(RESTClient, "_resmed_response_error_check", new=AsyncMock()),
    ):
        status = await client._verify_mfa("123456")
        assert status == AUTHN_SUCCESS
        assert client._session_token == "dummy_session_token"


@pytest.mark.asyncio
async def test_verify_mfa_raises_on_missing_status(config_na, session):
    """Test _verify_mfa raises AuthenticationError if status is missing in response."""
    client = RESTClient(config_na, session)
    client._state_token = "dummy_state_token"
    client._mfa_url = "https://example.com/mfa"
    client._json_headers = {"Content-Type": "application/json"}
    client._cookie_dt = None
    client._cookie_sid = None

    mock_response = MagicMock(spec=ClientResponse)
    mock_response.json = AsyncMock(return_value={})  # No status

    with (
        patch.object(
            session,
            "post",
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_response),
                __aexit__=AsyncMock(return_value=None),
            ),
        ),
        patch.object(RESTClient, "_resmed_response_error_check", new=AsyncMock()),
        pytest.raises(AuthenticationError, match="Cannot get status in verify_mfa step"),
    ):
        await client._verify_mfa("123456")


@pytest.mark.asyncio
async def test_verify_mfa_raises_on_missing_session_token(config_na, session):
    """Test _verify_mfa raises AuthenticationError if sessionToken is missing when status is AUTHN_SUCCESS."""
    client = RESTClient(config_na, session)
    client._state_token = "dummy_state_token"
    client._mfa_url = "https://example.com/mfa"
    client._json_headers = {"Content-Type": "application/json"}
    client._cookie_dt = None
    client._cookie_sid = None

    mock_response = MagicMock(spec=ClientResponse)
    mock_response.json = AsyncMock(
        return_value={
            "status": AUTHN_SUCCESS
            # sessionToken missing
        }
    )

    with (
        patch.object(
            session,
            "post",
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_response),
                __aexit__=AsyncMock(return_value=None),
            ),
        ),
        patch.object(RESTClient, "_resmed_response_error_check", new=AsyncMock()),
        pytest.raises(AuthenticationError, match="Cannot get sessionToken in verify_mfa step"),
    ):
        await client._verify_mfa("123456")


@pytest.mark.asyncio
async def test_verify_mfa_raises_on_unknown_status(config_na, session):
    """Test _verify_mfa raises AuthenticationError if status is not AUTHN_SUCCESS."""
    client = RESTClient(config_na, session)
    client._state_token = "dummy_state_token"
    client._mfa_url = "https://example.com/mfa"
    client._json_headers = {"Content-Type": "application/json"}
    client._cookie_dt = None
    client._cookie_sid = None

    mock_response = MagicMock(spec=ClientResponse)
    mock_response.json = AsyncMock(return_value={"status": "FAIL"})

    with (
        patch.object(
            session,
            "post",
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_response),
                __aexit__=AsyncMock(return_value=None),
            ),
        ),
        patch.object(RESTClient, "_resmed_response_error_check", new=AsyncMock()),
        pytest.raises(AuthenticationError, match="Unknown status in verify_mfa step: FAIL"),
    ):
        await client._verify_mfa("123456")


@pytest.mark.asyncio
async def test_get_access_token_success(config_na, session):
    """Test _get_access_token sets tokens on success."""
    client = RESTClient(config_na, session)
    client._session_token = "dummy_session_token"
    client._json_headers = {"Content-Type": "application/json"}
    client._cookie_dt = None
    client._cookie_sid = None

    # Mock the GET authorize response
    mock_code_res = MagicMock(spec=ClientResponse)
    mock_code_res.headers = MagicMock()
    mock_code_res.headers.getall = MagicMock(return_value=["https://redirect#code=abc123"])
    mock_code_res.headers.__contains__.side_effect = lambda k: k == "location"
    mock_code_res.headers.__getitem__.side_effect = (
        lambda k: "https://redirect#code=abc123" if k == "location" else None
    )
    mock_code_res.json = AsyncMock()

    # Mock the POST token response
    mock_token_res = MagicMock(spec=ClientResponse)
    mock_token_res.json = AsyncMock(
        return_value={"access_token": "access_token_value", "id_token": "id_token_value"}
    )

    # Patch urldefrag and parse_qs to simulate code extraction
    with (
        patch.object(
            session,
            "get",
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_code_res),
                __aexit__=AsyncMock(return_value=None),
            ),
        ),
        patch.object(
            session,
            "post",
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_token_res),
                __aexit__=AsyncMock(return_value=None),
            ),
        ),
        patch(
            "custom_components.resmed_myair.client.rest_client.urldefrag",
            return_value=MagicMock(fragment="code=abc123"),
        ),
        patch(
            "custom_components.resmed_myair.client.rest_client.parse_qs",
            return_value={"code": ["the_code"]},
        ),
        patch.object(RESTClient, "_extract_and_update_cookies", new=AsyncMock()),
        patch.object(RESTClient, "_resmed_response_error_check", new=AsyncMock()),
    ):
        await client._get_access_token()
        assert client._access_token == "access_token_value"
        assert client._id_token == "id_token_value"


@pytest.mark.asyncio
async def test_get_access_token_raises_on_missing_location(config_na, session):
    """Test _get_access_token raises ParsingError if location header is missing."""
    client = RESTClient(config_na, session)
    client._session_token = "dummy_session_token"
    client._json_headers = {"Content-Type": "application/json"}

    mock_code_res = MagicMock(spec=ClientResponse)
    mock_code_res.headers = {}
    mock_code_res.json = AsyncMock()
    mock_code_res.cookies = {}

    with (
        pytest.raises(ParsingError, match="Unable to get location from code_res"),
        patch.object(
            session,
            "get",
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_code_res),
                __aexit__=AsyncMock(return_value=None),
            ),
        ),
        patch.object(RESTClient, "_extract_and_update_cookies", new=AsyncMock()),
        patch.object(RESTClient, "_resmed_response_error_check", new=AsyncMock()),
    ):
        await client._get_access_token()


@pytest.mark.asyncio
async def test_get_access_token_raises_on_missing_access_token(config_na, session):
    """Test _get_access_token raises ParsingError if access_token is missing in token_dict."""
    client = RESTClient(config_na, session)
    client._session_token = "dummy_session_token"
    client._json_headers = {"Content-Type": "application/json"}
    client._cookie_dt = None
    client._cookie_sid = None

    mock_code_res = MagicMock(spec=ClientResponse)
    mock_headers = MagicMock()
    # mock_headers.__getitem__.side_effect = lambda k: {"location": "https://redirect#code=abc123"}[k]
    mock_headers.__getitem__.side_effect = defaultdict(
        lambda: None, {"location": "https://redirect#code=abc123"}
    ).__getitem__
    mock_headers.__contains__.side_effect = lambda k: k == "location"
    mock_headers.getall = MagicMock(return_value=["https://redirect#code=abc123"])
    mock_code_res.headers = mock_headers
    mock_code_res.json = AsyncMock()

    mock_token_res = MagicMock(spec=ClientResponse)
    mock_token_res.json = AsyncMock(return_value={"id_token": "id_token_value"})

    with (
        patch.object(
            session,
            "get",
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_code_res),
                __aexit__=AsyncMock(return_value=None),
            ),
        ),
        patch.object(
            session,
            "post",
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_token_res),
                __aexit__=AsyncMock(return_value=None),
            ),
        ),
        patch(
            "custom_components.resmed_myair.client.rest_client.urldefrag",
            return_value=MagicMock(fragment="code=abc123"),
        ),
        patch(
            "custom_components.resmed_myair.client.rest_client.parse_qs",
            return_value={"code": ["the_code"]},
        ),
        patch.object(RESTClient, "_extract_and_update_cookies", new=AsyncMock()),
        patch.object(RESTClient, "_resmed_response_error_check", new=AsyncMock()),
        pytest.raises(ParsingError, match="access_token not in token_dict"),
    ):
        await client._get_access_token()


@pytest.mark.asyncio
async def test_get_access_token_raises_on_missing_id_token(config_na, session):
    """Test _get_access_token raises ParsingError if id_token is missing in token_dict."""
    client = RESTClient(config_na, session)
    client._session_token = "dummy_session_token"
    client._json_headers = {"Content-Type": "application/json"}
    client._cookie_dt = None
    client._cookie_sid = None

    mock_code_res = MagicMock(spec=ClientResponse)
    # Use a MagicMock for headers to provide getall and dict access
    mock_headers = MagicMock()
    mock_headers.__getitem__.side_effect = lambda k: {"location": "https://redirect#code=abc123"}[k]
    mock_headers.__contains__.side_effect = lambda k: k == "location"
    mock_headers.getall = MagicMock(return_value=["https://redirect#code=abc123"])
    mock_code_res.headers = mock_headers
    mock_code_res.json = AsyncMock()

    mock_token_res = MagicMock(spec=ClientResponse)
    mock_token_res.json = AsyncMock(return_value={"access_token": "access_token_value"})

    with (
        patch.object(
            session,
            "get",
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_code_res),
                __aexit__=AsyncMock(return_value=None),
            ),
        ),
        patch.object(
            session,
            "post",
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_token_res),
                __aexit__=AsyncMock(return_value=None),
            ),
        ),
        patch(
            "custom_components.resmed_myair.client.rest_client.urldefrag",
            return_value=MagicMock(fragment="code=abc123"),
        ),
        patch(
            "custom_components.resmed_myair.client.rest_client.parse_qs",
            return_value={"code": ["the_code"]},
        ),
        patch.object(RESTClient, "_extract_and_update_cookies", new=AsyncMock()),
        patch.object(RESTClient, "_resmed_response_error_check", new=AsyncMock()),
        pytest.raises(ParsingError, match="id_token not in token_dict"),
    ):
        await client._get_access_token()


@pytest.mark.asyncio
async def test_gql_query_success_country_from_jwt(config_na, session):
    client = RESTClient(config_na, session)
    client._access_token = "access"
    client._id_token = "idtoken"
    client._country_code = None

    # Patch jwt.decode to return a valid payload
    with (
        patch("jwt.decode", return_value={"myAirCountryId": "US"}),
        patch.object(
            session,
            "post",
            return_value=AsyncMock(
                __aenter__=AsyncMock(
                    return_value=MagicMock(json=AsyncMock(return_value={"data": {"foo": "bar"}}))
                ),
                __aexit__=AsyncMock(return_value=None),
            ),
        ),
        patch.object(RESTClient, "_resmed_response_error_check", new=AsyncMock()),
    ):
        result = await client._gql_query("op", "query")
        assert result == {"data": {"foo": "bar"}}
        assert client._country_code == "US"


@pytest.mark.asyncio
async def test_gql_query_error_decoding_jwt(config_na, session):
    client = RESTClient(config_na, session)
    client._access_token = "access"
    client._id_token = "idtoken"
    client._country_code = None

    with (
        patch("jwt.decode", side_effect=Exception("bad jwt")),
        pytest.raises(ParsingError, match="Unable to decode id_token into jwt_data"),
    ):
        await client._gql_query("op", "query")


@pytest.mark.asyncio
async def test_gql_query_missing_myaircountryid(config_na, session):
    client = RESTClient(config_na, session)
    client._access_token = "access"
    client._id_token = "idtoken"
    client._country_code = None

    with (
        patch("jwt.decode", return_value={}),
        pytest.raises(ParsingError, match="myAirCountryId not found in jwt_data"),
    ):
        await client._gql_query("op", "query")


@pytest.mark.asyncio
async def test_gql_query_no_country_code_and_no_id_token(config_na, session):
    client = RESTClient(config_na, session)
    client._access_token = "access"
    client._id_token = None
    client._country_code = None

    with pytest.raises(
        ParsingError, match="country_code not defined and id_token not present to identify it"
    ):
        await client._gql_query("op", "query")


@pytest.mark.asyncio
async def test_gql_query_graphql_error(config_na, session):
    client = RESTClient(config_na, session)
    client._access_token = "access"
    client._id_token = None
    client._country_code = "US"

    mock_res = MagicMock()
    mock_res.json = AsyncMock(
        return_value={"errors": [{"errorInfo": {"errorType": "unauthorized", "errorCode": "401"}}]}
    )

    with (
        patch.object(
            session,
            "post",
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_res),
                __aexit__=AsyncMock(return_value=None),
            ),
        ),
        patch.object(
            RESTClient,
            "_resmed_response_error_check",
            side_effect=AuthenticationError("unauthorized"),
        ),
        pytest.raises(AuthenticationError, match="unauthorized"),
    ):
        await client._gql_query("op", "query")


@pytest.mark.asyncio
async def test_get_sleep_records_success(config_na, session):
    client = RESTClient(config_na, session)
    client._access_token = "access"
    client._country_code = "US"
    mock_records = [
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
    mock_response = {"data": {"getPatientWrapper": {"sleepRecords": {"items": mock_records}}}}
    with patch.object(client, "_gql_query", AsyncMock(return_value=mock_response)):
        records = await client.get_sleep_records()
        assert records == mock_records


@pytest.mark.asyncio
async def test_get_sleep_records_missing_keys(config_na, session):
    client = RESTClient(config_na, session)
    client._access_token = "access"
    client._country_code = "US"
    # Missing 'sleepRecords'
    mock_response = {"data": {"getPatientWrapper": {}}}
    with (
        patch.object(client, "_gql_query", AsyncMock(return_value=mock_response)),
        pytest.raises(ParsingError, match="Error getting Patient Sleep Records"),
    ):
        await client.get_sleep_records()


@pytest.mark.asyncio
async def test_get_sleep_records_not_a_list(config_na, session):
    client = RESTClient(config_na, session)
    client._access_token = "access"
    client._country_code = "US"
    # 'items' is not a list
    mock_response = {"data": {"getPatientWrapper": {"sleepRecords": {"items": "notalist"}}}}
    with (
        patch.object(client, "_gql_query", AsyncMock(return_value=mock_response)),
        pytest.raises(ParsingError, match="Returned records is not a list"),
    ):
        await client.get_sleep_records()


@pytest.mark.asyncio
async def test_get_user_device_data_success(config_na, session):
    client = RESTClient(config_na, session)
    client._access_token = "access"
    client._country_code = "US"
    mock_device = {
        "serialNumber": "12345",
        "deviceType": "CPAP",
        "lastSleepDataReportTime": "2024-07-01T00:00:00Z",
        "localizedName": "My CPAP",
        "fgDeviceManufacturerName": "ResMed",
        "fgDevicePatientId": "abc",
        "__typename": "FgDevice",
    }
    mock_response = {"data": {"getPatientWrapper": {"fgDevices": [mock_device]}}}
    with patch.object(client, "_gql_query", AsyncMock(return_value=mock_response)):
        device = await client.get_user_device_data()
        assert device == mock_device


@pytest.mark.asyncio
async def test_get_user_device_data_missing_keys(config_na, session):
    client = RESTClient(config_na, session)
    client._access_token = "access"
    client._country_code = "US"
    # Missing 'fgDevices'
    mock_response = {"data": {"getPatientWrapper": {}}}
    with (
        patch.object(client, "_gql_query", AsyncMock(return_value=mock_response)),
        pytest.raises(ParsingError, match="Error getting User Device Data"),
    ):
        await client.get_user_device_data()


@pytest.mark.asyncio
async def test_get_user_device_data_not_a_dict(config_na, session):
    client = RESTClient(config_na, session)
    client._access_token = "access"
    client._country_code = "US"
    # 'fgDevices' is a list with a non-dict item
    mock_response = {"data": {"getPatientWrapper": {"fgDevices": ["notadict"]}}}
    with (
        patch.object(client, "_gql_query", AsyncMock(return_value=mock_response)),
        pytest.raises(ParsingError, match="Returned data is not a dict"),
    ):
        await client.get_user_device_data()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cookie_headers, expected_extract_arg",
    [
        (["DT=token; Path=/;"], ["DT=token; Path=/;"]),
        ([], []),
    ],
)
async def test_get_initial_dt_variants(config_na, session, cookie_headers, expected_extract_arg):
    client = RESTClient(config_na, session)
    mock_headers = MagicMock()
    mock_headers.getall = MagicMock(return_value=cookie_headers)
    mock_response = MagicMock()
    mock_response.headers = mock_headers

    with (
        patch.object(
            session,
            "get",
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_response),
                __aexit__=AsyncMock(return_value=None),
            ),
        ),
        patch.object(client, "_extract_and_update_cookies", AsyncMock()) as mock_extract,
    ):
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
async def test_authn_check_email_factor_id_exceptions(authn_dict):
    """Test RESTClient._authn_check falls back to region_config['email_factor_id'] on KeyError/TypeError."""
    config = MagicMock(spec=MyAirConfig)
    config.region = "NA"
    config.username = "user"
    config.password = "pw"
    config.device_token = None
    # Provide a region_config with a known email_factor_id
    config.region = "NA"
    session = MagicMock(spec=ClientSession)
    client = RESTClient(config, session)

    # Patch session.post to return a mock response with .json() returning authn_dict
    mock_response = MagicMock()
    mock_response.json = AsyncMock(return_value=authn_dict)
    mock_response.__aenter__.return_value = mock_response
    session.post.return_value = mock_response

    # Patch _resmed_response_error_check to do nothing
    client._resmed_response_error_check = AsyncMock()

    # Should NOT raise, but should set _email_factor_id to region_config["email_factor_id"]
    result = await client._authn_check()
    assert client._email_factor_id == client._region_config["email_factor_id"]
    assert result == "MFA_REQUIRED"


@pytest.mark.asyncio
async def test_get_access_token_not_new_token(monkeypatch):
    """Test _get_access_token when access_token is present and equals self._access_token (NOT branch)."""
    config = MagicMock(spec=MyAirConfig)
    config.region = "NA"
    config.username = "user"
    config.password = "pw"
    config.device_token = None
    session = MagicMock(spec=ClientSession)
    client = RESTClient(config, session)

    # Set up the client with an existing access token
    client._access_token = "abc123"

    # Patch all network calls in _get_access_token
    # Patch the GET to authorize_url to return a location header with a code
    mock_code_res = MagicMock()
    mock_code_res.headers.get.return_value = "https://redirect#code=thecode"
    mock_code_res.headers.getall.return_value = []
    mock_code_res.__aenter__.return_value = mock_code_res
    session.get.return_value = mock_code_res

    # Patch the POST to token_url to return a token_dict with the same access_token as current
    mock_token_res = MagicMock()
    mock_token_res.json = AsyncMock(
        return_value={
            "access_token": "abc123",  # Same as client._access_token
            "id_token": "idtoken",
        }
    )
    mock_token_res.__aenter__.return_value = mock_token_res
    session.post.return_value = mock_token_res

    # Patch error check to do nothing
    with patch.object(RESTClient, "_resmed_response_error_check", AsyncMock()):
        await client._get_access_token()

    # Should NOT log "Obtained new access token" and should NOT change _access_token
    assert client._access_token == "abc123"


@pytest.mark.asyncio
async def test_get_access_token_logs_when_access_token_is_not_none(monkeypatch, caplog):
    """Test _get_access_token logs when self._access_token is not None and a new token is received."""
    config = MagicMock(spec=MyAirConfig)
    config.region = "NA"
    config.username = "user"
    config.password = "pw"
    config.device_token = None
    session = MagicMock(spec=ClientSession)
    client = RESTClient(config, session)

    # Set up the client with an existing access token
    client._access_token = "abc123"

    # Patch all network calls in _get_access_token
    # Patch the GET to authorize_url to return a location header with a code
    mock_code_res = MagicMock()
    mock_code_res.headers.get.return_value = "https://redirect#code=thecode"
    mock_code_res.headers.getall.return_value = []
    mock_code_res.__aenter__.return_value = mock_code_res
    session.get.return_value = mock_code_res

    # Patch the POST to token_url to return a token_dict with a new access_token
    mock_token_res = MagicMock()
    mock_token_res.json = AsyncMock(
        return_value={
            "access_token": "newtoken456",  # Different from client._access_token
            "id_token": "idtoken",
        }
    )
    mock_token_res.__aenter__.return_value = mock_token_res
    session.post.return_value = mock_token_res

    # Patch error check to do nothing
    with (
        patch.object(RESTClient, "_resmed_response_error_check", AsyncMock()),
        caplog.at_level("INFO"),
    ):
        await client._get_access_token()

    # Should log "Obtained new access token" and update _access_token
    assert "Obtained new access token" in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "active_value,expected",
    [
        (True, True),
        (False, False),
    ],
)
async def test_is_access_token_active_variants(config_na, session, active_value, expected):
    """Parametrized test for _is_access_token_active returning True/False."""
    client = RESTClient(config_na, session)
    client._access_token = "token"
    session.post.return_value.__aenter__.return_value.json = AsyncMock(
        return_value={"active": active_value}
    )
    session.post.return_value.__aenter__.return_value.headers = {}
    session.post.return_value.__aenter__.return_value.status = 200
    with patch.object(RESTClient, "_resmed_response_error_check", new=AsyncMock()):
        assert await client._is_access_token_active() is expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "email_verified_value,expected",
    [
        (True, True),
        (False, False),
    ],
)
async def test_is_email_verified_variants(config_na, session, email_verified_value, expected):
    """Parametrized test for is_email_verified returning True/False."""
    client = RESTClient(config_na, session)
    client._access_token = "token"
    session.get.return_value.__aenter__.return_value.json = AsyncMock(
        return_value={"email_verified": email_verified_value}
    )
    session.get.return_value.__aenter__.return_value.headers = {}
    session.get.return_value.__aenter__.return_value.status = 200
    with patch.object(RESTClient, "_resmed_response_error_check", new=AsyncMock()):
        assert await client.is_email_verified() is expected
