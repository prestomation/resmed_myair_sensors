"""Exercise the force-poll action through Home Assistant's config-entry lifecycle."""

from collections.abc import Iterator
from unittest.mock import AsyncMock, patch

from homeassistant.components import sensor as ha_sensor
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ServiceNotFound
import pytest

from custom_components.resmed_myair.client.myair_client import ServiceUnavailableError
from custom_components.resmed_myair.client.rest_client import RESTClient
from custom_components.resmed_myair.const import (
    CONF_PASSWORD,
    CONF_REGION,
    CONF_USER_NAME,
    DOMAIN,
    REGION_NA,
)
from custom_components.resmed_myair.models import MyAirDevice, MyAirSleepRecord
from tests.common import MockConfigEntry


@pytest.fixture(autouse=True)
def configure_hass(enable_custom_integrations: None) -> None:
    """Use Home Assistant's real config-entry manager and action registry.

    Args:
        enable_custom_integrations (None): Enable loading the integration under test.
    """


@pytest.fixture
def myair_requests() -> Iterator[AsyncMock]:
    """Simulate myAir responses while tracking which client fetches sleep records.

    Yields:
        AsyncMock: Spy on the sleep-record requests made by each client.
    """

    def get_device(client: RESTClient) -> MyAirDevice:
        """Return a distinct CPAP device for the second myAir Account.

        Args:
            client (RESTClient): Client requesting the device for its account.

        Returns:
            MyAirDevice: Simulated device metadata.
        """
        serial = (
            "SN456"
            if client._config.username in {"other@example.com", "upper+user@example.com"}
            else "SN123"
        )
        return MyAirDevice.from_api(
            {"serialNumber": serial, "lastSleepDataReportTime": "2024-06-01T12:00:00+00:00"}
        )

    with (
        patch.object(RESTClient, "connect", autospec=True, return_value="token"),
        patch.object(
            RESTClient,
            "get_user_device_data",
            autospec=True,
            side_effect=get_device,
        ),
        patch.object(
            RESTClient,
            "get_sleep_records",
            autospec=True,
            return_value=[MyAirSleepRecord.from_api({"startDate": "2024-06-01", "totalUsage": 60})],
        ) as fetch,
    ):
        yield fetch.mock


def _add_entry(hass: HomeAssistant, username: str) -> MockConfigEntry:
    """Add a myAir config entry to Home Assistant.

    Args:
        hass (HomeAssistant): Home Assistant instance that owns the entry.
        username (str): myAir Account username to store in the entry.

    Returns:
        MockConfigEntry: Entry ready to load through Home Assistant.
    """
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_USER_NAME: username, CONF_PASSWORD: "password", CONF_REGION: REGION_NA},
        version=2,
    )
    entry.add_to_hass(hass)
    return entry


async def test_force_poll_is_removed_on_unload(
    hass: HomeAssistant, myair_requests: AsyncMock
) -> None:
    """Only a loaded config entry can be polled.

    Args:
        hass (HomeAssistant): Home Assistant instance managing the entry and action.
        myair_requests (AsyncMock): Spy recording each client's sleep-record requests.
    """
    entry = _add_entry(hass, "test@example.com")
    action = "force_poll_test_example_com"
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.LOADED
    (setup_request,) = myair_requests.await_args_list
    myair_requests.reset_mock()

    await hass.services.async_call(DOMAIN, action, blocking=True)
    assert myair_requests.await_args_list == [setup_request]
    myair_requests.reset_mock()

    assert await hass.config_entries.async_unload(entry.entry_id)
    with pytest.raises(ServiceNotFound):
        await hass.services.async_call(DOMAIN, action, blocking=True)
    myair_requests.assert_not_awaited()


@pytest.mark.parametrize(
    ("username", "action"),
    [
        ("Upper.User@example.com", "force_poll_upper_user_example_com"),
        ("upper+user@example.com", "force_poll_upper_user_example_com"),
        ("test+alerts@example.com", "force_poll_test_alerts_example_com"),
    ],
)
async def test_force_poll_after_reload_uses_current_username_and_coordinator(
    hass: HomeAssistant, myair_requests: AsyncMock, username: str, action: str
) -> None:
    """Reload switches the action to the current name and coordinator.

    Args:
        hass (HomeAssistant): Home Assistant instance managing the entry and action.
        myair_requests (AsyncMock): Spy recording each client's sleep-record requests.
        username (str): Username stored when the entry is reloaded.
        action (str): Name expected after the reload.
    """
    entry = _add_entry(hass, "Upper.User@example.com")
    original_action = "force_poll_upper_user_example_com"
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    (original_request,) = myair_requests.await_args_list
    myair_requests.reset_mock()
    await hass.services.async_call(DOMAIN, original_action, blocking=True)
    assert myair_requests.await_args_list == [original_request]
    myair_requests.reset_mock()

    hass.config_entries.async_update_entry(entry, data={**entry.data, CONF_USER_NAME: username})
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()
    (reload_request,) = myair_requests.await_args_list
    assert reload_request != original_request
    myair_requests.reset_mock()

    if action != original_action:
        with pytest.raises(ServiceNotFound):
            await hass.services.async_call(DOMAIN, original_action, blocking=True)
    await hass.services.async_call(DOMAIN, action, blocking=True)
    assert myair_requests.await_args_list == [reload_request]


async def test_force_poll_actions_for_two_entries_are_independent(
    hass: HomeAssistant, myair_requests: AsyncMock
) -> None:
    """Reloading and unloading one entry leave the other entry's action usable.

    Args:
        hass (HomeAssistant): Home Assistant instance managing both entries and actions.
        myair_requests (AsyncMock): Spy recording each client's sleep-record requests.
    """
    first = _add_entry(hass, "test@example.com")
    first_action = "force_poll_test_example_com"
    assert await hass.config_entries.async_setup(first.entry_id)
    await hass.async_block_till_done()
    second = _add_entry(hass, "other@example.com")
    second_action = "force_poll_other_example_com"
    assert await hass.config_entries.async_setup(second.entry_id)
    await hass.async_block_till_done()
    first_request, second_request = myair_requests.await_args_list
    myair_requests.reset_mock()

    await hass.services.async_call(DOMAIN, first_action, blocking=True)
    await hass.services.async_call(DOMAIN, second_action, blocking=True)
    assert myair_requests.await_args_list == [first_request, second_request]
    myair_requests.reset_mock()

    assert await hass.config_entries.async_reload(first.entry_id)
    await hass.async_block_till_done()
    (reload_request,) = myair_requests.await_args_list
    assert reload_request != first_request
    myair_requests.reset_mock()
    await hass.services.async_call(DOMAIN, first_action, blocking=True)
    await hass.services.async_call(DOMAIN, second_action, blocking=True)
    assert myair_requests.await_args_list == [reload_request, second_request]
    myair_requests.reset_mock()

    assert await hass.config_entries.async_unload(first.entry_id)
    with pytest.raises(ServiceNotFound):
        await hass.services.async_call(DOMAIN, first_action, blocking=True)
    await hass.services.async_call(DOMAIN, second_action, blocking=True)
    assert myair_requests.await_args_list == [second_request]


async def test_unloading_previous_entry_keeps_replacement_force_poll_action(
    hass: HomeAssistant, myair_requests: AsyncMock
) -> None:
    """Unloading an entry preserves a later registration under the same name.

    Args:
        hass (HomeAssistant): Home Assistant instance managing both entries and the action.
        myair_requests (AsyncMock): Spy recording each client's sleep-record requests.
    """
    first = _add_entry(hass, "upper.user@example.com")
    action = "force_poll_upper_user_example_com"
    assert await hass.config_entries.async_setup(first.entry_id)
    await hass.async_block_till_done()
    second = _add_entry(hass, "upper+user@example.com")
    assert await hass.config_entries.async_setup(second.entry_id)
    await hass.async_block_till_done()
    _, second_request = myair_requests.await_args_list
    myair_requests.reset_mock()

    assert await hass.config_entries.async_unload(first.entry_id)
    await hass.services.async_call(DOMAIN, action, blocking=True)
    assert myair_requests.await_args_list == [second_request]


async def test_force_poll_is_unavailable_after_failed_setup(
    hass: HomeAssistant, myair_requests: AsyncMock
) -> None:
    """A failed initial refresh leaves the action unavailable.

    Args:
        hass (HomeAssistant): Home Assistant instance managing the entry and action.
        myair_requests (AsyncMock): Simulated sleep-record endpoint.
    """
    entry = _add_entry(hass, "test@example.com")
    myair_requests.side_effect = ServiceUnavailableError("myAir is down for maintenance")
    assert not await hass.config_entries.async_setup(entry.entry_id)
    assert entry.state is ConfigEntryState.SETUP_RETRY
    myair_requests.reset_mock()

    with pytest.raises(ServiceNotFound):
        await hass.services.async_call(DOMAIN, "force_poll_test_example_com", blocking=True)
    myair_requests.assert_not_awaited()
    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_force_poll_remains_usable_after_failed_unload(
    hass: HomeAssistant, myair_requests: AsyncMock
) -> None:
    """A failed sensor unload keeps the entry's existing action usable.

    Args:
        hass (HomeAssistant): Home Assistant instance managing the entry and action.
        myair_requests (AsyncMock): Spy recording each client's sleep-record requests.
    """
    entry = _add_entry(hass, "test@example.com")
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    (setup_request,) = myair_requests.await_args_list
    myair_requests.reset_mock()

    with patch.object(ha_sensor, "async_unload_entry", side_effect=RuntimeError("Unload failed")):
        assert not await hass.config_entries.async_unload(entry.entry_id)
    assert entry.state is ConfigEntryState.FAILED_UNLOAD

    await hass.services.async_call(DOMAIN, "force_poll_test_example_com", blocking=True)
    assert myair_requests.await_args_list == [setup_request]
    # The failed unload leaves the coordinator running, so cancel its refresh timer.
    await entry.runtime_data.async_shutdown()
