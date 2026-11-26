"""Response actions for ResMed myAir."""

from datetime import date

from homeassistant.const import ATTR_CONFIG_ENTRY_ID
from homeassistant.core import (
    HomeAssistant,
    ServiceCall,
    ServiceResponse,
    SupportsResponse,
    callback,
)
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import service
from homeassistant.util.dt import parse_date

from .const import DOMAIN
from .coordinator import TIMELINE_REQUEST_ERRORS, MyAirDataUpdateCoordinator

_TIMELINE_ACTION = "get_nightly_therapy_timeline"


@callback
def async_setup_services(hass: HomeAssistant) -> None:
    """Register the Nightly Therapy Timeline response action.

    Args:
        hass (HomeAssistant): Home Assistant instance.
    """

    async def get_nightly_therapy_timeline(call: ServiceCall) -> ServiceResponse:
        """Return the summary and ordered events for the requested night.

        Args:
            call (ServiceCall): Action call with the myAir config entry and assigned date.

        Returns:
            ServiceResponse: One Nightly Therapy Timeline.

        Raises:
            HomeAssistantError: myAir did not provide a usable timeline.
            ServiceValidationError: The account or date is missing or invalid.
        """
        entry_id = call.data.get(ATTR_CONFIG_ENTRY_ID)
        if not isinstance(entry_id, str) or not entry_id:
            raise ServiceValidationError(
                translation_domain=DOMAIN, translation_key="timeline_missing_account"
            )
        raw_date = call.data.get("date")
        assigned_date = raw_date if type(raw_date) is date else None
        if isinstance(raw_date, str):
            assigned_date = parse_date(raw_date)
        if assigned_date is None:
            raise ServiceValidationError(
                translation_domain=DOMAIN, translation_key="timeline_invalid_date"
            )
        entry = service.async_get_config_entry(hass, DOMAIN, entry_id)
        coordinator: MyAirDataUpdateCoordinator = entry.runtime_data
        try:
            timeline = await coordinator.async_get_nightly_therapy_timeline(assigned_date)
        except TIMELINE_REQUEST_ERRORS:
            raise HomeAssistantError(
                translation_domain=DOMAIN, translation_key="timeline_request_failed"
            ) from None
        if timeline is None or timeline.events is None:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="timeline_unavailable",
                translation_placeholders={"date": assigned_date.isoformat()},
            )
        return {
            "date": timeline.assigned_date.isoformat(),
            "ahi": timeline.ahi,
            "total_seconds_in_apnea": timeline.total_seconds_in_apnea,
            "total_usage_hours": timeline.total_usage_hours,
            "events": [event.as_dict() for event in timeline.events],
        }

    service.async_register_admin_service(
        hass,
        DOMAIN,
        _TIMELINE_ACTION,
        get_nightly_therapy_timeline,
        # The action validates its input in the handler. Core supports a null schema.
        schema=None,  # type: ignore[arg-type]
        supports_response=SupportsResponse.ONLY,
    )
