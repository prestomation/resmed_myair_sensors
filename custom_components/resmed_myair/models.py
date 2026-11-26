"""Typed domain models for ResMed myAir API payloads."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
import logging
from math import isfinite
from typing import Any, Self

from homeassistant.util.json import JsonObjectType

from .const import SCORE_COMPONENT_NAMES, SLEEP_RECORD_INDEX_FIELDS

_LOGGER: logging.Logger = logging.getLogger(__name__)


def _to_usage_minutes(raw_usage: Any) -> int | None:
    """Normalize myAir ``totalUsage`` values into whole minutes.

    Args:
        raw_usage (Any): API value that may arrive as an int, decimal-like string, float,
            or malformed scalar.

    Returns:
        int | None: Whole usage minutes, or ``None`` when the payload cannot
            represent usage.
    """
    if isinstance(raw_usage, bool):
        return None
    if isinstance(raw_usage, int):
        return raw_usage
    if isinstance(raw_usage, float | Decimal | str):
        try:
            usage_decimal = Decimal(str(raw_usage))
            usage_minutes = int(usage_decimal)
        except (
            InvalidOperation,
            ValueError,
        ):
            return None
        if usage_decimal != Decimal(usage_minutes):
            _LOGGER.info("Truncated fractional totalUsage value to minutes: %r", raw_usage)
        return usage_minutes
    return None


def _format_usage_time(total_usage_minutes: int | None) -> str | None:
    """Render usage minutes in the text format users expect in HA.

    Args:
        total_usage_minutes (int | None): Normalized CPAP usage minutes.

    Returns:
        str | None: ``H:MM`` text, or ``None`` when usage is unavailable.
    """
    if total_usage_minutes is None:
        return None

    clamped_minutes = max(total_usage_minutes, 0)
    return f"{clamped_minutes // 60}:{clamped_minutes % 60:02}"


def _to_optional_str(raw: Any) -> str | None:
    """Keep string API fields while discarding unexpected payload types.

    Args:
        raw (Any): Raw field value from a myAir payload.

    Returns:
        str | None: The string value, or ``None`` for missing and non-string
            values.
    """
    if not isinstance(raw, str):
        return None
    return raw


def _to_optional_date(raw: Any) -> date | None:
    """Parse ISO date fields while tolerating malformed myAir payloads.

    Args:
        raw (Any): Raw date field from a myAir payload.

    Returns:
        date | None: Parsed date, or ``None`` when the field is missing or invalid.
    """
    if not isinstance(raw, str):
        return None
    try:
        return date.fromisoformat(raw)
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class MyAirDevice:
    """Typed view of the assigned flow-generator payload and its raw source."""

    raw: dict[str, Any]
    serial_number: str
    manufacturer: str | None
    model: str | None
    name: str | None

    @classmethod
    def from_api(cls, data: Mapping[str, Any] | None) -> Self:
        """Build device metadata from a raw GraphQL device mapping.

        Args:
            data (Mapping[str, Any] | None): Raw myAir device payload, or
                ``None`` when the API omitted it.

        Returns:
            Self: Typed device with normalized serial, manufacturer, model, and
                name fields.
        """
        raw = dict(data or {})
        serial_number = raw.get("serialNumber", "")
        if not isinstance(serial_number, str):
            serial_number = ""
        return cls(
            raw=raw,
            serial_number=serial_number,
            manufacturer=_to_optional_str(raw.get("fgDeviceManufacturerName")),
            model=_to_optional_str(raw.get("deviceType")),
            name=_to_optional_str(raw.get("localizedName")),
        )

    def native_value(self, key: str) -> Any | None:
        """Read a sensor value from the original device payload.

        Args:
            key (str): GraphQL field name used by the sensor description.

        Returns:
            Any | None: Raw payload value, or ``None`` when the key is absent.
        """
        return self.raw.get(key)


@dataclass(frozen=True, slots=True)
class MyAirSleepRecord:
    """Typed view of a nightly sleep record and its derived usage fields."""

    raw: dict[str, Any]
    start_date: date | None
    total_usage_minutes: int | None
    friendly_usage_time: str | None
    has_usage: bool

    @classmethod
    def from_api(cls, data: Mapping[str, Any] | None) -> Self:
        """Build a sleep record from a raw GraphQL record mapping.

        Args:
            data (Mapping[str, Any] | None): Raw myAir sleep-record payload, or
                ``None`` when unavailable.

        Returns:
            Self: Typed record with parsed date, normalized minutes, and friendly
                usage text.
        """
        raw = dict(data or {})
        total_usage_minutes = _to_usage_minutes(raw.get("totalUsage"))
        has_usage = total_usage_minutes is not None and total_usage_minutes > 0
        return cls(
            raw=raw,
            start_date=_to_optional_date(raw.get("startDate")),
            total_usage_minutes=total_usage_minutes,
            friendly_usage_time=_format_usage_time(total_usage_minutes),
            has_usage=has_usage,
        )

    def native_value(self, key: str) -> Any | None:
        """Read a sensor value, validating respiratory indexes and score components.

        Args:
            key (str): GraphQL field name used by the sensor description.

        Returns:
            Any | None: Reported value, or ``None`` when absent or invalid.
        """
        value = self.raw.get(key)
        if key in SLEEP_RECORD_INDEX_FIELDS and (
            isinstance(value, bool)
            or not isinstance(value, int | float)
            or (isinstance(value, float) and not isfinite(value))
            or value < 0
        ):
            return None
        if key in SCORE_COMPONENT_NAMES and (not isinstance(value, int) or isinstance(value, bool)):
            return None
        return value


def _event_time(raw: object) -> datetime | None:
    """Parse a myAir event timestamp with an explicit timezone.

    Args:
        raw (object): Timestamp from a respiratory or therapy status event.

    Returns:
        datetime | None: The offset-aware timestamp, or None for missing or invalid values.
    """
    if not isinstance(raw, str):
        return None
    try:
        timestamp = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return timestamp if timestamp.tzinfo is not None else None


def _seconds(raw: object) -> int | None:
    """Validate an integer duration reported by myAir.

    Args:
        raw (object): Duration in seconds.

    Returns:
        int | None: Nonnegative integer seconds, or None for missing or invalid values.
    """
    return raw if type(raw) is int and raw >= 0 else None


def _summary_number(raw: object) -> float | None:
    """Validate a numeric value from the nightly summary.

    Args:
        raw (object): AHI or usage hours reported by myAir.

    Returns:
        float | None: A finite, nonnegative value, or None when unavailable.
    """
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        return None
    return float(raw) if raw >= 0 and isfinite(raw) else None


@dataclass(frozen=True, slots=True)
class MyAirTherapyEvent:
    """A respiratory event or therapy status transition at its original time."""

    event_type: str
    timestamp: datetime
    end_timestamp: datetime | None = None
    duration_seconds: int | None = None

    def as_dict(self) -> JsonObjectType:
        """Serialize the event for a Home Assistant action response.

        Returns:
            JsonObjectType: The event timestamps and details myAir supplied.
        """
        event: JsonObjectType = {
            "type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
        }
        if self.end_timestamp is not None:
            event["end_timestamp"] = self.end_timestamp.isoformat()
        if self.duration_seconds is not None:
            event["duration_seconds"] = self.duration_seconds
        return event


def _timeline_events(raw: Mapping[str, Any]) -> tuple[MyAirTherapyEvent, ...] | None:
    """Merge complete myAir event lists, sorting by occurrence time.

    Args:
        raw (Mapping[str, Any]): Nightly Therapy Timeline payload.

    Returns:
        tuple[MyAirTherapyEvent, ...] | None: Ordered events, or None when either
            list cannot be reliably interpreted.
    """
    respiratory = raw.get("respiratoryEvents")
    therapy_status = raw.get("therapyStatusEvents")
    if not isinstance(respiratory, list) or not isinstance(therapy_status, list):
        return None

    events: list[MyAirTherapyEvent] = []
    for item in respiratory:
        if not isinstance(item, Mapping) or not (
            event_type := _to_optional_str(item.get("eventType"))
        ):
            return None
        start = _event_time(item.get("startDate"))
        end = _event_time(item.get("endDate"))
        timestamp = start or end
        if timestamp is None:
            return None
        events.append(
            MyAirTherapyEvent(
                event_type, timestamp, end if start else None, _seconds(item.get("durationSeconds"))
            )
        )

    for item in therapy_status:
        if (
            not isinstance(item, Mapping)
            or not (event_type := _to_optional_str(item.get("eventType")))
            or (timestamp := _event_time(item.get("date"))) is None
        ):
            return None
        events.append(MyAirTherapyEvent(event_type, timestamp))

    return tuple(sorted(events, key=lambda event: event.timestamp))


@dataclass(frozen=True, slots=True)
class MyAirNightlyTherapyTimeline:
    """The myAir summary and events for a single assigned date."""

    assigned_date: date
    ahi: float | None
    total_seconds_in_apnea: int | None
    total_usage_hours: float | None
    events: tuple[MyAirTherapyEvent, ...] | None

    @classmethod
    def from_api(cls, assigned_date: date, raw: Mapping[str, Any]) -> Self:
        """Parse a matching Nightly Therapy Timeline payload.

        Args:
            assigned_date (date): myAir-assigned date of this timeline.
            raw (Mapping[str, Any]): Timeline data returned by myAir.

        Returns:
            Self: Normalized summary and events.
        """
        return cls(
            assigned_date=assigned_date,
            ahi=_summary_number(raw.get("ahi")),
            total_seconds_in_apnea=_seconds(raw.get("totalSecondsInApnea")),
            total_usage_hours=_summary_number(raw.get("totalUsageHours")),
            events=_timeline_events(raw),
        )


@dataclass(frozen=True, slots=True)
class MyAirCoordinatorData:
    """Immutable snapshot of the latest myAir device and sleep data."""

    device: MyAirDevice | None = None
    sleep_records: tuple[MyAirSleepRecord, ...] = ()
    time_in_apnea: int | None = None

    @property
    def latest_sleep_record(self) -> MyAirSleepRecord | None:
        """Select the newest sleep record by start date.

        Returns:
            MyAirSleepRecord | None: Most recent record, or ``None`` when the
                coordinator has no records.
        """
        return max(
            self.sleep_records,
            key=lambda record: record.start_date or date.min,
            default=None,
        )

    @property
    def most_recent_sleep_date(self) -> date | None:
        """Find the newest sleep date with non-zero CPAP usage.

        Returns:
            date | None: Date of the most recent usage-bearing record, or ``None``
                if none qualify.
        """
        return max(
            (
                record.start_date
                for record in self.sleep_records
                if record.start_date and record.has_usage
            ),
            default=None,
        )
