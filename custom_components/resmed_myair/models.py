"""Typed domain models for ResMed myAir API payloads."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
import logging
from typing import Any, Self

_LOGGER: logging.Logger = logging.getLogger(__name__)


def _to_usage_minutes(raw_usage: Any) -> int | None:
    """Normalize myAir ``totalUsage`` values into whole minutes.

    Args:
        raw_usage: API value that may arrive as an int, decimal-like string, float,
            or malformed scalar.

    Returns:
        Whole usage minutes, or ``None`` when the payload cannot represent usage.
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
        total_usage_minutes: Normalized CPAP usage minutes.

    Returns:
        ``H:MM`` text, or ``None`` when usage is unavailable.
    """
    if total_usage_minutes is None:
        return None

    clamped_minutes = max(total_usage_minutes, 0)
    return f"{clamped_minutes // 60}:{clamped_minutes % 60:02}"


def _to_optional_str(raw: Any) -> str | None:
    """Keep string API fields while discarding unexpected payload types.

    Args:
        raw: Raw field value from a myAir payload.

    Returns:
        The string value, or ``None`` for missing and non-string values.
    """
    if not isinstance(raw, str):
        return None
    return raw


def _to_optional_date(raw: Any) -> date | None:
    """Parse ISO date fields while tolerating malformed myAir payloads.

    Args:
        raw: Raw date field from a myAir payload.

    Returns:
        Parsed date, or ``None`` when the field is missing or invalid.
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
            data: Raw myAir device payload, or ``None`` when the API omitted it.

        Returns:
            Typed device with normalized serial, manufacturer, model, and name fields.
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
            key: GraphQL field name used by the sensor description.

        Returns:
            Raw payload value, or ``None`` when the key is absent.
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
            data: Raw myAir sleep-record payload, or ``None`` when unavailable.

        Returns:
            Typed record with parsed date, normalized minutes, and friendly usage text.
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
        """Read a sensor value from the original sleep-record payload.

        Args:
            key: GraphQL field name used by the sensor description.

        Returns:
            Raw payload value, or ``None`` when the key is absent.
        """
        return self.raw.get(key)


@dataclass(frozen=True, slots=True)
class MyAirCoordinatorData:
    """Immutable snapshot of the latest myAir device and sleep data."""

    device: MyAirDevice | None = None
    sleep_records: tuple[MyAirSleepRecord, ...] = ()

    @property
    def latest_sleep_record(self) -> MyAirSleepRecord | None:
        """Select the newest sleep record by start date.

        Returns:
            Most recent record, or ``None`` when the coordinator has no records.
        """
        if not self.sleep_records:
            return None
        return max(self.sleep_records, key=lambda record: record.start_date or date.min)

    @property
    def most_recent_sleep_date(self) -> date | None:
        """Find the newest sleep date with non-zero CPAP usage.

        Returns:
            Date of the most recent usage-bearing record, or ``None`` if none qualify.
        """
        records_with_usage = [
            record for record in self.sleep_records if record.start_date and record.has_usage
        ]
        if not records_with_usage:
            return None
        return max(records_with_usage, key=lambda record: record.start_date or date.min).start_date
