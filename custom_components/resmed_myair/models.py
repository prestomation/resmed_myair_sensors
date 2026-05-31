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
    """Convert API usage value to an integer minute count."""
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
    """Format usage minutes into friendly `H:MM` text."""
    if total_usage_minutes is None:
        return None

    clamped_minutes = max(total_usage_minutes, 0)
    return f"{clamped_minutes // 60}:{clamped_minutes % 60:02}"


def _to_optional_str(raw: Any) -> str | None:
    """Return a normalized optional string value from arbitrary API payload data."""
    if not isinstance(raw, str):
        return None
    return raw


def _to_optional_date(raw: Any) -> date | None:
    """Return a normalized optional date value from arbitrary API payload data."""
    if not isinstance(raw, str):
        return None
    try:
        return date.fromisoformat(raw)
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class MyAirDevice:
    """Normalized typed representation of a device payload."""

    raw: dict[str, Any]
    serial_number: str
    manufacturer: str | None
    model: str | None
    name: str | None

    @classmethod
    def from_api(cls, data: Mapping[str, Any] | None) -> Self:
        """Create a typed device from raw API payload data."""
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
        """Return the raw payload value for a key or ``None``."""
        return self.raw.get(key)


@dataclass(frozen=True, slots=True)
class MyAirSleepRecord:
    """Normalized typed representation of a sleep record payload."""

    raw: dict[str, Any]
    start_date: date | None
    total_usage_minutes: int | None
    friendly_usage_time: str | None
    has_usage: bool

    @classmethod
    def from_api(cls, data: Mapping[str, Any] | None) -> Self:
        """Create a typed sleep record from raw API payload data."""
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
        """Return the raw payload value for a key or ``None``."""
        return self.raw.get(key)


@dataclass(frozen=True, slots=True)
class MyAirCoordinatorData:
    """Typed coordinator payload wrapper for Home Assistant integration state."""

    device: MyAirDevice | None = None
    sleep_records: tuple[MyAirSleepRecord, ...] = ()

    @property
    def latest_sleep_record(self) -> MyAirSleepRecord | None:
        """Return the latest available sleep record if any."""
        if not self.sleep_records:
            return None
        return max(self.sleep_records, key=lambda record: record.start_date or date.min)

    @property
    def most_recent_sleep_date(self) -> date | None:
        """Return the most recent date that has recorded usage."""
        records_with_usage = [
            record for record in self.sleep_records if record.start_date and record.has_usage
        ]
        if not records_with_usage:
            return None
        return max(records_with_usage, key=lambda record: record.start_date or date.min).start_date
