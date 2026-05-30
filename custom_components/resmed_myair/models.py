"""Typed domain models for ResMed myAir API payloads."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from typing import Any, Self

from homeassistant.util import dt as dt_util


def _to_usage_minutes(raw_usage: Any) -> int | None:
    """Convert API usage value to an integer minute count."""
    if isinstance(raw_usage, bool):
        return None
    if isinstance(raw_usage, int):
        return raw_usage
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
        start_date = dt_util.parse_date(raw.get("startDate", ""))
        total_usage_minutes = _to_usage_minutes(raw.get("totalUsage"))
        has_usage = total_usage_minutes is not None and total_usage_minutes > 0
        return cls(
            raw=raw,
            start_date=start_date,
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
        return self.sleep_records[-1]

    @property
    def most_recent_sleep_date(self) -> date | None:
        """Return the most recent date that has recorded usage."""
        for record in reversed(self.sleep_records):
            if record.start_date and record.has_usage:
                return record.start_date
        return None
