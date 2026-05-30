"""Typed domain models for ResMed myAir API payloads."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from typing import Any, Self

from homeassistant.util import dt as dt_util


def _to_usage_minutes(raw_usage: Any) -> int:
    """Convert API usage value to an integer minute count."""
    if isinstance(raw_usage, int):
        return raw_usage
    if isinstance(raw_usage, bool):
        return 1 if raw_usage else 0
    if isinstance(raw_usage, float):
        return int(raw_usage)
    if isinstance(raw_usage, str):
        try:
            return int(raw_usage)
        except ValueError:
            return 0
    return 0


def _format_usage_time(total_usage_minutes: int) -> str:
    """Format usage minutes into friendly `H:MM` text."""
    clamped_minutes = max(total_usage_minutes, 0)
    return f"{clamped_minutes // 60}:{clamped_minutes % 60:02}"


@dataclass(frozen=True, slots=True)
class MyAirDevice:
    """Normalized typed representation of a device payload."""

    raw: dict[str, Any]
    serial_number: str
    manufacturer: str | None
    model: str | None
    name: str | None

    @classmethod
    def from_api(cls, data: Mapping[str, Any]) -> Self:
        """Create a typed device from raw API payload data."""
        raw = dict(data)
        return cls(
            raw=raw,
            serial_number=str(raw.get("serialNumber", "")),
            manufacturer=raw.get("fgDeviceManufacturerName"),
            model=raw.get("deviceType"),
            name=raw.get("localizedName"),
        )

    def native_value(self, key: str) -> Any | None:
        """Return the raw payload value for a key or ``None``."""
        return self.raw.get(key)


@dataclass(frozen=True, slots=True)
class MyAirSleepRecord:
    """Normalized typed representation of a sleep record payload."""

    raw: dict[str, Any]
    start_date: date | None
    total_usage_minutes: int
    friendly_usage_time: str
    has_usage: bool

    @classmethod
    def from_api(cls, data: Mapping[str, Any]) -> Self:
        """Create a typed sleep record from raw API payload data."""
        raw = dict(data)
        start_date = dt_util.parse_date(raw.get("startDate", ""))
        total_usage_minutes = _to_usage_minutes(raw.get("totalUsage", 0))
        has_usage = total_usage_minutes > 0
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

    device: MyAirDevice | None
    sleep_records: tuple[MyAirSleepRecord, ...]

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
