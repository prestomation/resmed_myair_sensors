"""Tests for typed ResMed myAir domain models."""

from datetime import date
from decimal import Decimal

import pytest

from custom_components.resmed_myair.models import (
    MyAirCoordinatorData,
    MyAirDevice,
    MyAirSleepRecord,
)


def test_device_preserves_raw_values_and_device_info_fields() -> None:
    """Device model exposes stable fields while preserving raw API data."""
    device = MyAirDevice.from_api(
        {
            "serialNumber": "123",
            "localizedName": "AirSense",
            "deviceType": "CPAP",
            "fgDeviceManufacturerName": "ResMed",
            "lastSleepDataReportTime": "2024-07-18T12:00:00+00:00",
            "maskCode": "M1",
        }
    )

    assert device.serial_number == "123"
    assert device.manufacturer == "ResMed"
    assert device.model == "CPAP"
    assert device.name == "AirSense"
    assert device.native_value("maskCode") == "M1"
    assert device.native_value("missing") is None


def test_sleep_record_parses_usage_and_start_date() -> None:
    """Sleep record model exposes typed convenience values."""
    record = MyAirSleepRecord.from_api(
        {
            "startDate": "2024-07-18",
            "totalUsage": 125,
            "ahi": 1.2,
        }
    )

    assert record.start_date == date(2024, 7, 18)
    assert record.total_usage_minutes == 125
    assert record.friendly_usage_time == "2:05"
    assert record.native_value("ahi") == 1.2


def test_negative_usage_is_clamped_for_friendly_display() -> None:
    """Negative usage values display as zero usage."""
    record = MyAirSleepRecord.from_api({"startDate": "2024-07-18", "totalUsage": -5})

    assert record.total_usage_minutes == -5
    assert record.friendly_usage_time == "0:00"


def test_coordinator_data_exposes_latest_and_most_recent_used_date() -> None:
    """Coordinator data exposes the latest record and most recent used date."""
    data = MyAirCoordinatorData(
        device=MyAirDevice.from_api({"serialNumber": "123"}),
        sleep_records=(
            MyAirSleepRecord.from_api({"startDate": "2024-07-17", "totalUsage": 0}),
            MyAirSleepRecord.from_api({"startDate": "2024-07-18", "totalUsage": 30}),
        ),
    )

    assert data.latest_sleep_record is not None
    assert data.latest_sleep_record.start_date == date(2024, 7, 18)
    assert data.most_recent_sleep_date == date(2024, 7, 18)


def test_device_fields_default_to_empty_or_none_for_missing_values() -> None:
    """Missing keys should not crash model construction."""
    device = MyAirDevice.from_api({})

    assert device.raw == {}
    assert device.serial_number == ""
    assert device.manufacturer is None
    assert device.model is None
    assert device.name is None


def test_device_ignores_non_string_serial_number() -> None:
    """Non-string serial numbers should not be coerced to text."""
    device = MyAirDevice.from_api({"serialNumber": None})

    assert device.serial_number == ""


def test_device_fields_with_non_string_optional_values_are_none() -> None:
    """Non-string optional fields should become None."""
    device = MyAirDevice.from_api(
        {
            "fgDeviceManufacturerName": 123,
            "deviceType": True,
            "localizedName": {"name": "AirSense"},
        }
    )

    assert device.manufacturer is None
    assert device.model is None
    assert device.name is None


def test_sleep_record_with_missing_fields_defaults() -> None:
    """Missing usage and date values should be safe defaults."""
    record = MyAirSleepRecord.from_api({})

    assert record.start_date is None
    assert record.total_usage_minutes is None
    assert record.friendly_usage_time is None
    assert record.has_usage is False


def test_sleep_record_with_non_string_start_date_has_none_start_date() -> None:
    """Non-string startDate values should not be parsed."""
    record = MyAirSleepRecord.from_api({"startDate": 123, "totalUsage": 30})

    assert record.start_date is None
    assert record.total_usage_minutes == 30
    assert record.friendly_usage_time == "0:30"
    assert record.has_usage is True


def test_sleep_record_with_invalid_start_date_has_none_start_date() -> None:
    """Invalid startDate strings should not crash model construction."""
    record = MyAirSleepRecord.from_api({"startDate": "not-a-date", "totalUsage": 30})

    assert record.start_date is None
    assert record.total_usage_minutes == 30


def test_device_from_api_accepts_none() -> None:
    """from_api accepts None and produces a safe empty device."""
    device = MyAirDevice.from_api(None)

    assert device.raw == {}
    assert device.serial_number == ""
    assert device.manufacturer is None
    assert device.model is None
    assert device.name is None


def test_sleep_record_from_api_accepts_none() -> None:
    """from_api accepts None and produces a safe empty record."""
    record = MyAirSleepRecord.from_api(None)

    assert record.raw == {}
    assert record.start_date is None
    assert record.total_usage_minutes is None
    assert record.friendly_usage_time is None
    assert record.has_usage is False


def test_most_recent_sleep_date_skips_zero_usage_records() -> None:
    """Most recent sleep date should ignore records with zero usage."""
    data = MyAirCoordinatorData(
        device=None,
        sleep_records=(
            MyAirSleepRecord.from_api({"startDate": "2024-07-17", "totalUsage": 0}),
            MyAirSleepRecord.from_api({"startDate": "2024-07-18", "totalUsage": 0}),
        ),
    )

    assert data.latest_sleep_record is not None
    assert data.latest_sleep_record.start_date == date(2024, 7, 18)
    assert data.most_recent_sleep_date is None


def test_sleep_record_with_non_int_usage_is_none() -> None:
    """Non-int usage values should not be treated as usage minutes."""
    record = MyAirSleepRecord.from_api({"startDate": "2024-07-18", "totalUsage": True})

    assert record.total_usage_minutes is None
    assert record.friendly_usage_time is None
    assert record.has_usage is False


@pytest.mark.parametrize("raw_usage", [125.9, Decimal("125.9"), "125.9"])
def test_sleep_record_coerces_numeric_usage_values(raw_usage: float | Decimal | str) -> None:
    """Numeric API usage values should be coerced to integer minutes."""
    record = MyAirSleepRecord.from_api({"startDate": "2024-07-18", "totalUsage": raw_usage})

    assert record.total_usage_minutes == 125
    assert record.friendly_usage_time == "2:05"
    assert record.has_usage is True


def test_coordinator_data_selects_latest_record_by_start_date() -> None:
    """Coordinator data should not rely on API sleep record order."""
    data = MyAirCoordinatorData(
        sleep_records=(
            MyAirSleepRecord.from_api({"startDate": "2024-07-20", "totalUsage": 0}),
            MyAirSleepRecord.from_api({"startDate": "2024-07-18", "totalUsage": 30}),
            MyAirSleepRecord.from_api({"startDate": "2024-07-19", "totalUsage": 60}),
        ),
    )

    assert data.latest_sleep_record is not None
    assert data.latest_sleep_record.start_date == date(2024, 7, 20)
    assert data.most_recent_sleep_date == date(2024, 7, 19)


def test_coordinator_data_defaults_to_empty() -> None:
    """Coordinator data should construct when payload members are omitted."""
    data = MyAirCoordinatorData()

    assert data.device is None
    assert data.sleep_records == ()
    assert data.latest_sleep_record is None
    assert data.most_recent_sleep_date is None
