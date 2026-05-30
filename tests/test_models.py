"""Tests for typed ResMed myAir domain models."""

from datetime import date

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


def test_sleep_record_with_missing_fields_defaults() -> None:
    """Missing usage and date values should be safe defaults."""
    record = MyAirSleepRecord.from_api({})

    assert record.start_date is None
    assert record.total_usage_minutes == 0
    assert record.friendly_usage_time == "0:00"
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
