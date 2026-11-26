"""Tests for the manual myAir live smoke-test script."""

from __future__ import annotations

from datetime import date
import importlib.util
from pathlib import Path

import pytest

from custom_components.resmed_myair.models import (
    MyAirCoordinatorData,
    MyAirDevice,
    MyAirSleepRecord,
)

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "live_smoke_test.py"
SPEC = importlib.util.spec_from_file_location("live_smoke_test", SCRIPT_PATH)
assert SPEC is not None
assert SPEC.loader is not None
live_smoke_test = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(live_smoke_test)


def test_load_env_file_parses_assignments_and_quoted_values(tmp_path: Path) -> None:
    """Verify env-file parsing keeps valid assignments and strips shell syntax.

    Args:
        tmp_path (Path): Isolated pytest directory in which to create the env
            fixture.
    """
    env_file = tmp_path / "live_smoke_test.env"
    env_file.write_text(
        """# local credentials
export MYAIR_USERNAME='user@example.com'
MYAIR_PASSWORD="secret value"
MYAIR_REGION=EU
IGNORED_LINE""",
        encoding="utf-8",
    )

    values = live_smoke_test.load_env_file(env_file)

    assert values == {
        "MYAIR_USERNAME": "user@example.com",
        "MYAIR_PASSWORD": "secret value",
        "MYAIR_REGION": "EU",
    }


def test_build_default_payload_matches_readme_sensor_fields() -> None:
    """Default output exposes the sensor fields listed in the README."""
    data = MyAirCoordinatorData(
        device=MyAirDevice.from_api(
            {
                "serialNumber": "SN123",
                "localizedName": "Bedroom CPAP",
                "fgDeviceManufacturerName": "ResMed",
                "deviceType": "AirSense 11",
                "lastSleepDataReportTime": "2026-05-30T11:22:33Z",
            }
        ),
        sleep_records=(
            MyAirSleepRecord.from_api(
                {
                    "startDate": "2026-05-29",
                    "totalUsage": 0,
                    "sleepScore": 0,
                    "ahi": 0,
                    "maskPairCount": 0,
                    "leakPercentile": 0,
                }
            ),
            MyAirSleepRecord.from_api(
                {
                    "startDate": "2026-05-30",
                    "totalUsage": 421,
                    "sleepScore": 92,
                    "usageScore": 70,
                    "leakScore": 15,
                    "ahiScore": 3,
                    "maskScore": 4,
                    "ahi": 1.2,
                    "maskPairCount": 3,
                    "leakPercentile": 8,
                }
            ),
        ),
    )

    payload = live_smoke_test.build_default_payload(data, status="SUCCESS", region="NA")

    assert payload == {
        "status": "SUCCESS",
        "region": "NA",
        "device": {
            "manufacturer": "ResMed",
            "model": "AirSense 11",
            "name": "Bedroom CPAP",
            "serial_number": "SN123",
        },
        "sensors": {
            "cpap_ahi_events_per_hour": 1.2,
            "cpap_usage_minutes": 421,
            "cpap_mask_on_off_count": 3,
            "cpap_current_data_date": "2026-05-30",
            "cpap_mask_leak_percent": 8,
            "cpap_total_myair_score": 92,
            "cpap_myair_usage_hours_score": 70,
            "cpap_myair_mask_seal_score": 15,
            "cpap_myair_events_per_hour_score": 3,
            "cpap_myair_mask_on_off_score": 4,
            "cpap_sleep_data_last_collected": "2026-05-30T11:22:33Z",
            "most_recent_sleep_date": "2026-05-30",
        },
        "record_count": 2,
    }


@pytest.mark.parametrize(
    ("record", "usage_score"),
    [
        (None, None),
        ({"startDate": "2026-05-30", "usageScore": 0, "ahiScore": None, "maskScore": True}, 0),
    ],
    ids=["no-record", "zero-and-unavailable-scores"],
)
def test_build_default_payload_preserves_zero_and_reports_missing_scores(
    record: dict[str, object] | None, usage_score: int | None
) -> None:
    """Distinguish reported zeroes from unavailable score components.

    Args:
        record (dict[str, object] | None): Optional myAir sleep record for the output.
        usage_score (int | None): Expected score for Usage Hours.
    """
    records = (MyAirSleepRecord.from_api(record),) if record is not None else ()
    payload = live_smoke_test.build_default_payload(
        MyAirCoordinatorData(sleep_records=records), status="SUCCESS", region="NA"
    )

    assert payload["sensors"]["cpap_myair_usage_hours_score"] == usage_score
    assert payload["sensors"]["cpap_myair_mask_seal_score"] is None
    assert payload["sensors"]["cpap_myair_events_per_hour_score"] is None
    assert payload["sensors"]["cpap_myair_mask_on_off_score"] is None


def test_write_json_payload_serializes_dates(tmp_path: Path) -> None:
    """Verify JSON output converts dates and creates missing parent directories.

    Args:
        tmp_path (Path): Isolated pytest directory for the nested output file.
    """
    output_file = tmp_path / "nested" / "live_smoke_test_output.json"

    live_smoke_test.write_json_payload(output_file, {"date": date(2026, 5, 30)})

    assert output_file.read_text(encoding="utf-8") == '{\n  "date": "2026-05-30"\n}\n'
