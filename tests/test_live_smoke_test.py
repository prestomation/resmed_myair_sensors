"""Tests for the manual myAir live smoke-test script."""

from __future__ import annotations

from datetime import date
import importlib.util
from pathlib import Path
import subprocess

from custom_components.resmed_myair.models import (
    MyAirCoordinatorData,
    MyAirDevice,
    MyAirSleepRecord,
)

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "live_smoke_test.py"
WRAPPER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "live_smoke_test"
SPEC = importlib.util.spec_from_file_location("live_smoke_test", SCRIPT_PATH)
assert SPEC is not None
assert SPEC.loader is not None
live_smoke_test = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(live_smoke_test)


def test_shell_wrapper_runs_resmed_live_smoke_test_help() -> None:
    """Shell wrapper invokes this repo's live smoke-test script."""
    result = subprocess.run(  # noqa: S603
        [str(WRAPPER_PATH), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Run a manual live smoke test against ResMed myAir." in result.stdout


def test_load_env_file_parses_assignments_and_quoted_values(tmp_path: Path) -> None:
    """Env-file loading accepts comments, blank lines, exports, and quotes."""
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
            "cpap_sleep_data_last_collected": "2026-05-30T11:22:33Z",
            "most_recent_sleep_date": "2026-05-30",
        },
        "record_count": 2,
    }


def test_write_json_payload_serializes_dates(tmp_path: Path) -> None:
    """Output writing serializes date values and creates parent directories."""
    output_file = tmp_path / "nested" / "live_smoke_test_output.json"

    live_smoke_test.write_json_payload(output_file, {"date": date(2026, 5, 30)})

    assert output_file.read_text(encoding="utf-8") == '{\n  "date": "2026-05-30"\n}\n'
