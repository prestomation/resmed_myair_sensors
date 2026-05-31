"""Manual live smoke test for ResMed myAir credentials and payload discovery."""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Mapping
from datetime import date, datetime
import getpass
import json
import os
from pathlib import Path
import sys
from typing import Any

from aiohttp import ClientConnectionError, ClientResponseError, ClientSession

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from custom_components.resmed_myair.client.const import (  # noqa: E402
    AUTH_NEEDS_MFA,
    AUTHN_SUCCESS,
    REGION_NA,
)
from custom_components.resmed_myair.client.myair_client import (  # noqa: E402
    AuthenticationError,
    IncompleteAccountError,
    MyAirConfig,
    ParsingError,
)
from custom_components.resmed_myair.client.rest_client import RESTClient  # noqa: E402
from custom_components.resmed_myair.models import MyAirCoordinatorData  # noqa: E402

DEFAULT_ENV_FILE = Path("live_smoke_test.env")
DEFAULT_OUTPUT_FILE = Path("live_smoke_test_output.json")
ENV_USERNAME = "MYAIR_USERNAME"
ENV_PASSWORD = "MYAIR_PASSWORD"  # noqa: S105
ENV_REGION = "MYAIR_REGION"
ENV_DEVICE_TOKEN = "MYAIR_DEVICE_TOKEN"  # noqa: S105
ENV_MFA_CODE = "MYAIR_MFA_CODE"


def load_env_file(path: Path) -> dict[str, str]:
    """Load simple KEY=VALUE assignments from an env file.

    Args:
        path: Env file to parse.

    Returns:
        Parsed environment assignments. Missing files return an empty mapping.
    """
    if not path.exists():
        return {}

    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line.removeprefix("export ").strip()
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1]
        values[key] = value
    return values


def _get_setting(
    env_values: Mapping[str, str],
    key: str,
    prompt: str,
    *,
    secret: bool = False,
    default: str | None = None,
    no_prompt: bool = False,
) -> str:
    """Resolve one setting from env file, process env, default, or prompt.

    Args:
        env_values: Values loaded from the optional env file.
        key: Environment variable name to resolve.
        prompt: Prompt shown when interactive input is needed.
        secret: Whether to use `getpass` for prompt input.
        default: Optional fallback value.
        no_prompt: Whether missing values should fail instead of prompting.

    Returns:
        Resolved setting value.

    Raises:
        ValueError: If no value is available and prompts are disabled.
    """
    value = env_values.get(key) or os.environ.get(key) or default
    if value:
        return value
    if no_prompt:
        raise ValueError(f"{key} is required when --no-prompt is used")
    if secret:
        return getpass.getpass(f"{prompt}: ")
    return input(f"{prompt}: ")


def build_config(env_values: Mapping[str, str], no_prompt: bool = False) -> MyAirConfig:
    """Build a myAir client config from env values or interactive prompts.

    Args:
        env_values: Values loaded from the optional env file.
        no_prompt: Whether missing credentials should raise instead of prompting.

    Returns:
        Config consumed by the existing REST client.
    """
    return MyAirConfig(
        username=_get_setting(env_values, ENV_USERNAME, "myAir username", no_prompt=no_prompt),
        password=_get_setting(
            env_values,
            ENV_PASSWORD,
            "myAir password",
            secret=True,
            no_prompt=no_prompt,
        ),
        region=_get_setting(
            env_values,
            ENV_REGION,
            "myAir region",
            default=REGION_NA,
            no_prompt=no_prompt,
        ),
        device_token=env_values.get(ENV_DEVICE_TOKEN) or os.environ.get(ENV_DEVICE_TOKEN),
    )


def _serialize_value(value: Any) -> Any:
    """Convert date-like values before JSON serialization.

    Args:
        value: Value passed by `json.dumps`.

    Returns:
        JSON-compatible representation.

    Raises:
        TypeError: If the value is unsupported by this serializer.
    """
    if isinstance(value, date | datetime):
        return value.isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def write_json_payload(path: Path, payload: Mapping[str, Any]) -> None:
    """Write a stable JSON payload to disk.

    Args:
        path: Output path to create.
        payload: JSON-compatible payload to serialize.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"{json.dumps(payload, indent=2, sort_keys=True, default=_serialize_value)}\n",
        encoding="utf-8",
    )


def build_default_payload(
    data: MyAirCoordinatorData,
    *,
    status: str,
    region: str,
) -> dict[str, Any]:
    """Build the default smoke-test output from README sensor fields.

    Args:
        data: Device and sleep records returned by myAir.
        status: Final authentication status.
        region: myAir region used for the request.

    Returns:
        JSON-compatible payload containing the README sensor values.
    """
    device = data.device
    latest_record = data.latest_sleep_record
    return {
        "status": status,
        "region": region,
        "device": {
            "manufacturer": device.manufacturer if device else None,
            "model": device.native_value("deviceType") if device else None,
            "name": device.name if device else None,
            "serial_number": device.serial_number if device else None,
        },
        "sensors": {
            "cpap_ahi_events_per_hour": latest_record.native_value("ahi")
            if latest_record
            else None,
            "cpap_usage_minutes": latest_record.total_usage_minutes if latest_record else None,
            "cpap_mask_on_off_count": latest_record.native_value("maskPairCount")
            if latest_record
            else None,
            "cpap_current_data_date": latest_record.start_date.isoformat()
            if latest_record and latest_record.start_date
            else None,
            "cpap_mask_leak_percent": latest_record.native_value("leakPercentile")
            if latest_record
            else None,
            "cpap_total_myair_score": latest_record.native_value("sleepScore")
            if latest_record
            else None,
            "cpap_sleep_data_last_collected": device.native_value("lastSleepDataReportTime")
            if device
            else None,
            "most_recent_sleep_date": data.most_recent_sleep_date.isoformat()
            if data.most_recent_sleep_date
            else None,
        },
        "record_count": len(data.sleep_records),
    }


def build_raw_payload(data: MyAirCoordinatorData) -> dict[str, Any]:
    """Build a raw payload for local inspection.

    Args:
        data: Device and sleep records returned by myAir.

    Returns:
        Raw device and sleep-record payloads from myAir.
    """
    return {
        "device": data.device.raw if data.device else None,
        "sleep_records": [record.raw for record in data.sleep_records],
    }


async def _authenticate(client: RESTClient, env_values: Mapping[str, str], no_prompt: bool) -> str:
    """Authenticate, prompting for MFA when the account requires it.

    Args:
        client: Client to authenticate.
        env_values: Values loaded from the optional env file.
        no_prompt: Whether missing MFA codes should raise instead of prompting.

    Returns:
        Final authentication status.
    """
    status = await client.connect(initial=True)
    if status != AUTH_NEEDS_MFA:
        return status

    verification_code = _get_setting(
        env_values,
        ENV_MFA_CODE,
        "myAir MFA verification code",
        no_prompt=no_prompt,
    )
    return await client.verify_mfa_and_get_access_token(verification_code)


async def run_live_smoke_test(
    config: MyAirConfig,
    env_values: Mapping[str, str],
    *,
    include_raw: bool,
    no_prompt: bool,
) -> dict[str, Any]:
    """Run the live myAir smoke test and return the selected output payload.

    Args:
        config: myAir credentials and region.
        env_values: Values loaded from the optional env file.
        include_raw: Whether to include raw payload values.
        no_prompt: Whether missing MFA codes should raise instead of prompting.

    Returns:
        JSON-compatible smoke-test output.
    """
    async with ClientSession() as session:
        client = RESTClient(config, session)
        status = await _authenticate(client, env_values, no_prompt)
        if status != AUTHN_SUCCESS:
            raise AuthenticationError(f"Unexpected authentication status: {status}")
        device = await client.get_user_device_data(initial=True)
        sleep_records = await client.get_sleep_records(initial=True)

    data = MyAirCoordinatorData(device=device, sleep_records=tuple(sleep_records))
    payload = build_default_payload(data, status=status, region=config.region)
    if client.device_token:
        payload["device_token_available"] = True
    if include_raw:
        payload["raw"] = build_raw_payload(data)
    return payload


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser for the smoke-test script.

    Returns:
        Configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Run a manual live smoke test against ResMed myAir.",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=DEFAULT_ENV_FILE,
        help=f"env file containing credentials; default: {DEFAULT_ENV_FILE}",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_FILE,
        help=f"JSON output path; default: {DEFAULT_OUTPUT_FILE}",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="include raw myAir payload values in the output file",
    )
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="fail when credentials or MFA code are missing instead of prompting",
    )
    return parser


async def async_main(argv: list[str] | None = None) -> int:
    """Run the smoke-test CLI asynchronously.

    Args:
        argv: Optional argument list for tests.

    Returns:
        Process exit code.
    """
    args = build_parser().parse_args(argv)
    env_values = load_env_file(args.env_file)
    config = build_config(env_values, no_prompt=args.no_prompt)
    payload = await run_live_smoke_test(
        config,
        env_values,
        include_raw=args.raw,
        no_prompt=args.no_prompt,
    )
    write_json_payload(args.output, payload)
    print(f"Wrote live myAir smoke-test output to {args.output}")  # noqa: T201
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the smoke-test CLI.

    Args:
        argv: Optional argument list for tests.

    Returns:
        Process exit code.
    """
    try:
        return asyncio.run(async_main(argv))
    except (
        AuthenticationError,
        ClientConnectionError,
        ClientResponseError,
        IncompleteAccountError,
        OSError,
        ParsingError,
        ValueError,
    ) as err:
        print(  # noqa: T201
            f"Live smoke test failed: {type(err).__name__}: {err}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
