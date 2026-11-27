"""Tests for the minimum Home Assistant test environment workflow helper."""

import importlib.util
import json
from pathlib import Path

from homeassistant import const as ha_const
import pytest

SCRIPT_PATH = Path(__file__).parents[1] / ".github" / "scripts" / "minimum_ha_test_env.py"
SCRIPT_SPEC = importlib.util.spec_from_file_location("minimum_ha_test_env", SCRIPT_PATH)
assert SCRIPT_SPEC is not None
assert SCRIPT_SPEC.loader is not None
minimum_env = importlib.util.module_from_spec(SCRIPT_SPEC)
SCRIPT_SPEC.loader.exec_module(minimum_env)


def _write_hacs(tmp_path: Path, payload: object) -> Path:
    """Write a hacs.json file.

    Args:
        tmp_path (Path): Directory for the file.
        payload (object): JSON payload to write.

    Returns:
        Path: Path to the written file.
    """
    hacs_path = tmp_path / "hacs.json"
    hacs_path.write_text(json.dumps(payload), encoding="utf-8")
    return hacs_path


@pytest.mark.parametrize(
    ("minimum", "plugin"),
    [
        ("2026.3.0b0", "pytest-homeassistant-custom-component>=0.13"),
        ("2026.10.4", "pytest-homeassistant-custom-component>=0.13"),
        ("2026.11.0b0", "pytest-homeassistant>=2026.11.0"),
        ("2026.11.0", "pytest-homeassistant>=2026.11.0"),
        ("2027.1.0", "pytest-homeassistant>=2026.11.0"),
    ],
)
def test_requirements_select_plugin_for_minimum(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], minimum: str, plugin: str
) -> None:
    """Print the plugin covering the hacs.json minimum and the HA lower bound.

    Args:
        tmp_path (Path): Directory for the hacs.json fixture.
        capsys (pytest.CaptureFixture[str]): Captures the printed requirements.
        minimum (str): Minimum Home Assistant version declared in hacs.json.
        plugin (str): Expected test plugin requirement.
    """
    hacs_path = _write_hacs(tmp_path, {"homeassistant": minimum})

    minimum_env.main(["--hacs", str(hacs_path), "requirements"])

    assert capsys.readouterr().out.splitlines() == [plugin, f"homeassistant>={minimum}"]


@pytest.mark.parametrize(
    "payload",
    [{}, {"homeassistant": ""}, {"homeassistant": 2026.3}, {"homeassistant": "latest"}],
)
def test_requirements_reject_unusable_minimum(tmp_path: Path, payload: object) -> None:
    """Fail instead of resolving an unbounded Home Assistant version.

    Args:
        tmp_path (Path): Directory for the hacs.json fixture.
        payload (object): hacs.json content without a usable minimum.
    """
    hacs_path = _write_hacs(tmp_path, payload)

    with pytest.raises(ValueError):
        minimum_env.main(["--hacs", str(hacs_path), "requirements"])


def test_verify_accepts_resolved_release_at_or_above_minimum(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Report the installed release when it is the resolved pin.

    Args:
        tmp_path (Path): Directory for the hacs.json fixture.
        capsys (pytest.CaptureFixture[str]): Captures the reported version.
    """
    hacs_path = _write_hacs(tmp_path, {"homeassistant": "2026.3.0b0"})
    installed = ha_const.__version__

    minimum_env.main(["--hacs", str(hacs_path), "verify", installed])

    assert capsys.readouterr().out == f"Home Assistant {installed} (minimum 2026.3.0b0)\n"


@pytest.mark.parametrize(
    ("minimum", "resolved"),
    [
        ("2026.3.0b0", "2000.1.0"),
        ("2999.1.0", ha_const.__version__),
    ],
    ids=["differs-from-resolved-pin", "older-than-minimum"],
)
def test_verify_rejects_unexpected_home_assistant(
    tmp_path: Path, minimum: str, resolved: str
) -> None:
    """Reject a release that is not the resolved pin or predates the minimum.

    Args:
        tmp_path (Path): Directory for the hacs.json fixture.
        minimum (str): Minimum Home Assistant version declared in hacs.json.
        resolved (str): Home Assistant version pinned by the resolver.
    """
    hacs_path = _write_hacs(tmp_path, {"homeassistant": minimum})

    with pytest.raises(SystemExit, match=f"expected {resolved}"):
        minimum_env.main(["--hacs", str(hacs_path), "verify", resolved])
