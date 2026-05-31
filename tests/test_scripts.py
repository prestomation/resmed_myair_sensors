"""Tests for repository shell helper scripts."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

REPO_ROOT = Path(__file__).resolve().parents[1]


def _copy_script_harness(tmp_path: Path, script_name: str) -> Path:
    """Copy one shell script plus a fake setup script into a temporary repo.

    Args:
        tmp_path: Temporary directory supplied by pytest.
        script_name: Name of the shell helper under `scripts`.

    Returns:
        Temporary repository root.
    """
    repo = tmp_path / "repo"
    scripts = repo / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(REPO_ROOT / "scripts" / script_name, scripts / script_name)
    (scripts / "setup").write_text(
        """#!/usr/bin/env bash
set -euo pipefail
mkdir -p .venv/bin
printf '#!/usr/bin/env bash\\necho python \"$@\" >> setup.log\\n' > .venv/bin/python
printf '#!/usr/bin/env bash\\necho prek \"$@\" >> setup.log\\n' > .venv/bin/prek
printf '#!/usr/bin/env bash\\necho mypy \"$@\" >> setup.log\\n' > .venv/bin/mypy
chmod +x .venv/bin/python .venv/bin/prek .venv/bin/mypy
echo setup >> setup.log
""",
        encoding="utf-8",
    )
    (scripts / "setup").chmod(0o755)
    (scripts / script_name).chmod(0o755)
    return repo


def test_test_script_runs_setup_when_venv_is_missing(tmp_path: Path) -> None:
    """Test helper bootstraps the venv before invoking pytest."""
    repo = _copy_script_harness(tmp_path, "test")

    result = subprocess.run(  # noqa: S603
        [str(repo / "scripts" / "test"), "tests/test_example.py"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert (repo / "setup.log").read_text(encoding="utf-8").splitlines() == [
        "setup",
        "python -m pytest tests/test_example.py",
    ]


def test_lint_script_runs_setup_when_tools_are_missing(tmp_path: Path) -> None:
    """Lint helper bootstraps missing lint tools before running prek."""
    repo = _copy_script_harness(tmp_path, "lint")

    result = subprocess.run(  # noqa: S603
        [str(repo / "scripts" / "lint")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert (repo / "setup.log").read_text(encoding="utf-8").splitlines() == [
        "setup",
        "prek run -a",
    ]


def test_live_smoke_test_script_runs_setup_when_venv_is_missing(tmp_path: Path) -> None:
    """Live-smoke wrapper bootstraps the venv before invoking the Python script."""
    repo = _copy_script_harness(tmp_path, "live_smoke_test")
    (repo / "scripts" / "live_smoke_test.py").write_text(
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )

    result = subprocess.run(  # noqa: S603
        [str(repo / "scripts" / "live_smoke_test"), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert (repo / "setup.log").read_text(encoding="utf-8").splitlines() == [
        "setup",
        "python scripts/live_smoke_test.py --help",
    ]
