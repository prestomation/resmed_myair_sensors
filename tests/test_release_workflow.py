"""Release-workflow tests that protect dispatch and versioning behavior."""

from importlib import util
import json
from pathlib import Path
import sys
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github/workflows/release.yml"
SCRIPT_PATH = REPO_ROOT / ".github/scripts/update_release_version.py"
WORKFLOW_SCRIPT_PATH = ".github/scripts/update_release_version.py"


def _workflow_text() -> str:
    """Return the checked-in release workflow text."""
    return WORKFLOW_PATH.read_text()


def _step_block(workflow: str, step_name: str) -> str:
    """Extract a named workflow step from raw workflow text.

    Args:
        workflow: Complete workflow text.
        step_name: Name of the step to extract.

    Returns:
        The text block for the requested step.
    """
    step_label = f"- name: {step_name}"
    assert step_label in workflow, f"{step_name} step is missing"
    step_index = workflow.index(step_label)
    next_step_index = workflow.find("\n      - name:", step_index + len(step_label))
    return workflow[step_index:] if next_step_index == -1 else workflow[step_index:next_step_index]


@pytest.fixture
def release_version_script() -> ModuleType:
    """Load the checked-in release version script as an importable module."""
    spec = util.spec_from_file_location("update_release_version", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = util.module_from_spec(spec)
    previous_module = sys.modules.get("update_release_version")
    sys.modules["update_release_version"] = module
    spec.loader.exec_module(module)
    try:
        return module
    finally:
        if previous_module is None:
            sys.modules.pop("update_release_version", None)
        else:
            sys.modules["update_release_version"] = previous_module


def test_release_workflow_is_dispatch_only() -> None:
    """Release creation requires an explicit manual dispatch."""
    workflow = _workflow_text()
    trigger_block = workflow.split("permissions:", 1)[0]

    assert "workflow_dispatch:" in trigger_block
    assert "\n  release:" not in trigger_block
    assert "bump:" in trigger_block
    assert "tag:" in trigger_block
    assert "prerelease:" in trigger_block


def test_release_workflow_serializes_tag_creation() -> None:
    """Release runs serialize without cancelling an in-progress publication."""
    workflow = _workflow_text()

    assert "concurrency:" in workflow
    assert "group: release" in workflow
    assert "cancel-in-progress: false" in workflow


def test_release_workflow_limits_write_permission_to_release_job() -> None:
    """Only the release job receives permission to publish tags and releases."""
    workflow = _workflow_text()

    assert "permissions:\n  contents: read" in workflow
    assert "release:\n    permissions:\n      contents: write" in workflow


def test_release_workflow_validates_default_branch_before_checkout() -> None:
    """Manual releases must target the repository default branch."""
    workflow = _workflow_text()

    assert workflow.index("- name: Validate dispatch ref") < workflow.index(
        "- name: Checkout selected revision"
    )
    assert '[[ "$RELEASE_REF" != "$DEFAULT_BRANCH" ]]' in workflow


def test_release_workflow_runs_checked_in_version_update_script() -> None:
    """Release workflow delegates version-file edits to the checked-in script."""
    workflow = _workflow_text()
    step_block = _step_block(workflow, "Create versioned release commit and annotated tag")

    assert f"python3 {WORKFLOW_SCRIPT_PATH}" in step_block
    assert '--tag-name "$RELEASE_TAG"' in step_block
    assert "python - <<'PY'" not in workflow


@pytest.mark.parametrize(
    "tag_name",
    ["v0.2.8", "v0.3.0-beta.1", "v0.2.7.1", "v0.3.0b1"],
)
def test_validate_release_tag_accepts_supported_formats(
    release_version_script: ModuleType, tag_name: str
) -> None:
    """Supported release tag formats pass validation."""
    release_version_script.validate_release_tag(tag_name)


@pytest.mark.parametrize(
    "tag_name",
    ["", "0.2.8", "v0", "v0.2.8 beta", "v0.2.8;echo-bad"],
)
def test_validate_release_tag_rejects_invalid_formats(
    release_version_script: ModuleType, tag_name: str
) -> None:
    """Malformed release tags fail before version files are changed."""
    with pytest.raises(ValueError, match="Invalid release tag"):
        release_version_script.validate_release_tag(tag_name)


@pytest.mark.parametrize(
    ("bump_type", "expected_tag"),
    [("patch", "v0.2.8"), ("minor", "v0.3.0"), ("major", "v1.0.0")],
)
def test_next_stable_release_tag(
    release_version_script: ModuleType, bump_type: str, expected_tag: str
) -> None:
    """Stable bumps use the highest stable release and ignore prereleases."""
    tags = ["v0.1.7", "v0.2.7", "v0.3.0-beta.1", "untagged-example"]

    assert release_version_script.next_stable_release_tag(tags, bump_type) == expected_tag


@pytest.mark.parametrize(
    ("const_text", "expected_error"),
    [
        ('"""Constants."""\n\nVERSION = "v0.1.0"\nDOMAIN = "resmed_myair"\n', None),
        ('"""Constants."""\n\nDOMAIN = "resmed_myair"\n', "VERSION assignment"),
    ],
)
def test_release_version_script_updates_manifest_and_const(
    tmp_path: Path,
    release_version_script: ModuleType,
    const_text: str,
    expected_error: str | None,
) -> None:
    """The release script rewrites files or rejects invalid const metadata."""
    manifest_path = tmp_path / "manifest.json"
    const_path = tmp_path / "const.py"
    manifest_path.write_text(json.dumps({"domain": "resmed_myair", "version": "v0.1.0"}))
    const_path.write_text(const_text)

    if expected_error is not None:
        with pytest.raises(ValueError, match=expected_error):
            release_version_script.update_release_version_files(
                tag_name="v1.2.3",
                manifest_path=manifest_path,
                const_path=const_path,
            )
        return

    release_version_script.update_release_version_files(
        tag_name="v1.2.3",
        manifest_path=manifest_path,
        const_path=const_path,
    )

    assert json.loads(manifest_path.read_text())["version"] == "v1.2.3"
    assert manifest_path.read_text().endswith("\n")
    assert 'VERSION = "v1.2.3"' in const_path.read_text()
