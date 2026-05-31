"""Release-workflow tests that protect versioning and tag-update behavior."""

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


def test_edited_release_checkout_uses_release_tag() -> None:
    """Edited release runs continue from the published release tag."""
    workflow = WORKFLOW_PATH.read_text()

    assert (
        "github.event_name == 'release' && github.event.release.tag_name || github.ref" in workflow
    )


def test_release_workflow_serializes_tag_updates() -> None:
    """Tag-updating release runs serialize via workflow concurrency."""
    workflow = WORKFLOW_PATH.read_text()

    assert "concurrency:" in workflow
    assert "${{ github.workflow }}-${{ github.event.release.tag_name || github.ref }}" in workflow
    assert "cancel-in-progress: true" in workflow


def test_published_release_checkout_uses_release_tag() -> None:
    """Published release builds check out the tag created for that release."""
    workflow = WORKFLOW_PATH.read_text()
    checkout_step = "- name: Checkout Repository"
    update_version_step = "- name: Update Release Version Files"

    assert checkout_step in workflow
    assert update_version_step in workflow
    checkout_index = workflow.index(checkout_step)
    update_version_index = workflow.index(update_version_step, checkout_index)
    checkout_block = workflow[checkout_index:update_version_index]

    assert "github.event.release.tag_name" in checkout_block
    assert "github.event.release.target_commitish" not in checkout_block


def test_release_shell_steps_use_tag_environment_variable() -> None:
    """Shell steps quote the release tag before moving or pushing it."""
    workflow = WORKFLOW_PATH.read_text()
    shell_step_names = [
        "Update Release Version Files",
        "Update Release with Version Changes Commit",
    ]

    for step_name in shell_step_names:
        step_label = f"- name: {step_name}"
        assert step_label in workflow, f"{step_name} step is missing"
        step_index = workflow.index(step_label)
        next_step_index = workflow.find("\n      - name:", step_index + len(step_label))
        step_block = (
            workflow[step_index:] if next_step_index == -1 else workflow[step_index:next_step_index]
        )

        assert "TAG_NAME: ${{ github.event.release.tag_name }}" in step_block
        assert "${{ github.event.release.tag_name }}" not in step_block.split("run: |", 1)[1]

    assert 'git tag -f "$TAG_NAME"' in workflow
    assert 'git push -f origin "$TAG_NAME"' in workflow


def test_release_workflow_runs_checked_in_version_update_script() -> None:
    """Release workflow delegates version-file edits to the checked-in script."""
    workflow = WORKFLOW_PATH.read_text()
    step_label = "- name: Update Release Version Files"

    assert step_label in workflow
    step_index = workflow.index(step_label)
    next_step_index = workflow.find("\n      - name:", step_index + len(step_label))
    step_block = (
        workflow[step_index:] if next_step_index == -1 else workflow[step_index:next_step_index]
    )

    assert f"python {WORKFLOW_SCRIPT_PATH}" in step_block
    assert '--tag-name "$TAG_NAME"' in step_block
    assert "python - <<'PY'" not in workflow


def test_release_version_script_updates_manifest_and_const(
    tmp_path: Path,
    release_version_script: ModuleType,
) -> None:
    """The version update script rewrites both manifest and const metadata."""
    manifest_path = tmp_path / "manifest.json"
    const_path = tmp_path / "const.py"
    manifest_path.write_text(json.dumps({"domain": "resmed_myair", "version": "v0.1.0"}))
    const_path.write_text('"""Constants."""\n\nVERSION = "v0.1.0"\nDOMAIN = "resmed_myair"\n')

    release_version_script.update_release_version_files(
        tag_name="v1.2.3",
        manifest_path=manifest_path,
        const_path=const_path,
    )

    assert json.loads(manifest_path.read_text())["version"] == "v1.2.3"
    assert manifest_path.read_text().endswith("\n")
    assert 'VERSION = "v1.2.3"' in const_path.read_text()


def test_release_version_script_rejects_missing_const_version(
    tmp_path: Path,
    release_version_script: ModuleType,
) -> None:
    """The version update script rejects const.py files without `VERSION`."""
    manifest_path = tmp_path / "manifest.json"
    const_path = tmp_path / "const.py"
    manifest_path.write_text(json.dumps({"domain": "resmed_myair", "version": "v0.1.0"}))
    const_path.write_text('"""Constants."""\n\nDOMAIN = "resmed_myair"\n')

    with pytest.raises(ValueError, match="VERSION assignment"):
        release_version_script.update_release_version_files(
            tag_name="v1.2.3",
            manifest_path=manifest_path,
            const_path=const_path,
        )


def test_edited_release_does_not_force_move_tag() -> None:
    """Edited releases skip version commits and avoid force-moving tags."""
    workflow = WORKFLOW_PATH.read_text()

    guarded_steps = [
        "Commit & Push Version Changes",
        "Update Release with Version Changes Commit",
    ]

    for step_name in guarded_steps:
        step_label = f"- name: {step_name}"
        assert step_label in workflow, f"{step_name} step is missing"
        step_index = workflow.index(step_label)
        assert "github.event.action == 'published'" in workflow[step_index:], (
            f"{step_name} must be guarded to published release events"
        )
        condition_index = workflow.index(
            "github.event.action == 'published'",
            step_index,
        )
        assert condition_index > step_index
