"""Tests for the release workflow guardrails."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github/workflows/release.yml"


def test_edited_release_checkout_uses_release_tag() -> None:
    """Edited releases should package the existing release tag."""
    workflow = WORKFLOW_PATH.read_text()

    assert (
        "github.event_name == 'release' && github.event.release.tag_name || github.ref" in workflow
    )


def test_release_workflow_serializes_tag_updates() -> None:
    """Release runs that update tags should not overlap."""
    workflow = WORKFLOW_PATH.read_text()

    assert "concurrency:" in workflow
    assert "${{ github.workflow }}-${{ github.event.release.tag_name || github.ref }}" in workflow
    assert "cancel-in-progress: true" in workflow


def test_published_release_checkout_uses_release_tag() -> None:
    """Published releases should package the tag created for the release."""
    workflow = WORKFLOW_PATH.read_text()
    checkout_step = "- name: Checkout Repository"
    update_version_step = "- name: Update Version in Manifest"

    assert checkout_step in workflow
    assert update_version_step in workflow
    checkout_index = workflow.index(checkout_step)
    update_version_index = workflow.index(update_version_step, checkout_index)
    checkout_block = workflow[checkout_index:update_version_index]

    assert "github.event.release.tag_name" in checkout_block
    assert "github.event.release.target_commitish" not in checkout_block


def test_release_shell_steps_use_tag_environment_variable() -> None:
    """Shell commands should quote the release tag from the environment."""
    workflow = WORKFLOW_PATH.read_text()
    shell_step_names = [
        "Update Version in Manifest",
        "Update Version in const.py",
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


def test_edited_release_does_not_force_move_tag() -> None:
    """Edited releases should not commit version changes or force-move tags."""
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
