"""Tests for the release workflow guardrails."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github/workflows/release.yml"


def test_edited_release_checkout_uses_release_tag() -> None:
    """Edited releases should package the existing release tag."""
    workflow = WORKFLOW_PATH.read_text()

    assert "github.event.action == 'edited'" in workflow
    assert "github.event.release.tag_name" in workflow
    assert "github.event.release.target_commitish || github.ref" in workflow


def test_edited_release_does_not_force_move_tag() -> None:
    """Edited releases should not commit version changes or force-move tags."""
    workflow = WORKFLOW_PATH.read_text()

    guarded_steps = [
        "Commit & Push Version Changes",
        "Update Release with Version Changes Commit",
    ]

    for step_name in guarded_steps:
        step_index = workflow.index(f"- name: {step_name}")
        condition_index = workflow.index(
            "github.event.action == 'published'",
            step_index,
        )
        assert condition_index > step_index
