"""Tests for the pytest coverage workflow guardrails."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github/workflows/pytest_coverage.yml"


def test_checkout_does_not_persist_credentials() -> None:
    """Checkout should not leave pull request credentials in the git config."""
    workflow = WORKFLOW_PATH.read_text()
    checkout_index = workflow.index("- name: Checkout Repository")
    next_step_index = workflow.index("- name: Debug GitHub Variables")
    checkout_block = workflow[checkout_index:next_step_index]

    assert "persist-credentials: false" in checkout_block
