"""Workflow-level tests that protect low-privilege CI behavior."""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _workflow_text(workflow_path: str) -> str:
    """Read a workflow file from the repository root.

    Args:
        workflow_path (str): Repository-relative path of the workflow under test.

    Returns:
        str: Complete text of the selected workflow file.
    """
    return (REPO_ROOT / workflow_path).read_text()


def _step_blocks(workflow: str, step_name: str) -> list[str]:
    """Extract every named workflow step from raw workflow text.

    Args:
        workflow (str): Complete workflow text to scan for named steps.
        step_name (str): Exact step label whose blocks should be collected.

    Returns:
        list[str]: Raw text block for each matching workflow step.
    """
    step_label = f"- name: {step_name}"
    step_blocks: list[str] = []
    search_start = 0
    while True:
        step_index = workflow.find(step_label, search_start)
        if step_index == -1:
            break
        next_step_index = workflow.find("\n      - name:", step_index + len(step_label))
        step_blocks.append(
            workflow[step_index:] if next_step_index == -1 else workflow[step_index:next_step_index]
        )
        search_start = step_index + len(step_label)
    assert step_blocks
    return step_blocks


@pytest.mark.parametrize(
    ("workflow_path", "checkout_step_name"),
    [
        (".github/workflows/linters.yml", "Checkout Repository"),
        (".github/workflows/uv-lock-check.yml", "Checkout repository"),
        (".github/workflows/validate.yml", "Checkout"),
        (".github/workflows/pytest_coverage.yml", "Checkout Repository"),
    ],
)
def test_read_only_workflows_disable_persisted_checkout_credentials(
    workflow_path: str, checkout_step_name: str
) -> None:
    """Verify read-only workflows do not persist checkout credentials.

    Args:
        workflow_path (str): Repository-relative workflow path in the read-only
            validation set.
        checkout_step_name (str): Checkout step label whose credential setting is
            protected by this assertion.
    """
    checkout_blocks = _step_blocks(_workflow_text(workflow_path), checkout_step_name)

    for checkout_block in checkout_blocks:
        assert "persist-credentials: false" in checkout_block


@pytest.mark.parametrize(
    "workflow_path",
    [
        ".github/workflows/linters.yml",
        ".github/workflows/uv-lock-check.yml",
        ".github/workflows/validate.yml",
    ],
)
def test_read_only_workflows_use_contents_read_permissions(workflow_path: str) -> None:
    """Verify validation workflows request repository contents access only for reading.

    Args:
        workflow_path (str): Repository-relative path of the validation workflow
            whose top-level permissions are inspected.
    """
    workflow = _workflow_text(workflow_path)

    assert "permissions:" in workflow
    assert "contents: read" in workflow
    assert "contents: write" not in workflow
    assert "pull-requests: write" not in workflow
