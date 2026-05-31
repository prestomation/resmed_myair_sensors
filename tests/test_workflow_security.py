"""Workflow-level tests that protect low-privilege CI behavior."""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _workflow_text(workflow_path: str) -> str:
    """Read a workflow file from the repository root.

    Args:
        workflow_path: Repository-relative workflow path.

    Returns:
        The workflow text.
    """
    return (REPO_ROOT / workflow_path).read_text()


def _step_blocks(workflow: str, step_name: str) -> list[str]:
    """Extract every named workflow step from raw workflow text.

    Args:
        workflow: Complete workflow text.
        step_name: Name of the step to extract.

    Returns:
        Text blocks for every matching step.
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
        (".github/workflows/validate.yml", "Checkout"),
        (".github/workflows/pytest_coverage.yml", "Checkout Repository"),
    ],
)
def test_read_only_workflows_disable_persisted_checkout_credentials(
    workflow_path: str, checkout_step_name: str
) -> None:
    """Read-only workflows do not leave a write-capable token in git config."""
    checkout_blocks = _step_blocks(_workflow_text(workflow_path), checkout_step_name)

    for checkout_block in checkout_blocks:
        assert "persist-credentials: false" in checkout_block


@pytest.mark.parametrize(
    "workflow_path",
    [
        ".github/workflows/linters.yml",
        ".github/workflows/validate.yml",
    ],
)
def test_read_only_workflows_use_contents_read_permissions(workflow_path: str) -> None:
    """Read-only validation workflows request only repository read access."""
    workflow = _workflow_text(workflow_path)

    assert "permissions:" in workflow
    assert "contents: read" in workflow
    assert "contents: write" not in workflow
    assert "pull-requests: write" not in workflow
