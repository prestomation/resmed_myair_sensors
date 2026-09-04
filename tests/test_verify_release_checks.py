"""Fail-closed tests for candidate workflow dispatch verification."""

import importlib.util
from pathlib import Path
import re
from typing import Any

import pytest

SCRIPT_PATH = Path(__file__).parents[1] / ".github/scripts/verify_release_checks.py"
SPEC = importlib.util.spec_from_file_location("verify_release_checks", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)

REPOSITORY = "owner/repository"
REF = "release-validation/v1.2.3-1-1"
SHA = "a" * 40


@pytest.mark.parametrize("response", [{}, {"workflow_run_id": 0}, {"workflow_run_id": True}])
def test_dispatch_requires_an_authoritative_run_id(
    monkeypatch: pytest.MonkeyPatch, response: dict[str, Any]
) -> None:
    """Reject dispatch responses that cannot identify exactly one new workflow run.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture replacing GitHub API calls.
        response (dict[str, Any]): Invalid dispatch payload.
    """
    monkeypatch.setattr(verify, "github_api", lambda _arguments, expected_status=None: response)
    with pytest.raises(verify.GitHubCommandError, match="valid workflow_run_id"):
        verify.dispatch_workflow(REPOSITORY, "linters.yml", REF, SHA)


@pytest.mark.parametrize(
    ("run", "message"),
    [
        (
            {
                "id": 7,
                "workflow_id": 9,
                "event": "push",
                "head_branch": REF,
                "head_sha": SHA,
                "status": "completed",
                "conclusion": "success",
            },
            "dispatched identity",
        ),
        (
            {
                "id": 7,
                "workflow_id": 9,
                "event": "workflow_dispatch",
                "head_branch": REF,
                "head_sha": "b" * 40,
                "status": "completed",
                "conclusion": "success",
            },
            "dispatched identity",
        ),
    ],
)
def test_wait_rejects_wrong_event_or_candidate_sha(
    monkeypatch: pytest.MonkeyPatch, run: dict[str, Any], message: str
) -> None:
    """Reject matching-looking runs that do not prove the dispatched candidate.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture replacing API calls and time.
        run (dict[str, Any]): Mismatched workflow-run payload.
        message (str): Expected failure-message fragment.
    """
    responses = iter([{"id": 9}, run])
    monkeypatch.setattr(verify, "github_api", lambda _arguments: next(responses))
    monkeypatch.setattr(verify.time, "monotonic", lambda: 0.0)
    with pytest.raises(verify.GitHubCommandError, match=re.escape(message)):
        verify.wait_for_workflow(REPOSITORY, "linters.yml", REF, SHA, set(), 1.0, 7)


@pytest.mark.parametrize(
    ("jobs", "message"),
    [
        ([], "missing=['Run Linters']"),
        ([{"name": "Run Linters", "conclusion": "success"}] * 2, "duplicate=['Run Linters']"),
        ([{"name": "Run Linters", "conclusion": "failure"}], "unsuccessful=['Run Linters']"),
    ],
)
def test_verify_jobs_rejects_missing_duplicate_or_failed_required_job(
    monkeypatch: pytest.MonkeyPatch, jobs: list[dict[str, str]], message: str
) -> None:
    """Require exactly one successful instance of each configured job name.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture replacing GitHub API calls.
        jobs (list[dict[str, str]]): Jobs returned by the fixture.
        message (str): Expected failure-message fragment.
    """
    monkeypatch.setattr(
        verify,
        "github_api",
        lambda _arguments: {"total_count": len(jobs), "jobs": jobs},
    )
    with pytest.raises(verify.GitHubCommandError, match=re.escape(message)):
        verify.verify_jobs(REPOSITORY, 7, {"Run Linters"})


def test_parse_required_checks_keeps_only_declared_workflow_job_pairs() -> None:
    """Group explicit candidate gates and reject malformed declarations."""
    assert verify.parse_required_checks(
        ["linters.yml::Run Linters", "validate.yml::Hassfest Validation"]
    ) == {
        "linters.yml": {"Run Linters"},
        "validate.yml": {"Hassfest Validation"},
    }
    with pytest.raises(ValueError, match="workflow::exact job name"):
        verify.parse_required_checks(["validate.yml:Hassfest Validation"])


def test_check_suite_requires_github_actions_and_candidate_sha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a successful run when its suite has a foreign provenance or SHA.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture replacing the suite API call.
    """
    monkeypatch.setattr(
        verify,
        "github_api",
        lambda _arguments: {"head_sha": SHA, "app": {"slug": "foreign"}},
    )
    with pytest.raises(verify.GitHubCommandError, match="check suite"):
        verify.verify_check_suite(REPOSITORY, {"check_suite_id": 10}, SHA)
