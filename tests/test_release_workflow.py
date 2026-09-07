"""Semantic contracts for guarded ResMed release automation."""

from pathlib import Path
from typing import Any, cast

import yaml  # type: ignore[import-untyped]

REPO_ROOT = Path(__file__).resolve().parents[1]


def _workflow(name: str) -> dict[str, Any]:
    """Load a workflow while normalizing YAML's boolean ``on`` key.

    Args:
        name (str): Workflow filename.

    Returns:
        dict[str, Any]: Parsed workflow document.
    """
    document = cast(
        "dict[object, Any]",
        yaml.safe_load((REPO_ROOT / ".github/workflows" / name).read_text(encoding="utf-8")),
    )
    if True in document:
        document["on"] = document.pop(True)
    return cast("dict[str, Any]", document)


def _steps(document: dict[str, Any], job: str) -> dict[str, dict[str, Any]]:
    """Return the named steps of one workflow job.

    Args:
        document (dict[str, Any]): Parsed workflow document.
        job (str): Workflow job identifier.

    Returns:
        dict[str, dict[str, Any]]: Named workflow step definitions.
    """
    return {
        step["name"]: step
        for step in document["jobs"][job]["steps"]
        if isinstance(step, dict) and isinstance(step.get("name"), str)
    }


def test_release_is_one_guarded_job_with_published_trigger() -> None:
    """Keep privileged release work in one source-preserving job."""
    document = _workflow("release.yml")

    assert document["on"] == {"release": {"types": ["published"]}}
    assert document["permissions"] == {"contents": "read"}
    assert set(document["jobs"]) == {"release"}
    job = document["jobs"]["release"]
    assert job["permissions"] == {
        "actions": "write",
        "checks": "read",
        "contents": "write",
        "statuses": "read",
    }
    steps = _steps(document, "release")
    assert "Package candidate source and verified archive" not in steps
    assert "Download candidate prepared by read-only job" not in steps
    assert "Run locked tests for candidate B" not in steps


def test_stable_release_has_exact_candidate_and_immutable_gates() -> None:
    """Require exact version-only candidates before guarded promotion."""
    steps = _steps(_workflow("release.yml"), "release")
    base = steps["Validate event source and immutable starting refs"]["run"]
    candidate = steps["Create deterministic stable release commit B"]["run"]
    dispatch = steps["Dispatch and verify immutable release gates"]["run"]
    promotion = steps["Atomically advance target and guarded release tag"]["run"]

    assert 'git diff --name-only "$source_sha^" "$source_sha"' in base
    assert '--manifest-path "$resume_dir/manifest.json"' in base
    assert 'cmp "$resume_dir/const.py" custom_components/resmed_myair/const.py' in base
    assert (
        "git add custom_components/resmed_myair/manifest.json custom_components/resmed_myair/const.py"
        in candidate
    )
    assert "git diff --cached --name-only" in candidate
    for check in (
        "linters.yml::Run Linters",
        "pytest_check.yml::pytest release check",
        "uv-lock-check.yml::Validate uv lock consistency",
        "validate.yml::Hassfest Validation",
        "validate.yml::HACS Validation",
    ):
        assert check in dispatch
    assert "git push --atomic" in promotion
    assert '--force-with-lease="refs/heads/$RELEASE_TARGET:$SOURCE_SHA"' in promotion
    assert '--force-with-lease="refs/tags/$RELEASE_TAG:$ORIGINAL_TAG_OID"' in promotion


def test_archives_are_tied_to_rechecked_source_identity() -> None:
    """Build from the candidate and verify refs before every upload."""
    steps = _steps(_workflow("release.yml"), "release")
    archive_mtime = '--mtime="@$(git log -1 --format=%ct HEAD)"'
    assert archive_mtime in steps["Build and verify release archive"]["run"]
    stable_upload = steps["Verify release identity and upload verified archive"]["run"]
    prerelease_upload = steps["Verify prerelease identity and upload archive"]["run"]
    assert "verify_hacs_archive.py" in stable_upload
    assert "refs/tags/$RELEASE_TAG^{}" in stable_upload
    assert "verify_hacs_archive.py" in prerelease_upload
    assert "refs/tags/$RELEASE_TAG^{}" in prerelease_upload
    assert "git push" not in prerelease_upload


def test_dispatched_pytest_gate_is_read_only_and_exact_sha() -> None:
    """Keep candidate testing out of the write-token release job."""
    document = _workflow("pytest_check.yml")

    assert document["on"]["workflow_dispatch"]["inputs"]["expected_sha"]["required"] is True
    job = document["jobs"]["release-tests"]
    assert job["permissions"] == {"contents": "read", "pull-requests": "read"}
    steps = _steps(document, "release-tests")
    guard = steps["Require the dispatched candidate SHA"]["run"]
    checkout = steps["Checkout Repository"]["with"]
    assert "^[0-9a-f]{40}$" in guard
    assert 'test "$WORKFLOW_SHA" = "$EXPECTED_SHA"' in guard
    assert checkout == {"ref": "${{ inputs.expected_sha }}", "persist-credentials": False}
    assert "uv run --locked --group pytest pytest" in steps["Run pytest from the lock"]["run"]
