"""Semantic contracts for guarded ResMed release automation."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType
from typing import cast

import pytest
import yaml  # type: ignore[import-untyped]

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github/workflows/release.yml"
VERSION_SCRIPT_PATH = REPO_ROOT / ".github/scripts/update_release_version.py"


def _workflow() -> dict[str, object]:
    """Load the release workflow while normalizing YAML's boolean ``on`` key.

    Returns:
        dict[str, object]: Parsed release workflow.
    """
    document = cast(
        "dict[object, object]", yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    )
    if True in document:
        document["on"] = document.pop(True)
    return cast("dict[str, object]", document)


def _steps(document: dict[str, object], job: str) -> dict[str, dict[str, object]]:
    """Return named steps for one workflow job.

    Args:
        document (dict[str, object]): Parsed release workflow.
        job (str): Job identifier to inspect.

    Returns:
        dict[str, dict[str, object]]: Mapping of step names to definitions.
    """
    jobs = document["jobs"]
    assert isinstance(jobs, dict)
    selected_job = jobs[job]
    assert isinstance(selected_job, dict)
    steps = selected_job["steps"]
    assert isinstance(steps, list)
    return {step["name"]: step for step in steps if isinstance(step, dict) and "name" in step}


@pytest.fixture
def version_script() -> ModuleType:
    """Load the checked-in version helper for direct command-line checks.

    Returns:
        ModuleType: Imported version helper module.
    """
    spec = importlib.util.spec_from_file_location("update_release_version", VERSION_SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["update_release_version"] = module
    spec.loader.exec_module(module)
    return module


def test_release_uses_published_event_and_unprivileged_preparation() -> None:
    """Keep candidate creation and tests outside the write-scoped job."""
    document = _workflow()
    assert document["on"] == {"release": {"types": ["published"]}}
    jobs = document["jobs"]
    assert isinstance(jobs, dict)
    prepare = jobs["prepare"]
    release = jobs["release"]
    assert isinstance(prepare, dict) and isinstance(release, dict)
    assert prepare["permissions"] == {"contents": "read"}
    assert release["permissions"] == {
        "actions": "write",
        "checks": "read",
        "contents": "write",
        "statuses": "read",
    }
    candidate_test = _steps(document, "prepare")["Run locked tests for candidate B"]["run"]
    assert isinstance(candidate_test, str)
    assert "uv run --locked pytest" in candidate_test
    assert _steps(document, "prepare")["Run locked tests for candidate B"]["if"] == (
        "github.event.release.prerelease == false"
    )
    release_checkout = _steps(document, "release")[
        "Checkout trusted default-branch workflow revision"
    ]
    assert release_checkout["with"] == {
        "ref": "${{ needs.prepare.outputs.source-sha }}",
        "fetch-depth": 0,
        "persist-credentials": False,
    }


def test_stable_promotion_requires_exact_candidate_gates_and_leases() -> None:
    """Require candidate gates before the single branch-and-tag mutation."""
    document = _workflow()
    release_steps = _steps(document, "release")
    dispatch = release_steps["Dispatch and verify immutable release gates"]["run"]
    assert isinstance(dispatch, str)
    assert "linters.yml::Run Linters" in dispatch
    assert "uv-lock-check.yml::Validate uv lock consistency" in dispatch
    assert "validate.yml::Hassfest Validation" in dispatch
    assert "validate.yml::HACS Validation" in dispatch
    promotion = release_steps["Atomically advance target and guarded release tag"]["run"]
    assert isinstance(promotion, str)
    assert "git push --atomic" in promotion
    assert "refs/heads/$RELEASE_TARGET:$SOURCE_SHA" in promotion
    assert "refs/tags/$RELEASE_TAG:$ORIGINAL_TAG_OID" in promotion
    assert 'echo "tag-oid=$(git rev-parse "refs/tags/$RELEASE_TAG")"' in promotion
    upload = release_steps["Verify release identity and upload verified archive"]["run"]
    assert isinstance(upload, str)
    assert '"refs/tags/$RELEASE_TAG")" == "$PROMOTED_TAG_OID"' in upload
    assert release_steps["Publish B to an isolated validation branch"]["if"] == (
        "github.event.release.prerelease == false"
    )
    assert release_steps["Dispatch and verify immutable release gates"]["if"] == (
        "github.event.release.prerelease == false"
    )


def test_prereleases_do_not_create_candidate_or_mutate_refs() -> None:
    """Keep prerelease publication archive-only and exclude it from promotion."""
    document = _workflow()
    prepare_steps = _steps(document, "prepare")
    release_steps = _steps(document, "release")
    assert prepare_steps["Create deterministic stable release commit B"]["if"] == (
        "github.event.release.prerelease == false"
    )
    assert release_steps["Upload verified prerelease archive"]["if"] == (
        "github.event.release.prerelease"
    )
    prerelease_upload = release_steps["Upload verified prerelease archive"]["run"]
    assert isinstance(prerelease_upload, str)
    assert "git push" not in prerelease_upload
    assert "refs/heads/$RELEASE_TARGET:refs/remotes/origin/$RELEASE_TARGET" in prerelease_upload
    assert "refs/tags/$RELEASE_TAG:refs/tags/$RELEASE_TAG" in prerelease_upload
    assert (
        'git merge-base --is-ancestor "$SOURCE_SHA" "refs/remotes/origin/$RELEASE_TARGET"'
        in prerelease_upload
    )
    assert '"refs/tags/$RELEASE_TAG")" == "$TAG_OID"' in prerelease_upload
    assert '"refs/tags/$RELEASE_TAG^{}")" == "$SOURCE_SHA"' in prerelease_upload
    assert 'cmp "$RELEASE_ARCHIVE" "$RUNNER_TEMP/rebuilt-resmed_myair.zip"' in prerelease_upload
    assert '--mtime="@$(git log -1 --format=%ct HEAD)"' in prerelease_upload


def test_resume_requires_exact_deterministic_release_delta_and_successful_cleanup() -> None:
    """Require resume evidence and preserve failed validation refs for recovery."""
    document = _workflow()
    prepare_steps = _steps(document, "prepare")
    release_steps = _steps(document, "release")
    base = prepare_steps["Validate event source and immutable starting refs"]["run"]
    assert isinstance(base, str)
    assert 'git diff --name-only "$source_sha^" "$source_sha"' in base
    assert '--manifest-path "$resume_dir/manifest.json"' in base
    assert 'cmp "$resume_dir/manifest.json" custom_components/resmed_myair/manifest.json' in base
    cleanup = release_steps["Delete validated temporary branch"]
    assert cleanup["if"] == "github.event.release.prerelease == false && success()"
    cleanup_run = cleanup["run"]
    assert isinstance(cleanup_run, str)
    assert cleanup_run.rstrip().endswith('git push origin --delete "$TEMP_REF"')


def test_release_artifact_is_rebuilt_from_proven_candidate_tree() -> None:
    """Prevent a prepared archive from substituting for the candidate tree."""
    document = _workflow()
    archive_mtime = '--mtime="@$(git log -1 --format=%ct HEAD)"'
    build = _steps(document, "prepare")["Build and verify release archive"]["run"]
    assert isinstance(build, str)
    assert archive_mtime in build
    proof = _steps(document, "release")["Re-prove candidate source and archive identity"]["run"]
    assert isinstance(proof, str)
    assert "git bundle verify" in proof
    assert "git bundle unbundle" in proof
    assert 'git diff --name-only "$SOURCE_SHA" "$CANDIDATE_SHA"' in proof
    assert "verify_hacs_archive.py" in proof
    assert archive_mtime in proof
    assert 'cmp "$RELEASE_ARCHIVE" "$RUNNER_TEMP/rebuilt-resmed_myair.zip"' in proof
    handoff = _steps(document, "release")["Require a bounded regular-file candidate handoff"]["run"]
    assert isinstance(handoff, str)
    assert "candidate.bundle" in handoff and "resmed_myair.zip" in handoff
    assert '-f "$path" && ! -L "$path"' in handoff
    assert "-le 104857600" in handoff


@pytest.mark.parametrize(
    ("tag", "expected_prerelease"),
    [("v1.2.3", "false"), ("v1.2.3-beta.1", "true")],
)
def test_version_helper_accepts_matching_prerelease_state(
    version_script: ModuleType, tag: str, expected_prerelease: str
) -> None:
    """Accept the release event's matching prerelease classification.

    Args:
        version_script (ModuleType): Imported version helper.
        tag (str): Release tag to validate.
        expected_prerelease (str): Expected event prerelease value.
    """
    assert (
        version_script.main(
            ["--tag-name", tag, "--check-only", "--expected-prerelease", expected_prerelease]
        )
        == 0
    )


def test_version_helper_rejects_prerelease_option_during_mutation(
    version_script: ModuleType,
) -> None:
    """Keep the event-only prerelease check from changing release files.

    Args:
        version_script (ModuleType): Imported version helper.
    """
    with pytest.raises(ValueError, match="requires --check-only"):
        version_script.main(["--tag-name", "v1.2.3", "--expected-prerelease", "false"])
