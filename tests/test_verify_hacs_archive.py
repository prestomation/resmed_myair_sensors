"""Tests for HACS release archive validation."""

import importlib.util
import json
from pathlib import Path
import stat
import zipfile

import pytest

SCRIPT_PATH = Path(__file__).parents[1] / ".github/scripts/verify_hacs_archive.py"
SPEC = importlib.util.spec_from_file_location("verify_hacs_archive", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
archive_verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(archive_verifier)


def _archive(path: Path, extra: list[tuple[str, bytes]] | None = None) -> None:
    """Build a small valid archive, with optional extra members.

    Args:
        path (Path): Destination ZIP path.
        extra (list[tuple[str, bytes]] | None): Optional appended members.
    """
    members = [
        ("manifest.json", json.dumps({"version": "v1.2.3"}).encode()),
        ("const.py", b'VERSION = "v1.2.3"\n'),
    ]
    with zipfile.ZipFile(path, "w") as output:
        for name, contents in members + (extra or []):
            output.writestr(name, contents)


def test_verify_archive_accepts_a_real_zip_artifact(tmp_path: Path) -> None:
    """Accept a normal integration archive produced for the release tag.

    Args:
        tmp_path (Path): Temporary test directory.
    """
    archive = tmp_path / "resmed_myair.zip"
    _archive(archive)
    archive_verifier.verify_archive(str(archive), "v1.2.3")


def test_verify_archive_allows_safe_directory_entries(tmp_path: Path) -> None:
    """Allow directories emitted by git archive while validating their contents.

    Args:
        tmp_path (Path): Temporary test directory.
    """
    archive = tmp_path / "directory.zip"
    _archive(archive)
    with zipfile.ZipFile(archive, "a") as output:
        output.writestr("client/", b"")
        output.writestr("client/module.py", b"VALUE = 1\n")
    archive_verifier.verify_archive(str(archive), "v1.2.3")


@pytest.mark.parametrize(
    ("member", "message"),
    [
        ("../manifest.json", "Invalid archive member"),
        ("nested/../../const.py", "Invalid archive member"),
    ],
)
def test_verify_archive_rejects_unsafe_member_paths(
    tmp_path: Path, member: str, message: str
) -> None:
    """Reject traversal members even when required files are also present.

    Args:
        tmp_path (Path): Temporary test directory.
        member (str): Unsafe archive member path.
        message (str): Expected validation message.
    """
    archive = tmp_path / "unsafe.zip"
    _archive(archive, [(member, b"unsafe")])
    with pytest.raises(archive_verifier.ArchiveError, match=message):
        archive_verifier.verify_archive(str(archive), "v1.2.3")


def test_verify_archive_rejects_duplicate_and_symlink_members(tmp_path: Path) -> None:
    """Reject duplicate names and symlinks before an archive is uploaded.

    Args:
        tmp_path (Path): Temporary test directory.
    """
    duplicate = tmp_path / "duplicate.zip"
    _archive(duplicate, [("const.py", b'VERSION = "v1.2.3"\n')])
    with pytest.raises(archive_verifier.ArchiveError, match="Duplicate"):
        archive_verifier.verify_archive(str(duplicate), "v1.2.3")
    symlink = tmp_path / "symlink.zip"
    _archive(symlink)
    with zipfile.ZipFile(symlink, "a") as output:
        info = zipfile.ZipInfo("linked.py")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        output.writestr(info, b"const.py")
    with pytest.raises(archive_verifier.ArchiveError, match="not a regular file"):
        archive_verifier.verify_archive(str(symlink), "v1.2.3")


def test_verify_archive_rejects_version_mismatch_and_oversized_member(tmp_path: Path) -> None:
    """Reject metadata mismatches and members beyond the expanded-size bound.

    Args:
        tmp_path (Path): Temporary test directory.
    """
    version_mismatch = tmp_path / "version.zip"
    _archive(version_mismatch)
    with pytest.raises(archive_verifier.ArchiveError, match="manifest version"):
        archive_verifier.verify_archive(str(version_mismatch), "v1.2.4")
    oversized = tmp_path / "oversized.zip"
    _archive(oversized, [("payload.bin", b"x" * (archive_verifier.MAX_FILE_BYTES + 1))])
    with pytest.raises(archive_verifier.ArchiveError, match="size limit"):
        archive_verifier.verify_archive(str(oversized), "v1.2.3")


def test_verify_archive_rejects_missing_files_expansion_and_compression_ratio(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reject missing metadata, total expansion, and compressed ZIP bombs.

    Args:
        tmp_path (Path): Temporary test directory.
        monkeypatch (pytest.MonkeyPatch): Fixture reducing test-only archive bounds.
    """
    missing = tmp_path / "missing.zip"
    with zipfile.ZipFile(missing, "w") as output:
        output.writestr("manifest.json", json.dumps({"version": "v1.2.3"}))
    with pytest.raises(archive_verifier.ArchiveError, match="required version files"):
        archive_verifier.verify_archive(str(missing), "v1.2.3")
    expanded = tmp_path / "expanded.zip"
    _archive(expanded, [("payload.bin", b"x" * 32)])
    monkeypatch.setattr(archive_verifier, "MAX_EXPANDED_BYTES", 32)
    with pytest.raises(archive_verifier.ArchiveError, match="expanded size"):
        archive_verifier.verify_archive(str(expanded), "v1.2.3")
    monkeypatch.setattr(archive_verifier, "MAX_EXPANDED_BYTES", 64 * 1024 * 1024)
    monkeypatch.setattr(archive_verifier, "MAX_COMPRESSION_RATIO", 2)
    compressed = tmp_path / "compressed.zip"
    with zipfile.ZipFile(compressed, "w", compression=zipfile.ZIP_DEFLATED) as output:
        output.writestr("manifest.json", json.dumps({"version": "v1.2.3"}))
        output.writestr("const.py", 'VERSION = "v1.2.3"\n')
        output.writestr("payload.bin", b"x" * 1_024)
    with pytest.raises(archive_verifier.ArchiveError, match="compression ratio"):
        archive_verifier.verify_archive(str(compressed), "v1.2.3")
