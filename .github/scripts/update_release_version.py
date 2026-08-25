"""Update release version metadata files."""

from __future__ import annotations

import argparse
from collections.abc import Iterable, Sequence
import json
from pathlib import Path
import re
import sys

DEFAULT_MANIFEST_PATH = Path("custom_components/resmed_myair/manifest.json")
DEFAULT_CONST_PATH = Path("custom_components/resmed_myair/const.py")
VERSION_PATTERN = re.compile(r'^VERSION = ".*"$', flags=re.MULTILINE)
TAG_PATTERN = re.compile(
    r"^v[0-9]+(?:\.[0-9]+){1,3}(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?(?:[A-Za-z]+[0-9]+)?$"
)
STABLE_TAG_PATTERN = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def validate_release_tag(tag_name: str) -> None:
    """Validate a release tag against the repository's supported formats.

    Args:
        tag_name: Candidate release tag.

    Raises:
        ValueError: If the tag does not use a supported version format.

    """
    if TAG_PATTERN.fullmatch(tag_name) is None:
        raise ValueError(f"Invalid release tag: {tag_name}")


def next_stable_release_tag(tags: Iterable[str], bump_type: str) -> str:
    """Return the next stable tag after the highest released stable version.

    Args:
        tags: Candidate tag names from the release repository.
        bump_type: Requested stable version increment.

    Returns:
        The next stable release tag.

    Raises:
        ValueError: If the bump type is unsupported or no stable tag is found.

    """
    if bump_type not in {"patch", "minor", "major"}:
        raise ValueError(f"Unsupported bump type: {bump_type}")

    versions = [
        tuple(int(component) for component in match.groups())
        for tag in tags
        if (match := STABLE_TAG_PATTERN.fullmatch(tag)) is not None
    ]
    if not versions:
        raise ValueError("No stable released tag found.")

    major, minor, patch = max(versions)
    if bump_type == "patch":
        patch += 1
    elif bump_type == "minor":
        minor += 1
        patch = 0
    else:
        major += 1
        minor = 0
        patch = 0
    return f"v{major}.{minor}.{patch}"


def update_release_version_files(
    *,
    tag_name: str,
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
    const_path: Path = DEFAULT_CONST_PATH,
) -> None:
    """Update release version metadata files.

    Args:
        tag_name: Release tag name to write as the integration version.
        manifest_path: Path to the Home Assistant integration manifest file.
        const_path: Path to the integration constants file.

    Raises:
        ValueError: Raised when the tag is invalid or ``const_path`` lacks a
            VERSION assignment.

    """
    validate_release_tag(tag_name)
    _update_manifest_version(manifest_path=manifest_path, tag_name=tag_name)
    _update_const_version(const_path=const_path, tag_name=tag_name)


def _update_manifest_version(*, manifest_path: Path, tag_name: str) -> None:
    """Update the version field in the integration manifest.

    Args:
        manifest_path: Path to the Home Assistant integration manifest file.
        tag_name: Release tag name to write as the integration version.

    """
    manifest = json.loads(manifest_path.read_text())
    manifest["version"] = tag_name
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")


def _update_const_version(*, const_path: Path, tag_name: str) -> None:
    """Update the VERSION assignment in the integration constants file.

    Args:
        const_path: Path to the integration constants file.
        tag_name: Release tag name to write as the integration version.

    Raises:
        ValueError: Raised when ``const_path`` lacks a VERSION assignment.

    """
    const_text = const_path.read_text()
    version_line = f"VERSION = {json.dumps(tag_name)}"
    updated_text, replacements = VERSION_PATTERN.subn(version_line, const_text, count=1)
    if replacements != 1:
        raise ValueError(f"{const_path} does not contain a VERSION assignment")
    const_path.write_text(updated_text)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        argv: Command-line arguments excluding the program name.

    Returns:
        Parsed command-line arguments.

    """
    parser = argparse.ArgumentParser(description=__doc__)
    version_group = parser.add_mutually_exclusive_group(required=True)
    version_group.add_argument("--tag-name", help="Release tag name to validate or write.")
    version_group.add_argument(
        "--next-tag",
        choices=("patch", "minor", "major"),
        help="Print the next stable release tag using tags read from standard input.",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Validate --tag-name without updating version files.",
    )
    parser.add_argument(
        "--manifest-path",
        type=Path,
        default=DEFAULT_MANIFEST_PATH,
        help="Path to the integration manifest file.",
    )
    parser.add_argument(
        "--const-path",
        type=Path,
        default=DEFAULT_CONST_PATH,
        help="Path to the integration const.py file.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the release version update script.

    Args:
        argv: Optional command-line arguments excluding the program name.

    Returns:
        Process exit code.

    """
    args = _parse_args(argv)
    if args.next_tag is not None:
        if args.check_only:
            raise ValueError("--check-only cannot be used with --next-tag")
        sys.stdout.write(
            f"{next_stable_release_tag(sys.stdin.read().splitlines(), args.next_tag)}\n"
        )
    elif args.check_only:
        validate_release_tag(args.tag_name)
    else:
        update_release_version_files(
            tag_name=args.tag_name,
            manifest_path=args.manifest_path,
            const_path=args.const_path,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
