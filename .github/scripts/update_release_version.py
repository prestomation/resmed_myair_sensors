"""Update release version metadata files."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
from pathlib import Path
import re

DEFAULT_MANIFEST_PATH = Path("custom_components/resmed_myair/manifest.json")
DEFAULT_CONST_PATH = Path("custom_components/resmed_myair/const.py")
VERSION_PATTERN = re.compile(r'^VERSION = ".*"$', flags=re.MULTILINE)


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
        ValueError: Raised when ``const_path`` lacks a VERSION assignment.

    """
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
    parser.add_argument("--tag-name", required=True, help="Release tag name to write.")
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
    update_release_version_files(
        tag_name=args.tag_name,
        manifest_path=args.manifest_path,
        const_path=args.const_path,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
