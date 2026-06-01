"""Tests for the curated GraphQL schema reference."""

import json
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "scripts" / "graphql_schema.json"


def test_graphql_schema_declares_manual_reference_status() -> None:
    """Schema notes are clearly marked as manual, non-authoritative reference data."""
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    assert schema["maintenance"] == {
        "generated": False,
        "authoritative": False,
        "update_process": (
            "Update manually when live smoke-test output, validation probes, or integration "
            "query changes confirm a field shape."
        ),
    }
    assert schema["introspection"]["available"] is False
