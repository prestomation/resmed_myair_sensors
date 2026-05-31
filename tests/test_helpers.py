"""Shared redaction tests that exercise both helper import paths."""

import importlib
from typing import Any

import pytest

from custom_components.resmed_myair import redaction

COMMON_CASES = [
    # No redaction needed
    ({"foo": "bar"}, {"foo": "bar"}),
    # Redact a single key
    ({"test_username": "bob"}, {"test_username": "<REDACTED>"}),
    # Redact nested dict
    ({"outer": {"test_password": "abc"}}, {"outer": {"test_password": "<REDACTED>"}}),
    # Redact in list of dicts
    (
        [{"test_token": "abc"}, {"foo": "bar"}],
        [{"test_token": "<REDACTED>"}, {"foo": "bar"}],
    ),
    # Redact in nested list
    (
        {"list": [{"test_username": "bob"}]},
        {"list": [{"test_username": "<REDACTED>"}]},
    ),
    # Ignore None and empty string
    ({"test_username": None, "test_password": ""}, {"test_username": None, "test_password": ""}),
    # Redact deeply nested
    (
        {"a": {"b": {"test_password": "abc"}}},
        {"a": {"b": {"test_password": "<REDACTED>"}}},
    ),
    # Non-dict/list input
    ("notadict", "notadict"),
    (None, None),
    ({}, {}),
    ([], []),
    ([{}], [{}]),
    ({"a": {}, "b": []}, {"a": {}, "b": []}),
]

MODULE_PATHS = [
    "custom_components.resmed_myair.client.helpers",
    "custom_components.resmed_myair.helpers",
]

MODULE_IDS = [p.replace("custom_components.resmed_myair.", "") for p in MODULE_PATHS]


def _replace_placeholder(obj: Any, placeholder: str, replacement: Any) -> Any:
    """Recursively replace placeholder values in nested expected structures.

    Args:
        obj: Nested object graph to traverse.
        placeholder: Sentinel string to replace.
        replacement: Value to substitute for the sentinel.

    Returns:
        A structure with matching placeholder strings replaced in place.
    """
    if isinstance(obj, str):
        return replacement if obj == placeholder else obj
    if isinstance(obj, dict):
        return {k: _replace_placeholder(v, placeholder, replacement) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_replace_placeholder(v, placeholder, replacement) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_replace_placeholder(v, placeholder, replacement) for v in obj)
    return obj


@pytest.mark.parametrize("module_path", MODULE_PATHS, ids=MODULE_IDS)
@pytest.mark.parametrize(("inp", "exp"), COMMON_CASES)
def test_redact_dict_equivalence(
    monkeypatch: pytest.MonkeyPatch, module_path: str, inp: Any, exp: Any
) -> None:
    """Both helper modules redact the same nested values and sentinels."""
    module = importlib.import_module(module_path)
    monkeypatch.setattr(
        redaction,
        "KEYS_TO_REDACT",
        {"test_username", "test_password", "test_token"},
    )

    redact = module.redact_dict
    redacted_const = module.REDACTED

    expected = _replace_placeholder(exp, "<REDACTED>", redacted_const)
    assert redact(inp) == expected


@pytest.mark.parametrize("module_path", MODULE_PATHS, ids=MODULE_IDS)
def test_helpers_reexport_shared_redactor_and_constants(module_path: str) -> None:
    """Both helper import paths re-export the shared redactor constant."""
    module = importlib.import_module(module_path)

    assert module.redact_dict is redaction.redact_dict
    assert module.REDACTED == redaction.REDACTED
