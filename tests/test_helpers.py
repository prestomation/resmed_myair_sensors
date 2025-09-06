"""Parametrized tests for both client and integration helpers."""

import importlib
from typing import Any

import pytest

COMMON_CASES = [
    # No redaction needed
    ({"foo": "bar"}, {"foo": "bar"}),
    # Redact a single key
    ({"username": "bob"}, {"username": "<REDACTED>"}),
    # Redact nested dict
    ({"outer": {"password": "abc"}}, {"outer": {"password": "<REDACTED>"}}),
    # Redact in list of dicts
    ([{"token": "abc"}, {"foo": "bar"}], [{"token": "<REDACTED>"}, {"foo": "bar"}]),
    # Redact in nested list
    ({"list": [{"username": "bob"}]}, {"list": [{"username": "<REDACTED>"}]}),
    # Ignore None and empty string
    ({"username": None, "password": ""}, {"username": None, "password": ""}),
    # Redact deeply nested
    (
        {"a": {"b": {"password": "abc"}}},
        {"a": {"b": {"password": "<REDACTED>"}}},
    ),
    # Non-dict/list input
    ("notadict", "notadict"),
    (None, None),
]

EMPTY_TRIVIAL = [
    ({}, {}),
    ([], []),
    ([{}], [{}]),
    ({"a": {}, "b": []}, {"a": {}, "b": []}),
]

MODULE_PATHS = [
    "custom_components.resmed_myair.client.helpers",
    "custom_components.resmed_myair.helpers",
]


def _replace_placeholder(obj: Any, placeholder: str, replacement: Any) -> Any:
    """Recursively replace placeholder strings in expected structures.

    This allows writing expected values with a sentinel and then substituting
    the actual module REDACTED constant at test time.
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


@pytest.mark.parametrize("module_path", MODULE_PATHS)
def test_redact_dict_equivalence(monkeypatch, module_path):
    """Run the common redact_dict test vectors against both implementations.

    The test monkeypatches KEYS_TO_REDACT for the module under test and swaps
    the '<REDACTED>' sentinel in the expected outputs with the module's
    REDACTED constant.
    """
    module = importlib.import_module(module_path)
    # Ensure both modules redact the same keys for testing
    monkeypatch.setattr(module, "KEYS_TO_REDACT", {"username", "password", "token"}, raising=False)

    redact = getattr(module, "redact_dict")
    redacted_const = getattr(module, "REDACTED")

    for inp, exp in COMMON_CASES:
        expected = _replace_placeholder(exp, "<REDACTED>", redacted_const)
        assert redact(inp) == expected


@pytest.mark.parametrize("module_path", MODULE_PATHS)
def test_redact_dict_empty_and_trivial(monkeypatch, module_path):
    """Ensure redact_dict handles empty/trivial inputs for both implementations."""
    module = importlib.import_module(module_path)
    monkeypatch.setattr(module, "KEYS_TO_REDACT", {"username", "password", "token"}, raising=False)
    redact = getattr(module, "redact_dict")

    for inp, exp in EMPTY_TRIVIAL:
        assert redact(inp) == exp
