"""Parametrized tests for both client and integration helpers."""

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

MODULE_IDS = [p.replace("custom_components.resmed_myair.", "") for p in MODULE_PATHS]


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


@pytest.mark.parametrize("module_path", MODULE_PATHS, ids=MODULE_IDS)
def test_redact_dict_equivalence(monkeypatch: pytest.MonkeyPatch, module_path: str) -> None:
    """Run the common redact_dict test vectors against both implementations.

    The test monkeypatches the shared redaction module KEYS_TO_REDACT and
    swaps the '<REDACTED>' sentinel in the expected outputs with the module's
    REDACTED constant.
    """
    module = importlib.import_module(module_path)
    monkeypatch.setattr(
        redaction,
        "KEYS_TO_REDACT",
        {"test_username", "test_password", "test_token"},
    )

    redact = module.redact_dict
    redacted_const = module.REDACTED

    for inp, exp in COMMON_CASES:
        expected = _replace_placeholder(exp, "<REDACTED>", redacted_const)
        assert redact(inp) == expected


@pytest.mark.parametrize("module_path", MODULE_PATHS, ids=MODULE_IDS)
def test_redact_dict_empty_and_trivial(monkeypatch: pytest.MonkeyPatch, module_path: str) -> None:
    """Ensure redact_dict handles empty/trivial inputs for both implementations."""
    module = importlib.import_module(module_path)
    monkeypatch.setattr(
        redaction,
        "KEYS_TO_REDACT",
        {"test_username", "test_password", "test_token"},
    )
    redact = module.redact_dict

    for inp, exp in EMPTY_TRIVIAL:
        assert redact(inp) == exp


@pytest.mark.parametrize("module_path", MODULE_PATHS, ids=MODULE_IDS)
def test_helpers_reexport_shared_redactor_and_constants(module_path: str) -> None:
    """Both helper import paths expose the shared redactor and redaction constant."""
    module = importlib.import_module(module_path)

    assert module.redact_dict is redaction.redact_dict
    assert module.REDACTED == redaction.REDACTED
