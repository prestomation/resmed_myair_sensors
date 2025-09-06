"""Unit tests for helper functions in the integration (redaction)."""

import pytest

from custom_components.resmed_myair.helpers import REDACTED, redact_dict


@pytest.mark.parametrize(
    "input_data,expected",
    [
        # No redaction needed
        ({"foo": "bar"}, {"foo": "bar"}),
        # Redact a single key
        ({"username": "bob"}, {"username": REDACTED}),
        # Redact nested dict
        ({"outer": {"password": "abc"}}, {"outer": {"password": REDACTED}}),
        # Redact in list of dicts
        ([{"token": "abc"}, {"foo": "bar"}], [{"token": REDACTED}, {"foo": "bar"}]),
        # Redact in nested list
        ({"list": [{"username": "bob"}]}, {"list": [{"username": REDACTED}]}),
        # Ignore None and empty string
        ({"username": None, "password": ""}, {"username": None, "password": ""}),
        # Redact deeply nested
        (
            {"a": {"b": {"password": "abc"}}},
            {"a": {"b": {"password": REDACTED}}},
        ),
        # Non-dict/list input
        ("notadict", "notadict"),
        (None, None),
    ],
)
def test_redact_dict(monkeypatch, input_data, expected):
    """Test redact_dict redacts sensitive keys as expected."""
    monkeypatch.setattr(
        "custom_components.resmed_myair.helpers.KEYS_TO_REDACT",
        {"username", "password", "token"},
    )
    assert redact_dict(input_data) == expected


@pytest.mark.parametrize(
    "input_data,expected",
    [
        ({}, {}),
        ([], []),
        ([{}], [{}]),
        ({"a": {}, "b": []}, {"a": {}, "b": []}),
    ],
)
def test_redact_dict_empty_and_trivial(monkeypatch, input_data, expected):
    """Ensure redact_dict handles empty and trivial cases without changes."""
    monkeypatch.setattr(
        "custom_components.resmed_myair.helpers.KEYS_TO_REDACT",
        {"username", "password", "token"},
    )
    assert redact_dict(input_data) == expected
