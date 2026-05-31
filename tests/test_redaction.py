"""Tests for shared ResMed myAir redaction helpers."""

from types import MappingProxyType

from custom_components.resmed_myair.redaction import REDACTED, redact_dict


def test_redact_dict_redacts_nested_sensitive_values() -> None:
    """Sensitive keys are redacted inside mappings and lists."""
    data = {
        "Username": "person@example.com",
        "nested": [{"access_token": "token-value"}, {"safe": "value"}],
        "safe": "visible",
    }

    assert redact_dict(data) == {
        "Username": REDACTED,
        "nested": [{"access_token": REDACTED}, {"safe": "value"}],
        "safe": "visible",
    }


def test_redact_dict_redacts_given_name() -> None:
    """The myAir given_name claim is redacted."""
    assert redact_dict({"given_name": "Alice"}) == {"given_name": REDACTED}


def test_redact_dict_redacts_nested_immutable_mappings() -> None:
    """Immutable nested mappings should be copied and redacted."""
    data = {"nested": MappingProxyType({"access_token": "token-value"})}

    assert redact_dict(data) == {"nested": {"access_token": REDACTED}}


def test_redact_dict_returns_non_collection_values_unchanged() -> None:
    """Scalar values are returned unchanged."""
    assert redact_dict("plain") == "plain"
    assert redact_dict(None) is None
