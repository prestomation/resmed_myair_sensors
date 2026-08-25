"""Redaction tests that protect nested secret-stripping behavior."""

from types import MappingProxyType

import pytest

from custom_components.resmed_myair.redaction import REDACTED, redact_dict


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (
            {
                "Username": "person@example.com",
                "nested": [{"access_token": "token-value"}, {"safe": "value"}],
                "safe": "visible",
            },
            {
                "Username": REDACTED,
                "nested": [{"access_token": REDACTED}, {"safe": "value"}],
                "safe": "visible",
            },
        ),
        ({"given_name": "Alice"}, {"given_name": REDACTED}),
        (
            {"nested": MappingProxyType({"access_token": "token-value"})},
            {"nested": {"access_token": REDACTED}},
        ),
    ],
)
def test_redact_dict_redacts_sensitive_values(data: object, expected: object) -> None:
    """Redact sensitive keys across nested, claim, and immutable mappings.

    Args:
        data (object): Mapping or nested value containing sensitive fields.
        expected (object): Redacted structure expected from the helper.
    """
    assert redact_dict(data) == expected


@pytest.mark.parametrize("value", ["plain", None])
def test_redact_dict_returns_non_collection_values_unchanged(value: object) -> None:
    """Leave scalar values unchanged when they pass through the redactor.

    Args:
        value (object): Non-collection value supplied to the redaction helper.
    """
    assert redact_dict(value) is value
