"""Shared redaction helpers for ResMed myAir logs."""

from collections.abc import Mapping
from typing import Any

from .const import KEYS_TO_REDACT

REDACTED = "**REDACTED**"


def redact_dict(data: Any | None) -> Any | None:
    """Redact sensitive values from nested dictionaries and lists.

    Args:
        data: Value to redact.

    Returns:
        A redacted copy of mappings/lists, or the original scalar value.
    """
    if not isinstance(data, Mapping | list):
        return data

    if isinstance(data, list):
        return [redact_dict(value) for value in data]

    redacted: dict[str, Any] = {**data}
    for key, value in redacted.items():
        if value is None or (isinstance(value, str) and not value):
            continue
        if key in KEYS_TO_REDACT:
            redacted[key] = REDACTED
        else:
            redacted[key] = redact_dict(value)
    return redacted
