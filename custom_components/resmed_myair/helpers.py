from collections.abc import Mapping
from typing import Any

from .const import KEYS_TO_REDACT

REDACTED = "**REDACTED**"


def redact_dict(data):
    """Redact sensitive data in a dict."""
    if not isinstance(data, (Mapping, list)):
        return data

    if isinstance(data, list):
        return [redact_dict(val) for val in data]

    redacted: Mapping[str, Any] = {**data}

    for key, value in redacted.items():
        if value is None:
            continue
        if isinstance(value, str) and not value:
            continue
        if key in KEYS_TO_REDACT:
            redacted[key] = REDACTED
        elif isinstance(value, Mapping):
            redacted[key] = redact_dict(value)
        elif isinstance(value, list):
            redacted[key] = [redact_dict(item) for item in value]

    return redacted
