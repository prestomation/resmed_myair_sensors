# Coding standards

Use these standards when changing or reviewing the ResMed myAir integration. The
[Home Assistant developer docs](https://developers.home-assistant.io/docs/) cover
platform conventions, and the [glossary](GLOSSARY.md) defines project terms.

## Scope and module boundaries

- Fix the root cause in the smallest cohesive change. Reuse existing behavior
  where it fits and preserve the contracts that callers and installed entries
  rely on. Update user-facing documentation when behavior changes.
- Keep myAir requests and authentication in `client/`, payload normalization and
  sleep-record selection in `models.py`, refresh and recovery in `coordinator.py`,
  and configuration flows in `config_flow.py`. Keep sensor behavior in `sensor.py`,
  Recorder behavior in `recorder.py`, and shared integration constants in `const.py`.

## Python, errors, and logging

- Target Python 3.14 and current Home Assistant. Type function and method
  parameters and return values, and annotate class attributes. Write module and
  class docstrings and use Google-style docstrings for functions and methods,
  including private and nested ones. Keep imports at the top of the module and
  preserve useful comments, updating them when behavior changes.
- Validate myAir data at the client or model boundary. Treat a missing or invalid
  measurement separately from a real zero. Use the glossary’s date distinctions
  when selecting records or exposing dates and timestamps.
- Catch specific exceptions and keep distinct recovery paths for sign-in failures,
  temporary service failures, and unavailable data. A coordinator change should
  preserve usable device or sleep data when only the other response is missing.
- Use Home Assistant’s logging conventions. Add debug or info messages that explain
  recovery decisions. Use the shared redaction helper before logging myAir payloads
  or entry data, and keep credentials and authentication tokens out of log messages.

## Home Assistant compatibility

- Preserve device and entity identity across setup, reauthentication, and
  reconfiguration. Check both the normal sign-in and MFA paths when changing how
  those flows verify the CPAP device serial number.
- Treat changes to stored entry fields, entity unique IDs, or sensor units as
  compatibility changes. Check existing entries, registry entities, and Recorder
  history as applicable. Provide a migration when existing data needs conversion.

## Tests and checks

- Add or update tests for changed behavior, including relevant no-op and failure
  cases. Assert observable outcomes such as a config flow result, sensor state,
  or migrated entry. Use typed, documented pytest tests and Home Assistant helpers
  such as `MockConfigEntry`, share fixtures in `tests/conftest.py`, and parameterize
  cases that exercise the same behavior.
- Organize module tests by integration source file and use the existing integration
  or workflow suites for scenarios spanning modules. Aim for at least 80% coverage.
- Run `./.venv/bin/prek run --all-files` and `./.venv/bin/pytest` from the repo root.
  Run the full pytest suite by default and explain a narrower selection when used.
  See [local setup](CONTRIBUTING.md#local-setup) and the tool configuration in
  [pyproject.toml](pyproject.toml) and [prek.toml](prek.toml).
