# AGENTS

## Purpose

- Provide clear, repo-specific instructions for autonomous agents working in this repository.

## General Guidelines

- Follow Home Assistant developer docs: https://developers.home-assistant.io/docs/.
- Be concise and explain coding steps briefly when making code changes; include code snippets and tests where relevant.
- For non-trivial edits, provide a short plan. For small, low-risk edits, implement and include a one-line summary.
- Focus on a single conceptual change at a time when public APIs or multiple modules are affected.
- Maintain project style and Python 3.14+ compatibility. Target latest Home Assistant core.
- If deviating from these guidelines, explicitly state which guideline is deviated from and why.

## Agent permissions and venv policy

- Agents may create and use a repository-local venv at `./.venv` and should reference `./.venv/bin/python` when running commands.
- Installing packages from repo manifests (e.g., `requirements-dev.txt`, `pyproject.toml`) into `./.venv` is allowed for running tests or local tooling.

## Coding standards

Read [coding standards](CODING_STANDARDS.md) when changing or reviewing code. It covers module boundaries, Python style, error handling, compatibility, and tests.

## Local tooling note

- If tests fail due to missing dev dependencies, either install them into `./.venv` (if allowed) or report exact `pip install` commands.

## PR & branch behavior

- Create branches or PRs only when explicitly requested. Do not open PRs autonomously.
- Use a Conventional Commit prefix for every created PR title (for example, `feat:`, `fix:`, or `chore:`).

## Network access

- Run read-only lookups that inform the task without asking: GitHub, Home Assistant docs and core source, and PyPI.
- Ask first for package installs beyond the repo manifests and for any write to an external service that this file does not already authorize.

## CI/CD

- Use GitHub Actions for CI/CD where applicable.

## Agent skills

### Issue tracker

Specs, tickets, and wayfinding maps use local Markdown under `.scratch/`. See [issue tracker](docs/agents/issue-tracker.md) when reading or publishing them.

### Triage labels

Use the five default triage labels. See [triage labels](docs/agents/triage-labels.md) when setting an issue's status.

### Domain docs

This repository uses a single glossary and ADR directory. See [domain docs](docs/agents/domain.md) before exploring the domain or proposing changes.
