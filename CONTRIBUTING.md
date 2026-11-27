# Contribution guidelines

Contributing to this project should be as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features

## GitHub is used for everything

GitHub is used to host code, to track issues and feature requests, as well as accept pull requests.

Pull requests are the best way to propose changes to the codebase.

1. Fork the repo and create your branch from `main`
2. If you've changed something, update the documentation
3. Make sure your code lints (using ruff)
4. Test your contribution
5. Issue that pull request!

## Any contributions you make will be under the MIT Software License

In short, when you submit code changes, your submissions are understood to be under the same [MIT License](http://choosealicense.com/licenses/mit/) that covers the project. Feel free to contact the maintainers if that's a concern.

## Report bugs using GitHub's [issues](../../issues)

GitHub issues are used to track public bugs.
Report a bug by [opening a new issue](../../issues/new/choose); it's that easy!

## Write bug reports with detail, background, and sample code

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

People *love* thorough bug reports. I'm not even kidding.

## Use a Consistent Coding Style

Follow the [coding standards](CODING_STANDARDS.md) for project conventions and local checks.

## Local setup

Install [uv](https://docs.astral.sh/uv/), then run `scripts/setup` to create the
Python 3.14 virtualenv, sync development dependencies and editable-install settings
from `pyproject.toml`, and install the Git hooks. Run `scripts/test` to run the tests.

## Minimum Home Assistant tests

CI also runs the tests against the minimum supported Home Assistant release declared in
`hacs.json` (see the matrix in `.github/workflows/pytest_check.yml`). The job resolves the
oldest Home Assistant release at or above that minimum together with a test plugin that
covers it: `pytest-homeassistant` from Home Assistant 2026.11, otherwise its predecessor
`pytest-homeassistant-custom-component`. It installs them with the `pytest-base` group
in a separate environment. Raising the minimum in `hacs.json` is all the job needs.

Import Home Assistant test plugin helpers such as `MockConfigEntry` from `tests.common`
so the tests work with either plugin. To reproduce the job locally, run the workflow's
minimum steps from a separate clone or worktree with `RUNNER_TEMP` set to a scratch
directory. The steps create their own `.venv` in the current directory, so they fail in a
checkout that already has one.

## License

By contributing, you agree that your contributions will be licensed under its MIT License.
