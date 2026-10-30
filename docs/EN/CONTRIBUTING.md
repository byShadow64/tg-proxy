# CONTRIBUTING

Thank you for helping TG Proxy (`byShadow64/tg-proxy`).

## Before Creating an Issue

1. Check the documentation in `docs/README.md`.
2. Make sure a similar issue hasn't already been opened.
3. Use the issue forms in this repository; no custom labels are required to file a report.

## How to Report Problems

- Use the `Problem report` template.
- If possible, provide:
  - Application version,
  - Operating system,
  - Steps to reproduce,
  - Expected and actual behavior,
  - A sanitized log excerpt or error text without credentials or personal data.

The more precise your description, the faster we can help.

## Local Development from Source

Python `>=3.11` is required. Security-maintained dependency versions are used for new builds; Windows 7 / Python 3.8 builds are not supported.

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[build,helper-server]" pytest
```

Running:

- console mode: `tg-ws-proxy`
- Windows tray: `tg-ws-proxy-tray-win`
- macOS tray: `tg-ws-proxy-tray-macos`
- Linux tray: `tg-ws-proxy-tray-linux`

On Windows use `.venv/Scripts/python.exe`. Details: [Build from source](BuildFromSource.md).

## Checks

Install the project dependencies and test runner, then run the Python suite:

```bash
python -m pytest -q
```

Linting (`ruff` is configured in `pyproject.toml`):

```bash
ruff check .
```

## Pull Request

Before opening a PR:

1. Make sure your change solves a specific problem.
2. Check that existing scenarios aren't broken; run the tests and the linter.
3. Update documentation if behavior or configuration changes.

Smaller and focused PRs are reviewed and accepted faster.
