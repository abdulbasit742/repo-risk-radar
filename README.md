# Repo Risk Radar

Local-first repository risk scanner for secrets, CI permissions, and dangerous automation patterns.

Repo Risk Radar gives maintainers a fast, offline-first way to spot repository hygiene issues before they turn into incidents. The initial release focuses on high-signal checks that are safe to run in developer laptops and CI without sending code or metadata to external services.

## Why this exists

Teams regularly miss small but expensive problems:

- a `.env` file slips into a branch
- a workflow quietly inherits broad permissions
- a third-party action is referenced by a mutable tag
- a helper script shells out unsafely

Repo Risk Radar turns those patterns into a single CLI report with actionable fixes.

## Current checks

- secret-like tokens and private key material in text files
- risky committed artifacts such as `.env`, `.pem`, `.key`, and SSH private keys
- workflow risks like `pull_request_target`, `permissions: write-all`, and `curl | sh`
- unpinned third-party GitHub Actions
- unsafe code patterns including `subprocess(..., shell=True)`, `eval(`, and `exec(`

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
repo-risk-radar scan . --format markdown
```

Run in CI and fail only on the severities you care about:

```bash
repo-risk-radar scan . --format json --fail-on high
```

## Example output

```text
# Repo Risk Radar Report

## Summary
- Critical: 0
- High: 2
- Medium: 1
- Low: 0
- Total: 3
```

## Security model

- scans the current repository tree only
- does not rewrite git history
- does not upload source files, findings, or paths anywhere
- uses Python standard library only at runtime

## Project baseline

- [Architecture notes](ARCHITECTURE.md)
- [Contribution guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Security audit log](docs/security-audit.md)
- [Skill registry](docs/SKILL_REGISTRY.md)

## Roadmap

1. add configurable allowlists and per-rule suppression
2. emit SARIF for GitHub code scanning ingestion
3. scan git history and release artifacts safely
4. add pre-commit and reusable workflow integrations

## Status

This repository ships a working vertical slice and green local tests are expected through the included CI workflow. GitHub native secret scanning may still be unavailable unless Advanced Security is enabled for the repository.
