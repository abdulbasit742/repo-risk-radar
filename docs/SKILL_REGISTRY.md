# Skill Registry

## Open skills

### SKILL-001 — SARIF export

**Why it matters:** lets teams publish findings into GitHub code scanning and other security dashboards.

**Acceptance criteria:**
- emit SARIF 2.1.0 output
- preserve rule ids and severities
- add tests for at least one finding per category

### SKILL-002 — Rule allowlists and suppressions

**Why it matters:** reduces noise without deleting rules.

**Acceptance criteria:**
- support repo-local configuration file
- allow path-based ignores and rule suppressions
- document safe suppression practices

### SKILL-003 — Git history and artifact scanning

**Why it matters:** current release covers the working tree only.

**Acceptance criteria:**
- optionally inspect git history metadata without rewriting history
- detect risky archive artifacts and generated bundles
- document performance and privacy trade-offs

### SKILL-004 — Pre-commit and reusable workflow integration

**Why it matters:** makes adoption easier for teams.

**Acceptance criteria:**
- ship a pre-commit hook snippet
- add a reusable GitHub Actions workflow example
- include dry-run guidance and failure-threshold examples

## Done this run

- shipped a working stdlib-only scanner CLI
- added tests, CI, security docs, and contributor docs
- created the initial security audit ledger
