# Architecture

## Goals

Repo Risk Radar is designed to be:

- **local-first** so source code never needs to leave the machine
- **high-signal** so findings are actionable instead of noisy
- **CI-friendly** so teams can gate merges on chosen severity thresholds
- **extensible** so new rule packs can be added without rewriting the CLI

## Layout

```text
src/repo_risk_radar/
  __init__.py
  __main__.py
  cli.py
  scanner.py
tests/
  test_cli.py
  test_scanner.py
```

## Flow

1. The CLI accepts a target path, output format, and failure threshold.
2. The scanner walks the repository while skipping common generated or vendor directories.
3. Each file goes through:
   - filename and artifact checks
   - text decoding guardrails
   - secret pattern checks
   - code-pattern checks for executable sources
   - workflow-specific checks for `.github/workflows/*`
4. Findings are normalized into a single structure.
5. Output renders as JSON or Markdown.
6. CI can fail the run when a configured severity threshold is exceeded.

## Security choices

- Runtime code relies on Python standard library only.
- File decoding is defensive and skips binary-heavy files.
- The scanner is read-only; it never edits or deletes files.
- Findings are intentionally short and sanitized.

## Extension points

Future enhancements can add:

- user-defined rule configuration
- SARIF output
- git-history scanning
- baseline snapshots and diff-aware scanning
