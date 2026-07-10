# Contributing

Thanks for improving Repo Risk Radar.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pytest
```

## Development rules

- keep runtime dependencies at zero unless there is a strong reason
- add or update tests with every rule change
- prefer high-signal checks over broad noisy heuristics
- keep fixes reversible and avoid automatic remediation in the scanner core
- document any new rule or workflow behavior in the README and audit docs

## Pull requests

- describe the user pain the change addresses
- include validation evidence
- note security implications and residual risk
