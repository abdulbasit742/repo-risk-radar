# Security Policy

## Supported versions

The project is in active `0.x` development. The latest `main` branch is the supported line.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the maintainer before public disclosure. Include:

- affected version or commit
- reproduction steps at a high level
- impact assessment
- suggested remediation if known

Do not include live secrets or harmful payloads in public issues.

## Secure usage notes

- Repo Risk Radar scans the current tree only. It does not rotate secrets or rewrite history.
- If the scanner surfaces a real credential, remove it from the current tree and rotate it with the provider.
- GitHub native secret scanning requires repository-level Advanced Security and may not be available in all environments.
