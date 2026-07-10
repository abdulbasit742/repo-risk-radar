from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import re

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
}
RISKY_FILENAMES = {
    ".env": (
        "high",
        "Environment file committed to repository",
        "Move secrets to local-only storage and keep only a sanitized .env.example file.",
    ),
    ".env.local": (
        "high",
        "Local environment file committed to repository",
        "Remove local overrides from the repository and add them to .gitignore.",
    ),
    "id_rsa": (
        "critical",
        "Private SSH key committed to repository",
        "Remove the private key from the repository tree and rotate the affected credential.",
    ),
    "id_ed25519": (
        "critical",
        "Private SSH key committed to repository",
        "Remove the private key from the repository tree and rotate the affected credential.",
    ),
}
TEXT_FILE_NAMES = {"Dockerfile", "Makefile", ".gitignore", ".env", ".env.example"}
TEXT_SUFFIXES = {
    ".py",
    ".md",
    ".txt",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".env",
    ".sh",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".sql",
    ".properties",
    ".xml",
    ".csv",
}
SECRET_PATTERNS = [
    (
        "critical",
        "Private key material detected",
        re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
        "Remove the key from the repository tree and rotate the credential outside GitHub.",
    ),
    (
        "critical",
        "AWS access key detected",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "Remove the credential from source and rotate the key in AWS.",
    ),
    (
        "high",
        "GitHub token pattern detected",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
        "Move the token to a secret manager and rotate it in GitHub.",
    ),
    (
        "high",
        "Slack token pattern detected",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "Remove the token from source and rotate it in Slack.",
    ),
    (
        "high",
        "OpenAI-style API key pattern detected",
        re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        "Remove the API key from source and rotate it with the provider.",
    ),
]
CODE_PATTERNS = [
    (
        "high",
        "Shell invocation with shell=True",
        re.compile(r"subprocess\.(?:run|Popen|call|check_call|check_output)\([^\n]*shell\s*=\s*True"),
        "Prefer argument lists and keep shell=False to reduce command-injection risk.",
    ),
    (
        "medium",
        "Dynamic eval detected",
        re.compile(r"\beval\s*\("),
        "Replace eval with explicit parsing or a fixed dispatch table.",
    ),
    (
        "medium",
        "Dynamic exec detected",
        re.compile(r"\bexec\s*\("),
        "Replace exec with explicit imports or controlled dispatch.",
    ),
]
USES_PATTERN = re.compile(r"^\s*uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([^\s]+)", re.MULTILINE)
CURL_PIPE_PATTERN = re.compile(r"(?:curl|wget)[^\n|>]*\|\s*(?:sh|bash)", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    severity: str
    category: str
    title: str
    path: str
    line: int | None
    snippet: str
    recommendation: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def iter_files(root: Path):
    for path in root.rglob("*"):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.is_file():
            yield path


def is_text_file(path: Path) -> bool:
    if path.name in TEXT_FILE_NAMES or path.suffix.lower() in TEXT_SUFFIXES:
        return True
    if path.stat().st_size > 1_000_000:
        return False
    try:
        raw = path.read_bytes()
    except OSError:
        return False
    return b"\x00" not in raw


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def add_finding(
    findings: list[Finding],
    severity: str,
    category: str,
    title: str,
    path: Path,
    line: int | None,
    snippet: str,
    recommendation: str,
    root: Path,
) -> None:
    findings.append(
        Finding(
            severity=severity,
            category=category,
            title=title,
            path=str(path.relative_to(root)),
            line=line,
            snippet=snippet.strip()[:200],
            recommendation=recommendation,
        )
    )


def scan_filename(path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    if path.name in RISKY_FILENAMES:
        severity, title, recommendation = RISKY_FILENAMES[path.name]
        add_finding(findings, severity, "artifact", title, path, None, path.name, recommendation, root)
    if path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}:
        add_finding(
            findings,
            "high",
            "artifact",
            "Sensitive certificate or key-like file committed",
            path,
            None,
            path.name,
            "Keep certificates and keys out of the repository and load them from secure local storage or secret managers.",
            root,
        )
    return findings


def scan_text(path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    if not is_text_file(path):
        return findings
    text = read_text(path)
    lines = text.splitlines()
    for severity, title, pattern, recommendation in SECRET_PATTERNS:
        for index, line in enumerate(lines, start=1):
            if pattern.search(line):
                add_finding(findings, severity, "secret", title, path, index, line, recommendation, root)
    if path.suffix.lower() in {".py", ".js", ".ts", ".tsx", ".jsx", ".sh"}:
        for severity, title, pattern, recommendation in CODE_PATTERNS:
            for index, line in enumerate(lines, start=1):
                if pattern.search(line):
                    add_finding(findings, severity, "code", title, path, index, line, recommendation, root)
    if ".github" in path.parts and "workflows" in path.parts and path.suffix.lower() in {".yml", ".yaml"}:
        findings.extend(scan_workflow(path, text, root))
    return findings


def scan_workflow(path: Path, text: str, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    if "permissions:" not in text:
        add_finding(
            findings,
            "medium",
            "ci",
            "Workflow does not declare explicit permissions",
            path,
            None,
            "permissions:",
            "Declare the minimum required permissions at workflow or job scope.",
            root,
        )
    if re.search(r"permissions:\s*write-all", text):
        add_finding(
            findings,
            "high",
            "ci",
            "Workflow requests write-all permissions",
            path,
            None,
            "permissions: write-all",
            "Replace write-all with the smallest permission set required for the job.",
            root,
        )
    if "pull_request_target" in text:
        add_finding(
            findings,
            "high",
            "ci",
            "Workflow uses pull_request_target",
            path,
            None,
            "pull_request_target",
            "Use pull_request unless elevated privileges are truly required and guard all untrusted inputs.",
            root,
        )
    if CURL_PIPE_PATTERN.search(text):
        add_finding(
            findings,
            "high",
            "ci",
            "Workflow pipes remote content directly into a shell",
            path,
            None,
            "curl | sh",
            "Download artifacts explicitly, verify integrity, and execute only trusted local files.",
            root,
        )
    for match in USES_PATTERN.finditer(text):
        action, ref = match.groups()
        owner, _ = action.split("/", 1)
        if owner not in {"actions", "github"} and not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
            add_finding(
                findings,
                "medium",
                "ci",
                "Third-party GitHub Action is not pinned to a full commit SHA",
                path,
                None,
                match.group(0),
                "Pin third-party actions to immutable commit SHAs to reduce supply-chain risk.",
                root,
            )
    return findings


def summarize(findings: list[Finding]) -> dict[str, int]:
    summary = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        summary[finding.severity] += 1
    summary["total"] = len(findings)
    return summary


def scan_repository(root: str | Path) -> dict[str, object]:
    root_path = Path(root).resolve()
    findings: list[Finding] = []
    for path in iter_files(root_path):
        findings.extend(scan_filename(path, root_path))
        findings.extend(scan_text(path, root_path))
    findings.sort(key=lambda item: (-SEVERITY_ORDER[item.severity], item.path, item.line or 0, item.title))
    return {
        "root": str(root_path),
        "summary": summarize(findings),
        "findings": [finding.to_dict() for finding in findings],
    }


def to_markdown(report: dict[str, object]) -> str:
    summary = report["summary"]
    findings = report["findings"]
    lines = [
        "# Repo Risk Radar Report",
        "",
        f"Scanned root: `{report['root']}`",
        "",
        "## Summary",
        "",
        f"- Critical: {summary['critical']}",
        f"- High: {summary['high']}",
        f"- Medium: {summary['medium']}",
        f"- Low: {summary['low']}",
        f"- Total: {summary['total']}",
    ]
    if not findings:
        lines.extend(["", "No findings detected in the scanned tree."])
        return "\n".join(lines)
    lines.extend(["", "## Findings", ""])
    for finding in findings:
        location = f"{finding['path']}:{finding['line']}" if finding.get("line") else finding["path"]
        lines.extend(
            [
                f"### {finding['severity'].upper()} — {finding['title']}",
                f"- Category: {finding['category']}",
                f"- Location: `{location}`",
                f"- Snippet: `{finding['snippet']}`",
                f"- Recommendation: {finding['recommendation']}",
                "",
            ]
        )
    return "\n".join(lines)


def exceeds_threshold(report: dict[str, object], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = SEVERITY_ORDER[fail_on]
    for severity, weight in SEVERITY_ORDER.items():
        if weight >= threshold and report["summary"][severity] > 0:
            return True
    return False
