from __future__ import annotations

import argparse
import json
from pathlib import Path

from .scanner import exceeds_threshold, scan_repository, to_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo-risk-radar",
        description="Scan a repository for secrets, risky workflow permissions, and dangerous automation patterns.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a repository path")
    scan_parser.add_argument("path", nargs="?", default=".", help="Repository root to scan")
    scan_parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="markdown",
        help="Output format",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="high",
        help="Return a non-zero exit code when findings at or above the threshold are present",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    report = scan_repository(Path(args.path))
    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(to_markdown(report))
    return 1 if exceeds_threshold(report, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
