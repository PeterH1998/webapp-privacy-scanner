"""
Privacy PII/GDPR scanner.

This scanner walks the repository tree, detects PII using regexes, respects an
allowlist, writes a JSON report, and exits non-zero when high severity issues
are found.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import yaml

# Default exclusions to avoid noise and expensive traversals
DEFAULT_IGNORED_DIRECTORIES = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    ".next",
    "dist",
    "build",
    "coverage",
    "reports",
}

DEFAULT_IGNORED_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}

PII_PATTERNS: Dict[str, re.Pattern[str]] = {
    "email": re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE),
    "phone": re.compile(
        r"(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}"
    ),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
}

SEVERITY_MAPPING = {
    "email": "medium",
    "phone": "high",
    "ssn": "high",
}


def load_allowlist(path: Path) -> Tuple[List[str], List[str]]:
    """Load allowlisted paths and patterns from YAML.

    The file supports keys "paths" and "regexes" (or "patterns") to ignore
    specific file paths or text matches.
    """
    if not path.exists():
        return [], []

    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    path_entries = data.get("paths", []) or []
    pattern_entries = data.get("regexes", []) or []
    pattern_entries.extend(data.get("patterns", []) or [])
    return path_entries, pattern_entries


def should_ignore_path(rel_path: Path, ignore_paths: Iterable[str]) -> bool:
    """Return True if the relative path should be skipped."""
    parts = set(rel_path.parts)
    if DEFAULT_IGNORED_DIRECTORIES & parts:
        return True

    if rel_path.name in DEFAULT_IGNORED_FILES:
        return True

    rel_posix = rel_path.as_posix()
    for entry in ignore_paths:
        if rel_path.match(entry) or rel_posix.startswith(entry.rstrip("/")):
            return True
    return False


def normalize_match(text: str) -> str:
    """Normalize matched text for stable allowlist comparisons."""

    return text.strip()


def is_allowed_match(text: str, allow_patterns: Iterable[str]) -> bool:
    return any(re.search(pattern, text) for pattern in allow_patterns)


def scan_file(file_path: Path, allow_patterns: Iterable[str]) -> List[Dict[str, str]]:
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return []

    issues: List[Dict[str, str]] = []
    for line_no, line in enumerate(content.splitlines(), start=1):
        for pii_type, pattern in PII_PATTERNS.items():
            for match in pattern.finditer(line):
                matched_text = normalize_match(match.group(0))

                # Only allowlist decisions happen after normalization of the match
                if is_allowed_match(matched_text, allow_patterns) or is_allowed_match(
                    line, allow_patterns
                ):
                    continue

                severity = SEVERITY_MAPPING.get(pii_type, "medium")
                issues.append(
                    {
                        "file": str(file_path),
                        "line": line_no,
                        "type": pii_type,
                        "match": matched_text,
                        "severity": severity,
                        "context": line.strip(),
                    }
                )
    return issues


def write_report(report_path: Path, issues: List[Dict[str, str]], root: Path) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)

    summary = {
        "total_findings": len(issues),
        "by_severity": {
            "high": sum(1 for issue in issues if issue["severity"] == "high"),
            "medium": sum(1 for issue in issues if issue["severity"] == "medium"),
            "low": sum(1 for issue in issues if issue["severity"] == "low"),
        },
    }

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "repository_root": str(root),
        "issues": issues,
        "summary": summary,
    }

    with report_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)


def scan_repository(root: Path, allow_paths: List[str], allow_patterns: List[str]) -> List[Dict[str, str]]:
    issues: List[Dict[str, str]] = []
    for path in root.rglob("*"):
        if path.is_dir():
            rel_dir = path.relative_to(root)
            if should_ignore_path(rel_dir, allow_paths):
                # Skip walking ignored directories
                path_parts = set(rel_dir.parts)
                if path_parts:
                    continue
            continue

        rel_file = path.relative_to(root)
        if should_ignore_path(rel_file, allow_paths):
            continue

        issues.extend(scan_file(path, allow_patterns))
    return issues


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Custom PII/GDPR scanner")
    repo_root = Path(__file__).resolve().parent.parent.parent
    parser.add_argument(
        "--root",
        type=Path,
        default=repo_root,
        help="Repository root to scan (default: project root)",
    )
    parser.add_argument(
        "--allowlist",
        type=Path,
        default=Path(__file__).resolve().with_name("allowlist.yml"),
        help="Path to allowlist YAML file",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=repo_root / "reports" / "pii_report.json",
        help="Path for the JSON report",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    try:
        allow_paths, allow_patterns = load_allowlist(args.allowlist)
        issues = scan_repository(args.root, allow_paths, allow_patterns)
        write_report(args.output, issues, args.root)
    except Exception as exc:  # pragma: no cover - defensive guard for CI clarity
        print(f"PII scanner runtime error: {exc}")
        sys.exit(2)

    if issues:
        print(f"PII findings detected (non-allowlisted): {len(issues)}")
        sys.exit(1)

    print("PII scan completed with no non-allowlisted findings.")


if __name__ == "__main__":
    main()
