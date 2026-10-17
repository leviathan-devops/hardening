#!/usr/bin/env python3
"""Render a gitleaks JSON report with secret values removed.

The written report keeps rule, file, and commit. Secret text, match text,
and source lines are dropped. A token-shaped leftover refuses the write.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

TOKEN = re.compile(
    r"(ghp_[A-Za-z0-9]{10,}|github_pat_[A-Za-z0-9_]{10,}|"
    r"AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]+PRIVATE KEY-----)"
)


def load_findings(path: Path) -> list:
    raw = path.read_text(encoding="utf-8") if path.exists() else "[]"
    data = json.loads(raw or "[]")
    if data is None:
        return []
    if not isinstance(data, list):
        print("gitleaks report must be a JSON list", file=sys.stderr)
        sys.exit(2)
    return data


def build_report(items: list) -> dict:
    findings = []
    for item in items:
        findings.append(
            {
                "rule": item.get("RuleID") or item.get("rule") or "unknown",
                "file": item.get("File") or item.get("file") or "",
                "commit": item.get("Commit") or item.get("commit") or "",
            }
        )
    findings.sort(key=lambda row: (row["file"], row["commit"], row["rule"]))
    counts = Counter(row["rule"] for row in findings)
    summary = "CLEAN" if not findings else f"FINDINGS {len(findings)}"
    return {
        "scanner": "gitleaks",
        "version": "8.30.1",
        "summary": summary,
        "counts_by_rule": dict(sorted(counts.items())),
        "findings": findings,
    }


def render_text(doc: dict) -> str:
    lines = [
        "Secret scan (redacted)",
        "scanner: gitleaks 8.30.1",
        "scope: full git history of leviathan-devops/hardening",
        "action: report only; values omitted; no history rewrite; no visibility change",
        f"summary: {doc['summary']}",
        "counts_by_rule:",
    ]
    if not doc["counts_by_rule"]:
        lines.append("  (none)")
    else:
        for rule, count in doc["counts_by_rule"].items():
            lines.append(f"  {rule}: {count}")
    lines.append("findings (file commit rule):")
    if not doc["findings"]:
        lines.append("  (none)")
    else:
        for row in doc["findings"]:
            lines.append(f"  {row['file']} {row['commit']} {row['rule']}")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    if len(sys.argv) != 4:
        print(
            "usage: redact_gitleaks.py <gitleaks.json> <out.json> <out.txt>",
            file=sys.stderr,
        )
        sys.exit(2)
    doc = build_report(load_findings(Path(sys.argv[1])))
    rendered_json = json.dumps(doc, indent=2) + "\n"
    rendered_text = render_text(doc)
    if TOKEN.search(rendered_json + rendered_text):
        print("refusing to write a report that still matches a token pattern", file=sys.stderr)
        sys.exit(1)
    Path(sys.argv[2]).write_text(rendered_json, encoding="utf-8")
    Path(sys.argv[3]).write_text(rendered_text, encoding="utf-8")


if __name__ == "__main__":
    main()
