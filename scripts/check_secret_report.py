#!/usr/bin/env python3
"""Compare two redacted secret-scan reports. Prints the summary only."""
from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 3:
        print("usage: check_secret_report.py <got.json> <expected.json>", file=sys.stderr)
        sys.exit(2)
    got = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    expected = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    got_findings = got.get("findings") or []
    expected_findings = expected.get("findings") or []
    if got_findings != expected_findings or got.get("summary") != expected.get("summary"):
        print(
            f"mismatch got={got.get('summary')} expected={expected.get('summary')} "
            f"got_n={len(got_findings)} expected_n={len(expected_findings)}",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"secret scan matches committed report: {got.get('summary')}")


if __name__ == "__main__":
    main()
