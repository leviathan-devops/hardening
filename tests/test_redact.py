"""The secret-scan renderer must drop secret material and keep rule/file/commit."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REDACT = ROOT / "scripts" / "redact_gitleaks.py"


def test_redact_drops_secret_fields(tmp_path):
    sample = tmp_path / "in.json"
    sample.write_text(
        json.dumps(
            [
                {
                    "RuleID": "generic",
                    "File": "harden.sh",
                    "Commit": "deadbeef",
                    "Secret": "planted-marker-value",
                    "Match": "planted-marker-value",
                    "Line": "planted-marker-value",
                }
            ]
        ),
        encoding="utf-8",
    )
    out_json = tmp_path / "out.json"
    out_txt = tmp_path / "out.txt"
    subprocess.run(
        [sys.executable, str(REDACT), str(sample), str(out_json), str(out_txt)],
        check=True,
    )
    blob = out_json.read_text(encoding="utf-8") + out_txt.read_text(encoding="utf-8")
    assert "planted-marker-value" not in blob
    doc = json.loads(out_json.read_text(encoding="utf-8"))
    assert doc["summary"] == "FINDINGS 1"
    assert doc["counts_by_rule"] == {"generic": 1}
    assert doc["findings"] == [
        {"rule": "generic", "file": "harden.sh", "commit": "deadbeef"}
    ]
    assert "FINDINGS 1" in out_txt.read_text(encoding="utf-8")


def test_redact_empty_scan_is_clean(tmp_path):
    sample = tmp_path / "in.json"
    sample.write_text("[]", encoding="utf-8")
    out_json = tmp_path / "out.json"
    out_txt = tmp_path / "out.txt"
    subprocess.run(
        [sys.executable, str(REDACT), str(sample), str(out_json), str(out_txt)],
        check=True,
    )
    doc = json.loads(out_json.read_text(encoding="utf-8"))
    assert doc["summary"] == "CLEAN"
    assert doc["findings"] == []
    assert doc["counts_by_rule"] == {}
    text = out_txt.read_text(encoding="utf-8")
    assert "CLEAN" in text
    assert "report only" in text
