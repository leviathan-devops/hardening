"""Ledger CLI and id behavior.

These tests describe the contract the shell tools already call. On the
unfixed ledger they fail: `event`, `record-json`, and `get-json` are not
commands, and two records in the same second collide on the primary key.
"""
from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime, timezone

import pytest

import ledger


class FrozenDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return datetime(2026, 10, 17, 11, 48, 0, tzinfo=timezone.utc)


def _use_db(monkeypatch, path):
    monkeypatch.setattr(ledger, "DB_PATH", path)


def test_event_cli_records_a_row(tmp_path, monkeypatch):
    db = tmp_path / "ledger.sqlite"
    _use_db(monkeypatch, db)
    monkeypatch.setattr(
        sys, "argv", ["ledger.py", "event", "unit-a", "unlock", "relaxed", "host1"]
    )
    ledger.main()
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM events").fetchone()
    assert row["target"] == "unit-a"
    assert row["action"] == "unlock"
    assert row["detail"] == "relaxed"
    assert row["actor"] == "host1"


def test_record_json_then_get_json_keeps_quoted_target(tmp_path, monkeypatch, capsys):
    db = tmp_path / "ledger.sqlite"
    _use_db(monkeypatch, db)
    payload = {
        "target": "o'brien",
        "profile": "strict",
        "unit_file": "",
        "dropin_file": "/tmp/drop.in",
        "before_json": "{}",
        "after_json": "{}",
        "directives_json": json.dumps({"profile": "strict"}),
        "backup_path": "",
        "rollback_cmd": "rollback",
        "unlock_cmd": "unlock",
        "lock_cmd": "lock",
        "smoke_cmd": "true",
        "smoke_result": "OK",
        "security_score_before": "",
        "security_score_after": "",
        "context_md": "because",
        "actor": "tester",
    }
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["ledger.py", "record-json", str(payload_path)])
    ledger.main()
    capsys.readouterr()
    monkeypatch.setattr(sys, "argv", ["ledger.py", "get-json", "o'brien"])
    ledger.main()
    doc = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert doc["dropin_file"] == "/tmp/drop.in"
    assert doc["backup_path"] == ""
    assert "error" not in doc


def test_get_json_missing_target_exits_1(tmp_path, monkeypatch, capsys):
    _use_db(monkeypatch, tmp_path / "ledger.sqlite")
    monkeypatch.setattr(sys, "argv", ["ledger.py", "get-json", "missing-unit"])
    with pytest.raises(SystemExit) as caught:
        ledger.main()
    assert caught.value.code == 1
    assert "no ledger record for missing-unit" in capsys.readouterr().err


def test_two_records_in_the_same_second_get_distinct_ids(tmp_path, monkeypatch):
    _use_db(monkeypatch, tmp_path / "ledger.sqlite")
    monkeypatch.setattr(ledger, "datetime", FrozenDateTime)
    first = ledger.record(target="unit-a", profile="strict")
    second = ledger.record(target="unit-a", profile="service")
    assert first != second
    assert first.startswith("unit-a-20261017-114800")
    assert second.startswith("unit-a-20261017-114800")
