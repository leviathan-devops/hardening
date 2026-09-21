#!/usr/bin/env python3
"""Ledger API + CLI for the production runtime hardening toolchain.

Schema is frozen (see CONTEXT block in the operator brief).  This module owns
ledger.sqlite at the project root, the single source of truth for every
hardening action taken on this host.
"""
from __future__ import annotations

import json
import sqlite3
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "ledger.sqlite"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_schema(wipe: bool = False) -> None:
    """Create tables if they do not exist."""
    conn = _connect()
    try:
        if wipe:
            conn.execute("DROP TABLE IF EXISTS hardened")
            conn.execute("DROP TABLE IF EXISTS events")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hardened (
              id            TEXT PRIMARY KEY,
              kind          TEXT NOT NULL,
              target        TEXT NOT NULL,
              unit_file     TEXT,
              dropin_file   TEXT,
              host          TEXT,
              profile       TEXT NOT NULL,
              applied_at    TEXT NOT NULL,
              before_json   TEXT,
              after_json    TEXT,
              directives_json TEXT,
              backup_path   TEXT,
              rollback_cmd  TEXT,
              unlock_cmd    TEXT,
              lock_cmd      TEXT,
              smoke_cmd     TEXT,
              smoke_result  TEXT,
              security_score_before TEXT,
              security_score_after  TEXT,
              context_md    TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              at TEXT NOT NULL,
              target TEXT NOT NULL,
              action TEXT NOT NULL,
              detail TEXT,
              actor TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def record(
    *,
    target: str,
    kind: str = "systemd-user-unit",
    unit_file: str | None = None,
    dropin_file: str | None = None,
    profile: str,
    before_json: dict | None = None,
    after_json: dict | None = None,
    directives_json: dict | None = None,
    backup_path: str | None = None,
    rollback_cmd: str | None = None,
    unlock_cmd: str | None = None,
    lock_cmd: str | None = None,
    smoke_cmd: str | None = None,
    smoke_result: str | None = None,
    security_score_before: str | None = None,
    security_score_after: str | None = None,
    context_md: str | None = None,
    actor: str | None = None,
) -> str:
    """Insert a hardening record and log an event. Returns the row id."""
    init_schema()
    now = datetime.now(timezone.utc).isoformat()
    slug = f"{target}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    conn = _connect()
    try:
        conn.execute(
            """
            INSERT INTO hardened (
              id, kind, target, unit_file, dropin_file, host, profile,
              applied_at, before_json, after_json, directives_json,
              backup_path, rollback_cmd, unlock_cmd, lock_cmd,
              smoke_cmd, smoke_result, security_score_before,
              security_score_after, context_md
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                slug,
                kind,
                target,
                unit_file,
                dropin_file,
                _hostname(),
                profile,
                now,
                json.dumps(before_json) if before_json is not None else None,
                json.dumps(after_json) if after_json is not None else None,
                json.dumps(directives_json) if directives_json is not None else None,
                backup_path,
                rollback_cmd,
                unlock_cmd,
                lock_cmd,
                smoke_cmd,
                smoke_result,
                security_score_before,
                security_score_after,
                context_md,
            ),
        )
        conn.execute(
            "INSERT INTO events (at, target, action, detail, actor) VALUES (?,?,?,?,?)",
            (now, target, "record", f"hardening applied with profile={profile}", actor),
        )
        conn.commit()
        return slug
    finally:
        conn.close()


def get(target: str) -> sqlite3.Row | None:
    """Fetch the most recent record for *target*."""
    init_schema()
    conn = _connect()
    try:
        cur = conn.execute(
            "SELECT * FROM hardened WHERE target = ? ORDER BY applied_at DESC LIMIT 1",
            (target,),
        )
        return cur.fetchone()
    finally:
        conn.close()


def list_all() -> list[sqlite3.Row]:
    """Fetch all hardened records, newest first."""
    init_schema()
    conn = _connect()
    try:
        cur = conn.execute(
            "SELECT * FROM hardened ORDER BY applied_at DESC"
        )
        return cur.fetchall()
    finally:
        conn.close()


def event(target: str, action: str, detail: str | None = None, actor: str | None = None) -> None:
    """Append an event row."""
    init_schema()
    now = datetime.now(timezone.utc).isoformat()
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO events (at, target, action, detail, actor) VALUES (?,?,?,?,?)",
            (now, target, action, detail, actor),
        )
        conn.commit()
    finally:
        conn.close()


# ── helpers ────────────────────────────────────────────────────────────────

def _hostname() -> str:
    import socket

    return socket.gethostname()


def _fmt_table(rows: list[sqlite3.Row]) -> str:
    if not rows:
        return "[no rows]"
    cols = list(rows[0].keys())
    widths = {c: len(c) for c in cols}
    for row in rows:
        for c in cols:
            widths[c] = max(widths[c], len(str(row[c]) if row[c] is not None else ""))
    sep = "  ".join("-" * widths[c] for c in cols)
    header = "  ".join(c.ljust(widths[c]) for c in cols)
    lines = [header, sep]
    for row in rows:
        lines.append("  ".join(
            str(row[c]).ljust(widths[c]) if row[c] is not None else "".ljust(widths[c])
            for c in cols
        ))
    return "\n".join(lines)


# ── CLI ────────────────────────────────────────────────────────────────────

def _cli_list() -> None:
    rows = list_all()
    print(f"ledger: {len(rows)} hardened record(s)")
    print(_fmt_table(rows))


def _cli_show(target: str) -> None:
    row = get(target)
    if row is None:
        print(f"[no hardened record for: {target}]")
        sys.exit(1)
    print(f"id            : {row['id']}")
    print(f"kind          : {row['kind']}")
    print(f"target        : {row['target']}")
    print(f"unit_file     : {row['unit_file']}")
    print(f"dropin_file   : {row['dropin_file']}")
    print(f"profile       : {row['profile']}")
    print(f"applied_at    : {row['applied_at']}")
    print(f"backup_path   : {row['backup_path']}")
    print(f"rollback_cmd  : {row['rollback_cmd']}")
    print(f"unlock_cmd    : {row['unlock_cmd']}")
    print(f"lock_cmd      : {row['lock_cmd']}")
    print(f"smoke_cmd     : {row['smoke_cmd']}")
    print(f"smoke_result  : {row['smoke_result']}")
    print(f"score_before  : {row['security_score_before']}")
    print(f"score_after   : {row['security_score_after']}")


def _cli_context(target: str) -> None:
    row = get(target)
    if row is None:
        print(f"[no hardened record for: {target}]")
        sys.exit(1)
    md = row["context_md"] or ""
    if not md.strip():
        print("[no context recorded]")
        return
    print(textwrap.dedent(md))


def main() -> None:
    init_schema()
    args = sys.argv[1:]
    if not args or args[0] not in ("list", "show", "context"):
        print("usage: ledger.py list | show <target> | context <target>", file=sys.stderr)
        sys.exit(2)
    if args[0] == "list":
        _cli_list()
    elif args[0] == "show":
        if len(args) < 2:
            print("usage: ledger.py show <target>", file=sys.stderr)
            sys.exit(2)
        _cli_show(args[1])
    elif args[0] == "context":
        if len(args) < 2:
            print("usage: ledger.py context <target>", file=sys.stderr)
            sys.exit(2)
        _cli_context(args[1])


if __name__ == "__main__":
    main()
