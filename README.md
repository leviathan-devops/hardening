# Production Runtime Hardening Toolchain

A systemd-user-unit hardening and audit toolchain.  Applies kernel-level
sandboxing and service-grade discipline via drop-ins (never edits the original
unit in place), records every action + full context into a shared SQLite
ledger, and **fails closed**: a broken service is never left running.

## Directory Layout

```
hardening/
├── harden.sh          # apply | show | unlock | lock | list
├── rollback.sh        # reverse the most recent apply for a unit
├── ledger.sqlite      # shared DB (created on first record)
├── ledger.py          # read/write API + CLI (list / show / context)
├── profiles/
│   ├── strict.conf    # full sandbox set (ProtectSystem=strict)
│   └── service.conf   # service-grade discipline only (no sandbox)
├── backups/           # timestamped copies of replaced drop-ins
└── README.md
```

## Profiles

### `strict`

The full sandbox set.  Applied as a drop-in at
`~/.config/systemd/user/<unit>.d/90-hardening.conf`.

| Directive | Value |
|---|---|
| `NoNewPrivileges` | `yes` |
| `PrivateTmp` | `yes` |
| `ProtectSystem` | `strict` (whole FS read-only) |
| `ProtectHome` | `read-only` |
| `ProtectKernelTunables` | `yes` |
| `ProtectKernelModules` | `yes` |
| `ProtectControlGroups` | `yes` |
| `ProtectClock` | `yes` |
| `ProtectHostname` | `yes` |
| `RestrictSUIDSGID` | `yes` |
| `RestrictNamespaces` | `yes` |
| `RestrictRealtime` | `yes` |
| `LockPersonality` | `yes` |
| `MemoryDenyWriteExecute` | `no` |
| `RestrictAddressFamilies` | `AF_UNIX AF_INET AF_INET6` |
| `SystemCallArchitectures` | `native` |

**`MemoryDenyWriteExecute=no`** — Node.js and Bun JIT/WASM require
writable+executable memory mappings.  This is intentionally relaxed so the
runtime does not crash on JIT compilation.

**`ProtectSystem=strict`** makes the *entire* filesystem read-only.  Therefore
`harden.sh` **must** emit a `ReadWritePaths=` line for:
1. Every path passed via `--allow-write`.
2. The service's `WorkingDirectory` (resolved via `systemctl --user show`).
3. `/run` (systemd runtime data — added as a safe default).

`/tmp` is covered by `PrivateTmp=yes` (a fresh private `/tmp` mount).

### `service`

Service-grade discipline only — no sandboxing.  Used for units that need
full filesystem access but still benefit from restart policy and resource
limits.

| Directive | Value |
|---|---|
| `Restart` | `always` |
| `RestartSec` | `5` |
| `StartLimitIntervalSec` | `0` |
| `SyslogIdentifier` | `%n` |
| `LimitNOFILE` | `65536` |
| `TimeoutStopSec` | `30` |
| `KillSignal` | `SIGTERM` |

## CLI Reference

### `harden.sh apply`

Apply a profile to a systemd user unit via a drop-in.

```
harden.sh apply  --unit <name> --profile <strict|service>
                [--allow-write <path>]...
                [--inaccessible <path>]...
                --smoke "<cmd>"
                [--context-file <path>]
                [--execute | --dry-run]
```

- **`--unit`** — the systemd user unit name (e.g. `llama-bonsai-qwen`).
- **`--profile`** — `strict` or `service`.
- **`--allow-write`** — paths the service legitimately needs to write to
  (under `ProtectSystem=strict`).  Can be repeated.
- **`--inaccessible`** — paths to make unreachable via `InaccessiblePaths=`.
  Can be repeated.
- **`--smoke`** — a command that proves the service still works after
  hardening (e.g. `'systemctl --user is-active llama-bonsai-qwen'`).
- **`--context-file`** — a Markdown file describing the why: the ruling,
  defect, or threat that motivated this hardening.  Stored verbatim in the
  ledger.
- **`--execute`** — perform the host change (write the drop-in, daemon-reload,
  record the ledger). Required. Without it, `apply` dry-runs.
- **`--dry-run`** — force the preview even when reviewing a command line.
  Prints the drop-in that *would* be written, the BEFORE score, the smoke
  command, and the rollback command. Writes **nothing** to disk and records
  **nothing** in the ledger. Cannot be combined with `--execute`.

Omitting both flags is a dry-run. `unlock`, `lock`, and `rollback.sh` follow
the same rule.

**Fail-closed guarantee:** If the smoke test fails after the drop-in is
applied and `daemon-reload` is run, the toolchain:
1. Restores the backup drop-in (or deletes the new one if there was no
   prior drop-in).
2. Runs `daemon-reload` again.
3. Reports the failure with the score diff.
4. Exits non-zero.

The service is **never** left in a broken state.

### `harden.sh show`

```
harden.sh show --unit <name>
```

Prints the current drop-in contents (if present) and the ledger entry for
the unit.

### `harden.sh unlock`

```
harden.sh unlock --unit <name>
```

Temporarily relaxes all sandbox directives by writing
`~/.config/systemd/user/<unit>.d/99-unlocked.conf` that overrides each
sandbox directive to `no`/`off`/empty.  Logs an `unlock` event in the
ledger.  The original `90-hardening.conf` drop-in is **not** removed — it
stays in place for `lock` to re-enable.  Refuses the write unless
`--execute` is passed.

### `harden.sh lock`

```
harden.sh lock --unit <name>
```

Removes the `99-unlocked.conf` marker, re-enabling the hardening.  Logs a
`lock` event.  Refuses the removal unless `--execute` is passed.

### `harden.sh list`

Lists all hardened records from the ledger.

### `rollback.sh --unit <name>`

```
rollback.sh --unit <name> [--execute | --dry-run]
```

Reverses the most recent `apply` for the target.  Uses the `backup_path`
stored in the ledger to restore the prior drop-in state (or deletes the
drop-in if there was no prior one).  Runs `daemon-reload`.  Logs a `rollback`
event.  Dry-run unless `--execute` is passed.

## Ledger Schema

`ledger.sqlite` (at the project root) has two tables:

### `hardened`

| Column | Type | Description |
|---|---|---|
| `id` | TEXT PK | Slug: `<unit>-<YYYYMMDD-HHMMSS>`, with `-<n>` if that second already has a row |
| `kind` | TEXT | `'systemd-user-unit'` |
| `target` | TEXT | The unit name |
| `unit_file` | TEXT | Absolute path of the unit file |
| `dropin_file` | TEXT | Absolute path of the drop-in written |
| `host` | TEXT | Hostname where applied |
| `profile` | TEXT | `strict` or `service` |
| `applied_at` | TEXT | ISO-8601 UTC |
| `before_json` | TEXT | `systemctl --user show` resolved props BEFORE |
| `after_json` | TEXT | Resolved props AFTER |
| `directives_json` | TEXT | Every directive applied, as an object |
| `backup_path` | TEXT | Pre-change copy on disk |
| `rollback_cmd` | TEXT | Exact one-line command to undo |
| `unlock_cmd` | TEXT | Exact one-line command to temporarily relax |
| `lock_cmd` | TEXT | Exact one-line command to re-apply |
| `smoke_cmd` | TEXT | The command that proves the service still works |
| `smoke_result` | TEXT | Raw output + exit code |
| `security_score_before` | TEXT | `systemd-analyze security --user` BEFORE |
| `security_score_after` | TEXT | Score AFTER |
| `context_md` | TEXT | Full context (ruling/defect/threat) |

### `events`

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Autoincrement |
| `at` | TEXT | ISO-8601 UTC |
| `target` | TEXT | The unit name |
| `action` | TEXT | `record` / `unlock` / `lock` / `rollback` |
| `detail` | TEXT | Human-readable detail |
| `actor` | TEXT | Hostname |

## `ledger.py` CLI

```
ledger.py list                      # table of all hardened records
ledger.py show <target>            # full record for a unit
ledger.py context <target>         # the context_md for a unit
ledger.py event <target> <action> [detail] [actor]
ledger.py get-json <target>        # backup_path and dropin_file as JSON
ledger.py record-json <file>       # insert the payload harden.sh writes
```

The programmatic API (`record()`, `get()`, `list_all()`, `event()`) is
importable. The shell tools pass unit names as arguments to `event`,
`get-json`, and `record-json`.

## Usage Example

```bash
cd /home/leviathan/JARVIS_WORKSPACE/Shared_Workspace/hardening

# Dry-run first:
bash harden.sh apply \
  --unit llama-bonsai-qwen \
  --profile strict \
  --allow-write /home/leviathan/models \
  --inaccessible /tmp/secret \
  --smoke 'systemctl --user is-active llama-bonsai-qwen' \
  --context-file ./context/llama-bonsai-qwen.md \
  --dry-run

# Real apply. Without --execute the same command only prints a dry-run:
bash harden.sh apply \
  --unit llama-bonsai-qwen \
  --profile strict \
  --allow-write /home/leviathan/models \
  --smoke 'systemctl --user is-active llama-bonsai-qwen' \
  --context-file ./context/llama-bonsai-qwen.md \
  --execute

# Unlock temporarily (debug):
bash harden.sh unlock --unit llama-bonsai-qwen --execute

# Re-lock:
bash harden.sh lock --unit llama-bonsai-qwen --execute

# Full rollback:
bash rollback.sh --unit llama-bonsai-qwen --execute
```

## Safety Rules

1. **DROP-IN ONLY** — The original unit file is never modified.  All hardening
   lives in `~/.config/systemd/user/<unit>.d/90-hardening.conf`.
2. **FAIL CLOSED** — Smoke test failure after apply triggers automatic
   rollback + daemon-reload.
3. **DRY-RUN BY DEFAULT** — `apply`, `unlock`, `lock`, and `rollback.sh` do
   not change the host unless `--execute` is passed. `--dry-run` forces that
   preview. The two flags cannot be combined.
4. **NO SERVICE RESTARTS** — `harden.sh` does not restart services; it only
   writes drop-ins and runs `daemon-reload`.
5. **WRITE ONLY** under `hardening/` — no files are written elsewhere on disk
   (except the drop-in and backups, which are part of the systemd mechanism).
   A dry-run writes nothing, including the backups directory.
6. **CI STAYS OFF THE HOST** — GitHub Actions runs shellcheck, bats, and pytest
   inside an `ubuntu:24.04` container. Tests mock `systemctl` and use a
   temporary `HOME`. Do not point these scripts at a real machine from CI.
