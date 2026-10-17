#!/usr/bin/env bats
bats_require_minimum_version 1.5.0

# Safety and fail-closed tests for harden.sh and rollback.sh.
# Every test runs with HOME pointed at a temp directory and systemctl mocked.
# The real user home must stay untouched.

setup() {
  ORIGINAL_HOME="$HOME"
  REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
  WORK="$(mktemp -d)"
  HOME_DIR="$(mktemp -d)"
  MOCK_BIN="$WORK/bin"
  mkdir -p "$MOCK_BIN" "$WORK/profiles" "$WORK/context"
  cp "$REPO_ROOT/harden.sh" "$REPO_ROOT/rollback.sh" "$REPO_ROOT/ledger.py" "$WORK/"
  cp "$REPO_ROOT/profiles/"*.conf "$WORK/profiles/"
  cp "$REPO_ROOT/tests/mocks/systemctl" "$REPO_ROOT/tests/mocks/systemd-analyze" "$MOCK_BIN/"
  chmod +x "$MOCK_BIN/systemctl" "$MOCK_BIN/systemd-analyze" "$WORK/harden.sh" "$WORK/rollback.sh"
  printf 'why this unit\n' >"$WORK/context/why.md"
  export HOME="$HOME_DIR"
  export SYSTEMCTL_LOG="$WORK/systemctl.log"
  export MOCK_WORKDIR="/var/lib/mock"
  : >"$SYSTEMCTL_LOG"
  export PATH="$MOCK_BIN:/usr/bin:/bin"
  if [[ -e "$ORIGINAL_HOME/.config/systemd" ]]; then
    find "$ORIGINAL_HOME/.config/systemd" -printf '%p\n' | sort >"$WORK/home-before"
  else
    : >"$WORK/home-before"
  fi
}

teardown() {
  local after="$WORK/home-after"
  if [[ -e "$ORIGINAL_HOME/.config/systemd" ]]; then
    find "$ORIGINAL_HOME/.config/systemd" -printf '%p\n' | sort >"$after"
  else
    : >"$after"
  fi
  diff -u "$WORK/home-before" "$after"
  rm -rf "$WORK" "$HOME_DIR"
}

dropin_for() {
  local unit="$1"
  printf '%s/.config/systemd/user/%s.service.d/90-hardening.conf' "$HOME_DIR" "$unit"
}

unlock_for() {
  local unit="$1"
  printf '%s/.config/systemd/user/%s.service.d/99-unlocked.conf' "$HOME_DIR" "$unit"
}

seed_rollback_pair() {
  local unit="$1"
  local dropin_dir="$HOME_DIR/.config/systemd/user/${unit}.service.d"
  mkdir -p "$dropin_dir" "$WORK/backups"
  printf 'OLD\n' >"$WORK/backups/${unit}.conf"
  printf 'NEW\n' >"$dropin_dir/90-hardening.conf"
  python3 - "$WORK" "$unit" "$dropin_dir/90-hardening.conf" "$WORK/backups/${unit}.conf" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
import ledger
ledger.record(
    target=sys.argv[2],
    profile="service",
    dropin_file=sys.argv[3],
    backup_path=sys.argv[4],
    rollback_cmd="rollback",
    smoke_cmd="true",
    smoke_result="OK",
)
PY
}

@test "list does not create a backups directory" {
  run -0 bash "$WORK/harden.sh" list
  [ ! -d "$WORK/backups" ]
  ! grep -q 'daemon-reload' "$SYSTEMCTL_LOG"
}

@test "show does not create a backups directory" {
  run -0 bash "$WORK/harden.sh" show --unit demo
  [ ! -d "$WORK/backups" ]
  [[ "$output" == *"no hardening drop-in"* ]]
}

@test "apply without --execute refuses host changes" {
  run -0 bash "$WORK/harden.sh" apply --unit demo --profile strict --smoke true
  [[ "$output" == *"DRY RUN"* ]]
  [[ "$output" == *"refusing host changes"* ]]
  [ ! -f "$(dropin_for demo)" ]
  [ ! -d "$WORK/backups" ]
  ! grep -q 'daemon-reload' "$SYSTEMCTL_LOG"
}

@test "explicit dry-run does not copy an existing drop-in into backups" {
  local dropin
  dropin="$(dropin_for demo)"
  mkdir -p "$(dirname "$dropin")"
  printf 'OLD-DROPIN\n' >"$dropin"
  run -0 bash "$WORK/harden.sh" apply --unit demo --profile strict --smoke true --dry-run
  [[ "$output" == *"refusing host changes"* ]]
  [ "$(grep -c '\[Service\]' <<<"$output")" -eq 1 ]
  cmp -s <(printf 'OLD-DROPIN\n') "$dropin"
  [ ! -d "$WORK/backups" ] || [ -z "$(find "$WORK/backups" -type f -print)" ]
  ! grep -q 'daemon-reload' "$SYSTEMCTL_LOG"
}

@test "dry-run succeeds when systemctl is not installed" {
  local safe cmd
  safe="$(mktemp -d)"
  for cmd in bash python3 dirname pwd cat mkdir cp rm printf grep date mktemp head tail ls true false sed chmod; do
    if command -v "$cmd" >/dev/null 2>&1; then
      ln -sf "$(command -v "$cmd")" "$safe/$cmd"
    fi
  done
  run -0 env PATH="$safe" HOME="$HOME_DIR" bash "$WORK/harden.sh" apply --unit demo --profile strict --smoke true
  [[ "$output" == *"refusing host changes"* ]]
  [ ! -f "$(dropin_for demo)" ]
  rm -rf "$safe"
}

@test "apply rejects --dry-run combined with --execute" {
  run -2 bash "$WORK/harden.sh" apply --unit demo --profile strict --smoke true --dry-run --execute
  [[ "$output" == *"cannot be combined"* ]]
  [ ! -f "$(dropin_for demo)" ]
}

@test "apply without --unit does not write and does not create backups" {
  run -2 bash "$WORK/harden.sh" apply --profile strict --smoke true
  [[ "$output" == *"--unit required"* ]]
  [ ! -d "$WORK/backups" ]
  [ ! -e "$HOME_DIR/.config/systemd" ]
}

@test "apply --execute writes the drop-in, records the ledger, and reloads once" {
  run -0 bash "$WORK/harden.sh" apply \
    --unit demo \
    --profile strict \
    --allow-write /var/lib/demo-cache \
    --inaccessible /tmp/secret \
    --smoke true \
    --context-file "$WORK/context/why.md" \
    --execute
  [[ "$output" == *"HARDENING APPLIED"* ]]
  local dropin
  dropin="$(dropin_for demo)"
  [ -f "$dropin" ]
  [ "$(grep -c '^\[Service\]$' "$dropin")" -eq 1 ]
  grep -q 'ProtectSystem=strict' "$dropin"
  grep -q 'ReadWritePaths=/var/lib/demo-cache' "$dropin"
  grep -q 'InaccessiblePaths=-/tmp/secret' "$dropin"
  [ "$(grep -c -- '--user daemon-reload' "$SYSTEMCTL_LOG")" -eq 1 ]
  run -0 python3 "$WORK/ledger.py" show demo
  [[ "$output" == *"strict"* ]]
  run -0 python3 "$WORK/ledger.py" context demo
  [[ "$output" == *"why this unit"* ]]
}

@test "apply --execute rolls back when the smoke command fails" {
  run -1 bash "$WORK/harden.sh" apply --unit demo --profile service --smoke false --execute
  [[ "$output" == *"FAIL CLOSED"* ]]
  [ ! -f "$(dropin_for demo)" ]
  grep -q 'daemon-reload' "$SYSTEMCTL_LOG"
}

@test "apply --execute removes the drop-in when daemon-reload fails" {
  run -1 env MOCK_DAEMON_RELOAD_FAIL=1 bash "$WORK/harden.sh" apply --unit other --profile service --smoke true --execute
  [[ "$output" == *"FAIL CLOSED"* ]]
  [ ! -f "$(dropin_for other)" ]
}

@test "apply --execute rolls back when the ledger record fails" {
  cat >"$WORK/ledger.py" <<'PY'
#!/usr/bin/env python3
import sys
print("ledger down", file=sys.stderr)
sys.exit(1)
PY
  run -1 bash "$WORK/harden.sh" apply --unit demo --profile service --smoke true --execute
  [[ "$output" == *"FAIL CLOSED"* ]]
  [ ! -f "$(dropin_for demo)" ]
}

@test "unlock without --execute does not write an unlock drop-in" {
  run -0 bash "$WORK/harden.sh" unlock --unit demo
  [[ "$output" == *"refusing host changes"* ]]
  [ ! -f "$(unlock_for demo)" ]
  ! grep -q 'daemon-reload' "$SYSTEMCTL_LOG"
}

@test "unlock --execute writes the marker and records an event" {
  run -0 bash "$WORK/harden.sh" unlock --unit demo --execute
  [ -f "$(unlock_for demo)" ]
  grep -q 'NoNewPrivileges=no' "$(unlock_for demo)"
  grep -q 'daemon-reload' "$SYSTEMCTL_LOG"
  python3 - "$WORK/ledger.sqlite" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
rows = conn.execute(
    "SELECT action FROM events WHERE target=? AND action='unlock'",
    ("demo",),
).fetchall()
if len(rows) != 1:
    raise SystemExit("expected exactly one unlock event, got %s" % (rows,))
PY
}

@test "unlock --execute removes the marker when the ledger event fails" {
  cat >"$WORK/ledger.py" <<'PY'
#!/usr/bin/env python3
import sys
print("ledger down", file=sys.stderr)
sys.exit(1)
PY
  run -1 bash "$WORK/harden.sh" unlock --unit demo --execute
  [[ "$output" == *"FAIL CLOSED"* ]]
  [ ! -f "$(unlock_for demo)" ]
}

@test "lock without --execute leaves the unlock marker in place" {
  local marker
  marker="$(unlock_for demo)"
  mkdir -p "$(dirname "$marker")"
  printf 'KEEP\n' >"$marker"
  run -0 bash "$WORK/harden.sh" lock --unit demo
  [[ "$output" == *"refusing host changes"* ]]
  cmp -s <(printf 'KEEP\n') "$marker"
  ! grep -q 'daemon-reload' "$SYSTEMCTL_LOG"
}

@test "lock --execute removes the unlock marker" {
  local marker
  marker="$(unlock_for demo)"
  mkdir -p "$(dirname "$marker")"
  printf 'KEEP\n' >"$marker"
  run -0 bash "$WORK/harden.sh" lock --unit demo --execute
  [ ! -f "$marker" ]
  grep -q 'daemon-reload' "$SYSTEMCTL_LOG"
}

@test "lock --execute with no marker does not reload" {
  run -0 bash "$WORK/harden.sh" lock --unit demo --execute
  [[ "$output" == *"no unlock marker"* ]]
  ! grep -q 'daemon-reload' "$SYSTEMCTL_LOG"
}

@test "rollback without --execute does not change the drop-in" {
  seed_rollback_pair demo
  : >"$SYSTEMCTL_LOG"
  run -0 bash "$WORK/rollback.sh" --unit demo
  [[ "$output" == *"refusing host changes"* ]]
  cmp -s <(printf 'NEW\n') "$(dropin_for demo)"
  ! grep -q 'daemon-reload' "$SYSTEMCTL_LOG"
}

@test "rollback --execute restores the backup" {
  seed_rollback_pair demo
  : >"$SYSTEMCTL_LOG"
  run -0 bash "$WORK/rollback.sh" --unit demo --execute
  cmp -s <(printf 'OLD\n') "$(dropin_for demo)"
  grep -q 'daemon-reload' "$SYSTEMCTL_LOG"
}

@test "rollback --execute restores the previous drop-in when daemon-reload fails" {
  seed_rollback_pair demo
  run -1 env MOCK_DAEMON_RELOAD_FAIL=1 bash "$WORK/rollback.sh" --unit demo --execute
  [[ "$output" == *"FAIL CLOSED"* ]]
  cmp -s <(printf 'NEW\n') "$(dropin_for demo)"
}

@test "rollback of a quoted unit name reports a missing record instead of a query error" {
  run -1 bash "$WORK/rollback.sh" --unit "o'brien"
  [[ "$output" == *"no ledger record"* ]]
  [[ "$output" != *"query failed"* ]]
  [[ "$output" != *"SyntaxError"* ]]
  ! grep -q 'daemon-reload' "$SYSTEMCTL_LOG"
}
