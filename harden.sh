#!/usr/bin/env bash
# harden.sh — production runtime hardening toolchain for systemd user units.
#
#   harden.sh apply  --unit <name> --profile <strict|service> [--allow-write <path>]... \
#                    [--inaccessible <path>]... --smoke "<cmd>" [--context-file <path>] \
#                    [--execute | --dry-run]
#   harden.sh show   --unit <name>
#   harden.sh unlock --unit <name> [--execute | --dry-run]
#   harden.sh lock   --unit <name> [--execute | --dry-run]
#   harden.sh list
#
# apply, unlock, and lock dry-run unless --execute is given. Dry-run writes
# nothing: no drop-in, no backup, no daemon-reload, no ledger row.
# FAIL-CLOSED: a failed reload, smoke command, or ledger write restores the
# previous drop-in. The service is never left broken.
set -euo pipefail

HARDENING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILES_DIR="${HARDENING_DIR}/profiles"
BACKUPS_DIR="${HARDENING_DIR}/backups"
LEDGER_PY="${HARDENING_DIR}/ledger.py"
DROPIN_BASE="${HOME}/.config/systemd/user"

usage() {
  cat <<'EOF'
usage: harden.sh apply  --unit <name> --profile <strict|service> --smoke "<cmd>" [--context-file <path>] [--allow-write <path>]... [--inaccessible <path>]... [--execute | --dry-run]
              show   --unit <name>
              unlock --unit <name> [--execute | --dry-run]
              lock   --unit <name> [--execute | --dry-run]
              list

Host changes dry-run unless --execute is given. --dry-run and --execute cannot be combined.
EOF
}

script_host() { python3 -c 'import socket; print(socket.gethostname())'; }

# Run a command; returns empty on failure (best-effort).
probe() {
  "$@" 2>/dev/null || true
}

# systemctl --user show <unit> → resolved props as JSON. Empty object if systemd is absent.
props_json() {
  local unit="$1"
  local raw
  raw="$(systemctl --user show "$unit" 2>/dev/null || true)"
  printf '%s\n' "$raw" | python3 -c '
import sys, json
out = {}
for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    k, _, v = line.partition("=")
    out[k] = v
print(json.dumps(out, indent=2, sort_keys=True))
'
}

# Capture the systemd-analyze security score summary line. Empty if the tool is absent.
security_score() {
  local unit="$1"
  local raw
  raw="$(systemd-analyze security --user "$unit" 2>/dev/null || true)"
  printf '%s\n' "$raw" | grep -E 'Overall exposure level' || true
}

require_value() {
  local flag="$1"
  if [[ $# -lt 2 || -z "${2:-}" ]]; then
    echo "FATAL: ${flag} requires a value" >&2
    exit 2
  fi
}

refuse_conflicting_flags() {
  if [[ "$DRY_RUN" -eq 1 && "$EXECUTE" -eq 1 ]]; then
    echo "FATAL: --dry-run and --execute cannot be combined" >&2
    exit 2
  fi
}

host_changes_allowed() {
  [[ "$EXECUTE" -eq 1 && "$DRY_RUN" -eq 0 ]]
}

say_dry_run() {
  echo "=== DRY RUN — refusing host changes without --execute ==="
}

# Build the drop-in content for a given profile + flags.
build_dropin() {
  local profile_name="$1"
  local profile_file="${PROFILES_DIR}/${profile_name}.conf"
  if [[ ! -f "$profile_file" ]]; then
    echo "FATAL: profile '${profile_name}' not found at ${profile_file}" >&2
    exit 2
  fi

  local body
  body="$(grep -v '^[[:space:]]*#' "$profile_file" | grep -v '^[[:space:]]*$' || true)"

  local inaccessible=""
  local readwrite=""

  # --inaccessible paths → InaccessiblePaths= (best-effort, `-` prefix
  # matches the precedent unit's house style: the unit still starts even
  # if a path is absent)
  if [[ "${#INACCESSIBLE_PATHS[@]}" -gt 0 ]]; then
    local p
    for p in "${INACCESSIBLE_PATHS[@]}"; do
      inaccessible+="${inaccessible:+$'\n'}InaccessiblePaths=-${p}"
    done
  fi

  # --allow-write paths → ReadWritePaths= (REQUIRED under ProtectSystem=strict)
  # Plus sensible defaults: WorkingDirectory + /run (systemd runtime data)
  local wd
  wd="$(probe systemctl --user show -p WorkingDirectory "$UNIT" || true)"
  wd="${wd#WorkingDirectory=}"
  wd="${wd:-${HOME}}"

  readwrite="${wd}"
  readwrite+=$'\n/run'
  if [[ "${#ALLOW_WRITE_PATHS[@]}" -gt 0 ]]; then
    local allow
    for allow in "${ALLOW_WRITE_PATHS[@]}"; do
      [[ -n "$allow" ]] && readwrite+=$'\n'"${allow}"
    done
  fi

  local result="$body"
  if [[ -n "$inaccessible" ]]; then
    result+=$'\n'"${inaccessible}"
  fi
  if [[ -n "$readwrite" ]]; then
    result+=$'\n# ReadWritePaths (defaults under ProtectSystem=strict)'
    local r
    while IFS= read -r r; do
      [[ -n "$r" ]] && result+=$'\n'"ReadWritePaths=${r}"
    done <<< "$readwrite"
  fi

  printf '%s\n' "$result"
}

restore_dropin() {
  if [[ -n "${BACKUP_PATH:-}" && -f "$BACKUP_PATH" ]]; then
    cp "$BACKUP_PATH" "$DROPIN_FILE"
  else
    rm -f "$DROPIN_FILE"
  fi
}

fail_closed() {
  local reason="$1"
  restore_dropin
  systemctl --user daemon-reload || true
  echo "========================================"
  echo "HARDENING FAILED — FAIL CLOSED"
  echo "========================================"
  echo "unit          : ${UNIT}"
  echo "profile       : ${PROFILE}"
  echo "reason        : ${reason}"
  if [[ -n "${SMOKE_RESULT:-}" ]]; then
    echo "smoke result  : ${SMOKE_RESULT}"
  fi
  echo "rollback cmd  : ${ROLLBACK_CMD}"
  echo "========================================"
  exit 1
}

write_record_payload() {
  python3 - "$@" <<'PY'
import json
import sys

(
    target,
    unit_file,
    dropin_file,
    profile,
    profile_file,
    before_json,
    after_json,
    backup_path,
    rollback_cmd,
    unlock_cmd,
    lock_cmd,
    smoke_cmd,
    smoke_result,
    score_before,
    score_after,
    context_md,
    actor,
    out_path,
) = sys.argv[1:]
profile_body = open(profile_file, encoding="utf-8").read()
directives = {
    "profile": profile,
    "profile_file": profile_file,
    "profile_body": profile_body,
}
data = {
    "target": target,
    "unit_file": unit_file,
    "dropin_file": dropin_file,
    "profile": profile,
    "before_json": before_json,
    "after_json": after_json,
    "directives_json": json.dumps(directives),
    "backup_path": backup_path,
    "rollback_cmd": rollback_cmd,
    "unlock_cmd": unlock_cmd,
    "lock_cmd": lock_cmd,
    "smoke_cmd": smoke_cmd,
    "smoke_result": smoke_result,
    "security_score_before": score_before,
    "security_score_after": score_after,
    "context_md": context_md,
    "actor": actor,
}
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(data, fh)
PY
}

# ── argument parsing ───────────────────────────────────────────────────────

ACTION="${1:-}"
shift || true

UNIT=""
UNIT_SYSTEMD=""
PROFILE=""
SMOKE_CMD=""
CONTEXT_FILE=""
DRY_RUN=0
EXECUTE=0
INACCESSIBLE_PATHS=()
ALLOW_WRITE_PATHS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --unit)
      require_value "$1" "${2:-}"
      UNIT="$2"
      shift 2
      ;;
    --profile)
      require_value "$1" "${2:-}"
      PROFILE="$2"
      shift 2
      ;;
    --smoke)
      require_value "$1" "${2:-}"
      SMOKE_CMD="$2"
      shift 2
      ;;
    --context-file)
      require_value "$1" "${2:-}"
      CONTEXT_FILE="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --execute)
      EXECUTE=1
      shift
      ;;
    --allow-write)
      require_value "$1" "${2:-}"
      ALLOW_WRITE_PATHS+=("$2")
      shift 2
      ;;
    --inaccessible)
      require_value "$1" "${2:-}"
      INACCESSIBLE_PATHS+=("$2")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -n "$UNIT" ]]; then
  UNIT_SYSTEMD="${UNIT%.service}.service"
fi

# ── commands ───────────────────────────────────────────────────────────────

case "$ACTION" in

apply)
  [[ -z "$UNIT" ]] && { echo "FATAL: --unit required" >&2; exit 2; }
  [[ -z "$PROFILE" ]] && { echo "FATAL: --profile required" >&2; exit 2; }
  [[ -z "$SMOKE_CMD" ]] && { echo "FATAL: --smoke required" >&2; exit 2; }
  refuse_conflicting_flags

  PROFILE_FILE="${PROFILES_DIR}/${PROFILE}.conf"
  [[ ! -f "$PROFILE_FILE" ]] && { echo "FATAL: profile '${PROFILE}' not found" >&2; exit 2; }

  UNIT_FILE="$(probe systemctl --user show -p FragmentPath "$UNIT" || true)"
  UNIT_FILE="${UNIT_FILE#FragmentPath=}"

  BEFORE_JSON="$(props_json "$UNIT")"
  SCORE_BEFORE="$(security_score "$UNIT")"
  DROPIN_CONTENT="$(printf '[Service]\n%s' "$(build_dropin "$PROFILE")")"

  DROPIN_DIR="${DROPIN_BASE}/${UNIT_SYSTEMD}.d"
  DROPIN_FILE="${DROPIN_DIR}/90-hardening.conf"
  BACKUP_PATH=""

  CONTEXT_MD=""
  if [[ -n "$CONTEXT_FILE" && -f "$CONTEXT_FILE" ]]; then
    CONTEXT_MD="$(cat "$CONTEXT_FILE")"
  fi

  unit_q="$(printf '%q' "$UNIT")"
  ROLLBACK_CMD="bash ${HARDENING_DIR}/rollback.sh --unit ${unit_q} --execute"
  UNLOCK_CMD="bash ${HARDENING_DIR}/harden.sh unlock --unit ${unit_q} --execute"
  LOCK_CMD="bash ${HARDENING_DIR}/harden.sh lock --unit ${unit_q} --execute"

  if ! host_changes_allowed; then
    say_dry_run
    echo "--- drop-in that WOULD be written: ${DROPIN_FILE} ---"
    printf '%s\n' "$DROPIN_CONTENT"
    echo "--- BEFORE score: ${SCORE_BEFORE:-<no score>} ---"
    echo "--- smoke command: ${SMOKE_CMD} ---"
    echo "--- rollback command: ${ROLLBACK_CMD} ---"
    if [[ -f "$DROPIN_FILE" ]]; then
      echo "--- would back up existing drop-in under: ${BACKUPS_DIR} ---"
    fi
    echo "=== DRY RUN complete — nothing written, ledger NOT modified ==="
    exit 0
  fi

  if [[ -f "$DROPIN_FILE" ]]; then
    mkdir -p "$BACKUPS_DIR"
    BACKUP_PATH="${BACKUPS_DIR}/${UNIT}-$(date +%Y%m%d-%H%M%S).conf"
    cp "$DROPIN_FILE" "$BACKUP_PATH"
  fi

  mkdir -p "$DROPIN_DIR"
  printf '%s\n' "$DROPIN_CONTENT" >"$DROPIN_FILE"

  if ! systemctl --user daemon-reload; then
    fail_closed "daemon-reload failed"
  fi

  SMOKE_OUTPUT=""
  SMOKE_EXIT=0
  set +e
  # Operator-supplied check. It is stored as a command string and re-run as given.
  SMOKE_OUTPUT="$(eval "$SMOKE_CMD" 2>&1)"
  SMOKE_EXIT=$?
  set -e
  if [[ $SMOKE_EXIT -ne 0 ]]; then
    SMOKE_RESULT="FAILED (exit ${SMOKE_EXIT})
${SMOKE_OUTPUT}"
    fail_closed "smoke command failed"
  fi
  SMOKE_RESULT="OK (exit ${SMOKE_EXIT})
${SMOKE_OUTPUT}"

  SCORE_AFTER="$(security_score "$UNIT")"
  AFTER_JSON="$(props_json "$UNIT")"

  tmp_json="$(mktemp)"
  if ! write_record_payload \
    "$UNIT" "$UNIT_FILE" "$DROPIN_FILE" "$PROFILE" "$PROFILE_FILE" \
    "$BEFORE_JSON" "$AFTER_JSON" "$BACKUP_PATH" "$ROLLBACK_CMD" "$UNLOCK_CMD" "$LOCK_CMD" \
    "$SMOKE_CMD" "$SMOKE_RESULT" "$SCORE_BEFORE" "$SCORE_AFTER" \
    "$CONTEXT_MD" "$(script_host)" "$tmp_json"; then
    rm -f "$tmp_json"
    fail_closed "ledger record failed"
  fi
  if ! python3 "$LEDGER_PY" record-json "$tmp_json"; then
    rm -f "$tmp_json"
    fail_closed "ledger record failed"
  fi
  rm -f "$tmp_json"

  echo "========================================"
  echo "HARDENING APPLIED"
  echo "========================================"
  echo "unit          : ${UNIT}"
  echo "profile       : ${PROFILE}"
  echo "drop-in       : ${DROPIN_FILE}"
  echo "before score  : ${SCORE_BEFORE:-<none>}"
  echo "after score   : ${SCORE_AFTER:-<none>}"
  echo "smoke result  : ${SMOKE_RESULT}"
  echo "rollback cmd  : ${ROLLBACK_CMD}"
  echo "unlock cmd    : ${UNLOCK_CMD}"
  echo "========================================"
  ;;

show)
  [[ -z "$UNIT" ]] && { echo "FATAL: --unit required" >&2; exit 2; }
  DROPIN_FILE="${DROPIN_BASE}/${UNIT_SYSTEMD}.d/90-hardening.conf"
  if [[ -f "$DROPIN_FILE" ]]; then
    echo "--- drop-in: ${DROPIN_FILE} ---"
    cat "$DROPIN_FILE"
  else
    echo "[no hardening drop-in found for ${UNIT} at ${DROPIN_FILE}]"
  fi
  echo "--- ledger entry ---"
  python3 "$LEDGER_PY" show "$UNIT" 2>/dev/null || echo "[no ledger record for ${UNIT}]"
  ;;

unlock)
  [[ -z "$UNIT" ]] && { echo "FATAL: --unit required" >&2; exit 2; }
  refuse_conflicting_flags
  DROPIN_DIR="${DROPIN_BASE}/${UNIT_SYSTEMD}.d"
  UNLOCK_FILE="${DROPIN_DIR}/99-unlocked.conf"
  if ! host_changes_allowed; then
    say_dry_run
    echo "would write ${UNLOCK_FILE} and daemon-reload"
    exit 0
  fi
  mkdir -p "$DROPIN_DIR"
  cat >"$UNLOCK_FILE" <<'EOF'
# Temporary unlock — written by harden.sh unlock
# Overrides ALL hardening sandbox directives to relaxed/off values.
NoNewPrivileges=no
PrivateTmp=no
ProtectSystem=off
ProtectHome=off
ProtectKernelTunables=no
ProtectKernelModules=no
ProtectControlGroups=no
ProtectClock=no
ProtectHostname=no
RestrictSUIDSGID=no
RestrictNamespaces=no
RestrictRealtime=no
LockPersonality=no
MemoryDenyWriteExecute=no
RestrictAddressFamilies=
SystemCallArchitectures=
InaccessiblePaths=
ReadWritePaths=
EOF
  if ! systemctl --user daemon-reload; then
    rm -f "$UNLOCK_FILE"
    echo "UNLOCK FAILED — FAIL CLOSED (daemon-reload)"
    exit 1
  fi
  if ! python3 "$LEDGER_PY" event "$UNIT" "unlock" "temporary sandbox relaxation via ${UNLOCK_FILE}" "$(script_host)"; then
    rm -f "$UNLOCK_FILE"
    systemctl --user daemon-reload || true
    echo "UNLOCK FAILED — FAIL CLOSED (ledger)"
    exit 1
  fi
  echo "UNLOCKED: ${UNLOCK_FILE} written, daemon-reload done."
  echo "Re-lock with: bash ${HARDENING_DIR}/harden.sh lock --unit $(printf '%q' "$UNIT") --execute"
  ;;

lock)
  [[ -z "$UNIT" ]] && { echo "FATAL: --unit required" >&2; exit 2; }
  refuse_conflicting_flags
  UNLOCK_FILE="${DROPIN_BASE}/${UNIT_SYSTEMD}.d/99-unlocked.conf"
  if ! host_changes_allowed; then
    say_dry_run
    if [[ -f "$UNLOCK_FILE" ]]; then
      echo "would remove ${UNLOCK_FILE} and daemon-reload"
    else
      echo "[no unlock marker found at ${UNLOCK_FILE}]"
    fi
    exit 0
  fi
  if [[ ! -f "$UNLOCK_FILE" ]]; then
    echo "[no unlock marker found at ${UNLOCK_FILE}]"
    exit 0
  fi
  snapshot="$(mktemp)"
  cp "$UNLOCK_FILE" "$snapshot"
  rm -f "$UNLOCK_FILE"
  if ! systemctl --user daemon-reload; then
    mkdir -p "$(dirname "$UNLOCK_FILE")"
    cp "$snapshot" "$UNLOCK_FILE"
    rm -f "$snapshot"
    echo "LOCK FAILED — FAIL CLOSED (daemon-reload)"
    exit 1
  fi
  if ! python3 "$LEDGER_PY" event "$UNIT" "lock" "unlock marker removed, hardening re-applied" "$(script_host)"; then
    mkdir -p "$(dirname "$UNLOCK_FILE")"
    cp "$snapshot" "$UNLOCK_FILE"
    rm -f "$snapshot"
    systemctl --user daemon-reload || true
    echo "LOCK FAILED — FAIL CLOSED (ledger)"
    exit 1
  fi
  rm -f "$snapshot"
  echo "LOCKED: ${UNLOCK_FILE} removed, daemon-reload done."
  ;;

list)
  python3 "$LEDGER_PY" list
  ;;

*)
  usage >&2
  exit 2
  ;;
esac
