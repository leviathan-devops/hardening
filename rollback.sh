#!/usr/bin/env bash
# rollback.sh — reverse the most recent apply for a target systemd user unit.
#
#   rollback.sh --unit <name> [--execute | --dry-run]
#
# Dry-run is the default. --execute restores the ledger backup (or deletes the
# drop-in when that apply was the first one), daemon-reloads, and logs the
# event. A failed reload or ledger write puts the drop-in back.
set -euo pipefail

HARDENING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LEDGER_PY="${HARDENING_DIR}/ledger.py"
DROPIN_BASE="${HOME}/.config/systemd/user"

usage() {
  cat <<'EOF'
usage: rollback.sh --unit <name> [--execute | --dry-run]

Host changes dry-run unless --execute is given. --dry-run and --execute cannot be combined.
EOF
}

script_host() { python3 -c 'import socket; print(socket.gethostname())'; }

require_value() {
  local flag="$1"
  if [[ $# -lt 2 || -z "${2:-}" ]]; then
    echo "FATAL: ${flag} requires a value" >&2
    exit 2
  fi
}

UNIT=""
DRY_RUN=0
EXECUTE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --unit)
      require_value "$1" "${2:-}"
      UNIT="$2"
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

[[ -z "$UNIT" ]] && { echo "FATAL: --unit required" >&2; exit 2; }

if [[ "$DRY_RUN" -eq 1 && "$EXECUTE" -eq 1 ]]; then
  echo "FATAL: --dry-run and --execute cannot be combined" >&2
  exit 2
fi

if ! BACKUP_INFO="$(python3 "$LEDGER_PY" get-json "$UNIT")"; then
  exit 1
fi

BACKUP_PATH="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("backup_path") or "")' <<<"$BACKUP_INFO")"
DROPIN_FILE="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("dropin_file") or "")' <<<"$BACKUP_INFO")"

UNIT_SYSTEMD="${UNIT%.service}.service"
if [[ -z "$DROPIN_FILE" ]]; then
  DROPIN_FILE="${DROPIN_BASE}/${UNIT_SYSTEMD}.d/90-hardening.conf"
fi

describe_rollback() {
  if [[ -n "$BACKUP_PATH" && -f "$BACKUP_PATH" ]]; then
    echo "would restore ${BACKUP_PATH} → ${DROPIN_FILE}"
  elif [[ -n "$DROPIN_FILE" && -f "$DROPIN_FILE" ]]; then
    echo "would remove ${DROPIN_FILE} (no backup — first apply)"
  else
    echo "would find no drop-in to reverse for ${UNIT}"
  fi
}

if [[ "$EXECUTE" -ne 1 || "$DRY_RUN" -eq 1 ]]; then
  echo "=== DRY RUN — refusing host changes without --execute ==="
  describe_rollback
  exit 0
fi

snapshot=""
had_file=0
if [[ -n "$DROPIN_FILE" && -f "$DROPIN_FILE" ]]; then
  had_file=1
  snapshot="$(mktemp)"
  cp "$DROPIN_FILE" "$snapshot"
fi

undo_rollback() {
  if [[ "$had_file" -eq 1 ]]; then
    mkdir -p "$(dirname "$DROPIN_FILE")"
    cp "$snapshot" "$DROPIN_FILE"
  elif [[ -n "$DROPIN_FILE" ]]; then
    rm -f "$DROPIN_FILE"
  fi
}

if [[ -n "$BACKUP_PATH" && -f "$BACKUP_PATH" ]]; then
  mkdir -p "$(dirname "$DROPIN_FILE")"
  cp "$BACKUP_PATH" "$DROPIN_FILE"
  echo "rollback: restored ${BACKUP_PATH} → ${DROPIN_FILE}"
elif [[ -n "$DROPIN_FILE" && -f "$DROPIN_FILE" ]]; then
  rm -f "$DROPIN_FILE"
  echo "rollback: removed ${DROPIN_FILE} (no backup — first apply)"
else
  echo "rollback: no drop-in to reverse for ${UNIT}"
fi

if ! systemctl --user daemon-reload; then
  undo_rollback
  rm -f "$snapshot"
  echo "ROLLBACK FAILED — FAIL CLOSED (daemon-reload)"
  exit 1
fi

if ! python3 "$LEDGER_PY" event "$UNIT" "rollback" \
  "reversed most recent apply; backup_path=${BACKUP_PATH:-none}" \
  "$(script_host)"; then
  undo_rollback
  systemctl --user daemon-reload || true
  rm -f "$snapshot"
  echo "ROLLBACK FAILED — FAIL CLOSED (ledger)"
  exit 1
fi
rm -f "$snapshot"

echo "========================================"
echo "ROLLBACK COMPLETE"
echo "========================================"
echo "unit          : ${UNIT}"
echo "drop-in       : ${DROPIN_FILE:-<none>}"
echo "backup        : ${BACKUP_PATH:-<was first apply>}"
echo "========================================"
