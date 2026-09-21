#!/usr/bin/env bash
# rollback.sh — reverse the most recent apply for a target systemd user unit.
#
# Frozen interface:
#   rollback.sh --unit <name>
#
# Uses the ledger's backup_path to restore the prior drop-in state, then
# daemon-reloads and logs the event.  Records nothing to the hardened table
# — the rollback IS the reversal of the record.
set -euo pipefail

HARDENING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LEDGER_PY="${HARDENING_DIR}/ledger.py"
DROPIN_BASE="${HOME}/.config/systemd/user"

hostname() { python3 -c 'import socket;print(socket.gethostname())'; }

UNIT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --unit) UNIT="$2"; shift 2 ;;
    -h|--help)
      echo "usage: rollback.sh --unit <name>"
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$UNIT" ]] && { echo "FATAL: --unit required" >&2; exit 2; }

# Look up the most recent record for this unit from the ledger
BACKUP_INFO="$(python3 -c "
import sys, json
sys.path.insert(0, '${HARDENING_DIR}')
import ledger as L
row = L.get('${UNIT}')
if row is None:
    print(json.dumps({'error': 'no ledger record for ${UNIT}'}))
else:
    print(json.dumps({'backup_path': row['backup_path'] or '', 'dropin_file': row['dropin_file'] or ''}))
" 2>/dev/null || echo '{"error":"ledger query failed"}')"

BACKUP_PATH="$(python3 -c "import json,sys; d=json.loads(sys.argv[1]); print(d.get('backup_path','') or '')" "$BACKUP_INFO" 2>/dev/null || true)"
DROPIN_FILE="$(python3 -c "import json,sys; d=json.loads(sys.argv[1]); print(d.get('dropin_file','') or '')" "$BACKUP_INFO" 2>/dev/null || true)"

if [[ "$BACKUP_INFO" == *'"error"'* && "$BACKUP_PATH" == "" ]]; then
  echo "FATAL: ${BACKUP_INFO}" >&2
  exit 1
fi

# Reverse the hardening:
#  - If we have a backup drop-in, restore it.
#  - If no backup exists (first apply), delete the drop-in.
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

systemctl --user daemon-reload

# Log the event
python3 "$LEDGER_PY" event "$UNIT" "rollback" \
  "reversed most recent apply; backup_path=${BACKUP_PATH:-none}" \
  "$(hostname)"

echo "========================================"
echo "ROLLBACK COMPLETE"
echo "========================================"
echo "unit          : ${UNIT}"
echo "drop-in       : ${DROPIN_FILE:-<none>}"
echo "backup        : ${BACKUP_PATH:-<was first apply>}"
echo "========================================"
