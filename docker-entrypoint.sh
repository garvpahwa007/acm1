#!/bin/sh
# PhishGuard container entrypoint.
# Job: make sure the data dir is writable by the unprivileged user, seed demo
# state on first run, then hand over to gunicorn.
set -eu

DATA_DIR="${PHISHGUARD_DATA_DIR:-/app/data}"
DB="${PHISHGUARD_DB:-$DATA_DIR/phishguard.db}"

log() { printf '[entrypoint] %s\n' "$*" >&2; }

# A bind mount from the host is often owned by root. Rather than failing with a
# confusing sqlite "unable to open database file", fall back to an ephemeral dir
# and say so loudly.
if ! mkdir -p "$DATA_DIR" 2>/dev/null || [ ! -w "$DATA_DIR" ]; then
  log "WARNING: $DATA_DIR is not writable by uid $(id -u)."
  log "WARNING: falling back to /tmp/phishguard-data — baselines/clusters will"
  log "WARNING: be lost on restart. Fix with: chown -R 10001:10001 <host dir>"
  DATA_DIR=/tmp/phishguard-data
  DB="$DATA_DIR/phishguard.db"
  mkdir -p "$DATA_DIR"
fi

export PHISHGUARD_DB="$DB"
export PHISHGUARD_DATA_DIR="$DATA_DIR"

if [ ! -f "$DB" ]; then
  log "no database at $DB — seeding demo baselines and clusters"
  python3 scripts/seed_demo.py || log "seed skipped (continuing with an empty store)"
else
  log "using existing database $DB"
fi

if [ -n "${GSB_API_KEY:-}${VT_API_KEY:-}" ]; then
  log "reputation keys detected"
else
  log "no reputation keys — running with BYO-key mode (fully functional)"
fi

log "starting gunicorn on 0.0.0.0:${PORT:-8000}"
exec "$@"
