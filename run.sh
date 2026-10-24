#!/usr/bin/env bash
# PhishGuard — one-command local run for macOS / Linux.
#   ./run.sh            normal start
#   ./run.sh --no-test  skip the test suite
#   ./run.sh --port 8080
set -euo pipefail
cd "$(dirname "$0")"

PORT=8000
RUN_TESTS=1
while [ $# -gt 0 ]; do
  case "$1" in
    --no-test) RUN_TESTS=0 ;;
    --port) shift; PORT="${1:-8000}" ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) echo "unknown option: $1"; exit 2 ;;
  esac
  shift
done

# 1. find a usable interpreter (python3 first, then python)
PY=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1 && \
     "$cand" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,9) else 1)' 2>/dev/null; then
    PY="$cand"; break
  fi
done
if [ -z "$PY" ]; then
  echo "ERROR: Python 3.9+ not found."
  echo "  macOS:  brew install python@3.12   (or python.org/downloads)"
  echo "  Debian: sudo apt install python3 python3-venv"
  exit 1
fi
echo "→ using $("$PY" -V 2>&1)"

# 2. virtual environment (isolated; never touches system Python)
if [ ! -d .venv ]; then
  echo "→ creating .venv"
  "$PY" -m venv .venv || {
    echo "ERROR: could not create a virtualenv."
    echo "  Debian/Ubuntu: sudo apt install python3-venv"
    exit 1
  }
fi
# shellcheck disable=SC1091
. .venv/bin/activate

# 3. dependencies
echo "→ installing dependencies (first run only, ~30s)"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r backend/requirements.txt
[ "$RUN_TESTS" = "1" ] && python -m pip install --quiet pytest

cd backend

# 4. demo state: vendor bank baselines + report clusters (first run only)
if [ ! -f data/phishguard.db ]; then
  echo "→ seeding demo baselines"
  python scripts/seed_demo.py
fi

# 5. prove the engine works before serving it
if [ "$RUN_TESTS" = "1" ]; then
  echo "→ running engine tests"
  python -m pytest tests/ -q || { echo "TESTS FAILED — not starting."; exit 1; }
fi

echo
echo "════════════════════════════════════════════════════"
echo "  PhishGuard running →  http://localhost:$PORT"
echo "  Stop with Ctrl+C"
echo "════════════════════════════════════════════════════"
echo
PORT="$PORT" exec python app.py
