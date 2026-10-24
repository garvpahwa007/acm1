# acm1 — PhishGuard

The dashboard from [Anshurawat-tech/acm1](https://github.com/Anshurawat-tech/acm1)
connected to the full PhishGuard Flask engine. Frontend and backend sources are
separate; the detection engine is unchanged.

## Run locally

Python 3.9+ is required. From this repository's root:

```bash
./run.sh                 # macOS / Linux
# Windows: run.bat
```

Open http://localhost:8000 for the dashboard, or http://localhost:8000/advanced
for the complete original interface, including campaign reports, receipts,
vendor account confirmation, coverage, and dark/light themes.

Manual setup:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
python3 backend/scripts/seed_demo.py
python3 backend/app.py
```

The HTML uses Flask templates: start the backend instead of opening the HTML
directly or serving it with GitHub Pages. Both interfaces use the same-origin API.
No npm install or JavaScript build is needed.

## Structure

```text
frontend/
  templates/index.html      dashboard adapted from acm1
  templates/advanced.html   original PhishGuard interface
  static/app.js             dashboard API integration and rendering
  static/style.css          acm1 dashboard styling
  static/engine.js          original PhishGuard browser code
  static/engine.css         original PhishGuard styling
backend/
  app.py                    Flask routes and both interface entry points
  engine/                   unchanged detection/scoring/persistence code
  requirements.txt          original Python runtime dependencies
  samples/                  original demo messages
  scripts/seed_demo.py       demo baselines and reports
  tests/                    engine and integration regression tests
  data/                     local SQLite state (excluded from Git)
```

## Scanning behavior

The dashboard requests an initial lexical URL verdict, then a full scan with
registration, DNS, TLS, optional reputation checks and a guarded preview.
Email uploads support raw `.eml` and `.txt` content. Browser demo scoring has
been replaced by engine requests; an unavailable engine produces an error.
If full URL verification fails, the initial verdict remains explicitly marked
as a lexical check. Unknown verdicts and confidence are preserved.

Safe Browsing and VirusTotal keys are optional. See `.env.example`; export keys
in your shell or use Docker Compose's `.env` support. The server does not load
`.env` files automatically when launched directly. No keys belong in frontend files.
The engine stores SQLite receipts and baselines; URL checks make outbound
network requests. Scan history is also saved in the browser until cleared.

## Tests

```bash
pip install pytest
python3 backend/scripts/seed_demo.py   # required before the original engine suite
python3 -m pytest backend/tests/ -q
```

## Docker

```bash
docker compose up -d --build
```

Both interfaces are served on port 8000. The named volume preserves engine data.
See [RUN-LOCAL.md](RUN-LOCAL.md) and [engine guide](docs/engine-guide.md)
for setup, configuration and existing engine limitations. Docker and Windows
launchers are included; local validation was performed on macOS with Python.

## Source provenance

- Dashboard HTML, CSS and interface rendering: Anshurawat-tech/acm1 at commit
  `3263ad1fa3b385b1b3f3f697ede78da12612acb9`, with styles and scripts extracted
  into separate files and scanning connected to Flask.
- Backend, samples, original interface and engine tests: the supplied PhishGuard
  project, reorganized into frontend/backend folders.
- The upstream FastAPI heuristic backend is superseded by the supplied Flask
  engine. Its original README is retained in `docs/upstream-frontend.md` for reference.
