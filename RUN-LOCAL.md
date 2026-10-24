# Run PhishGuard on your laptop

Two options. **Option A** is one command and no extra software. **Option B** uses Docker.

---

## Option A — Python (recommended)

### 0. What you need
- **Python 3.9 or newer** — check with `python3 -V` (macOS/Linux) or `py -3 -V` (Windows).
  - macOS: `brew install python@3.12`, or download from <https://www.python.org/downloads/>
  - Windows: installer from python.org — **tick “Add python.exe to PATH”** during setup
  - Ubuntu/Debian: `sudo apt install python3 python3-venv`
- An internet connection the first time (to install 5 packages) and for domain-age/DNS lookups.
- No API keys needed. Safe Browsing / VirusTotal are optional.

### 1. Get the folder onto your laptop
Download **`phishguard-0.9.0.zip`** from the workspace and unzip it. You should see:

```
phishguard/
├── run.sh          ← macOS / Linux launcher
├── run.bat         ← Windows launcher
├── frontend/
│   ├── templates/index.html
│   └── static/     ← app.js and style.css
├── backend/
│   ├── app.py
│   ├── engine/  samples/  tests/  scripts/  data/
│   └── requirements.txt
└── Dockerfile / docker-compose.yml
```

The root launchers start the backend and serve the frontend together at the same
URL. No JavaScript build step is required. Run the commands below from the project
root, which contains `run.sh` and `run.bat`.

### 2. Start it

**macOS / Linux**
```bash
cd phishguard
./run.sh
```

If you see `permission denied` (some archive tools drop the executable bit):

```bash
chmod +x run.sh     # fix it once
# or skip the fix entirely:
bash run.sh
```

**Windows** — double-click `run.bat` (if SmartScreen warns, choose *More info → Run anyway* — it's a plain batch file you can read in Notepad), or in PowerShell:
```powershell
cd phishguard
.\run.bat
```
If PowerShell blocks it: `powershell -ExecutionPolicy Bypass -File .\run.bat`

### 3. Open it
```
http://localhost:8000
```

The launcher prints a banner with the URL. Stop the server with **Ctrl+C**.

### What the launcher does (and why it's safe)
1. Finds Python 3.9+ (`python3`, then `python`).
2. Creates an isolated `.venv` — **your system Python is never modified**.
3. Installs the 5 pinned dependencies into that venv.
4. Seeds demo data (a vendor bank baseline + report clusters) **only if no database exists**.
5. Runs the 45-test engine suite and **refuses to start if it fails**.
6. Serves the app on `localhost:8000`.

Later runs skip steps 2–4 and start in about a second.

### Useful flags
```bash
./run.sh --port 8080     # different port
./run.sh --no-test       # skip the test suite
```

---

## Option B — Docker

Only needs Docker Desktop (or Engine). Gives you the same `http://localhost:8000`.

```bash
cd phishguard
docker compose up -d --build     # or: docker build -t phishguard . && docker run -d -p 8000:8000 -v phishguard-data:/app/data phishguard
# open http://localhost:8000
docker compose logs -f           # watch the log
docker compose down              # stop
```

Data persists in the `phishguard-data` volume. Full Docker notes (healthcheck, env keys,
troubleshooting table) are in `README.md` → *Deploy with Docker*.

---

## First 60 seconds once it's open

1. **Check a link** → click the `bank lookalike` chip. You get an instant verdict
   (~5 ms), then the five-stage pipeline fills in as registration, DNS, TLS, reputation
   and the click preview arrive.
2. **Check an email** → *Samples → BEC bank-change*. Look for the critical signal
   **“Bank details CHANGED vs this vendor's previous invoice — 50…7561, previously 40…4932.”**
3. **Org sweep** → the ₹ value-protected tiles and campaign clusters.
4. Toggle light mode at the bottom of the sidebar. `/` focuses the URL box from anywhere.

---

## Troubleshooting

| What you see | Why | Fix |
|---|---|---|
| `command not found: python3` / `'python' is not recognized` | Python not installed or not on PATH | install Python 3.9+; on Windows re-run the installer and tick **Add to PATH** |
| `could not create a virtualenv` | missing venv module (Debian/Ubuntu) | `sudo apt install python3-venv` |
| `Address already in use` / `[Errno 98]` | something is already on port 8000 | `./run.sh --port 8080` → `http://localhost:8080` |
| `permission denied: ./run.sh` | archive tool dropped the exec bit | `chmod +x run.sh`, or just run `bash run.sh` |
| macOS: `No module named pyexpat` / broken openssl | system Python quirk | use `brew install python@3.12` instead of the system Python |
| Domain age / DNS / TLS show `unknown` or `degraded` | no outbound network, VPN, or corporate proxy blocking RDAP | the app deliberately degrades to lexical-only and **labels** it — not a silent green tick. Try `curl https://rdap.org/domain/google.com` to confirm |
| Corporate TLS interception → `SSLError` | proxy's root CA isn't trusted by Python | set `REQUESTS_CA_BUNDLE=/path/to/your-ca-bundle.pem` (or `SSL_CERT_FILE`) before running |
| Tests fail on start | something changed in the engine | the launcher stops rather than serving a broken build — run `python -m pytest backend/tests/ -q -x` from the project root to see which assertion |
| Antivirus flags the preview fetch | the app deliberately requests suspicious URLs server-side | expected behaviour — it never executes JS or submits forms; whitelist the folder or run in Docker |

---

## Where things are stored

| Path | What | Safe to delete? |
|---|---|---|
| `backend/data/phishguard.db` | vendor bank baselines, first-contact domains, URL snapshots, report clusters, verdict receipts (SQLite) | yes — it's re-seeded on next start |
| `.venv/` | the isolated Python environment | yes — rebuilt by the launcher |
| `backend/samples/*.eml` | the four demo messages | yes |

Nothing is sent anywhere except outbound RDAP/DNS/TLS lookups and — if you add keys —
Safe Browsing / VirusTotal. Emails you analyse are parsed in memory; only hashes and
counters are stored.

---

## Before you point it at real mail

This is a working prototype, not a hardened service:

- **No login.** Bind it to localhost only (the default) — don't port-forward it or expose it to the LAN.
- **Dev server by default.** `run.sh` uses Flask's development server; use the Docker image (gunicorn) for anything shared.
- **Preview fetcher runs on your machine.** It's SSRF-guarded (private/loopback/metadata addresses refused) but for real deployments put it in an isolated egress-only container.
- **Retention.** Receipts contain email subjects and headers — add a retention job before processing other people's mail.
- **Calibrate before trusting.** Run it against your own legitimate mail first and watch the false-positive rate; extend `LEGIT_DOMAINS` in `backend/engine/data.py` for any internal systems it flags.
