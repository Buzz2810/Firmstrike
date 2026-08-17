<div align="center">

# 🛡️ FirmStrike

### AI-Powered IoT Firmware Security Analysis Platform

*Upload. Scan. Detect. Report.*

</div>

---

## 📖 Table of Contents

- [About](#-about)
- [Project Structure](#-project-structure)
- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Getting Started](#-getting-started)
  - [1. Clone and install Node dependencies](#1-clone-and-install-node-dependencies)
  - [2. Configure environment variables](#2-configure-environment-variables)
  - [3. Set up PostgreSQL](#3-set-up-postgresql)
  - [4. Set up the Python scanner](#4-set-up-the-python-scanner)
  - [5. Run everything](#5-run-everything)
- [Windows-Specific Notes](#-windows-specific-notes)
- [Available Scripts](#-available-scripts)
- [Troubleshooting](#-troubleshooting)
- [Known Limitations](#-known-limitations)
- [License](#-license)

---

## 🧭 About

**FirmStrike** is a full-stack security platform for analyzing IoT/embedded firmware images. Upload a firmware file and it will:

1. Detect the firmware format and CPU architecture
2. Extract the embedded filesystem (SquashFS, TRX, ZIP, TAR, GZIP, etc.)
3. Statically scan every extracted file — including compiled binaries — for hardcoded secrets and dangerous function calls (`system()`, `popen()`, `strcpy()`, ...)
4. Match detected components (BusyBox, Dropbear, OpenSSL, uhttpd, ...) against known CVEs
5. Hash and heuristically/VirusTotal-check extracted binaries for malware indicators
6. Generate an AI-written executive summary, a downloadable PDF report, and an SBOM (CycloneDX/SPDX)

The scanning pipeline is a **Python service** (`python-scanner/`) that does the heavy lifting — extraction, static analysis, hashing — and a **Node.js/Express backend** (`backend/`) that orchestrates scans, stores results in PostgreSQL, and serves the API the **React frontend** (`frontend/`) talks to.

---

## 📂 Project Structure

```
Firmstrike/
├── backend/                    # Express API server
│   └── src/
│       ├── routes/             # security.ts, cve.ts, malware.ts, scanner.ts, dashboard.ts, ...
│       └── services/           # python-scanner.ts, malware-analyzer.ts, gemini.ts, scan-pipeline.ts, ...
│
├── frontend/                   # React + Vite SPA
│   └── src/
│
├── python-scanner/              # FastAPI service that does the actual firmware analysis
│   ├── app.py                   # FastAPI entrypoint
│   ├── scanner.py                # Extraction + static analysis logic (the core engine)
│   ├── requirements.txt
│   └── .venv/                    # Python virtual environment (created locally, not committed)
│
├── lib/                          # (if present) shared packages: api-spec, api-client-react, db
├── package.json                  # pnpm workspace root
├── pnpm-workspace.yaml
└── README.md
```

---

## 🏗️ Architecture

```
┌──────────────────┐   HTTP /api/*   ┌───────────────────┐   HTTP :8010   ┌────────────────────┐
│ frontend (React)  │ ──────────────▶ │ backend (Express)  │ ─────────────▶ │ python-scanner       │
│ localhost:25439   │                  │ localhost:8080      │                 │ (FastAPI, uvicorn)   │
└──────────────────┘                  └──────────┬─────────┘                 │ localhost:8010        │
                                                    │                          └────────────────────┘
                                                    ▼
                                          ┌───────────────────┐
                                          │ PostgreSQL           │
                                          └───────────────────┘
```

The backend calls the Python scanner over HTTP (`PYTHON_SCANNER_URL`, default `http://127.0.0.1:8010`). If that service isn't reachable, it falls back to spawning `python3 scanner.py` directly as a subprocess — but **running the persistent FastAPI service is the supported path** and is what these instructions set up.

---

## ✅ Prerequisites

- **Node.js 24+**
- **pnpm** — this workspace is pnpm-only (`npm install` is actively blocked by a `preinstall` script)
- **Python 3.10+**
- A running **PostgreSQL** instance
- (Optional but recommended) A **Gemini API key** for AI report generation, and a **VirusTotal API key** for real malware hash lookups — the app degrades gracefully without them (heuristic-only malware scoring, no AI summary)

---

## 🚀 Getting Started

### 1. Clone and install Node dependencies

```bash
git clone <your-repo-url>
cd Firmstrike
pnpm install
```

### 2. Configure environment variables

Create `backend/.env`:

```env
# API server
PORT=8080
DATABASE_URL=postgres://user:password@localhost:5432/firmstrike
SESSION_SECRET=some-long-random-string
NODE_ENV=development

# AI report generation (optional — omit to disable AI summaries)
GEMINI_MODEL=gemini-2.5-flash
GEMINI_API_KEY=your-gemini-key

# Malware hash lookups (optional — omit to fall back to local heuristics only)
VIRUSTOTAL_API_KEY=your-virustotal-key

# Python scanner service
PYTHON_SCANNER_URL=http://127.0.0.1:8010
```

Create `frontend/.env`:

```env
VITE_PORT=25439
BASE_PATH=/
```

### 3. Set up PostgreSQL

Point `DATABASE_URL` at a running Postgres instance, then push the schema:

```bash
pnpm --filter @workspace/db run push
```

(If your workspace doesn't have a separate `db` package, check whichever package owns the Drizzle schema and run its migration/push script instead.)

### 4. Set up the Python scanner

This is the part most likely to trip people up, so follow it closely — every step here exists because of a real issue we hit getting this running.

```bash
cd python-scanner
python -m venv .venv
```

Activate the venv:

```bash
# macOS / Linux
source .venv/bin/activate

# Windows (Git Bash)
source .venv/Scripts/activate

# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Windows (cmd.exe)
.venv\Scripts\activate.bat
```

Then install dependencies:

```bash
pip install -r requirements.txt
```

`requirements.txt` includes:
- `fastapi`, `uvicorn`, `python-multipart` — the scanner's HTTP service
- `binwalk3` — firmware signature detection & extraction (bundles a Rust binwalk v3 binary, including a Windows x64 build, so no separate CLI install is needed)
- `PySquashfsImage` — pure-Python SquashFS extraction, used because binwalk's usual extractor (`sasquatch`) has no Windows build

**If you're on Windows, also enable Developer Mode** — see [Windows-Specific Notes](#-windows-specific-notes) below. Without it, extraction will fail with a symlink permission error.

### 5. Run everything

You need **three** processes running simultaneously, each in its own terminal:

```bash
# Terminal 1 — Python scanner (http://localhost:8010)
cd python-scanner
source .venv/Scripts/activate   # or the activation command for your shell/OS
python -m uvicorn app:app --host 127.0.0.1 --port 8010
```

```bash
# Terminal 2 — Backend API (http://localhost:8080)
pnpm --filter @workspace/backend run dev
```

```bash
# Terminal 3 — Frontend (http://localhost:25439)
pnpm --filter @workspace/frontend run dev
```

Then open **http://localhost:25439** and upload a firmware image.

---

## 🪟 Windows-Specific Notes

Firmware extraction unpacks real Linux filesystems, which use symlinks — and Windows blocks non-elevated processes from creating them by default. Without this step, extraction will fail with an error like:

```
Failed to create symlink ...: A required privilege is not held by the client. (os error 1314)
```

**Fix — enable Developer Mode (no admin/reboot required):**

1. **Settings** → **Privacy & security** → **For developers** (older Windows 10: **Update & Security** → **For developers**)
2. Turn on **Developer Mode**
3. Close and reopen your terminal

If your venv gets moved/copied between folders after creation (e.g. you renamed the project directory), **recreate it** rather than trying to reuse it — pip's internals hardcode absolute paths and break silently otherwise:

```bash
rm -rf .venv
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
```

---

## 📜 Available Scripts

| Command | Description |
|---|---|
| `pnpm install` | Install all Node workspace dependencies |
| `pnpm run typecheck` | Typecheck every package in the workspace |
| `pnpm run build` | Typecheck, then build all packages |
| `pnpm --filter @workspace/backend run dev` | Build + start the Express API server |
| `pnpm --filter @workspace/frontend run dev` | Start the Vite dev server |
| `python -m uvicorn app:app --port 8010` (from `python-scanner/`, venv active) | Start the Python scanner service |

---

## 🧯 Troubleshooting

**Scan completes but shows "No secrets detected" / "No dangerous functions detected" / only 1-2 files extracted**
Check the backend terminal output for `Binwalk available: false`. This means the persistent scanner service on port 8010 isn't running (or isn't the one you think it is) — the backend silently fell back to a different Python environment. Find and stop whatever's using port 8010, then start `uvicorn` from the correct activated venv:

```bash
# find what's using the port
netstat -ano | findstr :8010        # Windows
lsof -i :8010                        # macOS/Linux

# stop it, then restart uvicorn from python-scanner/ with the venv active
```

**`ModuleNotFoundError: No module named 'pip._internal.operations.build'`**
Your venv was created in one location and the project folder was later moved/renamed. Delete and recreate `.venv` (see [Windows-Specific Notes](#-windows-specific-notes)).

**`binwalk3 (python) found 0 signature(s)`, no errors, on a firmware you know isn't empty**
Confirm `signature=True` and `matryoshka=False` are set in `try_binwalk()`'s call to `binwalk3.scan(...)` inside `scanner.py`. `matryoshka=True` can cause `binwalk3`'s JSON output parser to choke on multi-document output and silently return zero results.

**Malware panel shows very few, repetitive-looking results**
BusyBox is a "multi-call binary" — dozens of filenames (`ash`, `cat`, `chmod`, `cp`, ...) are hardlinks to the exact same file content. The malware scanner dedupes by SHA-256 before sampling files to check, specifically to avoid this — if you're still seeing this, make sure `backend/src/services/malware-analyzer.ts` has the dedup-by-hash logic and isn't just taking the first N files in filesystem order.

**Security score always shows `0`**
Real firmware routinely has 50-100+ legitimate hardcoded-secret/dangerous-function hits in normal embedded Linux userspace. If the scoring formula in `backend/src/routes/security.ts` uses flat linear penalties per finding, the total blows past 100 almost immediately and floors at `0` for any moderately bad firmware, losing all differentiation. The formula should use diminishing-returns (sqrt) scaling with per-category caps that sum to ≤100.

---

## ⚠️ Known Limitations

- No automated test suite yet.
- Malware detection falls back to local heuristics (suspicious string matching + entropy) when `VIRUSTOTAL_API_KEY` isn't set.
- AI executive summaries are skipped when `GEMINI_API_KEY` isn't set.

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for details.

---

<div align="center">

Made with ☕ and a healthy paranoia about firmware.

</div>