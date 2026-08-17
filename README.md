::: {align="center"}
# 🛡️ FirmStrike

### AI-Powered IoT Firmware Security Analysis Platform

**Upload · Extract · Analyze · Detect · Score · Report**

```{=html}
<p>
```
`<img src="https://img.shields.io/badge/IoT-Security-0f172a?style=for-the-badge&logo=linux&logoColor=white" alt="IoT Security">`{=html}
`<img src="https://img.shields.io/badge/Firmware-Analysis-1e293b?style=for-the-badge" alt="Firmware Analysis">`{=html}
`<img src="https://img.shields.io/badge/AI-Gemini-4285F4?style=for-the-badge&logo=google&logoColor=white" alt="Gemini">`{=html}
`<img src="https://img.shields.io/badge/Backend-Node.js-339933?style=for-the-badge&logo=node.js&logoColor=white" alt="Node.js">`{=html}
`<img src="https://img.shields.io/badge/Scanner-Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">`{=html}
`<img src="https://img.shields.io/badge/Frontend-React-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React">`{=html}
```{=html}
</p>
```
```{=html}
<p>
```
`<b>`{=html}Analyze embedded firmware for vulnerabilities, secrets,
dangerous functions, CVEs, malware indicators, and overall security
risk.`</b>`{=html}
```{=html}
</p>
```
:::

------------------------------------------------------------------------

## ✨ What is FirmStrike?

**FirmStrike** is a full-stack security platform designed to analyze IoT
and embedded-device firmware.

A firmware image can contain Linux filesystems, binaries, credentials,
certificates, libraries, network services, and vulnerable third-party
components. FirmStrike automates the first layer of this investigation
so a security analyst can move from **firmware image → technical
findings → risk assessment → security report** in one workflow.

### 🔍 What FirmStrike can do

  -----------------------------------------------------------------------
  Capability                          What it does
  ----------------------------------- -----------------------------------
  📦 **Firmware Extraction**          Detects and extracts supported
                                      embedded filesystem/container
                                      formats

  🧬 **Architecture Detection**       Identifies CPU/firmware
                                      architecture information

  🔐 **Secret Detection**             Searches extracted files for
                                      hardcoded credentials, keys,
                                      certificates, and other sensitive
                                      material

  ⚠️ **Dangerous Function Analysis**  Detects risky functions such as
                                      `system()`, `popen()`, `strcpy()`,
                                      and related APIs

  🧩 **Component Detection**          Identifies components such as
                                      BusyBox, Dropbear, OpenSSL, uhttpd,
                                      etc.

  🛡️ **CVE Intelligence**             Matches detected
                                      components/versions against known
                                      CVEs

  🦠 **Malware Analysis**             Hashes binaries and performs
                                      heuristic/VirusTotal-based malware
                                      checks

  📊 **Risk Scoring**                 Combines security findings into an
                                      overall risk assessment

  🤖 **AI Security Report**           Uses Gemini to generate an
                                      executive-level security assessment

  🧯 **AI Fallback**                  Generates a local report when
                                      Gemini is unavailable

  📄 **PDF Reporting**                Produces downloadable security
                                      reports

  📦 **SBOM**                         Generates
                                      software-bill-of-materials output
                                      in supported formats
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## 🧠 How the Scan Works

``` text
                         ┌──────────────────────┐
                         │   Firmware Image     │
                         │ .img / .bin / etc.   │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │ React Frontend       │
                         │ Upload + Dashboard   │
                         └──────────┬───────────┘
                                    │ HTTP /api/*
                                    ▼
                         ┌──────────────────────┐
                         │ Node.js Backend      │
                         │ Scan Orchestrator    │
                         └──────────┬───────────┘
                                    │ HTTP :8010
                                    ▼
                         ┌──────────────────────┐
                         │ Python FastAPI       │
                         │ Firmware Scanner     │
                         └──────────┬───────────┘
                                    │
                    ┌───────────────┼────────────────┐
                    ▼               ▼                ▼
              📦 Extraction   🔐 Static Scan    🧬 Identification
                    │               │                │
                    └───────────────┼────────────────┘
                                    ▼
                         ┌──────────────────────┐
                         │ Backend Analysis     │
                         ├──────────────────────┤
                         │ CVE Intelligence     │
                         │ Malware Analysis     │
                         │ Risk Scoring         │
                         │ AI Report             │
                         └──────────┬───────────┘
                                    ▼
                         ┌──────────────────────┐
                         │ PostgreSQL           │
                         │ Scan Results          │
                         └──────────┬───────────┘
                                    ▼
                         ┌──────────────────────┐
                         │ Security Dashboard   │
                         │ PDF + SBOM + Findings│
                         └──────────────────────┘
```

### 🔄 Analysis pipeline

**1. Upload** → Firmware is stored and associated with a scan.

**2. Extract** → The Python scanner identifies supported firmware
structures and extracts embedded filesystems.

**3. Inspect** → Extracted files and binaries are analyzed for
architecture, components, secrets, and dangerous functions.

**4. Correlate** → Detected software/components are correlated with
known CVE information.

**5. Analyze malware** → Binary hashes are checked using local
heuristics and, when configured, VirusTotal.

**6. Score risk** → Security findings are combined into an overall risk
assessment.

**7. Generate report** → Gemini can produce an executive security
assessment; a deterministic local fallback is used if AI generation is
unavailable.

**8. Present results** → The React dashboard exposes scan results,
findings, CVEs, malware information, and reports.

------------------------------------------------------------------------

## 🏗️ Architecture

``` text
┌─────────────────────┐
│   React + Vite      │
│   Frontend          │
│   :25439            │
└──────────┬──────────┘
           │ REST API
           ▼
┌─────────────────────┐
│   Node.js Backend   │
│   Express           │
│   :8080             │
└───────┬───────┬─────┘
        │       │
        │       ├──────────────► PostgreSQL
        │
        │ HTTP :8010
        ▼
┌─────────────────────┐
│ Python FastAPI      │
│ Firmware Scanner    │
│ :8010               │
└─────────────────────┘
```

The backend is the orchestration layer. It communicates with the
persistent Python scanner service through `PYTHON_SCANNER_URL` (default:
`http://127.0.0.1:8010`). A subprocess fallback exists, but the
persistent FastAPI scanner is the supported development path.

------------------------------------------------------------------------

## 📂 Project Structure

``` text
Firmstrike/
│
├── backend/                       # Node.js / Express API
│   ├── src/
│   │   ├── routes/                # API routes
│   │   └── services/              # Scan, CVE, malware, AI, etc.
│   └── ...
│
├── frontend/                      # React + Vite SPA
│   ├── src/
│   └── ...
│
├── python-scanner/                # FastAPI firmware analysis service
│   ├── app.py                     # FastAPI entrypoint
│   ├── scanner.py                 # Core extraction + analysis engine
│   ├── requirements.txt
│   └── .venv/                     # Local virtual environment
│
├── package.json                   # pnpm workspace root
├── pnpm-workspace.yaml
└── README.md
```

> **Note:** `.venv/`, uploaded firmware, generated extraction
> directories, secrets, and environment files should not be committed to
> Git.

------------------------------------------------------------------------

## 🧰 Technology Stack

  Layer                           Technology
  ------------------------------- -------------------------------
  🎨 Frontend                     React, Vite
  ⚙️ Backend                      Node.js, Express, TypeScript
  🐍 Scanner                      Python, FastAPI, Uvicorn
  🗄️ Database                     PostgreSQL
  🧱 ORM                          Drizzle ORM
  🔬 Firmware Analysis            Binwalk 3, PySquashfsImage
  🦠 Malware Intelligence         VirusTotal + local heuristics
  🛡️ Vulnerability Intelligence   CVE/NVD-based analysis
  🤖 AI                           Google Gemini
  📄 Reporting                    PDF + SBOM
  📦 Package Manager              pnpm

------------------------------------------------------------------------

## ⚙️ Prerequisites

-   **Node.js 24+**
-   **pnpm**
-   **Python 3.10+**
-   **PostgreSQL**
-   A terminal capable of running three development processes

### Optional API keys

  Variable               Purpose
  ---------------------- -------------------------------
  `GEMINI_API_KEY`       AI-generated security reports
  `VIRUSTOTAL_API_KEY`   Real malware hash lookups

The application can degrade gracefully when optional services are
unavailable.

------------------------------------------------------------------------

# 🚀 Getting Started

## 1. Clone the repository

``` bash
git clone <your-repo-url>
cd Firmstrike
pnpm install
```

------------------------------------------------------------------------

## 2. Configure environment variables

Create:

``` text
backend/.env
```

Example:

``` env
PORT=8080
DATABASE_URL=postgres://user:password@localhost:5432/firmstrike
SESSION_SECRET=some-long-random-string
NODE_ENV=development

GEMINI_MODEL=gemini-2.5-flash
GEMINI_API_KEY=your-gemini-key

VIRUSTOTAL_API_KEY=your-virustotal-key

PYTHON_SCANNER_URL=http://127.0.0.1:8010
```

Create:

``` text
frontend/.env
```

Example:

``` env
VITE_PORT=25439
BASE_PATH=/
```

> Never commit real API keys or database passwords.

------------------------------------------------------------------------

## 3. Set up PostgreSQL

Configure `DATABASE_URL` and push the database schema:

``` bash
pnpm --filter @workspace/db run push
```

If your workspace uses a different package for the Drizzle schema, run
the corresponding database push/migration command from that package.

------------------------------------------------------------------------

## 4. Set up the Python scanner

``` bash
cd python-scanner
python -m venv .venv
```

### Windows --- Git Bash

``` bash
source .venv/Scripts/activate
```

### Windows --- PowerShell

``` powershell
.venv\Scripts\Activate.ps1
```

### Windows --- CMD

``` cmd
.venv\Scripts\activate.bat
```

### macOS / Linux

``` bash
source .venv/bin/activate
```

Install scanner dependencies:

``` bash
pip install -r requirements.txt
```

The scanner dependencies include:

-   `fastapi`
-   `uvicorn`
-   `python-multipart`
-   `binwalk3`
-   `PySquashfsImage`

------------------------------------------------------------------------

# ▶️ Run FirmStrike

FirmStrike uses **three processes** during local development.

### Terminal 1 --- Python scanner

``` bash
cd python-scanner
source .venv/Scripts/activate
python -m uvicorn app:app --host 127.0.0.1 --port 8010
```

Windows PowerShell users can activate the venv with the PowerShell
command above.

### Terminal 2 --- Backend

``` bash
pnpm --filter @workspace/backend run dev
```

Backend:

``` text
http://localhost:8080
```

### Terminal 3 --- Frontend

``` bash
pnpm --filter @workspace/frontend run dev
```

Frontend:

``` text
http://localhost:25439
```

Then open:

**http://localhost:25439**

Upload a firmware image and start a scan.

------------------------------------------------------------------------

# 🪟 Windows Notes

Firmware extraction can create Linux-style symbolic links. Windows may
block this for non-elevated processes.

If you encounter:

``` text
A required privilege is not held by the client. (os error 1314)
```

enable:

**Settings → Privacy & security → For developers → Developer Mode**

Then restart the terminal.

### If the Python virtual environment was moved

Do **not** reuse a broken `.venv` after moving or renaming the project
directory.

Recreate it:

``` bash
rm -rf .venv
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
```

------------------------------------------------------------------------

# 🧪 Available Commands

  Command                                       Purpose
  --------------------------------------------- --------------------------------
  `pnpm install`                                Install workspace dependencies
  `pnpm run typecheck`                          Typecheck workspace packages
  `pnpm run build`                              Build the project
  `pnpm --filter @workspace/backend run dev`    Start backend
  `pnpm --filter @workspace/frontend run dev`   Start frontend
  `python -m uvicorn app:app --port 8010`       Start Python scanner

------------------------------------------------------------------------

# 🧯 Troubleshooting

### ❌ Scan completes with almost no extracted files

Check the backend terminal for:

``` text
Binwalk available: false
```

Make sure the intended Python scanner is actually running on port
`8010`.

Windows:

``` bash
netstat -ano | findstr :8010
```

macOS/Linux:

``` bash
lsof -i :8010
```

Then restart the scanner from the activated virtual environment.

------------------------------------------------------------------------

### ❌ `ModuleNotFoundError: No module named 'pip._internal.operations.build'`

The virtual environment was probably created in a different location.

Recreate `.venv`:

``` bash
rm -rf .venv
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
```

------------------------------------------------------------------------

### ❌ Binwalk finds zero signatures

Verify that the scanner invokes `binwalk3.scan()` with the intended
signature/extraction configuration. Also verify that the firmware file
is actually being passed to the Python scanner and that the scanner
service running on `8010` is the expected environment.

------------------------------------------------------------------------

### ❌ Malware results look repetitive

BusyBox is commonly a multi-call binary: multiple executable names can
point to identical file content.

The malware analyzer should therefore deduplicate binaries using their
**SHA-256 hash** before sampling them for analysis.

------------------------------------------------------------------------

### ❌ Security score is always 0

Security findings can be numerous even in normal embedded Linux
firmware.

A scoring formula that simply subtracts a fixed amount for every finding
can saturate at zero. The scoring implementation should use bounded
category contributions and diminishing returns so different firmware
samples remain distinguishable.

------------------------------------------------------------------------

### ❌ Gemini report generation fails

Gemini failures do not necessarily mean that the scan itself failed.

FirmStrike retries Gemini requests and then falls back to a **local
deterministic security report** when all attempts fail.

------------------------------------------------------------------------

# 🔐 Security Analysis

FirmStrike examines multiple security dimensions:

``` text
                 SECURITY ANALYSIS
                        │
       ┌────────────────┼────────────────┐
       ▼                ▼                ▼
   🔐 Secrets       ⚠️ Functions      🧩 Components
       │                │                │
       ▼                ▼                ▼
 Credentials       system()          BusyBox
 SSH Keys          popen()            OpenSSL
 Certificates      strcpy()           Dropbear
       │                │                │
       └────────────────┼────────────────┘
                        ▼
                  🛡️ CVE Matching
                        │
                        ▼
                  🦠 Malware Analysis
                        │
                        ▼
                   📊 Risk Score
                        │
                        ▼
                🤖 AI / PDF Report
```

The result is intended to help security researchers and developers
identify areas requiring deeper manual validation.

> **Important:** Automated static analysis is not proof that firmware is
> secure. Findings should be manually validated before making production
> security decisions.

------------------------------------------------------------------------

# 📊 Output

A completed scan can provide information such as:

-   Firmware name
-   Architecture
-   Vendor/version information when detected
-   Extracted file information
-   Detected components
-   Hardcoded secrets
-   Dangerous functions
-   Known CVEs
-   Malware indicators
-   Threat scores
-   Overall risk level
-   AI-generated executive summary
-   Recommendations
-   PDF report
-   SBOM information

------------------------------------------------------------------------

# 🤖 AI Reporting & Fallback

When `GEMINI_API_KEY` is configured, FirmStrike can generate a
structured AI security assessment covering:

-   Overall risk
-   Most dangerous findings
-   Exploit probability
-   Remediation priorities
-   Executive summary

If Gemini is unavailable, the application uses a **local fallback
report** instead of treating the AI failure as a complete scan failure.

This means:

``` text
Gemini available
      │
      ▼
AI Security Report
      │
      └── Success → use AI result

Gemini unavailable / fails
      │
      ▼
Local Fallback Report
      │
      ▼
Scan can still complete
```

------------------------------------------------------------------------

# ⚠️ Known Limitations

-   No automated test suite yet.
-   Malware detection falls back to local heuristics when VirusTotal is
    unavailable.
-   AI summaries require `GEMINI_API_KEY`; otherwise the local fallback
    is used.
-   Firmware extraction support depends on the format and the tools
    available to the scanner.
-   Static analysis can produce false positives and false negatives.
-   CVE matches should be manually validated against the actual
    component/version in the firmware.
-   A clean automated scan does **not** guarantee that firmware is
    secure.

------------------------------------------------------------------------

# 🗺️ Future Improvements

Potential areas for future development:

-   [ ] Expanded firmware-format coverage
-   [ ] Deeper binary reverse-engineering integration
-   [ ] Improved CVE version correlation
-   [ ] YARA rule integration
-   [ ] QEMU-based dynamic analysis
-   [ ] Ghidra-assisted reverse engineering workflows
-   [ ] Automated regression tests
-   [ ] Enhanced SBOM visualization
-   [ ] More granular risk scoring
-   [ ] Authentication and role-based access controls
-   [ ] Production deployment documentation

------------------------------------------------------------------------

# 📄 License

Distributed under the **MIT License**.

See `LICENSE` for details.

------------------------------------------------------------------------

::: {align="center"}
### 🛡️ FirmStrike

**Firmware in. Security intelligence out.**

Made with ☕ and a healthy paranoia about firmware.
:::
