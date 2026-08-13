<div align="center">

# 🛡️ FirmStrike

### AI-Powered IoT Firmware Security Analysis Platform

*Upload. Scan. Detect. Emulate. Report.*

</div>

---

## 📖 Table of Contents

- [About](#-about)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Architecture](#-architecture)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Environment Variables](#environment-variables)
  - [Running Locally](#running-locally)
- [Available Scripts](#-available-scripts)
- [Application Pages](#-application-pages)
- [API Overview](#-api-overview)
- [Database Schema](#-database-schema)
- [Theming](#-theming)
- [Roadmap](#-roadmap)
- [Known Limitations](#-known-limitations)
- [FAQ](#-faq)
- [License](#-license)
- [Maintainers](#-maintainers)

---

## 🧭 About

**FirmStrike** (internally named **Viv Scanner**) is a full-stack cybersecurity platform built for security researchers, IoT manufacturers, and pentesters who need to analyze embedded and IoT firmware at scale.

Instead of juggling a dozen separate command-line tools, FirmStrike gives you one dashboard to:

1. Upload a firmware image
2. Extract and statically analyze its contents
3. Cross-reference known vulnerabilities against CVE databases
4. Scan for malware signatures and hardcoded secrets
5. Emulate the firmware in a QEMU sandbox to observe real runtime behavior
6. Generate a shareable, downloadable security report

The goal is to compress what normally takes hours of manual firmware reverse engineering into a guided, repeatable workflow.

> **Note:** This project is under active development. Some scan pipelines currently run against simulated/seeded data while the live analysis engines are being wired in — see [Known Limitations](#-known-limitations).

---

## ✨ Features

### 🔎 Firmware Intake & Extraction
- Upload firmware images directly through the web UI
- Automatic file extraction and content inventory
- Per-scan telemetry: file counts, extraction progress, timestamps

### 🛡️ Static & Binary Security Analysis
- Detection of hardcoded secrets (API keys, credentials, tokens)
- Flagging of dangerous/unsafe function usage
- Automated severity scoring per finding

### 🧬 CVE Intelligence
- CVSS score breakdown for matched vulnerabilities
- Direct links out to NVD (National Vulnerability Database)
- Matched security advisories tied to detected components

### 🦠 Malware Detection
- Hash-based matching against known malware signatures (VirusTotal-style)
- Visual threat-score meters for quick triage

### 🖥️ QEMU Emulation
- Boot firmware images inside an ARM emulator
- Discover open network ports and running services at runtime
- Useful for validating whether a static finding is actually exploitable

### 📊 Dashboard & Reporting
- Live threat metrics, vulnerability trend charts, and risk distribution
- AI-assisted risk summaries and exploit-probability estimates
- One-click downloadable PDF reports for stakeholders

### 🔐 Accounts
- Login/registration flow with session-based authentication

---

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| Monorepo tooling | pnpm workspaces, Node.js 24, TypeScript 5.9 |
| Frontend | React, Vite, Wouter (routing), Recharts (charts), Framer Motion (animation), Tailwind CSS v4, shadcn/ui |
| Backend / API | Express 5 |
| Database | PostgreSQL |
| ORM | Drizzle ORM (+ `drizzle-zod`) |
| Validation | Zod (`zod/v4`) |
| API contract & codegen | OpenAPI spec, generated via Orval into typed React Query hooks |
| Build tooling | esbuild (CJS bundle output) |
| Formatting | Prettier |

---

## 📂 Project Structure

```
FirmStrike/
├── artifacts/
│   ├── viv-scanner/                 # React frontend (cyberpunk dark theme)
│   │   └── src/
│   │       ├── pages/
│   │       │   ├── Dashboard.tsx
│   │       │   ├── FirmwareLibrary.tsx
│   │       │   ├── ScanDetails.tsx
│   │       │   ├── SecurityAnalysis.tsx
│   │       │   ├── CveIntelligence.tsx
│   │       │   ├── MalwareDetection.tsx
│   │       │   ├── QemuEmulation.tsx
│   │       │   ├── ReportsAi.tsx
│   │       │   ├── Login.tsx
│   │       │   └── Register.tsx
│   │       └── components/
│   │           ├── Layout.tsx        # Sidebar + main content shell
│   │           ├── theme-provider.tsx
│   │           └── ui/               # shadcn/ui components
│   │
│   └── api-server/
│       └── src/
│           └── routes/
│               ├── auth.ts
│               ├── firmware.ts
│               ├── scanner.ts
│               ├── security.ts
│               ├── cve.ts
│               ├── malware.ts
│               ├── qemu.ts
│               ├── reports.ts
│               └── dashboard.ts
│
├── lib/
│   ├── api-spec/
│   │   └── openapi.yaml             # Source-of-truth OpenAPI contract
│   ├── api-client-react/            # Generated React Query hooks + Zod schemas
│   └── db/
│       └── src/schema/              # Drizzle ORM schema (users, firmware, scans, security, index)
│
├── scripts/                         # Workspace-level scripts
├── attached_assets/                 # Static/reference assets
├── .gitignore
├── package.json
├── pnpm-lock.yaml
├── pnpm-workspace.yaml
├── tsconfig.base.json
├── tsconfig.json
└── replit.md                        # Internal engineering notes
```

---

## 🏗️ Architecture

- **Contract-first API** — `lib/api-spec/openapi.yaml` is the single source of truth. Both the server-side validation schemas and the frontend's typed React Query hooks are generated from it via Orval, so the client and server never drift out of sync.
- **Monorepo via pnpm workspaces** — the frontend (`viv-scanner`), backend (`api-server`), and shared packages (`api-spec`, `api-client-react`, `db`) live side by side and are typechecked/built together.
- **Session-based auth** — implemented with `express-session` and a `SESSION_SECRET`, with the full login/registration flow scaffolded and ready to be wired up end-to-end.
- **Routing convention** — all API routes are served under the `/api/` prefix; the frontend SPA is served at `/`.
- **Cyberpunk dark theme** — built with Tailwind CSS v4 custom variants (`@custom-variant dark (&:is(.dark *))`), toggled by adding a `.dark` class to `<html>` via `theme-provider.tsx`.

```
┌─────────────────────┐        OpenAPI spec        ┌─────────────────────┐
│  lib/api-spec        │ ─────────────────────────▶ │  Orval codegen       │
│  (openapi.yaml)       │                            │                      │
└─────────────────────┘                            └──────────┬──────────┘
                                                                │
                                       ┌────────────────────────┴────────────────────────┐
                                       ▼                                                  ▼
                          ┌───────────────────────┐                         ┌───────────────────────┐
                          │ lib/api-client-react   │                         │ api-server route        │
                          │ (typed hooks + Zod)    │                         │ validation (Zod schemas)│
                          └──────────┬────────────┘                         └──────────┬───────────┘
                                     │                                                    │
                                     ▼                                                    ▼
                          ┌───────────────────────┐                         ┌───────────────────────┐
                          │ viv-scanner frontend   │  ──── HTTP /api/* ────▶ │ Express 5 API server    │
                          │ (React + Vite)         │                         │                          │
                          └───────────────────────┘                         └──────────┬───────────┘
                                                                                        ▼
                                                                            ┌───────────────────────┐
                                                                            │ PostgreSQL + Drizzle    │
                                                                            └───────────────────────┘
```

---

## 🚀 Getting Started

### Prerequisites

- **Node.js 24+**
- **pnpm** — this workspace is pnpm-only. The `preinstall` script actively blocks `npm`/`yarn` installs and will exit with an error telling you to use pnpm.
- A running **PostgreSQL** instance

### Installation

```bash
git clone https://github.com/Redkrossresearch/FirmStrike.git
cd FirmStrike
pnpm install
```

### Environment Variables

Create a `.env` file (or export these in your shell) before running the API server:

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | ✅ | PostgreSQL connection string |
| `SESSION_SECRET` | ✅ | Secret used to sign session cookies |

### Running Locally

Run the frontend and API server in separate terminals:

```bash
# Terminal 1 — API server (http://localhost:8080)
pnpm --filter @workspace/backend run dev

# Terminal 2 — React frontend (http://localhost:25439)
pnpm --filter @workspace/frontend run dev
```

Then open **http://localhost:25439** in your browser.

---

## 📜 Available Scripts

| Command | Description |
|---|---|
| `pnpm install` | Install all workspace dependencies |
| `pnpm run typecheck` | Typecheck every package in the workspace |
| `pnpm run build` | Typecheck, then build all packages |
| `pnpm --filter @workspace/backend run dev` | Start the Express API server in dev mode |
| `pnpm --filter @workspace/frontend run dev` | Start the React frontend in dev mode |
| `pnpm --filter @workspace/api-spec run codegen` | Regenerate API hooks & Zod schemas from `openapi.yaml` |
| `pnpm --filter @workspace/db run push` | Push Drizzle schema changes to the database (dev only) |

> ⚠️ Do not run `pnpm add --no-frozen-lockfile` in this workspace — it can desync the lockfile across packages.

---

## 🗺️ Application Pages

| Page | Purpose |
|---|---|
| **Dashboard** | Live threat metrics, vulnerability trends, risk distribution overview |
| **Firmware Library** | Upload, browse, and manage firmware images |
| **Scan Details** | Per-scan extraction telemetry and progress |
| **Security Analysis** | Hardcoded secrets, dangerous functions, severity scores |
| **CVE Intelligence** | CVSS breakdowns, NVD links, matched advisories |
| **Malware Detection** | Hash-based threat matching and scoring |
| **QEMU Emulation** | Boot firmware, inspect open ports and running services |
| **Reports & AI** | Risk summaries, exploit probability, PDF export |
| **Login / Register** | Session-based account access |

---

## 🔌 API Overview

All backend routes are namespaced under `/api/` and grouped by domain in `backend/src/routes/`:

| Route file | Responsibility |
|---|---|
| `auth.ts` | Login, registration, session handling |
| `firmware.ts` | Firmware upload and library management |
| `scanner.ts` | Scan orchestration and progress tracking |
| `security.ts` | Static/binary security analysis findings |
| `cve.ts` | CVE matching and CVSS data |
| `malware.ts` | Malware hash matching |
| `qemu.ts` | QEMU emulation control and results |
| `reports.ts` | Report generation (including AI summaries) |
| `dashboard.ts` | Aggregated metrics for the dashboard view |

The full contract lives in [`lib/api-spec/openapi.yaml`](./lib/api-spec/openapi.yaml). After changing it, regenerate the typed client with:

```bash
pnpm --filter @workspace/api-spec run codegen
```

---

## 🗄️ Database Schema

Schema is defined with Drizzle ORM in `lib/db/src/schema/`, covering:

- `users` — accounts and auth data
- `firmware` — uploaded firmware image records
- `scans` — scan jobs and their progress/status
- `security` — findings from static/binary analysis
- `index` — shared schema exports

Seed data currently includes 4 firmware records (D-Link — critical, TP-Link — high, Netgear — scanning, Asus — pending), 12 vulnerabilities, 6 CVEs, 7 malware hashes, and 6 activity events — useful for local development and demos.

---

## 🎨 Theming

FirmStrike ships with a dark "cyberpunk" theme by default:

- **Accent:** electric teal `#00e5cc`
- **Background:** near-black `#0a0f14`
- Implemented with Tailwind CSS v4 custom properties scoped to a `.dark` class, applied via `theme-provider.tsx`

If you're extending the UI, keep in mind a few Recharts/shadcn quirks encountered in this codebase:

- Recharts `<Cell>` must be imported and capitalized — a lowercase `<cell>` is invalid JSX
- The `RadialBar` prop is `isClockWise`, not `clockWise`, in the current Recharts version
- shadcn's `Progress` component doesn't accept `indicatorColor` — use a Tailwind arbitrary selector like `[&>div]:bg-...` instead
- `useGetRunningServices` returns an `EmulationLog[]` array, not a single object — access it as `services?.[0]?.runningServices`

---

## 🛣️ Roadmap

- [ ] Replace simulated scan progression with real static/binary analysis pipelines
- [ ] Wire up live firmware extraction (e.g. Binwalk-based) end to end
- [ ] Connect CVE Intelligence to a live NVD/CVE feed
- [ ] Real malware hash lookups against an external threat-intel source
- [ ] Harden QEMU emulation sandboxing for untrusted firmware
- [ ] Full end-to-end auth flow (password reset, email verification)
- [ ] CI pipeline for typecheck/build/test on pull requests

Have an idea or priority you'd like bumped up? Open an issue!

---

## ⚠️ Known Limitations

- Some scan flows currently simulate progression via `setTimeout` rather than performing live analysis — this is being replaced incrementally.
- APIs and schemas may change without notice while the project is in active development.
- No automated test suite yet.

---

## ❓ FAQ

**Q: Why does it say "Use pnpm instead" when I try `npm install`?**
This workspace enforces pnpm via a `preinstall` script. Install pnpm (`npm i -g pnpm`) and use that instead.

**Q: Is the security analysis using real tools like Binwalk or Ghidra right now?**
Not yet end-to-end — some pipelines currently run against simulated/seeded data while live integrations are built out. See [Roadmap](#-roadmap).

**Q: What ports do the frontend and API run on locally?**
Frontend: `25439`. API server: `8080`.

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](./LICENSE) for details (add one if not already present).

---

## 👥 Maintainers

Maintained by [Redkrossresearch](https://github.com/Redkrossresearch).

---

<div align="center">

Made with ☕ and a healthy paranoia about firmware.

</div>
