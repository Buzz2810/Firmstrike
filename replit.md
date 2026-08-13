# Viv Scanner

A full-stack cybersecurity firmware analysis platform — upload firmware images, run deep security scans, detect CVEs, malware, hardcoded secrets, and emulate firmware with QEMU.

## Run & Operate

- `pnpm --filter @workspace/backend run dev` — run the API server (port 8080)
- `pnpm --filter @workspace/frontend run dev` — run the React frontend (port 25439)
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL` — Postgres connection string, `SESSION_SECRET` — session signing key

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- Frontend: React + Vite + Wouter + Recharts + Framer Motion + Tailwind v4
- API: Express 5
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)

## Where things live

- `frontend/` — React frontend (cyberpunk dark theme)
  - `src/pages/` — 10 pages: Dashboard, FirmwareLibrary, ScanDetails, SecurityAnalysis, CveIntelligence, MalwareDetection, QemuEmulation, ReportsAi, Login, Register
  - `src/components/` — Layout.tsx (sidebar + main), theme-provider.tsx, shadcn/ui components
- `backend/src/routes/` — Express routes: auth, firmware, scanner, security, cve, malware, qemu, reports, dashboard
- `lib/api-spec/openapi.yaml` — OpenAPI contract (source of truth for all endpoints)
- `lib/api-client-react/` — Generated React Query hooks + Zod schemas (from Orval codegen)
- `lib/db/src/schema/` — Drizzle ORM schema (users, firmware, scans, security, index)

## Architecture decisions

- Contract-first API: OpenAPI spec drives all generated client hooks and server validation schemas
- Dark cyberpunk theme: electric teal (#00e5cc) on near-black (#0a0f14), CSS custom properties scoped to `.dark` class
- Mock scan simulation: backend simulates real scan progression with setTimeout updates
- All API routes under `/api/` prefix, served by the API server artifact; frontend at `/`
- Session-based auth (express-session + SESSION_SECRET), ready to wire full login flow

## Product

**Viv Scanner** lets security analysts upload embedded/IoT firmware images and instantly get:
- Dashboard with live threat metrics, vulnerability trends, and risk distribution
- Scan telemetry with file extraction, vulnerability counts, and progress tracking
- Security analysis: hardcoded secrets, dangerous functions, severity scoring
- CVE intelligence: CVSS score breakdown, NVD links, matched advisories
- Malware detection: VirusTotal-style hash matching, threat score meters
- QEMU emulation: boot firmware in ARM emulator, discover open ports and running services
- Reports & AI: risk summaries, exploit probability, downloadable PDF reports

## User preferences

_Populate as you build — explicit user instructions worth remembering across sessions._

## Gotchas

- Tailwind v4 dark variant: `@custom-variant dark (&:is(.dark *))` — ThemeProvider must add `.dark` to `<html>` for dark: classes to work
- Recharts `Cell` must be imported from `recharts` and capitalized (`<Cell>`) — lowercase `<cell>` is invalid JSX
- `RadialBar` prop is `isClockWise` not `clockWise` in current recharts version
- Progress component from shadcn doesn't accept `indicatorColor` — use Tailwind arbitrary `[&>div]:` selector instead
- `useGetRunningServices` returns `EmulationLog[]` (array), not a single object — access `services?.[0]?.runningServices`
- Never `pnpm add --no-frozen-lockfile` in this workspace

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
- Seed data: 4 firmware records (D-Link critical, TP-Link high, Netgear scanning, Asus pending), 12 vulns, 6 CVEs, 7 malware hashes, 6 activity events
