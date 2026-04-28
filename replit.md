# Workspace

## Overview

pnpm workspace monorepo using TypeScript. Each package manages its own dependencies.

## Stack

- **Monorepo tool**: pnpm workspaces
- **Node.js version**: 24
- **Package manager**: pnpm
- **TypeScript version**: 5.9
- **API framework**: Express 5
- **Database**: PostgreSQL + Drizzle ORM
- **Validation**: Zod (`zod/v4`), `drizzle-zod`
- **API codegen**: Orval (from OpenAPI spec)
- **Build**: esbuild (CJS bundle)

## Key Commands

- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- `pnpm --filter @workspace/api-server run dev` — run API server locally

## Dashboard Charts (rebuilt 2026-04-28)

The dashboard now renders 6 donut charts driven by **real** data (no more mock seed tables).
Source views are defined in `supabase/migrations/20260428000000_dashboard_chart_views.sql`:

| View                              | Donut                          | Source data                                         |
| --------------------------------- | ------------------------------ | --------------------------------------------------- |
| `chart_vulns_by_exprt`            | Vulnerabilities by ExPRT       | `cve_catalog.cvss_v3_severity` of matched CVEs      |
| `chart_findings_by_type`          | Vulnerabilities by type        | `scan_findings.tool` bucketed (Vuln/Misconf/Other)  |
| `chart_exploitability_risk`       | Exploitability risk            | `cve_catalog` ⨝ `exploits` (verified / PoC / none)  |
| `chart_attack_vector`             | Attack vector                  | Parsed from `cve_catalog.cvss_v3_vector` (AV:N/A/L/P) |
| `chart_exploit_types`             | Exploit types                  | `exploits.type` from local ExploitDB                |
| `chart_top_vulnerable_products`   | Top vulnerable products        | `scan_findings.metadata->>'product'`                |

Each view returns a uniform `(segment_name, segment_value, segment_color, sort_order)` shape.
Frontend reads them through `useChartView()` (`src/hooks/useChartView.ts`) which gracefully falls back to an empty state if the migration hasn't been applied yet.

Legacy mock tables (`chart_data`, `severity_stats`, `review_status`) and their components
(`SeverityCards.tsx`, `ReviewStatusCard.tsx`) were removed.

## Replit Setup

- **Dev workflow**: `Start application` runs the Vite dev server for `artifacts/web-app` on port 5000 (host `0.0.0.0`, `allowedHosts: true` for the iframe proxy).
- **Frontend env**: Supabase URL/anon key are loaded from `.env` at the repo root and injected into Vite as `VITE_SUPABASE_URL` / `VITE_SUPABASE_PUBLISHABLE_KEY`.
- **API proxy**: Vite proxies `/api/*` to `http://localhost:8081` (the optional Express `@workspace/api-server`). Used only by the Admin Panel invitation endpoint.
- **Deployment**: Configured as `static` — builds with `pnpm --filter @workspace/web-app run build` and serves `artifacts/web-app/dist/public`.

See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details.
