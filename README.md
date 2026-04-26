# Vulnerability and Patch Tracking System

A full-stack PostgreSQL application that models the complete enterprise cybersecurity vulnerability lifecycle — from scanner discovery, through risk scoring and SLA enforcement, to patch tracking with a full audit trail.

**Final project for NYU Tandon — Principles of Database Systems — Spring 2026**

**Live application:** https://vuln-tracker.onrender.com
**GitHub repository:** https://github.com/pg1820/vuln-tracker

---

## Project at a Glance

| Deliverable | Count | Notes |
|---|---|---|
| Tables | 15 | 120+ columns across 5 tiers |
| Views | 4 | 5–7 table joins, CASE expressions, dual classification logic |
| Functions | 4 | One IMMUTABLE risk-score function, three VOLATILE helpers |
| Procedures | 3 | Idempotent scan ingestion, transactional patch action, daily risk snapshot |
| Triggers | 4 | Audit log, pre-insert risk computation, time-to-remediate, timestamp keeper |
| Aggregation Reports | 8 | GROUP BY, HAVING, CASE, COUNT(DISTINCT), date arithmetic, window functions |
| Foreign Keys | 18 | ON DELETE CASCADE for operational data, SET NULL for optional ownership |
| CHECK Constraints | 15+ | severity, criticality 1-5, employee_count > 0, etc. |
| UNIQUE Constraints | 12 | CVE IDs, hostnames, junction-table FK pairs |
| Junction Tables | 3 | Asset–group, asset–software, software–vulnerability |
| Seed Rows | 221 | Five organizations across Financial Services, Healthcare, Tech, Retail, Government — with real CVEs (Log4Shell, Spring4Shell, OpenSSL, etc.) and EPSS scores |
| Industry Sectors | 5 | Financial Services, Healthcare, Technology, Retail, Government |

---

## How the Rubric Maps to This Project

| Rubric Item | Where to Find It |
|---|---|
| Table DDL (/6) | `schema.sql` lines 1–860 — 15 `CREATE TABLE` statements |
| View DDL (/6) | `schema.sql` — `vw_asset_exposure_summary`, `vw_patch_compliance_status`, `vw_exploit_risk_dashboard`, `vw_organization_risk_posture` |
| Function DDL (/6) | `schema.sql` — `fn_finding_risk_score` (IMMUTABLE), `fn_sla_days_remaining`, `fn_org_compliance_rate`, `fn_asset_composite_risk` |
| Procedure DDL (/6) | `schema.sql` — `sp_record_scan_finding`, `sp_initiate_patch_action`, `sp_refresh_risk_snapshot` |
| Trigger DDL (/6) | `schema.sql` — `trg_patch_status_audit`, `trg_finding_pre_insert`, `trg_finding_remediated`, `trg_org_updated_at` |
| ER Diagram (/6) | `ER_Diagram.png` — 5-tier dark-theme PIL render |
| Discussion: Normalization (/3) | Presentation slide 9; this README — Schema Design section below |
| Discussion: Integrity (/3) | Presentation slide 10; this README — Integrity Constraints section below |
| Discussion: Isolation (/3) | Presentation slide 19; this README — Concurrency section below |
| Forms: Inserts (/10) | All 15 tables editable via `POST /table/<table_name>/create` |
| Forms: Updates (/10) | All 15 tables editable via `POST /table/<table_name>/edit/<pk>` |
| Forms: Deletes (/10) | All 15 tables editable via `POST /table/<table_name>/delete/<pk>` |
| Forms: Selects (/10) | All 15 tables listable via `GET /table/<table_name>` |
| Reports (/5) | 8 reports in `/reports/*` routes — Findings by Severity, Patch Status, Top Exposed Assets, Compliance by Org, Most Vulnerable Software, Exploit Risk Dashboard, Org Risk Posture, SLA Breach Analysis |
| Presentation (/10) | `Vuln_Tracker_Presentation.pptx` — 20 slides with full speaker notes |

---

## Architecture

### Five-Tier Schema

The 15 tables are organized into 5 layered tiers, top-down:

1. **Organizational** — `organizations`, `users`. Multi-tenancy boundary; six user roles; MFA tracking; regulatory scope.
2. **Asset Management** — `asset_groups`, `assets`, `asset_group_memberships`. Hosts, network zones. Uses PostgreSQL-native `INET` and `MACADDR` types.
3. **Software & Scanning** — `scan_sources`, `software_products`, `asset_software_installs`. CPE URI standard for software identification.
4. **Vulnerability Intelligence** — `vulnerabilities`, `software_vulnerabilities`, `remediation_sla_policies`. CVE catalogue with CVSS, EPSS scores, per-org SLA policies.
5. **Operations & Audit** — `scan_findings`, `patch_actions`, `patch_status_history`, `risk_score_snapshots`. The operational record with full audit trail and daily risk trending.

Three M:N junction tables resolve multi-valued relationships:
- `asset_group_memberships` — assets can belong to multiple groups
- `asset_software_installs` — assets can have multiple software products installed
- `software_vulnerabilities` — software products can have multiple known CVEs

### Tech Stack

- **PostgreSQL 18** — Database engine, hosted on Render's managed Postgres
- **Python · Flask** — Web framework with a generic CRUD pattern serving all 15 tables
- **psycopg2-binary** — PostgreSQL adapter
- **Gunicorn** — WSGI server for production
- **Render.com** — Cloud PaaS deployment
- **GitHub** — Version control with auto-deploy webhook to Render

### Generic CRUD Pattern

Rather than writing 15 sets of CRUD routes, the application uses **4 generic routes** that look up the requested table in a `TABLE_CONFIG` dictionary in `app.py`. The dictionary defines per-table:
- Which columns to display
- Which fields are editable
- How to resolve foreign keys to human-readable dropdowns
- What CHECK constraint values to offer in select boxes

Adding a new table to the application requires zero new Python code — just a new dictionary entry. The application is intentionally thin; the database does the heavy lifting.

---

## Quick Start

### Option 1 — Use the live application
Just open https://vuln-tracker.onrender.com. No setup required. The free tier may take ~30 seconds to wake up on the first request after inactivity.

### Option 2 — Run locally

```bash
# 1. Clone the repository
git clone https://github.com/pg1820/vuln-tracker.git
cd vuln-tracker

# 2. Create a virtual environment and install dependencies
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 3. Set up a PostgreSQL database (locally or via Render, ElephantSQL, etc.)
# Then export the connection string:
export DATABASE_URL="postgresql://user:password@host:5432/dbname"

# 4. Initialize the database schema and seed data:
psql "$DATABASE_URL" -f schema.sql

# 5. Run the application:
python app.py
# OR via Gunicorn for production:
gunicorn app:app

# 6. Open http://localhost:5000 in your browser
```

### Option 3 — Deploy your own copy on Render

1. Fork the GitHub repo
2. In Render, create a new Web Service from your fork
3. Render auto-detects the `Procfile` and `runtime.txt`
4. Provision a PostgreSQL database (free tier)
5. Set `DATABASE_URL` env var to your database's External Connection URL
6. Run `schema.sql` against it once via psql or a Render shell
7. Push to your fork — Render auto-deploys

---

## Risk Score Formula

The function `fn_finding_risk_score` is the brain of the prioritization system. Marked `IMMUTABLE` so PostgreSQL can cache results and use it in index expressions.

```
risk = CVSS × (0.4 + criticality × 0.32) × (1 + EPSS × 1.5) × exploit_bonus
```

Where:
- **CVSS** — Common Vulnerability Scoring System base score (0.0–10.0)
- **criticality** — Asset's business criticality on a 1–5 scale; weight ranges from 0.72 (criticality 1) to 2.0 (criticality 5)
- **EPSS** — Exploit Prediction Scoring System probability (0.0–1.0); the chance the vulnerability will be exploited in the wild within 30 days, sourced from FIRST.org
- **exploit_bonus** — 1.20 if a public exploit exists, otherwise 1.00

**Worked example — CVE-2021-44228 (Log4Shell, CVSS 9.8):**
- Production server, criticality 5, EPSS 0.97, public exploit confirmed: `9.8 × 2.0 × 2.455 × 1.20 = 57.7`
- Lab server, criticality 1, no public exploit: `9.8 × 0.72 × 2.455 × 1.00 = 17.3`

A 3.3× difference in urgency for the same CVE landing on different assets.

---

## Schema Design — Normalization

The schema is in **Third Normal Form** with one intentional, documented denormalization.

**1NF** — Every column stores atomic values. No repeating groups. All M:N relationships are resolved via junction tables.

**Intentional denormalization:** `regulatory_scope` on `organizations` stores a comma-separated string (e.g., `'PCI-DSS, HIPAA, SOC2'`). Compliance frameworks are display-only — never queried, joined, or aggregated. Normalizing them into a separate `compliance_frameworks` table plus a junction table would add two tables and zero analytical value.

**2NF** — Every non-key attribute depends on the entire key. The three junction tables enforce composite-key logic via UNIQUE constraints on the FK pair plus a SERIAL surrogate.

**3NF** — No transitive dependencies. The `risk_score` column on `scan_findings` is materialized for performance, but it is recomputable from CVSS, EPSS, and asset criticality via `fn_finding_risk_score`. It is a cached column, not a normal-form violation.

---

## Integrity Constraints

The database enforces all four standard integrity types:

- **Entity Integrity** — 15 SERIAL PRIMARY KEYs (auto-increment, NOT NULL, UNIQUE).
- **Referential Integrity** — 18 FOREIGN KEYs with `ON DELETE CASCADE` on operational data and `ON DELETE SET NULL` on optional ownership.
- **Domain Integrity** — 15+ CHECK constraints, native types (INET, MACADDR, NUMERIC), explicit value enumerations on `severity`, `status`, `role`.
- **User-Defined Integrity** — 12 UNIQUE constraints prevent duplicate CVE IDs, duplicate hostnames, duplicate junction-table mappings.

Plus NOT NULL on every business-critical column. The database refuses to enter an inconsistent state — application bugs cannot corrupt the schema.

---

## Concurrency & Isolation Levels

PostgreSQL exposes the four standard isolation levels but its MVCC architecture means **READ UNCOMMITTED behaves identically to READ COMMITTED** — Postgres never returns dirty reads regardless of the requested level. This differs from MySQL or SQL Server which use lock-based isolation.

This application uses **READ COMMITTED** (PostgreSQL's default). It is sufficient because every CRUD operation is a single statement — there is no read-modify-write pattern across multiple queries within a transaction.

The procedures handle concurrency through **application-level deduplication plus UNIQUE constraints**, not through elevated isolation levels. If two scanners try to insert the same finding simultaneously:

1. The UNIQUE constraint on `(asset_id_fk, sw_vuln_id_fk)` causes one INSERT to fail
2. The procedure catches the failure and refreshes `last_seen_at` instead

The `sp_refresh_risk_snapshot` procedure uses `INSERT ... ON CONFLICT DO UPDATE` — the UPSERT pattern is atomic at any isolation level, so the procedure is safely re-runnable.

---

## File Layout

```
vuln_tracker/
├── app.py              Flask application — generic CRUD, 8 report routes, dashboard
├── schema.sql          All DDL: 15 tables, 4 views, 4 functions, 3 procedures, 4 triggers, 221 seed rows
├── requirements.txt    Python dependencies
├── runtime.txt         Python version pin (3.11)
├── Procfile            Render/Gunicorn process declaration
├── render.yaml         Render service configuration
├── templates/          7 Jinja templates — base, home, table list/form, report, sql_objects, discussion
├── static/styles.css   Dark-themed CSS with mid-navy palette and gold/cyan accents
└── README.md           This file
```

---

## Author

**Pavlos Giannakis** · NYU Tandon School of Engineering · Principles of Database Systems · Spring 2026
