# Aegis-SOAR — Multi-Tenant Security Response Engine

Aegis-SOAR is a multi-tenant security orchestration and human-approved response engine built with **Python 3.12+**, **SQLAlchemy 2.0 Async**, **AsyncPG**, and **PostgreSQL 16**. It enforces tenant isolation, access control, blast-radius concurrency limits, and append-only audit logging at the database layer, paired with an I/O-free pure core and a simulated containment adapter.

> **Current Status:** Active Build — **5 of 6 security test gates (`G0, G1, G2, G3, G5`) passing locally** (12/12 `pytest` security & concurrency tests + 9/9 SQL schema tests). Phase 3 (FastAPI HTTP layer, Gate `G4` AI Guard AST/integration tests, Alembic schema-parity check, and GitHub Actions CI) is in progress.

---

## Architecture & Security Invariants

### 1. Fail-Closed Multi-Tenancy (`FORCE RLS`)
- Every tenant-scoped table enforces PostgreSQL 16 `ENABLE` and `FORCE ROW LEVEL SECURITY`.
- Runtime sessions connect exclusively as a least-privilege `aegis_app` role (`NOSUPERUSER NOBYPASSRLS`).
- Tenant context is bound per transaction via parameterized `set_config('app.current_tenant_id', :tid, true)` inside `tenant_transaction`, preventing connection-pool cross-talk.
- Pre-authentication identity lookup runs strictly through a scoped `SECURITY DEFINER` function (`public.auth_lookup_identity`).

### 2. Authentication, TOTP MFA & DB-Authoritative RBAC
- **Passwords:** Argon2id (`memory_cost=65536`, `time_cost=3`, `parallelism=4`) with constant-cost dummy verification for unknown emails to mitigate timing enumeration.
- **Access Tokens:** EdDSA (`Ed25519`) JWTs with mandatory `jti`, `sub`, `tid`, `iat`, `exp` claims and explicit rejection of `alg=none`, `HS256`, and `RS256`.
- **Refresh Tokens:** Opaque `<tenant_id>.<secret>` tokens stored as SHA-256 hashes, rotated on each use, with automatic **entire-family revocation** and audit logging on token reuse.
- **Per-Action TOTP MFA:** RFC 6238 TOTP secrets encrypted at rest with **AES-256-GCM** (96-bit nonce + `user_id:tenant_id` AAD). Single-use step consumption (`last_used_totp_step < :step`) prevents concurrent TOTP replay.
- **Separate-Transaction Lockout:** Failed TOTP attempts increment `mfa_failed_attempts` and apply a 15-minute lockout (`5` failures) in an independent transaction so the counter survives outer transaction rollbacks without self-deadlocking.
- **Authoritative RBAC:** Privileged actions re-read `users.role` and `is_active` from PostgreSQL inside the active transaction rather than trusting stale JWT role claims.

### 3. Human-Approved Response Automation & Safety Limits
- **4-Eyes Approval:** Approver must hold an active `APPROVER` role in PostgreSQL and cannot equal `proposed_by`.
- **CIDR Allowlists & Canonical IPs:** Rejects IPv4-mapped IPv6 addresses (`::ffff:0:0/96`) via DB `CHECK` constraints and enforces tenant `protected_assets` CIDR allowlists at approval time via database triggers (zero-TOCTOU).
- **Blast-Radius Concurrency Control:** Serializes concurrent approvals per tenant using `pg_advisory_xact_lock(hashtextextended(tenant_id || ':blast', 0))` across `HOST_ISOLATE` and `FIREWALL_BLOCK_IP` actions to enforce `blast_radius_k_max`.
- **Two-Phase Lock-Free Execution & Crash Reconciliation:**
  1. **Phase 1 (Short DB TX):** Acquires advisory lock, validates role/TOTP/allowlist/cap, transitions action to `EXECUTING`, records `slot_reserved_at`, and commits.
  2. **Phase 2 (Lock-Free):** Invokes idempotent `SimulatedResponseAdapter.apply(action_id, ...)`.
  3. **Phase 3 (Short DB TX):** Transitions action to `EXECUTED` (with `expires_at`) or `FAILED`.
  4. **Reaper:** `reconcile_stale_executing` queries `adapter.get_state(action_id)` for stale `EXECUTING` rows after worker crashes and deterministically reconciles state to `EXECUTED` or `FAILED`.
- **Idempotent Rollback:** Two-phase manual rollback (`EXECUTED -> ROLLING_BACK -> ROLLED_BACK`) requiring fresh TOTP verification.

### 4. Pure Core & Append-Only Hash-Chained Audit Log
- **Pure Core (`detection/`, `safety_limits/`, `ai_guard/`):** Zero I/O, zero database, and zero wall-clock dependencies—enforced statically by `import-linter` and `ruff`, and dynamically by runtime clock/socket monkeypatch tests.
- **Append-Only Audit Log (`audit_log`):** Per-tenant SHA-256 hash chain (`prev_hash` -> `event_hash`) with `UPDATE`, `DELETE`, and `TRUNCATE` blocked by privileges and triggers (including for the table owner).

---

## Repository Layout

```text
aegis-soar/
├── sql/
│   ├── schema.sql                       # Normative PostgreSQL 16 DDL, RLS policies & triggers
│   └── schema_tests.sql                 # 9/9 SQL-level isolation & constraint tests
├── src/aegis_soar/
│   ├── adapters/simulated.py            # Idempotent simulated containment adapter + fault injection
│   ├── ai_guard/sanitizer.py            # Pure prompt-injection sanitizer
│   ├── audit/logger.py                  # Per-tenant SHA-256 hash-chained audit logger
│   ├── auth/
│   │   ├── crypto.py                    # Argon2id, EdDSA JWT, AES-256-GCM, RFC 6238 TOTP
│   │   └── service.py                   # Login, refresh rotation, DB RBAC, TOTP replay & lockout
│   ├── db/
│   │   ├── engine.py                    # Async SQLAlchemy engine & session factory
│   │   └── models.py                    # ORM models mapped to PostgreSQL 16 schema
│   ├── detection/rules.py               # Pure MITRE ATT&CK detection rules
│   ├── response/service.py              # Two-phase approval, rollback, blast lock & reaper
│   ├── safety_limits/ip_guard.py        # Pure canonical IP & ::ffff:0:0/96 guard
│   └── tenancy/context.py               # tenant_transaction & pre_auth_session context managers
└── tests/
    ├── unit/test_purity_g0.py           # Gate G0: pure core runtime isolation
    ├── security/
    │   ├── test_rls_isolation.py        # Gate G1: cross-tenant RLS isolation as aegis_app
    │   ├── test_auth_rbac.py            # Gate G2: JWT alg rejection, DB demotion, refresh reuse
    │   ├── test_totp_mfa.py             # Gate G2: concurrent TOTP replay & separate-TX lockout
    │   ├── test_allowlist_inv5.py       # Gate G3: ::ffff:0:0/96 & zero-TOCTOU CIDR allowlist
    │   └── test_audit_immutability.py   # Gate G5: UPDATE/DELETE/TRUNCATE blocked (app & owner)
    └── concurrency/
        ├── test_blast_radius_inv6.py    # Gate G3: 10 concurrent approvers vs K_max=3 + NoopLock proof
        └── test_two_phase_reaper_inv7.py# Gate G5: crash after apply() reconciliation & idempotent rollback
```

---

## Security Test Gates Status

| Gate | Scope | Verification | Status |
| :--- | :--- | :--- | :--- |
| **G0** | Static & Core Purity | `ruff check`, `mypy --strict`, `lint-imports`, `test_purity_g0.py` | Passing locally |
| **G1** | Multi-Tenant RLS Isolation | `sql/schema_tests.sql` (9/9) + `test_rls_isolation.py` (`aegis_app`) | Passing locally |
| **G2** | Auth, RBAC & TOTP MFA | `test_auth_rbac.py` + `test_totp_mfa.py` | Passing locally |
| **G3** | Allowlist & Blast Radius | `test_allowlist_inv5.py` + `test_blast_radius_inv6.py` (10x race) | Passing locally |
| **G4** | FastAPI, Detection & AI Guard | HTTP layer + `test_ai_guard.py` + AST isolation | Pending (Phase 3) |
| **G5** | Crash Recovery & Audit Log | `test_two_phase_reaper_inv7.py` + `test_audit_immutability.py` | Passing locally |

---

## Local Setup & Verification

### Prerequisites
- Python 3.12+
- Docker (for PostgreSQL 16)

### 1. Start PostgreSQL 16 & Apply Schema
```powershell
docker run -d --name aegis-pg -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=aegis_soar -p 5433:5432 postgres:16
Get-Content sql/schema.sql | docker exec -i aegis-pg psql -U postgres -d aegis_soar
```

### 2. Install Dependencies & Configure Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

$env:AEGIS_APP_DATABASE_URL   = "postgresql+asyncpg://aegis_app:aegis_app_dev@localhost:5433/aegis_soar"
$env:AEGIS_OWNER_DATABASE_URL = "postgresql+asyncpg://postgres:postgres@localhost:5433/aegis_soar"
```

### 3. Run Static Analysis, Architecture Contracts & Test Suite
```powershell
ruff check src tests
mypy src tests
lint-imports
pytest -v
```

---

## Roadmap (Phase 3 — In Progress)
- FastAPI HTTP layer (`/v1/auth/*`, `/v1/events`, `/v1/actions/*`, `/healthz`) with uniform error envelopes and login rate limiting.
- Gate `G4`: MITRE ATT&CK synthetic fixtures + AST-verified isolation ensuring `response/` and `safety_limits/` never import `ai_guard` or read untrusted triage text.
- Alembic initial migration with automated `pg_dump` schema-drift parity check against `sql/schema.sql`.
- `Dockerfile`, `docker-compose.yml`, and GitHub Actions CI running Gates `G0–G5`.
