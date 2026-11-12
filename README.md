# BalanceVault

Secure Financial Account, Double-Entry Ledger, and Transaction Management System (Flask + SQLite + accessible vanilla JS).

## Quick Start

```bash
cd balancevault
pip install -r requirements.txt
BV_SECRET=<random-hex> python app.py
```

Open `http://localhost:5000` in your browser.
Default administrator credentials: `admin` / `Admin@123` (override via `BV_ADMIN_PW`).

Run the automated test suite:

```bash
python -m unittest tests/test_app.py -v
```

## Architecture & Security Controls

- **Authentication & Sessions**: `werkzeug.security` password hashing, `HttpOnly` + `SameSite=Lax` sessions, session regeneration on login, password rotation (`/api/me/password`), and per-IP/username login rate limiting (`BV_LOGIN_MAX_ATTEMPTS`).
- **Role-Based Access Control (RBAC)**:
  - `customer`: Apply for accounts, inspect own accounts/ledgers/transactions, and transfer between active accounts.
  - `auditor`: Read-only oversight across all accounts, transactions, double-entry ledgers, users, integrity checks, and immutable audit logs.
  - `admin`: Full onboarding review (approve/reject/freeze/unfreeze/close), system reserve deposits/withdrawals, user status/role management, and integrity reconciliation.
  - Role and `active`/`disabled` status are queried live from SQLite on every request (`g.user`).
- **Account Onboarding Lifecycle**: Validated state machine (`pending` → `active`/`rejected`; `active` ↔ `frozen`; `active`/`frozen` → `closed` only when balance is `0`).
- **Double-Entry Ledger & Zero-Sum Integrity**: Every financial operation writes paired `DEBIT` + `CREDIT` rows with `balance_after_cents` snapshots against `SYSTEM-0000`, so total system balances always sum to `0`. `/api/admin/integrity` reconciles every account and transaction.
- **Duplicate Prevention (Idempotency)**: `UNIQUE(created_by, idem_key)` combined with canonical `payload_hash` (`SHA-256`). Exact retries return `200` with `replayed: true`; key reuse with modified payloads returns `422` and logs `IDEMPOTENCY_CONFLICT`.
- **Concurrency & Deadlock Prevention**: SQLite `WAL` mode + `synchronous=FULL` + `BEGIN IMMEDIATE` write serialization + deterministic ascending account-ID update order + database `CHECK` constraints (`balance_cents >= 0 OR is_system = 1`).
- **Immutable Audit Trail**: Append-only `audit_log`, `ledger`, and `transactions` tables protected by SQLite `BEFORE UPDATE` and `BEFORE DELETE` triggers, written atomically inside the same database transaction as state mutations.
- **Web Hardening**: Strict `Content-Security-Policy` (`script-src 'self'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store` on API responses, `Origin`/`Sec-Fetch-Site` validation, and `X-CSRF-Token` verification.
