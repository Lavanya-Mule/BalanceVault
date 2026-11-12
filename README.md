# BalanceVault — Secure Financial Account and Transaction Management System

**BalanceVault** is a full-stack financial account, double-entry ledger, and transaction management platform built with **Flask**, **SQLite**, and accessible **vanilla JavaScript**.

Every financial transaction in BalanceVault is **server-authorized**, **processed at most once**, **recorded as balanced double-entry debit/credit ledger entries**, **protected against concurrency races and deadlocks**, and **captured in an immutable audit trail**.

---

## Tech Stack

- **Backend:** Python 3, Flask (`Flask>=3.0`), `werkzeug.security`
- **Database:** SQLite (`WAL` mode, `synchronous=FULL`, foreign keys, `CHECK` constraints, immutability triggers)
- **Frontend:** Semantic HTML5, responsive CSS (light/dark themes), CSP-compliant vanilla JavaScript (native `<dialog>` modals, no inline scripts/handlers)
- **Testing:** Python `unittest` (`tests/test_app.py`)

---

## Project Structure

```text
balancevault/
├── app.py              # Flask application, SQLite schema/triggers, RBAC, ledger engine, API routes
├── requirements.txt    # Python dependencies
├── README.md           # Project documentation
├── .gitignore          # Excludes local *.db files, __pycache__, .venv, and .env
├── static/
│   ├── index.html      # Single-page UI shell and native <dialog> modals
│   ├── styles.css      # Light/dark responsive styles and accessible form/modal rules
│   └── app.js          # Client state management, CSRF headers, ledger & admin views
└── tests/
    └── test_app.py     # End-to-end automated unit, RBAC, concurrency, and immutability tests
```

---

## Getting Started

### 1. Install Dependencies
```bash
cd balancevault
pip install -r requirements.txt
```

### 2. Run the Application

**Windows PowerShell:**
```powershell
$env:BV_SECRET="replace-with-random-secret"
python app.py
```

**Linux / macOS:**
```bash
BV_SECRET="$(openssl rand -hex 32)" python app.py
```

Open **http://127.0.0.1:5000** in your browser.

- **Default Administrator:** `admin` / `Admin@123` (override on first initialization with `BV_ADMIN_PW`).
- **System Reserve Account:** `SYSTEM-0000` is automatically provisioned to back deposits and withdrawals so total balances across all accounts always sum to `0`.

### Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `BV_DB` | `balancevault.db` | Path to the SQLite database file |
| `BV_SECRET` | Random 32-byte hex per process | Flask session signing key |
| `BV_ADMIN_PW` | `Admin@123` | Initial password for seeded `admin` account |
| `BV_COOKIE_SECURE` | `""` (`false`) | Set to `1` or `true` behind HTTPS |
| `BV_LOGIN_MAX_ATTEMPTS` | `10` | Failed login attempts allowed per 60-second window |

---

## Core Objectives & Architecture

1. **User Authentication & Session Management**
   - Salted password hashing via `werkzeug.security`, `HttpOnly` + `SameSite=Lax` permanent sessions (`8h` lifetime), session regeneration on login, password rotation (`/api/me/password`), and per-IP/username login rate limiting (`429 Too Many Requests`).

2. **Role-Based Access Control (RBAC)**
   - **`customer`**: Apply for accounts, inspect own accounts/ledgers/transactions, and transfer funds from own active accounts.
   - **`auditor`**: Read-only oversight across all accounts, transactions, double-entry ledgers, users, integrity reconciliation, and audit logs (zero mutation rights).
   - **`admin`**: Manage user status/roles, review account onboarding requests, freeze/unfreeze/close accounts, execute system reserve deposits/withdrawals, and inspect audit/integrity records.
   - Live `role` and `status` are queried from SQLite on every request (`g.user`), so disabled users or demoted sessions lose access immediately.

3. **Account Management & Onboarding Workflow**
   - Customers submit onboarding applications (`checking`, `savings`, or `business` with optional notes) in `pending` status.
   - Enforced state machine (`ACCOUNT_TRANSITIONS`):
     - `pending` → `active` | `rejected`
     - `active` ↔ `frozen`
     - `active` / `frozen` → `closed` (allowed only when `balance_cents == 0`)

4. **Financial Transactions & Double-Entry Ledger**
   - All monetary values are stored and calculated as **integer cents** (`CHECK(balance_cents >= 0 OR is_system = 1)`).
   - Every transfer, deposit, and withdrawal writes a `transactions` record and paired `DEBIT` + `CREDIT` rows in `ledger` with `balance_after_cents` snapshots.
   - `/api/admin/integrity` reconciles every account balance against its ledger sum, checks every transaction for balanced `DEBIT`/`CREDIT` pairs, and verifies global zero-sum conservation (`SUM(balance_cents) == 0`).

5. **Duplicate Prevention (Idempotency)**
   - `UNIQUE(created_by, idem_key)` combined with a SHA-256 `payload_hash` of `(txn_type, from_account, to_account, amount_cents, memo)`.
   - Exact retries return `200 OK` with `replayed: true` without debiting twice.
   - Reusing an idempotency key with altered amount, destination, or memo returns `422 Unprocessable Entity` and logs `IDEMPOTENCY_CONFLICT`.

6. **Concurrency & Deadlock Prevention**
   - SQLite runs in `WAL` mode with `PRAGMA synchronous=FULL` and `PRAGMA busy_timeout=15000`.
   - All balance mutations acquire `BEGIN IMMEDIATE` up front (eliminating read-to-write lock-upgrade deadlocks) and update accounts in deterministic ascending `id` order.

7. **Immutable Audit Trail & Web Security**
   - SQLite `BEFORE UPDATE` and `BEFORE DELETE` triggers make `ledger`, `transactions`, and `audit_log` strictly append-only.
   - Audit events (`REGISTER`, `LOGIN`, `LOGIN_FAILED`, `LOGIN_DENIED`, `LOGOUT`, `PASSWORD_CHANGED`, `ACCOUNT_REQUESTED`, `ACCOUNT_STATUS`, `TRANSFER`, `TRANSFER_DENIED`, `ADMIN_DEPOSIT`, `ADMIN_WITHDRAW`, `IDEMPOTENCY_CONFLICT`, `USER_STATUS`, `USER_ROLE`) commit atomically inside state-changing transactions.
   - Strict `Content-Security-Policy` (`script-src 'self'`, `style-src 'self'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store` on `/api/*`, and `Origin` / `Sec-Fetch-Site` / `X-CSRF-Token` validation.

---

## API Endpoints

| Method & Path | Access | Purpose |
| :--- | :--- | :--- |
| `GET /` | Public | Serve web application |
| `POST /api/register` | Public | Register a new `customer` user |
| `POST /api/login` | Public | Authenticate user and issue session + CSRF token |
| `POST /api/logout` | Authenticated | End session and record `LOGOUT` audit entry |
| `GET /api/me` | Authenticated | Return current user profile, permissions, and CSRF token |
| `POST /api/me/password` | Authenticated | Rotate current user's password |
| `POST /api/accounts` | `customer` | Submit new account onboarding application (`pending`) |
| `GET /api/accounts` | Authenticated | List own accounts (`customer`) or all accounts (`admin`/`auditor`) |
| `GET /api/accounts/<id>/ledger` | Owner / `admin` / `auditor` | Retrieve immutable `DEBIT`/`CREDIT` ledger statement |
| `POST /api/transfers` | `customer` | Execute idempotent atomic transfer between active accounts |
| `GET /api/transactions` | Authenticated | List/filter transactions (`account_id`, `type`, `q`, `limit`) |
| `POST /api/admin/accounts/<id>/status` | `admin` | Approve, reject, freeze, unfreeze, or close an account |
| `POST /api/admin/deposit` | `admin` | Credit an active customer account from `SYSTEM-0000` |
| `POST /api/admin/withdraw` | `admin` | Debit an active customer account to `SYSTEM-0000` |
| `GET /api/admin/users` | `admin` / `auditor` | List users with role, status, and account counts |
| `POST /api/admin/users/<id>/status` | `admin` | Enable or disable a user account |
| `POST /api/admin/users/<id>/role` | `admin` | Update a user's RBAC role (`customer`/`auditor`/`admin`) |
| `GET /api/admin/audit` | `admin` / `auditor` | Query immutable audit log (`action`, `q`, `limit`) |
| `GET /api/admin/integrity` | `admin` / `auditor` | Run full double-entry balance and zero-sum reconciliation |

---

## Testing

Run the automated test suite (uses isolated temporary SQLite databases):

```bash
cd balancevault
python -m unittest tests/test_app.py -v
```

Verify frontend JavaScript syntax:

```bash
node --check static/app.js
```
