(() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const esc = (val) =>
    String(val ?? "").replace(/[&<>"']/g, (ch) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[ch]));
  const money = (cents) => {
    const num = Number(cents || 0) / 100;
    return new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: "USD",
    }).format(num);
  };

  const state = {
    user: null,
    authMode: "login",
    adminTab: "accounts",
    acctStatusFilter: "all",
    txnQuery: "",
    txnTypeFilter: "",
    auditActionFilter: "",
    auditQuery: "",
    pendingIdemKey: crypto.randomUUID(),
    lastTransferPayload: null,
    pendingAccountAction: null,
    pendingFundsOp: null,
  };

  function clearDialogErrors() {
    for (const el of document.querySelectorAll(".dialog-error")) {
      el.textContent = "";
    }
  }

  function setStatus(message, kind = "info") {
    const openDialog = document.querySelector("dialog[open]");
    if (openDialog && kind === "error" && message) {
      let errBox = openDialog.querySelector(".dialog-error");
      if (!errBox) {
        errBox = document.createElement("div");
        errBox.className = "dialog-error";
        errBox.setAttribute("role", "alert");
        const head = openDialog.querySelector(".dialog-head");
        if (head) head.insertAdjacentElement("afterend", errBox);
        else openDialog.prepend(errBox);
      }
      errBox.textContent = message;
      return;
    }
    const el = $("#status-banner");
    el.className = "status-banner" + (message ? ` ${kind}` : "");
    el.textContent = message || "";
  }

  async function api(path, method = "GET", payload = undefined) {
    const headers = {};
    if (payload !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    if (method !== "GET" && state.user?.csrf_token) {
      headers["X-CSRF-Token"] = state.user.csrf_token;
    }
    const res = await fetch(`/api/${path}`, {
      method,
      headers,
      body: payload !== undefined ? JSON.stringify(payload) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg = data.error || `Request failed (${res.status})`;
      setStatus(msg, "error");
      const err = new Error(msg);
      err.status = res.status;
      err.payload = data;
      throw err;
    }
    return data;
  }

  function badge(val) {
    return `<span class="badge ${esc(val)}">${esc(val)}</span>`;
  }

  function renderTable(headers, rows, emptyText = "No records found.") {
    if (!rows.length) {
      return `<div class="empty-state">${esc(emptyText)}</div>`;
    }
    return `
      <div class="table-wrap">
        <table>
          <thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead>
          <tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody>
        </table>
      </div>
    `;
  }

  function renderTopBar() {
    const bar = $("#user-bar");
    const themeLabel = document.documentElement.dataset.theme === "dark" ? "Light Theme" : "Dark Theme";
    const themeBtn = `<button type="button" class="secondary sm" id="theme-toggle">${themeLabel}</button>`;
    if (!state.user) {
      bar.innerHTML = themeBtn;
      return;
    }
    bar.innerHTML = `
      <span><strong>${esc(state.user.username)}</strong> ${badge(state.user.role)}</span>
      ${themeBtn}
      <button type="button" class="secondary sm" id="open-pw-btn">Password</button>
      <button type="button" class="outline sm" id="logout-btn">Sign out</button>
    `;
  }

  function renderAuthView() {
    renderTopBar();
    const isReg = state.authMode === "register";
    $("#app").innerHTML = `
      <section class="auth-shell card" aria-labelledby="auth-heading">
        <div class="auth-tabs" role="tablist" aria-label="Authentication mode">
          <button type="button" class="tab-btn" role="tab" id="tab-login" aria-selected="${!isReg}">Sign In</button>
          <button type="button" class="tab-btn" role="tab" id="tab-register" aria-selected="${isReg}">Create Account</button>
        </div>
        <h2 id="auth-heading">${isReg ? "Register Customer Account" : "Sign In to BalanceVault"}</h2>
        <form id="auth-form">
          <div class="form-group">
            <label for="auth-username">Username <span aria-hidden="true">*</span></label>
            <input id="auth-username" name="username" type="text" required minlength="3" maxlength="30"
              pattern="[A-Za-z0-9_]{3,30}" autocomplete="username" autocorrect="off" autocapitalize="none" spellcheck="false"
              aria-describedby="username-hint">
            <span id="username-hint" class="hint">3–30 characters: letters, digits, or underscores.</span>
          </div>
          ${isReg ? `
            <div class="form-row">
              <div class="form-group">
                <label for="auth-fullname">Full Name</label>
                <input id="auth-fullname" name="full_name" type="text" maxlength="80" autocomplete="name">
              </div>
              <div class="form-group">
                <label for="auth-email">Email</label>
                <input id="auth-email" name="email" type="email" maxlength="120" autocomplete="email" autocorrect="off" autocapitalize="none" spellcheck="false">
              </div>
            </div>
          ` : ""}
          <div class="form-group">
            <label for="auth-password">Password <span aria-hidden="true">*</span></label>
            <div class="password-wrap">
              <input id="auth-password" name="password" type="password" required ${isReg ? 'minlength="8"' : ""}
                autocomplete="${isReg ? "new-password" : "current-password"}"
                aria-describedby="pw-hint">
              <button type="button" class="secondary" id="toggle-pw-vis" aria-pressed="false" aria-label="Show password">Show</button>
            </div>
            <span id="pw-hint" class="hint">${isReg ? "Minimum 8 characters with both letters and digits." : "Enter your BalanceVault password."}</span>
          </div>
          <button type="submit" id="auth-submit">${isReg ? "Create Customer Account" : "Sign In"}</button>
        </form>
      </section>
    `;
  }

  async function renderCustomerView() {
    const qs = new URLSearchParams();
    if (state.txnTypeFilter) qs.set("type", state.txnTypeFilter);
    if (state.txnQuery) qs.set("q", state.txnQuery);
    const [accounts, transactions] = await Promise.all([
      api("accounts"),
      api("transactions" + (qs.toString() ? `?${qs}` : "")),
    ]);

    const activeAccounts = accounts.filter((a) => a.status === "active");
    const pendingCount = accounts.filter((a) => a.status === "pending").length;
    const totalBalance = accounts.reduce((acc, a) => acc + (a.status !== "rejected" ? a.balance_cents : 0), 0);

    const accountRows = accounts.map((a) => [
      `<span class="mono">${esc(a.number)}</span>`,
      `<strong>${esc(a.account_name)}</strong><div class="hint">${esc(a.account_type)}</div>`,
      `<span class="money">${money(a.balance_cents)}</span>`,
      `${badge(a.status)}${a.review_note ? `<div class="hint">${esc(a.review_note)}</div>` : ""}`,
      `<button type="button" class="secondary sm" data-view-ledger="${a.id}" data-acct-num="${esc(a.number)}">View Ledger</button>`,
    ]);

    const txnRows = transactions.map((t) => [
      `<span class="mono">${esc(t.reference)}</span>`,
      badge(t.txn_type),
      `<span class="mono">${esc(t.from_account_number)}</span>`,
      `<span class="mono">${esc(t.to_account_number)}</span>`,
      `<span class="money">${money(t.amount_cents)}</span>`,
      esc(t.memo || "—"),
      `<span class="hint">${esc(t.created_at)}</span>`,
    ]);

    $("#app").innerHTML = `
      <section class="kpi-grid" aria-label="Account summary">
        <div class="kpi-card">
          <div class="kpi-label">Total Balance</div>
          <div class="kpi-value">${money(totalBalance)}</div>
          <div class="kpi-meta">${accounts.length} total account(s)</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Active Accounts</div>
          <div class="kpi-value">${activeAccounts.length}</div>
          <div class="kpi-meta">Ready for transfers</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Pending Onboarding</div>
          <div class="kpi-value">${pendingCount}</div>
          <div class="kpi-meta">Awaiting admin review</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Recent Activity</div>
          <div class="kpi-value">${transactions.length}</div>
          <div class="kpi-meta">Ledger-verified entries</div>
        </div>
      </section>

      <div class="grid-2">
        <section class="card" aria-labelledby="cust-accounts-heading">
          <div class="card-header">
            <h2 id="cust-accounts-heading">My Accounts &amp; Onboarding</h2>
            <button type="button" id="open-acct-btn">Apply for Account</button>
          </div>
          ${renderTable(["Account #", "Label / Type", "Balance", "Status", "Ledger"], accountRows, "No accounts yet. Click 'Apply for Account' to begin onboarding.")}
        </section>

        <section class="card" aria-labelledby="transfer-heading">
          <div class="card-header">
            <h2 id="transfer-heading">Atomic Money Transfer</h2>
          </div>
          ${activeAccounts.length ? `
            <form id="transfer-form">
              <div class="form-group">
                <label for="xfer-from">From Account</label>
                <select id="xfer-from" name="from_account_id" required>
                  ${activeAccounts.map((a) => `<option value="${a.id}">${esc(a.account_name)} (${esc(a.number)}) — ${money(a.balance_cents)}</option>`).join("")}
                </select>
              </div>
              <div class="form-row">
                <div class="form-group">
                  <label for="xfer-to">Destination Account Number</label>
                  <input id="xfer-to" name="to_account_number" type="text" required placeholder="BV-0000000000"
                    autocorrect="off" autocapitalize="none" spellcheck="false">
                </div>
                <div class="form-group">
                  <label for="xfer-amount">Amount (USD)</label>
                  <input id="xfer-amount" name="amount" type="number" step="0.01" min="0.01" required placeholder="25.00">
                </div>
              </div>
              <div class="form-group">
                <label for="xfer-memo">Memo (optional)</label>
                <input id="xfer-memo" name="memo" type="text" maxlength="140" placeholder="Invoice #104 or note">
              </div>
              <div class="idem-box">
                <span>Idempotency Key: <strong class="mono" id="idem-display">${esc(state.pendingIdemKey)}</strong></span>
                <button type="button" class="secondary sm" id="regen-idem-btn">New Key</button>
              </div>
              <div class="btn-group">
                <button type="submit" id="xfer-submit-btn">Send Transfer</button>
                ${state.lastTransferPayload ? `<button type="button" class="outline" id="replay-xfer-btn">Test Duplicate Replay</button>` : ""}
              </div>
            </form>
          ` : `<div class="empty-state">An active approved account is required before sending transfers.</div>`}
        </section>
      </div>

      <section class="card" aria-labelledby="cust-txns-heading">
        <div class="card-header">
          <h2 id="cust-txns-heading">Transaction History</h2>
        </div>
        <search>
          <form id="txn-filter-form" class="filter-bar">
            <label for="txn-q" class="visually-hidden">Search transactions</label>
            <input id="txn-q" type="search" placeholder="Search reference, memo, or account #" value="${esc(state.txnQuery)}">
            <label for="txn-type" class="visually-hidden">Filter by type</label>
            <select id="txn-type">
              <option value="">All types</option>
              <option value="transfer" ${state.txnTypeFilter === "transfer" ? "selected" : ""}>Transfers</option>
              <option value="deposit" ${state.txnTypeFilter === "deposit" ? "selected" : ""}>Deposits</option>
              <option value="withdrawal" ${state.txnTypeFilter === "withdrawal" ? "selected" : ""}>Withdrawals</option>
            </select>
            <button type="submit" class="secondary sm">Apply Filter</button>
          </form>
        </search>
        ${renderTable(["Reference", "Type", "From", "To", "Amount", "Memo", "Timestamp"], txnRows, "No transactions match the current filter.")}
      </section>
    `;
  }

  async function renderAdminView() {
    const isAdmin = state.user.role === "admin";
    const txnQs = new URLSearchParams();
    if (state.txnTypeFilter) txnQs.set("type", state.txnTypeFilter);
    if (state.txnQuery) txnQs.set("q", state.txnQuery);

    const auditQs = new URLSearchParams();
    if (state.auditActionFilter) auditQs.set("action", state.auditActionFilter);
    if (state.auditQuery) auditQs.set("q", state.auditQuery);

    const [accounts, users, auditLogs, integrity, transactions] = await Promise.all([
      api("accounts"),
      api("admin/users"),
      api("admin/audit" + (auditQs.toString() ? `?${auditQs}` : "")),
      api("admin/integrity"),
      api("transactions" + (txnQs.toString() ? `?${txnQs}` : "")),
    ]);

    const filteredAccounts = accounts.filter((a) =>
      state.acctStatusFilter === "all" ? true : a.status === state.acctStatusFilter
    );

    const acctRows = filteredAccounts.map((a) => {
      const actions = [];
      if (!a.is_system) {
        actions.push(`<button type="button" class="secondary sm" data-view-ledger="${a.id}" data-acct-num="${esc(a.number)}">Ledger</button>`);
        if (isAdmin) {
          if (a.status === "pending") {
            actions.push(`<button type="button" class="sm" data-acct-status="active" data-acct-id="${a.id}" data-acct-num="${esc(a.number)}">Approve</button>`);
            actions.push(`<button type="button" class="danger sm" data-acct-status="rejected" data-acct-id="${a.id}" data-acct-num="${esc(a.number)}">Reject</button>`);
          } else if (a.status === "active") {
            actions.push(`<button type="button" class="outline sm" data-funds-op="deposit" data-acct-id="${a.id}" data-acct-num="${esc(a.number)}">Deposit</button>`);
            actions.push(`<button type="button" class="secondary sm" data-funds-op="withdraw" data-acct-id="${a.id}" data-acct-num="${esc(a.number)}">Withdraw</button>`);
            actions.push(`<button type="button" class="secondary sm" data-acct-status="frozen" data-acct-id="${a.id}" data-acct-num="${esc(a.number)}">Freeze</button>`);
            if (a.balance_cents === 0) {
              actions.push(`<button type="button" class="danger sm" data-acct-status="closed" data-acct-id="${a.id}" data-acct-num="${esc(a.number)}">Close</button>`);
            }
          } else if (a.status === "frozen") {
            actions.push(`<button type="button" class="sm" data-acct-status="active" data-acct-id="${a.id}" data-acct-num="${esc(a.number)}">Unfreeze</button>`);
            if (a.balance_cents === 0) {
              actions.push(`<button type="button" class="danger sm" data-acct-status="closed" data-acct-id="${a.id}" data-acct-num="${esc(a.number)}">Close</button>`);
            }
          }
        }
      } else {
        actions.push(`<button type="button" class="secondary sm" data-view-ledger="${a.id}" data-acct-num="${esc(a.number)}">Reserve Ledger</button>`);
      }

      return [
        `<span class="mono">${esc(a.number)}</span>`,
        `<strong>${esc(a.account_name)}</strong><div class="hint">${esc(a.account_type)}${a.onboarding_notes ? ` · ${esc(a.onboarding_notes)}` : ""}</div>`,
        a.username ? `${esc(a.username)}${a.full_name ? `<div class="hint">${esc(a.full_name)}</div>` : ""}` : `<span class="badge admin">SYSTEM</span>`,
        `<span class="money">${money(a.balance_cents)}</span>`,
        `${badge(a.status)}${a.review_note ? `<div class="hint">${esc(a.review_note)}</div>` : ""}`,
        `<div class="btn-group">${actions.join("")}</div>`,
      ];
    });

    const userRows = users.map((u) => {
      const isSelf = u.id === state.user.id;
      const controls = isAdmin && !isSelf
        ? `<div class="btn-group">
            <select class="user-role-select" data-user-id="${u.id}" aria-label="Role for ${esc(u.username)}">
              <option value="customer" ${u.role === "customer" ? "selected" : ""}>customer</option>
              <option value="auditor" ${u.role === "auditor" ? "selected" : ""}>auditor</option>
              <option value="admin" ${u.role === "admin" ? "selected" : ""}>admin</option>
            </select>
            <button type="button" class="${u.status === "active" ? "danger" : "sm"} sm" data-toggle-user="${u.id}" data-next-status="${u.status === "active" ? "disabled" : "active"}">
              ${u.status === "active" ? "Disable" : "Enable"}
            </button>
          </div>`
        : `<span class="hint">${isSelf ? "Current user" : "Read-only"}</span>`;

      return [
        u.id,
        `<strong>${esc(u.username)}</strong>${u.full_name ? `<div class="hint">${esc(u.full_name)}</div>` : ""}`,
        badge(u.role),
        badge(u.status),
        u.account_count,
        `<span class="hint">${esc(u.created_at)}</span>`,
        controls,
      ];
    });

    const txnRows = transactions.map((t) => [
      `<span class="mono">${esc(t.reference)}</span>`,
      badge(t.txn_type),
      `<span class="mono">${esc(t.from_account_number)}</span>`,
      `<span class="mono">${esc(t.to_account_number)}</span>`,
      `<span class="money">${money(t.amount_cents)}</span>`,
      esc(t.created_by_username),
      esc(t.memo || "—"),
      `<span class="hint">${esc(t.created_at)}</span>`,
    ]);

    const auditRows = auditLogs.map((l) => [
      l.id,
      `${esc(l.actor)} ${badge(l.actor_role)}`,
      `<span class="mono">${esc(l.action)}</span>`,
      l.target_type ? `${esc(l.target_type)} #${esc(l.target_id)}` : "—",
      esc(l.detail),
      `<span class="mono">${esc(l.ip_address)}</span>`,
      `<span class="hint">${esc(l.created_at)}</span>`,
    ]);

    const pendingCount = accounts.filter((a) => a.status === "pending").length;

    let tabBody = "";
    if (state.adminTab === "accounts") {
      tabBody = `
        <section class="card" aria-labelledby="admin-accts-title">
          <div class="card-header">
            <h2 id="admin-accts-title">Accounts &amp; Onboarding Review</h2>
            <div class="filter-bar">
              <label for="acct-status-filter" class="visually-hidden">Filter accounts by status</label>
              <select id="acct-status-filter">
                <option value="all" ${state.acctStatusFilter === "all" ? "selected" : ""}>All statuses</option>
                <option value="pending" ${state.acctStatusFilter === "pending" ? "selected" : ""}>Pending (${pendingCount})</option>
                <option value="active" ${state.acctStatusFilter === "active" ? "selected" : ""}>Active</option>
                <option value="frozen" ${state.acctStatusFilter === "frozen" ? "selected" : ""}>Frozen</option>
                <option value="rejected" ${state.acctStatusFilter === "rejected" ? "selected" : ""}>Rejected</option>
                <option value="closed" ${state.acctStatusFilter === "closed" ? "selected" : ""}>Closed</option>
              </select>
            </div>
          </div>
          ${renderTable(["Account #", "Label & Notes", "Owner", "Balance", "Status", "Actions"], acctRows)}
        </section>
      `;
    } else if (state.adminTab === "transactions") {
      tabBody = `
        <section class="card" aria-labelledby="admin-txns-title">
          <div class="card-header"><h2 id="admin-txns-title">Global Transaction Ledger</h2></div>
          <search>
            <form id="txn-filter-form" class="filter-bar">
              <label for="txn-q" class="visually-hidden">Search transactions</label>
              <input id="txn-q" type="search" placeholder="Reference, memo, or account #" value="${esc(state.txnQuery)}">
              <label for="txn-type" class="visually-hidden">Transaction type</label>
              <select id="txn-type">
                <option value="">All types</option>
                <option value="transfer" ${state.txnTypeFilter === "transfer" ? "selected" : ""}>Transfers</option>
                <option value="deposit" ${state.txnTypeFilter === "deposit" ? "selected" : ""}>Deposits</option>
                <option value="withdrawal" ${state.txnTypeFilter === "withdrawal" ? "selected" : ""}>Withdrawals</option>
              </select>
              <button type="submit" class="secondary sm">Apply</button>
            </form>
          </search>
          ${renderTable(["Reference", "Type", "From", "To", "Amount", "Actor", "Memo", "Timestamp"], txnRows)}
        </section>
      `;
    } else if (state.adminTab === "users") {
      tabBody = `
        <section class="card" aria-labelledby="admin-users-title">
          <div class="card-header"><h2 id="admin-users-title">Users &amp; Role-Based Access Control</h2></div>
          ${renderTable(["ID", "User", "Role", "Status", "Accounts", "Created", "Controls"], userRows)}
        </section>
      `;
    } else {
      tabBody = `
        <section class="card" aria-labelledby="admin-audit-title">
          <div class="card-header"><h2 id="admin-audit-title">Immutable Security &amp; Operations Audit Trail</h2></div>
          <search>
            <form id="audit-filter-form" class="filter-bar">
              <label for="audit-q" class="visually-hidden">Search audit trail</label>
              <input id="audit-q" type="search" placeholder="Actor, target ID, or detail" value="${esc(state.auditQuery)}">
              <label for="audit-action" class="visually-hidden">Filter by action</label>
              <select id="audit-action">
                <option value="">All actions</option>
                ${["REGISTER", "LOGIN", "LOGIN_FAILED", "LOGIN_DENIED", "LOGOUT", "ACCOUNT_REQUESTED", "ACCOUNT_STATUS", "TRANSFER", "TRANSFER_DENIED", "ADMIN_DEPOSIT", "ADMIN_WITHDRAW", "IDEMPOTENCY_CONFLICT", "USER_STATUS", "USER_ROLE", "PASSWORD_CHANGED"].map((act) =>
                  `<option value="${act}" ${state.auditActionFilter === act ? "selected" : ""}>${act}</option>`
                ).join("")}
              </select>
              <button type="submit" class="secondary sm">Filter Audit</button>
            </form>
          </search>
          ${renderTable(["#", "Actor", "Action", "Target", "Detail", "IP", "Timestamp"], auditRows)}
        </section>
      `;
    }

    $("#app").innerHTML = `
      <section class="kpi-grid" aria-label="System telemetry">
        <div class="kpi-card">
          <div class="kpi-label">Customer Float</div>
          <div class="kpi-value">${money(integrity.customer_float_cents)}</div>
          <div class="kpi-meta">Offset by SYSTEM-0000</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Pending Onboarding</div>
          <div class="kpi-value">${pendingCount}</div>
          <div class="kpi-meta">${accounts.length} total accounts</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Transactions</div>
          <div class="kpi-value">${integrity.transaction_count}</div>
          <div class="kpi-meta">${integrity.ledger_entry_count} ledger rows</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Users</div>
          <div class="kpi-value">${users.length}</div>
          <div class="kpi-meta">RBAC enforced server-side</div>
        </div>
      </section>

      <section class="card integrity-box" aria-label="Double-entry integrity status">
        <div>
          <strong>Ledger Integrity:</strong>
          ${integrity.balanced
            ? `${badge("ok")} Zero-sum verified (${money(integrity.total_balance_sum)}), all accounts &amp; transactions reconciled`
            : `${badge("rejected")} Discrepancy detected (${integrity.mismatched_accounts.length} accounts, ${integrity.unbalanced_transactions.length} txns)`}
          <div class="hint">Checked at ${esc(integrity.checked_at)}</div>
        </div>
        <button type="button" class="secondary sm" id="refresh-integrity-btn">Re-run Reconciliation</button>
      </section>

      <nav class="tabs" role="tablist" aria-label="Administration sections">
        <button type="button" class="tab-btn" role="tab" data-admin-tab="accounts" aria-selected="${state.adminTab === "accounts"}">Accounts (${accounts.length})</button>
        <button type="button" class="tab-btn" role="tab" data-admin-tab="transactions" aria-selected="${state.adminTab === "transactions"}">Transactions (${transactions.length})</button>
        <button type="button" class="tab-btn" role="tab" data-admin-tab="users" aria-selected="${state.adminTab === "users"}">Users &amp; RBAC (${users.length})</button>
        <button type="button" class="tab-btn" role="tab" data-admin-tab="audit" aria-selected="${state.adminTab === "audit"}">Audit Trail (${auditLogs.length})</button>
      </nav>

      ${tabBody}
    `;
  }

  async function renderDashboard() {
    renderTopBar();
    if (!state.user) {
      renderAuthView();
      return;
    }
    if (state.user.role === "admin" || state.user.role === "auditor") {
      await renderAdminView();
    } else {
      await renderCustomerView();
    }
  }

  async function boot() {
    try {
      state.user = await api("me");
      await renderDashboard();
    } catch {
      state.user = null;
      setStatus("");
      renderAuthView();
    }
  }

  async function openLedgerModal(accountId, accountNumber) {
    const entries = await api(`accounts/${accountId}/ledger`);
    $("#ledger-dialog-subtitle").textContent = `Account ${accountNumber} — immutable DEBIT / CREDIT statement`;
    const rows = entries.map((e) => [
      `<span class="mono">${esc(e.reference)}</span>`,
      badge(e.entry_type),
      `<span class="money">${money(e.amount_cents)}</span>`,
      `<span class="money">${money(e.balance_after_cents)}</span>`,
      `<span class="mono">${esc(e.entry_type === "DEBIT" ? e.to_account_number : e.from_account_number)}</span>`,
      esc(e.memo || "—"),
      `<span class="hint">${esc(e.created_at)}</span>`,
    ]);
    $("#ledger-dialog-body").innerHTML = renderTable(
      ["Reference", "Entry", "Amount", "Balance After", "Counterparty", "Memo", "Timestamp"],
      rows,
      "No ledger entries recorded for this account yet."
    );
    $("#ledger-dialog").showModal();
  }

  // Fallback for browsers lacking native closedby="any"
  if (!("closedBy" in HTMLDialogElement.prototype)) {
    const outside = (e, dialog) => {
      const r = dialog.getBoundingClientRect();
      return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
    };
    for (const dialog of document.querySelectorAll('dialog[closedby="any"]')) {
      let pressedOutside = false;
      dialog.addEventListener("pointerdown", (e) => {
        pressedOutside = outside(e, dialog);
      });
      dialog.addEventListener("pointerup", (e) => {
        if (pressedOutside && outside(e, dialog)) {
          dialog.close();
        }
      });
    }
  }

  document.addEventListener("click", async (e) => {
    const rawTarget = e.target;
    if (!(rawTarget instanceof Element)) return;
    const target = rawTarget.closest("button, [data-close-dialog], [data-admin-tab], [data-view-ledger], [data-acct-status], [data-funds-op], [data-toggle-user]") || rawTarget;

    if (target.dataset.closeDialog) {
      document.getElementById(target.dataset.closeDialog)?.close();
      return;
    }
    if (target.id === "theme-toggle") {
      const current = document.documentElement.dataset.theme;
      const next = current === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = next;
      localStorage.setItem("bv-theme", next);
      renderTopBar();
      return;
    }
    if (target.id === "tab-login") {
      state.authMode = "login";
      setStatus("");
      renderAuthView();
      return;
    }
    if (target.id === "tab-register") {
      state.authMode = "register";
      setStatus("");
      renderAuthView();
      return;
    }
    if (target.id === "toggle-pw-vis") {
      const input = $("#auth-password");
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      target.setAttribute("aria-pressed", String(show));
      target.textContent = show ? "Hide" : "Show";
      return;
    }
    if (target.id === "logout-btn") {
      await api("logout", "POST", {});
      state.user = null;
      state.lastTransferPayload = null;
      state.pendingIdemKey = crypto.randomUUID();
      setStatus("Signed out securely.", "info");
      renderAuthView();
      return;
    }
    if (target.id === "open-pw-btn") {
      clearDialogErrors();
      $("#password-form").reset();
      $("#password-dialog").showModal();
      return;
    }
    if (target.id === "open-acct-btn") {
      clearDialogErrors();
      $("#open-account-dialog").showModal();
      return;
    }
    if (target.id === "regen-idem-btn") {
      state.pendingIdemKey = crypto.randomUUID();
      const disp = $("#idem-display");
      if (disp) disp.textContent = state.pendingIdemKey;
      return;
    }
    if (target.id === "replay-xfer-btn" && state.lastTransferPayload) {
      try {
        const res = await api("transfers", "POST", state.lastTransferPayload);
        setStatus(
          res.replayed
            ? `Idempotency verified: duplicate request ${res.reference} replayed safely (no extra debit).`
            : `Transfer ${res.reference} completed.`,
          "info"
        );
        await renderDashboard();
      } catch {
        // Status banner updated by api()
      }
      return;
    }
    if (target.id === "refresh-integrity-btn") {
      setStatus("Reconciliation verified.", "success");
      await renderDashboard();
      return;
    }
    if (target.dataset.adminTab) {
      state.adminTab = target.dataset.adminTab;
      await renderDashboard();
      return;
    }
    if (target.dataset.viewLedger) {
      await openLedgerModal(target.dataset.viewLedger, target.dataset.acctNum);
      return;
    }
    if (target.dataset.acctStatus) {
      clearDialogErrors();
      state.pendingAccountAction = {
        id: Number(target.dataset.acctId),
        number: target.dataset.acctNum,
        status: target.dataset.acctStatus,
      };
      $("#account-action-summary").textContent =
        `Transition account ${state.pendingAccountAction.number} to "${state.pendingAccountAction.status}".`;
      $("#action-review-note").value = "";
      $("#account-action-dialog").showModal();
      return;
    }
    if (target.dataset.fundsOp) {
      clearDialogErrors();
      state.pendingFundsOp = {
        op: target.dataset.fundsOp,
        id: Number(target.dataset.acctId),
        number: target.dataset.acctNum,
      };
      $("#admin-funds-title").textContent =
        state.pendingFundsOp.op === "deposit" ? "Admin System Deposit" : "Admin System Withdrawal";
      $("#admin-funds-summary").textContent =
        `${state.pendingFundsOp.op === "deposit" ? "Credit" : "Debit"} account ${state.pendingFundsOp.number} against SYSTEM-0000.`;
      $("#admin-funds-form").reset();
      $("#admin-funds-dialog").showModal();
      return;
    }
    if (target.dataset.toggleUser) {
      try {
        await api(`admin/users/${target.dataset.toggleUser}/status`, "POST", {
          status: target.dataset.nextStatus,
        });
        setStatus(`User status updated to ${target.dataset.nextStatus}.`, "success");
        await renderDashboard();
      } catch {
        // handled
      }
    }
  });

  document.addEventListener("change", async (e) => {
    const target = e.target;
    if (target.id === "acct-status-filter") {
      state.acctStatusFilter = target.value;
      await renderDashboard();
      return;
    }
    if (target.classList.contains("user-role-select")) {
      const uid = target.dataset.userId;
      try {
        await api(`admin/users/${uid}/role`, "POST", { role: target.value });
        setStatus(`Updated user role to ${target.value}.`, "success");
        await renderDashboard();
      } catch {
        await renderDashboard();
      }
    }
  });

  document.addEventListener("submit", async (e) => {
    const form = e.target;
    e.preventDefault();

    if (form.id === "auth-form") {
      const submitBtn = $("#auth-submit");
      submitBtn.disabled = true;
      const fd = new FormData(form);
      const payload = Object.fromEntries(fd.entries());
      try {
        if (state.authMode === "register") {
          await api("register", "POST", payload);
          state.authMode = "login";
          setStatus("Registration successful. Please sign in.", "success");
          renderAuthView();
        } else {
          state.user = await api("login", "POST", payload);
          state.lastTransferPayload = null;
          state.pendingIdemKey = crypto.randomUUID();
          setStatus(`Welcome back, ${state.user.username}.`, "success");
          await renderDashboard();
        }
      } catch {
        // handled in api()
      } finally {
        if ($("#auth-submit")) $("#auth-submit").disabled = false;
      }
      return;
    }

    if (form.id === "open-account-form") {
      const fd = new FormData(form);
      try {
        const res = await api("accounts", "POST", Object.fromEntries(fd.entries()));
        $("#open-account-dialog").close();
        form.reset();
        setStatus(`Account ${res.number} submitted for administrator approval.`, "success");
        await renderDashboard();
      } catch {
        // handled
      }
      return;
    }

    if (form.id === "transfer-form") {
      const btn = $("#xfer-submit-btn");
      btn.disabled = true;
      const fd = new FormData(form);
      const amountCents = Math.round(Number(fd.get("amount")) * 100);
      const payload = {
        from_account_id: Number(fd.get("from_account_id")),
        to_account_number: String(fd.get("to_account_number") || "").trim(),
        amount_cents: amountCents,
        idempotency_key: state.pendingIdemKey,
        memo: String(fd.get("memo") || "").trim(),
      };
      try {
        const res = await api("transfers", "POST", payload);
        state.lastTransferPayload = payload;
        state.pendingIdemKey = crypto.randomUUID();
        setStatus(
          res.replayed
            ? `Duplicate request ignored — original transaction ${res.reference} returned.`
            : `Transfer ${res.reference} processed (${money(res.amount_cents)}).`,
          "success"
        );
        await renderDashboard();
      } catch (err) {
        if (err.status && err.status < 500) {
          state.pendingIdemKey = crypto.randomUUID();
          const disp = $("#idem-display");
          if (disp) disp.textContent = state.pendingIdemKey;
        }
      } finally {
        if ($("#xfer-submit-btn")) $("#xfer-submit-btn").disabled = false;
      }
      return;
    }

    if (form.id === "txn-filter-form") {
      state.txnQuery = $("#txn-q").value.trim();
      state.txnTypeFilter = $("#txn-type").value;
      await renderDashboard();
      return;
    }

    if (form.id === "audit-filter-form") {
      state.auditQuery = $("#audit-q").value.trim();
      state.auditActionFilter = $("#audit-action").value;
      await renderDashboard();
      return;
    }

    if (form.id === "account-action-form" && state.pendingAccountAction) {
      const { id, number, status } = state.pendingAccountAction;
      try {
        await api(`admin/accounts/${id}/status`, "POST", {
          status,
          review_note: $("#action-review-note").value.trim(),
        });
        $("#account-action-dialog").close();
        setStatus(`Account ${number} updated to ${status}.`, "success");
        await renderDashboard();
      } catch {
        // handled
      }
      return;
    }

    if (form.id === "admin-funds-form" && state.pendingFundsOp) {
      const { op, id, number } = state.pendingFundsOp;
      const fd = new FormData(form);
      const amountCents = Math.round(Number(fd.get("amount")) * 100);
      try {
        const res = await api(`admin/${op}`, "POST", {
          account_id: id,
          amount_cents: amountCents,
          idempotency_key: crypto.randomUUID(),
          memo: String(fd.get("memo") || "").trim(),
        });
        $("#admin-funds-dialog").close();
        setStatus(`${op === "deposit" ? "Deposit" : "Withdrawal"} ${res.reference} on ${number} succeeded.`, "success");
        await renderDashboard();
      } catch {
        // handled
      }
      return;
    }

    if (form.id === "password-form") {
      const fd = new FormData(form);
      try {
        await api("me/password", "POST", Object.fromEntries(fd.entries()));
        $("#password-dialog").close();
        form.reset();
        setStatus("Password updated successfully.", "success");
      } catch {
        // handled
      }
    }
  });

  const savedTheme = localStorage.getItem("bv-theme");
  if (savedTheme === "dark" || savedTheme === "light") {
    document.documentElement.dataset.theme = savedTheme;
  }

  boot();
})();
