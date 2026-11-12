import os
import sqlite3
import tempfile
import threading
import unittest
import uuid

os.environ["BV_DB"] = os.path.join(tempfile.mkdtemp(), "test_balancevault.db")
os.environ["BV_LOGIN_MAX_ATTEMPTS"] = "5"

import app as bv  # noqa: E402


def make_client(username, password, register=False):
    client = bv.app.test_client()
    if register:
        res = client.post("/api/register", json={
            "username": username,
            "password": password,
            "full_name": f"{username.title()} User",
            "email": f"{username}@example.com",
        })
        assert res.status_code == 201, res.get_json()
    res = client.post("/api/login", json={"username": username, "password": password})
    assert res.status_code == 200, res.get_json()
    return client


class BalanceVaultTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin = make_client("admin", "Admin@123")
        cls.alice = make_client("alice", "Passw0rd1", register=True)
        cls.bob = make_client("bob", "Passw0rd2", register=True)

        # Create an auditor user via registration + admin role promotion
        cls.auditor = make_client("auditor1", "AuditPass1", register=True)
        auditor_id = cls.auditor.get("/api/me").get_json()["id"]
        r = cls.admin.post(f"/api/admin/users/{auditor_id}/role", json={"role": "auditor"})
        assert r.status_code == 200, r.get_json()

        # Open and fund accounts for alice and bob
        cls.alice_acct = cls.alice.post("/api/accounts", json={
            "account_name": "Alice Checking",
            "account_type": "checking",
            "onboarding_notes": "Primary payroll",
        }).get_json()["id"]
        cls.bob_acct = cls.bob.post("/api/accounts", json={
            "account_name": "Bob Savings",
            "account_type": "savings",
        }).get_json()["id"]

        for aid in (cls.alice_acct, cls.bob_acct):
            assert cls.admin.post(
                f"/api/admin/accounts/{aid}/status",
                json={"status": "active", "review_note": "KYC verified"},
            ).status_code == 200
            assert cls.admin.post(
                "/api/admin/deposit",
                json={"account_id": aid, "amount_cents": 100_000, "idempotency_key": str(uuid.uuid4())},
            ).status_code == 201

        accounts = {a["id"]: a["number"] for a in cls.admin.get("/api/accounts").get_json()}
        cls.alice_num = accounts[cls.alice_acct]
        cls.bob_num = accounts[cls.bob_acct]

    def transfer(self, client, from_id, to_num, amount, key=None, memo="test"):
        return client.post("/api/transfers", json={
            "from_account_id": from_id,
            "to_account_number": to_num,
            "amount_cents": amount,
            "idempotency_key": key or str(uuid.uuid4()),
            "memo": memo,
        })

    def balance_of(self, acct_id):
        rows = self.admin.get("/api/accounts").get_json()
        return next(r["balance_cents"] for r in rows if r["id"] == acct_id)

    def test_01_auth_and_password_rotation(self):
        anon = bv.app.test_client()
        self.assertEqual(anon.get("/api/accounts").status_code, 401)
        self.assertEqual(anon.post("/api/register", json={"username": "ab", "password": "123"}).status_code, 400)
        self.assertEqual(anon.post("/api/register", json={"username": "alice", "password": "Password1"}).status_code, 409)

        c = make_client("pwuser", "Initial123", register=True)
        self.assertEqual(c.post("/api/me/password", json={"current_password": "wrong", "new_password": "NewPass123"}).status_code, 401)
        self.assertEqual(c.post("/api/me/password", json={"current_password": "Initial123", "new_password": "NewPass123"}).status_code, 200)
        c.post("/api/logout", json={})
        self.assertEqual(c.post("/api/login", json={"username": "pwuser", "password": "Initial123"}).status_code, 401)
        self.assertEqual(c.post("/api/login", json={"username": "pwuser", "password": "NewPass123"}).status_code, 200)

    def test_02_login_rate_limiting(self):
        anon = bv.app.test_client()
        uname = f"ratelimit_{uuid.uuid4().hex[:6]}"
        for _ in range(5):
            r = anon.post("/api/login", json={"username": uname, "password": "wrong"})
            self.assertEqual(r.status_code, 401)
        blocked = anon.post("/api/login", json={"username": uname, "password": "wrong"})
        self.assertEqual(blocked.status_code, 429)

    def test_03_rbac_and_live_session_enforcement(self):
        # Customer denied admin/auditor routes
        self.assertEqual(self.alice.get("/api/admin/users").status_code, 403)
        self.assertEqual(self.alice.get("/api/admin/audit").status_code, 403)
        self.assertEqual(self.alice.get("/api/admin/integrity").status_code, 403)
        self.assertEqual(self.alice.post("/api/admin/deposit", json={}).status_code, 403)
        # Customer cannot view Bob's ledger or transfer from Bob's account
        self.assertEqual(self.alice.get(f"/api/accounts/{self.bob_acct}/ledger").status_code, 404)
        self.assertEqual(self.transfer(self.alice, self.bob_acct, self.alice_num, 100).status_code, 403)
        # Customer cannot transfer to SYSTEM-0000
        self.assertEqual(self.transfer(self.alice, self.alice_acct, "SYSTEM-0000", 100).status_code, 403)

        # Auditor has read-only access to oversight endpoints, zero mutation rights
        self.assertEqual(self.auditor.get("/api/accounts").status_code, 200)
        self.assertEqual(self.auditor.get("/api/admin/audit").status_code, 200)
        self.assertEqual(self.auditor.get("/api/admin/integrity").status_code, 200)
        self.assertEqual(self.auditor.get(f"/api/accounts/{self.alice_acct}/ledger").status_code, 200)
        self.assertEqual(self.auditor.post("/api/accounts", json={"account_name": "Nope"}).status_code, 403)
        self.assertEqual(self.auditor.post(f"/api/admin/accounts/{self.alice_acct}/status", json={"status": "frozen"}).status_code, 403)

        # Live disabling immediately revokes active session
        temp_user = make_client("tempuser", "TempPass1", register=True)
        uid = temp_user.get("/api/me").get_json()["id"]
        self.assertEqual(self.admin.post(f"/api/admin/users/{uid}/status", json={"status": "disabled"}).status_code, 200)
        self.assertEqual(temp_user.get("/api/accounts").status_code, 401)
        self.assertEqual(bv.app.test_client().post("/api/login", json={"username": "tempuser", "password": "TempPass1"}).status_code, 403)

        # Cannot disable or demote last active admin
        admin_id = self.admin.get("/api/me").get_json()["id"]
        self.assertEqual(self.admin.post(f"/api/admin/users/{admin_id}/status", json={"status": "disabled"}).status_code, 400)

    def test_04_account_onboarding_lifecycle(self):
        r = self.alice.post("/api/accounts", json={"account_name": "Temp Account", "account_type": "business"})
        self.assertEqual(r.status_code, 201)
        aid = r.get_json()["id"]
        anum = r.get_json()["number"]

        # Pending account cannot send or receive
        self.assertEqual(self.transfer(self.alice, aid, self.bob_num, 100).status_code, 409)
        self.assertEqual(self.transfer(self.bob, self.bob_acct, anum, 100).status_code, 409)

        # Approve, deposit, freeze, unfreeze, withdraw, close
        self.assertEqual(self.admin.post(f"/api/admin/accounts/{aid}/status", json={"status": "active"}).status_code, 200)
        self.assertEqual(self.admin.post("/api/admin/deposit", json={"account_id": aid, "amount_cents": 500, "idempotency_key": str(uuid.uuid4())}).status_code, 201)
        self.assertEqual(self.admin.post(f"/api/admin/accounts/{aid}/status", json={"status": "frozen", "review_note": "Review"}).status_code, 200)
        self.assertEqual(self.transfer(self.alice, aid, self.bob_num, 100).status_code, 409)
        # Cannot close with non-zero balance
        self.assertEqual(self.admin.post(f"/api/admin/accounts/{aid}/status", json={"status": "closed"}).status_code, 409)
        self.assertEqual(self.admin.post(f"/api/admin/accounts/{aid}/status", json={"status": "active"}).status_code, 200)
        self.assertEqual(self.admin.post("/api/admin/withdraw", json={"account_id": aid, "amount_cents": 500, "idempotency_key": str(uuid.uuid4())}).status_code, 201)
        self.assertEqual(self.admin.post(f"/api/admin/accounts/{aid}/status", json={"status": "closed"}).status_code, 200)
        # Closed is terminal
        self.assertEqual(self.admin.post(f"/api/admin/accounts/{aid}/status", json={"status": "active"}).status_code, 409)

    def test_05_validation_and_idempotency(self):
        self.assertEqual(self.transfer(self.alice, self.alice_acct, self.bob_num, -50).status_code, 400)
        self.assertEqual(self.transfer(self.alice, self.alice_acct, self.bob_num, 12.34).status_code, 400)
        self.assertEqual(self.transfer(self.alice, self.alice_acct, self.alice_num, 100).status_code, 400)
        self.assertEqual(self.transfer(self.alice, self.alice_acct, self.bob_num, 10**9).status_code, 409)

        key = str(uuid.uuid4())
        before = self.balance_of(self.alice_acct)
        r1 = self.transfer(self.alice, self.alice_acct, self.bob_num, 750, key=key, memo="invoice 1")
        r2 = self.transfer(self.alice, self.alice_acct, self.bob_num, 750, key=key, memo="invoice 1")
        self.assertEqual((r1.status_code, r2.status_code), (201, 200))
        self.assertFalse(r1.get_json()["replayed"])
        self.assertTrue(r2.get_json()["replayed"])
        self.assertEqual(self.balance_of(self.alice_acct), before - 750)

        # Reusing same key with different amount OR different destination OR different memo must return 422
        self.assertEqual(self.transfer(self.alice, self.alice_acct, self.bob_num, 751, key=key, memo="invoice 1").status_code, 422)
        self.assertEqual(self.transfer(self.alice, self.alice_acct, self.bob_num, 750, key=key, memo="tampered").status_code, 422)

        # Create third account to verify destination mismatch triggers 422
        charlie = make_client("charlie", "Charl1ePass", register=True)
        c_acct = charlie.post("/api/accounts", json={"account_name": "Charlie"}).get_json()
        self.admin.post(f"/api/admin/accounts/{c_acct['id']}/status", json={"status": "active"})
        self.assertEqual(self.transfer(self.alice, self.alice_acct, c_acct["number"], 750, key=key, memo="invoice 1").status_code, 422)

    def test_06_concurrent_transfers_and_duplicate_race(self):
        # 1) Opposite bidirectional concurrent transfers
        combined_before = self.balance_of(self.alice_acct) + self.balance_of(self.bob_acct)
        errors = []

        def worker(uname, pw, src, dst):
            try:
                c = make_client(uname, pw)
                for _ in range(15):
                    res = self.transfer(c, src, dst, 25)
                    assert res.status_code == 201, res.get_json()
            except Exception as exc:
                errors.append(exc)

        threads = (
            [threading.Thread(target=worker, args=("alice", "Passw0rd1", self.alice_acct, self.bob_num)) for _ in range(3)]
            + [threading.Thread(target=worker, args=("bob", "Passw0rd2", self.bob_acct, self.alice_num)) for _ in range(3)]
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(self.balance_of(self.alice_acct) + self.balance_of(self.bob_acct), combined_before)

        # 2) Simultaneous duplicate idempotency race: 6 threads send identical key at once
        race_key = str(uuid.uuid4())
        alice_before = self.balance_of(self.alice_acct)
        statuses = []
        lock = threading.Lock()

        def race_worker():
            c = make_client("alice", "Passw0rd1")
            r = self.transfer(c, self.alice_acct, self.bob_num, 333, key=race_key, memo="race")
            with lock:
                statuses.append(r.status_code)

        race_threads = [threading.Thread(target=race_worker) for _ in range(6)]
        for t in race_threads:
            t.start()
        for t in race_threads:
            t.join()

        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(200), 5)
        self.assertEqual(self.balance_of(self.alice_acct), alice_before - 333)

        integrity = self.admin.get("/api/admin/integrity").get_json()
        self.assertTrue(integrity["balanced"], integrity)

    def test_07_immutability_audit_and_csrf_headers(self):
        conn = bv.connect()
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("DELETE FROM ledger")
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("UPDATE ledger SET amount_cents=1")
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("DELETE FROM transactions")
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("UPDATE transactions SET amount_cents=1")
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("DELETE FROM audit_log")
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("UPDATE audit_log SET action='TAMPERED'")
        finally:
            conn.close()

        audit_actions = {row["action"] for row in self.admin.get("/api/admin/audit").get_json()}
        self.assertTrue({"REGISTER", "LOGIN", "ACCOUNT_REQUESTED", "ACCOUNT_STATUS", "TRANSFER", "TRANSFER_DENIED", "IDEMPOTENCY_CONFLICT"}.issubset(audit_actions))

        # CSRF & security headers checks
        bad_csrf = self.alice.post(
            "/api/accounts",
            json={"account_name": "Evil"},
            headers={"X-CSRF-Token": "wrong-token"},
        )
        self.assertEqual(bad_csrf.status_code, 403)

        cross_site = self.alice.post(
            "/api/accounts",
            json={"account_name": "Evil"},
            headers={"Sec-Fetch-Site": "cross-site"},
        )
        self.assertEqual(cross_site.status_code, 403)

        me_resp = self.alice.get("/api/me")
        self.assertEqual(me_resp.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(me_resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(me_resp.headers.get("Cache-Control"), "no-store")
        self.assertIn("script-src 'self'", me_resp.headers.get("Content-Security-Policy", ""))

    def test_08_ledger_filtering_and_role_demotion(self):
        # Ledger statement matches live balance and records DEBIT/CREDIT balance_after_cents
        ledger_rows = self.alice.get(f"/api/accounts/{self.alice_acct}/ledger").get_json()
        self.assertTrue(len(ledger_rows) >= 2)
        self.assertEqual(ledger_rows[0]["balance_after_cents"], self.balance_of(self.alice_acct))
        computed = sum(r["amount_cents"] if r["entry_type"] == "CREDIT" else -r["amount_cents"] for r in ledger_rows)
        self.assertEqual(computed, self.balance_of(self.alice_acct))

        # Transaction & audit filtering
        filtered_txns = self.alice.get("/api/transactions?type=transfer&q=invoice").get_json()
        self.assertTrue(all(t["txn_type"] == "transfer" and "invoice" in t["memo"] for t in filtered_txns))
        filtered_audit = self.admin.get("/api/admin/audit?action=TRANSFER").get_json()
        self.assertTrue(len(filtered_audit) >= 1 and all(a["action"] == "TRANSFER" for a in filtered_audit))

        # Live role demotion immediately blocks elevated access on existing session
        promo = make_client("promouser", "PromoPass1", register=True)
        pid = promo.get("/api/me").get_json()["id"]
        self.assertEqual(self.admin.post(f"/api/admin/users/{pid}/role", json={"role": "auditor"}).status_code, 200)
        self.assertEqual(promo.get("/api/admin/integrity").status_code, 200)
        self.assertEqual(self.admin.post(f"/api/admin/users/{pid}/role", json={"role": "customer"}).status_code, 200)
        self.assertEqual(promo.get("/api/admin/integrity").status_code, 403)


if __name__ == "__main__":
    unittest.main()
