---
domain: race-conditions
version: 1.0.0
stacks: [stripe]
always_load: false
owasp: [A04]
priority: [financial]
---

## Quick Check

```bash
# Payment/charge operations without idempotency keys
rg -n "charges\.create|paymentIntents\.create" --type ts --type js | rg -v "idempotency"
# Balance/credit check followed by deduction not in a transaction
rg -n "balance|credits" --type ts --type js -A 5 | rg "update|decrement|subtract"
# Concurrent signup — missing unique constraints on email
rg -n "insert.*email|create.*email" --type ts --type js | rg -v "unique|conflict|upsert"
# Inventory/stock operations without locking
rg -n "stock|inventory|quantity" --type ts --type js --type sql | rg -v "FOR UPDATE|optimistic|version"
```

## Full Patterns

### 1. Double-Charge Prevention

**Vulnerability:** Payment operations without idempotency keys
**Severity:** High
**Detect:** Grep for `charges.create` or `paymentIntents.create` without `idempotencyKey` or `idempotency_key` in the same call.
**Impact:** Network retry or user double-click triggers two real charges on the customer's card. Refund process is manual and damages trust.
**Fix:** Always pass `idempotencyKey` to Stripe API calls. Wrap the full order-creation + charge flow in a DB transaction so partial failures don't leave orphaned records.
**OWASP:** A04 — Insecure Design

### 2. TOCTOU — Time of Check to Time of Use

**Vulnerability:** Non-atomic check-then-act on balances or credits
**Severity:** High
**Detect:** Look for patterns where a balance is read (`SELECT balance`), compared in application code, then updated (`UPDATE balance`) in separate queries.
**Impact:** Two concurrent requests both read balance = $50, both pass the >= $30 check, both deduct — user spends $60 from a $50 balance.
**Fix:** Use `SELECT ... FOR UPDATE` to lock the row during the transaction, or use a single atomic `UPDATE credits SET balance = balance - $amount WHERE balance >= $amount` and check affected rows.
**OWASP:** A04 — Insecure Design

### 3. Concurrent Account Creation

**Vulnerability:** Parallel signup requests create duplicate accounts for the same email
**Severity:** Medium
**Detect:** Check user creation logic for unique constraint on email column. Grep for `INSERT INTO users` or `create({ data: { email` without `ON CONFLICT` / upsert handling.
**Impact:** Duplicate accounts cause billing confusion, split user data, and potential privilege escalation if one account gets admin rights.
**Fix:** Add a `UNIQUE` constraint on the email column. Handle the constraint violation error gracefully in application code (return "account already exists").
**OWASP:** A04 — Insecure Design

### 4. Inventory / Credit Oversell

**Vulnerability:** Parallel purchases can exceed available stock or credits
**Severity:** High
**Detect:** Grep for stock/inventory decrement operations. Check if they use application-level checks without DB-level locking.
**Impact:** 10 units in stock, 15 concurrent purchases all succeed — you oversell by 5 units, causing fulfillment failures and refund costs.
**Fix:** Use `UPDATE inventory SET stock = stock - 1 WHERE stock > 0` and check `rowCount === 1`. Alternatively, use `SELECT ... FOR UPDATE` with explicit locking.
**OWASP:** A04 — Insecure Design

### 5. Balance Manipulation via Parallel Requests

**Vulnerability:** Concurrent top-up and spend requests exploit non-serializable transactions
**Severity:** High
**Detect:** Check if top-up (credit addition) and spend (credit deduction) operations share the same transaction isolation level. Look for `READ COMMITTED` when `SERIALIZABLE` is needed.
**Impact:** User sends top-up ($10) and spend ($10) simultaneously. Both read old balance, both succeed — user effectively gets a free $10 spend.
**Fix:** Use `SERIALIZABLE` isolation for financial operations, or use atomic single-query updates that don't depend on a prior read.
**OWASP:** A04 — Insecure Design

### 6. Transaction Isolation Levels

**Vulnerability:** Using default (READ COMMITTED) isolation for operations that require stronger guarantees
**Severity:** Medium
**Detect:** Grep for explicit transaction isolation settings. If none found, the database default (usually READ COMMITTED) is in effect.
**Impact:** Phantom reads and non-repeatable reads in financial calculations lead to incorrect totals, double-spending, or data corruption.
**Fix:**
- **READ COMMITTED** (default): Fine for most CRUD operations. Two reads in the same transaction may return different results.
- **REPEATABLE READ**: Use when a transaction reads the same data multiple times (e.g., generating reports). Prevents non-repeatable reads.
- **SERIALIZABLE**: Use for financial operations where concurrent transactions must not interfere (balance transfers, inventory). Highest safety, lowest throughput.
- In practice: wrap critical financial paths in `SERIALIZABLE`, leave everything else at `READ COMMITTED`.
**OWASP:** A04 — Insecure Design
