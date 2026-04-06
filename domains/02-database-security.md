---
domain: database-security
version: 1.0.0
stacks: [supabase, firebase, prisma]
always_load: false
owasp: [A01]
priority: [data-breach, privesc, financial]
---

## Quick Check

1. `grep -rn "CREATE TABLE" supabase/migrations/ | while read t; do table=$(echo "$t" | grep -oP 'CREATE TABLE (\w+\.)?(\w+)' | awk '{print $NF}'); grep -q "ENABLE ROW LEVEL SECURITY" <<< "$(grep -A5 "$table" supabase/migrations/*.sql)" || echo "NO RLS: $table"; done` — tables missing RLS
2. `grep -riEn "USING\s*\(\s*true\s*\)|USING\s*\(\s*auth\.uid\(\)\s+IS\s+NOT\s+NULL\s*\)" supabase/migrations/` — overly permissive RLS (Critical)
3. `grep -rn "allow read, write: if true" firestore.rules database.rules.json` — completely open Firebase rules (Critical)
4. `grep -riEn "(subscription_status|is_premium|rate_limit|credits|role|is_admin)" supabase/migrations/` — sensitive fields; cross-check with UPDATE/INSERT policies on same table (Critical)
5. `grep -rn "SECURITY DEFINER" supabase/migrations/` — check if private schema + `search_path = ''`
6. `grep -rEn "\\\$queryRawUnsafe|\\\$executeRawUnsafe" --include="*.ts" --include="*.js" .` — Prisma raw SQL injection risk (Critical)
7. `grep -rn "storage.objects" supabase/migrations/` — verify uploads scoped to `auth.uid()` folders
8. `grep -riEn "FOR (INSERT|UPDATE)" supabase/migrations/ | while read p; do file=$(echo "$p" | cut -d: -f1); line=$(echo "$p" | cut -d: -f2); grep -A5 "WITH CHECK" "$file" | head -1 || echo "MISSING WITH CHECK: $p"; done` — INSERT/UPDATE policies without WITH CHECK
9. `grep -rn "request.auth != null" firestore.rules` — Firebase auth-only rules missing ownership check
10. `grep -riEn "postgres://|mongodb://|DATABASE_URL" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" src/ app/ pages/ components/` — connection strings in client code (Critical)

## Full Patterns

### Supabase RLS Patterns

**Pattern 1: RLS Disabled on Table**
**Vulnerability:** Table accessible without Row Level Security
**Severity:** Critical
**Detect:** Table exists in migrations without `ENABLE ROW LEVEL SECURITY`. Verify via SQL: `SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename NOT IN (SELECT relname FROM pg_class WHERE relrowsecurity = true);`
**Impact:** Without RLS, anyone with the anon key (which is PUBLIC — embedded in every client bundle) can read, write, and delete ALL data in the table via PostgREST. Complete data breach. This is the #1 cause of vibe-coded app data breaches.
**Fix:**
```sql
-- BEFORE: table created without RLS
CREATE TABLE public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users,
  name TEXT
);

-- AFTER: enable AND force RLS on every public table
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles FORCE ROW LEVEL SECURITY;
-- FORCE prevents bypass via service_role key used client-side
```
**OWASP:** A01

---

**Pattern 2: Overly Permissive RLS — USING (true)**
**Vulnerability:** RLS policy grants access to all rows
**Severity:** Critical
**Detect:** Grep for `USING (true)` or `USING (auth.uid() IS NOT NULL)` in SQL migrations. Both mean "any authenticated user sees ALL rows."
**Impact:** Any authenticated user can read/modify ALL data in the table, not just their own. One user can download every other user's private data.
**Fix:**
```sql
-- WRONG: any authenticated user sees everything
CREATE POLICY "Users can read" ON profiles FOR SELECT
TO authenticated USING (true);

-- WRONG: any logged-in user sees all rows
CREATE POLICY "Users can read" ON profiles FOR SELECT
TO authenticated USING (auth.uid() IS NOT NULL);

-- RIGHT: users see only their own data (subquery for performance)
CREATE POLICY "Users can read own profile" ON profiles FOR SELECT
TO authenticated USING ((SELECT auth.uid()) = user_id);
```
**OWASP:** A01

---

**Pattern 3: Missing WITH CHECK on INSERT/UPDATE**
**Vulnerability:** Users can insert/update rows belonging to other users
**Severity:** High
**Detect:** INSERT or UPDATE policies with USING clause but no WITH CHECK. `WITH CHECK` validates the NEW row data — without it, users can write data with another user's ID.
**Impact:** User creates a record with another user's ID, or changes a record's `user_id` to impersonate someone else. Enables cross-user data injection and impersonation.
**Fix:**
```sql
-- WRONG: missing WITH CHECK — user could change user_id to someone else's
CREATE POLICY "Users can update profile" ON profiles FOR UPDATE
TO authenticated USING ((SELECT auth.uid()) = user_id);

-- RIGHT: WITH CHECK ensures new row also belongs to user
CREATE POLICY "Users can update profile" ON profiles FOR UPDATE
TO authenticated
USING ((SELECT auth.uid()) = user_id)
WITH CHECK ((SELECT auth.uid()) = user_id);
```
**OWASP:** A01

---

**Pattern 4: Sensitive Data on User-Writable Tables (THE CHRIS RAROQUE PATTERN)**
**Vulnerability:** Subscription, billing, or privilege fields on tables users can UPDATE
**Severity:** Critical
**Detect:** Fields named `subscription_status`, `subscription_tier`, `is_premium`, `rate_limit`, `rate_limit_per_hour`, `credits`, `credits_remaining`, `usage_count`, `is_admin`, `role`, or `plan` on tables where the user has UPDATE or INSERT RLS policies. The RLS may be syntactically perfect — the vulnerability is in the DATA ARCHITECTURE, not the policy syntax.
**Impact:** This is the EXACT vulnerability that hacked Chris Raroque's calorie tracking app. His RLS was technically correct — users could only read/write THEIR OWN data. But "their own data" included `subscription_status` and `rate_limit`. Users changed `subscription_status` to `'premium'` and `rate_limit` to `999999`, then hammered his AI endpoint unlimited times, racking up $10K+ in API bills. AI code auditors (Claude, Cursor, GPT) consistently MISS this because the RLS is syntactically valid. The vulnerability is semantic — it's about WHAT data lives WHERE.
**Fix:**
```sql
-- WRONG: sensitive fields on user-writable table
CREATE TABLE public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users,
  name TEXT,
  avatar_url TEXT,
  subscription_status TEXT DEFAULT 'free',    -- user can SET to 'premium'!
  rate_limit_per_hour INT DEFAULT 10,          -- user can SET to 999999!
  credits INT DEFAULT 100                      -- user can SET to unlimited!
);

-- RIGHT: separate PRIVATE table for entitlements (no public RLS policies)
CREATE TABLE private.user_entitlements (
  user_id UUID PRIMARY KEY REFERENCES auth.users,
  subscription_status TEXT NOT NULL DEFAULT 'free',
  rate_limit_per_hour INT NOT NULL DEFAULT 10,
  credits_remaining INT NOT NULL DEFAULT 100
);
ALTER TABLE private.user_entitlements ENABLE ROW LEVEL SECURITY;
-- NO public policies — only accessible via service_role in Edge Functions

-- User's public profile: only safe, non-sensitive fields
CREATE TABLE public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users,
  name TEXT,
  avatar_url TEXT
);
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can read own profile" ON public.profiles
  FOR SELECT TO authenticated USING ((SELECT auth.uid()) = id);
CREATE POLICY "Users can update own profile" ON public.profiles
  FOR UPDATE TO authenticated
  USING ((SELECT auth.uid()) = id)
  WITH CHECK ((SELECT auth.uid()) = id);
```
**OWASP:** A01, A04

---

**Pattern 5: SECURITY DEFINER Functions Exposed via API**
**Vulnerability:** Privileged functions callable from client via PostgREST
**Severity:** High
**Detect:** Functions created with `SECURITY DEFINER` in the `public` schema. These run with the OWNER's privileges, bypassing RLS when called.
**Impact:** Any user can call public SECURITY DEFINER functions via `supabase.rpc('function_name')`, potentially accessing or modifying data that RLS would normally block. Equivalent to giving every user service_role access to that function's logic.
**Fix:**
```sql
-- WRONG: SECURITY DEFINER in public schema, callable by anyone
CREATE FUNCTION public.get_all_users() RETURNS SETOF profiles
LANGUAGE sql SECURITY DEFINER AS $$
  SELECT * FROM profiles;
$$;

-- RIGHT: private schema (not exposed via PostgREST) + restricted search_path
CREATE FUNCTION private.get_all_users() RETURNS SETOF profiles
LANGUAGE sql SECURITY DEFINER
SET search_path = '' AS $$
  SELECT * FROM public.profiles;
$$;
-- search_path = '' prevents search path injection attacks
```
**OWASP:** A01

---

**Pattern 6: Storage Bucket Policies Missing or Permissive**
**Vulnerability:** Unscoped file access in Supabase Storage
**Severity:** High
**Detect:** Supabase storage buckets without policies, or with policies that don't scope to user UID folders. Check `storage.objects` policies in migrations.
**Impact:** Users can access, overwrite, or delete other users' uploaded files. Or upload malicious files to arbitrary paths, including paths that may be served publicly.
**Fix:**
```sql
-- Scope uploads to user's own folder
CREATE POLICY "Users upload to own folder" ON storage.objects
FOR INSERT TO authenticated
WITH CHECK (
  bucket_id = 'avatars'
  AND (storage.foldername(name))[1] = (SELECT auth.uid())::text
);

-- Scope reads to user's own folder
CREATE POLICY "Users read own files" ON storage.objects
FOR SELECT TO authenticated
USING (
  bucket_id = 'avatars'
  AND (storage.foldername(name))[1] = (SELECT auth.uid())::text
);

-- Scope deletes to user's own folder
CREATE POLICY "Users delete own files" ON storage.objects
FOR DELETE TO authenticated
USING (
  bucket_id = 'avatars'
  AND (storage.foldername(name))[1] = (SELECT auth.uid())::text
);
```
**OWASP:** A01

---

**Pattern 7: Cross-User Data Access via Missing Ownership Filter**
**Vulnerability:** SELECT policies without auth.uid() ownership check
**Severity:** Critical
**Detect:** RLS SELECT policies that don't filter by `auth.uid()`. Also detect policies using a field from request headers or JWT claims that can be forged instead of the built-in `auth.uid()`.
**Impact:** User A can read all of User B's data. In apps audited by Chris Raroque, over half had this issue — he could download entire user tables with a single query. Even "read-only" leaks are Critical because the data itself is the asset.
**Fix:**
```sql
-- WRONG: no ownership filter
CREATE POLICY "Anyone can read" ON messages FOR SELECT
TO authenticated USING (true);

-- WRONG: using a forgeable claim instead of auth.uid()
CREATE POLICY "Read by role" ON messages FOR SELECT
TO authenticated USING (
  (current_setting('request.jwt.claims', true)::json->>'role') = 'admin'
);

-- RIGHT: ownership check via auth.uid()
CREATE POLICY "Users read own messages" ON messages FOR SELECT
TO authenticated USING ((SELECT auth.uid()) = sender_id OR (SELECT auth.uid()) = recipient_id);
```
**OWASP:** A01

---

### Firebase Patterns

**Pattern 8: Firebase — Open Security Rules**
**Vulnerability:** Firestore/RTDB rules allow unrestricted access
**Severity:** Critical
**Detect:** `allow read, write: if true` or `allow read, write: if request.auth != null` without ownership validation in `firestore.rules` or `database.rules.json`.
**Impact:** `if true` — anyone on the internet can read/write everything, no authentication needed. `if request.auth != null` — any logged-in user can read/write ALL data across ALL users. Both are complete data breaches.
**Fix:**
```
// WRONG: completely open
match /users/{userId} {
  allow read, write: if true;
}

// WRONG: auth-only, no ownership
match /users/{userId} {
  allow read, write: if request.auth != null;
}

// RIGHT: ownership validation
match /users/{userId} {
  allow read, write: if request.auth != null && request.auth.uid == userId;
}
```
**OWASP:** A01

---

**Pattern 9: Firebase — Subcollection Rules Not Inherited**
**Vulnerability:** Subcollections unprotected despite parent document having rules
**Severity:** High
**Detect:** Parent document has security rules but subcollections have no explicit rules. In Firestore, rules do NOT cascade — `match /users/{userId}` does NOT protect `/users/{userId}/messages/{messageId}`.
**Impact:** Subcollection data (messages, transactions, payment history, etc.) is completely unprotected even if the parent document is locked down. Attackers can directly query subcollections.
**Fix:**
```
// WRONG: only parent is protected
match /users/{userId} {
  allow read, write: if request.auth.uid == userId;
  // /users/{userId}/messages/* is UNPROTECTED!
}

// RIGHT: explicit rules for every subcollection
match /users/{userId} {
  allow read, write: if request.auth.uid == userId;

  match /messages/{messageId} {
    allow read, write: if request.auth.uid == userId;
  }

  match /transactions/{transactionId} {
    allow read: if request.auth.uid == userId;
    allow write: if false; // server-only writes
  }
}
```
**OWASP:** A01

---

**Pattern 10: Firebase — Missing Field Validation on Writes**
**Vulnerability:** Write rules accept any data shape or field
**Severity:** Medium
**Detect:** Write rules that don't validate data types, field names, sizes, or restrict which fields can be modified. No `request.resource.data` checks.
**Impact:** Users can write unexpected field types (causing app crashes), excessively large data (storage/cost abuse), or inject fields they shouldn't control (e.g., `isAdmin: true`, `role: 'admin'`).
**Fix:**
```
// WRONG: no field validation
match /users/{userId} {
  allow write: if request.auth.uid == userId;
}

// RIGHT: validate fields on write
match /users/{userId} {
  allow read: if request.auth.uid == userId;
  allow create: if request.auth.uid == userId
    && request.resource.data.keys().hasOnly(['name', 'email', 'avatarUrl'])
    && request.resource.data.name is string
    && request.resource.data.name.size() <= 100;
  allow update: if request.auth.uid == userId
    && request.resource.data.diff(resource.data).affectedKeys()
        .hasOnly(['name', 'avatarUrl']);
    // Users cannot modify email, role, or any other field
}
```
**OWASP:** A01

---

**Pattern 11: Firebase — Custom Claims vs Document Roles**
**Vulnerability:** User roles stored in writable Firestore documents instead of custom claims
**Severity:** Medium
**Detect:** Firestore documents containing `role`, `isAdmin`, `tier`, or `permissions` fields on user-writable collections. Security rules that read role from a document rather than `request.auth.token`.
**Impact:** If the role document is writable (even indirectly), users can escalate privileges to admin. Even if read-only, querying a document on every request adds latency and cost. Document-based roles are also harder to revoke instantly.
**Fix:**
```
// WRONG: role from Firestore doc (user might be able to write it)
match /admin/{document} {
  allow read: if get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin';
}

// RIGHT: role from custom claims (set via Admin SDK only)
match /admin/{document} {
  allow read: if request.auth.token.role == 'admin';
}
```
Set custom claims server-side only:
```javascript
// Admin SDK — server-side
await admin.auth().setCustomUserClaims(uid, { role: 'admin' });
```
**OWASP:** A01

---

### Prisma / General Database Patterns

**Pattern 12: Prisma — $queryRawUnsafe with User Input**
**Vulnerability:** SQL injection via Prisma raw query methods
**Severity:** Critical
**Detect:** Grep for `$queryRawUnsafe` or `$executeRawUnsafe` where the SQL string uses template literals (`${variable}`), string concatenation (`+`), or `.replace()` with user-supplied values.
**Impact:** Full SQL injection. Attacker can read/modify/delete any data, dump credentials, escalate to OS-level access (via `COPY`, `lo_export`, etc.). Prisma's safe `$queryRaw` uses tagged template literals that auto-parameterize — the `Unsafe` variants exist for dynamic queries but bypass all protection.
**Fix:**
```typescript
// WRONG: user input directly in SQL string
const users = await prisma.$queryRawUnsafe(
  `SELECT * FROM users WHERE email = '${req.body.email}'`
);

// WRONG: string concatenation
const query = "SELECT * FROM users WHERE name = '" + name + "'";
const users = await prisma.$queryRawUnsafe(query);

// RIGHT: parameterized via tagged template literal (auto-escaped by Prisma)
const users = await prisma.$queryRaw`
  SELECT * FROM users WHERE email = ${req.body.email}
`;

// RIGHT: if dynamic table/column names needed, allowlist them
const allowedColumns = ['name', 'email', 'created_at'];
if (!allowedColumns.includes(sortBy)) throw new Error('Invalid column');
const users = await prisma.$queryRawUnsafe(
  `SELECT * FROM users ORDER BY "${sortBy}" ASC`
);
```
**OWASP:** A03

---

**Pattern 13: Connection String in Client Code**
**Vulnerability:** Database credentials exposed in client-accessible code
**Severity:** Critical
**Detect:** `DATABASE_URL`, `DIRECT_URL`, `postgres://`, `postgresql://`, `mongodb://`, `mongodb+srv://`, `mysql://` in client-side files. Also check for `NEXT_PUBLIC_DATABASE`, `VITE_DATABASE`, `REACT_APP_DB` — any client-prefixed env var containing a connection string.
**Impact:** Direct database access bypassing ALL application security — RLS, auth, rate limits, everything. Complete data breach, data destruction, and potential server compromise. Connection strings include credentials.
**Fix:**
```bash
# WRONG: client-prefixed env var
NEXT_PUBLIC_DATABASE_URL=postgres://user:pass@host:5432/db

# RIGHT: server-only env var (no client prefix)
DATABASE_URL=postgres://user:pass@host:5432/db
# Access only in server-side code (API routes, Edge Functions, server components)
```
Audit: grep all `.env*` files and client code for connection string patterns. Rotate any credentials that were ever in client code.
**OWASP:** A05

---

**Pattern 14: Prisma — Missing Auth Middleware**
**Vulnerability:** Database operations without authorization checks
**Severity:** High
**Detect:** Prisma `findMany`, `findUnique`, `create`, `update`, `delete` calls in API routes without prior auth verification. Prisma has NO built-in RLS — unlike Supabase, every query runs with full database privileges.
**Impact:** Unauthenticated users access protected data. Authenticated users access other users' data. No ownership filtering means any user can query any record.
**Fix:**
```typescript
// WRONG: no auth check before Prisma query
app.get('/api/messages', async (req, res) => {
  const messages = await prisma.message.findMany();
  res.json(messages);
});

// RIGHT: auth + ownership filter on every query
app.get('/api/messages', async (req, res) => {
  const user = await getAuthUser(req); // verify JWT/session
  if (!user) return res.status(401).json({ error: 'Unauthorized' });

  const messages = await prisma.message.findMany({
    where: { userId: user.id }, // ownership filter
  });
  res.json(messages);
});

// BETTER: Prisma middleware for global enforcement
prisma.$use(async (params, next) => {
  if (params.model === 'Message' && params.action === 'findMany') {
    params.args.where = { ...params.args.where, userId: getCurrentUserId() };
  }
  return next(params);
});
```
**OWASP:** A01

---

**Pattern 15: Migration Files Containing Secrets**
**Vulnerability:** Hardcoded credentials in SQL migration files
**Severity:** Medium
**Detect:** SQL migration files containing patterns like `password`, `secret`, `api_key`, `token`, or literal connection strings. Common in seed data, initial config inserts, or `CREATE ROLE ... PASSWORD`.
**Impact:** Migration files are committed to git and persist in history forever. Even if deleted in a later commit, secrets remain in git history. Any contributor or anyone with repo access can extract them.
**Fix:**
```sql
-- WRONG: hardcoded password in migration
CREATE ROLE app_user WITH LOGIN PASSWORD 'super_secret_123';
INSERT INTO config (key, value) VALUES ('api_key', 'sk-live-abc123');

-- RIGHT: use environment variables, set credentials outside migrations
-- In migration:
CREATE ROLE app_user WITH LOGIN;
-- In deployment script (not committed):
ALTER ROLE app_user WITH PASSWORD :'db_password';
-- Or use a secrets manager and set via application startup
```
**OWASP:** A05

---

**Pattern 16: Database Backup Exposure**
**Vulnerability:** Unprotected database backups in accessible locations
**Severity:** Medium
**Detect:** Database backup files (`.sql`, `.dump`, `.bak`, `.sqlite`, `*.pg_dump`) in the repo, in `public/` directories, or in web-accessible storage. Also check `.gitignore` for missing backup exclusions.
**Impact:** Backups contain ALL data — a leaked backup is equivalent to a full database breach. Backups may also contain credentials, schema details useful for further attacks, and historical data that was "deleted" from production.
**Fix:**
```gitignore
# .gitignore — exclude all backup formats
*.sql
*.dump
*.bak
*.sqlite
*.pg_dump
backup/
backups/
```
- Encrypt backups at rest (AES-256 or equivalent)
- Store in access-controlled locations (S3 with IAM, not public buckets)
- Never commit to git — if already committed, use `git filter-repo` to purge from history
- Rotate database credentials if backups containing them were ever exposed
**OWASP:** A05
