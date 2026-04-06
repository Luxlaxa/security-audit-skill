---
domain: architecture-tier
version: 1.0.0
stacks: []
always_load: true
owasp: [A04]
priority: [financial, data-breach, privesc]
---

## Quick Check

1. `grep -r "createClient.*@supabase/supabase-js" app/ src/ pages/ components/` — If found without `supabase/functions/` existing → **Tier 1**
2. `grep -r "SUPABASE_SERVICE_ROLE_KEY\|service_role" app/ src/ pages/ components/` — **Critical**: service role key in client code
3. `ls supabase/functions/ functions/` — If exists with DB calls inside → likely **Tier 2**
4. `grep -r "initializeApp.*firebase" app/ src/ pages/ components/` — Without `/functions/` dir → **Tier 1 Firebase**
5. `grep -r "express\|fastify" package.json` + confirm DB client only in `server/` or `backend/` → **Tier 3**
6. `grep -r "NEXT_PUBLIC_SUPABASE_SERVICE" .env* app/ src/` — **Critical**: service key with public prefix
7. `grep -r "subscription_status\|is_premium\|credits\|rate_limit" supabase/migrations/ *.sql` — Check if on user-writable tables
8. `grep -rn "supabase\.from(" app/ src/ pages/ components/` + `grep -rn "fetch.*\/api\/" app/ src/` — Both present → **Hybrid** (mixed access)
9. `grep -r "\.rpc(" app/ src/ pages/ components/` — Direct RPC calls from client bypass edge function layer
10. Check `.env*` files for `SERVICE_ROLE` values committed to repo — **Critical** if found

## Full Patterns

### Architecture Tier Detection

**Vulnerability:** Single-Layer Defense (Direct BaaS) — Tier 1 Architecture Detected
**Severity:** High
**Detect:** Frontend code imports Supabase/Firebase client and makes DB calls directly. No edge/cloud functions layer exists. `supabase/functions/` or `functions/` directory is absent or empty.
**Impact:** Your ONLY defense is RLS/Security Rules. One misconfiguration = full data breach. Rate limits, subscription status, and business logic are enforced only by client-side code or database policies that are historically the #1 source of vibe-coded app breaches.
**Fix:**
```typescript
// BEFORE — Tier 1 (vulnerable): client calls DB directly
// app/page.tsx
import { createClient } from '@supabase/supabase-js'
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!)

const { data } = await supabase
  .from('generations')
  .insert({ prompt: userPrompt, user_id: userId })
// Rate limits? Only if RLS enforces them. Subscription check? Only if RLS checks it.

// AFTER — Tier 2 (secure): client calls Edge Function
// app/page.tsx
const response = await fetch('/api/generate', {
  method: 'POST',
  body: JSON.stringify({ prompt: userPrompt })
})

// supabase/functions/generate/index.ts — Edge Function handles business logic
import { createClient } from '@supabase/supabase-js'

Deno.serve(async (req) => {
  const supabase = createClient(url, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!)

  // 1. Verify auth
  const authHeader = req.headers.get('Authorization')!
  const { data: { user } } = await supabase.auth.getUser(authHeader.replace('Bearer ', ''))
  if (!user) return new Response('Unauthorized', { status: 401 })

  // 2. Check subscription (private table, not user-writable)
  const { data: entitlement } = await supabase
    .from('user_entitlements')  // private schema, no public RLS
    .select('subscription_status, rate_limit_per_hour')
    .eq('user_id', user.id)
    .single()

  if (entitlement.subscription_status !== 'premium') {
    return new Response('Premium required', { status: 403 })
  }

  // 3. Check rate limit (server-side, not user-modifiable)
  const { count } = await supabase
    .from('generation_logs')
    .select('*', { count: 'exact' })
    .eq('user_id', user.id)
    .gte('created_at', new Date(Date.now() - 3600000).toISOString())

  if (count >= entitlement.rate_limit_per_hour) {
    return new Response('Rate limit exceeded', { status: 429 })
  }

  // 4. NOW call AI endpoint
  // ...
})
```
**OWASP:** A04

---

### Exposed Credentials

**Vulnerability:** service_role Key Exposed in Client Bundle
**Severity:** Critical
**Detect:** Grep for `SUPABASE_SERVICE_ROLE_KEY`, `service_role`, `NEXT_PUBLIC_SUPABASE_SERVICE` in any file under `/app/`, `/src/`, `/pages/`, `/components/`, or any file with `NEXT_PUBLIC_` prefix.
**Impact:** The service_role key bypasses ALL Row-Level Security. Anyone can extract it from the browser bundle and read, modify, or delete every row in every table in your database. This is a total database compromise.
**Fix:**
```bash
# Move service_role to server-side only (Edge Functions, API routes, or backend)
# Client code should only ever use the anon key

# .env.local (client-safe)
NEXT_PUBLIC_SUPABASE_URL=https://xyz.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...  # safe — limited by RLS

# .env (server-only, never prefixed with NEXT_PUBLIC_)
SUPABASE_SERVICE_ROLE_KEY=eyJ...  # never expose to client
```
**OWASP:** A04, A05

---

### Data Architecture Flaws

**Vulnerability:** Subscription/Rate Limit Data in User-Accessible Tables
**Severity:** Critical
**Detect:** Check if fields like `subscription_status`, `subscription_tier`, `is_premium`, `rate_limit`, `credits`, `usage_count`, `is_admin`, `role` exist on tables where the user has UPDATE or INSERT RLS policies.
**Impact:** This is the exact vulnerability that got Chris Raroque's calorie tracking app hacked. Users can modify their subscription status to get free premium, change their rate limits to unlimited, then abuse AI endpoints to rack up thousands in bills. AI auditors (Claude, Cursor) consistently MISS this because the RLS policies are technically correct — the flaw is in the data architecture.
**Fix:**
```sql
-- Move sensitive fields to a private table with NO public RLS policies
-- Access only via Edge Functions using service_role key

CREATE SCHEMA IF NOT EXISTS private;

CREATE TABLE private.user_entitlements (
  user_id UUID REFERENCES auth.users PRIMARY KEY,
  subscription_status TEXT NOT NULL DEFAULT 'free',
  rate_limit_per_hour INT NOT NULL DEFAULT 10,
  credits_remaining INT NOT NULL DEFAULT 0
);

ALTER TABLE private.user_entitlements ENABLE ROW LEVEL SECURITY;
-- NO policies = only accessible via service_role in Edge Functions
```
**OWASP:** A04, A01

---

### Inconsistent Access Paths

**Vulnerability:** Mixed Direct and Proxied Database Access (Hybrid Architecture)
**Severity:** Medium
**Detect:** Some routes call DB directly from client while others go through Edge Functions. Look for both `supabase.from(...)` in frontend code AND fetch calls to `/api/` or Edge Function URLs in the same codebase.
**Impact:** Security is only as strong as the weakest path. If even one route bypasses the Edge Function layer, that route has Tier 1 exposure. Attackers target the weakest entry point.
**Fix:**
```typescript
// BEFORE — mixed access (some direct, some proxied)
// app/dashboard/page.tsx — direct DB call (Tier 1 exposure)
const { data } = await supabase.from('profiles').select('*')

// app/generate/page.tsx — proxied (Tier 2)
const res = await fetch('/api/generate', { method: 'POST', body })

// AFTER — all access goes through Edge Functions or API routes
// app/dashboard/page.tsx — now proxied
const { data } = await fetch('/api/profile').then(r => r.json())

// app/generate/page.tsx — already proxied
const res = await fetch('/api/generate', { method: 'POST', body })
```
**OWASP:** A04

---

### Grade Cap

**Vulnerability:** Architecture Tier Caps Maximum Security Grade
**Severity:** Informational
**Detect:** Determined by the tier detection checks above.
**Impact:** Your architecture tier CAPS your maximum security grade:

| Tier | Architecture | Max Grade | Rationale |
|------|-------------|-----------|-----------|
| Tier 1 | Frontend → Database (direct BaaS) | **C** | Single point of failure — RLS is your only defense |
| Tier 2 | Frontend → Edge Functions → Database | **A** | Two-layer defense — business logic + RLS |
| Tier 3 | Frontend → Backend Server → Database | **A** | Traditional backend — full control |
| Hybrid | Mixed direct + proxied access | **B** | Weakest path determines exposure |

This is not a penalty — it reflects structural risk. A Tier 1 app with perfect RLS still has a single point of failure.
**Fix:** Migrate to Tier 2 or Tier 3 architecture. See Pattern 1 for a complete migration example.
**OWASP:** A04

---

## Defense-in-Depth Principle

Understanding why architecture tier matters more than any individual vulnerability:

- **Traditional (Tier 3):** Frontend → Backend → Database. The backend is the gatekeeper. Auth, rate limiting, business logic, and input validation all happen before any query touches the database.
- **BaaS promise (Tier 1):** Frontend → Database directly. RLS is the only gatekeeper. Every security check must be encoded as a database policy. One missed policy = breach.
- **Defense in depth (Tier 2):** Frontend → Edge Functions (Layer 1: auth, business logic, rate limiting, input validation) → Database with RLS (Layer 2: safety net). With Tier 2, RLS becomes your SECOND line of defense, not your only one. Both layers must fail for a breach to occur.

The key insight: RLS was designed as a safety net, not a perimeter. When you use it as your only defense (Tier 1), you are operating outside its design intent. Adding an Edge Function layer restores the defense-in-depth model that every security framework recommends.
