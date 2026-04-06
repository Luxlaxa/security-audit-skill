---
domain: rate-limiting
version: 1.0.0
stacks: []
always_load: true
owasp: []
priority: [financial, disruption]
---

## Quick Check

```bash
# 1. AI endpoint routes — check for rate limiting middleware
grep -rn "\/api\/generate\|\/api\/chat\|\/api\/complete\|\/api\/ai\/\|openai\|anthropic" --include="*.ts" --include="*.js" src/ app/ pages/ || true

# 2. Rate limit counters on user-writable tables (Critical if modifiable via RLS)
grep -rn "rate_limit\|usage_count\|generations_count\|credits\|daily_limit\|generations_remaining" --include="*.sql" --include="*.ts" --include="*.js" supabase/ migrations/ src/ || true

# 3. Rate limiting packages in dependencies
grep -n "express-rate-limit\|@upstash/ratelimit\|rate-limiter-flexible\|bottleneck\|p-throttle\|limiter" package.json || true

# 4. Auth endpoints without rate limiting
grep -rn "\/api\/auth\|\/api\/login\|\/api\/signup\|\/api\/reset-password\|\/forgot-password\|\/verify-email" --include="*.ts" --include="*.js" src/ app/ pages/ || true

# 5. API routes missing rate limiting middleware in route chain
grep -rn "app\.\(get\|post\|put\|delete\|patch\)\|router\.\(get\|post\|put\|delete\|patch\)" --include="*.ts" --include="*.js" src/ app/ || true

# 6. Email/SMS send functions — check for rate limits
grep -rn "sendgrid\|postmark\|nodemailer\|resend\|twilio\|\.send(\|sendEmail\|sendMail" --include="*.ts" --include="*.js" src/ app/ lib/ || true
```

## Full Patterns

### AI & Provider Abuse

**Vulnerability:** No Rate Limits on AI Endpoints
**Severity:** Critical
**Detect:** API routes calling `openai.chat.completions.create`, `anthropic.messages.create`, or similar AI provider methods without rate limiting middleware in the route handler chain. Check route definitions for the presence of a limiter before the handler.
**Impact:** Attacker finds your endpoint via browser network tab or mobile traffic inspection, then calls it unlimited times. Each call costs you money. A single attacker can rack up $10,000+ in AI provider bills overnight. This is the #1 financial drain attack vector.
**Fix:**
```typescript
// BEFORE — no rate limiting
app.post('/api/generate', authenticate, async (req, res) => {
  const response = await openai.chat.completions.create({ ... })
  res.json(response)
})

// AFTER — per-user rate limiting
import rateLimit from 'express-rate-limit'

const aiLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // 20 requests per hour per user
  keyGenerator: (req) => req.user.id, // per-user, not per-IP
  message: { error: 'Rate limit exceeded. Try again later.' }
})

app.post('/api/generate', authenticate, aiLimiter, async (req, res) => {
  const response = await openai.chat.completions.create({ ... })
  res.json(response)
})
```
**OWASP:** N/A (rate limiting is cross-cutting)

---

**Vulnerability:** No Budget Caps on Providers
**Severity:** High
**Detect:** Check if AI provider dashboards have spending limits set. Grep for budget-related env vars or configuration. Look for absence of `OPENAI_BUDGET`, `ANTHROPIC_SPEND_LIMIT`, or equivalent infrastructure-as-code budget settings.
**Impact:** Without caps, a compromised key or rate limit bypass can drain your account. Chris Raroque got a $30K AWS bill from a leaked key. The service running until you notice is the default behavior.
**Fix:** Set hard spending caps on EVERY provider (OpenAI, Anthropic, AWS, GCP, Vercel, Supabase). At bare minimum, set spend alerts. Better: implement automatic shutdown when budget is reached.
**OWASP:** N/A (rate limiting is cross-cutting)

---

**Vulnerability:** Cost-Based Rate Limiting Missing
**Severity:** Medium
**Detect:** All endpoints share the same rate limit regardless of computational cost. An image generation endpoint (expensive) has the same limit as a text endpoint (cheap). Check if rate limit `max` values are identical across routes with different provider costs.
**Impact:** Attackers target the most expensive operations to maximize financial damage per request.
**Fix:** Set lower rate limits for expensive operations (AI generation, file processing, export) and higher limits for cheap operations (reads, simple queries).
**OWASP:** N/A (rate limiting is cross-cutting)

---

### Data Layer Abuse

**Vulnerability:** Rate Limit Counters in User-Writable Tables
**Severity:** Critical
**Detect:** Fields like `rate_limit`, `daily_limit`, `usage_count`, `generations_remaining`, `credits` on Supabase/Firebase tables where the user has UPDATE access via RLS policies. This is the EXACT vulnerability that got Chris Raroque's app hacked.
**Impact:** Users modify their own rate limits to unlimited, then abuse AI endpoints freely. Or they reset their usage count to zero. Combined with unprotected AI endpoints, this is devastating — the attacker can both find the endpoint AND remove all limits.
**Fix:** Store rate limits and usage counts in a PRIVATE table (no public RLS policies) or in a server-side cache (Redis/Upstash). Access only from Edge Functions or backend using service_role.
```sql
-- WRONG: rate limits on public user table
CREATE TABLE public.profiles (
  id UUID PRIMARY KEY,
  name TEXT,
  rate_limit_per_hour INT DEFAULT 10,  -- user can modify!
  usage_count INT DEFAULT 0            -- user can reset!
);

-- RIGHT: private rate limit table
CREATE TABLE private.usage_tracking (
  user_id UUID PRIMARY KEY REFERENCES auth.users,
  rate_limit_per_hour INT DEFAULT 10,
  current_hour_count INT DEFAULT 0,
  last_reset_at TIMESTAMPTZ DEFAULT now()
);
-- NO public RLS policies — accessed only via service_role
```
**OWASP:** N/A (rate limiting is cross-cutting)

---

**Vulnerability:** Supabase/Firebase Usage-Based Billing Abuse
**Severity:** High
**Detect:** Supabase or Firebase project without rate limiting on database reads/writes or storage bandwidth. Check for unprotected storage endpoints, public bucket access, or unrestricted realtime subscriptions.
**Impact:** Even without AI features, someone spamming your database reads/writes or storage downloads can rack up $50,000+ bills. There are documented cases of this happening.
**Fix:** Add rate limiting on all endpoints that trigger database operations. Set budget alerts on Supabase/Firebase. For Firebase, implement billing shutdown via Google Billing API as a hard cap.
**OWASP:** N/A (rate limiting is cross-cutting)

---

### Auth & Identity

**Vulnerability:** No Rate Limits on Auth Endpoints
**Severity:** High
**Detect:** Login, signup, password reset, and email verification endpoints without rate limiting. Grep for `/login`, `/signup`, `/register`, `/reset-password`, `/forgot-password`, `/verify-email` routes and check if rate limiting middleware is applied.
**Impact:** Brute force attacks on login (try thousands of passwords), credential stuffing (try leaked credentials from other sites), account enumeration (determine which emails have accounts), password reset spam (flood user with reset emails).
**Fix:** Apply strict rate limits — 5 login attempts per 15 minutes per IP, 3 password reset requests per hour per email.
**OWASP:** N/A (rate limiting is cross-cutting)

---

**Vulnerability:** No IP-Based Rate Limiting
**Severity:** Medium
**Detect:** Rate limiting is per-user only (keyed by user ID or session) without any IP-based component. Check `keyGenerator` or equivalent config in rate limiting setup.
**Impact:** An attacker creates many accounts and distributes requests across them to bypass per-user limits. IP-based limiting adds a second layer that catches this pattern.
**Fix:** Combine per-user AND per-IP limiting:
```typescript
import { Ratelimit } from '@upstash/ratelimit'
import { Redis } from '@upstash/redis'

const userLimiter = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(20, '1 h'),
})

const ipLimiter = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(100, '1 h'),
  prefix: 'ip',
})

const userResult = await userLimiter.limit(userId)
const ipResult = await ipLimiter.limit(clientIp)
if (!userResult.success || !ipResult.success) {
  return new Response('Rate limited', { status: 429 })
}
```
**OWASP:** N/A (rate limiting is cross-cutting)

---

### Client-Side Bypass

**Vulnerability:** Frontend-Only Rate Limits
**Severity:** High
**Detect:** Rate limiting logic only in frontend code (React state counters, localStorage limits, disabled buttons after N uses). No corresponding server-side enforcement. Grep for `localStorage.*count`, `useState.*limit`, `remaining.*0` in frontend files.
**Impact:** Frontend limits are trivially bypassed. Anyone can call the API directly via curl, Postman, or a script. All frontend protections are cosmetic.
**Fix:** All rate limits MUST be enforced server-side. Frontend limits are UX sugar only — they should never be the sole enforcement mechanism.
**OWASP:** N/A (rate limiting is cross-cutting)

---

### Communication Channels

**Vulnerability:** Missing Email/SMS Rate Limits
**Severity:** Medium
**Detect:** Email or SMS send functions (SendGrid, Postmark, Twilio, Resend, Nodemailer) called without rate limiting. Grep for `sendgrid`, `postmark`, `twilio`, `resend`, `nodemailer`, `.sendMail`, `.sendEmail` in server-side code.
**Impact:** Attacker uses your email endpoint to send spam as your domain — burning your sender reputation and potentially getting you blacklisted. SMS abuse can incur significant per-message costs.
**Fix:** Rate limit email sends per-user and per-IP. Validate recipients. Set daily send caps.
**OWASP:** N/A (rate limiting is cross-cutting)

---

### Infrastructure

**Vulnerability:** Rate Limit Header Information Leakage
**Severity:** Low
**Detect:** Response headers like `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` returned to clients. Check rate limiter configuration for `headers: true` or equivalent.
**Impact:** Attackers learn your exact limits and can optimize their abuse to stay just under them, or time their attacks to windows when the limit resets.
**Fix:** Consider omitting rate limit headers on sensitive endpoints, or return less specific information.
**OWASP:** N/A (rate limiting is cross-cutting)

---

**Vulnerability:** Connection Pool Exhaustion
**Severity:** Medium
**Detect:** Supabase projects using pgbouncer (default) without connection limits per user/request. High-concurrency endpoints that open many DB connections. Check for missing `statement_timeout` or `idle_in_transaction_session_timeout` settings.
**Impact:** An attacker sending many concurrent requests can exhaust the connection pool, causing denial of service for all users.
**Fix:** Limit concurrent connections per user. Use connection pooling mode correctly (transaction mode for serverless). Set statement timeouts.
**OWASP:** N/A (rate limiting is cross-cutting)
