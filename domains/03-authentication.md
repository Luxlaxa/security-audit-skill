---
domain: authentication
version: 1.0.0
stacks: []
always_load: true
owasp: [A07]
priority: [ato, privesc]
---

## Quick Check

```bash
# JWT decode without verify — signature bypass (Critical)
grep -rn "jwt\.decode(" --include="*.ts" --include="*.js" --include="*.tsx"

# Tokens in localStorage — XSS-stealable (High)
grep -rn "localStorage\.setItem(" --include="*.ts" --include="*.js" --include="*.tsx" | grep -i "token\|session\|jwt\|auth"

# Unprotected Server Actions / Route Handlers — missing auth check (High)
grep -rln "'use server'" --include="*.ts" --include="*.tsx" | xargs grep -L "auth()\|getSession\|getUser\|getServerSession"
grep -rln "export.*GET\|export.*POST\|export.*PUT\|export.*DELETE" app/api/ --include="*.ts" --include="*.tsx" 2>/dev/null | xargs grep -L "auth()\|getSession\|getUser\|getServerSession"

# JWT algorithm "none" — token forgery (Critical)
grep -rn "alg.*none\|algorithm.*none\|algorithms.*none" --include="*.ts" --include="*.js" --include="*.json"

# OAuth wildcard or unvalidated redirect URIs (Critical)
grep -rn "redirect_uri\|redirectUri\|redirect_url" --include="*.ts" --include="*.js" --include="*.tsx" | grep -i "wildcard\|param\|query\|\*"

# Missing SameSite on auth cookies — CSRF risk (Medium)
grep -rn "sameSite.*none\|samesite.*none" --include="*.ts" --include="*.js" --include="*.tsx"
grep -rn "\.cookie(" --include="*.ts" --include="*.js" | grep -v "sameSite\|samesite"

# Middleware-only auth without Server Action re-verification (High)
grep -rln "middleware" --include="*.ts" --include="*.tsx" | head -5

# Session tokens in URL parameters — leakage via referrer/logs (High)
grep -rn "\?token=\|&token=\|\?session=\|&session=\|\?auth=" --include="*.ts" --include="*.js" --include="*.tsx"
```

## Full Patterns

### JWT Patterns

**Vulnerability:** JWT decode() Without Verify
**Severity:** Critical
**Detect:** `jwt.decode(token)` used to extract claims for authorization decisions without `jwt.verify()`. The `decode` function does NOT verify the signature.
**Impact:** Attacker crafts a fake JWT with any claims they want (admin=true, userId=anyone). Since the signature isn't checked, the server accepts it.
**Fix:**
```typescript
// WRONG — decode doesn't verify signature
import jwt from 'jsonwebtoken'
const payload = jwt.decode(token)
if (payload.role === 'admin') { grantAccess() }

// RIGHT — verify checks signature
try {
  const payload = jwt.verify(token, process.env.JWT_SECRET)
  if (payload.role === 'admin') { grantAccess() }
} catch (err) {
  return res.status(401).json({ error: 'Invalid token' })
}
```
**OWASP:** A07

---

**Vulnerability:** JWT Algorithm "none" Accepted
**Severity:** Critical
**Detect:** JWT verification that doesn't explicitly specify allowed algorithms. Some JWT libraries accept `alg: "none"` by default, which means unsigned tokens.
**Impact:** Attacker sends a JWT with `"alg": "none"` and no signature. If the library accepts it, the attacker has full token forgery.
**Fix:**
```typescript
// WRONG — no algorithm restriction
jwt.verify(token, secret)

// RIGHT — explicit algorithm whitelist
jwt.verify(token, secret, { algorithms: ['HS256'] })
```
**OWASP:** A07

---

**Vulnerability:** Algorithm Confusion (HS256 / RS256)
**Severity:** High
**Detect:** Application uses RS256 (asymmetric) for JWT signing but doesn't restrict algorithms in verify. Attacker can switch to HS256 and sign with the public key (which is public).
**Impact:** Attacker obtains the public key (often in a JWKS endpoint or config), changes the token's algorithm to HS256, signs with the public key, and the server accepts it because HMAC verification with the public key as secret matches.
**Fix:** Always specify the exact algorithm in verify: `{ algorithms: ['RS256'] }`. Never allow algorithm flexibility.
**OWASP:** A07

---

**Vulnerability:** Missing Claims Validation
**Severity:** High
**Detect:** JWT verification without checking `iss` (issuer), `aud` (audience), or `exp` (expiration). Just verifying the signature is not enough.
**Impact:** Token from a different application/issuer could be accepted. Expired tokens remain valid. Tokens intended for a different audience are accepted.
**Fix:**
```typescript
jwt.verify(token, secret, {
  algorithms: ['HS256'],
  issuer: 'your-app',
  audience: 'your-api',
  clockTolerance: 30 // 30 seconds tolerance for clock skew
})
```
**OWASP:** A07

### OAuth / OIDC Patterns

**Vulnerability:** OAuth Missing PKCE
**Severity:** High
**Detect:** OAuth authorization code flow without PKCE (Proof Key for Code Exchange). Check for absence of `code_verifier` and `code_challenge` in the authorization request.
**Impact:** Authorization code interception attack. On mobile or in environments where the redirect can be intercepted, an attacker captures the authorization code and exchanges it for tokens.
**Fix:** Always use PKCE. Generate `code_verifier` (random string), compute `code_challenge` (SHA256 hash), send challenge in auth request, send verifier in token exchange.
**OWASP:** A07

---

**Vulnerability:** OAuth Missing State Parameter
**Severity:** High
**Detect:** OAuth authorization request without a `state` parameter, or state parameter not validated on callback.
**Impact:** CSRF on OAuth flow. Attacker initiates OAuth flow with their account, gets the callback URL, and tricks the victim into clicking it -- linking the attacker's OAuth account to the victim's session.
**Fix:** Generate cryptographic random state, store in session, validate on callback matches.
**OWASP:** A07

---

**Vulnerability:** OAuth Redirect URI Not Validated
**Severity:** Critical
**Detect:** OAuth configuration with wildcard redirect URIs or redirect URI taken from request parameter without validation against an allowlist.
**Impact:** Attacker sets redirect URI to their own server, receives the authorization code or tokens, and gains access to the user's account.
**Fix:** Maintain a strict allowlist of redirect URIs. Validate exact match, not prefix or substring match. Never accept redirect URIs from user input.
**OWASP:** A07

### Session Management Patterns

**Vulnerability:** Tokens in localStorage
**Severity:** High
**Detect:** `localStorage.setItem('token', ...)`, `localStorage.setItem('session', ...)`, `localStorage.setItem('jwt', ...)`.
**Impact:** localStorage is accessible to any JavaScript on the page. A single XSS vulnerability (or a compromised third-party script) steals all tokens. Unlike cookies, localStorage has no HttpOnly equivalent.
**Fix:**
```typescript
// WRONG — token in localStorage, XSS-stealable
localStorage.setItem('auth_token', response.token)

// RIGHT — HttpOnly cookie set by server
res.cookie('auth_token', token, {
  httpOnly: true,    // JavaScript can't access
  secure: true,      // HTTPS only
  sameSite: 'lax',   // CSRF protection
  maxAge: 3600000    // 1 hour
})
```
**OWASP:** A07

---

**Vulnerability:** Session Fixation
**Severity:** Medium
**Detect:** Session ID not regenerated after login. The same session ID used before and after authentication.
**Impact:** Attacker sets a known session ID (via URL parameter, cookie injection, etc.) before the victim logs in. After login, the attacker's known session ID now has an authenticated session.
**Fix:** Always regenerate the session ID after successful authentication: `req.session.regenerate()`.
**OWASP:** A07

---

**Vulnerability:** Session Replay / No Token Rotation
**Severity:** Medium
**Detect:** Long-lived tokens without rotation. No refresh token mechanism. Token expiry set to days or weeks instead of hours.
**Impact:** A stolen token remains valid for the entire lifetime. No mechanism to revoke it.
**Fix:** Short-lived access tokens (15-60 minutes) + refresh token rotation. Revoke refresh tokens on logout.
**OWASP:** A07

### Framework-Specific Patterns

**Vulnerability:** Next.js Middleware-Only Auth
**Severity:** High
**Detect:** Auth checks only in `middleware.ts` without re-verification in Server Actions, Route Handlers, or data access functions.
**Impact:** Next.js middleware runs on the Edge runtime and can be bypassed in certain scenarios (e.g., direct API calls, internal redirects). If auth is only checked in middleware, protected Server Actions and Route Handlers are effectively unprotected.
**Fix:**
```typescript
// middleware.ts — first layer (not sufficient alone)
export async function middleware(req) {
  const session = await getSession(req)
  if (!session) return NextResponse.redirect('/login')
}

// app/actions.ts — MUST verify again
'use server'
export async function updateProfile(formData) {
  const session = await auth()  // re-verify!
  if (!session) throw new Error('Unauthorized')
  // ... proceed
}
```
**OWASP:** A07

---

**Vulnerability:** Server Actions Are Public Endpoints
**Severity:** High
**Detect:** Server Actions (files with `'use server'`) that don't validate: 1) authentication (is the user logged in?), 2) authorization (does the user have permission?), 3) input (is the data valid?).
**Impact:** Server Actions are callable as HTTP POST endpoints. Anyone can call them with any payload, from any origin. Without all three checks, they're completely unprotected public endpoints.
**Fix:**
```typescript
'use server'
export async function deleteAccount(formData) {
  // 1. Authenticate
  const session = await auth()
  if (!session) throw new Error('Unauthorized')

  // 2. Authorize
  const userId = formData.get('userId')
  if (session.user.id !== userId) throw new Error('Forbidden')

  // 3. Validate input
  const parsed = deleteAccountSchema.safeParse({ userId })
  if (!parsed.success) throw new Error('Invalid input')

  // NOW proceed
  await db.users.delete({ where: { id: parsed.data.userId } })
}
```
**OWASP:** A07

---

**Vulnerability:** MFA Bypass
**Severity:** High
**Detect:** MFA verification as a separate step that can be skipped by directly calling protected endpoints. MFA check only on the login page, not re-verified on sensitive actions.
**Impact:** Attacker obtains a valid session token (phishing, session theft) and bypasses MFA by calling APIs directly.
**Fix:** MFA status must be a claim in the session/token, verified server-side on every sensitive request. Not just a UI gate.
**OWASP:** A07
