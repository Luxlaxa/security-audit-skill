---
stack: nextjs
version: 1.0.0
augments: [03, 04, 05, 08, 12]
---

## Platform-Specific Patterns

### Server Actions Are Public Endpoints
- Every `"use server"` function is a publicly accessible HTTP POST endpoint
- ALWAYS validate input (zod schema), authenticate caller, and check authorization
- Never assume Server Actions are "private" because they're in a server file
- Treat them identically to API routes from a security perspective

### Middleware Limitations
- Runs on Edge Runtime: no full Node.js API (no `fs`, limited `crypto`, no native modules)
- Middleware auth checks are for UX (redirects) — NOT security enforcement
- MUST re-verify auth in Server Actions, Route Handlers, and data-fetching layers
- Middleware can be bypassed by direct API calls — never rely on it as sole auth gate

### Route Handlers
- Same security requirements as traditional Express API routes
- Validate auth: check session/token in every handler
- Use `NextRequest` for typed access to headers, cookies, search params
- Rate limiting: apply per-handler or via middleware (but remember Edge limitations)

### React Server Components (RSC) Data Fetching
- Never pass sensitive data from server to Client Components — it serializes into HTML/JS payload
- Select only needed fields: `SELECT id, name FROM users` not `SELECT *`
- Use `server-only` package to prevent accidental client import of server modules
- Data fetched in RSC is NOT automatically protected — still need auth checks

### next.config.js Security Headers
- `productionBrowserSourceMaps: false` — prevent source code exposure in production
- Security headers via `headers()` config: CSP, X-Frame-Options, X-Content-Type-Options
- `poweredBy: false` — remove `X-Powered-By: Next.js` header
- Configure `images.remotePatterns` strictly — open patterns allow SSRF via image optimization

### server-only Package
- `import 'server-only'` at top of any module with secrets, DB connections, or sensitive logic
- Build fails if a Client Component imports a `server-only` module — compile-time protection
- Essential for preventing credential leakage in RSC/Client Component boundaries

### Common Mistakes
- Using `process.env.NEXT_PUBLIC_*` for secrets — these are bundled into client JavaScript
- Trusting `headers()` or `cookies()` without verification in Server Actions
- Not setting CSP headers — XSS in any Client Component compromises the entire app
- Using `redirect()` in middleware as security — client can ignore redirects via direct fetch

## Cross-References
- **Domain 03** (Authentication): Server Actions need zod/yup validation — no automatic sanitization
- **Domain 04** (Authorization): Route Handlers are REST endpoints — apply full API security checklist
- **Domain 05** (Input Validation): Next.js has no built-in sessions — verify your auth library's cookie config
- **Domain 08** (API Security): Custom error pages (`error.tsx`) — never expose stack traces
- **Domain 12** (Deployment): Audit `next.config.js` rewrites/redirects — open redirects via misconfigured patterns
