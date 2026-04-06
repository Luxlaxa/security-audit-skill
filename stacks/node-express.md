---
stack: node-express
version: 1.0.0
augments: [05, 06, 08, 12]
---

## Platform-Specific Patterns

### Middleware Ordering
- Correct order matters — misordering creates security gaps:
  1. `helmet()` — security headers first
  2. `cors(corsOptions)` — reject disallowed origins early
  3. `rateLimit(limiterConfig)` — throttle before processing
  4. `express.json({ limit: '1mb' })` — parse body with size limit
  5. `authenticate()` — verify identity
  6. Route handlers — business logic last

### Error Handling Middleware
- Always define 4-param error handler: `(err, req, res, next) =>`
- Production: return generic message `{ error: 'Internal server error' }` with 500
- Never send `err.stack`, `err.message`, or raw error objects to client
- Log full error server-side (structured logging with request ID)
- Handle async errors: wrap handlers with try/catch or use `express-async-errors`

### Body Parser Limits
- `express.json({ limit: '1mb' })` — prevents payload-based DoS
- `express.urlencoded({ extended: false, limit: '1mb' })` — `extended: false` uses querystring (safer)
- For file uploads: use `multer` with explicit `limits.fileSize`
- Reject unexpected content types: check `Content-Type` header before parsing

### Trust Proxy Configuration
- `app.set('trust proxy', 1)` — required behind reverse proxy (Vercel, Cloudflare, AWS ALB)
- Without it: `req.ip` returns proxy IP, rate limiting becomes per-proxy (useless)
- `1` = trust first proxy hop — correct for single-layer proxies
- Never use `true` (trusts all) in production — allows IP spoofing via X-Forwarded-For

### CORS Configuration
- Explicit origin allowlist: `origin: ['https://myapp.com', 'https://staging.myapp.com']`
- Never use `origin: '*'` on authenticated endpoints — browsers won't send cookies with wildcard
- `credentials: true` requires explicit origin (not wildcard)
- Set `methods` and `allowedHeaders` explicitly — don't rely on defaults

### Helmet.js
- One line for baseline security headers: `app.use(helmet())`
- Includes: CSP, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, and more
- Customize CSP for your needs: `helmet({ contentSecurityPolicy: { directives: {...} } })`
- `helmet.hidePoweredBy()` — removes X-Powered-By header (included by default)

### Common Mistakes
- Using `app.use(cors())` with no options — allows all origins
- Forgetting `express.raw()` on webhook routes (Stripe, etc.) — breaks signature verification
- Not setting `secure: true` on cookies behind HTTPS proxy
- Using `req.query` or `req.params` without validation — all values are strings, never assume types
- Serving static files without cache headers or path traversal protection

## Cross-References
- **Domain 05** (Input Validation): Configure `express-session` with secure cookie flags, store sessions server-side
- **Domain 06** (Rate Limiting): Use helmet for transport security headers, enforce HTTPS
- **Domain 08** (API Security): 4-param middleware pattern, never leak stack traces
- **Domain 12** (Deployment): Audit npm dependencies — `npm audit`, lock file integrity, minimize packages
