---
domain: serverless-edge
version: 1.0.0
stacks: [supabase, firebase, vercel]
always_load: false
owasp: [A05]
priority: [financial, data-breach]
---

## Quick Check

```bash
# Overly broad IAM policies — wildcard actions or resources
rg -n '"Action":\s*"\*"|"Resource":\s*"\*"' --type json --type yaml
# Secrets hardcoded in function source (not env vars)
rg -n "(sk_live_|sk_test_|AKIA[A-Z0-9]{16}|ghp_|glpat-|xoxb-)" --type ts --type js --type py
# Excessively long function timeouts (>60s for most use cases)
rg -n "timeout.*[0-9]{3,}|TimeoutSeconds|functionTimeout" --type json --type yaml --type toml
# Edge runtime using Node.js-only crypto APIs
rg -n "require\(['\"]crypto['\"]\)|from ['\"]crypto['\"]" --type ts --type js | rg -i "edge|middleware"
```

## Full Patterns

### 1. Over-Permissioned IAM Roles

**Vulnerability:** Lambda/Cloud Functions with `Action: *` or `Resource: *` in IAM policies
**Severity:** High
**Detect:** Search IAM policy JSON/YAML files for wildcard permissions. Check `serverless.yml`, `template.yaml` (SAM), or `terraform` files for `Effect: Allow` with `Action: "*"`.
**Impact:** A compromised function with `Action: *` can read all S3 buckets, modify databases, create new IAM users — full account takeover from a single function exploit.
**Fix:** Apply least privilege. Each function gets only the specific permissions it needs (e.g., `s3:GetObject` on one specific bucket ARN). Use separate IAM roles per function, not one shared role.
**OWASP:** A05 — Security Misconfiguration

### 2. Function Timeout Abuse

**Vulnerability:** Excessively long timeouts on serverless functions enable resource exhaustion
**Severity:** Medium
**Detect:** Check function configuration for timeouts > 60 seconds. Look at `vercel.json`, `netlify.toml`, `serverless.yml`, or cloud console settings.
**Impact:** Attacker sends slow requests that hold functions open for the maximum timeout. At $0.0000166667/GB-second (Lambda), 1000 concurrent 900-second invocations = significant bill. Also exhausts concurrency limits, causing DoS for legitimate users.
**Fix:** Set timeouts to the minimum needed (most API handlers need < 10s). Add request-level timeouts for external API calls. Set concurrency limits and billing alerts.
**OWASP:** A05 — Security Misconfiguration

### 3. Cold Start Timing Attacks

**Vulnerability:** Timing differences between cold and warm starts leak request pattern information
**Severity:** Low
**Detect:** Measure response times for the same endpoint over time. Cold starts typically add 100-500ms (Node.js) or 1-5s (Java/C#).
**Impact:** Attacker can infer whether a function is frequently called (warm) or rarely called (cold). In multi-tenant setups, this can reveal usage patterns of other tenants.
**Fix:** Use provisioned concurrency for sensitive endpoints. Add random jitter to response times if timing is a concern. Generally low risk — prioritize other issues first.
**OWASP:** A05 — Security Misconfiguration

### 4. Secrets in Function Source Code

**Vulnerability:** API keys, database credentials, or tokens hardcoded in .js/.ts/.py files
**Severity:** Critical
**Detect:** Grep for patterns like `sk_live_`, `AKIA`, `ghp_`, `password = "`, or long base64 strings assigned to variables named `key`, `secret`, `token`.
**Impact:** Secrets in source code end up in version control, build logs, error stack traces, and client bundles. Anyone with repo access (or a leaked bundle) gets full API access.
**Fix:** Use environment variables (`process.env.STRIPE_KEY`, `Deno.env.get("KEY")`). In Vercel/Netlify: set via dashboard. In AWS: use Secrets Manager or SSM Parameter Store. Never log env vars.
**OWASP:** A05 — Security Misconfiguration

### 5. Shared Execution Environment Risks

**Vulnerability:** Data leaking between invocations via global state or /tmp directory
**Severity:** Medium
**Detect:** Grep for writes to `/tmp` or global/module-level variables that store user-specific data (`let userSession = ...` outside handler function).
**Impact:** User A's request stores sensitive data in a global variable. User B's request (on the same warm instance) reads it. In `/tmp`: files from previous invocations persist and may contain credentials or PII.
**Fix:** Never store user-specific data in global scope or `/tmp` without per-request namespacing. Clear `/tmp` files after use. Use global scope only for reusable connections (DB pools) that don't contain user data.
**OWASP:** A05 — Security Misconfiguration

### 6. Edge Runtime Crypto Limitations

**Vulnerability:** Vercel Edge Runtime and Cloudflare Workers lack full Node.js `crypto` module
**Severity:** Medium
**Detect:** Grep for `require('crypto')` or `import { ... } from 'crypto'` in files marked as edge runtime (`export const runtime = 'edge'`). Check middleware files.
**Impact:** Code that works in Node.js serverless functions silently fails or throws at the edge. If crypto operations fail, auth checks may be bypassed, signatures may not be verified, or the function falls back to insecure alternatives.
**Fix:** Use the Web Crypto API (`crypto.subtle`) which is available in all edge runtimes. For HMAC verification: `crypto.subtle.importKey()` + `crypto.subtle.sign()`. Use libraries like `jose` (for JWT) that support Web Crypto natively.
**OWASP:** A05 — Security Misconfiguration
