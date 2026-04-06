---
domain: secrets-and-env
version: 1.0.0
stacks: []
always_load: true
owasp: [A05]
priority: [financial, data-breach]
---

## Quick Check

1. `grep -rn 'sk_live_\|sk_test_\|AKIA[A-Z0-9]\|ghp_\|glpat-\|xoxb-' --include='*.{ts,js,py,go,java,rb,env,json,yml,yaml,toml}' .`
2. `grep -rn '-----BEGIN.*PRIVATE KEY' .`
3. `grep -rn 'Bearer [a-zA-Z0-9]' --include='*.{ts,js,py,go,rb}' .`
4. `grep -E '\.env' .gitignore || echo "CRITICAL: .env not in .gitignore"`
5. `git ls-files | grep '\.env'`
6. `grep -rn 'NEXT_PUBLIC_\|VITE_\|EXPO_PUBLIC_\|REACT_APP_' --include='*.env*' . | grep -i 'SECRET\|SERVICE_ROLE\|PRIVATE\|API_KEY'`
7. `grep -rn 'password\s*=\s*["\x27]\|secret\s*=\s*["\x27]\|apiKey\s*=\s*["\x27]\|token\s*=\s*["\x27]' --include='*.{ts,js,py,go,rb}' .`
8. `grep -rn 'postgres://\|mongodb://\|mongodb+srv://\|mysql://\|redis://' . | grep -v node_modules | grep -v '.env.example'`
9. `grep -rn 'service_role\|SERVICE_ROLE' --include='*.{ts,js,tsx,jsx,vue,svelte}' .`

## Full Patterns

### Hardcoded API Keys
**Vulnerability:** Hardcoded API Keys in Source Code
**Severity:** Critical
**Detect:** Regex patterns for common key formats:
- Stripe: `sk_live_[a-zA-Z0-9]{24,}`, `sk_test_[a-zA-Z0-9]{24,}`
- AWS: `AKIA[A-Z0-9]{16}`
- GitHub: `ghp_[a-zA-Z0-9]{36}`
- GitLab: `glpat-[a-zA-Z0-9\-]{20}`
- Slack: `xoxb-[0-9]+-[0-9A-Za-z]+`
- Private Keys: `-----BEGIN (RSA |EC )?PRIVATE KEY-----`
**Impact:** Leaked API keys give attackers direct access to paid services. AWS keys have been used to spin up crypto mining ($30K+ bills). Stripe keys allow fraudulent charges. GitHub tokens allow code theft and supply chain attacks.
**Fix:**
```diff
- const stripe = new Stripe("sk_live_abc123def456...");
+ const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
```
Move all keys to environment variables. If a key was ever committed to git, it is compromised — rotate immediately. Git history cannot be fully cleaned.
**OWASP:** A05

### Client-Side Environment Variable Prefix Exposure
**Vulnerability:** Secrets Exposed via Client-Side Env Prefixes
**Severity:** Critical
**Detect:** Check env files and code for these prefixes on secret values:
- Next.js: `NEXT_PUBLIC_` — exposed in browser bundle
- Vite: `VITE_` — exposed in browser bundle
- Expo: `EXPO_PUBLIC_` — exposed in mobile bundle
- Create React App: `REACT_APP_` — exposed in browser bundle

Safe to expose client-side: Supabase anon key, Stripe publishable key (`pk_`), Firebase config (apiKey, authDomain), public analytics IDs.

NEVER expose client-side: Supabase `service_role`, Stripe secret key (`sk_`), database connection strings, OpenAI/Anthropic API keys, JWT signing secrets, OAuth client secrets, email service API keys (SendGrid, Postmark).
**Impact:** Any value with these prefixes is extractable by anyone visiting your site. If it is a secret key, your service is fully compromised. Supabase `service_role` bypasses all RLS policies.
**Fix:**
```diff
- NEXT_PUBLIC_SUPABASE_SERVICE_ROLE=eyJhbGciOi...
+ SUPABASE_SERVICE_ROLE=eyJhbGciOi...
```
Remove the client prefix, move to server-side only env var, access only from API routes or Edge Functions.
**OWASP:** A05

### .env Not in .gitignore
**Vulnerability:** Environment Files Not Excluded from Version Control
**Severity:** Critical
**Detect:** Check if `.env` appears in `.gitignore`. Run `git ls-files | grep '\.env'` to find tracked env files.
**Impact:** Environment files committed to git are permanently in history. Even after removal, anyone with repo access (or if the repo was ever public) can extract all secrets from git history.
**Fix:**
```gitignore
# Add to .gitignore
.env
.env.local
.env.*.local
```
Add to `.gitignore` immediately. Rotate ALL keys that were in the committed file. Use BFG Repo Cleaner if needed, but assume keys are compromised regardless.
**OWASP:** A05

### Git History Secret Leakage
**Vulnerability:** Secrets Persisting in Git History After Removal
**Severity:** High
**Detect:** Run `gitleaks detect` or grep git log for key patterns. Common patterns: `sk_live_`, `AKIA`, `ghp_`, `password`, `secret`, connection strings. Check with: `git log -p --all -S 'sk_live_' --diff-filter=D`
**Impact:** Secrets removed from current code may still be in git history. Automated scanners continuously search public repos. Keys are typically exploited within minutes of public exposure.
**Fix:** Rotate the key immediately — this is the only real fix. Optionally clean history with BFG Repo Cleaner. Set up `gitleaks` as a pre-commit hook to prevent future leaks:
```bash
# Install gitleaks pre-commit hook
brew install gitleaks
gitleaks protect --staged
```
**OWASP:** A05

### CI/CD Secret Exposure
**Vulnerability:** Secrets Hardcoded or Logged in CI/CD Pipelines
**Severity:** High
**Detect:** Check CI config files for hardcoded secrets or debug logging:
- `.github/workflows/*.yml` — look for inline secrets or `echo $SECRET`
- `vercel.json` — check for `env` blocks with literal values
- `netlify.toml` — check for `[build.environment]` with secrets
- Dockerfile — check for `ARG` or `ENV` with secret values
**Impact:** Build logs and artifacts may be accessible to all repo collaborators. Secrets printed to stdout appear in logs and are often retained for weeks. Docker layer caching can expose secrets in intermediate layers.
**Fix:**
```diff
# GitHub Actions
- env:
-   API_KEY: sk_live_abc123
+ env:
+   API_KEY: ${{ secrets.API_KEY }}
```
Use CI platform secret management (GitHub Secrets, Vercel Environment Variables). Never echo secret values. Use masking.
**OWASP:** A05

### Hardcoded Connection Strings
**Vulnerability:** Database Credentials Embedded in Connection Strings
**Severity:** Critical
**Detect:** Grep for connection string patterns with embedded credentials:
- `postgres://user:password@host/db`
- `postgresql://user:password@host/db`
- `mongodb://user:password@host/db`
- `mongodb+srv://user:password@host/db`
- `mysql://user:password@host/db`
- `redis://user:password@host:port`
**Impact:** Database connection strings give direct database access, bypassing all application-level security including RLS. Attackers can read, modify, or delete all data.
**Fix:**
```diff
- const db = new Pool({ connectionString: "postgres://admin:s3cret@db.example.com/myapp" });
+ const db = new Pool({ connectionString: process.env.DATABASE_URL });
```
Use environment variables for connection strings. Never hardcode. Restrict database network access with allowlists.
**OWASP:** A05

### Monorepo Secret Isolation
**Vulnerability:** Shared Secrets Across Monorepo Packages
**Severity:** Medium
**Detect:** In monorepos, check if a shared `.env` at the root contains secrets for multiple services. Check if frontend packages can access backend env files. Look for `../../.env` references in package code.
**Impact:** A frontend package could accidentally bundle secrets meant for the backend package. Turborepo, Nx, and similar tools may propagate env vars across packages unexpectedly.
**Fix:**
```
# Per-package .env files instead of shared root
packages/
  web/.env          # Only NEXT_PUBLIC_ vars
  api/.env          # Server-only secrets
  shared/.env       # No secrets, only config
```
Use per-package `.env` files. Configure build tools to restrict which env vars each package can access. Use Turborepo's `globalEnv` and `env` in `turbo.json`.
**OWASP:** A05

### .env.local vs .env Confusion
**Vulnerability:** Local Environment Override Files Committed to Git
**Severity:** Medium
**Detect:** Check for `.env.local`, `.env.development.local`, `.env.production.local` files. Verify all are in `.gitignore`. Check for secrets in `.env.development` or `.env.production` (these are often committed intentionally but should not contain real secrets).
**Impact:** Local override files sometimes contain real production credentials that get committed by mistake. Developers may put their personal API keys in `.env.local` and accidentally commit them.
**Fix:**
```gitignore
# .gitignore — cover all local override patterns
.env.local
.env.development.local
.env.test.local
.env.production.local
```
Commit only `.env.example` with placeholder values as the template. Document which variables are required in the example file.
**OWASP:** A05

### Secret Rotation Detection
**Vulnerability:** Long-Lived Unrotated API Keys
**Severity:** Medium
**Detect:** Check if API keys in use match known old or default patterns. Look for `TODO`, `FIXME`, `HACK` comments about key rotation. Check if the same key appears in multiple environments. Look for keys created more than 90 days ago (check provider dashboards).
**Impact:** Long-lived keys accumulate risk. If ever exposed (even briefly), old unrotated keys remain valid indefinitely. Compromised keys discovered months later still work.
**Fix:** Implement a regular rotation schedule:
1. Create new key in provider dashboard
2. Update environment variables in all deployments
3. Verify new key works in production
4. Revoke old key
Most providers support key rotation without downtime. Set calendar reminders for 90-day rotation cycles.
**OWASP:** A05

### AWS Credential Patterns
**Vulnerability:** AWS Access Keys Hardcoded or Leaked
**Severity:** Critical
**Detect:** Grep for `AKIA[A-Z0-9]{16}` (access key ID) near a 40-character base64 string (secret access key). Also check for `aws_access_key_id` and `aws_secret_access_key` in any non-`.env` file. Check `~/.aws/credentials` for overly broad permissions.
**Impact:** AWS credentials with broad permissions have been used for crypto mining, SageMaker abuse ($30K+ bills overnight), S3 data theft, and spam relay via SES. This is one of the most financially devastating leaks. Attackers run automated scanners on every public GitHub commit.
**Fix:**
```diff
- aws_access_key_id = AKIAIOSFODNN7EXAMPLE
- aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
+ # Use IAM roles (EC2/ECS/Lambda) or SSO
+ # If keys are required, scope to minimum permissions
```
Use IAM roles instead of long-lived keys where possible. If keys are needed, scope to minimum permissions with an explicit policy. Set AWS budget alerts and hard spending caps. Rotate immediately if leaked — AWS provides automated key rotation via Secrets Manager.
**OWASP:** A05
