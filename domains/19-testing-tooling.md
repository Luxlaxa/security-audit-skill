---
domain: testing-tooling
version: 1.0.0
always_load: false
owasp: []
priority: []
stacks: []
---

> **Note:** This domain is loaded only during manual `/security-audit` audits. No automated Quick Check patterns — this is a reference guide for security testing tools and integration.

## SAST (Static Analysis)

### Semgrep
Custom rules for framework-specific patterns. Best balance of speed, accuracy, and customizability.
```bash
pip install semgrep
semgrep --config=auto .                    # Use curated community rules
semgrep --config=p/owasp-top-ten .         # OWASP-focused ruleset
semgrep --config=p/typescript .            # Language-specific rules
```

### CodeQL
GitHub-native, runs in CI via GitHub Actions. Best for complex data flow analysis (taint tracking across function boundaries). Free for public repos, included with GitHub Advanced Security for private repos.

### eslint-plugin-security
Lightweight, catches common Node.js patterns (eval, non-literal RegExp, timing attacks).
```bash
npm i -D eslint-plugin-security
# Add to .eslintrc: plugins: ["security"], extends: ["plugin:security/recommended"]
```

## DAST (Dynamic Analysis)

### OWASP ZAP
Free and open source. Good for API testing and automated scanning.
- Run against **staging**, never production
- API scan: `zap-api-scan.py -t https://staging.example.com/api/openapi.json -f openapi`
- Spider + active scan for full-site coverage

### Burp Suite
Professional-grade manual testing tool. Community Edition is free (no scanner, but interceptor + repeater work).
- Best for manual penetration testing of auth flows, business logic
- Use with browser proxy to intercept and modify requests

## Secret Scanning

### gitleaks
Pre-commit hook and CI integration. Catches keys, tokens, and passwords in source code and git history.
```bash
brew install gitleaks
gitleaks detect --source .                 # Scan current files
gitleaks detect --source . --log-opts="--all"  # Scan full git history
```

**Pre-commit hook config** (`.pre-commit-config.yaml`):
```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

## Dependency Scanning

### npm audit
Built-in, zero setup. Run in CI to catch known vulnerabilities in dependencies.
```bash
npm audit                                  # Full report
npm audit --audit-level=high               # Fail only on high/critical
npm audit fix                              # Auto-fix where possible
```

### Snyk
More comprehensive than npm audit. Monitors dependencies continuously, suggests fixes with PRs.
```bash
npm i -g snyk
snyk test                                  # One-time scan
snyk monitor                               # Continuous monitoring
```

### Socket.dev
Focuses on supply chain attacks — typosquatting, install scripts, obfuscated code. Catches threats that npm audit and Snyk miss because those tools only check known CVEs.

## CI Integration Example

**GitHub Actions** (`.github/workflows/security.yml`):
```yaml
name: Security Checks
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # Full history for gitleaks
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci
      - name: Dependency audit
        run: npm audit --audit-level=high
      - name: Secret scanning
        run: npx gitleaks detect --source .
      - name: Static analysis
        run: npx semgrep --config=auto .
```

## Code Review Security Checklist

For non-security-experts reviewing PRs — check these before approving:

- [ ] Are all user inputs validated and sanitized before use?
- [ ] Are auth checks present in every API route, server action, and middleware?
- [ ] Are secrets stored in env vars, not hardcoded in source?
- [ ] Is data access scoped to the authenticated user (RLS, WHERE clauses)?
- [ ] Are prices, amounts, and quantities looked up server-side (not from client)?
- [ ] Are external API calls rate limited and wrapped in timeouts?
- [ ] Are error messages generic to users (no stack traces, SQL errors, or internal paths)?
- [ ] Do new database queries use parameterized statements (no string concatenation)?
- [ ] Are file uploads validated for type, size, and stored outside webroot?
- [ ] Are new dependencies from trusted sources with active maintenance?
