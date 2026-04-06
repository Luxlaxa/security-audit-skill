---
domain: supply-chain
version: 1.0.0
stacks: []
always_load: true
owasp: [A06, A08]
priority: [data-breach]
---

## Quick Check
1. Check `package-lock.json` or `pnpm-lock.yaml` committed to git
2. Check for `npm audit` / dependency scanning in CI config (`.github/workflows/`)
3. Grep for `postinstall` scripts in `package.json` of dependencies
4. Check for `.github/dependabot.yml` or `renovate.json`
5. Check if any dependency uses version ranges without lockfile

## Full Patterns

### No Lockfile Committed
**Vulnerability:** Build reproducibility failure / supply chain injection
**Severity:** High
**Detect:** Check git for `package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock`. If missing from repo but `package.json` exists, flag.
**Impact:** Attacker publishes malicious patch version of a dependency. Without lockfile, `npm install` in CI pulls the compromised version silently. Full server compromise.
**Fix:**
```bash
# Before: lockfile in .gitignore
echo "package-lock.json" >> .gitignore
# After: commit lockfile, remove from .gitignore
git add package-lock.json && git commit -m "chore: commit lockfile"
```
**OWASP:** A08 - Software and Data Integrity Failures

### No Dependency Scanning in CI
**Vulnerability:** Known vulnerabilities ship to production undetected
**Severity:** Medium
**Detect:** Grep `.github/workflows/*.yml` for `npm audit`, `snyk`, `socket`, or `trivy`. If absent, flag.
**Impact:** Dependencies with published CVEs deployed to production. Attackers exploit known vulns with public exploit code.
**Fix:**
```yaml
# Add to CI pipeline
- run: npm audit --audit-level=high
# Or use dedicated tools: Snyk, Socket.dev, Trivy
```
**OWASP:** A06 - Vulnerable and Outdated Components

### Typosquatting Risk
**Vulnerability:** Misspelled package names resolve to attacker-controlled packages
**Severity:** Medium
**Detect:** Compare `package.json` dependency names against known popular packages. Flag near-matches (e.g., `lodahs` vs `lodash`, `expres` vs `express`).
**Impact:** Developer typos during install pull malicious package that exfiltrates env vars, installs backdoors, or mines crypto.
**Fix:** Review all dependency names manually. Use `npm ls` to verify package metadata matches expected author/repo.
**OWASP:** A08 - Software and Data Integrity Failures

### Malicious Postinstall Scripts
**Vulnerability:** Lifecycle scripts execute arbitrary code during install
**Severity:** High
**Detect:** `grep -r "postinstall\|preinstall\|install" node_modules/*/package.json | grep -v "node-gyp\|node-pre-gyp"` — flag unfamiliar packages with lifecycle scripts.
**Impact:** Malicious `postinstall` runs on `npm install`, exfiltrating `.env`, SSH keys, or installing persistent backdoor before any code review.
**Fix:**
```bash
# Use --ignore-scripts for untrusted packages
npm install --ignore-scripts
# Or use npm config set ignore-scripts true (then manually run trusted scripts)
```
**OWASP:** A08 - Software and Data Integrity Failures

### Dependency Confusion
**Vulnerability:** Private package name squatted on public npm registry
**Severity:** High
**Detect:** Check for scoped packages (`@org/pkg`) vs unscoped private names. Grep `.npmrc` for registry config. Flag unscoped private package names that could exist on public npm.
**Impact:** Attacker registers your private package name on npmjs.com with higher version. CI pulls public malicious version instead of private one.
**Fix:**
```bash
# Before: unscoped private package
"my-internal-lib": "^1.0.0"
# After: scoped + registry pinned in .npmrc
"@myorg/internal-lib": "^1.0.0"
# .npmrc: @myorg:registry=https://npm.pkg.github.com
```
**OWASP:** A08 - Software and Data Integrity Failures

### Version Ranges Without Lockfile
**Vulnerability:** Semver ranges allow silent malicious updates
**Severity:** Medium
**Detect:** Grep `package.json` for `"^` or `"~` version prefixes. Cross-check that lockfile exists and is committed.
**Impact:** `^1.0.0` allows any `1.x.x`. Compromised minor/patch release auto-installed on next `npm install`.
**Fix:** Pin exact versions (`1.2.3` not `^1.2.3`) or ensure lockfile is committed and CI uses `npm ci` (not `npm install`).
**OWASP:** A08 - Software and Data Integrity Failures

### Outdated Dependencies with Known CVEs
**Vulnerability:** Running packages with published security advisories
**Severity:** Varies (check CVE severity)
**Detect:** `npm audit --json` — parse for critical/high severity. Check `npm outdated` for major version gaps.
**Impact:** Attackers use public exploit code for known CVEs. Prototype pollution, RCE, SSRF depending on the vulnerable package.
**Fix:**
```bash
npm audit fix
# For breaking changes:
npm audit fix --force  # review changes carefully
```
**OWASP:** A06 - Vulnerable and Outdated Components

### License Changes as Supply Chain Signal
**Vulnerability:** Unexpected license change indicates possible package takeover
**Severity:** Low
**Detect:** Compare current dependency licenses against baseline. Flag changes from permissive (MIT/Apache) to restrictive (GPL/SSPL) or unusual licenses.
**Impact:** License change may indicate maintainer account compromise, hostile takeover, or protest-ware. Review changelog and maintainer activity.
**Fix:** Pin to last known-good version. Investigate maintainer changes. Consider forking if package is compromised.
**OWASP:** A08 - Software and Data Integrity Failures
