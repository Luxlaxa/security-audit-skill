# Security Audit Scoring System

> Version: 1.0.0
> Referenced by: SKILL.md (scoring step)
> Purpose: Deterministic grade calculation from audit findings

---

## 1. Severity Point Deductions

| Severity | Points Deducted | Example Findings |
|----------|----------------|-----------------|
| Critical | -25 | Exposed service_role key, RLS disabled on table with user data, hardcoded secrets committed to git, client-side AI API keys |
| High | -15 | Client-submitted prices, no rate limits on AI endpoint, jwt.decode() without verify, tokens in localStorage, SSRF via user URL |
| Medium | -8 | Missing security headers (CSP, HSTS), no budget caps on AI providers, verbose error messages in production, no audit logging |
| Low | -3 | Missing Referrer-Policy header, dependency with known low-severity CVE, no structured logging |

---

## 2. Grade Thresholds

| Grade | Score Range | Meaning | Action |
|-------|-----------|---------|--------|
| A | 90-100 | Ship with confidence | Deploy |
| B | 75-89 | Solid, minor hardening needed | Ship with a plan to fix |
| C | 60-74 | Significant gaps | Fix before public launch |
| D | 40-59 | Serious vulnerabilities | Do not ship |
| F | 20-39 | Actively exploitable | Stop everything and fix |
| F- | 0-19 | Catastrophically compromised | Emergency: rotate ALL keys, assume breach has occurred |

---

## 3. Architecture Tier Grade Caps

| Tier | Max Grade | Rationale |
|------|-----------|-----------|
| Tier 1 (direct BaaS) | C | Single-layer defense is a structural risk — no matter how good your RLS is |
| Tier 2 (edge-protected) | A | Defense in depth — both layers must fail for a breach |
| Tier 3 (full backend) | A | Maximum control over security boundaries |
| Hybrid | B | Inconsistent defense layers = inconsistent security posture |

If the raw score would yield a higher grade than the tier cap allows, cap at the tier's maximum. Report:

> "Grade capped at [X] due to Tier [N] architecture. Upgrade to Tier [N+1] to unlock higher grades."

---

## 4. Bonus Points (max +10 total)

| Bonus | Points | How to Detect |
|-------|--------|--------------|
| SAST/DAST tooling configured | +3 | `.semgrep.yml`, `.github/codeql/`, `eslint-plugin-security` in config |
| Dependency scanning in CI | +3 | `npm audit` in CI scripts, Dependabot config (`.github/dependabot.yml`), Renovate config |
| Audit logging implemented | +2 | Structured security event logging detected in codebase (auth events, data access logs) |
| Key rotation policy | +2 | Documented rotation schedule or automated rotation scripts detected |

---

## 5. Calculation Formula

```
base_score = 100

for each unique finding:
    base_score -= severity_points[finding.severity]

bonus = min(10, sum of applicable bonus points)
base_score += bonus

final_score = max(0, min(100, base_score))

raw_grade = grade_from_score(final_score)
tier_cap = tier_grade_cap[detected_tier]
final_grade = min(raw_grade, tier_cap)  // apply tier cap
```

Grade comparison for tier capping uses this ordering: A > B > C > D > F > F-

---

## 6. Deduplication Rule

One finding per unique vulnerability. If both a domain file (e.g., `02-database-security.md`) and a stack file (e.g., `stacks/supabase.md`) identify the same RLS issue, count it **ONCE** under the domain file. Stack files add platform-specific context to findings but do not create separate deductions.

---

## 7. Grade Qualifiers

When score is F- (0-19), the report **MUST** include emergency messaging:

> **EMERGENCY: This codebase is catastrophically compromised.**
>
> Immediate actions required:
> 1. Rotate ALL API keys and secrets
> 2. Assume unauthorized access has occurred
> 3. Audit access logs for the past 30 days
> 4. Notify affected users if data exposure is confirmed

---

## 8. Score Breakdown in Report

The report must include a breakdown table showing per-domain deductions, bonuses, and final calculation:

| Domain | Findings | Deductions |
|--------|----------|-----------|
| 01-secrets-and-env | 2 Critical, 1 Medium | -58 |
| 02-database-security | 1 High | -15 |
| ... | ... | ... |
| **Subtotal** | | **-73** |
| **Bonuses** | SAST configured, Dep scanning | **+6** |
| **Final Score** | | **33** |
| **Raw Grade** | | **F** |
| **Tier Cap** | Tier 1 → Max C | **F (below cap)** |
| **Final Grade** | | **F** |

Rules for the breakdown table:
- List every domain file that produced findings, sorted by domain number
- Omit domains with zero findings
- Show finding counts grouped by severity
- Show arithmetic clearly so the score is auditable

---

## 9. Audit Comparison

If a previous audit report exists (check for `docs/security-audit-*.md`), include a comparison section:

- **Score delta**: "+12 points (45 → 57)"
- **Grade change**: "D → D (no change)" or "F → D (improved)"
- **Fixed findings**: list what was resolved since last audit
- **New findings**: list what appeared since last audit
- **Regressed findings**: list what got worse since last audit
- **Domain version changes**: note if domain file versions changed between audits (e.g., "02-database-security upgraded from v1.0.0 to v1.1.0 — 3 new patterns added")

If no previous audit report exists, state: "No previous audit found. Baseline established."
