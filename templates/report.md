# Security Audit Report

**Project:** [PROJECT_NAME]
**Date:** [YYYY-MM-DD]
**Grade:** [GRADE] (Score: [SCORE]/100)
**Architecture Tier:** [TIER_NUMBER] — [TIER_NAME] ([GRADE_CAP_NOTE])
**Audit Status:** [COMPLETE | INCOMPLETE — domains not checked: LIST]

---

## Stack Detected

[List each detected technology on its own line, grouped by category]

- **Runtime:** [e.g., Node.js 20, Python 3.12]
- **Framework:** [e.g., Next.js 14, Express 4]
- **Database:** [e.g., PostgreSQL via Supabase, MongoDB]
- **Auth:** [e.g., Supabase Auth, NextAuth, custom JWT]
- **Hosting:** [e.g., Vercel, AWS EC2, self-hosted]
- **Other:** [e.g., Stripe SDK, Redis, Docker]

---

## Architecture Assessment

**Detected Tier:** [TIER_NUMBER] — [TIER_NAME]

[Explain which tier was detected and why. Reference specific evidence: e.g., "Server-side API routes in /app/api/ with Supabase service-role key usage indicate Tier 2 (Server-Mediated)."]

**Grade Cap:** [GRADE_CAP_NOTE — e.g., "Tier 2 allows up to A. No cap applied." or "Tier 1 caps the maximum grade at C regardless of score."]

[If Tier 1:]
> **Migration Recommendation:** This project accesses backend services directly from client code (Tier 1). To move to Tier 2:
> 1. Create server-side API routes or edge functions to proxy all sensitive operations
> 2. Move all secrets/service-role keys to server-only environment variables
> 3. Add Row Level Security (RLS) policies if using Supabase/Postgres
> 4. Re-audit after migration to unlock higher grades

---

## Findings

### Critical

[For each critical finding, use this format:]

**`[FILE:LINE]` — [VULNERABILITY_NAME]**

[Describe what an attacker can do. Be concrete: "An unauthenticated user can call this endpoint to delete any user's account by passing an arbitrary user ID." Avoid abstract language like "this could potentially be exploited."]

```[language]
// Before (vulnerable)
[vulnerable code snippet]

// After (secure)
[fixed code snippet with explanation comments]
```

[Repeat for each critical finding. If none: "No critical findings."]

---

### High

[Same format as Critical. Include code fix for each.]

[If none: "No high-severity findings."]

---

### Medium

[Same format. Code fix is optional — include when the fix is non-obvious.]

[If none: "No medium-severity findings."]

---

### Low

[Same format. Code fix is optional.]

[If none: "No low-severity findings."]

---

## Score Breakdown

| Domain | Findings | Deductions |
|--------|----------|------------|
| [domain] | [count by severity, e.g., 1 Critical, 2 Medium] | -[points] |
| [domain] | [count by severity] | -[points] |
| ... | ... | ... |
| **Subtotal** | | **-[total deductions]** |
| **Bonuses** | [list which bonuses apply, e.g., CSP headers, rate limiting] | **+[bonus points]** |
| **Final Score** | | **[100 - deductions + bonuses]** |
| **Raw Grade** | | **[grade before tier cap]** |
| **Tier Cap** | Tier [N] -> Max [cap grade] | **[applied / N/A]** |
| **Final Grade** | | **[final grade]** |

---

## Domain File Versions

| Domain | Version |
|--------|---------|
| [domain-name] | [version from domain file frontmatter] |
| [domain-name] | [version from domain file frontmatter] |
| ... | ... |

---

## Prioritized Fix Order

1. **[Most impactful fix]** — [Why this is #1: e.g., "Unauthenticated RCE; trivial to exploit, maximum blast radius."]
2. **[Second fix]** — [Rationale: e.g., "Auth bypass allows privilege escalation across all accounts."]
3. **[Third fix]** — [Rationale]
4. ...

[Order by: exploitability x impact. A trivially exploitable medium-severity issue may rank above a hard-to-reach high-severity one.]

---

## Comparison to Previous Audit

[If a previous report exists at `docs/security-audit-*.md`:]

- **Score delta:** [+/- points] ([old score] -> [new score])
- **Grade change:** [old grade] -> [new grade]
- **Fixed:** [list findings from previous audit that are now resolved]
- **New:** [list findings that appear for the first time]
- **Regressed:** [list findings that got worse or were reintroduced]

[If no previous report exists:]

This is the first audit for this project.
