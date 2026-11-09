---
name: security-audit
description: >
  Audits codebases for security vulnerabilities that AI coding assistants introduce.
  Checks for exposed API keys, broken access control (Supabase RLS, Firebase rules),
  missing auth validation, client-side trust issues, insecure payment flows, rate
  limiting gaps, cryptographic failures, SSRF, CSRF, XSS, prompt injection, supply
  chain risks, and more. Use when the user asks about security, wants a code review,
  mentions vibe coding, or when writing/reviewing code that handles authentication,
  authorization, payments, database access, API keys, secrets, rate limits, AI
  integration, file uploads, deployment, or user data. Also trigger on: is this safe,
  check my code, audit this, review for vulnerabilities, can someone hack this,
  security audit, pen test, vulnerability scan.
license: MIT
metadata:
  author: Nut Suwanchote (Luxlaxa)
  version: 1.0.0
---

# Security Audit Skill

## Core Principle

**Never trust the client.** Every price, user ID, role, subscription status, feature flag, and rate limit counter must be validated or enforced server-side. If it exists only in the browser, mobile bundle, or request body, an attacker controls it.

---

## Trigger Modes

### 1. Auto-trigger (Shallow)

Fires automatically during security-related conversations. Designed to be invisible and lightweight.

- **Loads:** Only the **Quick Check** sections of relevant domains.
- **Actions:** Inline fixes for **Critical** findings, warnings for **High**, silence for Medium/Low.
- **Context budget:** <800 tokens.

### 2. Manual Audit (`/security-audit`)

Full deep audit with stack detection. Generates a scored report.

**Process:**

1. Run detector (`detector.md`).
2. Determine architecture tier.
3. Load relevant domains (full content) + stack-specific files.
4. Audit systematically, domain by domain.
5. Calculate security grade using `scoring.md`.
6. Generate report using `templates/report.md`.
7. Write report to `docs/security-audit-YYYY-MM-DD.md` in the project root.

**Context budget overflow rule:** If loaded domains exceed **1,200 lines**, load in threat-priority order:

1. Financial impact (payments, billing)
2. Data breach (secrets, database, data protection)
3. Privilege escalation (authorization, authentication)
4. Account takeover (auth, session)
5. Disruption (rate limiting, deployment)

Note any skipped domains in the report.

**Partial/interrupted audit:** If the audit cannot complete, save with an `[INCOMPLETE]` marker and list all unchecked domains.

### 3. Pre-deploy Gate

Medium depth check before shipping.

- **Loads:** Quick Check sections of **all** relevant domains.
- **Output:** `PASS` / `FAIL`.
- **Blocks** on any Critical finding.
- **Warns** on High findings.

---

## Detection Process

Before auditing, read `detector.md` and follow its instructions to identify the project's:

- **Stack** (frameworks, databases, payment providers, AI SDKs)
- **Architecture tier** (static site, SPA, SSR, API server, full-stack, monorepo)
- **Which domain files to load** based on detected technologies

---

## Audit Process

Work through each applicable step in order. Skip steps whose technology is not detected in the codebase.

| Step | Domain | Reference File |
|------|--------|---------------|
| 1 | Secrets & Environment Variables | `domains/01-secrets-and-env.md` |
| 2 | Architecture Tier | `domains/00-architecture-tier.md` |
| 3 | Database Access Control | `domains/02-database-security.md` *(if Supabase/Firebase/Prisma)* |
| 4 | Authentication & Authorization | `domains/03-authentication.md` + `domains/04-authorization.md` |
| 5 | Rate Limiting & Abuse Prevention | `domains/06-rate-limiting.md` |
| 6 | Payment Security | `domains/07-payments.md` *(if Stripe)* |
| 7 | API Security | `domains/08-api-security.md` *(if API routes exist)* |
| 8 | AI/LLM Integration | `domains/10-ai-integration.md` *(if AI SDK detected)* |
| 9 | Additional domains as detected: | |
| | Input Validation | `domains/05-input-validation.md` |
| | Cryptography | `domains/09-cryptography.md` |
| | Mobile Security | `domains/11-mobile.md` |
| | Deployment | `domains/12-deployment.md` |
| | Supply Chain | `domains/13-supply-chain.md` |
| | Logging & Monitoring | `domains/14-logging-monitoring.md` |
| | Data Protection | `domains/15-data-protection.md` |
| | Race Conditions | `domains/16-race-conditions.md` |
| | Serverless & Edge | `domains/17-serverless-edge.md` |

**Manual audit only:**

| Domain | Reference File |
|--------|---------------|
| Incident Response | `domains/18-incident-response.md` |
| Testing & Tooling | `domains/19-testing-tooling.md` |

---

## Scoring

Refer to `scoring.md` for the full scoring rubric, grade thresholds, and calculation methodology.

---

## Output Format

Organize all findings from **Critical > High > Medium > Low**.

Each finding must include:

1. **File + line** — exact location in the codebase.
2. **Vulnerability name** — concise label (e.g., "Exposed Stripe Secret Key").
3. **Concrete attacker impact** — what an attacker can do, not theoretical risk.
4. **Before/after code fix** — working remediation, not just advice.

**Skip areas with no issues.** Do not pad the report.

End with a **prioritized summary** listing the top actions the developer should take, ordered by severity and exploitability.

---

## When Generating Code

These rules also apply proactively. Before writing code that touches auth, payments, database access, API keys, or user data, consult the relevant reference file to avoid introducing the vulnerability in the first place.

---

## Core Instructions

- **Report only genuine security issues.** Do not nitpick style.
- **Prioritize by exploitability and real-world impact.**
- **Skip technologies not in the codebase.**
- **Flag critical issues immediately at the top** — don't bury them.
- **Load only relevant reference files** for the detected stack.

---

## References

### Domain Files

| File | Description |
|------|-------------|
| `domains/00-architecture-tier.md` | Architecture tier classification and tier-specific security requirements |
| `domains/01-secrets-and-env.md` | API key exposure, .env handling, secret rotation, and environment variable security |
| `domains/02-database-security.md` | RLS policies, Firebase rules, ORM injection, direct DB access control |
| `domains/03-authentication.md` | Auth flows, session management, token handling, OAuth/OIDC, MFA |
| `domains/04-authorization.md` | Role-based access, permission checks, privilege escalation prevention |
| `domains/05-input-validation.md` | XSS, SQL injection, path traversal, file upload validation, sanitization |
| `domains/06-rate-limiting.md` | Brute force prevention, API throttling, abuse detection, DDoS mitigation |
| `domains/07-payments.md` | Stripe integration security, price validation, webhook verification, PCI compliance |
| `domains/08-api-security.md` | CORS, CSRF, SSRF, API authentication, request validation, endpoint hardening |
| `domains/09-cryptography.md` | Hashing, encryption, key management, TLS configuration, random number generation |
| `domains/10-ai-integration.md` | Prompt injection, LLM output sanitization, API key scoping, cost controls |
| `domains/11-mobile.md` | Mobile-specific storage, certificate pinning, binary protections, deep links |
| `domains/12-deployment.md` | CI/CD security, container hardening, cloud misconfigurations, infrastructure as code |
| `domains/13-supply-chain.md` | Dependency vulnerabilities, lockfile integrity, typosquatting, build pipeline security |
| `domains/14-logging-monitoring.md` | Sensitive data in logs, audit trails, alerting, log injection prevention |
| `domains/15-data-protection.md` | PII handling, encryption at rest, data retention, GDPR/privacy compliance |
| `domains/16-race-conditions.md` | TOCTOU bugs, double-spend, concurrent request exploitation, atomic operations |
| `domains/17-serverless-edge.md` | Cold start leaks, function permissions, edge runtime limitations, state management |
| `domains/18-incident-response.md` | Breach response plans, key rotation procedures, forensic readiness (manual audit only) |
| `domains/19-testing-tooling.md` | Security testing tools, SAST/DAST integration, penetration testing guidance (manual audit only) |

### Stack Files

| File | Description |
|------|-------------|
| `stacks/nextjs.md` | Next.js-specific security patterns (App Router, Server Actions, middleware) |
| `stacks/supabase.md` | Supabase RLS, auth helpers, edge functions, storage policies |
| `stacks/firebase.md` | Firebase security rules, Admin SDK usage, Firestore/RTDB access control |
| `stacks/stripe.md` | Stripe integration hardening, webhook security, Connect/Billing patterns |
| `stacks/node-express.md` | Express/Fastify middleware ordering, body parsing, trust proxy, helmet |
| `stacks/react-native.md` | React Native/Expo secure storage, certificate pinning, OTA updates |

### Supporting Files

| File | Description |
|------|-------------|
| `detector.md` | Stack and architecture detection logic — run first before any audit |
| `scoring.md` | Severity scoring rubric, grade calculation, and threshold definitions |
| `templates/report.md` | Full audit report template with all sections |
| `templates/gate.md` | Pre-deploy pass/fail gate output template |
