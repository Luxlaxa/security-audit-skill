# Security Audit — Agent Skill for Claude Code

A 20-domain, enterprise-grade security audit skill for AI coding assistants. Detects your stack, assesses your architecture tier, and audits at three depth levels with an A-F security grade.

Built by Nut Suwanchote (Luxlaxa) and Trace, inspired by [Chris Raroque's vibe-security skill](https://github.com/raroque/vibe-security-skill).

## Install

### Claude Code

```bash
npx skills add https://github.com/Luxlaxa/security-audit-skill --skill security-audit
```

Or manually:

```bash
git clone https://github.com/Luxlaxa/security-audit-skill.git
cp -r security-audit-skill/ ~/.claude/skills/security-audit/
```

### Manual (any project)

```bash
cp -r security-audit-skill/ .claude/skills/security-audit/
```

## Usage

**Manual audit:** `/security-audit` or ask naturally — "audit my code", "check security", "is this safe?"

**Auto-trigger:** The skill activates automatically when you're writing code that touches auth, payments, database access, API keys, or AI integration.

**Pre-deploy gate:** Configure the hook in `settings.json` to check security before `git push`.

## What It Covers

| Domain | What It Catches |
|--------|----------------|
| **Architecture Tier** | Direct BaaS vs edge-protected vs full backend — caps your security grade |
| **Secrets & Env** | Hardcoded keys, client-side prefix exposure, git history leaks, AWS credentials |
| **Database Security** | Supabase RLS, Firebase Rules, Prisma injection, sensitive data on user-writable tables |
| **Authentication** | JWT bypass, OAuth/OIDC flaws, session hijacking, MFA bypass, Server Action exposure |
| **Authorization** | IDOR, privilege escalation, mass assignment, path traversal, multi-tenant isolation |
| **Input Validation** | XSS, SQL/NoSQL/command injection, file upload exploits, prototype pollution, ReDoS |
| **Rate Limiting** | Missing AI endpoint limits, user-writable rate counters, budget drain attacks |
| **Payments** | Client-submitted prices, webhook forgery, replay attacks, business logic flaws |
| **API Security** | CORS misconfiguration, CSRF, SSRF, GraphQL attacks, WebSocket auth |
| **Cryptography** | Weak hashing, predictable RNG, timing attacks, TLS bypass |
| **AI Integration** | Prompt injection, tool call forgery, RAG poisoning, spending caps, PII in prompts |
| **Mobile** | Bundle secret extraction, insecure storage, deep link injection, biometric bypass |
| **Deployment** | Source maps, .git exposure, missing headers, preview env key leakage, CI/CD injection |
| **Supply Chain** | Dependency vulns, lockfile tampering, typosquatting, malicious postinstall scripts |
| **Logging** | PII in logs, missing audit trails, log injection, no brute force alerting |
| **Data Protection** | Missing encryption at rest, no retention policy, GDPR right-to-deletion gaps |
| **Race Conditions** | Double-charge, TOCTOU, concurrent account creation, inventory oversell |
| **Serverless** | Over-permissioned IAM, timeout abuse, edge runtime limitations |
| **Incident Response** | Key rotation playbooks per provider, breach detection checklist |
| **Testing & Tooling** | SAST/DAST recommendations, gitleaks, npm audit, security code review checklist |

## How It Works

1. **Detects your stack** — scans package.json, config files, and imports
2. **Classifies architecture tier** — Tier 1 (direct BaaS), Tier 2 (edge-protected), Tier 3 (full backend)
3. **Loads relevant domains** — only checks what applies to your stack
4. **Audits systematically** — 20 security domains, 150+ vulnerability patterns
5. **Scores and grades** — A-F with severity breakdown, architecture tier caps

## Scoring

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 90-100 | Ship with confidence |
| B | 75-89 | Solid, minor hardening needed |
| C | 60-74 | Fix before public launch |
| D | 40-59 | Do not ship |
| F | 20-39 | Stop everything and fix |
| F- | 0-19 | Emergency: rotate all keys, assume breach |

Architecture tier caps your max grade: Tier 1 = max C, Tier 2 = max A, Tier 3 = max A.

## OWASP Top 10 Coverage

Full coverage of all OWASP Top 10 (2021):
A01 (Broken Access Control), A02 (Cryptographic Failures), A03 (Injection), A04 (Insecure Design), A05 (Security Misconfiguration), A06 (Vulnerable Components), A07 (Auth Failures), A08 (Data Integrity), A09 (Logging Failures), A10 (SSRF)

## License

MIT
