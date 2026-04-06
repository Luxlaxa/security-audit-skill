# Stack Detector & Domain Loader

> Referenced by SKILL.md as the first step of any audit.
> Detects project technologies, classifies architecture tier, determines which domain and stack files to load.

---

## 1. Stack Detection Rules

Check in order: `package.json` (fastest) → directory structure → config files → import grep. Report **all** detected technologies.

| Technology | package.json | Directory | Config | Import Pattern |
|---|---|---|---|---|
| Supabase | `@supabase/supabase-js`, `@supabase/ssr` | `/supabase/`, `/supabase/functions/` | `supabase/config.toml` | `createClient` from supabase |
| Firebase | `firebase`, `firebase-admin` | `/functions/` | `firebase.json`, `.firebaserc` | `initializeApp` |
| Stripe | `stripe` | — | — | `new Stripe` |
| Next.js | `next` | `/app/`, `/pages/` | `next.config.js`, `next.config.mjs` | — |
| Express | `express` | `/server/`, `/api/` | — | `express()` |
| Fastify | `fastify` | — | — | `fastify()` |
| React Native | `react-native` | — | — | — |
| Expo | `expo` | — | `app.json`, `app.config.js` | — |
| OpenAI | `openai` | — | — | `new OpenAI` |
| Anthropic | `@anthropic-ai/sdk` | — | — | `new Anthropic` |
| Prisma | `@prisma/client` | `/prisma/` | `prisma/schema.prisma` | `new PrismaClient` |
| GraphQL | `graphql`, `@apollo/server`, `@apollo/client` | — | — | — |
| Docker | — | — | `Dockerfile`, `docker-compose.yml` | — |
| Vercel | — | — | `vercel.json` | — |
| Netlify | — | — | `netlify.toml` | — |

### Detection Procedure

1. Read `package.json` — scan `dependencies` and `devDependencies` keys against the table above.
2. List top-level directories — match against the Directory column.
3. Check for config files — match against the Config column.
4. If ambiguity remains, grep source files for import patterns in the Import Pattern column.
5. Collect all matches into a `detected_stack[]` list for use in later steps.

---

## 2. Architecture Tier Classification

| Tier | Detection Logic | Grade Cap |
|---|---|---|
| **Tier 1** (direct BaaS) | Supabase/Firebase client SDK imported in frontend dirs (`/app/`, `/src/`, `/pages/`, `/components/`) AND no edge functions directory (`/supabase/functions/`, `/functions/`) | Max **C** |
| **Tier 2** (edge-protected) | Edge/Cloud functions directory exists AND contains DB access logic (`service_role`, admin SDK) AND client code calls functions, not DB directly | Max **A** |
| **Tier 3** (full backend) | Express/Fastify in `package.json` AND DB client only in server dirs (`/server/`, `/api/`, `/backend/`, `/lib/server/`) | Max **A** |
| **Hybrid** | Mixed signals — some routes use direct BaaS, some go through functions | Max **B** |

### Tier Detection Steps

1. Check for Supabase/Firebase in `detected_stack[]`.
2. If found: grep for `createClient` / `initializeApp` in frontend directories (`/app/`, `/src/`, `/pages/`, `/components/`).
3. Check for edge/cloud functions directories (`/supabase/functions/`, `/functions/`).
4. If functions directory exists AND contains DB access patterns (`service_role`, `firebase-admin`, `getFirestore`): **Tier 2**.
5. If no functions directory AND client code calls DB directly: **Tier 1**.
6. If Express/Fastify detected AND no client-side DB calls found: **Tier 3**.
7. If mixed patterns (some direct BaaS + some function-mediated): **Hybrid**.

> **Important:** The tier grade cap limits the maximum overall score. A Tier 1 project cannot score above C regardless of how well other domains perform.

---

## 3. Domain Loading Matrix

### Always Load (11 domains)

These domains apply to every project regardless of stack:

| Domain | Reason |
|---|---|
| `00-architecture-tier` | Tier classification is always relevant |
| `01-secrets-and-env` | Every project has secrets to protect |
| `03-authentication` | Every user-facing app needs auth review |
| `04-authorization` | Access control is universally required |
| `05-input-validation` | All inputs must be validated |
| `06-rate-limiting` | All endpoints need abuse protection |
| `09-cryptography` | Crypto misuse is always possible |
| `12-deployment` | Deployment config affects security posture |
| `13-supply-chain` | Dependency risks apply to all projects |
| `14-logging-monitoring` | Observability is always needed |
| `15-data-protection` | Data handling rules are universal |

### Conditional Load (7 domains)

Load only when the detection condition is met:

| Domain | Load Condition |
|---|---|
| `02-database-security` | Supabase, Firebase, Prisma, or any database dependency in `detected_stack[]` |
| `07-payments` | Stripe or any payment library in `detected_stack[]` |
| `08-api-security` | API routes exist: Next.js `/app/api/`, `/pages/api/`, Express/Fastify routes, or GraphQL endpoint |
| `10-ai-integration` | OpenAI, Anthropic, or any AI SDK in `detected_stack[]` |
| `11-mobile` | React Native or Expo in `detected_stack[]` |
| `16-race-conditions` | Payments detected OR concurrent operation patterns found (queue workers, batch processing, shared mutable state) |
| `17-serverless-edge` | Supabase Edge Functions, Firebase Functions, Vercel Edge, AWS Lambda, or Netlify Functions detected |

### Manual Audit Only (2 domains)

These are loaded **only** during a `/security-audit` manual audit invocation:

| Domain | When |
|---|---|
| `18-incident-response` | Manual audit only |
| `19-testing-tooling` | Manual audit only |

---

## 4. Stack File Loading

After domain files are resolved, load matching stack-specific guidance:

| Stack File | Load Condition |
|---|---|
| `stacks/supabase.md` | Supabase in `detected_stack[]` |
| `stacks/firebase.md` | Firebase in `detected_stack[]` |
| `stacks/nextjs.md` | Next.js in `detected_stack[]` |
| `stacks/stripe.md` | Stripe in `detected_stack[]` |
| `stacks/node-express.md` | Express or Fastify in `detected_stack[]` |
| `stacks/react-native.md` | React Native or Expo in `detected_stack[]` |

---

## 5. Monorepo Detection

**Trigger:** Any of these files found at project root:
- `turbo.json`
- `pnpm-workspace.yaml`
- `lerna.json`
- `nx.json`

**If monorepo detected:**

1. Scan each `apps/*/package.json` and `packages/*/package.json` separately.
2. Run the full detection pipeline (Sections 1-4) per package.
3. Scope all findings to their package path (e.g., `apps/web: Tier 1`, `apps/api: Tier 3`).
4. The overall project tier is the **lowest** (most permissive / worst) tier found across packages.
5. Domain loading is the **union** of all per-package domain requirements.

---

## 6. Context Budget

Loading behavior varies by audit trigger mode:

| Mode | What to Load | Token Budget | Notes |
|---|---|---|---|
| **Auto-trigger** | Quick Check sections of relevant domains only | < 800 tokens | Minimal footprint for inline warnings |
| **Pre-deploy gate** | Quick Check sections of ALL relevant domains | < 500 tokens | Tight budget — essentials only |
| **Manual audit** | Full content of all relevant domains + stack files | No hard cap (see overflow rule) | Most thorough |

### Manual Audit Overflow Rule

If total loaded content exceeds **1,200 lines**, load domains in threat-priority order:

1. **Financial** — payment fraud, billing manipulation
2. **Data breach** — unauthorized data access, exfiltration
3. **Privilege escalation** — gaining unauthorized elevated access
4. **Account takeover** — auth bypass, session hijacking
5. **Disruption** — DoS, data corruption, service degradation

Priority is determined by each domain file's `priority` frontmatter field. Note which domains were skipped in the audit output so they can be reviewed in a follow-up pass.
