---
stack: supabase
version: 1.0.0
augments: [00, 01, 02, 03, 04, 06, 17]
---

## Platform-Specific Patterns

### RLS Policy Best Practices
- Always use `(SELECT auth.uid())` subquery form — prevents per-row re-evaluation, major perf win
- Specify `TO authenticated` (or `TO anon`) on every policy — implicit `TO public` grants both roles
- Separate SELECT/INSERT/UPDATE/DELETE policies — combined policies hide logic bugs
- Use `WITH CHECK` for write policies, `USING` for read policies — don't confuse them

### Edge Function Security
- Use `service_role` key ONLY inside Edge Functions or server-side code — never in client bundles
- Set CORS headers explicitly: `Access-Control-Allow-Origin` to your domain, not `*`
- Validate auth: `const { data: { user } } = await supabase.auth.getUser()` — do NOT trust JWT without verification
- Edge Functions have no RLS bypass unless you use `supabase.auth.admin` with service_role

### Storage Bucket Policies
- Scope uploads to user UID folders: `(storage.foldername(name) = auth.uid()::text)`
- Validate file types in policy: `(storage.extension(name) = ANY(ARRAY['jpg','png','pdf']))`
- Set file size limits per bucket in dashboard — no policy-level enforcement

### Service Role Key Isolation
- NEVER ship `service_role` key in client code — it bypasses ALL RLS
- Use `anon` key in client, `service_role` only in Edge Functions or trusted servers
- Rotate keys if leaked: Dashboard > Settings > API > Regenerate

### Realtime Subscription Auth
- Realtime respects RLS — but verify user has SELECT policy on subscribed tables
- Channel-level auth: use Realtime Authorization (RLS on `realtime.messages`) for custom channels

### Common Mistakes
- Storing `subscription_status` or `credits` on a public profiles table — users can read/write via RLS gaps
- Trusting client-submitted `user_id` in INSERT — always override with `auth.uid()` in policy or trigger
- Forgetting RLS on junction tables — exposes relationships even if parent tables are protected

### MCP Integration
- Use Supabase MCP server for direct config auditing: query policies, inspect schemas, verify RLS status

## Cross-References
- **Domain 00** (Architecture Tier): Model Supabase-specific threats — RLS bypass, key leakage, storage abuse
- **Domain 01** (Secrets & Env): Supabase Auth handles sessions, but verify email confirmation is enforced
- **Domain 02** (Database Security): RLS IS your access control — audit every table
- **Domain 03** (Authentication): Edge Functions need input validation — Supabase doesn't auto-sanitize
- **Domain 04** (Authorization): PostgREST exposes your schema — restrict with RLS, not obscurity
- **Domain 06** (Rate Limiting): Enable TLS, audit column-level security for PII
- **Domain 17** (Serverless & Edge): Edge Functions = Deno Deploy — cold start, execution limits, no persistent state
