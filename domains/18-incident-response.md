---
domain: incident-response
version: 1.0.0
always_load: false
owasp: []
priority: [financial, data-breach]
stacks: []
---

> **Note:** This domain is loaded only during manual `/security-audit` audits. No automated Quick Check patterns — this is a reference playbook for incident response.

## Key Rotation Playbooks

### Supabase Key Rotation

1. Go to Supabase Dashboard > Settings > API
2. Generate new `anon` key and `service_role` key
3. Update all Edge Functions and server-side code with the new `service_role` key
4. Update all client-side apps with the new `anon` key
5. Redeploy all affected services
6. Revoke the old keys in the dashboard
7. Verify: test auth flows, RLS policies, and Edge Function calls

### Stripe Key Rotation

1. Go to Stripe Dashboard > Developers > API Keys
2. Create a new API key (Restricted Key for specific services, or Secret Key for full access)
3. Update server-side environment variables with the new key
4. Verify webhook endpoints still work (webhook signing secret is separate — rotate it independently if compromised)
5. Test a payment flow end-to-end in test mode, then verify live
6. Revoke the old key in the dashboard

### AWS Credential Rotation

1. Go to IAM Console > Users > Security Credentials
2. Create a new access key pair (Access Key ID + Secret Access Key)
3. Update all services, CI/CD pipelines, and deployments using the old key
4. Verify all services are functioning with the new key
5. Deactivate the old access key (do NOT delete yet)
6. Wait 24 hours, monitor for errors from anything still using the old key
7. Delete the old access key after confirming nothing depends on it

### OpenAI / Anthropic Key Rotation

1. Go to provider dashboard (platform.openai.com or console.anthropic.com)
2. Generate a new API key
3. Update server-side environment variables
4. Verify API calls work (test a simple completion/message request)
5. Delete the old key in the provider dashboard
6. Check usage dashboard for any unexpected activity before deletion

---

## "Key Leaked in Git" Emergency Checklist

**Priority: CRITICAL — Do this NOW, not after your standup.**

1. **Rotate the key IMMEDIATELY.** This is the only real fix. Cleaning git history does NOT un-compromise the key — bots scrape GitHub in real time.
2. **Check provider usage logs** for unauthorized activity in the last 24-48 hours:
   - Stripe: Dashboard > Events, look for unfamiliar charges or customer exports
   - AWS: CloudTrail, look for unfamiliar API calls or new resources
   - Supabase: Logs > API, look for bulk reads or admin operations
   - OpenAI/Anthropic: Usage dashboard, look for spikes
3. **If unauthorized usage found:** Assess scope of damage. Check what data was accessed, what actions were performed. Document everything with timestamps.
4. **Clean git history** with BFG Repo Cleaner (optional — the key is already compromised regardless):
   ```bash
   # Install: brew install bfg
   bfg --replace-text passwords.txt repo.git
   git reflog expire --expire=now --all && git gc --prune=now --aggressive
   git push --force
   ```
5. **Set up gitleaks pre-commit hook** to prevent future leaks:
   ```bash
   brew install gitleaks
   # Add to .pre-commit-config.yaml:
   # - repo: https://github.com/gitleaks/gitleaks
   #   rev: v8.18.0
   #   hooks:
   #     - id: gitleaks
   ```
6. **If user data was accessed:** Prepare breach notification per applicable legal requirements (GDPR: 72 hours, CCPA: "expedient", etc.). Consult legal counsel.

---

## Breach Detection Signs

Watch for these indicators across all services:

- **Unexpected API usage spikes** — sudden 10x increase in requests or costs
- **New admin accounts you didn't create** — check user tables and IAM users
- **Bulk data export patterns in logs** — large `SELECT *` queries, paginated full-table reads
- **Login from unexpected geographies** — auth logs showing unfamiliar IPs or countries
- **Unfamiliar webhook endpoints configured** — attacker adds their URL to receive your events
- **Modified RLS policies or security rules** — attacker weakens access controls for persistence
- **Unexpected DNS changes** — subdomain takeover or MX record modification
- **CI/CD pipeline modifications** — attacker adds exfiltration step to your build process
