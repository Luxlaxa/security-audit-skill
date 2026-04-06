---
stack: stripe
version: 1.0.0
augments: [07, 16]
---

## Platform-Specific Patterns

### Checkout Session Security
- ALWAYS use Stripe Price IDs (`price_xxx`) — never accept amounts from the client
- Set `mode` explicitly: `payment`, `subscription`, or `setup`
- Use `client_reference_id` to tie session to your user — verify on completion
- `success_url` and `cancel_url`: never trust these as confirmation — always verify via webhook

### Webhook Endpoint
- MUST use raw body for signature verification: `express.raw({ type: 'application/json' })`
- Using `express.json()` on webhook route breaks signature — constructEvent will fail silently or throw
- `stripe.webhooks.constructEvent(rawBody, sig, webhookSecret)` — all three params required
- Return 200 quickly — process asynchronously to avoid timeouts and retries

### Webhook Secret Management
- Webhook signing secret (`whsec_xxx`) is separate from API key (`sk_xxx`)
- Each webhook endpoint gets its own secret — don't share across endpoints
- Rotate via Stripe Dashboard if compromised — update server immediately

### Customer Portal CSRF
- Portal sessions are URL-based — add CSRF protection on the endpoint that creates portal sessions
- Validate the authenticated user matches the Stripe customer ID before creating portal session
- Set `return_url` to your domain — never accept client-submitted return URLs

### Stripe Connect Security
- Scope all API calls to connected account: `stripe.accounts.retrieve(connectedAccountId)`
- Verify account ownership before any operation — don't trust client-submitted account IDs
- Use `stripe_account` header for on-behalf-of operations
- Restrict Connect scopes to minimum required (read vs write, specific resources)

### Idempotency
- Required on all mutation endpoints: `stripe.paymentIntents.create({...}, { idempotencyKey })`
- Generate keys server-side (UUID v4) — never accept client-generated keys
- Keys expire after 24 hours — safe for retry logic within that window
- Same key + different params = error — keys are bound to the first request

### Key Separation
- `sk_test_` vs `sk_live_` — separate keys per environment
- Never use live keys in preview/staging deployments
- Use restricted keys with minimum scopes for server-side operations
- `pk_test_` and `pk_live_` are safe for client — but don't mix environments

### Subscription Lifecycle
- Sync ALL state via webhooks — never trust client-side subscription status
- Critical events: `customer.subscription.created`, `.updated`, `.deleted`
- Payment events: `invoice.paid`, `invoice.payment_failed`
- Store `subscription.status` from webhook — not from Checkout Session completion
- Handle `past_due` and `unpaid` states — don't assume active after initial payment

## Cross-References
- **Domain 07** (Payments): Price manipulation, subscription status bypass, coupon abuse
- **Domain 16** (Race Conditions): PCI compliance via Stripe Elements, never handle raw card data
