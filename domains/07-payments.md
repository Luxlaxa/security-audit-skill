---
domain: payments
version: 1.0.0
stacks: [stripe]
always_load: false
owasp: [A04]
priority: [financial]
---

## Quick Check

1. `grep -rn "req\.body\.price\|req\.body\.amount\|body\.price\|body\.amount\|body\.unitAmount" --include="*.ts" --include="*.js"` → client-submitted prices (Critical)
2. Webhook route WITHOUT `stripe.webhooks.constructEvent` → no signature verification (Critical)
3. `grep -rn "localStorage.*subscription\|localStorage.*premium\|useState.*subscription\|cookie.*plan" --include="*.ts" --include="*.tsx" --include="*.js"` → client-side subscription status
4. `grep -rn "express\.json" --include="*.ts" --include="*.js"` on webhook route → breaks signature verification (needs `express.raw()`)
5. `grep -rn "sk_live_\|sk_test_" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx"` in client-accessible dirs → exposed secret key (Critical)
6. `grep -rn "req\.body\.metadata\|body\.metadata" --include="*.ts" --include="*.js"` → client-controlled metadata
7. `grep -rn "idempotencyKey\|idempotency_key\|Idempotency-Key" --include="*.ts" --include="*.js"` → check presence on payment mutation endpoints

## Full Patterns

### Client-Submitted Prices
**Vulnerability:** Price/amount sourced from client request body
**Severity:** Critical
**Detect:** Checkout or payment creation reads price/amount from `req.body.price`, `req.body.amount`, `body.unitAmount`. Price should come from server-side lookup.
**Impact:** Attacker intercepts request and sets price to $0.01 or $0. They purchase products/subscriptions for nothing. Most common payment vulnerability in vibe-coded apps.
**Fix:**
```typescript
// VULNERABLE — price from client request
app.post('/api/checkout', async (req, res) => {
  const session = await stripe.checkout.sessions.create({
    line_items: [{
      price_data: {
        currency: 'usd',
        unit_amount: req.body.price,  // attacker controls this!
        product_data: { name: req.body.productName }
      },
      quantity: 1
    }]
  })
  res.json({ url: session.url })
})

// SECURE — price looked up server-side
app.post('/api/checkout', async (req, res) => {
  const product = await db.products.findUnique({
    where: { id: req.body.productId }
  })
  if (!product) return res.status(404).json({ error: 'Product not found' })

  const session = await stripe.checkout.sessions.create({
    line_items: [{ price: product.stripePriceId, quantity: 1 }]
  })
  res.json({ url: session.url })
})
```
**OWASP:** A04

### Missing Webhook Signature Verification
**Vulnerability:** Stripe webhook events processed without cryptographic verification
**Severity:** Critical
**Detect:** Webhook endpoint processes Stripe events without `stripe.webhooks.constructEvent()`. Or endpoint uses `express.json()` instead of `express.raw()` — signature verification requires the raw request body.
**Impact:** Anyone can send fake webhook events — granting themselves premium subscriptions, marking fake payments complete, triggering fake refunds.
**Fix:**
```typescript
// VULNERABLE — no signature verification
app.post('/webhook', express.json(), (req, res) => {
  const event = req.body  // trusting unverified payload!
  if (event.type === 'checkout.session.completed') {
    grantPremium(event.data.object.customer)
  }
  res.json({ received: true })
})

// SECURE — verified with raw body
app.post('/webhook',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const sig = req.headers['stripe-signature']
    let event
    try {
      event = stripe.webhooks.constructEvent(
        req.body,    // raw body, NOT parsed JSON
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      )
    } catch (err) {
      console.log(`Webhook signature verification failed: ${err.message}`)
      return res.status(400).send(`Webhook Error: ${err.message}`)
    }
    switch (event.type) {
      case 'checkout.session.completed':
        grantPremium(event.data.object.customer)
        break
    }
    res.json({ received: true })
  }
)
```
**OWASP:** A04

### Stale Subscription Status Checks
**Vulnerability:** Subscription/premium status read from client-side state
**Severity:** High
**Detect:** Premium status checked from React state, localStorage, cookies, or JWT claims instead of server-side database lookup. Database should be source of truth, synced by webhooks.
**Impact:** User modifies local subscription status via devtools, cookie edit, or modified JWT to access premium features without paying.
**Fix:** Check subscription status server-side on every protected request. Sync via webhooks: `customer.subscription.created`, `customer.subscription.updated`, `customer.subscription.deleted`, `invoice.paid`, `invoice.payment_failed`.
**OWASP:** A04

### Webhook Replay Attacks
**Vulnerability:** No deduplication or timestamp freshness check on webhook events
**Severity:** High
**Detect:** Webhook handler that doesn't check event ID uniqueness or timestamp freshness. No deduplication of processed events.
**Impact:** Attacker captures a valid webhook event and replays it — e.g., replaying a successful payment event to get multiple credits/subscriptions from one payment.
**Fix:** Store processed event IDs and reject duplicates. Check `event.created` timestamp and reject events older than tolerance window (e.g., 5 minutes). Stripe events include these fields.
**OWASP:** A04

### Idempotency Key Manipulation
**Vulnerability:** Missing or client-controlled idempotency keys on payment mutations
**Severity:** Medium
**Detect:** Payment mutation endpoints (charge, refund, transfer) without idempotency keys. Or idempotency keys generated client-side and passed in request body.
**Impact:** Network retries or intentional duplicate requests cause double charges. Client-generated idempotency keys can be manipulated to bypass deduplication.
**Fix:** Generate idempotency keys server-side. Use Stripe's built-in idempotency support: `stripe.paymentIntents.create({...}, { idempotencyKey: serverGeneratedKey })`.
**OWASP:** A04

### Coupon/Promo Code Abuse
**Vulnerability:** Unrestricted coupon application logic
**Severity:** Medium
**Detect:** Coupon application logic that doesn't check: usage limits per user, total redemption caps, or valid product/plan restrictions.
**Impact:** Attacker applies same coupon multiple times, discovers valid codes through enumeration (sequential IDs or brute force), or applies coupons to plans that shouldn't be discounted.
**Fix:** Set max redemption limits on Stripe coupons. Validate coupon applicability server-side. Use random coupon codes, not sequential. Log and monitor coupon usage.
**OWASP:** A04

### Refund Logic Bypass
**Vulnerability:** Unvalidated refund amounts or duplicate refund requests
**Severity:** Medium
**Detect:** Refund endpoint that doesn't validate: refund amount <= original charge, refund not already processed, charge not already disputed/chargebacked.
**Impact:** Attacker requests refund greater than original amount (if amount is user-submitted). Or requests multiple refunds on the same charge.
**Fix:** Always look up original charge server-side. Use Stripe's refund API which enforces refund <= charge. Track refund status in your database.
**OWASP:** A04

### Client-Controlled Metadata
**Vulnerability:** Stripe object metadata set from user-submitted request body
**Severity:** Medium
**Detect:** Stripe object creation (checkout session, payment intent) where metadata is set from `req.body.metadata` or includes user-submitted values without validation.
**Impact:** Metadata often drives server-side business logic (e.g., `plan: 'enterprise'` determines provisioning). Client-controlled metadata lets attacker upgrade themselves.
**Fix:**
```typescript
// VULNERABLE — metadata from client
metadata: req.body.metadata

// SECURE — metadata set server-side
metadata: {
  userId: authenticatedUser.id,
  planId: product.planId,
  source: 'checkout'
}
```
**OWASP:** A04

### Stripe Connect Account Isolation
**Vulnerability:** Missing account scoping in Stripe Connect platform operations
**Severity:** Medium
**Detect:** Stripe Connect platform where connected account operations don't scope to the correct account. Missing `stripeAccount` parameter on API calls.
**Impact:** Operations intended for one connected account affect another. Financial data leaks between merchants.
**Fix:** Always pass `stripeAccount` parameter. Validate connected account ID belongs to the authenticated user before any operation.
**OWASP:** A04

### PCI-DSS Scope Violation
**Vulnerability:** Raw card data handled in backend code
**Severity:** Low
**Detect:** Any code handling raw card numbers outside Stripe Elements/Checkout. Grep for `card_number`, `cardNumber`, `cvv`, `cvc` in backend code.
**Impact:** Handling raw card data puts you in PCI-DSS scope — expensive compliance requirements. A breach means massive fines and liability.
**Fix:** Always use Stripe Elements, Checkout, or Payment Links. Never handle raw card data on your server.
**OWASP:** A04

### Business Logic Flaws
**Vulnerability:** Exploitable business rules around pricing, trials, and referrals
**Severity:** High
**Detect:** Check for: negative quantities in cart/checkout, trial period manipulation (changing trial end date), referral loop exploitation (referring yourself), free tier resource hoarding (many free accounts to aggregate free tier limits).
**Impact:** Financial loss through exploited business logic. Commonly missed in AI-coded apps because the AI focuses on technical correctness, not business rule enforcement.
**Fix:** Validate quantities > 0 server-side. Enforce one trial per customer/email. Validate referral chains. Rate limit account creation per IP/device fingerprint.
**OWASP:** A04
