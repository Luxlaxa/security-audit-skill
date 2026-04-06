---
stack: firebase
version: 1.0.0
augments: [00, 01, 02, 03, 04, 06, 17]
---

## Platform-Specific Patterns

### Firestore Security Rules
- Ownership validation: `allow read, write: if request.auth != null && request.auth.uid == resource.data.userId;`
- Field validation on write: `request.resource.data.keys().hasOnly(['name', 'email', 'updatedAt'])`
- Type checking: `request.resource.data.name is string && request.resource.data.name.size() <= 100`
- Never use `allow read, write: if true;` — even temporarily in production
- Recursive wildcards `{document=**}` are dangerous — scope rules to specific collections

### Realtime Database (RTDB) Rules
- Different syntax from Firestore: JSON-based, not CEL
- Validate ownership: `".write": "auth.uid === $userId"`
- Use `.validate` for schema enforcement: `".validate": "newData.hasChildren(['name', 'email'])"`
- Index rules: `".indexOn"` — unindexed queries fail silently on large datasets

### Cloud Functions Auth
- Verify ID token: `const decoded = await admin.auth().verifyIdToken(req.headers.authorization.split('Bearer ')[1])`
- Extract UID: `decoded.uid` — never trust client-submitted UID
- Callable functions get `context.auth` automatically — use it
- HTTP functions require manual token verification

### Storage Rules
- Ownership validation: `allow write: if request.auth.uid == userId;` with path `/{userId}/{allPaths=**}`
- File size limits: `request.resource.size < 5 * 1024 * 1024`
- Content type validation: `request.resource.contentType.matches('image/.*')`

### Custom Claims
- Set ONLY via Admin SDK: `admin.auth().setCustomUserClaims(uid, { role: 'admin' })`
- Never use document-based roles for security rules — too easy to bypass with direct API calls
- Claims propagate on next token refresh — force refresh after role change
- Max claims payload: 1000 bytes — keep it small (role flags, not full profiles)

### Budget & Abuse Protection
- No built-in spend cap — call Google Cloud Billing API to disable billing programmatically
- Set up budget alerts in Google Cloud Console — but alerts don't stop spend
- App Check: enable to prevent API abuse from spoofed clients
- Firebase auto-restricts default rules after 30-day test period — plan for this

### Common Mistakes
- Deploying with test-mode rules to production
- Using `admin` SDK in client code (it bypasses all rules)
- Not validating `request.resource.data` shape — allows arbitrary field injection
- Trusting `request.auth.token.email` without checking `email_verified`

## Cross-References
- **Domain 00** (Architecture Tier): Firebase-specific threats — rules bypass, admin SDK exposure, billing abuse
- **Domain 01** (Secrets & Env): Firebase Auth handles identity, but verify email_verified in rules
- **Domain 02** (Database Security): Security Rules ARE your access control layer — audit exhaustively
- **Domain 03** (Authentication): Rules handle some validation, but Cloud Functions need full input validation
- **Domain 04** (Authorization): Firebase endpoints are public — rules are your only protection
- **Domain 06** (Rate Limiting): Firestore data is encrypted at rest, but audit field-level access
- **Domain 17** (Serverless & Edge): Cloud Functions = GCP Functions — cold starts, timeout limits, memory constraints
