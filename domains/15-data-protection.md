---
domain: data-protection
version: 1.0.0
stacks: []
always_load: true
owasp: [A02, A04]
priority: [data-breach]
---

## Quick Check
1. Check for unencrypted PII fields in DB schema (SSN, credit card, health data in plaintext columns)
2. Grep for data deletion endpoints/functions — right to deletion implementation
3. Check for backup encryption configuration
4. Grep for analytics/tracking that sends PII without anonymization
5. Check for data retention policy implementation or documentation

## Full Patterns

### Data Minimization Violation
**Vulnerability:** Collecting unnecessary personally identifiable information
**Severity:** Medium
**Detect:** `grep -rn "ssn\|social_security\|date_of_birth\|dob\|gender\|ethnicity" migrations/ prisma/ schema/ src/components/`
**Impact:** Every extra PII field increases breach severity. Collecting SSN for a newsletter app turns minor breach into identity theft. GDPR Article 5(1)(c) violation.
**Fix:** Audit each PII field: "Does this feature break without this data?" If no, remove. For analytics, use aggregates instead of individual records.
**OWASP:** A04 - Insecure Design

### No Encryption at Rest for Sensitive Fields
**Vulnerability:** PII stored in plaintext database columns
**Severity:** Medium
**Detect:** `grep -rn "ssn\|credit_card\|card_number\|social_security\|tax_id\|bank_account" migrations/ prisma/ schema/` — then check for `encrypt\|decrypt\|aes\|cipher` in src/.
**Impact:** Database breach exposes all PII in cleartext. PCI-DSS 3.4 violation for card data.
**Fix:**
```javascript
// Before
await db.user.create({ data: { ssn: '123-45-6789' } });
// After — field-level encryption (@47ng/cloak, prisma-field-encryption, or AWS KMS)
const encrypted = encrypt(ssn, process.env.FIELD_ENCRYPTION_KEY);
await db.user.create({ data: { ssn_encrypted: encrypted } });
```
**OWASP:** A02 - Cryptographic Failures

### No Data Retention Policy
**Vulnerability:** User data kept indefinitely with no automated cleanup
**Severity:** Medium
**Detect:** `grep -rn "retention\|cleanup\|purge\|ttl\|expire" src/ cron/ jobs/`
**Impact:** Years of accumulated data increases breach impact exponentially. GDPR Article 5(1)(e) — storage limitation.
**Fix:**
```javascript
const RETENTION_DAYS = 365;
await db.execute(
  `DELETE FROM user_sessions WHERE created_at < NOW() - INTERVAL '${RETENTION_DAYS} days'`
);
```
**OWASP:** A04 - Insecure Design

### Right to Deletion Not Implemented
**Vulnerability:** No mechanism for users to request deletion of their personal data
**Severity:** Medium
**Detect:** `grep -rn "deleteAccount\|delete.*account\|erasure\|gdpr\|ccpa\|right.*delet" src/`
**Impact:** GDPR Article 17 / CCPA violation. Fines up to 4% annual revenue. Data persists in: main DB, backups, logs, analytics, third-party services.
**Fix:**
```javascript
async function deleteUserData(userId) {
  await db.user.delete({ where: { id: userId } });
  await db.userLogs.deleteMany({ where: { userId } });
  await analyticsService.deleteUser(userId);
  await searchIndex.delete(`user:${userId}`);
  logger.info('user.data_deleted', { userId, timestamp: new Date() });
}
```
**OWASP:** A04 - Insecure Design

### Data Export Not Available
**Vulnerability:** No mechanism for users to export their personal data (DSAR)
**Severity:** Low
**Detect:** `grep -rn "export.*data\|download.*data\|portability\|dsar" src/`
**Impact:** GDPR Article 20 — right to data portability. Non-compliance results in regulatory action.
**Fix:**
```javascript
app.get('/api/user/export', auth, async (req, res) => {
  const userData = await collectAllUserData(req.user.id);
  res.setHeader('Content-Disposition', 'attachment; filename=my-data.json');
  res.json(userData);
});
```
**OWASP:** A04 - Insecure Design

### Backups Unencrypted
**Vulnerability:** Database backups stored without encryption
**Severity:** Medium
**Detect:** `grep -rn "pg_dump\|mysqldump\|mongodump" scripts/ cron/ .github/` — then check for `gpg\|openssl\|aws.*sse` in same paths.
**Impact:** Backup files contain complete database. Unencrypted backup on compromised S3 = full data breach.
**Fix:**
```bash
# Before
pg_dump mydb > backup.sql && aws s3 cp backup.sql s3://backups/
# After
pg_dump mydb | gpg --encrypt --recipient backup@co.com > backup.sql.gpg
aws s3 cp backup.sql.gpg s3://backups/ --sse aws:kms --sse-kms-key-id $KMS_KEY
```
**OWASP:** A02 - Cryptographic Failures

### Analytics Not Anonymized
**Vulnerability:** User PII sent to third-party analytics without pseudonymization
**Severity:** Low
**Detect:** `grep -rn "analytics.*email\|analytics.*name\|analytics.*phone\|identify.*email" src/`
**Impact:** PII in Mixpanel/Segment/GA lives outside your control. Vendor breach exposes your users. GDPR requires DPA with each processor.
**Fix:**
```javascript
// Before
analytics.identify(user.id, { email: user.email, name: user.name });
// After — pseudonymized, no PII
analytics.identify(hashUserId(user.id), { plan: user.plan, region: user.region });
```
**OWASP:** A04 - Insecure Design
