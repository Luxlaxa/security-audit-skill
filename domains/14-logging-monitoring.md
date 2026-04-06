---
domain: logging-monitoring
version: 1.0.0
stacks: []
always_load: true
owasp: [A09]
priority: [data-breach, ato]
---

## Quick Check
1. Grep `console.log(.*password`, `console.log(.*token`, `console.log(.*secret` for PII in logs
2. Check for structured logging library (`winston`, `pino`, `bunyan`) vs raw `console.log`
3. Grep for auth event logging (login success/failure, signup, password reset)
4. Check for error handlers that log full request bodies (may contain sensitive data)
5. Grep for log messages containing user input without sanitization (log injection)

## Full Patterns

### PII in Logs
**Vulnerability:** Passwords, tokens, card numbers, or personal data written to log output
**Severity:** High
**Detect:** `grep -rn "console\.log.*password\|console\.log.*token\|console\.log.*secret\|console\.log.*ssn" src/`
**Impact:** Log aggregators store PII in plaintext. Breach of log storage exposes all credentials. GDPR Article 5 violation. SOC2 audit failure.
**Fix:**
```javascript
// Before
console.log('User login:', { email, password, token });
// After — redact sensitive fields
const sanitize = (obj) => ({ ...obj, password: '[REDACTED]', token: '[REDACTED]' });
logger.info('User login:', sanitize({ email, password, token }));
```
**OWASP:** A09 - Security Logging and Monitoring Failures

### No Audit Trail for Auth Events
**Vulnerability:** Authentication events not logged — cannot detect account takeover
**Severity:** Medium
**Detect:** Search auth handlers (login, signup, password reset, MFA) for logging calls. If absent, flag.
**Impact:** Brute force attacks go undetected. No forensic trail for incident response. PCI-DSS 10.2 failure.
**Fix:**
```javascript
logger.info('auth.login.success', { userId, ip, userAgent, timestamp });
logger.warn('auth.login.failure', { email, ip, userAgent, reason, timestamp });
```
**OWASP:** A09 - Security Logging and Monitoring Failures

### Log Injection
**Vulnerability:** User input with newlines or control characters injected into log output
**Severity:** Medium
**Detect:** `grep -rn "console\.log.*req\.\(body\|query\|params\)" src/`
**Impact:** Attacker injects fake log entries, poisons log analysis, hides real attacks, triggers false alerts.
**Fix:**
```javascript
// Before — string interpolation
logger.info(`Login attempt for ${req.body.username}`);
// After — structured logging neutralizes injection
logger.info({ event: 'login_attempt', username: req.body.username });
```
**OWASP:** A09 - Security Logging and Monitoring Failures

### No Alerting for Brute Force
**Vulnerability:** No detection or alerting for repeated failed authentication attempts
**Severity:** Medium
**Detect:** Check for threshold logic on failed login counters and alerting integrations (PagerDuty, Slack, CloudWatch).
**Impact:** Credential stuffing at thousands of attempts/minute succeeds before anyone notices.
**Fix:**
```javascript
if (failedAttempts >= THRESHOLD) {
  logger.error('auth.brute_force.detected', { ip, account, attempts: failedAttempts });
  alertService.notify('Brute force detected', { ip, account });
}
```
**OWASP:** A09 - Security Logging and Monitoring Failures

### No Alerting for Bulk Data Export
**Vulnerability:** No detection of mass data access or bulk export patterns
**Severity:** Medium
**Detect:** Check data-heavy endpoints for volume-based logging/alerting. Look for anomaly detection on result sizes.
**Impact:** Compromised account exports entire user database. Breach discovered months later via external report.
**Fix:**
```javascript
if (results.length > BULK_THRESHOLD) {
  logger.warn('data.bulk_access', { userId, endpoint, count: results.length });
  alertService.notify('Bulk data access', { userId, count: results.length });
}
```
**OWASP:** A09 - Security Logging and Monitoring Failures

### Full Request Bodies in Error Logs
**Vulnerability:** Error handlers dump entire request body including passwords, tokens, card numbers
**Severity:** High
**Detect:** `grep -rn "req\.body" src/ | grep -i "error\|catch\|log"`
**Impact:** Every failed request logs full payload. Payment errors log card numbers. All stored in log aggregator.
**Fix:**
```javascript
// Before
app.use((err, req, res, next) => { logger.error({ error: err, body: req.body }); });
// After — sanitize
app.use((err, req, res, next) => {
  logger.error({ error: err.message, path: req.path, body: redactSensitiveFields(req.body) });
});
```
**OWASP:** A09 - Security Logging and Monitoring Failures

### Missing Structured Logging
**Vulnerability:** Using `console.log` instead of structured JSON logging
**Severity:** Low
**Detect:** Count `console.log` vs structured logger calls. If ratio favors console.log, flag.
**Impact:** Unstructured logs cannot be searched, correlated, or alerted on. No request-ID correlation across services.
**Fix:**
```javascript
// Before
console.log('User ' + userId + ' created order ' + orderId);
// After
logger.info({ userId, orderId, event: 'order.created' }, 'Order created');
```
**OWASP:** A09 - Security Logging and Monitoring Failures
