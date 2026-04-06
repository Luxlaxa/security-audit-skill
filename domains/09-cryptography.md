---
domain: cryptography
version: 1.0.0
stacks: []
always_load: true
owasp: [A02]
priority: [data-breach, ato]
---

## Quick Check

1. `grep -rn 'md5(\|sha1(\|SHA1\|MD5' --include='*.{ts,js,py,go,java,rb}' . | grep -i 'password\|token\|secret\|hash'`
2. `grep -rn 'Math\.random()' --include='*.{ts,js,tsx,jsx}' . | grep -i 'token\|secret\|id\|key\|nonce\|session'`
3. `grep -rn '===' --include='*.{ts,js,tsx,jsx}' . | grep -i 'token\|hash\|secret\|signature\|hmac' | grep -v 'timingSafeEqual'`
4. `grep -rn 'rejectUnauthorized:\s*false\|NODE_TLS_REJECT_UNAUTHORIZED.*0' --include='*.{ts,js,tsx,jsx,json,yml,yaml}' .`
5. `grep -rn "key\s*=\s*['\"].\{16,\}['\"]\\|iv\s*=\s*['\"].\{8,\}['\"]\\|secret\s*=\s*['\"].\{16,\}['\"]" --include='*.{ts,js,py,go,java,rb}' . | grep -vi 'process\.env\|os\.environ\|env\.\|getenv'`
6. `grep -rn "createHash('md5')\|createHash('sha1')\|createHash(\"md5\")\|createHash(\"sha1\")" --include='*.{ts,js,tsx,jsx}' . | grep -i 'password\|credential'`

## Full Patterns

### Weak Password Hashing
**Vulnerability:** MD5/SHA1/SHA256 Used for Password Hashing
**Severity:** Critical
**Detect:** Grep for `md5(`, `sha1(`, `createHash('md5')`, `createHash('sha1')`, `createHash('sha256')` near password variables. Also check for raw SHA-256 without a work factor — SHA-256 alone is NOT suitable for passwords because it lacks cost tuning.
**Impact:** MD5 and SHA1 are broken — rainbow tables and GPU cracking recover passwords in seconds. Even SHA-256 without salting or iteration is insufficient. A single data breach exposes all user credentials, enabling credential stuffing across other services.
**Fix:**
```diff
- const hash = crypto.createHash('sha1').update(password).digest('hex');
+ import bcrypt from 'bcrypt';
+ const hash = await bcrypt.hash(password, 12);
+ // Or use argon2:
+ // import argon2 from 'argon2';
+ // const hash = await argon2.hash(password, { type: argon2.argon2id });
```
Use bcrypt (cost >= 12), argon2id, or scrypt. Never roll your own password hashing. Migrate existing hashes by re-hashing on next login.
**OWASP:** A02

### Predictable RNG
**Vulnerability:** Math.random() Used for Security-Sensitive Values
**Severity:** High
**Detect:** Grep for `Math.random()` used to generate tokens, session IDs, OTPs, nonces, password reset links, or API keys. Also check for Python `random.randint`/`random.choice` (not `secrets` module) in similar contexts.
**Impact:** `Math.random()` uses a predictable PRNG seeded from system time. Attackers can predict future outputs, forge tokens, hijack sessions, and bypass email verification. This directly enables account takeover.
**Fix:**
```diff
- const token = Math.random().toString(36).substring(2);
+ import crypto from 'crypto';
+ const token = crypto.randomBytes(32).toString('hex');
+ // Or in browser:
+ // const token = crypto.getRandomValues(new Uint8Array(32));
```
Use `crypto.randomBytes()` (Node.js), `crypto.getRandomValues()` (browser), or Python `secrets.token_hex()`. Every security token must come from a CSPRNG.
**OWASP:** A02

### Timing Attacks on Token Comparison
**Vulnerability:** String Equality Used to Compare Secrets
**Severity:** High
**Detect:** Grep for `===` or `==` comparing tokens, hashes, HMAC signatures, API keys, or webhook secrets. Look for patterns like `if (token === storedToken)` or `if (signature === expected)` without `timingSafeEqual`.
**Impact:** String comparison short-circuits on the first mismatched byte, leaking information about the secret through response timing. Attackers can reconstruct tokens byte-by-byte with enough requests. Particularly dangerous for HMAC webhook verification and API key validation.
**Fix:**
```diff
- if (req.headers['x-webhook-signature'] === expectedSignature) {
+ import crypto from 'crypto';
+ const sig = Buffer.from(req.headers['x-webhook-signature'], 'hex');
+ const expected = Buffer.from(expectedSignature, 'hex');
+ if (sig.length === expected.length && crypto.timingSafeEqual(sig, expected)) {
```
Always use `crypto.timingSafeEqual()` for comparing secrets. Buffers must be the same length — check length first to avoid throwing. In Python, use `hmac.compare_digest()`.
**OWASP:** A02

### TLS Certificate Validation Disabled
**Vulnerability:** TLS Certificate Verification Bypassed in Production
**Severity:** Critical
**Detect:** Grep for `rejectUnauthorized: false` in HTTPS agent config, `NODE_TLS_REJECT_UNAUTHORIZED=0` in env or code, Python `verify=False` in requests, Go `InsecureSkipVerify: true`. Check if these are conditionally set only for dev or unconditionally applied.
**Impact:** Disabling certificate validation allows man-in-the-middle attacks. Any network intermediary (ISP, WiFi hotspot, corporate proxy) can intercept and modify all HTTPS traffic, including credentials and tokens. Completely negates TLS encryption.
**Fix:** Remove `rejectUnauthorized: false` and `NODE_TLS_REJECT_UNAUTHORIZED=0`. If needed for self-signed certs in dev, gate behind `NODE_ENV !== 'production'`. For internal services with custom CAs, configure the CA certificate explicitly via the `ca` option instead of disabling validation entirely.
**OWASP:** A02

### Missing HSTS Header
**Vulnerability:** Missing Strict-Transport-Security Header
**Severity:** Medium
**Detect:** Check HTTP response headers for `Strict-Transport-Security`. Verify it includes `max-age` of at least 31536000 (1 year) and `includeSubDomains`. Check if the app is on the HSTS preload list for maximum protection.
**Impact:** Without HSTS, the first request to a site may go over HTTP before redirect, allowing SSL stripping attacks. An attacker on the same network can intercept the initial HTTP request, preventing the upgrade to HTTPS and capturing all subsequent traffic in plaintext.
**Fix:** Set the header in your application or reverse proxy:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```
In Express: `app.use(helmet({ hsts: { maxAge: 31536000, includeSubDomains: true, preload: true } }))`. Submit to hstspreload.org for browser-level enforcement.
**OWASP:** A02

### Encryption at Rest Missing for PII
**Vulnerability:** Sensitive Data Stored in Plaintext in Database
**Severity:** Medium
**Detect:** Check database schemas and models for PII fields (SSN, credit card, health data, government IDs) stored as plain text columns. Look for `VARCHAR`, `TEXT`, or `STRING` types on fields named `ssn`, `tax_id`, `card_number`, `medical_record`, `national_id`. Check if the database or cloud provider's encryption-at-rest is enabled.
**Impact:** A database breach (SQL injection, backup theft, insider threat) exposes all PII in readable form. Regulatory violations under GDPR, HIPAA, PCI-DSS. Potential fines, lawsuits, and mandatory breach notification.
**Fix:** Enable database-level encryption at rest (e.g., AWS RDS encryption, Supabase enables by default). For highly sensitive fields, add application-level encryption using AES-256-GCM before storage. Store encryption keys in a KMS (AWS KMS, HashiCorp Vault), never in the database or application code.
**OWASP:** A02

### Hardcoded Encryption Keys
**Vulnerability:** Encryption Keys or IVs Hardcoded in Source Code
**Severity:** Critical
**Detect:** Grep for long hex/base64 strings assigned to variables named `key`, `iv`, `secret`, `encryptionKey`, `aesKey`, `ENCRYPTION_KEY`. Check for `Buffer.from('...')` or `new Uint8Array([...])` in encryption contexts. Verify these come from environment variables, not literals.
**Impact:** Hardcoded keys mean every deployment uses the same key. Anyone with source access (including git history) can decrypt all data. Key rotation is impossible without code changes and redeployment. A single source code leak compromises all encrypted data.
**Fix:** Store encryption keys in environment variables or a secrets manager (AWS KMS, HashiCorp Vault, Doppler). Generate keys with `crypto.randomBytes(32)`. Use a key derivation function if deriving from a passphrase. Implement key rotation by supporting multiple key versions.
**OWASP:** A02

### Weak Cipher Suites
**Vulnerability:** Outdated TLS Versions or Weak Cipher Algorithms
**Severity:** Medium
**Detect:** Check TLS configuration for: TLS 1.0/1.1 enabled, RC4 cipher, DES/3DES, export-grade ciphers, NULL ciphers. In Node.js, check `tls.createServer()` options for `secureProtocol`, `ciphers`, `minVersion`. Check nginx/Apache config for `ssl_protocols` and `ssl_ciphers`.
**Impact:** Weak cipher suites enable known attacks: BEAST (TLS 1.0), POODLE (SSL 3.0), SWEET32 (3DES), RC4 bias attacks. Attackers can decrypt intercepted traffic. PCI-DSS and most compliance frameworks require TLS 1.2+.
**Fix:** Enforce TLS 1.2 minimum (TLS 1.3 preferred). In Node.js: `tls.createServer({ minVersion: 'TLSv1.2' })`. In nginx: `ssl_protocols TLSv1.2 TLSv1.3;`. Use Mozilla's SSL Configuration Generator for recommended cipher suites. Disable all CBC-mode ciphers if possible, prefer AEAD ciphers (AES-GCM, ChaCha20-Poly1305).
**OWASP:** A02

### Key Derivation from Passwords
**Vulnerability:** Direct Hashing Instead of Key Derivation for Password-Based Encryption
**Severity:** Medium
**Detect:** Grep for `createHash` or `hashlib` used to derive encryption keys from passwords. Look for patterns like `crypto.createHash('sha256').update(password).digest()` used as an encryption key. Check for missing salt or iteration count in key derivation.
**Impact:** Direct hashing of passwords to derive encryption keys is vulnerable to brute-force and dictionary attacks. Without a salt, identical passwords produce identical keys. Without iteration/cost, GPUs can test billions of candidates per second.
**Fix:** Use a proper key derivation function:
```diff
- const key = crypto.createHash('sha256').update(password).digest();
+ const salt = crypto.randomBytes(16);
+ const key = crypto.pbkdf2Sync(password, salt, 310000, 32, 'sha256');
+ // Or better — use scrypt:
+ // const key = crypto.scryptSync(password, salt, 32, { N: 2**17 });
```
Use PBKDF2 (>=310,000 iterations per OWASP 2023), scrypt, or argon2id for deriving keys from passwords. Always use a unique random salt. Store the salt alongside the ciphertext.
**OWASP:** A02
