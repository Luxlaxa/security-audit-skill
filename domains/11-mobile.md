---
domain: mobile
version: 1.0.0
stacks: [react-native, expo]
always_load: false
owasp: [A02, A05]
priority: [data-breach, ato]
---

# Mobile Security Domain (React Native / Expo)

## Quick Check

1. **Insecure Token Storage** — Grep `AsyncStorage` co-located with `token|session|jwt|auth`. Tokens in AsyncStorage are plaintext and extractable. Severity: High.
2. **Hardcoded Secrets in JS** — Grep `\.js$|\.ts$|\.tsx$` for `apiKey|api_key|secret|STRIPE_|OPENAI_|firebase` not behind a backend proxy. Severity: Critical.
3. **Deep Link Injection** — Grep `Linking.addEventListener|useURL|expo-linking` — confirm all params are validated/sanitized before use. Severity: High.
4. **Secure Storage Missing** — Check `package.json` for `expo-secure-store` (Expo) or `react-native-keychain` (bare RN). At least one MUST be present if app handles auth. Severity: High.
5. **Biometric Boolean Bypass** — Grep `isAuthenticated\s*=\s*true|biometric.*true|authenticated\s*=\s*true` — boolean-only biometric checks are trivially patchable. Severity: High.
6. **No Certificate Pinning** — Check for `ssl-pinning|cert-pinning|TrustKit|react-native-ssl-pinning` in deps or config. Absence = MITM-vulnerable on untrusted networks. Severity: Medium.

---

## Full Patterns

### 1. Secrets in JS Bundle (Critical)

- **OWASP**: A02 (Cryptographic Failures)
- **Detect**: Grep all `.js/.ts/.tsx` for API keys, secrets, tokens. Even Hermes bytecode is extractable via `hermes-dec` or `jadx`.
- **Impact**: Full API key compromise. Attacker calls your APIs at your cost, accesses user data.
- **Fix**: All API calls with secrets must route through a backend proxy. Use `expo-constants` for non-secret config only. Strip `.env` from bundles.

### 2. AsyncStorage for Auth Tokens (High)

- **OWASP**: A02
- **Detect**: `AsyncStorage.setItem` with token/session/jwt values.
- **Impact**: Tokens stored in plaintext SQLite, accessible on rooted/jailbroken devices or via backup extraction.
- **Fix**:
  ```ts
  // Expo
  import * as SecureStore from 'expo-secure-store';
  await SecureStore.setItemAsync('authToken', token);

  // Bare RN
  import * as Keychain from 'react-native-keychain';
  await Keychain.setGenericPassword('auth', token);
  ```

### 3. No Certificate Pinning (Medium)

- **OWASP**: A02
- **Detect**: Absence of `react-native-ssl-pinning`, `TrustKit`, or custom `OkHttp` CertificatePinner config.
- **Impact**: Attacker on same WiFi intercepts all API traffic via proxy (Burp/mitmproxy).
- **Fix**: Use `react-native-ssl-pinning` or configure TrustKit. Pin the leaf cert hash. Rotate plan required — pin backup cert too.

### 4. Deep Link Parameter Injection (High)

- **OWASP**: A05 (Security Misconfiguration)
- **Detect**: Grep `Linking.addEventListener|useURL|expo-router` — follow param usage. Look for unvalidated `id`, `token`, `redirect` params.
- **Impact**: Attacker crafts malicious deep link → triggers unintended navigation, token theft, or action execution.
- **Fix**: Validate and sanitize all deep link params with allowlists. Never pass auth tokens or sensitive data in URL schemes. Use universal links over custom schemes.

### 5. Biometric Boolean Bypass (High)

- **OWASP**: A02
- **Detect**: Pattern `if (biometricResult.success) { setAuthenticated(true) }` — no crypto involved.
- **Impact**: Attacker patches JS bundle or uses Frida to set the boolean → full auth bypass.
- **Fix**: Biometric must gate a **cryptographic operation** — unlock a hardware-backed key that signs a server-issued nonce. Server validates signature, not a boolean.

### 6. Expo OTA Update Signing (Medium)

- **OWASP**: A05
- **Detect**: Check `app.json` / `app.config.js` for `updates.codeSigningCertificate` or EAS Update signing config.
- **Impact**: Unsigned OTA updates can be tampered with in transit → arbitrary code execution on user devices.
- **Fix**: Enable EAS Update code signing. Generate signing key, configure in `eas.json`. Verify signatures on client.

### 7. Jailbreak / Root Detection (Low)

- **OWASP**: A05
- **Detect**: Check deps for `jail-monkey`, `react-native-device-info` (isRooted), or `expo-device`.
- **Impact**: Rooted devices expose secure storage, allow runtime hooking (Frida), bypass all client-side controls.
- **Fix**: Detect and warn users. For banking/health apps, restrict functionality. Graceful degradation, not hard block (users complain).

### 8. Screenshot Prevention (Low)

- **OWASP**: A02
- **Detect**: Grep for `FLAG_SECURE` (Android) or `UIScreen.captured` / `reactNativeScreenshot` usage on sensitive screens.
- **Impact**: Sensitive data (account numbers, tokens, health info) captured in screenshots/screen recordings.
- **Fix**: Android: `getWindow().setFlags(FLAG_SECURE)`. iOS: overlay sensitive views when `UIScreen.captured` is true. Apply only to sensitive screens — not globally.

### 9. Clipboard Data Exposure (Low)

- **OWASP**: A02
- **Detect**: Grep `Clipboard.setString` with sensitive data (passwords, tokens, account numbers).
- **Impact**: Other apps can read clipboard. On Android <10, any app can read it silently.
- **Fix**: Clear clipboard after short timeout (30s). Use `expo-clipboard` with `setStringAsync` + `setTimeout` cleanup. Warn users before copying sensitive data.

### 10. Push Notification Token Handling (Low)

- **OWASP**: A05
- **Detect**: Grep for `getExpoPushTokenAsync|messaging().getToken` — verify tokens are scoped per-user and revoked on logout.
- **Impact**: Stale push tokens allow notifications to wrong user after logout. Token leakage enables push spam.
- **Fix**: Bind push token to authenticated user on backend. On logout: call backend to deregister token, then delete locally. Re-register on next login.
