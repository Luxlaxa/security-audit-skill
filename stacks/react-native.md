---
stack: react-native
version: 1.0.0
augments: [01, 03, 09, 11]
---

## Platform-Specific Patterns

### Secure Storage
- **expo-secure-store**: Expo-managed, simple API, 2KB value limit, good for tokens and small secrets
  - `await SecureStore.setItemAsync('token', value)` — uses Keychain (iOS) / Keystore (Android)
- **react-native-keychain**: Bare RN, no size limit, supports biometric access control
  - `await Keychain.setGenericPassword('user', token, { accessControl: ACCESS_CONTROL.BIOMETRY_ANY })`
- NEVER use AsyncStorage for tokens, keys, or sensitive data — it's plaintext on disk
- Choose expo-secure-store for Expo projects, react-native-keychain for bare workflow or biometric needs

### Certificate Pinning
- **Bare RN**: Use TrustKit — configure pins in `AppDelegate.m` / `MainApplication.java`
- **Expo**: Custom native module required — no pure-JS pinning solution is reliable
- Pin the intermediate CA cert, not the leaf — leaf certs rotate frequently
- Include backup pins for cert rotation — pinning failures = app completely offline
- Test pin validation with proxy tools (Charles/mitmproxy) before shipping

### Expo OTA Update Security
- Sign updates with `expo-updates` code signing — prevents tampered bundles
- Configure signing in `app.json`: `updates.codeSigningCertificate` and `codeSigningMetadata`
- Without signing: anyone who compromises the update server can push arbitrary code
- Pin update server certificate for defense-in-depth

### Environment Variables
- `app.config.js` extras / `Constants.expoConfig.extra` — compiled into the JS bundle, NOT secret
- NONE of these are truly secret: `EXPO_PUBLIC_*`, `extra` fields, `.env` values bundled by Metro
- Any value in the JS bundle is extractable — even with Hermes bytecode
- Pattern: store only public keys (Stripe publishable, Supabase anon) in client config
- All secret keys must live on your backend — client calls your server, server calls third-party

### Hermes Bytecode is NOT Security
- Hermes compiles JS to bytecode — but strings, API keys, URLs remain in plaintext
- Tools like `hbcdump` extract readable strings from Hermes bundles
- Do NOT rely on Hermes as obfuscation — treat all client code as public
- If you need obfuscation (not security): use `react-native-obfuscating-transformer` as a speed bump only

### Backend Proxy Pattern
- ALL third-party API calls must route through your server — never call directly from client
- Client sends auth token to your server, server validates, server calls third-party with secret key
- This protects: API keys, rate limits, business logic, and allows server-side validation
- Exceptions: Stripe publishable key (designed for client), Supabase anon key (with RLS)

### Common Mistakes
- Shipping API keys in `app.config.js` extras — extractable from published app binary
- Using HTTP (not HTTPS) for any API call — iOS ATS blocks by default, Android does not
- Storing JWT in AsyncStorage — accessible via device backup extraction or rooted devices
- Deep link scheme hijacking — validate all deep link parameters, don't auto-navigate to arbitrary URLs
- Not implementing token refresh — expired tokens cause UX issues that devs "fix" by extending expiry

## Cross-References
- **Domain 01** (Secrets & Env): Biometric auth is local verification only — always back with server-side session
- **Domain 03** (Authentication): Deep link params and push notification payloads need full validation
- **Domain 09** (Cryptography): Certificate pinning, TLS enforcement, ATS configuration
- **Domain 11** (Mobile): Jailbreak/root detection, screenshot prevention, secure clipboard
