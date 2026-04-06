---
domain: api-security
version: 1.0.0
stacks: [nextjs, express, graphql]
always_load: false
owasp: [A01, A05, A10]
priority: [data-breach, ato]
---

# API Security

## Quick Check

1. Grep `Access-Control-Allow-Origin: *` or `cors({ origin: '*' })` or `origin: true` — CORS wildcard on auth endpoints
2. Grep Server Actions / POST routes without CSRF token validation or SameSite cookies
3. Grep `fetch(userInput)` or `axios.get(userInput)` on server-side — SSRF
4. Grep for GraphQL `introspection: true` in production config
5. Grep for WebSocket connection handlers without auth verification
6. Grep for `169.254.169.254` or cloud metadata URL blocking absent in outbound request handling
7. Check for missing query depth/complexity limits in GraphQL schema config

---

## Full Patterns

### CORS Patterns

#### 1. CORS Wildcard on Authenticated Endpoints

- **Severity:** High
- **OWASP:** A01 (Broken Access Control)
- **Detect:** Grep for `origin: '*'` or `Access-Control-Allow-Origin: *` in middleware/route config, especially routes that read cookies or Authorization headers.
- **Impact:** Any website can make authenticated cross-origin requests if credentials are sent via cookies with `SameSite=None`. Enables data exfiltration from authenticated endpoints.
- **Fix:** Replace wildcard with an explicit origin allowlist.
  ```typescript
  // VULNERABLE
  app.use(cors({ origin: '*' }))

  // SECURE
  const ALLOWED_ORIGINS = ['https://app.example.com', 'https://admin.example.com']
  app.use(cors({
    origin: (origin, callback) => {
      if (!origin || ALLOWED_ORIGINS.includes(origin)) {
        callback(null, true)
      } else {
        callback(new Error('Not allowed by CORS'))
      }
    }
  }))
  ```

#### 2. CORS Credentials with Wildcard (Origin Reflection)

- **Severity:** Critical
- **OWASP:** A01 (Broken Access Control)
- **Detect:** Grep for `origin: true` combined with `credentials: true`. Browsers block `Access-Control-Allow-Credentials: true` + `Access-Control-Allow-Origin: *`, but `origin: true` reflects any requesting origin back — which browsers DO allow with credentials.
- **Impact:** Any attacker-controlled site can make fully authenticated requests and read responses. Complete account takeover and data theft.
- **Fix:** Validate the Origin header against an allowlist before reflecting it.
  ```typescript
  // VULNERABLE — reflects any origin, credentials allowed
  app.use(cors({ origin: true, credentials: true }))

  // SECURE — validate origin before reflecting
  app.use(cors({
    origin: (origin, callback) => {
      if (ALLOWED_ORIGINS.includes(origin)) {
        callback(null, origin)
      } else {
        callback(new Error('Blocked by CORS'))
      }
    },
    credentials: true
  }))
  ```

---

### CSRF Patterns

#### 3. CSRF on Server Actions

- **Severity:** High
- **OWASP:** A01 (Broken Access Control)
- **Detect:** Grep for Next.js Server Actions (`'use server'` in files or inline) that mutate state. Check whether SameSite cookie attribute is set and whether the Origin header is validated.
- **Impact:** Attacker site can trigger server actions on behalf of an authenticated user — create/delete resources, change settings, transfer funds.
- **Fix:** SameSite=Lax cookies (default in modern browsers) block cross-origin POST from third-party sites. Additionally validate the Origin header server-side for defense in depth.
  ```typescript
  // In middleware.ts — validate Origin header for Server Actions
  import { NextRequest, NextResponse } from 'next/server'

  export function middleware(request: NextRequest) {
    if (request.method === 'POST') {
      const origin = request.headers.get('origin')
      const host = request.headers.get('host')
      if (origin && new URL(origin).host !== host) {
        return new NextResponse(null, { status: 403 })
      }
    }
    return NextResponse.next()
  }
  ```

#### 4. CSRF on API Routes

- **Severity:** Medium
- **OWASP:** A01 (Broken Access Control)
- **Detect:** Grep for state-changing API routes (POST/PUT/DELETE handlers) that rely solely on cookies for auth without CSRF token validation, Origin/Referer header checks, or SameSite cookie enforcement.
- **Impact:** Cross-site form submissions or fetch requests can execute state-changing operations on behalf of the victim user.
- **Fix:** Use the double-submit cookie pattern or validate Origin/Referer headers on all state-changing requests.
  ```typescript
  // Double-submit cookie pattern
  import crypto from 'crypto'

  // On login — set CSRF token cookie
  function setCsrfToken(res: Response) {
    const token = crypto.randomBytes(32).toString('hex')
    res.setHeader('Set-Cookie', `csrf=${token}; SameSite=Strict; Secure; Path=/`)
    return token
  }

  // On state-changing request — validate token
  function validateCsrf(req: Request): boolean {
    const cookieToken = parseCookies(req).csrf
    const headerToken = req.headers.get('x-csrf-token')
    return cookieToken && headerToken && cookieToken === headerToken
  }
  ```

---

### SSRF Patterns

#### 5. SSRF via User-Controlled URLs

- **Severity:** Critical
- **OWASP:** A10 (Server-Side Request Forgery)
- **Detect:** Grep for `fetch(req.body.url)`, `fetch(req.query.url)`, `axios.get(userInput)`, or any pattern where a user-supplied string is passed to an HTTP client on the server side.
- **Impact:** Attacker points server to internal services, cloud metadata endpoint (`169.254.169.254`), or localhost. Can read cloud credentials (AWS IAM role tokens, GCP service account tokens), access internal APIs, port-scan the internal network.
- **Fix:** Validate URL against an allowlist, block private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x), resolve DNS and re-check the resolved IP before fetching.
  ```typescript
  // VULNERABLE
  app.post('/api/preview', async (req, res) => {
    const response = await fetch(req.body.url) // attacker controls URL
    res.json(await response.json())
  })

  // SECURE — validate and block private IPs
  import { isPrivateIP } from './security'
  app.post('/api/preview', async (req, res) => {
    const url = new URL(req.body.url)
    const ip = await dns.resolve(url.hostname)
    if (isPrivateIP(ip) || url.hostname === 'localhost') {
      return res.status(400).json({ error: 'Invalid URL' })
    }
    // Also block cloud metadata
    if (ip === '169.254.169.254') {
      return res.status(400).json({ error: 'Invalid URL' })
    }
    const response = await fetch(url.toString())
    res.json(await response.json())
  })
  ```

#### 6. DNS Rebinding

- **Severity:** High
- **OWASP:** A10 (Server-Side Request Forgery)
- **Detect:** Check if SSRF protections resolve DNS and validate the IP but then fetch using the original hostname (allowing a second DNS resolution that returns a different IP).
- **Impact:** Attacker's DNS initially resolves to a public IP (passes validation), then switches to an internal IP (e.g., 127.0.0.1, 169.254.169.254) when the server makes the actual request. Bypasses IP-based SSRF protections entirely.
- **Fix:** Resolve DNS once, validate the IP, then fetch using the resolved IP directly (not the hostname). Pin the resolved IP for the duration of the request.
  ```typescript
  import dns from 'dns/promises'
  import { isPrivateIP } from './security'

  async function safeFetch(userUrl: string): Promise<Response> {
    const url = new URL(userUrl)
    const { address } = await dns.lookup(url.hostname)

    if (isPrivateIP(address)) {
      throw new Error('Blocked: private IP')
    }

    // Fetch using resolved IP, set Host header for virtual hosting
    const safeUrl = new URL(url.toString())
    safeUrl.hostname = address
    return fetch(safeUrl.toString(), {
      headers: { Host: url.hostname }
    })
  }
  ```

---

### GraphQL Patterns

#### 7. Introspection Enabled in Production

- **Severity:** Medium
- **OWASP:** A05 (Security Misconfiguration)
- **Detect:** Grep for `introspection: true` in GraphQL server config, or absence of `introspection: false` in production configuration. Test by sending `{ __schema { types { name } } }`.
- **Impact:** Attackers can map the entire API schema — all types, fields, mutations, subscriptions. Reveals internal data models, hidden admin mutations, and relationships that inform targeted attacks.
- **Fix:** Disable introspection in production.
  ```typescript
  // Apollo Server
  const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: process.env.NODE_ENV !== 'production',
  })

  // Yoga / Envelop
  import { useDisableIntrospection } from '@graphql-yoga/plugin-disable-introspection'
  const yoga = createYoga({
    plugins: process.env.NODE_ENV === 'production'
      ? [useDisableIntrospection()]
      : [],
  })
  ```

#### 8. No Query Depth Limit

- **Severity:** High
- **OWASP:** A05 (Security Misconfiguration)
- **Detect:** Grep for `graphql-depth-limit` or `depthLimit` or equivalent depth-limiting middleware. If absent, the API is vulnerable.
- **Impact:** Deeply nested queries cause exponential database load and can take down the server. Example: `{ user { posts { comments { author { posts { comments... } } } } } }` — each level multiplies DB queries.
- **Fix:** Set a maximum query depth (e.g., 10) using `graphql-depth-limit` or equivalent.
  ```typescript
  import depthLimit from 'graphql-depth-limit'

  const server = new ApolloServer({
    typeDefs,
    resolvers,
    validationRules: [depthLimit(10)],
  })
  ```

#### 9. No Query Complexity Analysis

- **Severity:** Medium
- **OWASP:** A05 (Security Misconfiguration)
- **Detect:** Grep for `graphql-query-complexity`, `costAnalysis`, `complexityLimit`, or field-level cost directives. If absent, even shallow but wide queries can overwhelm the server.
- **Impact:** A single shallow query requesting all fields across many connections can be extremely expensive. Attackers craft queries that maximize server load without triggering depth limits.
- **Fix:** Assign complexity scores per field, reject queries exceeding a threshold.
  ```typescript
  import { createComplexityRule, simpleEstimator, fieldExtensionsEstimator } from 'graphql-query-complexity'

  const server = new ApolloServer({
    typeDefs,
    resolvers,
    validationRules: [
      createComplexityRule({
        maximumComplexity: 1000,
        estimators: [
          fieldExtensionsEstimator(),
          simpleEstimator({ defaultComplexity: 1 }),
        ],
        onComplete: (complexity) => {
          console.log('Query complexity:', complexity)
        },
      }),
    ],
  })
  ```

#### 10. Batch/Aliasing Attack

- **Severity:** Medium
- **OWASP:** A01 (Broken Access Control)
- **Detect:** Grep for alias/batch limiting middleware. Test by sending a query with many aliases: `{ a1: login(pass:"aaa") a2: login(pass:"bbb") ... }`. If all execute, the API is vulnerable.
- **Impact:** Multiple aliased queries in a single request bypass per-request rate limiting. Enables brute-force attacks (password guessing, OTP enumeration) within a single HTTP request.
- **Fix:** Limit aliases per query and count individual operations (not just HTTP requests) for rate limiting.
  ```typescript
  // Custom validation rule to limit aliases
  import { ValidationContext, ASTVisitor } from 'graphql'

  function aliasLimit(maxAliases: number) {
    return (context: ValidationContext): ASTVisitor => ({
      OperationDefinition(node) {
        const aliasCount = node.selectionSet.selections.filter(
          (s) => s.kind === 'Field' && s.alias
        ).length
        if (aliasCount > maxAliases) {
          context.reportError(
            new Error(`Too many aliases: ${aliasCount} (max ${maxAliases})`)
          )
        }
      },
    })
  }

  const server = new ApolloServer({
    validationRules: [aliasLimit(10)],
  })
  ```

#### 11. Field-Level Authorization Missing

- **Severity:** High
- **OWASP:** A01 (Broken Access Control)
- **Detect:** Grep for authorization checks in GraphQL resolvers. If auth is only checked at the query/mutation level (e.g., `isAuthenticated` middleware) but individual field resolvers return sensitive data without per-field permission checks, the API is vulnerable.
- **Impact:** Authenticated users can access fields they shouldn't — other users' emails, SSNs, internal IDs, admin-only metadata. Horizontal and vertical privilege escalation.
- **Fix:** Check permissions in resolvers at the field level, not just at the query level. Use directives or middleware for consistent enforcement.
  ```typescript
  // VULNERABLE — query-level auth only
  const resolvers = {
    Query: {
      user: authenticate(async (_, { id }, ctx) => {
        return db.user.findUnique({ where: { id } }) // returns ALL fields
      }),
    },
  }

  // SECURE — field-level authorization
  const resolvers = {
    Query: {
      user: authenticate(async (_, { id }, ctx) => {
        return db.user.findUnique({ where: { id } })
      }),
    },
    User: {
      email: (parent, _, ctx) => {
        if (ctx.user.id !== parent.id && !ctx.user.isAdmin) {
          return null // or throw AuthorizationError
        }
        return parent.email
      },
      ssn: (parent, _, ctx) => {
        if (!ctx.user.isAdmin) {
          throw new ForbiddenError('Not authorized')
        }
        return parent.ssn
      },
    },
  }
  ```

---

### WebSocket Patterns

#### 12. No Auth on WebSocket Connection

- **Severity:** High
- **OWASP:** A01 (Broken Access Control)
- **Detect:** Grep for WebSocket upgrade handlers (`wss.on('connection')`, `io.on('connection')`, `ws.handleUpgrade`). Check whether JWT/session validation occurs in the `upgrade` or `connection` handler before the connection is accepted.
- **Impact:** Unauthenticated users can establish WebSocket connections and receive real-time data, send commands, or access internal messaging channels. Bypasses all HTTP-level auth middleware.
- **Fix:** Verify JWT or session token in the upgrade handler before accepting the WebSocket connection.
  ```typescript
  import { WebSocketServer } from 'ws'
  import { verifyToken } from './auth'

  const wss = new WebSocketServer({ noServer: true })

  server.on('upgrade', async (request, socket, head) => {
    try {
      // Extract token from query string or cookie
      const url = new URL(request.url, `http://${request.headers.host}`)
      const token = url.searchParams.get('token')

      if (!token) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n')
        socket.destroy()
        return
      }

      const user = await verifyToken(token)
      wss.handleUpgrade(request, socket, head, (ws) => {
        ws.user = user // attach user to socket
        wss.emit('connection', ws, request)
      })
    } catch (err) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n')
      socket.destroy()
    }
  })
  ```

#### 13. No Message Schema Validation

- **Severity:** Medium
- **OWASP:** A05 (Security Misconfiguration)
- **Detect:** Grep for WebSocket `message` event handlers. Check whether incoming messages are validated against a schema or type-checked before processing. Look for raw `JSON.parse(data)` with no subsequent validation.
- **Impact:** Attackers send malformed, oversized, or unexpected message types that crash the server, trigger unintended code paths, or exploit type confusion bugs. Without rate limiting, a single connection can flood the server.
- **Fix:** Validate each message against a schema and rate-limit messages per connection.
  ```typescript
  import { z } from 'zod'

  const MessageSchema = z.discriminatedUnion('type', [
    z.object({ type: z.literal('chat'), content: z.string().max(2000) }),
    z.object({ type: z.literal('ping') }),
    z.object({ type: z.literal('subscribe'), channel: z.string().max(100) }),
  ])

  // Rate limiter per connection
  const rateLimits = new WeakMap<WebSocket, { count: number; reset: number }>()

  wss.on('connection', (ws) => {
    rateLimits.set(ws, { count: 0, reset: Date.now() + 1000 })

    ws.on('message', (raw) => {
      // Rate limit: max 30 messages per second
      const limit = rateLimits.get(ws)!
      if (Date.now() > limit.reset) {
        limit.count = 0
        limit.reset = Date.now() + 1000
      }
      if (++limit.count > 30) {
        ws.close(1008, 'Rate limit exceeded')
        return
      }

      // Schema validation
      let data: unknown
      try {
        data = JSON.parse(raw.toString())
      } catch {
        ws.close(1003, 'Invalid JSON')
        return
      }

      const result = MessageSchema.safeParse(data)
      if (!result.success) {
        ws.send(JSON.stringify({ error: 'Invalid message format' }))
        return
      }

      handleMessage(ws, result.data)
    })
  })
  ```
