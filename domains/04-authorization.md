---
domain: authorization
version: 1.0.0
stacks: []
always_load: true
owasp: [A01]
priority: [privesc, data-breach]
---

## Quick Check

```bash
# IDOR — routes fetching resources by req.params.id without ownership check (Critical)
grep -rn "req\.params\.id\|req\.query\.userId\|req\.params\.userId" --include="*.ts" --include="*.js" --include="*.tsx" | grep -v "req\.user"

# Privilege escalation — role/admin fields in user-writable tables or request bodies (Critical)
grep -rn "is_admin\|isAdmin\|role.*admin\|is_premium\|tier" --include="*.ts" --include="*.js" --include="*.tsx" | grep -i "req\.body\|update\|create\|schema"

# Admin routes without role checks (High)
grep -rln "admin\|manage" app/api/ routes/ --include="*.ts" --include="*.js" --include="*.tsx" 2>/dev/null | xargs grep -L "requireRole\|isAdmin\|role.*admin\|checkPermission"

# Mass assignment — req.body spread into ORM operations (High)
grep -rn "data:.*req\.body\|\.update(.*req\.body\|\.create(.*req\.body\|\.assign(.*req\.body\|{.*\.\.\.req\.body" --include="*.ts" --include="*.js" --include="*.tsx"

# Path traversal — user input in file paths (High)
grep -rn "path\.join(\|path\.resolve(\|fs\.readFile(\|fs\.writeFile(" --include="*.ts" --include="*.js" --include="*.tsx" | grep "req\.params\|req\.query\|req\.body"

# Sequential IDs in routes — enumeration risk (Medium)
grep -rn "/:id\b\|/:userId\b\|/:orderId\b" --include="*.ts" --include="*.js" --include="*.tsx" | grep -v "uuid\|UUID"

# Multi-tenant missing scoping — queries without tenantId (High)
grep -rn "findMany\|findAll\|select.*from" --include="*.ts" --include="*.js" --include="*.tsx" | grep -v "tenantId\|tenant_id\|organizationId\|org_id"
```

## Full Patterns

### Insecure Direct Object Reference (IDOR)

**Vulnerability:** IDOR via Sequential IDs
**Severity:** Critical
**Detect:** API routes using sequential numeric IDs in URLs (`/api/users/123`, `/api/orders/456`) that fetch the resource without verifying the authenticated user owns it.
```bash
grep -rn "findUnique\|findOne\|findByPk" --include="*.ts" --include="*.js" | grep "req\.params" | grep -v "userId.*req\.user\|req\.user.*userId"
```
**Impact:** Attacker increments the ID to access other users' resources. `/api/users/123` → `/api/users/124` reveals User 124's data. One of the most common web vulnerabilities — trivial to exploit, devastating at scale.
**Fix:**
```typescript
// WRONG — fetch by ID without ownership check
app.get('/api/orders/:id', authenticate, async (req, res) => {
  const order = await db.orders.findUnique({ where: { id: parseInt(req.params.id) } })
  res.json(order) // attacker can access ANY order
})

// RIGHT — verify ownership
app.get('/api/orders/:id', authenticate, async (req, res) => {
  const order = await db.orders.findFirst({
    where: { id: req.params.id, userId: req.user.id } // scoped to user
  })
  if (!order) return res.status(404).json({ error: 'Not found' })
  res.json(order)
})
```
Also use UUIDs instead of sequential IDs to make enumeration harder (defense in depth, not a substitute for ownership checks).
**OWASP:** A01

---

### Request Body Tampering

**Vulnerability:** IDOR via Request Body Parameter Tampering
**Severity:** High
**Detect:** API routes that trust `userId`, `ownerId`, `createdBy` from the request body instead of deriving it from the authenticated session.
```bash
grep -rn "req\.body\.userId\|req\.body\.ownerId\|req\.body\.createdBy\|req\.body\.user_id" --include="*.ts" --include="*.js" --include="*.tsx"
```
**Impact:** Attacker submits a different userId in the request body, creating resources attributed to other users or accessing others' data.
**Fix:**
```typescript
// WRONG — userId from request body
app.post('/api/posts', authenticate, async (req, res) => {
  await db.posts.create({ data: { content: req.body.content, userId: req.body.userId } })
})

// RIGHT — userId from session
app.post('/api/posts', authenticate, async (req, res) => {
  await db.posts.create({ data: { content: req.body.content, userId: req.user.id } })
})
```
**OWASP:** A01

---

### Function-Level Access Control

**Vulnerability:** Missing Function-Level Access Control
**Severity:** High
**Detect:** Admin/management routes that only check if the user is authenticated but don't verify their role. Routes like `/api/admin/users`, `/api/admin/settings`, `/api/manage/billing` without role checks.
```bash
grep -rln "\/admin\/\|\/manage\/" --include="*.ts" --include="*.js" --include="*.tsx" | xargs grep -L "requireRole\|isAdmin\|role\|permission\|authorize"
```
**Impact:** Any authenticated user can access admin functionality — viewing all users' data, changing system settings, managing billing.
**Fix:**
```typescript
function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) return res.status(403).json({ error: 'Forbidden' })
    next()
  }
}

// Every admin route gets role middleware
app.get('/api/admin/users', authenticate, requireRole('admin'), handler)
app.put('/api/admin/settings', authenticate, requireRole('admin'), handler)
```
**OWASP:** A01

---

### Vertical Privilege Escalation

**Vulnerability:** Vertical Privilege Escalation via Role in User-Writable Data
**Severity:** Critical
**Detect:** `role`, `is_admin`, `isAdmin`, `permissions`, `tier` fields on database tables where users have write access. Or: these fields accepted in API request bodies for user profile updates.
```bash
grep -rn "role\|is_admin\|isAdmin\|permissions\|tier" --include="*.ts" --include="*.js" --include="*.tsx" | grep -i "update\|patch\|put\|req\.body"
```
**Impact:** Same pattern as the Chris Raroque subscription hack but for roles. User updates their profile with `{ role: 'admin' }` or `{ is_admin: true }` and gains full admin access. The authorization equivalent of storing subscription_status in user-writable tables.
**Fix:** Role/permission fields must be in a private table (no user write access) or in a system like Firebase Custom Claims (set via Admin SDK only). Never accept role changes from user-facing APIs.
```typescript
// WRONG — role field accepted in profile update
app.patch('/api/profile', authenticate, async (req, res) => {
  await db.users.update({ where: { id: req.user.id }, data: req.body }) // user sends { role: 'admin' }
})

// RIGHT — explicit allowlist, role excluded
app.patch('/api/profile', authenticate, async (req, res) => {
  const { name, bio, avatarUrl } = req.body // role intentionally excluded
  await db.users.update({ where: { id: req.user.id }, data: { name, bio, avatarUrl } })
})
```
**OWASP:** A01

---

### Horizontal Privilege Escalation

**Vulnerability:** Horizontal Privilege Escalation — Cross-User Data Access
**Severity:** High
**Detect:** API routes that check "is user authenticated?" but not "does this user own this resource?" User A can access User B's resources if both are authenticated.
```bash
grep -rn "authenticate\|isAuthenticated\|requireAuth" --include="*.ts" --include="*.js" --include="*.tsx" | grep -v "req\.user\.id\|userId\|ownerId\|ownership"
```
**Impact:** Any authenticated user can view, modify, or delete any other user's data by manipulating resource IDs in requests.
**Fix:** Every data access operation must include ownership verification. Use a helper:
```typescript
async function getOwnedResource(model, resourceId, userId) {
  const resource = await model.findFirst({
    where: { id: resourceId, userId }
  })
  if (!resource) throw new ForbiddenError('Access denied')
  return resource
}

// Usage
app.get('/api/documents/:id', authenticate, async (req, res) => {
  const doc = await getOwnedResource(db.documents, req.params.id, req.user.id)
  res.json(doc)
})
```
**OWASP:** A01

---

### Path Traversal

**Vulnerability:** Path Traversal in File Operations
**Severity:** High
**Detect:** User input used in file paths without sanitization. Grep for `path.join(`, `path.resolve(`, `fs.readFile(`, `fs.writeFile(` where the path includes values from `req.params`, `req.query`, or `req.body`. Look for `../` traversal.
```bash
grep -rn "path\.join\|path\.resolve\|fs\.readFile\|fs\.writeFile\|fs\.createReadStream" --include="*.ts" --include="*.js" --include="*.tsx" | grep "req\.\(params\|query\|body\)"
```
**Impact:** Attacker reads arbitrary files from the server: `../../etc/passwd`, `../../.env`, `../../src/config/secrets.js`. Can also overwrite files if write operations are exposed.
**Fix:** Validate and sanitize file paths. Use `path.basename()` to strip directory components. Verify the resolved path stays within the allowed directory:
```typescript
const UPLOAD_DIR = path.resolve(__dirname, '../uploads')

app.get('/api/files/:filename', authenticate, (req, res) => {
  const safePath = path.resolve(UPLOAD_DIR, path.basename(req.params.filename))
  if (!safePath.startsWith(UPLOAD_DIR)) {
    return res.status(400).json({ error: 'Invalid path' })
  }
  res.sendFile(safePath)
})
```
**OWASP:** A01

---

### Mass Assignment

**Vulnerability:** Mass Assignment of Privileged Fields
**Severity:** High
**Detect:** ORM create/update operations where `req.body` is spread directly into the data parameter. Allows users to set ANY field including ones they shouldn't.
```bash
grep -rn "\.\.\.req\.body\|data:.*req\.body\|Object\.assign.*req\.body" --include="*.ts" --include="*.js" --include="*.tsx"
```
**Impact:** Attacker adds `{ role: 'admin', credits: 999999 }` to their profile update request. The spread passes it straight through to the database.
**Fix:** Pick only allowed fields explicitly:
```typescript
// WRONG — user can set role, isAdmin, credits, etc.
await db.users.update({ where: { id: userId }, data: req.body })
await db.users.update({ where: { id: userId }, data: { ...req.body } })

// RIGHT — only allowed fields
const { name, bio, avatarUrl } = req.body
await db.users.update({ where: { id: userId }, data: { name, bio, avatarUrl } })
```
**OWASP:** A01

---

### Multi-Tenant Isolation

**Vulnerability:** Multi-Tenant Isolation Failure
**Severity:** High
**Detect:** Multi-tenant application where database queries don't filter by tenant ID. API routes that access shared tables without tenant scoping.
```bash
# Find tables/models without tenant scoping
grep -rn "findMany\|findAll\|\.find(\|\.select(" --include="*.ts" --include="*.js" --include="*.tsx" | grep -v "tenantId\|tenant_id\|organizationId\|org_id"
```
**Impact:** User in Tenant A can access Tenant B's data by manipulating API requests. Data leaks across organizational boundaries. In B2B SaaS, this means one company sees another company's data.
**Fix:** Include `tenantId` filter in every database query. Use middleware to extract and enforce tenant context from the authenticated session:
```typescript
function tenantScope(req, res, next) {
  req.tenantId = req.user.tenantId
  if (!req.tenantId) return res.status(403).json({ error: 'No tenant context' })
  next()
}

// Every query includes tenant scoping
app.get('/api/projects', authenticate, tenantScope, async (req, res) => {
  const projects = await db.projects.findMany({
    where: { tenantId: req.tenantId } // never omit this
  })
  res.json(projects)
})
```
Consider Row-Level Security (RLS) in PostgreSQL or separate schemas per tenant for strong isolation.
**OWASP:** A01

---

### Parameter Tampering on Updates

**Vulnerability:** Parameter Tampering on Update Operations
**Severity:** Medium
**Detect:** Update operations where the API accepts more fields than the UI form sends. No strict schema validation on input.
```bash
grep -rn "\.update(\|\.patch(" --include="*.ts" --include="*.js" --include="*.tsx" | grep "req\.body" | grep -v "parse\|validate\|schema\|zod\|yup\|joi"
```
**Impact:** Attacker uses dev tools or curl to send additional fields in the update request, modifying data they shouldn't change (e.g., `verified: true`, `emailVerified: true`, `createdAt`, `updatedAt`).
**Fix:** Validate input against a strict schema that only allows expected fields. Reject unknown properties:
```typescript
import { z } from 'zod'

const updateProfileSchema = z.object({
  name: z.string().max(100),
  bio: z.string().max(500).optional()
}).strict() // rejects unknown fields

app.patch('/api/profile', authenticate, async (req, res) => {
  const data = updateProfileSchema.parse(req.body) // throws if extra fields
  await db.users.update({ where: { id: req.user.id }, data })
  res.json({ success: true })
})
```
**OWASP:** A01
