# Chapter 2: Capture & Replay — Reverse-Engineering APIs from Browser Interactions

> Sometimes you don't have the source code. Sometimes it's a third-party system, a black-box service, or just a team that doesn't document their APIs. The capture system lets you **derive CLI commands from live user interactions**.

This chapter covers the design and implementation of a browser-based API capture system. We'll see how to intercept network traffic and DOM events, correlate them into semantic "user actions," and convert those actions into CLI command definitions — all without reading a single line of backend code.

---

## 2.1 Why Capture?

In Chapter 1, we built an auth system that makes every CLI command "just work." But that assumes you **already know the API endpoints**. What if you don't?

Internal developer platforms often have these characteristics:

- **No public API docs** — the "documentation" is the web UI
- **No source code access** — owned by another team, or a third-party vendor
- **Undocumented parameters** — required fields only discoverable by using the UI
- **Multi-step workflows** — "create X" actually means "POST /validate + POST /create + GET /status"

The traditional approach is to open Chrome DevTools, click around, copy curl commands, and reverse-engineer. The capture system automates and structures this process.

### Capture vs. Source Analysis

| Approach | Input | Strengths | Weaknesses |
|----------|-------|-----------|------------|
| **Source analysis** (Chapter 3) | Frontend source code | Complete, sees all edge cases | Requires code access, can't see runtime behavior |
| **Capture** | Live browser usage | Sees actual parameters, real workflows, UI context | Only captures what the user does, misses hidden features |
| **HAR import** | Chrome DevTools export | No tool setup, quick turnaround | No DOM context, no user intent |

**Capture is the bridge** — it turns "I clicked this button and something happened" into "here's the exact API call, its parameters, and what it does."

---

## 2.2 The Data Model

A capture session is the unit of work. It records everything that happened during a single browser session:

```typescript
interface CaptureSession {
  id: string                    // e.g. "kfc-20260508-142800"
  targetUrl: string             // Where the user started
  baseUrl: string               // Origin extracted from targetUrl
  startedAt: number             // Unix timestamp
  endedAt: number
  mode: 'manual' | 'har' | 'ai'
  requestCount: number
  domEventCount: number
  requests: CapturedRequest[]
  domEvents: DomEvent[]
}
```

### CapturedRequest

```typescript
interface CapturedRequest {
  id: string                    // "req-1", "req-2"...
  timestamp: number             // When it fired
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH'
  url: string                   // Full URL
  baseUrl: string               // Origin
  path: string                  // Path only
  queryString: Record<string, string>
  requestHeaders: Record<string, string>   // Filtered subset
  requestBody: string | null
  responseStatus: number | null
  responseBody: string | null   // Truncated to 2KB
  resourceType: string          // 'xhr' or 'fetch'
  pageUrl: string | null        // Which page triggered it
  pageTitle: string | null
  triggeredBy: string[]         // IDs of DOM events that caused this
}
```

### DomEvent

```typescript
interface DomEvent {
  id: string                    // "dom-1", "dom-2"...
  timestamp: number
  type: 'click' | 'form_submit' | 'input_change' | 'navigation'
  element: DomElementInfo
  pageUrl: string
  pageTitle: string
  triggeredRequests: string[]   // IDs of requests triggered by this event
}

interface DomElementInfo {
  tag: string                   // "BUTTON", "A", "INPUT"...
  text: string | null           // Visible text (truncated to 50 chars)
  id: string | null
  className: string | null      // CSS classes (truncated to 100 chars)
  ariaLabel: string | null      // Accessibility label
  title: string | null          // Tooltip
  dataTestId: string | null     // Common in React/Vue component testing
  name: string | null           // Form input name
  inputType: string | null      // "text", "search", "submit"...
  inputValue: string | null     // Current value (for input_change)
  closestDialog: string | null  // Nearest modal/dialog ancestor
  closestForm: string | null    // Nearest form ancestor
  closestTableRow: string | null
  closestNav: string | null
}
```

The key insight: **we capture both the API call AND the UI context that triggered it.** A `POST /api/flags` is meaningless. A `POST /api/flags` triggered by a click on a button labeled "Create Flag" inside a dialog titled "New Feature Flag" tells us exactly what capability this represents.

---

## 2.3 Network Interception

We use Playwright's built-in network events to intercept all XHR and fetch requests.

### Filtering Noise

Not every HTTP request is worth capturing. We skip:

```typescript
const SKIP_URL_PATTERNS = [
  // Static assets
  /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|webp|avif)(\?|$)/i,
  // Health checks and infrastructure
  /\/health(-check)?$/i,
  /\/actuator/i,
  /\/swagger/i,
  /\/api-docs/i,
  // Webpack dev server
  /\/__webpack_hmr/i,
  /\/hot-update/i,
]

// Universal noise — APIs that are never business-relevant
const NOISE_API_PATTERNS = [
  /\/rest\/wd\/common\/log\/collect/i,      // Analytics/tracking
  /\/api\/common\/login\//i,                 // Auth endpoints
  /\/h5\/v1\/getehid/i,                      // Device fingerprinting
  /\/api\/report\//i,                        // Telemetry
  /\/rest\/flow\/v1\//i,                     // Remote config/AB testing
  /\/api\/common\/menu\//i,                  // Navigation menus
]
```

These patterns are **carefully curated** over time. Every "noise" entry represents a real API that someone initially thought was important, only to realize it's infrastructure, not business logic.

### Request Capture

```typescript
function handleRequest(req: Request, pageUrl: string, pageTitle: string): void {
  if (!API_RESOURCE_TYPES.has(req.resourceType())) return
  if (shouldSkipUrl(req.url())) return

  const method = req.method()
  const { baseUrl, path, queryString } = splitUrl(req.url())
  const requestBody = req.postData() ?? null

  // Deduplication: same method + path + query + body = same request
  const key = dedupKey(method, path, queryString, requestBody)
  if (seenDedupKeys.has(key)) return
  seenDedupKeys.add(key)

  capturedRequests.push({
    id: `req-${++requestCounter}`,
    timestamp: Date.now(),
    method,
    url: req.url(),
    baseUrl, path, queryString,
    requestHeaders: filterHeaders(req.headers()),
    requestBody,
    responseStatus: null,    // filled later by handleResponse
    responseBody: null,
    resourceType: req.resourceType(),
    pageUrl, pageTitle,
    triggeredBy: [],         // filled by correlation engine
  })
}
```

### Response Attachment

```typescript
async function handleResponse(res: Response): Promise<void> {
  const req = res.request()

  // Find the matching captured request (same URL, same method, no response yet)
  const match = capturedRequests.find(
    r => r.url === req.url() && r.method === req.method() && r.responseStatus === null
  )
  if (!match) return

  match.responseStatus = res.status()
  try {
    const body = await res.text()
    match.responseBody = body.slice(0, MAX_RESPONSE_BODY_SIZE)  // 2KB cap
  } catch {
    match.responseBody = '[unable to read response body]'
  }
}
```

The 2KB response body limit is intentional. We're capturing enough to understand the schema (field names, nested structure) without storing entire database dumps.

---

## 2.4 DOM Interaction Interception

Network interception tells us **what** API was called. DOM interception tells us **why**.

We inject a small JavaScript snippet into every page that listens for clicks, form submissions, and input changes:

```javascript
// Injected into every page via Playwright's addInitScript
document.addEventListener('click', function(e) {
  const el = e.target
  const info = {
    type: 'click',
    timestamp: Date.now(),
    tag: el.tagName,
    text: (el.textContent || '').trim().slice(0, 50),
    id: el.id || null,
    className: (el.className || '').toString().slice(0, 100),
    ariaLabel: el.getAttribute('aria-label') || null,
    // ... more fields
    closestDialog: null,
    closestForm: null,
  }

  // Find nearest semantic ancestors for context
  const dialog = el.closest('[role="dialog"],.modal,.drawer,.popup,.ant-modal,.el-dialog')
  if (dialog) {
    info.closestDialog = (dialog.getAttribute('aria-label') || dialog.className || '').slice(0, 100)
  }

  const form = el.closest('form')
  if (form) {
    info.closestForm = form.id || (form.className || '').slice(0, 100)
  }

  // Report to the Node.js process
  window.__ksCliReportInteraction(info)
}, true)  // capture phase — catches all clicks
```

The script uses **event delegation with capture phase** so it intercepts clicks even on deeply nested elements, and before any page-level `stopPropagation()` can block it.

### Exposing the Bridge

Playwright's `context.exposeFunction` creates a bridge from the page back to Node.js:

```typescript
await context.exposeFunction('__ksCliReportInteraction', async (raw) => {
  const activePage = context.pages()[context.pages().length - 1]
  let pageUrl = '', pageTitle = ''
  try {
    pageUrl = activePage?.url() ?? ''
    pageTitle = (await activePage?.title()) ?? ''
  } catch {
    // Page may have been closed
  }
  handleDomEvent(raw, pageUrl, pageTitle)
})

// Then inject the listener script into every page
await context.addInitScript(DOM_INTERACTION_SCRIPT)
```

---

## 2.5 Correlation Engine

Now we have two streams of data: API requests and DOM events. The correlation engine connects them.

### Time-Window Correlation

```typescript
const CORRELATION_WINDOW_MS = 2000  // A DOM event can trigger requests up to 2s later

function correlateDomToRequests(domEvents: DomEvent[], requests: CapturedRequest[]): void {
  for (const domEvt of domEvents) {
    const after = domEvt.timestamp
    const before = domEvt.timestamp + CORRELATION_WINDOW_MS

    // Find requests that occurred within the window after this DOM event
    const triggered = requests
      .filter(r => r.timestamp >= after && r.timestamp <= before)
      .map(r => r.id)

    domEvt.triggeredRequests = triggered

    // Reverse: mark requests as triggered by this DOM event
    for (const reqId of triggered) {
      const req = requests.find(r => r.id === reqId)
      if (req && !req.triggeredBy.includes(domEvt.id)) {
        req.triggeredBy.push(domEvt.id)
      }
    }
  }
}
```

This is a simple but effective heuristic. When a user clicks "Search", the browser typically fires the API request within milliseconds. When they submit a complex form, there might be validation calls, then the main POST, then a status poll — all within a few seconds.

### Bidirectional Links

The correlation is **bidirectional**:
- `DomEvent.triggeredRequests[]` — which APIs did this click trigger?
- `CapturedRequest.triggeredBy[]` — which DOM event caused this API call?

This lets us answer both directions:
- "What APIs does the 'Create' button trigger?"
- "What button did the user click to trigger this POST /api/create?"

---

## 2.6 The Capture Lifecycle

### Starting a Capture

```bash
my-cli capture start https://internal-tool.corp.example.com/
```

Behind the scenes:

1. **Generate session ID**: `kfc-20260508-142800` (domain prefix + timestamp)
2. **Spawn detached process**: The browser runs in a background child process so the CLI returns immediately
3. **Write PID file**: `~/.my-cli/captures/kfc/kfc-20260508-142800.pid`
4. **Launch browser**: Reuses the same persistent Chrome profile from auth (so the user is already logged in)
5. **Inject listeners**: Network + DOM interception is active
6. **Navigate to URL**: The target web app loads

```typescript
// capture.ts — spawning the background runner
const child = spawn('node', [CAPTURE_RUNNER_PATH, url, sessionId], {
  detached: true,
  stdio: 'ignore',
})
writePidFile(sessionId, child.pid!, baseUrl)
child.unref()  // parent exits, child keeps running
```

### Auto-Save

The capture runner writes a `.tmp.json` file every 5 seconds:

```typescript
const autoSaveInterval = setInterval(() => {
  const partialSession: CaptureSession = {
    id: sessionId,
    targetUrl, baseUrl,
    startedAt, endedAt: Date.now(),
    mode: 'manual',
    requestCount: capturedRequests.length,
    domEventCount: capturedDomEvents.length,
    requests: [...capturedRequests],
    domEvents: [...capturedDomEvents],
  }
  fs.writeFileSync(tempFilePath, JSON.stringify(partialSession, null, 2))
}, 5000)
```

This ensures that even if the browser crashes, the user force-quits, or the laptop dies, **no more than 5 seconds of data is lost**.

### Stopping a Capture

Three ways to stop:

1. **Close the browser window** — the runner detects all pages closed and finalizes
2. **Ctrl+C in terminal** — SIGINT triggers graceful shutdown
3. **`my-cli capture stop <session-id>`** — sends SIGTERM to the runner process

```typescript
// Detecting "all pages closed" with persistent context
function checkAllPagesClosed(): void {
  const pages = context.pages()
  const realPages = pages.filter(p => {
    try { return p.url() !== '' && p.url() !== 'about:blank' }
    catch { return false }
  })
  if (realPages.length === 0) resolve()  // finalize session
}
```

Persistent contexts are tricky: closing the last tab doesn't kill Chrome. The process keeps running. So we poll the pages list and check if only `about:blank` remains.

### Finalization

When stopping:

1. Clear the auto-save interval
2. Run the correlation engine (`correlateDomToRequests()`)
3. Close the browser
4. Write final `.json` file
5. Delete the `.tmp.json` file
6. Clean up the PID file

---

## 2.7 HAR Import (The Poor Man's Capture)

Sometimes you already have a HAR file from Chrome DevTools. The system can import it:

```bash
my-cli capture har ./network-log.har --url https://internal-tool.corp.example.com/
```

```typescript
export function parseHarFile(harFilePath: string, targetUrl?: string): CaptureSession {
  const har: HarFile = JSON.parse(fs.readFileSync(harFilePath, 'utf-8'))

  for (const entry of har.log.entries) {
    // Skip static assets
    if (SKIP_URL_PATTERNS.some(p => p.test(entry.request.url))) continue

    // Heuristic: is this an API call?
    const isApiLike =
      contentType.includes('json') ||
      accept.includes('json') ||
      responseContentType.includes('json') ||
      /\/api\/|\/v[0-9]+\/|\/graphql/i.test(entry.request.url)

    if (!isApiLike) continue

    // Deduplicate
    // ...

    requests.push({
      id: `req-${++requestCounter}`,
      // ...
      triggeredBy: [],  // HAR has no DOM events
    })
  }

  return {
    mode: 'har',
    domEvents: [],  // empty!
    // ...
  }
}
```

**HAR imports have no DOM context.** You get the API calls, but you don't know which button triggered them. This is fine for simple GET queries, but terrible for understanding multi-step workflows.

> **Rule of thumb**: If you have access to the web UI, always do a live capture. Use HAR only when you can't interact with the UI.

---

## 2.8 Storage and Organization

Capture files are organized by project (derived from URL domain):

```
~/.my-cli/captures/
├── kfc/
│   ├── kfc-20260508-142800.json
│   ├── kfc-20260508-142800.tmp.json   # auto-save (deleted on finalize)
│   ├── kfc-20260508-142800.pid        # PID file (deleted on stop)
│   └── kfc-20260509-093012.json
├── kswitch/
│   └── kswitch-20260510-112233.json
└── team/
    └── team-20260511-080000.json
```

### Session Listing

```bash
my-cli capture list
```

Output:
```
5 capture session(s) in 3 projects:

  [kfc] (2 sessions)
    kfc-20260508-142800   12 req, 8 dom  45s  2026/05/08 14:28:00
    kfc-20260509-093012   34 req, 21 dom  120s 2026/05/09 09:30:12

  [kswitch] (2 sessions)
    kswitch-20260510-112233 ⏳  5 req, 3 dom  30s  2026/05/10 11:22:33 (PID 12345)

  [team] (1 sessions)
    team-20260511-080000   8 req, 5 dom  60s  2026/05/11 08:00:00
```

The `⏳` indicator shows sessions that are still capturing (have a `.tmp.json` but no `.json`).

### Session Inspection

```bash
# Summary view (default)
my-cli capture show kfc-20260508-142800

# Full API requests
my-cli capture show kfc-20260508-142800 --requests

# Full DOM events
my-cli capture show kfc-20260508-142800 --dom-events
```

The default summary view shows a correlation table:

```
─ API Requests with DOM Context ─
  GET    /api/applications         200  ← 点击 "应用列表" [page: 应用管理]
  POST   /api/applications/create  201  ← 点击 "创建应用" [dialog: 新建应用]
  GET    /api/applications/123     200  ← 点击 "查看详情" [table row: app-123]
  DELETE /api/applications/123     204  ← 点击 "删除" [dialog: 确认删除]
```

---

## 2.9 From Capture to CLI Commands

This is where the magic happens. A capture session contains raw data. The analysis layer turns it into CLI command definitions.

### The Analysis Pipeline

1. **Group by DOM event**: Each `click` + its `triggeredRequests` = one user action
2. **Classify by HTTP method**:
   - `GET` → likely a query command (HTTP type)
   - `POST`/`PUT`/`PATCH`/`DELETE` → likely a write command (SCRIPT type)
3. **Infer parameters**: From `queryString` and `requestBody` JSON structure
4. **Name the command**: From `element.ariaLabel` or `element.text`
5. **Determine domain**: From `pageUrl` and `pageTitle`

### Example

A user clicks a button with `ariaLabel="搜索开关"` (Search Flags). The correlation engine finds:

```
DOM: click "搜索开关"
  → API: GET /api/flags/search?page=1&pageSize=20&keyword=test
```

This becomes:

```json
{
  "name": "flag-search",
  "description": "搜索开关列表（在开关列表页面点击"搜索"触发）",
  "method": "GET",
  "endpoint": "/api/flags/search",
  "requiresAuth": true,
  "parameters": [
    { "name": "page", "type": "string", "required": false, "defaultValue": "1" },
    { "name": "pageSize", "type": "string", "required": false, "defaultValue": "20" },
    { "name": "keyword", "type": "string", "required": false }
  ],
  "tags": ["core"]
}
```

### Multi-Step Workflows

A more complex case: "Create Feature Flag" triggers three APIs:

```
DOM: click "创建开关" [dialog: 新建开关]
  → API 1: POST /api/flags/validate  { name, type, defaultValue }
  → API 2: POST /api/flags/create    { name, type, defaultValue, description }
  → API 3: GET  /api/flags/{id}/detail
```

This is a **SCRIPT command** — it requires multiple API calls with logic between them:

```javascript
// scripts/flag-create.js
import { getRequiredParam, apiPost } from './_utils.js'

const name = getRequiredParam('name')
const type = getRequiredParam('type')
const defaultValue = getRequiredParam('defaultValue')

async function main() {
  // Step 1: Validate
  await apiPost('/api/flags/validate', { name, type, defaultValue })

  // Step 2: Create
  const result = await apiPost('/api/flags/create', {
    name, type, defaultValue,
    description: getParam('description') || ''
  })

  console.log(JSON.stringify({ ok: true, flagId: result.data.id }))
}

main().catch(err => {
  console.error(JSON.stringify({ ok: false, error: err.message }))
  process.exit(1)
})
```

---

## 2.10 Integration with the Auth System

A key design decision: **the capture browser uses the same Chrome profile as auth.**

This means:

1. User runs `my-cli login` — SSO cookies are saved to the persistent profile
2. User runs `my-cli capture start https://internal-tool.corp.example.com/`
3. The capture browser launches with the **same profile**
4. The user is **already logged in** — no QR code needed
5. All captured API requests include the authenticated cookies
6. The generated scripts receive `MYCLI_COOKIE` env var automatically

The auth system and capture system are **seamlessly connected**.

---

## 2.11 Design Principles

### 1. Capture is a background process

The user shouldn't have to keep a terminal open while clicking around a web app. `capture start` spawns a detached process and returns immediately. The user operates the browser naturally.

### 2. Auto-save prevents data loss

A 5-second auto-save interval means crashes, force-quits, and dead batteries don't destroy hours of work. The `.tmp.json` file is the safety net.

### 3. DOM context is more valuable than API data

A `POST /api/v2/create` tells you nothing. A `POST /api/v2/create` triggered by clicking a button labeled "Deploy to Production" inside a dialog titled "Confirm Deployment" tells you everything.

### 4. Deduplication is essential

SPAs poll for updates, auto-save drafts, and retry failed requests. Without deduplication, a 10-minute capture session might contain 500 requests, 400 of which are duplicates.

### 5. Noise filtering is a living document

The `NOISE_API_PATTERNS` list grows over time. Every analytics endpoint, every telemetry ping, every menu API that someone once thought was important gets added. This is institutional knowledge encoded as regex.

---

## 2.12 Common Pitfalls

### Pitfall 1: Missing the "why"

Capturing only network requests (HAR-style) gives you the "what" but not the "why." Always inject DOM listeners.

### Pitfall 2: Correlation window too narrow

Some workflows have delays — a file upload might take 5s before the API responds. If your correlation window is only 500ms, you'll miss the link. Use 2 seconds as a default, but make it configurable.

### Pitfall 3: Not handling page navigations

When the user clicks a link that navigates to a new page, the Playwright page object changes. Make sure you attach listeners to new pages:

```typescript
context.on('page', (page) => {
  attachNetworkListeners(page)
})
```

### Pitfall 4: Storing too much response data

Full response bodies can be megabytes. Truncate to 2KB — enough to see the schema, not enough to bloat storage.

### Pitfall 5: Not deduplicating

Without deduplication, you'll generate redundant commands for the same API called with slightly different parameters.

---

## 2.13 Summary

The capture system turns "I used the web UI" into "here are the CLI commands." Its architecture:

| Component | Purpose |
|-----------|---------|
| **Network interception** | Capture all XHR/fetch requests and responses |
| **DOM interception** | Capture clicks, form submits, and input changes with semantic context |
| **Correlation engine** | Link DOM events to API requests via time-window matching |
| **Deduplication** | Prevent duplicate requests from polluting the data |
| **Noise filtering** | Skip static assets, telemetry, and infrastructure APIs |
| **Auto-save** | Write `.tmp.json` every 5s to prevent data loss |
| **Background runner** | Detached process so the CLI doesn't block the browser |
| **HAR import** | Fallback when live capture isn't possible |
| **Analysis layer** | Convert raw capture data into CLI command definitions |

In the next chapter, we'll look at **command manifests** — the formal schema that describes what commands exist, what parameters they take, and how they're organized into a CLI interface.
