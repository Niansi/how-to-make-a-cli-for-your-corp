# Chapter 1: SSO Authentication — The "It Just Works" Login Flow

> The single most important feature of an internal CLI is not the commands it exposes. It's the fact that **you never have to think about authentication**.

This chapter explains how to build an SSO login system where the user scans a QR code once, and every subsequent command automatically carries the right cookies. We'll cover the full implementation — storage, browser automation, silent refresh, cross-domain session sharing, and failure recovery.

---

## 1.1 The Problem

Internal tools at most companies use a centralized SSO (Single Sign-On) gateway. The flow looks like this:

1. User visits `https://internal-tool.corp.example.com`
2. Gets redirected to `https://sso.corp.example.com/login`
3. Scans a QR code or enters credentials
4. Gets redirected back with session cookies
5. The app sets additional cookies (`_t`, `username`, `department`, etc.)

This works great in a browser, but it's a nightmare for CLI tools:

- **No browser = no cookies** — `curl` doesn't share cookies with Chrome
- **QR codes require a UI** — you can't scan a QR code in a terminal
- **Sessions expire** — the CLI suddenly stops working and users blame the tool
- **Multiple subdomains** — each internal tool has its own domain but shares the same SSO

The solution: **make the CLI open a real browser for login, then steal the cookies and persist them locally.**

---

## 1.2 High-Level Flow

```
User runs: my-cli login

    |
    v
Launch system Chrome (not a downloaded browser)
    |
    v
Open https://sso-portal.corp.example.com
    |
    v
User scans QR code in the browser window
    |
    v
Browser gets redirected to target domain with cookies
    |
    v
CLI captures all cookies for that domain
    |
    v
Save to ~/.my-cli/session.json (chmod 600)
    |
    v
Every future command reads cookies from session.json
    |
    v
If cookies expired -> silent headless refresh
    |
    v
If silent refresh fails -> open browser again
```

---

## 1.3 Session Storage

### File Layout

```
~/.my-cli/
├── session.json          # Cookie store (chmod 600)
├── chrome-profile/       # Persistent browser profile
└── debug/                # Screenshots for failed silent auth
```

### Data Model

```typescript
interface Cookie {
  name: string
  value: string
  domain: string
  path: string
  expires: number   // Unix timestamp in seconds, -1 = session cookie
  httpOnly: boolean
  secure: boolean
  sameSite: 'Strict' | 'Lax' | 'None' | ''
}

interface SessionStore {
  username?: string
  [domain: string]: Cookie[] | string | undefined
}
```

Example `session.json`:

```json
{
  "username": "alice",
  "kconf.corp.example.com": [
    {
      "name": "accessproxy_session",
      "value": "abc123...",
      "domain": "kconf.corp.example.com",
      "path": "/",
      "expires": 1759872000,
      "httpOnly": true,
      "secure": true,
      "sameSite": "Lax"
    }
  ],
  "team.corp.example.com": [
    { ... }
  ]
}
```

### Key Design Decisions

**Exact domain matching, not suffix matching.**

```typescript
// session.ts
function getCookiesForDomain(domain: string): Cookie[] | null {
  const key = Object.keys(store).find((k) => k === domain)  // exact match only
  // ...
}
```

Why? Suffix matching (`*.corp.example.com`) would cause `foo.corp.example.com` cookies to leak into `bar.corp.example.com`. Each domain gets its own isolated cookie jar.

**Merge, don't replace.**

```typescript
function saveCookiesForDomain(domain: string, cookies: Cookie[]): void {
  const merged = mergeCookieLists(existing, cookies)  // by name@domain key
  store[domain] = merged
}
```

This handles the case where a response only sets one new cookie but you already have five others for that domain.

**Auto-migrate from legacy directories.**

```typescript
const KSCLI_DIR = path.join(os.homedir(), '.my-cli')
const LEGACY_DIR = path.join(os.homedir(), '.old-cli-name')

function migrateLegacyDir(): void {
  if (!fs.existsSync(LEGACY_DIR)) return
  if (!fs.existsSync(KSCLI_DIR)) {
    fs.cpSync(LEGACY_DIR, KSCLI_DIR, { recursive: true })
    fs.rmSync(LEGACY_DIR, { recursive: true, force: true })
  }
}
```

Users upgrade their CLI, their sessions survive.

---

## 1.4 Browser Login (The Headed Flow)

### Why Playwright + System Chrome?

Most browser automation tutorials tell you to `npx playwright install` to download Chromium. **Don't do this for a CLI.** Your users already have Chrome installed. Downloading a 150MB browser binary is slow and wastes disk space.

Instead, detect the system Chrome:

```typescript
// browser.ts
export function findSystemChrome(): string {
  const platform = process.platform
  const candidates: string[] = []

  if (platform === 'darwin') {
    candidates.push(
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
      path.join(os.homedir(), 'Applications/Google Chrome.app/Contents/MacOS/Google Chrome'),
    )
  } else if (platform === 'linux') {
    candidates.push(
      '/usr/bin/google-chrome',
      '/usr/bin/chromium',
      '/snap/bin/chromium',
    )
  }

  // Also check PATH
  for (const bin of ['google-chrome', 'chromium']) {
    try {
      const resolved = execFileSync('which', [bin], { encoding: 'utf8' }).trim()
      if (resolved) candidates.unshift(resolved)
    } catch { /* not found */ }
  }

  for (const p of candidates) {
    if (fs.existsSync(p)) return p
  }
  throw new Error('No system Chrome found. Please install Google Chrome.')
}
```

### The Login Flow

```typescript
export async function launchSSOLogin(url: string, domain: string): Promise<Cookie[]> {
  const { chromium } = await import('playwright')
  const executablePath = findSystemChrome()
  const chromeProfileDir = path.join(KSCLI_DIR, 'chrome-profile')

  // Persistent context = cookies survive across CLI runs
  const context = await chromium.launchPersistentContext(chromeProfileDir, {
    executablePath,
    headless: false,           // user needs to see the browser
    ignoreHTTPSErrors: true,
    viewport: null,
    args: ['--start-maximized'],
  })

  const page = context.pages()[0] ?? (await context.newPage())
  await page.goto(url)

  try {
    const cookies = await waitForLogin(page, context, domain)
    await refreshAllKnownDomains(await context.cookies(), domain)
    return cookies
  } finally {
    await context.close()
  }
}
```

### Detecting Login Completion

The trickiest part: how do you know the user has finished scanning the QR code?

```typescript
const SSO_DOMAIN = 'sso.corp.example.com'
const LOGIN_TIMEOUT_MS = 120_000  // 2 minutes

async function waitForLogin(page, context, targetDomain): Promise<Cookie[]> {
  const startTime = Date.now()

  while (Date.now() - startTime < LOGIN_TIMEOUT_MS) {
    const currentUrl = page.url()

    // Still on SSO login page — keep waiting
    if (currentUrl.includes(SSO_DOMAIN)) {
      await sleep(1000)
      continue
    }

    // Left SSO domain, but might be a secondary confirmation page
    try {
      await page.waitForSelector('h3:has-text("Login")', { timeout: 1000 })
      await sleep(1000)
      continue
    } catch {
      // No login heading found — we're in!
      await sleep(2000)  // wait for frontend JS to set cookies
      break
    }
  }

  if (Date.now() - startTime >= LOGIN_TIMEOUT_MS) {
    throw new Error('timeout')
  }

  const all = await context.cookies()
  return all.filter(c => matchesDomain(c.domain, targetDomain))
}
```

The `sleep(2000)` at the end is critical. Many SPAs set additional cookies (`_t`, `username`, `department`) via JavaScript **after** the SSO redirect completes. If you capture cookies immediately, you miss them.

---

## 1.5 Silent Auth (The Headless Flow)

This is the magic that makes commands "just work" without bothering the user.

When a command needs cookies but `session.json` has none (or they're expired), the CLI automatically tries to refresh using the existing Chrome profile — headless, no UI, ~15 seconds.

```typescript
export async function silentAuth(targetUrl: string, domain: string): Promise<Cookie[]> {
  const { chromium } = await import('playwright')
  const executablePath = findSystemChrome()
  const chromeProfileDir = path.join(KSCLI_DIR, 'chrome-profile')

  const context = await chromium.launchPersistentContext(chromeProfileDir, {
    executablePath,
    headless: true,            // no UI
    ignoreHTTPSErrors: true,
  })

  const page = context.pages()[0] ?? (await context.newPage())

  try {
    await page.goto(targetUrl, {
      waitUntil: 'domcontentloaded',
      timeout: 15_000,
    })
  } catch (err) {
    // goto might timeout, that's okay — we care about the final URL
    await page.screenshot({
      path: path.join(DEBUG_DIR, `chrome-goto-fail-${domain}.png`)
    })
  }

  // Poll for up to 15s
  const deadline = Date.now() + 15_000
  while (Date.now() < deadline) {
    if (!page.url().includes(SSO_DOMAIN)) break
    await sleep(1000)
  }

  await sleep(1000)

  const finalUrl = page.url()
  if (finalUrl.includes(SSO_DOMAIN)) {
    throw new Error('SSO session expired. Run `my-cli login` to re-authenticate.')
  }

  const all = await context.cookies()
  const domainCookies = all.filter(c => matchesDomain(c.domain, domain))

  // Must have the SSO session cookie
  const hasAccessProxy = domainCookies.some(
    c => c.name === 'accessproxy_session'
  )
  if (domainCookies.length === 0 || !hasAccessProxy) {
    throw new Error('No valid session after silent auth.')
  }

  await refreshAllKnownDomains(all, domain)
  return domainCookies
}
```

### Debuggability

Silent auth can fail for many reasons (SSO expired, network hiccup, cookie name changed). Save screenshots on every failure:

```typescript
await page.screenshot({
  path: path.join(DEBUG_DIR, `chrome-final-${domain}.png`)
})
```

Users can inspect `~/.my-cli/debug/` to see what the browser saw.

---

## 1.6 Cross-Domain Session Refresh

Here's a pattern that saves massive support burden: **logging into one platform refreshes sessions for all platforms.**

When your SSO issues cookies, it often sets them for the entire `*.corp.example.com` scope. If the user has previously logged into `kconf.corp.example.com` and `team.corp.example.com`, a single browser session refresh gives you fresh cookies for **both**.

```typescript
async function refreshAllKnownDomains(
  allCookies: PlaywrightCookie[],
  primaryDomain: string
): Promise<void> {
  const knownDomains = listDomains()

  // Refresh existing known domains
  for (const knownDomain of knownDomains) {
    if (knownDomain === primaryDomain) continue
    const refreshed = allCookies.filter(c => matchesDomain(c.domain, knownDomain))
    if (refreshed.length > 0) {
      saveCookiesForDomain(knownDomain, mapCookies(refreshed))
    }
  }

  // Discover new *.corp.example.com subdomains
  const allKnown = [...knownDomains, primaryDomain]
  for (const c of allCookies) {
    const d = c.domain.replace(/^\./, '')
    if (d.endsWith('.corp.example.com') && !allKnown.includes(d)) {
      const domainCookies = allCookies.filter(cc => matchesDomain(cc.domain, d))
      saveCookiesForDomain(d, mapCookies(domainCookies))
    }
  }
}
```

---

## 1.7 Automatic Cookie Injection

The CLI shouldn't require users to pass `--cookie` flags. Every command should resolve its own auth.

### For HTTP Commands

```typescript
// platform.ts — before executing an HTTP command
const cookieHeader = await resolveCookieHeader(command, manifest.baseUrl)
// -> "accessproxy_session=abc; _t=xyz"

const result = await executeCommand(command, params, { cookieHeader, baseUrl })

// In the HTTP runner:
function buildRequestInit(command, params, cookieHeader) {
  const headers = { 'Content-Type': 'application/json' }
  if (cookieHeader) headers['Cookie'] = cookieHeader
  return { method: command.method, headers, body: JSON.stringify(body) }
}
```

### For Script Commands

Script commands run as child processes and receive cookies via environment variables:

```typescript
const env = { ...process.env }
if (cookieHeader) {
  env['MYCLI_COOKIE'] = cookieHeader   // scripts read this
}
env['MYCLI_BASE_URL'] = baseUrl
env['MYCLI_USERNAME'] = username

spawn('node', [scriptPath], { cwd: toolDir, env })
```

Scripts then do:

```javascript
const cookie = process.env.MYCLI_COOKIE
fetch(url, { headers: { 'Cookie': cookie } })
```

### The Full `resolveCookieHeader` Flow

```typescript
async function resolveCookieHeader(command, baseUrl): Promise<string | undefined> {
  // SCRIPT commands default to requiring auth
  const requiresAuth = command.requiresAuth ??
    (command.method === 'SCRIPT' ? true : false)
  if (!requiresAuth) return undefined

  const domain = extractDomain(baseUrl)

  // 1. Try cached session
  let cookies = getCookiesForDomain(domain)

  // 2. No cache? Silent auth
  if (!cookies) {
    cookies = await silentAuth(baseUrl, domain)
    saveCookiesForDomain(domain, cookies)
  }

  return buildCookieHeader(cookies)
}
```

---

## 1.8 Auth Failure Recovery

Even with all this automation, auth can fail. Handle it gracefully:

```typescript
// After executing a command:
if (isAuthFailure(result.status, result.body)) {
  // isAuthFailure: status === 401/403 or body has code === 101

  deleteCookiesForDomain(domain)

  try {
    const freshCookies = await silentAuth(baseUrl, domain)
    saveCookiesForDomain(domain, freshCookies)
    result = await executeCommand(command, params, {
      cookieHeader: buildCookieHeader(freshCookies)
    })
  } catch {
    // Silent failed — open browser for user to re-auth
    const freshCookies = await launchSSOLogin(baseUrl, domain)
    saveCookiesForDomain(domain, freshCookies)
    result = await executeCommand(command, params, {
      cookieHeader: buildCookieHeader(freshCookies)
    })
  }
}
```

The user experience: "Oh, it said my session expired, opened a browser, I scanned the code, and it worked."

---

## 1.9 Set-Cookie Refresh

HTTP responses may return new cookies (session extension, CSRF tokens, etc.). Capture them:

```typescript
const response = await fetch(url, init)

// Node 22+ supports response.headers.getSetCookie()
const setCookies = (response.headers as any).getSetCookie?.()
if (setCookies && setCookies.length > 0) {
  updateCookiesFromSetCookie(domain, setCookies)
}
```

This means: user logs in Monday, uses the CLI all week, and their session never expires because each API call silently refreshes the cookies.

---

## 1.10 CLI Commands

| Command | Behavior |
|---------|----------|
| `my-cli login` | Open browser, wait for SSO, save cookies |
| `my-cli auth login --force` | Re-authenticate even if session is valid |
| `my-cli auth logout` | Clear all sessions |
| `my-cli auth logout --domain x.corp.example.com` | Clear one domain |
| `my-cli auth logout --all` | Clear sessions + delete Chrome profile |
| `my-cli auth status` | Show active sessions and expiry times |

---

## 1.11 Common Pitfalls

### Pitfall 1: Using a downloaded browser instead of system Chrome
Users hate waiting for a 150MB download. Use their existing Chrome.

### Pitfall 2: Capturing cookies too early
After SSO redirect, wait 1-2 seconds for SPA JavaScript to set additional cookies.

### Pitfall 3: Session cookie storage without permission hardening
`session.json` contains live SSO sessions. Use `chmod 600` on the file and `chmod 700` on the directory.

### Pitfall 4: Not handling the "secondary login page"
Some SSO flows redirect to an intermediate page ("Confirm login?"). Check for login-related UI elements before declaring success.

### Pitfall 5: Losing cookies on CLI upgrade
Provide an automatic migration path from old config directories.

---

## 1.12 Summary

A great internal CLI auth system has these properties:

1. **One login, many commands** — scan QR once, everything works
2. **Silent refresh** — expired sessions are fixed automatically
3. **Cross-domain sharing** — login to A refreshes B, C, D
4. **Graceful degradation** — silent fails → headed login → clear error message
5. **Debuggable** — screenshots, verbose logs, `auth status`
6. **Secure** — least-privilege file permissions, no token leaks in env

In the next chapter, we'll look at **command discovery and manifests** — how to register platform commands so the CLI knows what endpoints exist, what parameters they take, and which ones need auth.
