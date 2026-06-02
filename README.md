# 🔴 Red Team Agent v2.0

Automated web application red teaming platform with a headless browser, 10-phase security testing, a smart learning engine, and PDF reporting. Written in **Go**.

---

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Architecture](#-architecture)
- [How to Run](#-how-to-run)
- [Configuration](#-configuration)
- [Authentication Setup (Login / Token)](#-authentication-setup-login--token)
- [10-Phase Testing — Technique Details](#-10-phase-testing--technique-details)
  - [Phase 1: Reconnaissance](#phase-1-reconnaissance)
  - [Phase 2: Discovery](#phase-2-discovery)
  - [Phase 3: Authentication](#phase-3-authentication)
  - [Phase 4: Authorization](#phase-4-authorization)
  - [Phase 5: Injection](#phase-5-injection)
  - [Phase 6: Logic & Business Flow](#phase-6-logic--business-flow)
  - [Phase 7: Client-Side](#phase-7-client-side)
  - [Phase 8: Infrastructure](#phase-8-infrastructure)
  - [Phase 9: DDoS Simulation](#phase-9-ddos-simulation)
  - [Phase 10: Fuzzing Stress](#phase-10-fuzzing-stress)
- [Learning Engine](#-learning-engine)
- [API Endpoints](#-api-endpoints)
- [Web Dashboard](#-web-dashboard)
- [Project Structure](#-project-structure)
- [Cross-Compilation](#-cross-compilation)
- [Docker](#-docker)
- [Disclaimer](#-disclaimer)

---

## 🚀 Quick Start

```bash
# Clone and enter the directory
cd red-team-agent

# Build the binary
make build

# Run with the default config
./red-team-agent --config config.json --data data

# Or development mode (no build)
make dev
```

The dashboard is available at: **http://localhost:5555**

---

## 🏗 Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        AGENT LOOP                            │
│                                                              │
│   Plan ──▶ Scan ──▶ Analyze ──▶ Learn ──▶ Report ──▶ Repeat │
│     ▲                                           │            │
│     └───────────────────────────────────────────┘            │
│                                                              │
│  ┌───────────┐  ┌──────────────┐  ┌────────────────────┐     │
│  │ Knowledge │  │   Scanner    │  │  Headless Browser  │     │
│  │   Base    │  │ (10 phases)  │  │    (Rod/CDP)       │     │
│  │  (JSON)   │  │              │  │                    │     │
│  └───────────┘  └──────────────┘  └────────────────────┘     │
│                        │                                     │
│                  ┌─────▼──────┐                               │
│                  │ PDF Report │                               │
│                  │  (gofpdf)  │                               │
│                  └────────────┘                               │
│                                                              │
│  ┌──────────────────────────────────────────────────┐        │
│  │         Dashboard (Go net/http + gorilla)        │        │
│  │            http://localhost:5555                  │        │
│  └──────────────────────────────────────────────────┘        │
└──────────────────────────────────────────────────────────────┘
```

The **Agent Loop** runs continuously:
1. **Plan** — Build a scan plan based on the knowledge base
2. **Scan** — Execute the 10 testing phases (Recon → Discovery → Auth → Authz → Injection → Logic → Client-Side → Infra → DDoS → Fuzz)
3. **Analyze** — Collect findings, endpoints, parameters
4. **Learn** — Record successful/failed techniques into the knowledge base
5. **Report** — Generate a PDF report
6. **Repeat** — The next iteration is smarter

---

## 🏃 How to Run

### 1. Build from Source

```bash
# Make sure Go 1.21+ is installed
go version

# Build the binary
make build

# Run
./red-team-agent --config config.json --data data
```

### 2. Development Mode

```bash
# Run directly without building
make dev

# Or manually
go run ./cmd/agent/ --config config.json --data data
```

### Triggering a Scan

The agent does **not** scan on startup by default — it waits for each target's
`schedule` (interval/cron) to fire. To start scanning immediately, use one of:

```bash
# Run one scan per enabled target right away, then keep the schedule running
./red-team-agent --config config.json --data data --scan-now

# Or trigger a single target on demand via the API (see "Via API" below)
curl -X POST http://localhost:5555/api/scan/start -d '{"target_id":"example"}'
```

If `agent.max_iterations` is set (> 0), a target's schedule stops automatically
once it has completed that many scan iterations.

### 3. Docker

```bash
# Build and run the container
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

### 4. Custom Port/Host

```bash
# Change port and host via CLI flags
./red-team-agent --config config.json --data data --port 8080 --host 127.0.0.1

# Or edit the "dashboard" section of config.json
```

### 5. Cross-Platform Binary

```bash
# Build all platforms at once
make build-all

# Or build per platform
make build-linux      # Linux AMD64
make build-mac-intel  # macOS Intel
make build-mac-arm    # macOS Apple Silicon
make build-windows    # Windows AMD64
```

### 6. Via API

```bash
# Start a scan for a specific target
curl -X POST http://localhost:5555/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"target_id": "example"}'

# Check progress
curl http://localhost:5555/api/scan/progress

# Download a report
curl -O http://localhost:5555/api/reports/download/redteam_example_2026-06-02.pdf
```

---

## ⚙️ Configuration

Edit `config.json` or use the web dashboard:

```json
{
  "targets": [
    {
      "id": "my-app",
      "name": "My Application",
      "url": "https://myapp.example.com",
      "enabled": true,
      "auth": {
        "method": "form",
        "username": "admin",
        "password": "test",
        "login_url": "https://myapp.example.com/login"
      },
      "scope": {
        "include_paths": ["*"],
        "exclude_paths": [],
        "max_depth": 2,
        "rate_limit_rps": 5,
        "timeout": "10s",
        "slow_threshold_ms": 500
      },
      "tests": {
        "recon": true,
        "discovery": true,
        "auth": true,
        "authz": true,
        "injection": true,
        "logic": true,
        "client_side": true,
        "infra": true,
        "ddos": true,
        "fuzz": true
      },
      "schedule": {
        "interval": "",
        "cron": "0 2 * * *"
      }
    }
  ],
  "agent": {
    "headless": true,
    "auto_download_chrome": true,
    "user_agent": "RedTeamAgent/2.0",
    "max_iterations": 0,
    "proxy": ""
  },
  "dashboard": {
    "host": "0.0.0.0",
    "port": 5555
  }
}
```

**Key fields:**
| Field | Description |
|-------|-------------|
| `auth.method` | `none`, `form`, `token`, `basic` — applied to the whole scan session and scoped to the target host |
| `scope.include_paths` | Allowlist of path patterns to scan (default `["*"]` = all). Supports exact, prefix `*`, and `*` |
| `scope.exclude_paths` | Path patterns that are blocked at the HTTP layer (e.g. `["/admin/delete", "/admin/drop"]`). Enforced for every request |
| `scope.rate_limit_rps` | Max requests per second, enforced globally across concurrent phases (default: 5) |
| `scope.timeout` | HTTP timeout per request |
| `scope.slow_threshold_ms` | Flag a response as `minor` if it exceeds this threshold (default: `500` ms, set `0` to disable) |
| `tests.*` | Enable/disable per phase |
| `schedule.cron` | Cron expression for auto-scan |
| `agent.max_iterations` | Stop a target's schedule after this many iterations (`0` = unlimited) |
| `agent.proxy` | HTTP proxy (optional) |

---

## 🔍 10-Phase Testing — Technique Details

### Phase 1: Reconnaissance

**Goal:** Gather as much information about the target as possible before launching attacks.

| Technique | Detail |
|--------|--------|
| **HTTP Fingerprinting** | Analyze response headers (`Server`, `X-Powered-By`) to identify the web server and technologies |
| **Framework Detection via Cookies** | Detect the framework from cookie names: `PHPSESSID` → PHP, `JSESSIONID` → Java, `laravel_session` → Laravel, `rack.session` → Rails, `ASP.NET_SessionId` → ASP.NET |
| **robots.txt Analysis** | Parse `robots.txt` to find hidden paths (Disallow/Allow entries) |
| **sitemap.xml Parsing** | Extract all URLs from `sitemap.xml` |
| **TLS/SSL Check** | Verify whether HTTPS is used; if not → medium finding |
| **JavaScript File Analysis** | Scan common JS files (`/static/js/app.js`, `/js/main.js`, etc.) for: API keys, secrets, passwords, tokens, authorization references |
| **Error Page Analysis** | Send a request to a non-existent page and check whether the error page leaks info: stack trace, exception, debug mode, server software (Apache/Nginx/IIS) |

**Key Findings:**
- `info-disclosure` — Sensitive data in JS files
- `info-disclosure` — Tech stack leaked in error pages
- `No TLS` — Target without HTTPS

---

### Phase 2: Discovery

**Goal:** Find as many endpoints, parameters, and attack entry points as possible.

| Technique | Detail |
|--------|--------|
| **Directory/File Brute Force** | Check 50+ common paths: `/admin`, `/.env`, `/.git/config`, `/swagger.json`, `/phpmyadmin`, `/backup.sql`, etc. Flag severity based on sensitivity |
| **API Endpoint Discovery** | Scan API patterns: `/api`, `/api/v1`, `/api/v2`, `/rest`, `/graphql` |
| **Deep REST API Discovery** | Test 70+ REST API patterns: `/api/v1/users`, `/api/v1/posts`, `/api/v1/admin`, including auth endpoints and OAuth paths |
| **Parameter Discovery** | Identify common query parameters: `id`, `page`, `search`, `file`, `path`, `url`, `redirect`, `callback`, etc. |
| **Source Code Comment Analysis** | Parse HTML comments, looking for sensitive keywords: `password`, `secret`, `api`, `key`, `token`, `admin`, `debug`, `todo`, `fixme`, `hack`, `temp` |
| **HTTP Method Fuzzing** | Test GET, POST, PUT, DELETE, PATCH, OPTIONS on discovered endpoints. Check the `Allow` header from OPTIONS |
| **JavaScript Endpoint Extraction** | Parse `<script>` tags, fetch JS files, extract endpoints from: `fetch()`, `axios.get/post()`, `XMLHttpRequest`, URL string patterns |
| **Form Discovery** | Parse HTML forms, extract: action URL, method, input fields (including textarea and select). Detect **missing CSRF token** on POST forms |
| **GraphQL Introspection** | Send an introspection query to `/graphql`, `/graphiql`, `/api/graphql`, `/query`, `/v1/graphql`. If `__schema` is exposed → finding |

**Key Findings:**
- `sensitive-file` — Sensitive file publicly accessible
- `api-docs` — Swagger/OpenAPI documentation exposed
- `http-methods` — Too many HTTP methods accepted
- `csrf-missing` — POST form without a CSRF token
- `graphql-introspection` — GraphQL schema exposed

---

### Phase 3: Authentication

**Goal:** Test the security of the authentication mechanism.

| Technique | Detail |
|--------|--------|
| **Default Credential Testing** | Try 14 common credential combinations: `admin/admin`, `admin/password`, `root/root`, `admin/123456`, `guest/guest`, etc. |
| **Login Bypass via SQLi** | 7 bypass payloads: `admin'--`, `admin' OR '1'='1`, `' OR 1=1--`, `admin%00` (null byte), `admin\` (backslash), empty password |
| **JWT alg:none Attack** | Send a JWT with algorithm `none` and body `{"sub":"1","role":"admin"}` to authenticated endpoints. If accepted → critical |
| **Password Reset User Enumeration** | Test password reset endpoints (`/forgot-password`, `/api/auth/forgot`), checking whether the response leaks whether an email exists |
| **Session Fixation** | Set cookie `session=<fixed>` before login and check whether the session ID is rotated after a successful login |

**Key Findings:**
- `default-credentials` (Critical) — Default password still valid
- `auth-bypass` (Critical) — Login can be bypassed via SQLi
- `jwt-alg-none` (Critical) — Server accepts JWT without a signature
- `user-enumeration` (Medium) — Password reset leaks user info
- `session-fixation` (High) — Session ID not rotated after login

---

### Phase 4: Authorization

**Goal:** Test whether access control is implemented correctly.

| Technique | Detail |
|--------|--------|
| **Privilege Escalation** | Access admin paths (`/admin`, `/admin/users`, `/api/admin`) without authentication |
| **IDOR (Insecure Direct Object Reference)** | Test sequential IDs (`/api/users/1`, `/api/orders/1`) without auth. Check whether the response contains user data (email, name, password). Also test endpoints from the knowledge base |
| **Missing Function-Level Access Control** | Send GET, POST, PUT, DELETE, PATCH to sensitive endpoints (`/api/users`, `/api/config`) without auth |
| **API Authorization Bypass via Headers** | 7 bypass techniques: `X-Forwarded-For: 127.0.0.1`, `X-Original-URL: /admin`, `X-Rewrite-URL: /admin`, `X-Custom-IP-Authorization: 127.0.0.1`, `X-Real-IP: 127.0.0.1`, `Content-Type: application/json`, `X-HTTP-Method-Override: GET` |

**Key Findings:**
- `privilege-escalation` (High) — Admin path accessible without auth
- `idor` (High) — Other users' data accessible via sequential ID
- `missing-access-control` (High) — Sensitive HTTP method accepted without auth
- `authz-bypass` (High) — Bypass via spoofed headers

---

### Phase 5: Injection

**Goal:** Test every kind of injection attack against every discovered parameter and endpoint.

#### SQL Injection (6 Variants)

| Type | Example Payload | Detection |
|------|---------------|---------|
| **Error-based** | `'`, `"`, `' OR '1'='1`, `' UNION SELECT NULL--` | SQL error patterns: `SQL syntax`, `mysql_fetch`, `ORA-01756`, `SQLSTATE`, `sqlite_` |
| **MySQL-specific** | `' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--` | MySQL error |
| **PostgreSQL-specific** | `' AND 1=CAST((SELECT version()) AS INT)--` | PG error |
| **Time-based** | `' AND SLEEP(5)--`, `1; WAITFOR DELAY '0:0:5'--` | Response > 4 seconds |
| **Stacked Queries** | `'; SELECT SLEEP(5)--`, `'; WAITFOR DELAY '0:0:5'--` | Delay detected |
| **Boolean Blind** | `' AND 1=1--` vs `' AND 1=2--` | Response difference |

**21 SQL error patterns** are detected: `SQL syntax`, `mysql_fetch`, `ORA-01756`, `SQLSTATE`, `sqlite_`, `unclosed quotation mark`, etc.

#### XSS (Cross-Site Scripting)

| Type | Example Payload |
|------|---------------|
| **Basic** | `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>` |
| **Filter Bypass** | `<SCRIPT>`, `<ScRiPt>`, `<scr<script>ipt>`, `<svg/onload=alert(1)>` |
| **Event Handlers** | `" onmouseover="alert(1)`, `' onfocus='alert(1)` |
| **No Parentheses** | `<script>alert\`1\`</script>` |
| **Encoded** | `%3Cscript%3Ealert(1)%3C/script%3E` |
| **DOM-based** | `#<img src=x onerror=alert(1)>`, `javascript:void(alert(1))` |
| **Template Literal** | `${alert(1)}`, `{{constructor.constructor('return alert(1)')()}}` |

Detection: Payload reflected in the response body.

#### Command Injection

| Type | Example Payload |
|------|---------------|
| **Unix** | `; id`, `\| id`, `` `id` ``, `$(id)`, `; cat /etc/passwd` |
| **Windows** | `& dir`, `\| dir`, `&& type C:\boot.ini` |
| **Newline** | `\nid`, `\r\nid`, `%0aid` |
| **Encoding Bypass** | `%3bid`, `%7cid` |
| **Direct Path** | `;/bin/id`, `` `/bin/id` ``, `$(/bin/id)` |

Detection: Output patterns — `uid=`, `gid=`, `root:`, `drwx`, `total `, `/bin/sh`.

#### SSTI (Server-Side Template Injection)

| Engine | Payload |
|--------|---------|
| **Jinja2/Flask** | `{{7*7}}` → `49`, `{{config}}`, `{{self.__class__.__mro__}}` |
| **Spring EL** | `${T(java.lang.Runtime).getRuntime().exec('id')}` |
| **FreeMarker** | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` |
| **ERB/Ruby** | `<%= 7*7 %>` |
| **Django** | `#{7*7}`, `{{request.application...}}` |
| **Pug** | `*{7*7}` |

#### LDAP Injection

Payload: `*)(|(cn=*`, `admin)(&))`, `*)(objectClass=*`, `admin*)((|userPassword=*)`

Detection: Response contains `ldap`, `dn=`, `dc=`, `ou=`, `invalid dn`.

#### XXE (XML External Entity)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

5 XXE payload variants: file read (`/etc/passwd`, `C:\boot.ini`), SSRF via XXE, DTD-based.

Detection: Response contains `root:`, `/etc/passwd`, `<?xml`, `<!entity`.

#### CRLF Injection

Payload: `%0d%0aSet-Cookie:%20evil=injected`, `%0d%0aLocation:%20https://evil.com`

Detection: The injected header appears in the response.

#### SSRF (Server-Side Request Forgery)

| Category | Payload |
|----------|---------|
| **Internal IPs** | `http://127.0.0.1`, `http://localhost:22/80/443/3306/6379/27017`, `http://[::1]`, `http://0.0.0.0` |
| **IP Encoding Bypass** | `http://0x7f000001`, `http://0177.0.0.1`, `http://2130706433` |
| **Private Network** | `http://10.0.0.1`, `http://172.16.0.1`, `http://192.168.0.1/1.254` |
| **AWS Metadata** | `http://169.254.169.254/latest/meta-data/`, `iam/security-credentials/` |
| **GCP Metadata** | `http://metadata.google.internal/computeMetadata/v1/` |
| **Azure/Alibaba** | `http://169.254.169.254/metadata/instance`, `http://100.100.100.200/latest/meta-data/` |
| **File Protocol** | `file:///etc/passwd`, `file:///proc/self/environ` |
| **Gopher/Dict** | `gopher://127.0.0.1:6379/`, `dict://127.0.0.1:6379/INFO` |

Detection: Response contains `ami-id`, `instance-id`, `root:`, `<ListAllMyBucketsResult>`.

#### Prototype Pollution

| Via | Payload |
|-----|---------|
| **Query Params** | `__proto__[polluted]=yes`, `constructor[prototype][isAdmin]=true` |
| **JSON Body** | `{"__proto__": {"isAdmin": true}}`, `{"constructor": {"prototype": {"polluted": "yes"}}}` |

#### Host Header Injection

Payload: `evil.com`, `localhost`, `127.0.0.1`, `attacker.com`, `original-host.com\r\nX-Injected: true`

Check: Reflected host in the response, and **password reset poisoning** via the Host header.

#### HTTP Method Tampering

Test the headers `X-HTTP-Method-Override`, `X-Method-Override`, `X-HTTP-Method`, `_method` on protected endpoints. If a normal request → 401/403 but the override → 200 → bypass.

#### Multi-Method Injection

Test SQLi and XSS via **POST**, **PUT**, **PATCH** with:
- JSON body: `{"username": "' OR '1'='1"}`
- Form-urlencoded body: `username=' OR '1'='1`

---

### Phase 6: Logic & Business Flow

**Goal:** Test for business-logic flaws and race conditions.

| Technique | Detail |
|--------|--------|
| **Rate Limit Bypass** | Send 20 rapid consecutive login attempts. If ≥15 succeed without a block → finding |
| **Parameter Tampering** | Test parameters: `price=0.01`, `role=admin`, `isAdmin=true`, `admin=1`, `debug=true`, `access_level=99` |
| **Force Browsing** | Direct access to: `/admin/delete-user`, `/admin/export`, `/api/internal`, `/api/debug`, `/actuator/shutdown` |
| **Race Condition** | Send 10–20 concurrent requests to state-changing endpoints: coupon apply, transfer, withdraw, vote, like, checkout, referral, redeem. If >1 succeed → race condition |
| **IDOR in API** | Test 17 API patterns × 6 IDs (`1`, `2`, `3`, `999`, `0`, `-1`) for users, orders, documents, messages |
| **HTTP Method Bypass** | Compare the response of 7 HTTP methods on protected paths. If any method bypasses 401/403 → finding |
| **Mass Assignment** | Inject extra fields in the JSON body on POST/PUT: `{"role": "admin"}`, `{"isAdmin": true}`, `{"plan": "premium"}`, `{"credit": 99999}`, `{"permissions": ["admin", "superadmin"]}` |

**Key Findings:**
- `rate-limit` — Login without rate limiting
- `race-condition` — Endpoint can be called concurrently
- `idor-api` — Other users' data via API
- `mass-assignment` — Extra JSON fields accepted by the server

---

### Phase 7: Client-Side

**Goal:** Test client-side (browser) security.

| Technique | Detail |
|--------|--------|
| **CORS Misconfiguration** | Send OPTIONS with Origin: `https://evil.com`, `http://localhost`, `https://attacker.example.com`. Check `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`. If ACAO = `*` or = origin → finding. If + credentials → severity raised to high |
| **Clickjacking** | Check whether `X-Frame-Options` or CSP `frame-ancestors` is present. If absent → the page can be iframed |
| **Open Redirect** | Test 8 redirect parameters (`redirect`, `url`, `next`, `return`, `goto`, `continue`, etc.) × 3 payloads (`https://evil.com`, `//evil.com`, `/\evil.com`). Check the `Location` header |
| **CSP Analysis** | Check the `Content-Security-Policy` header. If missing → finding. If present but containing `'unsafe-inline'` or `'unsafe-eval'` → weak |
| **Client-Side Prototype Pollution** | Scan JS code for dangerous patterns: deep merge without `hasOwnProperty`, `_.merge`, `$.extend`, `Object.assign`, `__proto__` assignment, `constructor.prototype` |
| **postMessage Security** | Check `addEventListener("message", ...)` without `origin` validation. Check `postMessage(..., '*')` that leaks data to any window |
| **DOM Clobbering** | Detect: `window.location` comparison, `document.getElementById` without a null check, `window.property` comparison |
| **DOM Sinks** | Detect 16 dangerous sinks: `innerHTML`, `outerHTML`, `document.write`, `eval()`, `setTimeout(string)`, `new Function()`, `insertAdjacentHTML`, `location=`, etc. |

---

### Phase 8: Infrastructure

**Goal:** Test server infrastructure security.

| Technique | Detail |
|--------|--------|
| **Security Headers Audit** | Check 6 headers: `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Strict-Transport-Security`, `Referrer-Policy`, `Permissions-Policy`. Missing ≥4 → medium |
| **Cookie Security** | Audit session cookies for: `HttpOnly`, `Secure`, `SameSite` flags |
| **Information Disclosure** | Scan 20+ sensitive paths: `/.env`, `/.git/config`, `/.htaccess`, `/server-status`, `/phpinfo.php`, `/actuator/env`, `/swagger.json`, `/.DS_Store`, etc. |
| **Path Traversal / LFI** | 14 payloads: `../../../etc/passwd`, `..\\..\\..\\boot.ini`, `..%2f..%2f`, `..%c0%af`, `/etc/passwd%00`, double-encoding variants |
| **Backup File Detection** | Check 18 backup paths: `backup.sql`, `database.sql`, `.env.backup`, `.env.bak`, `backup.zip`, `dump.rdb`, etc. |
| **Debug Mode Detection** | Check 17 debug paths: `/debug`, `/trace`, `/_debugbar`, `/actuator/beans`, `/actuator/heapdump`, `/_profiler`, `/phpinfo.php` |
| **SSRF via URL Parameters** | Test SSRF payloads on 28 URL-like parameters across 8 endpoint patterns |
| **Subdomain Takeover** | Resolve CNAME records, check whether they point to vulnerable services (CloudFront, S3, Heroku, GitHub Pages, Azure, etc.). Verify via response body indicators |
| **Certificate Transparency** | Query `crt.sh` to discover subdomains from CT logs. Store them as endpoints for further testing |
| **HTTPS/TLS Misconfiguration** | Connect directly to TLS, check: expired cert, self-signed, hostname mismatch, expiring <30 days, weak signature (SHA1), TLS 1.0/1.1, missing HSTS |

**Key Findings:**
- `path-traversal` (Critical) — Can read system files
- `backup-file` (High) — Backup file exposed
- `subdomain-takeover` (High) — Dangling CNAME
- `tls-cert-expired` (High) — Certificate expired
- `debug-mode` (Medium) — Debug endpoint exposed

---

### Phase 9: DDoS Simulation

**Goal:** Test the server's resilience against denial-of-service attacks.

| Technique | Detail |
|--------|--------|
| **Slowloris** | Open 10 TCP connections, send partial HTTP headers slowly every 3 seconds for 15 seconds. If ≥50% of connections stay alive → vulnerable |
| **HTTP Flood** | Send 100 concurrent requests (20 concurrency). Measure: success rate, 5xx errors, timeouts, min/max/avg response time. If >5 5xx or >20 timeouts → high |
| **Amplification Check** | Test 3 kinds of oversized request: 8KB URL, 100KB POST body, 8KB header value. If accepted without error → server can be abused |
| **Connection Exhaustion** | Open 50 concurrent TCP connections. If ≥45 succeed → no connection rate limiting |
| **Slow POST (R.U.D.Y.)** | Send a POST with `Content-Length: 10000` but deliver the body at 1 byte/second. If ≥50% of connections stay alive after 10 seconds → vulnerable |

**Key Findings:**
- `slowloris` — Server vulnerable to Slowloris
- `http-flood-degradation` — Server degrades under load
- `connection-exhaustion` — No connection rate limit
- `slow-post` — R.U.D.Y. vulnerability

---

### Phase 10: Fuzzing Stress

**Goal:** Send abnormal input to find crashes, unhandled errors, and edge cases.

| Technique | Detail |
|--------|--------|
| **Parameter Fuzzing** | Send 25 fuzz values to 16 common parameters across 5 endpoints. Values: long string (10K), format strings (`%s`, `%n`, `%x`), template injection (`{{7*7}}`, `${7*7}`), null bytes, SQLi, XSS, unicode flood (🐱), CRLF, path traversal, file URI, ldap/gopher URIs. Cap: 50 tests |
| **Header Fuzzing** | Fuzz 11 headers × 10 values: long value (8K), special chars, null byte, newline injection, format string, unicode flood, template injection, SSI, CRLF double |
| **Method Fuzzing** | Test 16 unusual methods: `TRACE`, `TRACK`, `CONNECT`, `PROPFIND`, `MKCOL`, `COPY`, `MOVE`, `LOCK`, `PURGE`, `LINK`, etc. **TRACE** is special: if it reflects the request → Cross-Site Tracing (XST) |
| **Content-Type Fuzzing** | Send POST with 13 content-type/body combos: oversized JSON, invalid JSON, deep JSON, XXE in XML, multipart, NoSQL injection (`$gt`, `$ne`, `$where`), prototype pollution, binary data |
| **Boundary Fuzzing** | 8 extreme payloads: 100KB JSON, empty body, deeply nested JSON (50 levels), binary garbage, partial JSON, array overflow (10K elements), unicode null JSON |
| **Encoding Fuzzing** | 13 encoded payloads: double-encoded (`%252e%252e`), URL-encoded XSS/SQLi, base64-encoded attacks, mixed unicode, overlong UTF-8 (`%c0%ae`), percent null/newline |

**Key Findings:**
- `param-fuzz-500` — A fuzzed parameter caused a server error
- `unusual-method` — Unusual HTTP method accepted
- `boundary-fuzz-timeout` — Server timeout on an extreme payload
- `encoding-fuzz-reflection` — Server decodes and reflects a dangerous payload
- `slow-response` — Endpoint responds above the threshold (default: 500ms)

---

### ⏱ Slow Response Tracking (Automatic Across All Phases)

In addition to the 10 testing phases, the agent automatically checks the response time of **every HTTP request** it sends. If a response time exceeds the threshold, a `minor` finding is created.

**Configuration:**

```json
{
  "scope": {
    "slow_threshold_ms": 500
  }
}
```

| Setting | Effect |
|---------|------|
| `500` (default) | Flag responses > 500ms |
| `200` | More sensitive, flag > 200ms |
| `1000` | Only flag very slow responses > 1 second |
| `0` | Disable slow response tracking |

**How it works:**
- Hooks into every `MakeRequest` via a callback — no changes to phase code
- Deduplication per URL (the same URL is only reported once per scan)
- The finding automatically goes into the currently running phase
- Severity: `minor`
- Included in the PDF report and the knowledge base

**Example finding:**
```
Type:        slow-response
Severity:    minor
Title:       Slow Response: 823ms
Description: GET https://target.com/api/users responded in 823ms (threshold: 500ms)
Remediation: Investigate slow endpoint. Consider caching, query optimization, or pagination.
```

---

## 🧠 Learning Engine

On every iteration, the agent learns and improves its attacks:

1. **Load** — Knowledge base: endpoints, parameters, past findings, tech stack, successful/failed techniques
2. **Plan** — Build a scan plan based on the data: tech-specific payloads, skip failed techniques, deep-dive into successful techniques
3. **Scan** — Execute all 10 phases
4. **Learn** — Record: new findings, new endpoints, technique success/failure, payloads already used
5. **Report** — Generate a PDF
6. **Improve** — On the next iteration:
   - Skip payloads already tested (deduplication)
   - Skip techniques that always fail on this target
   - Deep-dive into successful techniques (e.g. error-based SQLi → blind/time-based)
   - Tech-specific payloads (detect PHP → try PHP-specific payloads)

**Evolution example:**
```
Iteration 1: Find error-based SQLi in the "id" parameter
Iteration 2: Try blind/time-based SQLi on the same parameter + other parameters
Iteration 3: Try WAF bypass techniques on the SQLi already found
```

---

## 🌐 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-----------|
| `POST` | `/api/scan/start` | Start a scan (`{"target_id": "..."}`) |
| `GET` | `/api/scan/progress` | Current scan progress |
| `GET` | `/api/scan/history` | History of all scans |
| `GET` | `/api/config` | Get configuration |
| `PUT` | `/api/config` | Update configuration (hot-reload) |
| `GET` | `/api/targets` | List all targets |
| `POST` | `/api/targets` | Add a new target |
| `PUT` | `/api/targets/{id}` | Update a target |
| `DELETE` | `/api/targets/{id}` | Delete a target |
| `GET` | `/api/reports` | List all reports |
| `GET` | `/api/reports/download/{file}` | Download a PDF report |
| `GET` | `/api/skills` | Learning overview |
| `POST` | `/api/skills/{id}/reset` | Reset the knowledge base |

---

## 📊 Web Dashboard

A built-in dashboard at **http://localhost:5555** with these pages:

- **Dashboard** — Overview: active scans, findings summary, severity breakdown
- **Scan** — Start/monitor a scan, real-time progress per phase
- **Reports** — List and download PDF reports
- **Config** — Edit target and agent configuration
- **Skills** — View learning progress, knowledge base, reset

---

## 📁 Project Structure

```
red-team-agent/
├── cmd/agent/main.go              # Entry point
├── internal/
│   ├── agent/                     # Agent loop + planner + scheduler
│   │   ├── agent.go               # Main agent logic
│   │   ├── planner.go             # Scan planning
│   │   ├── scheduler.go           # Cron scheduling
│   │   └── types.go               # Type definitions
│   ├── scanner/                   # 10-phase security scanner
│   │   ├── scanner.go             # Scanner engine + HTTP client
│   │   ├── recon.go               # Phase 1: Reconnaissance
│   │   ├── discovery.go           # Phase 2: Discovery
│   │   ├── auth.go                # Phase 3: Authentication
│   │   ├── authz.go               # Phase 4: Authorization
│   │   ├── injection.go           # Phase 5: Injection (SQLi, XSS, CMD, SSTI, LDAP, XXE, CRLF, SSRF, PP, Host Header, Method Tampering, Multi-method)
│   │   ├── logic.go               # Phase 6: Logic (Rate limit, Param tamper, Force browse, Race condition, IDOR, Method bypass, Mass assignment)
│   │   ├── clientside.go          # Phase 7: Client-Side (CORS, Clickjacking, Open Redirect, CSP, PP, postMessage, DOM Clobbering, DOM Sinks)
│   │   ├── infra.go               # Phase 8: Infrastructure (Headers, Cookies, Info Disclosure, Path Traversal, Backup, Debug, SSRF, Subdomain Takeover, CT Logs, TLS)
│   │   ├── ddos.go                # Phase 9: DDoS (Slowloris, HTTP Flood, Amplification, Connection Exhaustion, R.U.D.Y.)
│   │   ├── fuzz.go                # Phase 10: Fuzzing (Param, Header, Method, Content-Type, Boundary, Encoding)
│   │   └── payloads.go            # All attack payloads
│   ├── knowledge/                 # Knowledge base + skills engine
│   │   ├── knowledge.go           # KB management
│   │   ├── profile.go             # Tech profile tracking
│   │   └── skills.go              # Learning skills
│   ├── browser/                   # Rod headless browser
│   │   └── browser.go
│   ├── report/                    # PDF generation
│   │   └── pdf.go                 # gofpdf-based reports
│   ├── config/                    # Config management
│   │   └── config.go              # Hot-reload config
│   └── api/                       # Dashboard + REST API
│       └── server.go              # Go net/http + gorilla/mux
├── web/                           # Frontend
│   ├── templates/                 # HTML templates
│   │   ├── dashboard.html
│   │   ├── scan.html
│   │   ├── reports.html
│   │   ├── config.html
│   │   └── skills.html
│   └── static/                    # CSS, JS
│       ├── css/style.css
│       └── js/
│           ├── dashboard.js
│           ├── scan.js
│           ├── reports.js
│           ├── config.js
│           └── skills.js
├── data/                          # Knowledge base data (per target)
│   └── {target_id}/
│       ├── endpoints.json
│       ├── parameters.json
│       ├── techniques.json
│       ├── payloads_used.json
│       ├── profile.json
│       ├── skills.json
│       ├── vuln_history.json
│       └── improvements.json
├── reports/                       # Generated PDF reports
├── Dockerfile                     # Multi-stage Docker build
├── docker-compose.yml
├── Makefile                       # Build, cross-compile, Docker
├── config.json                    # Default configuration
├── go.mod
└── go.sum
```

---

## 🔨 Cross-Compilation

```bash
# All platforms
make build-all

# Per platform
make build-linux       # Linux AMD64
make build-mac-intel   # macOS Intel
make build-mac-arm     # macOS Apple Silicon (M1/M2/M3)
make build-windows     # Windows AMD64 (.exe)
```

Binary output: ~11MB per platform (stripped).

---

## 🐳 Docker

```bash
# Build and run
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down

# Rebuild after code changes
docker-compose up -d --build
```

Volumes:
- `./config:/app/config` — Configuration
- `./data:/app/data` — Knowledge base
- `./reports:/app/reports` — PDF reports

---

## 🔐 Authentication Setup (Login / Token)

Many targets require authentication before they can be scanned. Red Team Agent supports 4 auth methods.

---

### Method 1: Form Login (Username + Password)

For applications that use a regular login form (POST username & password).

**Via `config.json`:**

```json
{
  "targets": [{
    "id": "my-app",
    "name": "My App",
    "url": "https://myapp.example.com",
    "auth": {
      "method": "form",
      "username": "admin",
      "password": "mysecretpassword",
      "login_url": "https://myapp.example.com/login",
      "login_selectors": {
        "username": "input[name='email']",
        "password": "input[name='password']",
        "submit": "button[type='submit']"
      }
    }
  }]
}
```

**Field explanation:**

| Field | Required | Description |
|-------|-------|----------|
| `method` | ✅ | Set to `"form"` |
| `username` | ✅ | Username/email for login |
| `password` | ✅ | Account password |
| `login_url` | ✅ | Full URL of the login page |
| `login_selectors` | ⬜ | CSS selectors for the form elements (for headless browser login) |

**How it works:**
1. The agent opens `login_url` using the headless browser
2. Fills the form using the selectors (or default input fields)
3. Submits and stores the session cookie
4. All subsequent requests use that cookie

---

### Method 2: Bearer Token (API Key / JWT)

For APIs that use a token in the `Authorization` header.

**Via `config.json`:**

```json
{
  "targets": [{
    "id": "my-api",
    "name": "My API",
    "url": "https://api.example.com",
    "auth": {
      "method": "token",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0..."
    }
  }]
}
```

**How it works:**
- Every request the agent sends will include the header:
  ```
  Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
  ```

**Tips:**
- You can use a JWT token, API key, or anything placed in the `Authorization` header
- If the API uses a custom header (e.g. `X-API-Key`), use the token as well — the agent will detect its format

---

### Method 3: HTTP Basic Auth

For servers/APIs that use standard HTTP Basic Authentication.

**Via `config.json`:**

```json
{
  "targets": [{
    "id": "staging-api",
    "name": "Staging API",
    "url": "https://staging.example.com",
    "auth": {
      "method": "basic",
      "username": "admin",
      "password": "staging123"
    }
  }]
}
```

**How it works:**
- The agent encodes `username:password` to Base64
- Every request includes the header: `Authorization: Basic YWRtaW46c3RhZ2luZzEyMw==`

---

### Method 4: No Authentication

For public targets that don't require login.

```json
{
  "targets": [{
    "id": "public-site",
    "name": "Public Website",
    "url": "https://example.com",
    "auth": {
      "method": "none"
    }
  }]
```

Phase 3 (Authentication Testing) is skipped automatically.

---

### Setup via Environment Variables

If you don't want to store credentials in `config.json` (e.g. for CI/CD or security):

```bash
# Format: RTA_TARGET_{ID}_USERNAME, RTA_TARGET_{ID}_PASSWORD, RTA_TARGET_{ID}_TOKEN
# ID is uppercased, non-alphanumeric replaced with underscore

# Example for target ID "my-app":
export RTA_TARGET_MY_APP_USERNAME=admin
export RTA_TARGET_MY_APP_PASSWORD=secret123
export RTA_TARGET_MY_APP_LOGIN_URL=/login

# Example for target ID "api-prod" using a token:
export RTA_TARGET_API_PROD_TOKEN=eyJhbGciOiJIUzI1NiIs...

# Overriding the URL also works:
export RTA_TARGET_MY_APP_URL=https://staging.example.com

# The agent auto-detects:
# - USERNAME present → method = "form"
# - TOKEN present → method = "token"

./red-team-agent --config config.json --data data
```

**All supported env vars:**

| Env Var | Example | Description |
|---------|--------|----------|
| `RTA_TARGET_{ID}_USERNAME` | `RTA_TARGET_MY_APP_USERNAME=admin` | Username for login |
| `RTA_TARGET_{ID}_PASSWORD` | `RTA_TARGET_MY_APP_PASSWORD=secret` | Password for login |
| `RTA_TARGET_{ID}_TOKEN` | `RTA_TARGET_API_PROD_TOKEN=eyJ...` | Bearer token / API key |
| `RTA_TARGET_{ID}_LOGIN_URL` | `RTA_TARGET_MY_APP_LOGIN_URL=/login` | Login URL path |
| `RTA_TARGET_{ID}_URL` | `RTA_TARGET_MY_APP_URL=https://...` | Override target URL |
| `RTA_TARGET_{ID}_ENABLED` | `RTA_TARGET_MY_APP_ENABLED=true` | Enable/disable target |
| `RTA_AGENT_PROXY` | `RTA_AGENT_PROXY=socks5://127.0.0.1:9050` | HTTP/SOCKS proxy |

---

### Setup via the Web Dashboard

1. Open **http://localhost:5555**
2. Go to the **Config** tab
3. Edit the target → set `auth.method`, `auth.username`, `auth.password`, or `auth.token`
4. Save — the config hot-reloads immediately, and the next scan uses the new credentials

---

### Full Example: Login Form + Scan

```json
{
  "targets": [
    {
      "id": "webapp-staging",
      "name": "WebApp Staging",
      "url": "https://staging.webapp.com",
      "enabled": true,
      "auth": {
        "method": "form",
        "username": "testadmin",
        "password": "TestAdmin@2024",
        "login_url": "https://staging.webapp.com/auth/login",
        "login_selectors": {
          "username": "#email",
          "password": "#password",
          "submit": "button.btn-login"
        }
      },
      "scope": {
        "include_paths": ["*"],
        "exclude_paths": ["/admin/delete", "/admin/drop"],
        "max_depth": 3,
        "rate_limit_rps": 3,
        "timeout": "15s",
        "slow_threshold_ms": 500
      },
      "tests": {
        "recon": true,
        "discovery": true,
        "auth": true,
        "authz": true,
        "injection": true,
        "logic": true,
        "client_side": true,
        "infra": true,
        "ddos": false,
        "fuzz": true
      }
    }
  ]
}
```

**Notes:**
- `exclude_paths` can be used to skip dangerous paths (e.g. delete/drop)
- `ddos: false` — disable DDoS simulation so staging doesn't go down
- `rate_limit_rps: 3` — slow down requests so things don't get out of hand

---

### Example: API with a Bearer Token

```json
{
  "targets": [
    {
      "id": "api-production",
      "name": "Production API",
      "url": "https://api.production.com",
      "enabled": true,
      "auth": {
        "method": "token",
        "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9..."
      },
      "scope": {
        "rate_limit_rps": 2,
        "timeout": "20s",
        "slow_threshold_ms": 500
      },
      "tests": {
        "recon": true,
        "discovery": true,
        "auth": false,
        "authz": true,
        "injection": true,
        "logic": true,
        "client_side": false,
        "infra": true,
        "ddos": false,
        "fuzz": false
      }
    }
  ]
}
```

**Notes:**
- `auth: false` — skip auth testing because a token is already used
- `client_side: false` — APIs usually have no UI
- `ddos: false`, `fuzz: false` — don't stress-test a production API
- `rate_limit_rps: 2` — be careful in production

---

### Example: Multiple Targets

```json
{
  "targets": [
    {
      "id": "frontend-prod",
      "name": "Frontend Production",
      "url": "https://www.example.com",
      "auth": { "method": "none" },
      "tests": { "ddos": false, "fuzz": false }
    },
    {
      "id": "api-staging",
      "name": "API Staging",
      "url": "https://staging-api.example.com",
      "auth": {
        "method": "token",
        "token": "stg_tok_abc123..."
      },
      "tests": { "client_side": false }
    },
    {
      "id": "admin-panel",
      "name": "Admin Panel",
      "url": "https://admin.example.com",
      "auth": {
        "method": "form",
        "username": "admin",
        "password": "admin123",
        "login_url": "https://admin.example.com/login"
      },
      "tests": { "ddos": false }
    },
    {
      "id": "internal-api",
      "name": "Internal API",
      "url": "http://192.168.1.50:8080",
      "auth": {
        "method": "basic",
        "username": "service_user",
        "password": "service_pass"
      }
    }
  ]
}
```

---

## ⚠️ Disclaimer

This tool is built for **authorized security testing**. Only use it on:

- Applications **you own**
- Applications you have **explicit permission** to test
- Approved **staging/testing** environments

**Unauthorized use is illegal.** This tool sends aggressive requests (injection payloads, fuzzing, DDoS simulation) that can disrupt production systems. Use it responsibly.

---

## 📊 Coverage Statistics

| Category | Count |
|----------|--------|
| **Attack Phases** | 10 |
| **Unique Techniques** | 80+ |
| **SQLi Payloads** | 27 |
| **XSS Payloads** | 26 |
| **CMD Injection Payloads** | 22 |
| **SSTI Payloads** | 14 |
| **SSRF Payloads** | 35+ |
| **Path Traversal Payloads** | 14 |
| **Fuzz Values** | 25+ |
| **API Patterns Tested** | 70+ |
| **Common Paths Brute-forced** | 50+ |
| **Default Credential Combos** | 14 |
| **Login Bypass Payloads** | 7 |
| **HTTP Bypass Headers** | 7 |
| **Race Condition Patterns** | 8+ |
| **DDoS Test Types** | 5 |
| **Fuzz Categories** | 6 |
