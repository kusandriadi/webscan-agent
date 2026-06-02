# 🔴 Red Team Agent v2.0

Automated web application red teaming platform dengan headless browser, 10-phase security testing, smart learning engine, dan PDF reporting. Ditulis dalam **Go**.

---

## 📋 Daftar Isi

- [Quick Start](#-quick-start)
- [Arsitektur](#-arsitektur)
- [Cara Menjalankan](#-cara-menjalankan)
- [Konfigurasi](#-konfigurasi)
- [Setup Autentikasi (Login / Token)](#-cara-setup-autentikasi-login--token)
- [10-Phase Testing — Detail Teknik](#-10-phase-testing--detail-teknik)
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
- [Dashboard Web](#-dashboard-web)
- [Project Structure](#-project-structure)
- [Cross-Compilation](#-cross-compilation)
- [Docker](#-docker)
- [Disclaimer](#-disclaimer)

---

## 🚀 Quick Start

```bash
# Clone dan masuk direktori
cd red-team-agent

# Build binary
make build

# Jalankan dengan config default
./red-team-agent --config config.json --data data

# Atau development mode (tanpa build)
make dev
```

Dashboard bisa diakses di: **http://localhost:5555**

---

## 🏗 Arsitektur

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

**Agent Loop** berjalan secara continuous:
1. **Plan** — Bikin rencana scan berdasarkan knowledge base
2. **Scan** — Eksekusi 10 phase testing ( Recon → Discovery → Auth → Authz → Injection → Logic → Client-Side → Infra → DDoS → Fuzz)
3. **Analyze** — Kumpulkan findings, endpoints, parameters
4. **Learn** — Record teknik yang berhasil/gagal ke knowledge base
5. **Report** — Generate PDF report
6. **Repeat** — Iterasi berikutnya lebih pintar

---

## 🏃 Cara Menjalankan

### 1. Build dari Source

```bash
# Pastikan Go 1.21+ terinstal
go version

# Build binary
make build

# Jalankan
./red-team-agent --config config.json --data data
```

### 2. Development Mode

```bash
# Langsung run tanpa build
make dev

# Atau manual
go run ./cmd/agent/ --config config.json --data data
```

### 3. Docker

```bash
# Build dan jalankan container
docker-compose up -d

# Lihat logs
docker-compose logs -f

# Stop
docker-compose down
```

### 4. Custom Port/Host

```bash
# Ganti port dan host via CLI flags
./red-team-agent --config config.json --data data --port 8080 --host 127.0.0.1

# Atau edit config.json bagian "dashboard"
```

### 5. Cross-Platform Binary

```bash
# Build semua platform sekaligus
make build-all

# Atau build per platform
make build-linux      # Linux AMD64
make build-mac-intel  # macOS Intel
make build-mac-arm    # macOS Apple Silicon
make build-windows    # Windows AMD64
```

### 6. Via API

```bash
# Start scan untuk target tertentu
curl -X POST http://localhost:5555/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"target_id": "example"}'

# Cek progress
curl http://localhost:5555/api/scan/progress

# Download report
curl -O http://localhost:5555/api/reports/download/redteam_example_2026-06-02.pdf
```

---

## ⚙️ Konfigurasi

Edit `config.json` atau pakai dashboard web:

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

**Field penting:**
| Field | Deskripsi |
|-------|-----------|
| `auth.method` | `none`, `form`, `token`, `basic` |
| `scope.rate_limit_rps` | Max requests per detik (default: 5) |
| `scope.timeout` | HTTP timeout per request |
| `scope.slow_threshold_ms` | Flag response sebagai `minor` jika di atas threshold ini (default: `500` ms, set `0` untuk disable) |
| `tests.*` | Enable/disable per phase |
| `schedule.cron` | Cron expression untuk auto-scan |
| `agent.proxy` | HTTP proxy (opsional) |

---

## 🔍 10-Phase Testing — Detail Teknik

### Phase 1: Reconnaissance

**Tujuan:** Mengumpulkan informasi sebanyak mungkin tentang target sebelum melakukan serangan.

| Teknik | Detail |
|--------|--------|
| **HTTP Fingerprinting** | Analisis response headers (`Server`, `X-Powered-By`) untuk identifikasi web server dan teknologi |
| **Framework Detection via Cookies** | Deteksi framework dari nama cookie: `PHPSESSID` → PHP, `JSESSIONID` → Java, `laravel_session` → Laravel, `rack.session` → Rails, `ASP.NET_SessionId` → ASP.NET |
| **robots.txt Analysis** | Parse `robots.txt` untuk menemukan path tersembunyi (Disallow/Allow entries) |
| **sitemap.xml Parsing** | Extract semua URL dari `sitemap.xml` |
| **TLS/SSL Check** | Verifikasi apakah HTTPS digunakan; jika tidak → medium finding |
| **JavaScript File Analysis** | Scan file JS umum (`/static/js/app.js`, `/js/main.js`, dll) untuk cari: API key, secret, password, token, authorization references |
| **Error Page Analysis** | Kirim request ke page yang tidak ada, cek apakah error page membocorkan info: stack trace, exception, debug mode, server software (Apache/Nginx/IIS) |

**Key Findings:**
- `info-disclosure` — Sensitive data in JS files
- `info-disclosure` — Tech stack leaked in error pages
- `No TLS` — Target tanpa HTTPS

---

### Phase 2: Discovery

**Tujuan:** Menemukan endpoint, parameter, dan entry point serangan sebanyak mungkin.

| Teknik | Detail |
|--------|--------|
| **Directory/File Brute Force** | Cek 50+ path umum: `/admin`, `/.env`, `/.git/config`, `/swagger.json`, `/phpmyadmin`, `/backup.sql`, dll. Flag severity berdasarkan sensitivitas |
| **API Endpoint Discovery** | Scan pola API: `/api`, `/api/v1`, `/api/v2`, `/rest`, `/graphql` |
| **Deep REST API Discovery** | Test 70+ REST API patterns: `/api/v1/users`, `/api/v1/posts`, `/api/v1/admin`, termasuk auth endpoints dan OAuth paths |
| **Parameter Discovery** | Identifikasi parameter query umum: `id`, `page`, `search`, `file`, `path`, `url`, `redirect`, `callback`, dll |
| **Source Code Comment Analysis** | Parse HTML comments, cari keyword sensitif: `password`, `secret`, `api`, `key`, `token`, `admin`, `debug`, `todo`, `fixme`, `hack`, `temp` |
| **HTTP Method Fuzzing** | Test GET, POST, PUT, DELETE, PATCH, OPTIONS pada discovered endpoints. Cek `Allow` header dari OPTIONS |
| **JavaScript Endpoint Extraction** | Parse `<script>` tags, fetch JS files, extract endpoint dari: `fetch()`, `axios.get/post()`, `XMLHttpRequest`, string URL patterns |
| **Form Discovery** | Parse HTML forms, extract: action URL, method, input fields (termasuk textarea dan select). Deteksi **missing CSRF token** pada POST forms |
| **GraphQL Introspection** | Kirim introspection query ke `/graphql`, `/graphiql`, `/api/graphql`, `/query`, `/v1/graphql`. Jika `__schema` terexpose → finding |

**Key Findings:**
- `sensitive-file` — File sensitif bisa diakses publik
- `api-docs` — Swagger/OpenAPI documentation exposed
- `http-methods` — Terlalu banyak HTTP methods diterima
- `csrf-missing` — POST form tanpa CSRF token
- `graphql-introspection` — GraphQL schema terbuka

---

### Phase 3: Authentication

**Tujuan:** Menguji keamanan mekanisme authentication.

| Teknik | Detail |
|--------|--------|
| **Default Credential Testing** | Coba 14 kombinasi credential umum: `admin/admin`, `admin/password`, `root/root`, `admin/123456`, `guest/guest`, dll |
| **Login Bypass via SQLi** | 7 payload bypass: `admin'--`, `admin' OR '1'='1`, `' OR 1=1--`, `admin%00` (null byte), `admin\` (backslash), empty password |
| **JWT alg:none Attack** | Kirim JWT dengan algorithm `none` dan body `{"sub":"1","role":"admin"}` ke authenticated endpoints. Jika diterima → critical |
| **Password Reset User Enumeration** | Test reset password endpoints (`/forgot-password`, `/api/auth/forgot`), cek apakah response membocorkan apakah email ada atau tidak |
| **Session Fixation** | Set cookie `session=<fixed>` sebelum login, cek apakah session ID diganti setelah login berhasil |

**Key Findings:**
- `default-credentials` (Critical) — Default password masih berlaku
- `auth-bypass` (Critical) — Login bisa di-bypass via SQLi
- `jwt-alg-none` (Critical) — Server menerima JWT tanpa signature
- `user-enumeration` (Medium) — Password reset bocor info user
- `session-fixation` (High) — Session ID tidak diperbarui pasca-login

---

### Phase 4: Authorization

**Tujuan:** Menguji apakah access control diimplementasi dengan benar.

| Teknik | Detail |
|--------|--------|
| **Privilege Escalation** | Akses admin paths (`/admin`, `/admin/users`, `/api/admin`) tanpa authentication |
| **IDOR (Insecure Direct Object Reference)** | Test sequential IDs (`/api/users/1`, `/api/orders/1`) tanpa auth. Cek apakah response mengandung user data (email, name, password). Juga test dari knowledge base endpoints |
| **Missing Function-Level Access Control** | Kirim GET, POST, PUT, DELETE, PATCH ke sensitive endpoints (`/api/users`, `/api/config`) tanpa auth |
| **API Authorization Bypass via Headers** | 7 bypass teknik: `X-Forwarded-For: 127.0.0.1`, `X-Original-URL: /admin`, `X-Rewrite-URL: /admin`, `X-Custom-IP-Authorization: 127.0.0.1`, `X-Real-IP: 127.0.0.1`, `Content-Type: application/json`, `X-HTTP-Method-Override: GET` |

**Key Findings:**
- `privilege-escalation` (High) — Admin path bisa diakses tanpa auth
- `idor` (High) — Data user lain bisa diakses via sequential ID
- `missing-access-control` (High) — HTTP method sensitif diterima tanpa auth
- `authz-bypass` (High) — Bypass via spoofed headers

---

### Phase 5: Injection

**Tujuan:** Menguji semua jenis injection attack pada setiap parameter dan endpoint yang ditemukan.

#### SQL Injection (6 Variants)

| Tipe | Payload Contoh | Deteksi |
|------|---------------|---------|
| **Error-based** | `'`, `"`, `' OR '1'='1`, `' UNION SELECT NULL--` | SQL error patterns: `SQL syntax`, `mysql_fetch`, `ORA-01756`, `SQLSTATE`, `sqlite_` |
| **MySQL-specific** | `' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--` | MySQL error |
| **PostgreSQL-specific** | `' AND 1=CAST((SELECT version()) AS INT)--` | PG error |
| **Time-based** | `' AND SLEEP(5)--`, `1; WAITFOR DELAY '0:0:5'--` | Response > 4 detik |
| **Stacked Queries** | `'; SELECT SLEEP(5)--`, `'; WAITFOR DELAY '0:0:5'--` | Delay detected |
| **Boolean Blind** | `' AND 1=1--` vs `' AND 1=2--` | Response difference |

**21 SQL error patterns** dideteksi: `SQL syntax`, `mysql_fetch`, `ORA-01756`, `SQLSTATE`, `sqlite_`, `unclosed quotation mark`, dll.

#### XSS (Cross-Site Scripting)

| Tipe | Payload Contoh |
|------|---------------|
| **Basic** | `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>` |
| **Filter Bypass** | `<SCRIPT>`, `<ScRiPt>`, `<scr<script>ipt>`, `<svg/onload=alert(1)>` |
| **Event Handlers** | `" onmouseover="alert(1)`, `' onfocus='alert(1)` |
| **No Parentheses** | `<script>alert\`1\`</script>` |
| **Encoded** | `%3Cscript%3Ealert(1)%3C/script%3E` |
| **DOM-based** | `#<img src=x onerror=alert(1)>`, `javascript:void(alert(1))` |
| **Template Literal** | `${alert(1)}`, `{{constructor.constructor('return alert(1)')()}}` |

Deteksi: Payload reflected di response body.

#### Command Injection

| Tipe | Payload Contoh |
|------|---------------|
| **Unix** | `; id`, `\| id`, `` `id` ``, `$(id)`, `; cat /etc/passwd` |
| **Windows** | `& dir`, `\| dir`, `&& type C:\boot.ini` |
| **Newline** | `\nid`, `\r\nid`, `%0aid` |
| **Encoding Bypass** | `%3bid`, `%7cid` |
| **Direct Path** | `;/bin/id`, `` `/bin/id` ``, `$(/bin/id)` |

Deteksi: Output patterns — `uid=`, `gid=`, `root:`, `drwx`, `total `, `/bin/sh`.

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

Deteksi: Response mengandung `ldap`, `dn=`, `dc=`, `ou=`, `invalid dn`.

#### XXE (XML External Entity)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

5 XXE payload variants: file read (`/etc/passwd`, `C:\boot.ini`), SSRF via XXE, DTD-based.

Deteksi: Response mengandung `root:`, `/etc/passwd`, `<?xml`, `<!entity`.

#### CRLF Injection

Payload: `%0d%0aSet-Cookie:%20evil=injected`, `%0d%0aLocation:%20https://evil.com`

Deteksi: Injected header muncul di response.

#### SSRF (Server-Side Request Forgery)

| Kategori | Payload |
|----------|---------|
| **Internal IPs** | `http://127.0.0.1`, `http://localhost:22/80/443/3306/6379/27017`, `http://[::1]`, `http://0.0.0.0` |
| **IP Encoding Bypass** | `http://0x7f000001`, `http://0177.0.0.1`, `http://2130706433` |
| **Private Network** | `http://10.0.0.1`, `http://172.16.0.1`, `http://192.168.0.1/1.254` |
| **AWS Metadata** | `http://169.254.169.254/latest/meta-data/`, `iam/security-credentials/` |
| **GCP Metadata** | `http://metadata.google.internal/computeMetadata/v1/` |
| **Azure/Alibaba** | `http://169.254.169.254/metadata/instance`, `http://100.100.100.200/latest/meta-data/` |
| **File Protocol** | `file:///etc/passwd`, `file:///proc/self/environ` |
| **Gopher/Dict** | `gopher://127.0.0.1:6379/`, `dict://127.0.0.1:6379/INFO` |

Deteksi: Response mengandung `ami-id`, `instance-id`, `root:`, `<ListAllMyBucketsResult>`.

#### Prototype Pollution

| Via | Payload |
|-----|---------|
| **Query Params** | `__proto__[polluted]=yes`, `constructor[prototype][isAdmin]=true` |
| **JSON Body** | `{"__proto__": {"isAdmin": true}}`, `{"constructor": {"prototype": {"polluted": "yes"}}}` |

#### Host Header Injection

Payload: `evil.com`, `localhost`, `127.0.0.1`, `attacker.com`, `original-host.com\r\nX-Injected: true`

Cek: Reflected host in response, dan **password reset poisoning** via Host header.

#### HTTP Method Tampering

Test header `X-HTTP-Method-Override`, `X-Method-Override`, `X-HTTP-Method`, `_method` pada protected endpoints. Jika normal request → 401/403 tapi override → 200 → bypass.

#### Multi-Method Injection

Test SQLi dan XSS via **POST**, **PUT**, **PATCH** dengan:
- JSON body: `{"username": "' OR '1'='1"}`
- Form-urlencoded body: `username=' OR '1'='1`

---

### Phase 6: Logic & Business Flow

**Tujuan:** Menguji celah logika bisnis dan race condition.

| Teknik | Detail |
|--------|--------|
| **Rate Limit Bypass** | Kirim 20 login attempts cepat berturut-turut. Jika ≥15 berhasil tanpa block → finding |
| **Parameter Tampering** | Test parameter: `price=0.01`, `role=admin`, `isAdmin=true`, `admin=1`, `debug=true`, `access_level=99` |
| **Force Browsing** | Akses langsung: `/admin/delete-user`, `/admin/export`, `/api/internal`, `/api/debug`, `/actuator/shutdown` |
| **Race Condition** | Kirim 10-20 concurrent requests ke state-changing endpoints: coupon apply, transfer, withdraw, vote, like, checkout, referral, redeem. Jika >1 berhasil → race condition |
| **IDOR in API** | Test 17 API patterns × 6 IDs (`1`, `2`, `3`, `999`, `0`, `-1`) untuk users, orders, documents, messages |
| **HTTP Method Bypass** | Bandingkan response 7 HTTP methods pada protected paths. Jika ada method yang bypass 401/403 → finding |
| **Mass Assignment** | Inject extra fields di JSON body saat POST/PUT: `{"role": "admin"}`, `{"isAdmin": true}`, `{"plan": "premium"}`, `{"credit": 99999}`, `{"permissions": ["admin", "superadmin"]}` |

**Key Findings:**
- `rate-limit` — Login tanpa rate limiting
- `race-condition` — Endpoint bisa dipanggil bersamaan
- `idor-api` — Data user lain via API
- `mass-assignment` — Extra JSON fields diterima server

---

### Phase 7: Client-Side

**Tujuan:** Menguji keamanan sisi client (browser).

| Teknik | Detail |
|--------|--------|
| **CORS Misconfiguration** | Kirim OPTIONS dengan Origin: `https://evil.com`, `http://localhost`, `https://attacker.example.com`. Cek `Access-Control-Allow-Origin` dan `Access-Control-Allow-Credentials`. Jika ACAO = `*` atau = origin → finding. Jika + credentials → severity naik ke high |
| **Clickjacking** | Cek apakah `X-Frame-Options` atau CSP `frame-ancestors` ada. Jika tidak ada → page bisa di-iframe |
| **Open Redirect** | Test 8 redirect parameters (`redirect`, `url`, `next`, `return`, `goto`, `continue`, dll) × 3 payloads (`https://evil.com`, `//evil.com`, `/\evil.com`). Cek `Location` header |
| **CSP Analysis** | Cek `Content-Security-Policy` header. Jika missing → finding. Jika ada tapi mengandung `'unsafe-inline'` atau `'unsafe-eval'` → weak |
| **Client-Side Prototype Pollution** | Scan JS code untuk pattern berbahaya: deep merge tanpa `hasOwnProperty`, `_.merge`, `$.extend`, `Object.assign`, `__proto__` assignment, `constructor.prototype` |
| **postMessage Security** | Cek `addEventListener("message", ...)` tanpa `origin` validation. Cek `postMessage(..., '*')` yang bocor data ke window manapun |
| **DOM Clobbering** | Deteksi: `window.location` comparison, `document.getElementById` tanpa null check, `window.property` comparison |
| **DOM Sinks** | Deteksi 16 dangerous sinks: `innerHTML`, `outerHTML`, `document.write`, `eval()`, `setTimeout(string)`, `new Function()`, `insertAdjacentHTML`, `location=`, dll |

---

### Phase 8: Infrastructure

**Tujuan:** Menguji keamanan infrastruktur server.

| Teknik | Detail |
|--------|--------|
| **Security Headers Audit** | Cek 6 headers: `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Strict-Transport-Security`, `Referrer-Policy`, `Permissions-Policy`. Missing ≥4 → medium |
| **Cookie Security** | Audit session cookies untuk: `HttpOnly`, `Secure`, `SameSite` flags |
| **Information Disclosure** | Scan 20+ sensitive paths: `/.env`, `/.git/config`, `/.htaccess`, `/server-status`, `/phpinfo.php`, `/actuator/env`, `/swagger.json`, `/.DS_Store`, dll |
| **Path Traversal / LFI** | 14 payloads: `../../../etc/passwd`, `..\\..\\..\\boot.ini`, `..%2f..%2f`, `..%c0%af`, `/etc/passwd%00`, double-encoding variants |
| **Backup File Detection** | Cek 18 backup paths: `backup.sql`, `database.sql`, `.env.backup`, `.env.bak`, `backup.zip`, `dump.rdb`, dll |
| **Debug Mode Detection** | Cek 17 debug paths: `/debug`, `/trace`, `/_debugbar`, `/actuator/beans`, `/actuator/heapdump`, `/_profiler`, `/phpinfo.php` |
| **SSRF via URL Parameters** | Test SSRF payloads pada 28 URL-like parameters di 8 endpoint patterns |
| **Subdomain Takeover** | Resolve CNAME records, cek apakah point ke vulnerable services (CloudFront, S3, Heroku, GitHub Pages, Azure, dll). Verifikasi via response body indicators |
| **Certificate Transparency** | Query `crt.sh` untuk discover subdomains dari CT logs. Simpan sebagai endpoints untuk testing lanjutan |
| **HTTPS/TLS Misconfiguration** | Koneksi langsung ke TLS, cek: cert expired, self-signed, hostname mismatch, expiring <30 hari, weak signature (SHA1), TLS 1.0/1.1, missing HSTS |

**Key Findings:**
- `path-traversal` (Critical) — Bisa baca file sistem
- `backup-file` (High) — Backup file terekspos
- `subdomain-takeover` (High) — CNAME dangling
- `tls-cert-expired` (High) — Sertifikat kadaluarsa
- `debug-mode` (Medium) — Debug endpoint terekspos

---

### Phase 9: DDoS Simulation

**Tujuan:** Menguji ketahanan server terhadap serangan denial of service.

| Teknik | Detail |
|--------|--------|
| **Slowloris** | Buka 10 koneksi TCP, kirim partial HTTP headers pelan-pelan setiap 3 detik selama 15 detik. Jika ≥50% koneksi masih hidup → vulnerable |
| **HTTP Flood** | Kirim 100 concurrent requests (20 concurrency). Ukur: success rate, 5xx errors, timeouts, min/max/avg response time. Jika >5 5xx atau >20 timeout → high |
| **Amplification Check** | Test 3 jenis oversized request: URL 8KB, POST body 100KB, header value 8KB. Jika diterima tanpa error → server bisa di-abuse |
| **Connection Exhaustion** | Buka 50 concurrent TCP connections. Jika ≥45 berhasil → tidak ada connection rate limiting |
| **Slow POST (R.U.D.Y.)** | Kirim POST dengan `Content-Length: 10000` tapi deliver body 1 byte/detik. Jika ≥50% koneksi masih hidup setelah 10 detik → vulnerable |

**Key Findings:**
- `slowloris` — Server rentan terhadap Slowloris
- `http-flood-degradation` — Server degradasi under load
- `connection-exhaustion` — Tidak ada connection rate limit
- `slow-post` — R.U.D.Y. vulnerability

---

### Phase 10: Fuzzing Stress

**Tujuan:** Mengirim input abnormal untuk menemukan crash, unhandled errors, dan edge cases.

| Teknik | Detail |
|--------|--------|
| **Parameter Fuzzing** | Kirim 25 fuzz values ke 16 parameter umum di 5 endpoints. Values: long string (10K), format strings (`%s`, `%n`, `%x`), template injection (`{{7*7}}`, `${7*7}`), null bytes, SQLi, XSS, unicode flood (🐱), CRLF, path traversal, file URI, ldap/gopher URIs. Cap: 50 tests |
| **Header Fuzzing** | Fuzz 11 headers × 10 values: long value (8K), special chars, null byte, newline injection, format string, unicode flood, template injection, SSI, CRLF double |
| **Method Fuzzing** | Test 16 unusual methods: `TRACE`, `TRACK`, `CONNECT`, `PROPFIND`, `MKCOL`, `COPY`, `MOVE`, `LOCK`, `PURGE`, `LINK`, dll. **TRACE** special: jika reflects request → Cross-Site Tracing (XST) |
| **Content-Type Fuzzing** | Kirim POST dengan 13 content-type/body combos: oversized JSON, invalid JSON, deep JSON, XXE in XML, multipart, NoSQL injection (`$gt`, `$ne`, `$where`), prototype pollution, binary data |
| **Boundary Fuzzing** | 8 extreme payloads: 100KB JSON, empty body, deeply nested JSON (50 levels), binary garbage, partial JSON, array overflow (10K elements), unicode null JSON |
| **Encoding Fuzzing** | 13 encoded payloads: double-encoded (`%252e%252e`), URL-encoded XSS/SQLi, base64-encoded attacks, mixed unicode, overlong UTF-8 (`%c0%ae`), percent null/newline |

**Key Findings:**
- `param-fuzz-500` — Parameter fuzzed menyebabkan server error
- `unusual-method` — HTTP method tidak umum diterima
- `boundary-fuzz-timeout` — Server timeout on extreme payload
- `encoding-fuzz-reflection` — Server decode dan reflect payload berbahaya
- `slow-response` — Endpoint merespons di atas threshold (default: 500ms)

---

### ⏱ Slow Response Tracking (Otomatis di Semua Phase)

Selain 10 phase testing, agent otomatis mengecek response time **setiap HTTP request** yang dikirim. Jika response time melebihi threshold, akan dibuatkan finding `minor`.

**Konfigurasi:**

```json
{
  "scope": {
    "slow_threshold_ms": 500
  }
}
```

| Setting | Efek |
|---------|------|
| `500` (default) | Flag response yang > 500ms |
| `200` | Lebih sensitif, flag > 200ms |
| `1000` | Hanya flag response sangat lambat > 1 detik |
| `0` | Disable slow response tracking |

**Cara kerja:**
- Hook ke setiap `MakeRequest` via callback — tidak ada perubahan ke phase code
- Deduplikasi per URL (URL yang sama hanya dilaporkan sekali per scan)
- Finding otomatis masuk ke phase yang sedang berjalan
- Severity: `minor`
- Masuk ke PDF report dan knowledge base

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

Setiap iterasi, agent belajar dan meningkatkan serangan:

1. **Load** — Knowledge base: endpoints, parameters, past findings, tech stack, teknik yang berhasil/gagal
2. **Plan** — Buat rencana scan berdasarkan data: tech-specific payloads, skip teknik yang gagal, deep-dive di teknik yang berhasil
3. **Scan** — Eksekusi semua 10 phase
4. **Learn** — Record: findings baru, endpoints baru, techniques success/failure, payloads yang sudah dipakai
5. **Report** — Generate PDF
6. **Improve** — Iterasi berikutnya:
   - Skip payloads yang sudah ditest (deduplication)
   - Skip teknik yang selalu gagal di target ini
   - Deep-dive di teknik yang berhasil (misal: error-based SQLi → blind/time-based)
   - Tech-specific payloads (deteksi PHP → coba PHP-specific payloads)

**Contoh evolusi:**
```
Iterasi 1: Temukan error-based SQLi di parameter "id"
Iterasi 2: Coba blind/time-based SQLi di parameter yang sama + parameter lain
Iterasi 3: Coba WAF bypass techniques di SQLi yang sudah ditemukan
```

---

## 🌐 API Endpoints

| Method | Endpoint | Deskripsi |
|--------|----------|-----------|
| `POST` | `/api/scan/start` | Mulai scan (`{"target_id": "..."}`) |
| `GET` | `/api/scan/progress` | Progress scan saat ini |
| `GET` | `/api/scan/history` | Riwayat semua scan |
| `GET` | `/api/config` | Ambil konfigurasi |
| `PUT` | `/api/config` | Update konfigurasi (hot-reload) |
| `GET` | `/api/targets` | List semua target |
| `POST` | `/api/targets` | Tambah target baru |
| `PUT` | `/api/targets/{id}` | Update target |
| `DELETE` | `/api/targets/{id}` | Hapus target |
| `GET` | `/api/reports` | List semua report |
| `GET` | `/api/reports/download/{file}` | Download PDF report |
| `GET` | `/api/skills` | Learning overview |
| `POST` | `/api/skills/{id}/reset` | Reset knowledge base |

---

## 📊 Dashboard Web

Dashboard built-in di **http://localhost:5555** dengan halaman:

- **Dashboard** — Overview: active scans, findings summary, severity breakdown
- **Scan** — Start/monitor scan, real-time progress per phase
- **Reports** — List dan download PDF reports
- **Config** — Edit konfigurasi target dan agent
- **Skills** — Lihat learning progress, knowledge base, reset

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
# Semua platform
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
# Build dan jalankan
docker-compose up -d

# Lihat logs
docker-compose logs -f

# Stop
docker-compose down

# Rebuild setelah code changes
docker-compose up -d --build
```

Volumes:
- `./config:/app/config` — Konfigurasi
- `./data:/app/data` — Knowledge base
- `./reports:/app/reports` — PDF reports

---

## 🔐 Cara Setup Autentikasi (Login / Token)

Banyak target butuh autentikasi sebelum bisa di-scan. Red Team Agent support 4 metode auth.

---

### Metode 1: Form Login (Username + Password)

Untuk aplikasi yang pakai form login biasa (POST username & password).

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

**Penjelasan field:**

| Field | Wajib | Deskripsi |
|-------|-------|----------|
| `method` | ✅ | Set ke `"form"` |
| `username` | ✅ | Username/email untuk login |
| `password` | ✅ | Password akun |
| `login_url` | ✅ | URL lengkap halaman login |
| `login_selectors` | ⬜ | CSS selector untuk form elements (untuk headless browser login) |

**Cara kerja:**
1. Agent buka `login_url` pakai headless browser
2. Isi form pakai selectors (atau default input fields)
3. Submit dan simpan session cookie
4. Semua request selanjutnya pakai cookie tersebut

---

### Metode 2: Bearer Token (API Key / JWT)

Untuk API yang pakai token di header `Authorization`.

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

**Cara kerja:**
- Setiap request yang dikirim agent akan include header:
  ```
  Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
  ```

**Tips:**
- Bisa pakai JWT token, API key, atau apa saja yang dimasukkan ke `Authorization` header
- Jika API pakai custom header (misal `X-API-Key`), gunakan token juga — agent akan deteksi formatnya

---

### Metode 3: HTTP Basic Auth

Untuk server/api yang pakai standard HTTP Basic Authentication.

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

**Cara kerja:**
- Agent encode `username:password` ke Base64
- Setiap request include header: `Authorization: Basic YWRtaW46c3RhZ2luZzEyMw==`

---

### Metode 4: Tanpa Autentikasi

Untuk target publik yang tidak butuh login.

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

Phase 3 (Authentication Testing) akan diskip otomatis.

---

### Setup via Environment Variable

Kalo gak mau simpan credentials di `config.json` (misalnya untuk CI/CD atau security):

```bash
# Format: RTA_TARGET_{ID}_USERNAME, RTA_TARGET_{ID}_PASSWORD, RTA_TARGET_{ID}_TOKEN
# ID di-uppercase, non-alphanumeric diganti underscore

# Contoh untuk target ID "my-app":
export RTA_TARGET_MY_APP_USERNAME=admin
export RTA_TARGET_MY_APP_PASSWORD=secret123
export RTA_TARGET_MY_APP_LOGIN_URL=/login

# Contoh untuk target ID "api-prod" pakai token:
export RTA_TARGET_API_PROD_TOKEN=eyJhbGciOiJIUzI1NiIs...

# Override URL juga bisa:
export RTA_TARGET_MY_APP_URL=https://staging.example.com

# Agent otomatis deteksi:
# - Ada USERNAME → method = "form"
# - Ada TOKEN → method = "token"

./red-team-agent --config config.json --data data
```

**Semua env vars yang didukung:**

| Env Var | Contoh | Deskripsi |
|---------|--------|----------|
| `RTA_TARGET_{ID}_USERNAME` | `RTA_TARGET_MY_APP_USERNAME=admin` | Username untuk login |
| `RTA_TARGET_{ID}_PASSWORD` | `RTA_TARGET_MY_APP_PASSWORD=secret` | Password untuk login |
| `RTA_TARGET_{ID}_TOKEN` | `RTA_TARGET_API_PROD_TOKEN=eyJ...` | Bearer token / API key |
| `RTA_TARGET_{ID}_LOGIN_URL` | `RTA_TARGET_MY_APP_LOGIN_URL=/login` | Path login URL |
| `RTA_TARGET_{ID}_URL` | `RTA_TARGET_MY_APP_URL=https://...` | Override target URL |
| `RTA_TARGET_{ID}_ENABLED` | `RTA_TARGET_MY_APP_ENABLED=true` | Enable/disable target |
| `RTA_AGENT_PROXY` | `RTA_AGENT_PROXY=socks5://127.0.0.1:9050` | HTTP/SOCKS proxy |

---

### Setup via Dashboard Web

1. Buka **http://localhost:5555**
2. Pergi ke tab **Config**
3. Edit target → set `auth.method`, `auth.username`, `auth.password`, atau `auth.token`
4. Save — config langsung hot-reload, scan berikutnya pakai credentials baru

---

### Contoh Lengkap: Login Form + Scan

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

**Catatan:**
- `exclude_paths` bisa dipakai untuk skip path yang berbahaya (misal delete/drop)
- `ddos: false` — matiin DDoS simulation biar staging gak down
- `rate_limit_rps: 3` — perlambat request biar gak kebablasan

---

### Contoh: API dengan Bearer Token

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

**Catatan:**
- `auth: false` — skip auth testing karena udah pakai token
- `client_side: false` — API biasanya gak ada UI
- `ddos: false`, `fuzz: false` — jangan stress-test production API
- `rate_limit_rps: 2` — hati-hati di production

---

### Contoh: Multiple Targets

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

Tool ini dibuat untuk **security testing yang sah**. Hanya gunakan pada:

- Aplikasi yang **Anda miliki**
- Aplikasi yang Anda punya **izin eksplisit** untuk ditest
- Environment **staging/testing** yang disetujuh

**Penggunaan tanpa izin adalah ilegal.** Tool ini mengirimkan request agresif (injection payloads, fuzzing, DDoS simulation) yang bisa menyebabkan gangguan pada production systems. Gunakan dengan bertanggung jawab.

---

## 📊 Statistik Coverage

| Kategori | Jumlah |
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
