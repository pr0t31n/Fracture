<details>
<summary><strong>FULL DISCLOSURE</strong> — AI Development & Legal Notice</summary>

---

### AI Development Disclosure

This tool is part of the **pr0t31n toolkit**, a collection of security testing and penetration testing automation tools. The toolkit was created through AI-assisted development, guided by the professional experience and domain expertise of a cybersecurity consultant and penetration tester. Ya, I named it after myself - but to be fair, AI is horrible at naming things.

**The pr0t31n toolkit exists to serve two purposes:**

1. **Automate repetitive penetration testing workflow steps.** Security assessments involve significant amounts of repetitive, procedural work — running sequential tool chains, parsing outputs, correlating findings across tools, and managing engagement data. Automating these steps frees testers to focus on the work that requires human judgment: manual testing, creative attack paths, analysis, and reporting.

2. **Demonstrate the benefits and failures of AI-assisted development.** This toolkit is a real-world case study in building production security tooling with AI assistance. It demonstrates both what AI-assisted development can accomplish and where it falls short. The quality of AI-generated code varies significantly — between context refreshes, the output can range from senior/principal-level software engineering to the work of a still-in-school intern. This inconsistency is itself part of the demonstration.

In the interest of transparency, every tool in the pr0t31n toolkit carries this disclosure. The creator believes that AI-assisted development should be acknowledged openly, not concealed. Users, reviewers, and anyone examining this code should know how it was built so they can evaluate it accordingly.

---

### Legal & Authorization Notice

> **⚠ WARNING: AUTHORIZED USE ONLY**

This tool is designed and intended **exclusively** for use in **authorized security testing engagements**. "Authorized" means **all** of the following conditions are met:

- **Explicit Written Permission.** You possess explicit, documented, written authorization from the owner or authorized representative of the target system(s), network(s), or application(s) to conduct security testing. Verbal agreements are not sufficient.
- **Defined Scope.** The authorization clearly defines the scope of testing, including which systems, networks, IP ranges, applications, and/or endpoints are included. You must not exceed the boundaries of this defined scope under any circumstances.
- **Defined Timeframe.** The authorization specifies the dates and times during which testing is permitted. Testing outside the authorized window is unauthorized testing.
- **Rules of Engagement.** You are operating under a set of rules of engagement (RoE) or equivalent governing document that establishes acceptable testing methods, escalation procedures, emergency contacts, and any restrictions or exclusions.
- **Legal Compliance.** Your testing complies with all applicable local, state, national, and international laws and regulations, including but not limited to the Computer Fraud and Abuse Act (CFAA), the General Data Protection Regulation (GDPR), and equivalent legislation in your jurisdiction.

**Prohibited uses** include but are not limited to: unauthorized access to or testing of any system; testing against systems without explicit written authorization; any activity that violates applicable laws; use for malicious purposes including data theft, extortion, sabotage, or disruption of services; distribution intended to facilitate unauthorized access; and use without a clear legal basis.

**THIS TOOL IS PROVIDED "AS IS," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.**

The creator(s) and contributor(s) accept no responsibility or liability for any damage, loss, legal consequence, or other harm resulting from the use or misuse of this tool — including damage to systems or data, legal penalties or prosecution, loss of data or revenue, and any direct, indirect, incidental, special, consequential, or punitive damages.

**By using this tool, you acknowledge that you are solely responsible for ensuring that your use is authorized, lawful, and within the defined scope of your engagement. You assume all risk associated with the use of this tool.**

Security testing is a professional discipline with significant ethical and legal obligations. Users operating in a professional capacity are expected to adhere to the standards and codes of conduct established by recognized industry bodies, including PTES, OWASP, NIST, and any certifying body under which they hold credentials.

---

</details>

# Fracture

Web Application Penetration Testing Orchestrator — v2.12.0

Fracture is a Python CLI tool that performs comprehensive web application security assessments across all OWASP Top 10 2025 categories. It orchestrates a suite of open-source tools (gobuster, sqlmap, nuclei, dalfox, wpscan, sslscan, testssl.sh, nikto, ffuf, and more) alongside its own built-in probes, and integrates with the Crucible management platform for real-time monitoring and findings management.

**AI/ML Service Detection (v2.99.0):** During the vulnscan phase, Fracture detects AI/ML services via nuclei template tags (Ollama, vLLM, Gradio, Streamlit, MLflow, LiteLLM, TorchServe, Triton, and 25+ other AI platforms). Detected services generate an INFO finding and an `ai_discovered` action item recommending pAIn testing for LLM-specific vulnerabilities (prompt injection, data exfiltration, model abuse).

---


> **[View full documentation on the Codex Wiki](https://wiki.pr0t31n.com/tools/fracture)** — detailed features, CLI reference, findings catalogue, and integration guides.

## OWASP Top 10 2025 Coverage

| OWASP Category | Phases |
|---|---|
| A01 Broken Access Control | traversal, authorization, cross_user, bfla, access_matrix |
| A02 Cryptographic Failures | tls, files |
| A03 Injection | injection |
| A04 Insecure Design | crawl, csrf, business_logic |
| A05 Security Misconfiguration | recon, headers, files, graphql |
| A06 Vulnerable & Outdated Components | recon (wpscan/nuclei/nikto), vulnscan |
| A07 Identification & Authentication Failures | auth_bypass, session, account_lockout, logout |
| A08 Software & Data Integrity Failures | deserialization, files |
| A09 Security Logging & Monitoring Failures | logging_monitoring |
| A10 Server-Side Request Forgery | ssrf |

---

## Phase Table

| # | Phase | OWASP | Description |
|---|---|---|---|
| 0 | recon | A05, A06 | HTTP probe, technology fingerprinting, CDN/WAF detection, admin panel and sensitive path discovery, gobuster directory brute-force, wpscan, robots.txt, web screenshot |
| 0b | screenshot | A05 | Standalone web screenshot capture for discovered endpoints |
| 0c | webfiles | A05 | Static web file analysis |
| 1 | tls | A02 | sslscan, testssl.sh, weak cipher/protocol detection, certificate information findings |
| 1b | subdomain_takeover | A01 | Dangling CNAME detection, DNS AXFR zone transfer |
| 2 | headers | A05 | Security header inspection, CORS analysis, cookie flag analysis |
| 2b | shcheck | A05 | Secondary security header check |
| 3 | crawl | A04, A01 | Link, form, and JS extraction; secret/credential scanning in JS; login page detection |
| 3b | jwt | A07 | JWT identification, none-algorithm bypass, missing expiry |
| 3c | ffuf | A05 | Virtual host and hidden parameter fuzzing via ffuf |
| 4 | injection | A03 | SQLi (error-based, blind, time-based), XSS (reflected, stored, DOM), SSTI, CMDi, CRLF, XXE, SSRF via params, second-order SQLi, CSV/formula injection, log injection, HPP, deserialization probes, JSONP |
| 5 | traversal | A01 | Path traversal, LFI |
| 5b | business_logic | A04 | Workflow bypass, race conditions, TOCTOU, value tampering, mass assignment |
| 6 | ssrf | A10 | SSRF via URL parameters and cloud metadata endpoints |
| 7 | auth_bypass | A07 | Default credentials, SQLi login bypass, JWT none algorithm |
| 7b | account_lockout | A07 | Brute-force protection and account lockout validation |
| 8 | files | A02, A05 | Sensitive file exposure (.env, .git, config files, backups, debug logs) |
| 9 | vulnscan | A06 | Nuclei + Nikto vulnerability scanning, AI/ML service detection via nuclei AI tags |
| 10 | graphql | A05 | GraphQL endpoint detection, introspection, batch query attacks, field suggestion |
| 10b | logging_monitoring | A09 | Actuator/debug endpoint exposure, verbose error disclosure, metrics exposure |
| 11 | auth_recon | A01 | Authenticated endpoint enumeration (requires auth) |
| 12 | authorization | A01 | IDOR, privilege escalation, HTTP method tampering (requires auth) |
| 13 | session | A07 | Session entropy, fixation, timeout, concurrent sessions, logout invalidation (requires auth) |
| 14 | csrf | A04 | CSRF token presence and bypass validation (requires auth) |
| 15 | cross_user | A01 | Cross-user data leakage (requires auth + auth2) |
| 16 | open_redirect | A01 | Open redirect via URL parameters and headers |
| 17 | deserialization | A08 | Insecure deserialization — serialised object acceptance, YAML tag injection, error disclosure |
| 18 | file_upload_info | A08 | File upload endpoint detection (informational) |
| 19 | mass_assignment | A01 | Mass assignment / privilege escalation via parameter binding |
| 20 | access_matrix | A01 | Multi-credential access matrix testing (unauthenticated + each role) |
| 21 | bfla | A01 | Broken Function Level Authorization — cross-role endpoint replay |
| 22 | logout | A07 | Logoff detection, session timeout measurement, server-side session invalidation (requires auth) |

---

## Authentication Methods

Fracture supports 23 distinct authentication methods to reach authenticated scan phases:

| Method | Description |
|---|---|
| `form_login` | HTML form POST → session cookie (auto-detects CSRF token) |
| `basic` | HTTP Basic Auth (RFC 7617) |
| `digest` | HTTP Digest Auth (RFC 7616) |
| `ntlm` | NTLM / Windows Integrated Auth |
| `ntlm_v2` | NTLMv2 + Channel Binding Token |
| `bearer` / `token` | Bearer token in Authorization header |
| `jwt_bearer` | JWT Bearer with optional credential POST fallback |
| `session_cookie` | Pre-captured cookie string |
| `token_login` | POST credentials → JSON token response |
| `oauth2_client_creds` | OAuth2 Client Credentials Grant (RFC 6749) |
| `oauth1a` | OAuth 1.0a three-legged flow |
| `saml_assertion` | SAML 2.0 Assertion POST |
| `oidc_token` | OpenID Connect id_token |
| `mtls` | Mutual TLS client certificate |
| `totp_mfa` | TOTP/HOTP second factor (time-based OTP) |
| `webauthn_probe` | WebAuthn probe header |
| `apikey_header` | API key in custom request header |
| `apikey_cookie` | API key in cookie |
| `header_creds` | Arbitrary custom credential headers |
| `proxy_header` | Trusted proxy header forwarding (X-Forwarded-User) |
| `kerberos` | Kerberos / SPNEGO |
| `kerberos_delegation` | Kerberos S4U2Proxy delegation |
| `auto` | Auto-detect: tries form_login → token_login → basic → digest → ntlm |

### Browser-Assisted Login

When automated authentication is not possible, Fracture opens a visible browser window for manual login and captures the resulting session cookies. Browser preference order:

```
Chrome → Brave → Chromium → Firefox → Iceweasel → LibreWolf → Waterfox → Pale Moon → Edge
```

Chrome is tried first because ChromeDriver's CDP interface allows richer network-level request recording. Firefox and compatible browsers are the fallback when Chrome or ChromeDriver is not available.

---

## Login Profile Store

Fracture maintains a persistent cross-project login profile store at:

```
/opt/pr0t31n/Fracture/login_profiles/
    index.json                       ← manifest of all stored profiles
    lp_<timestamp>_<hash>.json       ← individual profile files
```

### How it works

**On first encounter with an unknown login page:**

1. Fracture fingerprints the login page (input field count/types, form structure, framework hints)
2. Compares the fingerprint against all stored profiles in `index.json`
3. If no profile matches (confidence < 75%), Fracture opens a browser for manual login
4. The session is recorded — every click, field input, form submission, URL navigation, and (on Chrome) every network request with POST body
5. Fracture writes a human-readable recording file to the project output directory:

```
FRACTURE LOGIN SESSION RECORDING
Target: https://example.com/login
Browser: Chrome
Captured: 2026-05-01T14:32:01
---
STEP 001  NAVIGATE  https://example.com/login
STEP 002  CLICK     selector=#email  text=""
STEP 003  INPUT     selector=#email  value="admin@example.com"
STEP 004  CLICK     selector=#password  text=""
STEP 005  INPUT     selector=#password  value=[REDACTED]
STEP 006  CLICK     selector=button[type=submit]  text="Sign In"
STEP 007  SUBMIT    action="https://example.com/auth/login"  method=POST  fields=email,password,_token
STEP 008  REQUEST   POST  https://example.com/auth/login
            Content-Type: application/x-www-form-urlencoded
            Body: email=admin%40example.com&password=[REDACTED]&_token=abc123
STEP 009  NAVIGATE  https://example.com/dashboard
STEP 010  COOKIE    name=session  domain=example.com  httpOnly=True  secure=True

SESSION INDICATORS
  Login URL: https://example.com/login
  Submit URL: https://example.com/auth/login
  Submit method: POST
  Session cookies: session
  CSRF field: _token
  Success URL pattern: /dashboard
```

6. Fracture prompts: **"Save this login session as a reusable profile?"**
7. If confirmed, the session recording is parsed into a structured replay recipe and fingerprint, then saved to the profile store

**On subsequent encounters (matching profile found):**

1. Fracture fingerprints the new login page
2. Scores it against every stored profile — weighted on password field, hidden fields, input count, form method, and framework hints
3. If confidence ≥ 75%, the profile is replayed automatically:
   - Fracture GETs the login page to harvest a fresh CSRF token (if required)
   - POSTs credentials to the stored submit URL
   - Validates success by checking for the expected post-login URL pattern or session cookie
4. No browser window is opened

**Profile sharing with AuthProbe:**

AuthProbe reads `index.json` at the same path and runs the same fingerprint-match logic. When AuthProbe detects a matching profile it surfaces it in a new **LOGIN PROFILE MATCH** output section:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  LOGIN PROFILE MATCH
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✓  Profile ID:    lp_20260501_143201_a1b2c3
       Confidence:  91%
       Recorded on: https://example.com/login
       Created:     2026-05-01T14:32:01
       Description: POST application/x-www-form-urlencoded csrf=hidden_field carrier=session

  Fracture will replay this profile automatically.
```

Crucible surfaces the matched profile ID in the AuthProbe panel and pre-fills `fr_auth_login_profile_id` for the Fracture scan configuration.

---

## Prerequisites

**Python packages** (auto-installed on first run):
- requests >= 2.28.0
- colorama >= 0.4.6
- beautifulsoup4 >= 4.12.0
- selenium >= 4.6.0 (required for browser-assisted login and SPA crawling)

**System tools** (install via `python3 install.py` or manually):

| Tool | Purpose | Install |
|---|---|---|
| gobuster | Directory brute-forcing | `apt install gobuster` / `go install` |
| nikto | Web server scanning | `apt install nikto` |
| sqlmap | SQL injection | `apt install sqlmap` |
| nuclei | Vulnerability templates | `go install projectdiscovery/nuclei` |
| dalfox | XSS scanning | `go install hahwul/dalfox` |
| wpscan | WordPress scanning | `gem install wpscan` |
| sslscan | TLS enumeration | `apt install sslscan` |
| testssl.sh | TLS analysis | `git clone drwetter/testssl.sh` |
| tplmap | SSTI detection | `git clone epinna/tplmap` |
| ffuf | Virtual host / param fuzzing | `go install ffuf/v2` |
| chromedriver | Chrome browser automation | `apt install chromium-driver` / download from Google |
| geckodriver | Firefox browser automation (fallback) | `apt install firefox-geckodriver` / Mozilla releases |

---

## Installation

```bash
cd /opt/pr0t31n/Fracture

# Install all dependencies
python3 install.py

# Verify only (no changes)
python3 install.py --check

# Skip system packages (pip + wordlists only)
python3 install.py --skip-system
```

---

## Usage

### Unauthenticated scan

```bash
python3 fracture.py --url https://target.example.com --project ./output
```

### Fast scan (skip nuclei, sqlmap, slow tools)

```bash
python3 fracture.py --url https://target.example.com --fast
```

### Authenticated scan — form login (auto-detected)

```bash
python3 fracture.py \
  --url https://target.example.com \
  --username admin \
  --password secret \
  --auth-type form \
  --login-url https://target.example.com/login
```

### Authenticated scan — Bearer token

```bash
python3 fracture.py \
  --url https://target.example.com \
  --auth-token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Browser-assisted login (manual)

```bash
python3 fracture.py \
  --url https://target.example.com \
  --browser-auth

# Pin a specific chromedriver if not on PATH
python3 fracture.py \
  --url https://target.example.com \
  --browser-auth \
  --chromedriver /usr/local/bin/chromedriver
```

Chrome is attempted first. If Chrome or ChromeDriver is not found, Fracture automatically falls back to Firefox via geckodriver.

### Via settings file (Crucible mode)

```bash
python3 fracture.py --settings /path/to/settings.json
```

### Resume from checkpoint

```bash
python3 fracture.py --settings settings.json --resume
```

### List available phases

```bash
python3 fracture.py --list-phases
```

---

## CLI Flags

| Flag | Description |
|---|---|
| `--settings FILE` | Path to JSON settings file |
| `--url URL` | Target URL (inline mode) |
| `--project DIR` | Output directory |
| `--fast` | Skip slow phases (vulnscan, sqlmap) |
| `--resume` | Resume from checkpoint |
| `--no-injection` | Skip injection phase |
| `--no-vulnscan` | Skip nuclei vulnscan |
| `--no-ffuf` | Skip ffuf vhost and parameter fuzzing |
| `--no-auth` | Skip all authenticated phases |
| `--browser-auth` | Fall back to browser-assisted login |
| `--chromedriver PATH` | Path to chromedriver binary |
| `--list-phases` | Print phase table and exit |
| `--username USER` | Auth username |
| `--password PASS` | Auth password |
| `--auth-type TYPE` | Auth method (default: `form`) |
| `--login-url URL` | Login endpoint URL |
| `--auth-token TOKEN` | Bearer/API token |
| `--threads N` | Number of concurrent threads |
| `--timeout N` | Per-request timeout in seconds |
| `--no-cve-correlation` | Skip OSV CVE version correlation |

---

## Settings File Reference

```json
{
  "engagement": {
    "consultant": "Jane Smith",
    "client_name": "ACME Corporation",
    "client_short": "acme",
    "consultant_email": "jane@example.com",
    "start_date": "2026-05-01",
    "end_date": "2026-05-08"
  },
  "scan": {
    "project": "acme_webapp",
    "target_url": "https://app.acme.com",
    "target_urls": [],
    "wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt",
    "gobuster_wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
    "ffuf_vhost_wordlist": "/usr/share/seclists/Discovery/DNS/namelist.txt",
    "ffuf_param_wordlist": "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    "threads": 30,
    "timeout": 10,
    "follow_redirects": true,
    "user_agent": "Mozilla/5.0 (compatible; Fracture/2.12.0; Security Assessment)",
    "extra_headers": {},
    "proxy": "",
    "verify_ssl": false,
    "sqlmap_timeout": 300,
    "nuclei_timeout": 600,
    "crawl_depth": 3,
    "crawl_max_pages": 150,
    "wpscan_token": "",
    "phases": {
      "recon": true,
      "screenshot": true,
      "webfiles": true,
      "tls": true,
      "subdomain_takeover": false,
      "headers": true,
      "shcheck": false,
      "ffuf": false,
      "crawl": true,
      "jwt": true,
      "injection": true,
      "traversal": true,
      "business_logic": false,
      "ssrf": true,
      "auth_bypass": true,
      "files": true,
      "vulnscan": true,
      "graphql": false,
      "logging_monitoring": false,
      "account_lockout": false,
      "auth_recon": false,
      "authorization": false,
      "session": false,
      "csrf": false,
      "cross_user": false,
      "logout": false,
      "open_redirect": false,
      "deserialization": false,
      "file_upload_info": false,
      "mass_assignment": false,
      "access_matrix": false,
      "bfla": false
    },
    "auth": {
      "enabled": true,
      "method": "form_login",
      "username": "testuser",
      "password": "testpass",
      "domain": "",
      "auth_token": "",
      "token_type": "Bearer",
      "session_cookie": "",
      "login_url": "https://app.acme.com/login",
      "login_mode": "fields",
      "login_data": "{}",
      "login_content_type": "application/x-www-form-urlencoded",
      "login_username_field": "username",
      "login_password_field": "password",
      "login_token_path": "token",
      "oauth_token_url": "",
      "oauth_client_id": "",
      "oauth_client_secret": "",
      "oauth_scope": "",
      "client_auth_method": "body",
      "oauth1_consumer_key": "",
      "oauth1_consumer_secret": "",
      "oauth1_access_token": "",
      "oauth1_token_secret": "",
      "saml_acs_url": "",
      "saml_assertion": "",
      "saml_relay_state": "",
      "oidc_id_token": "",
      "oidc_userinfo_url": "",
      "mtls_cert": "",
      "mtls_key": "",
      "mtls_ca_bundle": "",
      "totp_secret": "",
      "totp_mfa_url": "",
      "totp_field": "otp",
      "webauthn_probe_url": "",
      "api_key": "",
      "api_key_header": "X-API-Key",
      "api_key_cookie": "api_key",
      "custom_headers": {},
      "kerberos_impersonate": "",
      "proxy_header_name": "X-Remote-User",
      "proxy_header_value": "",
      "login_profile_id": ""
    },
    "auth2": {
      "enabled": false,
      "method": "form_login",
      "username": "",
      "password": ""
    },
    "auth_matrix": []
  }
}
```

### `scan.auth.login_profile_id`

Controls how the login profile store is used:

| Value | Behaviour |
|---|---|
| `""` (empty) | Auto-detect: fingerprint the login page and replay the best matching profile if confidence ≥ 75% |
| `"lp_20260501_143201_a1b2c3"` | Pin a specific profile ID — skips fingerprinting and replays this profile directly |
| `"none"` | Disable profile replay — always open a browser for manual login |

---

## Output Directory Structure

```
<project>/
├── recon/
├── tls/
├── headers/
├── crawl/
├── injection/
├── traversal/
├── ssrf/
├── auth_bypass/
├── files/
├── vulnscan/
├── graphql/
├── auth_recon/
├── authorization/
├── session/
├── csrf/
├── cross_user/
├── logout/
├── login_recording_<timestamp>.txt   ← browser session recording (when browser-auth used)
├── scan.log
├── scan.log.json
├── errors.log
├── findings.json
├── findings.csv
├── checkpoint.json
├── summary.json
└── target_profile.json
```

### Login Recording Files

When browser-assisted login is used, a `login_recording_<timestamp>.txt` file is written to the project directory. This file documents the complete manual login session (clicks, inputs, form submissions, POST requests, cookies) and is the source used to parse and store a new login profile. Passwords are always redacted as `[REDACTED]`.

---

## Findings Format

Each entry in `findings.json`:

```json
{
  "title": "SQL Injection (Error-Based)",
  "datetime": "2026-05-01 14:23:07",
  "ip": "https://app.acme.com/search?q=test",
  "port": 443,
  "hostname": "app.acme.com",
  "risk": "CRITICAL",
  "command": "",
  "description": "SQL injection detected in parameter 'q'...",
  "output": "Parameter: q\nURL: https://...",
  "cves": "",
  "sources": "fracture-injection",
  "service": "https",
  "output_file": "",
  "affected": "https://app.acme.com/search?q=test",
  "exploitdb": false,
  "metasploit": false,
  "exploit_details": [],
  "owasp": "A03:2025 Injection",
  "nist": "SI-10",
  "remediation": "Use parameterised queries throughout the application."
}
```

Risk levels: `CRITICAL` | `HIGH` | `MEDIUM` | `LOW` | `INFO`

---

## Crucible Integration

Fracture is designed to run under Crucible as a managed subprocess. When `CRUCIBLE_MANAGED=1` is set:

- All log output is emitted as `__CRUCIBLE_LOG__:<json>` tokens on stdout
- Errors are emitted as `__CRUCIBLE_ERR__:<json>` tokens on stderr
- Phase status is emitted as `__CRUCIBLE_STATUS__:<json>` tokens on stdout
- Interactive prompts (including browser-auth and profile-save prompts) are emitted as `__CRUCIBLE_PROMPT__:<json>` tokens on stdout
- Dependencies are auto-installed without user prompting

Crucible reads these tokens and routes them to the appropriate UI channels. The AuthProbe panel in Crucible surfaces any matched login profile ID and pre-fills the `fr_auth_login_profile_id` field so the next Fracture run can replay it automatically.

---

## Login Profile Store — Technical Reference

**Location:** `/opt/pr0t31n/Fracture/login_profiles/`

**Index file** (`index.json`) — array of lightweight entries:
```json
[
  {
    "id": "lp_20260501_143201_a1b2c3",
    "file": "lp_20260501_143201_a1b2c3.json",
    "created": "2026-05-01T14:32:01",
    "target_url": "https://example.com/login",
    "description": "POST application/x-www-form-urlencoded csrf=hidden_field carrier=session",
    "fingerprint": {
      "input_count": 3,
      "has_password_field": true,
      "has_hidden_fields": true,
      "hidden_field_count": 1,
      "form_action_path": "/auth/login",
      "form_action_depth": 2,
      "form_method": "POST",
      "login_path": "login",
      "framework_hints": ["laravel"]
    }
  }
]
```

**Profile file** (`lp_<id>.json`) — full recipe + fingerprint:
```json
{
  "id": "lp_20260501_143201_a1b2c3",
  "created": "2026-05-01T14:32:01",
  "target_url": "https://example.com/login",
  "browser_used": "Chrome",
  "fingerprint": { ... },
  "recipe": {
    "login_path": "/login",
    "submit_url": "https://example.com/auth/login",
    "submit_method": "POST",
    "content_type": "application/x-www-form-urlencoded",
    "credential_fields": {
      "email": "#email",
      "password": "#password"
    },
    "csrf_strategy": "hidden_field",
    "csrf_field": "_token",
    "success_indicator": {
      "type": "url_pattern",
      "pattern": "/dashboard"
    },
    "session_carriers": ["session"]
  }
}
```

**Fingerprint matching weights:**

| Feature | Weight |
|---|---|
| Password field present | 3.0 |
| Hidden fields present | 2.0 |
| Input count (exact / ±1) | 2.0 / 1.0 |
| Framework hints overlap | 2.0 |
| Form method | 1.0 |
| Form action depth | 1.0 |
| Login path match | 1.0 |

Confidence threshold for automatic replay: **75%**

---

## Legal Disclaimer

Fracture is provided for authorised security testing only. You must have explicit written permission from the system owner before running any scans. Unauthorised use against systems you do not own or have permission to test is illegal and unethical. The authors assume no liability for misuse.
