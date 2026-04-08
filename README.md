# Fracture

Web Application Penetration Testing Orchestrator — v1.0.0

Fracture is a Python CLI tool that performs comprehensive web application security assessments across all OWASP Top 10 2025 categories. It follows the same architecture as Scattershot3 (network recon), sharing VantageConsole protocol tokens, ProgressManager checkpointing, and OutputManager findings format for seamless Crucible integration.

---

## OWASP Top 10 2025 Coverage

| OWASP Category | Phases |
|---|---|
| A01 Broken Access Control | traversal, authorization, cross_user |
| A02 Cryptographic Failures | tls, files |
| A03 Injection | injection |
| A04 Insecure Design | crawl, csrf |
| A05 Security Misconfiguration | recon, headers, files, graphql |
| A06 Vulnerable & Outdated Components | recon (wpscan), vulnscan |
| A07 Identification & Authentication Failures | auth_bypass, session |
| A08 Software & Data Integrity Failures | (detected via files phase) |
| A09 Security Logging & Monitoring Failures | (out of scope for dynamic scanner) |
| A10 Server-Side Request Forgery | ssrf |

---

## Phase Table

| # | Phase | OWASP | Description |
|---|---|---|---|
| 0 | recon | A05, A06 | HTTP probe, fingerprinting, admin panel detection, gobuster/wpscan |
| 1 | tls | A02 | sslscan, testssl.sh, weak cipher/protocol detection |
| 2 | headers | A05 | Security header inspection, CORS, cookie flag analysis |
| 3 | crawl | A04, A01 | Link/form/JS extraction, secret scanning in JS files |
| 4 | injection | A03 | SQLi, XSS, SSTI, CMDi, CRLF, XXE |
| 5 | traversal | A01 | Path traversal, LFI |
| 6 | ssrf | A10 | SSRF via URL parameters, cloud metadata endpoints |
| 7 | auth_bypass | A07 | Default creds, SQLi login bypass, JWT none algorithm |
| 8 | files | A02, A05 | Sensitive file exposure (.env, .git, config files, backups) |
| 9 | vulnscan | A06 | Nuclei + Nikto vulnerability scanning |
| 10 | graphql | A05 | GraphQL endpoint detection, introspection, batch queries |
| 11 | auth_recon | A01 | Authenticated endpoint enumeration (requires auth) |
| 12 | authorization | A01 | IDOR, privilege escalation, HTTP method tampering (requires auth) |
| 13 | session | A07 | Session entropy, fixation, logout invalidation (requires auth) |
| 14 | csrf | A04 | CSRF token presence and validation (requires auth) |
| 15 | cross_user | A01 | Cross-user data leakage (requires auth + auth2) |

---

## Prerequisites

**Python packages** (auto-installed on first run):
- requests >= 2.28.0
- colorama >= 0.4.6
- beautifulsoup4 >= 4.12.0

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

---

## Installation

```bash
cd /Users/pr0t31n/Fracture

# Install dependencies
python3 install.py

# Or step by step
python3 install.py --skip-system  # skip apt/brew
python3 install.py --check        # verify only
```

---

## Usage Examples

### Unauthenticated scan (inline mode)

```bash
python3 fracture.py --url https://target.example.com --project ./output
```

### Fast scan (skip nuclei/sqlmap)

```bash
python3 fracture.py --url https://target.example.com --fast
```

### Authenticated scan — form login

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

### Via settings file (Crucible mode)

```bash
python3 fracture.py --settings /path/to/settings.json
```

### Resume from checkpoint

```bash
python3 fracture.py --settings settings.json --resume
```

### List phases

```bash
python3 fracture.py --list-phases
```

---

## Settings File Reference

```json
{
  "engagement": {
    "consultant": "Jane Smith",
    "client_name": "ACME Corporation",
    "client_short": "acme",
    "consultant_email": "jane@example.com",
    "start_date": "2026-04-08",
    "end_date": "2026-04-15"
  },
  "scan": {
    "project": "acme_webapp",
    "target_url": "https://app.acme.com",
    "target_urls": [],
    "wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt",
    "threads": 30,
    "timeout": 10,
    "follow_redirects": true,
    "user_agent": "Mozilla/5.0 (compatible; Fracture/1.0; Security Assessment)",
    "extra_headers": {},
    "proxy": "",
    "verify_ssl": false,
    "phases": {
      "recon": true,
      "tls": true,
      "headers": true,
      "crawl": true,
      "injection": true,
      "traversal": true,
      "ssrf": true,
      "auth_bypass": true,
      "files": true,
      "vulnscan": true,
      "graphql": false,
      "auth_recon": false,
      "authorization": false,
      "session": false,
      "csrf": false,
      "cross_user": false
    },
    "auth": {
      "enabled": true,
      "username": "testuser",
      "password": "testpass",
      "auth_type": "form",
      "login_url": "https://app.acme.com/login",
      "login_data": "",
      "auth_token": "",
      "token_type": "Bearer",
      "session_cookie": ""
    },
    "auth2": {
      "enabled": false,
      "username": "",
      "password": "",
      "auth_token": "",
      "session_cookie": ""
    },
    "sqlmap_timeout": 300,
    "nuclei_timeout": 600,
    "crawl_depth": 3,
    "crawl_max_pages": 150,
    "gobuster_wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
    "wpscan_token": ""
  }
}
```

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
├── scan.log
├── scan.log.json
├── errors.log
├── findings.json
├── findings.csv
├── checkpoint.json
└── summary.json
```

---

## Findings Format

Each finding in `findings.json`:

```json
{
  "title": "SQL Injection (Error-Based)",
  "datetime": "2026-04-08 14:23:07",
  "ip": "https://app.acme.com/search?q=test",
  "port": 443,
  "hostname": "app.acme.com",
  "risk": "CRITICAL",
  "command": "",
  "description": "SQL injection detected in parameter 'q' ...",
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

Fracture is designed to run under Crucible as a managed subprocess. When the environment variable `VANTAGE_MANAGED=1` is set:

- All log output is emitted as `__VANTAGE_LOG__:<json>` tokens on stdout
- Errors are emitted as `__VANTAGE_ERR__:<json>` tokens on stderr
- Phase status is emitted as `__VANTAGE_STATUS__:<json>` tokens on stdout
- Interactive prompts are emitted as `__VANTAGE_PROMPT__:<json>` tokens on stdout
- Dependencies are auto-installed without prompting

Crucible reads these tokens and routes them to the appropriate UI channels.

---

## Legal Disclaimer

Fracture is provided for authorised security testing only. You must have explicit written permission from the system owner before running any scans. Unauthorised use against systems you do not own or have permission to test is illegal and unethical. The authors assume no liability for misuse.
