#!/usr/bin/env python3
"""fingerprint_auth.py — MITM browser-based auth flow recorder for Fracture.

Opens a proxied browser, records the user's login sequence, and produces a
machine-readable auth fingerprint that Fracture can replay mechanically.

Usage (standalone):
    python3 fingerprint_auth.py --target-url https://example.com \\
                                --output-dir /path/to/project

Usage (Crucible-managed):
    CRUCIBLE_MANAGED=1 python3 fingerprint_auth.py --target-url ... --output-dir ...

The output is a fingerprint JSON file at <output-dir>/auth_fingerprint.json.
"""
import argparse
import json
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()

_MANAGED = os.environ.get("CRUCIBLE_MANAGED") == "1"


# ── Crucible token protocol ─────────────────────────────────────────────

def _emit(token: str, payload):
    if _MANAGED:
        print(f"__{token}__:{json.dumps(payload)}", flush=True)
    else:
        if token == "CRUCIBLE_LOG":
            lvl = payload.get("level", "INFO")
            msg = payload.get("message", "")
            print(f"[{lvl}] {msg}", flush=True)
        elif token == "CRUCIBLE_STATUS":
            print(f"[STATUS] {payload.get('phase', '')} — {payload.get('message', '')}", flush=True)


def _log(msg: str, level: str = "INFO"):
    _emit("CRUCIBLE_LOG", {"message": msg, "level": level, "ts": _now_iso()})


def _status(phase: str, msg: str, detail: str = ""):
    _emit("CRUCIBLE_STATUS", {
        "phase": phase, "message": msg, "detail": detail, "ts": _now_iso()})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ── SSO provider detection ───────────────────────────────────────────────

_SSO_PATTERNS = {
    "okta": {
        "url_indicators": [
            r"\.okta\.com",
            r"/api/v1/authn",
            r"/oauth2/.*/v1/authorize",
            r"okta-sign-in",
            r"/login/sessionCookieRedirect",
        ],
        "header_indicators": [],
        "body_indicators": [
            r"OktaSignIn", r"okta-signin-widget", r"okta-auth-js",
            r'"baseUrl"\s*:', r"oktaData",
        ],
    },
    "azure_ad": {
        "url_indicators": [
            r"login\.microsoftonline\.com",
            r"login\.microsoft\.com",
            r"/oauth2/v2\.0/authorize",
            r"/common/oauth2",
        ],
        "header_indicators": [],
        "body_indicators": [r"AADSTS", r"microsoftonline"],
    },
    "ping": {
        "url_indicators": [
            r"\.pingone\.com", r"\.pingidentity\.com",
            r"/as/authorization\.oauth2",
        ],
        "header_indicators": [],
        "body_indicators": [r"PingFederate", r"pingone"],
    },
    "auth0": {
        "url_indicators": [
            r"\.auth0\.com", r"/authorize\?.*client_id=",
        ],
        "header_indicators": [],
        "body_indicators": [r"auth0-lock", r"Auth0Lock"],
    },
    "keycloak": {
        "url_indicators": [
            r"/realms/.*/protocol/openid-connect",
            r"/auth/realms/",
        ],
        "header_indicators": [],
        "body_indicators": [r"kc-form-login", r"keycloak"],
    },
    "saml": {
        "url_indicators": [r"/saml2?/", r"/adfs/ls", r"SAMLRequest="],
        "header_indicators": [],
        "body_indicators": [
            r"SAMLResponse", r"saml2p:Response", r"samlp:AuthnRequest",
        ],
    },
    "cas": {
        "url_indicators": [r"/cas/login", r"service="],
        "header_indicators": [],
        "body_indicators": [r"cas-login", r"execution="],
    },
}

_CREDENTIAL_FIELD_NAMES = {
    "username": {"username", "user", "email", "login", "user_name",
                 "userName", "userid", "user_id", "account", "loginfmt",
                 "j_username", "uname", "usr"},
    "password": {"password", "pass", "passwd", "pwd", "secret",
                 "user_password", "userPassword", "j_password",
                 "credential", "passw"},
}

_LOGIN_URL_PATTERNS = re.compile(
    r"(?:^|[/?&])(?:login|signin|sign-in|logon|log-in|authenticate?|sso|"
    r"auth/redirect|login_okta|session/new)", re.I)


# ── mitmproxy addon script generator ────────────────────────────────────

_ADDON_TEMPLATE = r'''
"""mitmproxy addon for fingerprint_auth.py — records HTTP exchanges."""
import json, os, time, re
from mitmproxy import http

_SOCKET_PATH = "{socket_path}"
_SCOPE_HOSTS = {scope_hosts!r}
_EXCHANGE_FILE = "{exchange_file}"
_exchanges = []
_started = time.time()

def _in_scope(host: str) -> bool:
    if not _SCOPE_HOSTS:
        return True
    h = host.lower().rstrip(".")
    for s in _SCOPE_HOSTS:
        if h == s or h.endswith("." + s):
            return True
    return False

def _safe_headers(headers) -> dict:
    d = {{}}
    for k, v in headers.items():
        lk = k.lower()
        if lk in ("cookie", "set-cookie", "authorization"):
            d[k] = v[:200] + "..." if len(v) > 200 else v
        else:
            d[k] = v
    return d

def _extract_cookies(headers) -> list:
    cookies = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            parts = v.split(";")
            nv = parts[0].strip()
            eq = nv.find("=")
            if eq > 0:
                name = nv[:eq].strip()
                domain = ""
                for p in parts[1:]:
                    p = p.strip().lower()
                    if p.startswith("domain="):
                        domain = p[7:].strip()
                cookies.append({{"name": name, "domain": domain}})
    return cookies

class Recorder:
    def response(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        if not _in_scope(host):
            return
        req = flow.request
        resp = flow.response
        body_bytes = req.get_content(strict=False) or b""
        try:
            body_text = body_bytes.decode("utf-8", errors="replace")[:8192]
        except Exception:
            body_text = ""
        content_type = req.headers.get("content-type", "")
        # Parse form/json body for field names
        fields = {{}}
        if "json" in content_type:
            try:
                fields = json.loads(body_text)
                if not isinstance(fields, dict):
                    fields = {{}}
            except Exception:
                fields = {{}}
        elif "form" in content_type or "urlencoded" in content_type:
            for pair in body_text.split("&"):
                eq = pair.find("=")
                if eq > 0:
                    fields[pair[:eq]] = pair[eq+1:]

        entry = {{
            "ts": time.time() - _started,
            "request": {{
                "method": req.method,
                "url": req.pretty_url,
                "host": host,
                "path": req.path,
                "content_type": content_type,
                "fields": fields,
                "headers": _safe_headers(req.headers),
            }},
            "response": {{
                "status": resp.status_code,
                "headers": _safe_headers(resp.headers),
                "cookies_set": _extract_cookies(resp.headers),
                "location": resp.headers.get("location", ""),
                "body_size": len(resp.get_content(strict=False) or b""),
            }},
        }}
        _exchanges.append(entry)
        # Flush periodically
        if len(_exchanges) % 5 == 0:
            _flush()

    def done(self):
        _flush()

def _flush():
    try:
        with open(_EXCHANGE_FILE, "w") as f:
            json.dump(_exchanges, f)
    except Exception:
        pass

addons = [Recorder()]
'''


# ── Analysis engine ──────────────────────────────────────────────────────

class AuthFlowAnalyzer:
    """Analyzes recorded HTTP exchanges to identify the auth flow."""

    def __init__(self, exchanges: list, target_url: str):
        self.exchanges = exchanges
        self.target_url = target_url
        self.target_host = urlparse(target_url).hostname or ""
        self.sso_provider = None
        self.sso_base = ""
        self.credential_request = None
        self.login_initiation = None
        self.redirect_chain = []
        self.success_cookies = []
        self.all_hosts = set()
        self.auth_type = "unknown"

    def analyze(self) -> dict:
        self._catalog_hosts()
        self._detect_sso_provider()
        self._find_credential_submission()
        self._find_login_initiation()
        self._trace_redirect_chain()
        self._identify_success_cookies()
        self._classify_auth_type()
        return self._build_fingerprint()

    def _catalog_hosts(self):
        for ex in self.exchanges:
            h = ex["request"].get("host", "")
            if h:
                self.all_hosts.add(h.lower())

    def _detect_sso_provider(self):
        scores = {}
        for provider, patterns in _SSO_PATTERNS.items():
            score = 0
            base_candidates = []
            for ex in self.exchanges:
                url = ex["request"].get("url", "")
                for pat in patterns["url_indicators"]:
                    if re.search(pat, url, re.I):
                        score += 2
                        parsed = urlparse(url)
                        cand = f"{parsed.scheme}://{parsed.netloc}"
                        if cand not in base_candidates:
                            base_candidates.append(cand)
                resp_headers = ex["response"].get("headers", {})
                for pat in patterns["header_indicators"]:
                    for v in resp_headers.values():
                        if re.search(pat, v, re.I):
                            score += 1
            if score > 0:
                scores[provider] = (score, base_candidates)

        if scores:
            best = max(scores, key=lambda k: scores[k][0])
            if scores[best][0] >= 2:
                self.sso_provider = best
                candidates = scores[best][1]
                # Pick the base URL that isn't the target
                for c in candidates:
                    cp = urlparse(c).hostname or ""
                    if cp != self.target_host:
                        self.sso_base = c.rstrip("/")
                        break
                if not self.sso_base and candidates:
                    self.sso_base = candidates[0].rstrip("/")

    def _find_credential_submission(self):
        for ex in self.exchanges:
            req = ex["request"]
            if req["method"] != "POST":
                continue
            fields = req.get("fields", {})
            if not fields:
                continue
            field_names = {k.lower() for k in fields}
            has_user = bool(field_names & _CREDENTIAL_FIELD_NAMES["username"])
            has_pass = bool(field_names & _CREDENTIAL_FIELD_NAMES["password"])
            if has_user and has_pass:
                # Map field names
                user_field = ""
                pass_field = ""
                for k in fields:
                    if k.lower() in _CREDENTIAL_FIELD_NAMES["username"]:
                        user_field = k
                    if k.lower() in _CREDENTIAL_FIELD_NAMES["password"]:
                        pass_field = k
                extra = {}
                for k, v in fields.items():
                    if k.lower() not in (
                            _CREDENTIAL_FIELD_NAMES["username"]
                            | _CREDENTIAL_FIELD_NAMES["password"]):
                        if k.lower() not in ("remember", "rememberme",
                                              "remember_me", "options"):
                            extra[k] = v
                self.credential_request = {
                    "url": req["url"],
                    "method": "POST",
                    "content_type": req.get("content_type", ""),
                    "username_field": user_field,
                    "password_field": pass_field,
                    "extra_fields": extra,
                    "host": req.get("host", ""),
                    "path": req.get("path", ""),
                    "exchange_index": self.exchanges.index(ex),
                    "response_status": ex["response"]["status"],
                    "response_body_keys": list(fields.keys()) if ex["response"]["status"] == 200 else [],
                }
                break
        # OKTA authn API special case: username/password in JSON body
        if not self.credential_request and self.sso_provider == "okta":
            for ex in self.exchanges:
                req = ex["request"]
                if (req["method"] == "POST"
                        and "/api/v1/authn" in req.get("url", "")):
                    fields = req.get("fields", {})
                    self.credential_request = {
                        "url": req["url"],
                        "method": "POST",
                        "content_type": "application/json",
                        "username_field": "username",
                        "password_field": "password",
                        "extra_fields": {
                            k: v for k, v in fields.items()
                            if k not in ("username", "password")},
                        "host": req.get("host", ""),
                        "path": "/api/v1/authn",
                        "exchange_index": self.exchanges.index(ex),
                        "response_status": ex["response"]["status"],
                    }
                    break

    def _find_login_initiation(self):
        if not self.credential_request:
            return
        cred_idx = self.credential_request.get("exchange_index", 0)
        # Look backwards from credential submission for the first
        # request to the target that triggered SSO redirect
        for i in range(cred_idx - 1, -1, -1):
            ex = self.exchanges[i]
            req = ex["request"]
            resp = ex["response"]
            req_host = req.get("host", "").lower()
            # Login-initiation = request to TARGET host that redirects to SSO
            if req_host == self.target_host or self.target_host in req_host:
                status = resp.get("status", 0)
                location = resp.get("location", "")
                if status in (301, 302, 303, 307, 308) and location:
                    loc_host = urlparse(location).hostname or ""
                    if (loc_host != self.target_host
                            and (self.sso_base and self.sso_base.split("//", 1)[-1].split("/")[0] in loc_host
                                 or "/authorize" in location
                                 or "/oauth2/" in location
                                 or "/saml" in location.lower()
                                 or "/adfs/" in location.lower())):
                        self.login_initiation = {
                            "url": req["url"],
                            "method": req["method"],
                            "path": req.get("path", ""),
                            "redirect_to": location,
                            "exchange_index": i,
                        }
                        break
                # Also check for login-page URLs that match patterns
                if _LOGIN_URL_PATTERNS.search(req.get("path", "")):
                    if status in (200, 301, 302, 303, 307, 308):
                        self.login_initiation = {
                            "url": req["url"],
                            "method": req["method"],
                            "path": req.get("path", ""),
                            "redirect_to": location if status in (301, 302, 303, 307, 308) else "",
                            "exchange_index": i,
                        }
                        # Don't break — keep looking for a better SSO redirect

    def _trace_redirect_chain(self):
        if not self.credential_request:
            return
        cred_idx = self.credential_request.get("exchange_index", 0)
        chain = []
        for ex in self.exchanges[cred_idx:]:
            resp = ex["response"]
            chain.append({
                "url": ex["request"]["url"],
                "method": ex["request"]["method"],
                "status": resp["status"],
                "location": resp.get("location", ""),
                "cookies_set": [c["name"] for c in resp.get("cookies_set", [])],
            })
            # Stop at the first non-redirect after credential submission
            if (resp["status"] not in (301, 302, 303, 307, 308)
                    and len(chain) > 1):
                break
        self.redirect_chain = chain

    def _identify_success_cookies(self):
        if not self.credential_request:
            return
        cred_idx = self.credential_request.get("exchange_index", 0)
        cookies = {}
        for ex in self.exchanges[cred_idx:]:
            for ck in ex["response"].get("cookies_set", []):
                name = ck["name"]
                domain = ck.get("domain", "")
                if name not in cookies:
                    cookies[name] = domain
        self.success_cookies = [
            {"name": n, "domain": d} for n, d in cookies.items()]

    def _classify_auth_type(self):
        if self.sso_provider == "okta":
            has_authn = any(
                "/api/v1/authn" in ex["request"].get("url", "")
                for ex in self.exchanges)
            has_authorize = any(
                "/authorize" in ex["request"].get("url", "")
                for ex in self.exchanges)
            if has_authn and has_authorize:
                self.auth_type = "okta_oauth2"
            elif has_authn:
                self.auth_type = "okta_authn"
            else:
                self.auth_type = "okta_widget"
        elif self.sso_provider == "azure_ad":
            self.auth_type = "azure_ad_oauth2"
        elif self.sso_provider == "saml":
            self.auth_type = "saml"
        elif self.sso_provider:
            self.auth_type = f"{self.sso_provider}_sso"
        elif self.credential_request:
            ct = self.credential_request.get("content_type", "")
            if "json" in ct:
                self.auth_type = "json_api"
            else:
                self.auth_type = "form_post"
        else:
            self.auth_type = "unknown"

    def _build_fingerprint(self) -> dict:
        fp = {
            "schema_version": "1.0",
            "tool": "fingerprint_auth",
            "tool_version": VERSION,
            "created": _now_iso(),
            "target_url": self.target_url,
            "auth_type": self.auth_type,
            "hosts_observed": sorted(self.all_hosts),
            "total_exchanges": len(self.exchanges),
        }
        if self.sso_provider:
            is_custom = True
            if self.sso_provider == "okta":
                is_custom = ".okta.com" not in (self.sso_base or "")
            fp["sso_provider"] = {
                "type": self.sso_provider,
                "base_url": self.sso_base,
                "custom_domain": is_custom,
            }
        if self.login_initiation:
            fp["login_initiation"] = {
                "url": self.login_initiation["url"],
                "method": self.login_initiation["method"],
                "path": self.login_initiation["path"],
                "redirect_to": self.login_initiation.get("redirect_to", ""),
            }
        if self.credential_request:
            cr = self.credential_request
            # Redact actual credential values
            fp["credential_submission"] = {
                "url": cr["url"],
                "method": cr["method"],
                "content_type": cr["content_type"],
                "username_field": cr["username_field"],
                "password_field": cr["password_field"],
                "extra_fields": list(cr["extra_fields"].keys()),
                "response_status": cr["response_status"],
            }
        if self.redirect_chain:
            fp["post_auth_chain"] = self.redirect_chain
        if self.success_cookies:
            fp["success_indicators"] = {
                "cookies": self.success_cookies,
                "min_cookie_count": len(self.success_cookies),
                "cookie_names": [c["name"] for c in self.success_cookies],
                "cookie_domains": sorted({
                    c["domain"] for c in self.success_cookies if c["domain"]}),
            }
        # Build Fracture-compatible auth config
        fp["fracture_auth_config"] = self._build_fracture_config()
        # Notes about what was detected
        fp["analysis_notes"] = self._build_notes()
        return fp

    def _build_fracture_config(self) -> dict:
        cfg = {"method": "form_login"}
        if self.login_initiation:
            cfg["login_url"] = self.login_initiation["url"]
        elif self.credential_request:
            cfg["login_url"] = self.credential_request["url"]
        if self.credential_request:
            cfg["username_field"] = self.credential_request["username_field"]
            cfg["password_field"] = self.credential_request["password_field"]
            ct = self.credential_request.get("content_type", "")
            if "json" in ct:
                cfg["login_mode"] = "json"
            elif "form" in ct or "urlencoded" in ct:
                cfg["login_mode"] = "fields"
            else:
                cfg["login_mode"] = "fields"
        # OKTA recipe for the new unified auth
        if self.sso_provider == "okta" and self.sso_base:
            recipe = {
                "method": "okta_authn",
                "okta_base": self.sso_base,
            }
            if self.login_initiation:
                recipe["login_initiation_url"] = self.login_initiation["url"]
            cfg["_auth_recipe"] = recipe
        return cfg

    def _build_notes(self) -> list:
        notes = []
        if self.auth_type == "unknown":
            notes.append(
                "Could not auto-classify the auth flow. The raw exchange "
                "log is preserved for manual analysis.")
        if self.sso_provider and not self.login_initiation:
            notes.append(
                f"SSO provider ({self.sso_provider}) detected but no "
                f"login-initiation redirect from the target was found. "
                f"The target may use client-side JS to initiate SSO.")
        if not self.credential_request:
            notes.append(
                "No credential submission request was detected. The login "
                "may use a non-standard field naming or a multi-step flow "
                "that needs manual mapping.")
        if self.sso_provider == "okta" and self.sso_base:
            is_custom = ".okta.com" not in self.sso_base
            if is_custom:
                notes.append(
                    f"OKTA is running on a custom domain ({self.sso_base}). "
                    f"Fracture's auto-detect may not recognize this — the "
                    f"auth recipe in this fingerprint handles it.")
        if self.success_cookies:
            names = [c["name"] for c in self.success_cookies]
            notes.append(
                f"Post-auth cookies: {', '.join(names[:10])}"
                f"{' (+ more)' if len(names) > 10 else ''}")
        return notes


# ── Browser + proxy launcher ─────────────────────────────────────────────

def _find_free_port(start: int = 8080, end: int = 9000) -> int:
    for port in range(start, end):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("No free port in range")


def _find_browser() -> tuple:
    """Return (browser_type, path) for the first available browser."""
    candidates = [
        ("firefox", ["firefox", "/usr/bin/firefox",
                      "/usr/bin/firefox-esr",
                      "/snap/bin/firefox"]),
        ("chrome", ["google-chrome", "google-chrome-stable",
                     "chromium", "chromium-browser",
                     "/usr/bin/google-chrome",
                     "/usr/bin/chromium-browser"]),
    ]
    for btype, paths in candidates:
        for p in paths:
            if shutil.which(p):
                return btype, p
    return None, None


def _launch_firefox(proxy_port: int, target_url: str,
                    tmpdir: str) -> subprocess.Popen:
    profile_dir = os.path.join(tmpdir, "ff_profile")
    os.makedirs(profile_dir, exist_ok=True)
    prefs = os.path.join(profile_dir, "user.js")
    with open(prefs, "w") as f:
        f.write(f'user_pref("network.proxy.type", 1);\n')
        f.write(f'user_pref("network.proxy.http", "127.0.0.1");\n')
        f.write(f'user_pref("network.proxy.http_port", {proxy_port});\n')
        f.write(f'user_pref("network.proxy.ssl", "127.0.0.1");\n')
        f.write(f'user_pref("network.proxy.ssl_port", {proxy_port});\n')
        f.write(f'user_pref("network.proxy.no_proxies_on", "");\n')
        f.write(f'user_pref("security.enterprise_roots.enabled", true);\n')
        f.write(f'user_pref("network.stricttransportsecurity.preloadlist", false);\n')
        f.write(f'user_pref("security.cert_pinning.enforcement_level", 0);\n')
        f.write(f'user_pref("browser.shell.checkDefaultBrowser", false);\n')
        f.write(f'user_pref("browser.startup.homepage_override.mstone", "ignore");\n')
    _, ff_path = _find_browser()
    cmd = [ff_path or "firefox", "-profile", profile_dir, "-no-remote",
           target_url]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


def _launch_chrome(proxy_port: int, target_url: str,
                   tmpdir: str) -> subprocess.Popen:
    profile_dir = os.path.join(tmpdir, "chrome_profile")
    os.makedirs(profile_dir, exist_ok=True)
    _, chrome_path = _find_browser()
    cmd = [
        chrome_path or "google-chrome",
        f"--proxy-server=http://127.0.0.1:{proxy_port}",
        f"--user-data-dir={profile_dir}",
        "--ignore-certificate-errors",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-features=RendererCodeIntegrity",
        target_url,
    ]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


# ── Control page (served on a local port) ────────────────────────────────

_CONTROL_HTML = r"""<!DOCTYPE html>
<html><head>
<title>Fingerprint Auth — Recording</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
       max-width: 640px; margin: 40px auto; padding: 0 20px; background: #1a1a2e; color: #e0e0e0; }
h1 { color: #00d4ff; font-size: 1.4em; }
.target { background: #16213e; padding: 12px 16px; border-radius: 8px; margin: 16px 0;
          font-family: monospace; color: #4ecca3; word-break: break-all; }
.instructions { background: #0f3460; padding: 16px; border-radius: 8px; margin: 16px 0; line-height: 1.6; }
.instructions ol { padding-left: 20px; }
.instructions li { margin: 8px 0; }
.btn { display: inline-block; padding: 12px 32px; background: #e94560; color: white; border: none;
       border-radius: 6px; font-size: 1.1em; cursor: pointer; margin-top: 16px; }
.btn:hover { background: #c73e55; }
.btn:disabled { background: #555; cursor: not-allowed; }
.status { margin-top: 16px; padding: 12px; border-radius: 8px; display: none; }
.status.recording { display: block; background: #1b4332; color: #95d5b2; }
.status.done { display: block; background: #0f3460; color: #00d4ff; }
.exchange-count { font-size: 2em; font-weight: bold; color: #00d4ff; }
</style>
</head><body>
<h1>Auth Fingerprint Recorder</h1>
<div class="target">Target: <strong>TARGET_URL_PLACEHOLDER</strong></div>
<div class="instructions">
<ol>
<li>A browser has opened pointed at your target.</li>
<li><strong>Log in normally</strong> — use whatever login flow the application requires.</li>
<li>Once you see the authenticated landing page, come back here and click <strong>Done</strong>.</li>
</ol>
</div>
<div class="status recording" id="recording">
  Recording... <span class="exchange-count" id="count">0</span> exchanges captured
</div>
<div class="status done" id="done-msg" style="display:none;">
  Fingerprint saved! You can close this window.
</div>
<button class="btn" id="done-btn" onclick="finish()">Done — I'm Logged In</button>
<script>
function updateCount() {
    fetch('/api/count').then(r => r.json()).then(d => {
        document.getElementById('count').textContent = d.count;
    }).catch(() => {});
}
setInterval(updateCount, 2000);
function finish() {
    document.getElementById('done-btn').disabled = true;
    document.getElementById('done-btn').textContent = 'Analyzing...';
    fetch('/api/done', {method: 'POST'}).then(r => r.json()).then(d => {
        document.getElementById('recording').style.display = 'none';
        document.getElementById('done-msg').style.display = 'block';
        document.getElementById('done-btn').style.display = 'none';
    }).catch(() => {
        document.getElementById('done-btn').textContent = 'Error — try again';
        document.getElementById('done-btn').disabled = false;
    });
}
</script>
</body></html>"""


def _run_control_server(port: int, target_url: str, exchange_file: str,
                        done_event: threading.Event, result_holder: list):
    """Simple HTTP server for the control page."""
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                html = _CONTROL_HTML.replace("TARGET_URL_PLACEHOLDER", target_url)
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(html.encode())
            elif self.path == "/api/count":
                count = 0
                try:
                    with open(exchange_file) as f:
                        data = json.load(f)
                        count = len(data)
                except Exception:
                    pass
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"count": count}).encode())
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            if self.path == "/api/done":
                done_event.set()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": True}).encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", port), Handler)
    server.timeout = 1.0
    while not done_event.is_set():
        server.handle_request()
    # Handle a few more to serve the done response
    for _ in range(3):
        server.handle_request()
    server.server_close()


# ── Main orchestrator ────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Record an auth flow via MITM browser and produce "
                    "a fingerprint for Fracture.")
    parser.add_argument("--target-url", required=True,
                        help="Target URL to authenticate against")
    parser.add_argument("--output-dir", required=True,
                        help="Directory to write auth_fingerprint.json")
    parser.add_argument("--scope-hosts", default="",
                        help="Comma-separated hostnames to record (default: "
                             "target host + detected SSO host)")
    parser.add_argument("--proxy-port", type=int, default=0,
                        help="Proxy port (default: auto-find)")
    parser.add_argument("--no-browser", action="store_true",
                        help="Don't launch a browser (print proxy config)")
    parser.add_argument("--no-control-page", action="store_true",
                        help="Skip control page; press Enter to stop")
    parser.add_argument("--browser", choices=["firefox", "chrome"],
                        default="", help="Force browser type")
    args = parser.parse_args()

    target_url = args.target_url.rstrip("/")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    target_parsed = urlparse(target_url)
    target_host = target_parsed.hostname or ""

    # Scope hosts — start with target, expand as SSO hosts are discovered
    scope_hosts = set()
    scope_hosts.add(target_host)
    if args.scope_hosts:
        for h in args.scope_hosts.split(","):
            h = h.strip()
            if h:
                scope_hosts.add(h.lower())

    _log(f"Fingerprint Auth v{VERSION} — target: {target_url}")
    _status("fingerprint", "Starting", "initializing proxy and browser")

    # Check dependencies
    if not shutil.which("mitmdump"):
        _log("mitmdump not found — install mitmproxy (pip3 install mitmproxy)", "ERROR")
        sys.exit(1)

    # Temp directory for addon, exchange file, browser profile
    tmpdir = tempfile.mkdtemp(prefix="fp_auth_")

    # Exchange file — addon writes here, we read after
    exchange_file = os.path.join(tmpdir, "exchanges.json")
    with open(exchange_file, "w") as f:
        json.dump([], f)

    # Generate addon script
    addon_path = os.path.join(tmpdir, "fp_addon.py")
    addon_code = _ADDON_TEMPLATE.format(
        socket_path=os.path.join(tmpdir, "fp.sock"),
        scope_hosts=list(scope_hosts),
        exchange_file=exchange_file,
    )
    with open(addon_path, "w") as f:
        f.write(addon_code)

    # Find free ports
    proxy_port = args.proxy_port or _find_free_port(8080, 9000)
    control_port = _find_free_port(9100, 9200)

    # Start mitmproxy
    _log(f"Starting mitmproxy on port {proxy_port}")
    mitm_cmd = [
        "mitmdump",
        "-p", str(proxy_port),
        "--ssl-insecure",
        "--quiet",
        "-s", addon_path,
    ]
    mitm_proc = subprocess.Popen(
        mitm_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2.0)  # Let proxy start

    if mitm_proc.poll() is not None:
        _log("mitmproxy failed to start", "ERROR")
        sys.exit(1)

    # Start control page
    done_event = threading.Event()
    result_holder = []

    if not args.no_control_page:
        ctrl_thread = threading.Thread(
            target=_run_control_server,
            args=(control_port, target_url, exchange_file,
                  done_event, result_holder),
            daemon=True)
        ctrl_thread.start()

    # Launch browser
    browser_proc = None
    if not args.no_browser:
        btype, bpath = _find_browser()
        if args.browser:
            btype = args.browser
        if btype == "firefox":
            browser_proc = _launch_firefox(proxy_port, target_url, tmpdir)
            _log(f"Launched Firefox (proxy :{proxy_port})")
        elif btype == "chrome":
            browser_proc = _launch_chrome(proxy_port, target_url, tmpdir)
            _log(f"Launched Chrome (proxy :{proxy_port})")
        else:
            _log("No browser found — configure proxy manually", "WARNING")
            args.no_browser = True

    if args.no_browser:
        _log(f"Configure your browser proxy: 127.0.0.1:{proxy_port}")
        _log(f"Then navigate to: {target_url}")

    _status("fingerprint", "Recording", "waiting for login")

    if not args.no_control_page:
        _log(f"Control page: http://127.0.0.1:{control_port}/")
        # Also open control page in the default browser if no-browser mode
        if args.no_browser:
            _log(f"Open http://127.0.0.1:{control_port}/ and click Done when logged in")

    # Wait for done signal
    if args.no_control_page:
        _log("Press Enter when you have finished logging in...")
        try:
            input()
        except (EOFError, KeyboardInterrupt):
            pass
        done_event.set()
    else:
        # Wait for done_event from control page, or browser close, or Ctrl-C
        try:
            while not done_event.is_set():
                if browser_proc and browser_proc.poll() is not None:
                    _log("Browser closed — analyzing")
                    done_event.set()
                    break
                done_event.wait(timeout=2.0)
        except KeyboardInterrupt:
            _log("Interrupted — analyzing what was captured")
            done_event.set()

    _status("fingerprint", "Analyzing", "processing recorded traffic")
    _log("Recording stopped — analyzing auth flow")

    # Kill browser and proxy
    if browser_proc and browser_proc.poll() is None:
        try:
            browser_proc.terminate()
            browser_proc.wait(timeout=5)
        except Exception:
            try:
                browser_proc.kill()
            except Exception:
                pass

    # Give addon time to flush
    time.sleep(1.0)
    mitm_proc.terminate()
    try:
        mitm_proc.wait(timeout=5)
    except Exception:
        mitm_proc.kill()

    # Load exchanges
    exchanges = []
    try:
        with open(exchange_file) as f:
            exchanges = json.load(f)
    except Exception as e:
        _log(f"Failed to load exchanges: {e}", "ERROR")

    if not exchanges:
        _log("No HTTP exchanges recorded — fingerprint cannot be generated", "ERROR")
        _status("fingerprint", "Failed", "no traffic recorded")
        _cleanup(tmpdir)
        sys.exit(1)

    _log(f"Recorded {len(exchanges)} HTTP exchanges — analyzing")

    # Analyze
    analyzer = AuthFlowAnalyzer(exchanges, target_url)
    fingerprint = analyzer.analyze()

    # Save fingerprint
    fp_path = output_dir / "auth_fingerprint.json"
    try:
        fp_path.write_text(json.dumps(fingerprint, indent=2))
        _log(f"Fingerprint saved: {fp_path}", "SUCCESS")
    except Exception as e:
        _log(f"Failed to save fingerprint: {e}", "ERROR")
        _status("fingerprint", "Failed", str(e))
        _cleanup(tmpdir)
        sys.exit(1)

    # Save raw exchanges for debugging
    raw_path = output_dir / "auth_fingerprint_raw.json"
    try:
        raw_path.write_text(json.dumps(exchanges, indent=2))
    except Exception:
        pass

    # Summary
    _log(f"Auth type: {fingerprint['auth_type']}")
    if fingerprint.get("sso_provider"):
        _log(f"SSO provider: {fingerprint['sso_provider']['type']} "
             f"({fingerprint['sso_provider']['base_url']})")
    if fingerprint.get("login_initiation"):
        _log(f"Login initiation: {fingerprint['login_initiation']['url']}")
    if fingerprint.get("credential_submission"):
        cs = fingerprint["credential_submission"]
        _log(f"Credential endpoint: {cs['method']} {cs['url']}")
        _log(f"Fields: user={cs['username_field']}, pass={cs['password_field']}")
    if fingerprint.get("success_indicators"):
        si = fingerprint["success_indicators"]
        _log(f"Success cookies ({si['min_cookie_count']}): "
             f"{', '.join(si['cookie_names'][:8])}")
    if fingerprint.get("analysis_notes"):
        for note in fingerprint["analysis_notes"]:
            _log(f"Note: {note}")

    _log("Re-run testConnection with this fingerprint to verify it works", "SUCCESS")
    _status("fingerprint", "Complete",
            f"{fingerprint['auth_type']} — {len(exchanges)} exchanges")

    _emit("CRUCIBLE_FINDING", {
        "title": f"Auth Fingerprint: {fingerprint['auth_type']}",
        "risk": "INFO",
        "description": (
            f"Auth flow fingerprinted via MITM browser recording. "
            f"Detected: {fingerprint['auth_type']}. "
            f"{'SSO: ' + fingerprint['sso_provider']['type'] + '. ' if fingerprint.get('sso_provider') else ''}"
            f"{len(exchanges)} HTTP exchanges recorded. "
            f"Fingerprint saved to {fp_path}."
        ),
        "output_file": str(fp_path),
    })

    _cleanup(tmpdir)
    sys.exit(0)


def _cleanup(tmpdir: str):
    try:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
    except Exception:
        pass


if __name__ == "__main__":
    main()
