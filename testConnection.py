#!/usr/bin/env python3
"""
testConnection.py — Fracture authentication connection test utility.

Tests that configured credentials successfully authenticate against the
target web application and that subsequent requests can be made.  Designed
to be called both from the command line and from Crucible's test-connection
endpoint (via --output-json for machine-readable results).

Usage examples:

  # Use an existing Fracture settings file
  python3 testConnection.py --settings fr_settings.json

  # Inline JSON config (used by Crucible backend)
  python3 testConnection.py --json '{"url":"https://app.example.com","auth":{...}}'

  # Individual flags
  python3 testConnection.py --url https://app.example.com \
      --auth-method form_login \
      --login-url https://app.example.com/login \
      --username admin --password secret

  # List supported auth methods
  python3 testConnection.py --list-methods
"""

import argparse
import json
import sys

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERSION = "1.6.0"

AUTH_METHODS: dict[str, str] = {
    "form_login":          "Form Login  — POST credentials → session cookies (most web apps)",
    "basic":               "HTTP Basic Auth  (Authorization: Basic …)",
    "digest":              "HTTP Digest Auth  (challenge-response)",
    "ntlm":                "NTLM / Windows Integrated Auth  (Active Directory)",
    "bearer":              "Bearer Token  (Authorization: Bearer …)",
    "session_cookie":      "Session Cookie  — pre-captured cookie string",
    "token_login":         "Token Login  — POST credentials → JSON token → Bearer header",
    "oauth2_client_creds": "OAuth2 Client Credentials  (machine-to-machine, RFC 6749 §4.4)",
    "apikey_header":       "API Key in Header  (custom header name)",
    "apikey_cookie":       "API Key / Token in Cookie  (cookie-based key injection)",
    "header_creds":        "Custom Credential Headers  (static key-value pairs)",
    "kerberos":            "Kerberos / SPNEGO Negotiate  (domain Kerberos ticket)",
}


# ─────────────────────────────────────────────────────────────────────────────
# Session helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_session(verify_ssl: bool = False, proxy: str = "") -> requests.Session:
    """Create a requests.Session with retry adapter and Fracture User-Agent."""
    sess = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    sess.mount("http://",  HTTPAdapter(max_retries=retry))
    sess.mount("https://", HTTPAdapter(max_retries=retry))
    sess.verify = verify_ssl
    if proxy:
        sess.proxies = {"http": proxy, "https": proxy}
    sess.headers["User-Agent"] = f"Fracture-testConnection/{VERSION}"
    return sess


def _login_post(
    sess: requests.Session,
    auth: dict,
    timeout: int,
) -> "requests.Response | None":
    """POST to login_url, building the body according to login_mode."""
    url = auth.get("login_url", "")
    if not url:
        return None

    login_mode = auth.get("login_mode", "fields")
    uf = auth.get("login_username_field", "username")
    pf = auth.get("login_password_field", "password")
    u  = auth.get("username", "")
    p  = auth.get("password", "")

    if login_mode == "fields":
        # Body built entirely from the credential field values
        data: dict = {}
        if u:
            data[uf] = u
        if p:
            data[pf] = p
    elif login_mode == "json":
        # Use the raw JSON body as-is; no credential injection
        raw = auth.get("login_data", "{}")
        try:
            data = json.loads(raw) if isinstance(raw, str) else dict(raw)
        except Exception:
            data = {}
    else:
        # "merge" (legacy): JSON body with missing creds injected
        raw = auth.get("login_data", "{}")
        try:
            data = json.loads(raw) if isinstance(raw, str) else dict(raw)
        except Exception:
            data = {}
        if u and uf not in data:
            data[uf] = u
        if p and pf not in data:
            data[pf] = p

    ct = auth.get("login_content_type", "application/json")
    try:
        if "json" in ct:
            return sess.post(url, json=data, timeout=timeout)
        return sess.post(url, data=data, timeout=timeout)
    except Exception:
        return None  # caller handles


# ─────────────────────────────────────────────────────────────────────────────
# Auth session builder
# ─────────────────────────────────────────────────────────────────────────────

def build_auth_session(
    auth: dict,
    timeout: int = 10,
    proxy: str = "",
    verify_ssl: bool = False,
) -> tuple[requests.Session, str]:
    """
    Construct an authenticated requests.Session for the given auth config.

    Returns (session, info_message).  info_message starts with "ERROR:" for
    any hard failure; anything else indicates success or a warning.
    """
    sess = _make_session(verify_ssl, proxy)
    method = (auth.get("method") or auth.get("auth_type") or "form_login").strip().lower()

    # ── Form Login ────────────────────────────────────────────────────────────
    if method == "form_login":
        login_url = auth.get("login_url", "")
        if not login_url:
            return sess, "ERROR: login_url is required for form_login"
        resp = _login_post(sess, auth, timeout)
        if resp is None:
            return sess, f"ERROR: POST to {login_url} failed (network/timeout)"
        if not resp.ok:
            return sess, (
                f"ERROR: POST {login_url} → HTTP {resp.status_code} — "
                "login rejected (check credentials and login URL)"
            )
        n = len(sess.cookies)
        sc = resp.status_code
        if n == 0:
            return sess, (
                f"WARNING: POST {login_url} → HTTP {sc} — "
                "login accepted but no session cookies returned"
            )
        return sess, f"POST {login_url} → HTTP {sc}, {n} cookie(s) stored"

    # ── HTTP Basic ────────────────────────────────────────────────────────────
    elif method == "basic":
        user = auth.get("username", "")
        pw   = auth.get("password", "")
        if not user:
            return sess, "WARNING: no username provided for HTTP Basic"
        sess.auth = (user, pw)
        return sess, f"HTTP Basic: user={user}"

    # ── HTTP Digest ───────────────────────────────────────────────────────────
    elif method == "digest":
        from requests.auth import HTTPDigestAuth
        user = auth.get("username", "")
        pw   = auth.get("password", "")
        if not user:
            return sess, "WARNING: no username provided for HTTP Digest"
        sess.auth = HTTPDigestAuth(user, pw)
        return sess, f"HTTP Digest: user={user}"

    # ── NTLM ──────────────────────────────────────────────────────────────────
    elif method == "ntlm":
        user   = auth.get("username", "")
        pw     = auth.get("password", "")
        domain = auth.get("domain", "")
        if not user:
            return sess, "ERROR: username is required for NTLM"
        try:
            from requests_ntlm import HttpNtlmAuth  # type: ignore[import]
        except ImportError:
            return sess, "ERROR: NTLM auth requires: pip install requests-ntlm"
        ntlm_user = f"{domain}\\{user}" if domain else user
        sess.auth = HttpNtlmAuth(ntlm_user, pw)
        return sess, f"NTLM: {ntlm_user}"

    # ── Bearer Token ──────────────────────────────────────────────────────────
    elif method == "bearer":
        token = auth.get("auth_token", "").strip()
        if not token:
            return sess, "WARNING: no token provided for Bearer auth"
        tt = auth.get("token_type", "Bearer")
        sess.headers["Authorization"] = f"{tt} {token}"
        return sess, f"Authorization: {tt} ***"

    # ── Session Cookie ────────────────────────────────────────────────────────
    elif method == "session_cookie":
        raw = auth.get("session_cookie", "").strip()
        if not raw:
            return sess, "WARNING: no session_cookie value provided"
        names = []
        for part in raw.split(";"):
            part = part.strip()
            if not part:
                continue
            if "=" in part:
                k, _, v = part.partition("=")
                sess.cookies.set(k.strip(), v.strip())
                names.append(k.strip())
            else:
                # bare token — treat as value under generic key
                sess.cookies.set(part, "")
                names.append(part)
        return sess, f"Session cookie(s) set: {', '.join(names)}"

    # ── Token Login ───────────────────────────────────────────────────────────
    elif method == "token_login":
        login_url = auth.get("login_url", "")
        if not login_url:
            return sess, "ERROR: login_url is required for token_login"
        resp = _login_post(sess, auth, timeout)
        if resp is None:
            return sess, f"ERROR: POST to {login_url} failed (network/timeout)"
        if not resp.ok:
            return sess, (
                f"ERROR: POST {login_url} → HTTP {resp.status_code} — "
                "login rejected (check credentials and login URL)"
            )
        try:
            body = resp.json()
        except Exception:
            return sess, (
                f"ERROR: POST {login_url} → HTTP {resp.status_code} — "
                "response is not JSON; cannot extract token"
            )
        # Traverse dot-path (e.g. "data.access_token")
        token_path = auth.get("login_token_path", "token")
        token: object = body
        for part in token_path.split("."):
            token = token.get(part) if isinstance(token, dict) else None
        if not token or not isinstance(token, str):
            # Fallback: look for common key names
            for k in ("token", "access_token", "jwt", "id_token", "auth_token"):
                if k in body:
                    token = body[k]
                    break
        if token and isinstance(token, str):
            tt = auth.get("token_type", "Bearer")
            sess.headers["Authorization"] = f"{tt} {token}"
            return sess, (
                f"POST {login_url} → HTTP {resp.status_code}; "
                f"token extracted via path='{token_path}'"
            )
        return sess, (
            f"ERROR: POST {login_url} → HTTP {resp.status_code}; "
            f"no token found at path='{token_path}' — "
            "check Token Path in Response"
        )

    # ── OAuth2 Client Credentials ─────────────────────────────────────────────
    elif method == "oauth2_client_creds":
        token_url     = auth.get("oauth_token_url", "")
        client_id     = auth.get("oauth_client_id", "")
        client_secret = auth.get("oauth_client_secret", "")
        scope         = auth.get("oauth_scope", "")
        if not token_url:
            return sess, "ERROR: oauth_token_url is required"
        if not client_id:
            return sess, "ERROR: oauth_client_id is required"
        data: dict = {
            "grant_type":    "client_credentials",
            "client_id":     client_id,
            "client_secret": client_secret,
        }
        if scope:
            data["scope"] = scope
        try:
            resp = sess.post(token_url, data=data, timeout=timeout)
        except requests.exceptions.RequestException as exc:
            return sess, f"ERROR: OAuth2 token request failed: {exc}"
        if not resp.ok:
            return sess, (
                f"ERROR: OAuth2 POST {token_url} → HTTP {resp.status_code} — "
                "token request rejected"
            )
        try:
            body = resp.json()
        except Exception:
            return sess, (
                f"ERROR: OAuth2 POST {token_url} → HTTP {resp.status_code} — "
                "response is not JSON"
            )
        access_token = body.get("access_token", "")
        if not access_token:
            return sess, (
                f"ERROR: OAuth2 POST {token_url} → HTTP {resp.status_code}; "
                "no access_token in response"
            )
        tt = body.get("token_type", "Bearer")
        sess.headers["Authorization"] = f"{tt} {access_token}"
        return sess, f"OAuth2 token obtained from {token_url} → HTTP {resp.status_code}"

    # ── API Key in Header ─────────────────────────────────────────────────────
    elif method == "apikey_header":
        key    = auth.get("api_key", "").strip()
        header = auth.get("api_key_header", "X-API-Key")
        if not key:
            return sess, "WARNING: no api_key provided for apikey_header"
        sess.headers[header] = key
        return sess, f"{header}: ***"

    # ── API Key in Cookie ─────────────────────────────────────────────────────
    elif method == "apikey_cookie":
        key         = auth.get("api_key", "").strip()
        cookie_name = auth.get("api_key_cookie", "api_key")
        if not key:
            return sess, "WARNING: no api_key provided for apikey_cookie"
        sess.cookies.set(cookie_name, key)
        return sess, f"Cookie {cookie_name}=***"

    # ── Custom Credential Headers ─────────────────────────────────────────────
    elif method == "header_creds":
        hdrs = auth.get("custom_headers", {})
        if not isinstance(hdrs, dict) or not hdrs:
            return sess, "WARNING: no custom_headers provided"
        sess.headers.update(hdrs)
        names = list(hdrs.keys())
        return sess, f"Set {len(names)} header(s): {', '.join(names)}"

    # ── Kerberos / SPNEGO ─────────────────────────────────────────────────────
    elif method == "kerberos":
        try:
            from requests_kerberos import HTTPKerberosAuth, OPTIONAL  # type: ignore[import]
        except ImportError:
            return sess, "ERROR: Kerberos auth requires: pip install requests-kerberos"
        sess.auth = HTTPKerberosAuth(mutual_authentication=OPTIONAL)
        return sess, "Kerberos SPNEGO auth configured"

    return sess, f"WARNING: unknown auth method '{method}'"


# ─────────────────────────────────────────────────────────────────────────────
# Connection test
# ─────────────────────────────────────────────────────────────────────────────

def test_connection(
    url: str,
    auth: dict,
    timeout: int = 10,
    proxy: str = "",
    verify_ssl: bool = False,
) -> dict:
    """
    Authenticate and probe the target web application URL.

    For login-based methods (form_login, token_login) the outcome of the
    login POST is the definitive success indicator — the base URL is not
    probed separately to avoid false positives on publicly accessible pages.

    Returns::

        {
          "success":     bool,
          "message":     str,   # human-readable outcome
          "status_code": int | None,
          "auth_info":   str,   # what auth was configured
        }
    """
    sess, auth_info = build_auth_session(auth, timeout, proxy, verify_ssl)
    auth_method = (auth.get("method") or auth.get("auth_type") or "form_login").strip().lower()

    # ── Login-based methods: POST result is the definitive answer ─────────────
    if auth_method in ("form_login", "token_login"):
        failed = auth_info.startswith("ERROR:")
        return {
            "success":     not failed,
            "message":     auth_info,
            "status_code": None,
            "auth_info":   auth_info,
        }

    # ── Any setup-time ERROR is a hard failure ────────────────────────────────
    if auth_info.startswith("ERROR:"):
        return {
            "success":     False,
            "message":     auth_info,
            "status_code": None,
            "auth_info":   auth_info,
        }

    # ── session_cookie / kerberos: probe with GET then HEAD ───────────────────
    if auth_method in ("session_cookie", "kerberos"):
        for http_method in ("GET", "HEAD"):
            try:
                resp = sess.request(http_method, url, timeout=timeout)
                sc = resp.status_code
                if sc == 401:
                    return {
                        "success":     False,
                        "message":     "Authentication failed — HTTP 401 Unauthorized",
                        "status_code": sc,
                        "auth_info":   auth_info,
                    }
                if sc == 403:
                    return {
                        "success":     False,
                        "message":     "HTTP 403 Forbidden — credentials accepted but access denied",
                        "status_code": sc,
                        "auth_info":   auth_info,
                    }
                return {
                    "success":     True,
                    "message":     f"Connection successful — HTTP {sc}",
                    "status_code": sc,
                    "auth_info":   auth_info,
                }
            except requests.exceptions.SSLError as exc:
                return {
                    "success":     False,
                    "message":     f"SSL error: {exc} — try enabling 'verify_ssl: false'",
                    "status_code": None,
                    "auth_info":   auth_info,
                }
            except requests.exceptions.ConnectionError as exc:
                return {
                    "success":     False,
                    "message":     f"Connection error: {exc}",
                    "status_code": None,
                    "auth_info":   auth_info,
                }
            except requests.exceptions.Timeout:
                return {
                    "success":     False,
                    "message":     f"Request timed out after {timeout}s",
                    "status_code": None,
                    "auth_info":   auth_info,
                }
            except Exception as exc:
                return {
                    "success":     False,
                    "message":     f"Request failed: {exc}",
                    "status_code": None,
                    "auth_info":   auth_info,
                }

    # ── All other methods: probe URL with GET then HEAD ───────────────────────
    last_exc: str = ""
    for http_method in ("GET", "HEAD"):
        try:
            resp = sess.request(http_method, url, timeout=timeout)
            sc = resp.status_code
            if sc == 401:
                return {
                    "success":     False,
                    "message":     "Authentication failed — HTTP 401 Unauthorized",
                    "status_code": sc,
                    "auth_info":   auth_info,
                }
            if sc == 403:
                return {
                    "success":     False,
                    "message":     "HTTP 403 Forbidden — credentials accepted but access denied",
                    "status_code": sc,
                    "auth_info":   auth_info,
                }
            return {
                "success":     True,
                "message":     f"Connection successful — HTTP {sc}",
                "status_code": sc,
                "auth_info":   auth_info,
            }
        except requests.exceptions.SSLError as exc:
            return {
                "success":     False,
                "message":     f"SSL error: {exc} — try enabling 'verify_ssl: false'",
                "status_code": None,
                "auth_info":   auth_info,
            }
        except requests.exceptions.ConnectionError as exc:
            return {
                "success":     False,
                "message":     f"Connection error: {exc}",
                "status_code": None,
                "auth_info":   auth_info,
            }
        except requests.exceptions.Timeout:
            return {
                "success":     False,
                "message":     f"Request timed out after {timeout}s",
                "status_code": None,
                "auth_info":   auth_info,
            }
        except Exception as exc:
            last_exc = str(exc)

    return {
        "success":     False,
        "message":     f"Request failed: {last_exc}",
        "status_code": None,
        "auth_info":   auth_info,
    }


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        prog="testConnection",
        description=f"Fracture v{VERSION} — Web Application Authentication Connection Test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(f"  {k:<25} {v}" for k, v in AUTH_METHODS.items()),
    )

    # Source flags
    ap.add_argument("--settings",     metavar="FILE",
                    help="Fracture settings JSON file (reads scan.auth + scan.target_url)")
    ap.add_argument("--json",         metavar="JSON",
                    help='Inline config: \'{"url":"...","auth":{...}}\'')

    # Target / method
    ap.add_argument("--url",          metavar="URL",    help="Target web application URL to test")
    ap.add_argument("--auth-method",  metavar="METHOD",
                    choices=list(AUTH_METHODS.keys()), help="Auth method")

    # Credential flags
    ap.add_argument("--username",     metavar="USER",   help="Username")
    ap.add_argument("--password",     metavar="PASS",   help="Password")
    ap.add_argument("--domain",       metavar="DOMAIN", help="Domain (NTLM)")

    # Bearer / token
    ap.add_argument("--token",        metavar="TOKEN",  help="Bearer / auth token value")
    ap.add_argument("--token-type",   metavar="TYPE",   default="Bearer",
                    help="Token type prefix (default: Bearer)")

    # Session cookie
    ap.add_argument("--session-cookie", metavar="COOKIE",
                    help="Pre-captured cookie string (semicolon-separated key=value pairs)")

    # Form / token login
    ap.add_argument("--login-url",    metavar="URL",    help="Login endpoint URL")
    ap.add_argument("--login-data",   metavar="JSON",
                    help='Login POST body, e.g. \'{"username":"u","password":"p"}\'')
    ap.add_argument("--login-content-type", metavar="CT", default="application/json",
                    help="Content-Type for login POST (default: application/json)")
    ap.add_argument("--login-username-field", metavar="FIELD", default="username",
                    help="Username field name in login POST body (default: username)")
    ap.add_argument("--login-password-field", metavar="FIELD", default="password",
                    help="Password field name in login POST body (default: password)")
    ap.add_argument("--login-mode",   metavar="MODE",
                    choices=["fields", "json", "merge"], default="fields",
                    help="Login body construction mode (default: fields)")
    ap.add_argument("--login-token-path", metavar="PATH", default="token",
                    help="Dot-path to token in login JSON response (default: token)")

    # OAuth2
    ap.add_argument("--oauth-token-url",     metavar="URL")
    ap.add_argument("--oauth-client-id",     metavar="ID")
    ap.add_argument("--oauth-client-secret", metavar="SECRET")
    ap.add_argument("--oauth-scope",         metavar="SCOPE")

    # API key
    ap.add_argument("--api-key",        metavar="KEY",  help="API key value")
    ap.add_argument("--api-key-header", metavar="HDR",  default="X-API-Key",
                    help="Header name for apikey_header (default: X-API-Key)")
    ap.add_argument("--api-key-cookie", metavar="NAME",
                    help="Cookie name for apikey_cookie")

    # Connection
    ap.add_argument("--timeout",      type=int, default=10,
                    help="Request timeout in seconds (default: 10)")
    ap.add_argument("--proxy",        metavar="URL", default="", help="HTTP proxy URL")
    ap.add_argument("--no-verify",    action="store_true",
                    help="Skip TLS certificate verification (insecure)")

    # Output
    ap.add_argument("--output-json",  action="store_true",
                    help="Print result as JSON (for programmatic use by Crucible)")
    ap.add_argument("--list-methods", action="store_true",
                    help="List supported auth methods and exit")

    args = ap.parse_args()

    if args.list_methods:
        print(f"\nFracture testConnection v{VERSION} — supported auth methods:\n")
        for k, v in AUTH_METHODS.items():
            print(f"  {k:<25} {v}")
        print()
        sys.exit(0)

    # ── Build config — priority: --settings → --json → CLI flags ─────────────
    url        = ""
    auth: dict = {}
    timeout    = args.timeout
    proxy      = args.proxy
    verify_ssl = not args.no_verify

    if args.settings:
        try:
            with open(args.settings) as fh:
                cfg = json.loads(fh.read())
            scan       = cfg.get("scan", {})
            url        = scan.get("target_url", "")
            auth       = dict(scan.get("auth", {}))
            timeout    = scan.get("timeout", timeout)
            proxy      = scan.get("proxy", proxy)
            verify_ssl = scan.get("verify_ssl", verify_ssl)
        except Exception as exc:
            print(f"ERROR: could not read settings file: {exc}", file=sys.stderr)
            sys.exit(1)

    if args.json:
        try:
            j = json.loads(args.json)
            if "url"        in j: url        = j["url"]
            if "auth"       in j: auth        = dict(j["auth"])
            if "timeout"    in j: timeout     = int(j["timeout"])
            if "proxy"      in j: proxy       = j["proxy"]
            if "verify_ssl" in j: verify_ssl  = bool(j["verify_ssl"])
        except Exception as exc:
            print(f"ERROR: could not parse --json: {exc}", file=sys.stderr)
            sys.exit(1)

    # CLI flags override settings/json
    if args.url:                   url                          = args.url
    if args.auth_method:           auth["method"]               = args.auth_method
    if args.username:              auth["username"]              = args.username
    if args.password:              auth["password"]              = args.password
    if args.domain:                auth["domain"]                = args.domain
    if args.token:                 auth["auth_token"]            = args.token
    if args.token_type:            auth["token_type"]            = args.token_type
    if args.session_cookie:        auth["session_cookie"]        = args.session_cookie
    if args.login_url:             auth["login_url"]             = args.login_url
    if args.login_data:            auth["login_data"]            = args.login_data
    if args.login_content_type:    auth["login_content_type"]    = args.login_content_type
    if args.login_username_field:  auth["login_username_field"]  = args.login_username_field
    if args.login_password_field:  auth["login_password_field"]  = args.login_password_field
    if args.login_mode:            auth["login_mode"]            = args.login_mode
    if args.login_token_path:      auth["login_token_path"]      = args.login_token_path
    if args.oauth_token_url:       auth["oauth_token_url"]       = args.oauth_token_url
    if args.oauth_client_id:       auth["oauth_client_id"]       = args.oauth_client_id
    if args.oauth_client_secret:   auth["oauth_client_secret"]   = args.oauth_client_secret
    if args.oauth_scope:           auth["oauth_scope"]           = args.oauth_scope
    if args.api_key:               auth["api_key"]               = args.api_key
    if args.api_key_header:        auth["api_key_header"]        = args.api_key_header
    if args.api_key_cookie:        auth["api_key_cookie"]        = args.api_key_cookie
    if args.no_verify:             verify_ssl                    = False

    if not url:
        print(
            "ERROR: no URL specified. Use --url, --settings FILE, or --json '{...}'.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not auth.get("method"):
        auth["method"] = "form_login"

    # ── Run test ──────────────────────────────────────────────────────────────
    result = test_connection(url, auth, timeout, proxy, verify_ssl)

    if args.output_json:
        print(json.dumps(result))
        sys.exit(0 if result["success"] else 1)

    method_key   = auth.get("method", "form_login")
    method_label = AUTH_METHODS.get(method_key, method_key)
    ok           = result["success"]
    icon         = "\u2713" if ok else "\u2717"

    print(f"\nFracture testConnection v{VERSION}")
    print(f"  URL        : {url}")
    print(f"  Method     : {method_label}")
    print(f"  Auth setup : {result['auth_info']}")
    print(f"  Result     : {icon} {result['message']}")
    if result.get("status_code") is not None:
        print(f"  HTTP       : {result['status_code']}")
    print()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
