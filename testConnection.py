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

VERSION = "2.3.2"

AUTH_METHODS: dict[str, str] = {
    "form_login":           "Form Login  — POST credentials → session cookies (most web apps)",
    "basic":                "HTTP Basic Auth  (Authorization: Basic …)",
    "digest":               "HTTP Digest Auth  (challenge-response)",
    "ntlm":                 "NTLM / Windows Integrated Auth  (Active Directory)",
    "ntlm_v2":              "NTLMv2 + Channel Binding Token  (EPA / extended protection for auth)",
    "bearer":               "Bearer Token  (Authorization: Bearer …)",
    "session_cookie":       "Session Cookie  — pre-captured cookie string",
    "token_login":          "Token Login  — POST credentials → JSON token → Bearer header",
    "oauth2_client_creds":  "OAuth2 Client Credentials  (machine-to-machine, RFC 6749 §4.4)",
    "oauth1a":              "OAuth 1.0a  — HMAC-SHA1 signed request (consumer key + access token)",
    "saml_assertion":       "SAML 2.0  — POST pre-captured SAMLResponse to ACS URL",
    "oidc_token":           "OIDC  — pre-obtained id_token as Bearer + userinfo endpoint probe",
    "mtls":                 "mTLS  — mutual TLS with client certificate and private key",
    "totp_mfa":             "TOTP/HOTP MFA  — form login followed by TOTP second-factor step",
    "webauthn_probe":       "WebAuthn/FIDO2  — probe server for WebAuthn support (detection only)",
    "apikey_header":        "API Key in Header  (custom header name)",
    "apikey_cookie":        "API Key / Token in Cookie  (cookie-based key injection)",
    "header_creds":         "Custom Credential Headers  (static key-value pairs)",
    "kerberos":             "Kerberos / SPNEGO Negotiate  (domain Kerberos ticket)",
    "kerberos_delegation":  "Kerberos S4U2Proxy  — constrained delegation / impersonation",
    "proxy_header":         "Proxy / Gateway Auth Header  — inject header set by upstream auth proxy",
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


def _csrf_prefetch(
    sess: "requests.Session",
    login_url: str,
    timeout: int,
) -> "tuple[str, dict]":
    """
    GET login_url; return (form_action_url, hidden_input_fields).

    Locates the first <form> that contains a password input, extracts its
    action URL (resolved relative to login_url) and all hidden <input> values
    (CSRF tokens, nonce fields, etc.).  Returns ("", {}) on any error so
    callers fall back to the original login_url with no extra fields.
    """
    import re
    from urllib.parse import urljoin
    try:
        r = sess.get(login_url, timeout=timeout)
        html = r.text
    except Exception:
        return "", {}
    hidden: dict = {}
    form_action = ""
    for form_m in re.finditer(r"(?s)<form[^>]*>(.+?)</form>", html, re.IGNORECASE):
        form_tag  = form_m.group(0)
        form_body = form_m.group(1)
        if not re.search(r'<input[^>]+type=["\']?password["\']?', form_body, re.IGNORECASE):
            continue
        act_m = re.search(r'\baction=["\']([^"\']*)["\']', form_tag, re.IGNORECASE)
        if act_m:
            raw = act_m.group(1).strip()
            if raw:
                form_action = urljoin(login_url, raw)
        for inp in re.finditer(r"<input[^>]+>", form_body, re.IGNORECASE):
            tag = inp.group(0)
            t_m = re.search(r'\btype=["\']?(\w+)["\']?', tag, re.IGNORECASE)
            if not t_m or t_m.group(1).lower() != "hidden":
                continue
            n_m = re.search(r'\bname=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            v_m = re.search(r'\bvalue=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            if n_m:
                hidden[n_m.group(1)] = v_m.group(1) if v_m else ""
        break  # use first form containing a password field
    return form_action, hidden


def _login_post(
    sess: requests.Session,
    auth: dict,
    timeout: int,
    allow_redirects: bool = True,
) -> "tuple[requests.Response | None, str]":
    """
    GET the login page (CSRF prefetch + form action detection), then POST
    credentials to the resolved endpoint.

    Returns (response_or_None, actual_post_url).  The actual_post_url may
    differ from login_url when the HTML form's action attribute points to a
    different endpoint (common in MVC frameworks).
    """
    url = auth.get("login_url", "")
    if not url:
        return None, ""

    login_mode = auth.get("login_mode", "fields")
    uf = auth.get("login_username_field", "username")
    pf = auth.get("login_password_field", "password")
    u  = auth.get("username", "")
    p  = auth.get("password", "")

    # Prefetch login page: resolve form action URL + collect hidden/CSRF fields
    form_action, hidden = _csrf_prefetch(sess, url, timeout)
    post_url = form_action if form_action else url

    if login_mode == "fields":
        # Start with hidden fields (CSRF tokens etc.), then overlay credentials
        data: dict = dict(hidden)
        if u:
            data[uf] = u
        if p:
            data[pf] = p
    elif login_mode == "json":
        # Use the raw JSON body as-is; no credential or CSRF injection
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
        for k, v in hidden.items():
            if k not in data:
                data[k] = v

    ct = auth.get("login_content_type", "application/json")
    try:
        if "json" in ct:
            return sess.post(post_url, json=data, timeout=timeout,
                             allow_redirects=allow_redirects), post_url
        return sess.post(post_url, data=data, timeout=timeout,
                         allow_redirects=allow_redirects), post_url
    except Exception:
        return None, post_url  # caller handles


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
    method = (auth.get("method") or auth.get("auth_method") or auth.get("auth_type") or "form_login").strip().lower()

    # ── Form Login ────────────────────────────────────────────────────────────
    if method == "form_login":
        login_url = auth.get("login_url", "")
        if not login_url:
            return sess, "ERROR: login_url is required for form_login"
        resp, post_url = _login_post(sess, auth, timeout)
        if resp is None:
            return sess, f"ERROR: POST to {post_url or login_url} failed (network/timeout)"
        if not resp.ok:
            if resp.status_code == 405:
                return sess, (
                    f"ERROR: POST {post_url} → HTTP 405 Method Not Allowed — "
                    "this URL only accepts GET; check the HTML form action attribute "
                    "for the correct submission endpoint"
                )
            return sess, (
                f"ERROR: POST {post_url} → HTTP {resp.status_code} — "
                "login rejected (check credentials and login URL)"
            )
        n = len(sess.cookies)
        sc = resp.status_code
        if n == 0:
            return sess, (
                f"WARNING: POST {post_url} → HTTP {sc} — "
                "login accepted but no session cookies returned"
            )
        return sess, f"POST {post_url} → HTTP {sc}, {n} cookie(s) stored"

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
        domain = domain.rstrip("\\").strip()
        ntlm_user = f"{domain}\\{user}" if domain else user
        sess.auth = HttpNtlmAuth(ntlm_user, pw)
        return sess, f"NTLM: {ntlm_user}"

    # ── Bearer Token ──────────────────────────────────────────────────────────
    elif method == "bearer":
        token = auth.get("auth_token", "").strip()
        if not token:
            return sess, "WARNING: no token provided for Bearer auth"
        tt = auth.get("token_type", "Bearer").strip()
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
        resp, post_url = _login_post(sess, auth, timeout)
        if resp is None:
            return sess, f"ERROR: POST to {post_url or login_url} failed (network/timeout)"
        if not resp.ok:
            return sess, (
                f"ERROR: POST {post_url} → HTTP {resp.status_code} — "
                "login rejected (check credentials and login URL)"
            )
        try:
            body = resp.json()
        except Exception:
            return sess, (
                f"ERROR: POST {post_url} → HTTP {resp.status_code} — "
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
        if token is not None and token != "":
            token = str(token)
            tt = auth.get("token_type", "Bearer").strip()
            sess.headers["Authorization"] = f"{tt} {token}"
            return sess, (
                f"POST {post_url} → HTTP {resp.status_code}; "
                f"token extracted via path='{token_path}'"
            )
        return sess, (
            f"ERROR: POST {post_url} → HTTP {resp.status_code}; "
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
        client_auth_method = auth.get("client_auth_method", "body").strip().lower()
        data: dict = {"grant_type": "client_credentials"}
        req_kwargs: dict = {"timeout": timeout}
        if client_auth_method == "basic":
            # RFC 6749 §2.3.1: credentials in HTTP Basic auth header
            req_kwargs["auth"] = (client_id, client_secret)
        else:
            # "body" (default): credentials as POST body fields
            data["client_id"]     = client_id
            data["client_secret"] = client_secret
        if scope:
            data["scope"] = scope
        try:
            resp = sess.post(token_url, data=data, **req_kwargs)
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

    # ── Kerberos S4U2Proxy Delegation ─────────────────────────────────────────
    elif method == "kerberos_delegation":
        try:
            from requests_kerberos import HTTPKerberosAuth, REQUIRED  # type: ignore[import]
        except ImportError:
            return sess, "ERROR: Kerberos delegation requires: pip install requests-kerberos"
        impersonate = auth.get("kerberos_impersonate", "")
        kwargs: dict = {"mutual_authentication": REQUIRED, "delegate": True}
        if impersonate:
            kwargs["principal"] = impersonate
        sess.auth = HTTPKerberosAuth(**kwargs)
        detail = f"Kerberos delegation configured (impersonate={impersonate})" if impersonate \
            else "Kerberos S4U2Proxy delegation configured"
        return sess, detail

    # ── NTLMv2 + Channel Binding Token ───────────────────────────────────────
    elif method == "ntlm_v2":
        user   = auth.get("username", "")
        pw     = auth.get("password", "")
        domain = auth.get("domain", "").rstrip("\\").strip()
        if not user:
            return sess, "ERROR: username is required for ntlm_v2"
        try:
            from requests_ntlm import HttpNtlmAuth  # type: ignore[import]
        except ImportError:
            return sess, "ERROR: NTLMv2 requires: pip install requests-ntlm"
        ntlm_user = f"{domain}\\{user}" if domain else user
        # send_cbt=True enables channel binding tokens (EPA) — NTLMv2 protection
        try:
            sess.auth = HttpNtlmAuth(ntlm_user, pw, send_cbt=True)
        except TypeError:
            # Older versions of requests-ntlm do not support send_cbt
            sess.auth = HttpNtlmAuth(ntlm_user, pw)
            return sess, f"NTLMv2 (send_cbt not supported by installed requests-ntlm): {ntlm_user}"
        return sess, f"NTLMv2 + channel binding: {ntlm_user}"

    # ── OAuth 1.0a ────────────────────────────────────────────────────────────
    elif method == "oauth1a":
        consumer_key    = auth.get("oauth1_consumer_key", "").strip()
        consumer_secret = auth.get("oauth1_consumer_secret", "").strip()
        access_token    = auth.get("oauth1_access_token", "").strip()
        token_secret    = auth.get("oauth1_token_secret", "").strip()
        if not consumer_key:
            return sess, "ERROR: oauth1_consumer_key is required for oauth1a"
        try:
            from requests_oauthlib import OAuth1  # type: ignore[import]
        except ImportError:
            return sess, "ERROR: OAuth 1.0a requires: pip install requests-oauthlib"
        sess.auth = OAuth1(consumer_key, consumer_secret,
                           access_token or None, token_secret or None)
        return sess, f"OAuth 1.0a configured (consumer={consumer_key})"

    # ── SAML 2.0 Assertion POST ───────────────────────────────────────────────
    elif method == "saml_assertion":
        acs_url   = auth.get("saml_acs_url", "").strip()
        assertion = auth.get("saml_assertion", "").strip()
        relay_state = auth.get("saml_relay_state", "")
        if not acs_url:
            return sess, "ERROR: saml_acs_url is required for saml_assertion"
        if not assertion:
            return sess, "ERROR: saml_assertion (base64-encoded SAMLResponse) is required"
        try:
            data = {"SAMLResponse": assertion}
            if relay_state:
                data["RelayState"] = relay_state
            resp = sess.post(acs_url, data=data, timeout=timeout, allow_redirects=True)
            if resp.status_code in (401, 403):
                return sess, (
                    f"ERROR: SAML POST to {acs_url} → HTTP {resp.status_code} — "
                    "assertion rejected"
                )
            return sess, f"SAML assertion posted to {acs_url} → HTTP {resp.status_code}"
        except Exception as exc:
            return sess, f"ERROR: SAML POST failed: {exc}"

    # ── OIDC id_token ─────────────────────────────────────────────────────────
    elif method == "oidc_token":
        id_token  = auth.get("oidc_id_token", "").strip()
        userinfo  = auth.get("oidc_userinfo_url", "").strip()
        if not id_token:
            return sess, "ERROR: oidc_id_token is required for oidc_token"
        sess.headers["Authorization"] = f"Bearer {id_token}"
        if not userinfo:
            return sess, "OIDC id_token set as Bearer (no userinfo_url provided)"
        try:
            r = sess.get(userinfo, timeout=timeout)
            if r.status_code == 401:
                return sess, f"ERROR: OIDC userinfo {userinfo} → HTTP 401 — token rejected"
            return sess, f"OIDC id_token valid — userinfo {userinfo} → HTTP {r.status_code}"
        except Exception as exc:
            return sess, f"OIDC id_token set; userinfo probe failed: {exc}"

    # ── mTLS — mutual TLS client certificate ─────────────────────────────────
    elif method == "mtls":
        cert_path = auth.get("mtls_cert", "").strip()
        key_path  = auth.get("mtls_key", "").strip()
        ca_bundle = auth.get("mtls_ca_bundle", "").strip()
        if not cert_path:
            return sess, "ERROR: mtls_cert (path to PEM certificate) is required"
        if not key_path:
            return sess, "ERROR: mtls_key (path to PEM private key) is required"
        import os
        if not os.path.isfile(cert_path):
            return sess, f"ERROR: mtls_cert file not found: {cert_path}"
        if not os.path.isfile(key_path):
            return sess, f"ERROR: mtls_key file not found: {key_path}"
        sess.cert  = (cert_path, key_path)
        if ca_bundle and os.path.isfile(ca_bundle):
            sess.verify = ca_bundle
        return sess, f"mTLS client cert configured: {cert_path}"

    # ── TOTP/HOTP MFA  (form login + second factor) ───────────────────────────
    elif method == "totp_mfa":
        login_url   = auth.get("login_url", "")
        mfa_url     = auth.get("totp_mfa_url", "").strip()
        totp_secret = auth.get("totp_secret", "").strip()
        mfa_field   = auth.get("totp_field", "otp")
        if not login_url:
            return sess, "ERROR: login_url is required for totp_mfa"
        # Step 1: regular form login (with CSRF prefetch)
        resp, post_url = _login_post(sess, auth, timeout)
        if resp is None:
            return sess, f"ERROR: POST to {post_url or login_url} failed (network/timeout)"
        if not resp.ok:
            if resp.status_code == 405:
                return sess, (
                    f"ERROR: POST {post_url} → HTTP 405 Method Not Allowed — "
                    "this URL only accepts GET; check the HTML form action attribute "
                    "for the correct submission endpoint"
                )
            return sess, (
                f"ERROR: POST {post_url} → HTTP {resp.status_code} — "
                "primary login rejected"
            )
        # Step 2: TOTP second factor
        if not mfa_url:
            return sess, (
                f"POST {post_url} → HTTP {resp.status_code} (primary OK); "
                "no totp_mfa_url provided — skipping MFA step"
            )
        if not totp_secret:
            return sess, (
                f"POST {post_url} → HTTP {resp.status_code} (primary OK); "
                "no totp_secret provided — cannot generate OTP"
            )
        try:
            import hmac as _hmac
            import hashlib as _hl
            import struct as _struct
            import time as _time
            import base64 as _b64

            def _totp(secret: str, digits: int = 6, period: int = 30) -> str:
                key = _b64.b32decode(secret.upper().replace(" ", ""))
                t   = int(_time.time()) // period
                msg = _struct.pack(">Q", t)
                h   = _hmac.new(key, msg, _hl.sha1).digest()
                off = h[-1] & 0x0F
                code = (_struct.unpack(">I", h[off:off+4])[0] & 0x7FFFFFFF) % (10 ** digits)
                return str(code).zfill(digits)

            otp = _totp(totp_secret)
            mfa_resp = sess.post(mfa_url, data={mfa_field: otp}, timeout=timeout)
            if not mfa_resp.ok:
                return sess, (
                    f"ERROR: MFA POST {mfa_url} → HTTP {mfa_resp.status_code} — "
                    "second factor rejected (check totp_secret / totp_field)"
                )
            return sess, (
                f"POST {post_url} → HTTP {resp.status_code}; "
                f"MFA POST {mfa_url} → HTTP {mfa_resp.status_code} (OTP accepted)"
            )
        except Exception as exc:
            return sess, f"ERROR: TOTP MFA step failed: {exc}"

    # ── WebAuthn / FIDO2 probe (detection only) ───────────────────────────────
    elif method == "webauthn_probe":
        # Full WebAuthn flows require a browser + hardware authenticator.
        # This method probes for WebAuthn support indicators on the target URL.
        probe_url = auth.get("webauthn_probe_url", "").strip()
        try:
            r = sess.get(probe_url, timeout=timeout) if probe_url else None
        except Exception:
            r = None
        indicators = []
        if r is not None:
            body = r.text
            if "webauthn" in body.lower() or "fido" in body.lower():
                indicators.append("WebAuthn/FIDO keywords in page body")
            if "/.well-known/webauthn" in body or "PublicKeyCredential" in body:
                indicators.append("WebAuthn API reference detected")
            ct = r.headers.get("Content-Type", "")
            if "json" in ct:
                try:
                    j = r.json()
                    if any(k in str(j).lower() for k in ("challenge", "rpid", "allowcredentials")):
                        indicators.append("WebAuthn challenge structure in JSON response")
                except Exception:
                    pass
        if indicators:
            return sess, f"WebAuthn support detected: {'; '.join(indicators)}"
        return sess, "WebAuthn probe complete — no WebAuthn indicators found on target"

    # ── Proxy / Gateway Auth Header ───────────────────────────────────────────
    elif method == "proxy_header":
        hdr_name  = auth.get("proxy_header_name", "X-Remote-User").strip()
        hdr_value = auth.get("proxy_header_value", "").strip()
        if not hdr_value:
            return sess, f"WARNING: no proxy_header_value provided for header '{hdr_name}'"
        sess.headers[hdr_name] = hdr_value
        return sess, f"Proxy auth header set: {hdr_name}: {hdr_value}"

    # ── Auto-Detect ──────────────────────────────────────────────────────────
    elif method == "auto":
        import re as _re
        from urllib.parse import urljoin, urlparse

        login_url  = auth.get("login_url", "").strip()
        has_creds  = bool(auth.get("username"))
        target_url = auth.get("_target_url", "")  # injected by test_connection()
        effective_login = login_url or target_url

        if not has_creds:
            return sess, (
                "ERROR: auto-detect needs credentials in the "
                "Credential Matrix"
            )

        _http_methods = frozenset({"basic", "digest", "ntlm"})
        _LOGIN_PATH_PAT = _re.compile(
            r'/(?:login|signin|sign-in|auth|account/login|session)',
            _re.IGNORECASE,
        )

        # ── Baseline: GET the target without auth ────────────────────────
        # Captures: status, body size, cookies, final URL (after redirects),
        # and the HTML source for API endpoint discovery.
        _baseline_sc:      int = 0
        _baseline_len:     int = 0
        _baseline_loc:     str = ""
        _baseline_final:   str = ""
        _baseline_html:    str = ""
        _baseline_cookies: set[str] = set()
        _baseline_body_len: int = 0  # full response body length (SPA detection)
        if target_url:
            try:
                _bl_sess = _make_session(verify_ssl, proxy)
                # First: no-redirect probe for status/Location
                _bl_resp = _bl_sess.get(target_url, timeout=timeout,
                                        allow_redirects=False)
                _baseline_sc  = _bl_resp.status_code
                _baseline_len = len(_bl_resp.content)
                _baseline_loc = _bl_resp.headers.get("Location", "")
                _baseline_cookies = set(_bl_sess.cookies.keys())
                # Second: follow redirects to capture final URL + HTML
                _bl_resp2 = _bl_sess.get(target_url, timeout=timeout,
                                         allow_redirects=True)
                _baseline_final    = _bl_resp2.url
                _baseline_html     = _bl_resp2.text[:131072]  # 128 KB
                _baseline_body_len = len(_bl_resp2.content)
            except Exception:
                pass

        # Extract an SPA root marker from the baseline HTML.
        # React/Vue/Angular SPAs have a distinctive root element
        # (<div id="root">, <div id="app">, etc.) that appears in
        # every response from the SPA catch-all router.
        _spa_marker: str = ""
        if _baseline_html:
            _spa_root_m = _re.search(
                r'<div\s+id=["\']('
                r'root|app|__next|__nuxt|___gatsby'
                r'|angular-app|blazor-app|main-app'
                r')["\']',
                _baseline_html, _re.IGNORECASE,
            )
            if _spa_root_m:
                _spa_marker = _spa_root_m.group(0)
            else:
                # Fallback: capture the <title> tag as a fingerprint
                _title_m = _re.search(
                    r'<title[^>]*>([^<]{2,100})</title>',
                    _baseline_html, _re.IGNORECASE,
                )
                if _title_m:
                    _spa_marker = _title_m.group(0)

        # ── Discover API login endpoints from page source ────────────────
        _api_login_urls: list[str] = []
        _API_URL_PAT = _re.compile(
            r"""(?:ApiLoginUrl|loginUrl|authUrl|login_url|auth_url"""
            r"""|signInUrl|tokenUrl|token_url|authEndpoint|loginEndpoint)"""
            r"""\s*[=:]\s*["']([^"']+)["']""",
            _re.IGNORECASE,
        )
        _API_PATH_PAT = _re.compile(
            r"""(?:href|action|src)\s*=\s*["']([^"']*"""
            r"""(?:/api/(?:login|auth|token|signin|session)"""
            r"""|/connect/token|/oauth/token)[^"']*)["']""",
            _re.IGNORECASE,
        )
        # Broader: any URL string literal whose path ends at an auth segment
        _JS_AUTH_URL_PAT = _re.compile(
            r"""["'](/(?:[^"'\s/]+/)*"""
            r"""(?:token|login|auth(?:enticate)?"""
            r"""|sign[_-]?in|sessions?"""
            r"""|connect/token|oauth/token"""
            r"""|account/login|identity/token)"""
            r"""(?:/[^"'\s]*)?)["']""",
            _re.IGNORECASE,
        )
        _STATIC_EXT = _re.compile(
            r'\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map)$',
            _re.IGNORECASE,
        )
        # fetch / post / get / put / request calls
        _FETCH_URL_PAT = _re.compile(
            r"""(?:fetch|\.post|\.get|\.put|\.request)\s*\(\s*"""
            r"""["']([^"']+)["']""",
            _re.IGNORECASE,
        )

        def _scan_source_for_api_urls(text: str, base: str) -> None:
            for _m in _API_URL_PAT.finditer(text):
                _c = urljoin(base, _m.group(1))
                if _c not in _api_login_urls:
                    _api_login_urls.append(_c)
            for _m in _API_PATH_PAT.finditer(text):
                _c = urljoin(base, _m.group(1))
                if _c not in _api_login_urls:
                    _api_login_urls.append(_c)
            # Broader: URL literals with auth-related path segments
            for _m in _JS_AUTH_URL_PAT.finditer(text):
                _raw = _m.group(1)
                if _STATIC_EXT.search(_raw):
                    continue
                _c = urljoin(base, _raw)
                if _c not in _api_login_urls:
                    _api_login_urls.append(_c)
            # fetch/post/get calls targeting auth-like paths
            for _m in _FETCH_URL_PAT.finditer(text):
                _raw = _m.group(1)
                if _re.search(
                    r'/(?:token|login|auth|signin|session'
                    r'|account|connect|identity|oauth)',
                    _raw, _re.IGNORECASE,
                ) and not _STATIC_EXT.search(_raw):
                    _c = urljoin(base, _raw)
                    if _c not in _api_login_urls:
                        _api_login_urls.append(_c)

        # Search the inline HTML first
        if _baseline_html:
            _scan_source_for_api_urls(_baseline_html, target_url)

            # Fetch referenced JS files — API login URLs are often in
            # external bundles (e.g. client.bundle.js), not inline HTML.
            _js_refs: list[str] = []
            for _m in _re.finditer(
                r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
                _baseline_html, _re.IGNORECASE,
            ):
                _js_url = urljoin(target_url, _m.group(1))
                _js_refs.append(_js_url)
            # Fetch up to 10 JS files, max 3 MB each — webpack bundles
            # can be large and the config/login URL is often deep inside.
            _bl_js_sess = _make_session(verify_ssl, proxy)
            _js_bodies: list[str] = []
            for _js_url in _js_refs[:10]:
                try:
                    _js_r = _bl_js_sess.get(
                        _js_url, timeout=timeout,
                        headers={"Accept": "*/*"},
                        stream=True,
                    )
                    _js_body = _js_r.content[:3145728].decode(
                        "utf-8", errors="replace")
                    _scan_source_for_api_urls(_js_body, target_url)
                    _js_bodies.append(_js_body)
                except Exception:
                    pass

            # ── API base URL discovery from global config objects ────
            # SPAs often set window.OmtSite = {ApiUrl: "/OMT/Api", ...}
            # and construct login URLs at runtime (ApiUrl + "/Login").
            # Find base URLs and derive login endpoint candidates.
            # Scan ALL source: inline HTML AND fetched JS bundles.
            _API_BASE_PAT = _re.compile(
                r"""(?:ApiUrl|apiUrl|ApiBase|apiBase|apiBaseUrl"""
                r"""|ApiBaseUrl|baseApiUrl|BaseApiUrl|serviceUrl"""
                r"""|ServiceUrl|ServerUrl|serverUrl"""
                r"""|baseUrl|BaseUrl|ClientApiUrl|clientApiUrl"""
                r"""|apiHost|ApiHost|apiRoot|ApiRoot"""
                r"""|REACT_APP_API_URL|VUE_APP_API_URL)"""
                r"""\s*[=:]\s*["']([^"']+)["']""",
                _re.IGNORECASE,
            )
            _AUTH_SUFFIXES = (
                "/Login", "/login",
                "/Token", "/token",
                "/Account/Login", "/account/login",
                "/Account/Authenticate", "/account/authenticate",
                "/Auth/Login", "/auth/login",
                "/Auth/Token", "/auth/token",
                "/Auth/Authenticate", "/auth/authenticate",
                "/Authenticate", "/authenticate",
                "/Session", "/session",
                "/Users/Login", "/users/login",
                "/Identity/Token", "/identity/token",
                "/Connect/Token", "/connect/token",
                "/Security/Login", "/security/login",
            )
            _all_sources = [_baseline_html] + _js_bodies
            _api_bases_found: list[str] = []
            for _src_chunk in _all_sources:
                if not _src_chunk:
                    continue
                for _bm in _API_BASE_PAT.finditer(_src_chunk):
                    _bval = _bm.group(1).rstrip("/")
                    if _bval and not _STATIC_EXT.search(_bval):
                        _base_full = urljoin(target_url, _bval)
                        if _base_full not in _api_bases_found:
                            _api_bases_found.append(_base_full)
                # Global config objects: window.XyzSite = {...} or
                # global.XyzSite = {...}.  Allow up to 8KB for the
                # object body (webpack can emit large configs).  Also
                # match const/var/let config assignments in JS bundles:
                # const OmtConfig = {ApiUrl: "...",...}
                for _cfg_m in _re.finditer(
                    r"""(?:"""
                    r"""(?:window|global)\.(\w+)\s*=\s*\{"""
                    r"""|(?:const|var|let)\s+(\w+)\s*=\s*\{"""
                    r""")([^}]{10,8000})\}""",
                    _src_chunk,
                ):
                    _cfg_name = _cfg_m.group(1) or _cfg_m.group(2) or ""
                    _cfg_body = _cfg_m.group(3)
                    # Extract URL-valued properties from the config
                    for _val_m in _re.finditer(
                        r"""["']((?:https?://[^"']+)|(?:/[^"']+))["']""",
                        _cfg_body,
                    ):
                        _cval = _val_m.group(1).rstrip("/")
                        if (not _STATIC_EXT.search(_cval)
                                and ('api' in _cval.lower()
                                     or 'service' in _cval.lower()
                                     or 'auth' in _cval.lower())):
                            _base_full = urljoin(target_url, _cval)
                            if _base_full not in _api_bases_found:
                                _api_bases_found.append(_base_full)
            # Derive login endpoints from discovered base URLs
            for _api_base in _api_bases_found:
                for _suf in _AUTH_SUFFIXES:
                    _c = _api_base + _suf
                    if _c not in _api_login_urls:
                        _api_login_urls.append(_c)

        # ── OpenID Connect / OAuth well-known discovery ─────────────────
        if target_url:
            _tp = urlparse(target_url)
            _path_parts = [p for p in _tp.path.split("/") if p]
            _app_root = ("/" + _path_parts[0] + "/"
                         if _path_parts else "/")
            _wk_sess = _make_session(verify_ssl, proxy)
            for _wk_base in (_app_root, "/"):
                _wk_url = (f"{_tp.scheme}://{_tp.netloc}"
                           f"{_wk_base}.well-known/openid-configuration")
                try:
                    _wk_r = _wk_sess.get(_wk_url, timeout=5)
                    if _wk_r.ok:
                        _wk = _wk_r.json()
                        for _ek in ("token_endpoint",
                                    "authorization_endpoint"):
                            _ev = _wk.get(_ek, "")
                            if _ev and _ev not in _api_login_urls:
                                _api_login_urls.append(_ev)
                except Exception:
                    pass

        # Heuristic: derive API path variants from the URL structure.
        # Always runs (supplements JS-discovered and config-derived URLs).
        if target_url:
            _tp = urlparse(target_url)
            _path_parts = [p for p in _tp.path.split("/") if p]
            # Replace middle segment with "Api"/"api"
            if len(_path_parts) >= 2:
                for _api_seg in ("Api", "api"):
                    _try_parts = list(_path_parts)
                    _try_parts[-2] = _api_seg
                    _try_path = "/" + "/".join(_try_parts)
                    _c = f"{_tp.scheme}://{_tp.netloc}{_try_path}"
                    if _c not in _api_login_urls:
                        _api_login_urls.append(_c)
                # Insert "api"/"Api" before the last segment
                for _api_insert in ("api", "Api"):
                    _try_parts = list(_path_parts)
                    _try_parts.insert(-1, _api_insert)
                    _try_path = "/" + "/".join(_try_parts)
                    _c = f"{_tp.scheme}://{_tp.netloc}{_try_path}"
                    if _c not in _api_login_urls:
                        _api_login_urls.append(_c)
                # Replace last segment with auth alternatives
                for _last in ("Token", "token", "Authenticate",
                              "authenticate", "Session"):
                    _try_parts = list(_path_parts)
                    _try_parts[-1] = _last
                    _try_path = "/" + "/".join(_try_parts)
                    _c = f"{_tp.scheme}://{_tp.netloc}{_try_path}"
                    if _c not in _api_login_urls:
                        _api_login_urls.append(_c)
            # Common paths at app root
            _app_root = ("/" + _path_parts[0] + "/"
                         if _path_parts else "/")
            for _suffix in ("api/login", "api/auth", "api/token",
                            "Api/Login", "Api/Auth",
                            "Token", "token",
                            "Account/Login", "account/login",
                            "Auth/Token", "auth/token",
                            "Auth/Login", "auth/login",
                            "Connect/Token", "connect/token",
                            "Identity/Token", "identity/token",
                            "api/authenticate", "api/Account/Login",
                            "Api/Account/Login", "Api/Auth/Login",
                            "Api/Auth/Token", "Api/Token",
                            "Api/Session", "Api/Users/Login"):
                _c = f"{_tp.scheme}://{_tp.netloc}{_app_root}{_suffix}"
                if _c not in _api_login_urls:
                    _api_login_urls.append(_c)

        def _is_login_redirect(final_url: str) -> bool:
            """True if the final URL looks like a login page (redirect-to-self)."""
            if not final_url:
                return False
            _fp = urlparse(final_url).path.rstrip("/")
            if _LOGIN_PATH_PAT.search(_fp):
                return True
            # Compare against baseline: if unauthenticated GET also landed
            # on this URL, we're right back where we started
            if _baseline_final and final_url.rstrip("/") == _baseline_final.rstrip("/"):
                return True
            return False

        def _verify_session(s: "requests.Session", method_name: str
                            ) -> "tuple[bool, str]":
            """GET the target URL with the supposedly-authenticated session.
            Returns (success, detail)."""
            if not target_url:
                return True, "no target URL to verify against"
            try:
                _vr = s.get(target_url, timeout=timeout, allow_redirects=True)
                _new_ck = set(s.cookies.keys()) - _baseline_cookies
                # New auth cookies are the strongest signal — check first.
                # SPAs serve the same HTML from every URL, so URL-based
                # detection ("redirected back to login") is unreliable when
                # the SPA catch-all always returns a path containing /login.
                if _new_ck:
                    return True, (
                        f"HTTP {_vr.status_code}, "
                        f"{len(_new_ck)} new cookie(s): "
                        + ", ".join(sorted(_new_ck)))
                # No new cookies — check URL for redirect-to-login
                if _is_login_redirect(_vr.url):
                    return False, (
                        f"redirected back to login page: {_vr.url}")
                # Same page as unauthenticated baseline = auth had no effect
                if (abs(len(_vr.content) - _baseline_len) < 256
                        and _vr.status_code == _baseline_sc):
                    return False, (
                        "response identical to unauthenticated baseline")
                return True, (
                    f"HTTP {_vr.status_code} at {_vr.url}")
            except Exception as _e:
                return False, str(_e)

        # ── Build method order ───────────────────────────────────────────
        _auto_order: list[str] = []
        if effective_login:
            _auto_order.extend(["form_login", "token_login"])
        _auto_order.extend(["basic", "digest", "ntlm"])

        _errors: list[str] = []
        _tried_api_urls: set[str] = set()

        for _am in _auto_order:
            _auto_auth = dict(auth)
            _auto_auth["method"] = _am
            if _am in ("form_login", "token_login") and effective_login:
                _auto_auth["login_url"] = effective_login

            _auto_sess, _auto_info = build_auth_session(
                _auto_auth, timeout, proxy, verify_ssl)

            if _auto_info.startswith("ERROR:"):
                _errors.append(f"{_am} ({effective_login}): {_auto_info}")
                continue

            # Extract the POST URL from the info string
            _post_url = effective_login
            _post_m = _re.search(r'POST\s+(\S+)', _auto_info)
            if _post_m:
                _post_url = _post_m.group(1)

            if _am in ("form_login", "token_login"):
                # Verify: GET target with session — did we actually auth?
                _ok, _detail = _verify_session(_auto_sess, _am)
                if _ok:
                    return _auto_sess, (
                        f"auto-detect → {_am} ({_post_url}): "
                        f"{_auto_info} — verified: {_detail}")
                _errors.append(f"{_am} ({_post_url}): {_detail}")
                _tried_api_urls.add((effective_login or "").rstrip("/"))
                continue

            # For HTTP auth methods, compare authenticated GET against baseline
            if _am in _http_methods and target_url:
                try:
                    _vr = _auto_sess.get(target_url, timeout=timeout,
                                         allow_redirects=False)
                    _auth_sc  = _vr.status_code
                    _auth_len = len(_vr.content)
                    _auth_loc = _vr.headers.get("Location", "")

                    if _auth_sc in (401, 403):
                        _errors.append(
                            f"{_am}: HTTP {_auth_sc} — rejected")
                        continue

                    _diff_reasons: list[str] = []
                    _new_cookies = (set(_auto_sess.cookies.keys())
                                    - _baseline_cookies)
                    if _new_cookies:
                        _diff_reasons.append(
                            f"{len(_new_cookies)} new cookie(s): "
                            + ", ".join(sorted(_new_cookies)))
                    if _auth_sc != _baseline_sc:
                        _diff_reasons.append(
                            f"status {_baseline_sc}→{_auth_sc}")
                    if _auth_loc != _baseline_loc and _auth_loc:
                        _diff_reasons.append(
                            f"redirect→{_auth_loc[:60]}")
                    if abs(_auth_len - _baseline_len) > 256:
                        _diff_reasons.append(
                            f"body size {_baseline_len}→{_auth_len}")

                    if _diff_reasons:
                        return _auto_sess, (
                            f"auto-detect → {_am}: HTTP {_auth_sc} — "
                            + ", ".join(_diff_reasons))

                    _errors.append(
                        f"{_am}: HTTP {_auth_sc} — response identical "
                        "to unauthenticated baseline")
                except Exception as _exc:
                    _errors.append(f"{_am}: {_exc}")
                continue
            return _auto_sess, f"auto-detect → {_am}: {_auto_info}"

        # ── Phase 2: try discovered API login endpoints ──────────────────
        # Try API login URLs from JS source, config objects, OIDC
        # well-known, and path heuristics.  Pre-filter with a quick
        # GET probe to skip 404s and avoid slow auth attempts.
        if _api_login_urls:
            _probe_sess = _make_session(verify_ssl, proxy)
            _live_urls: list[str] = []
            for _pu in _api_login_urls:
                _pu_norm = _pu.rstrip("/")
                if _pu_norm in _tried_api_urls:
                    continue
                try:
                    _pr = _probe_sess.get(
                        _pu, timeout=5, allow_redirects=True)
                    if _pr.status_code == 404:
                        _tried_api_urls.add(_pu_norm)
                        continue  # URL doesn't exist — skip
                    # SPA catch-all detection.  A real API endpoint
                    # returns application/json (or similar); the SPA
                    # catch-all returns text/html containing the same
                    # root element/title as the baseline page.
                    _pr_ct = _pr.headers.get(
                        "Content-Type", "").lower()
                    if "text/html" in _pr_ct and _spa_marker:
                        _pr_text = _pr.text[:8192]
                        if _spa_marker in _pr_text:
                            _tried_api_urls.add(_pu_norm)
                            continue  # SPA catch-all — skip
                    # Also catch by body size when we have no marker
                    # but the response is HTML and nearly identical.
                    if ("text/html" in _pr_ct
                            and _baseline_body_len
                            and abs(len(_pr.content)
                                    - _baseline_body_len) < 2048):
                        _tried_api_urls.add(_pu_norm)
                        continue  # likely SPA catch-all — skip
                except Exception:
                    pass
                _live_urls.append(_pu)

            for _api_url in _live_urls:
                if _api_url.rstrip("/") in _tried_api_urls:
                    continue
                _tried_api_urls.add(_api_url.rstrip("/"))
                for _api_method in ("token_login", "form_login"):
                    _api_auth = dict(auth)
                    _api_auth["method"] = _api_method
                    _api_auth["login_url"] = _api_url
                    # API endpoints typically expect JSON
                    if _api_method == "token_login":
                        _api_auth["login_content_type"] = "application/json"
                    _api_sess, _api_info = build_auth_session(
                        _api_auth, timeout, proxy, verify_ssl)
                    if _api_info.startswith("ERROR:"):
                        _errors.append(
                            f"{_api_method} (discovered: {_api_url}): "
                            f"{_api_info}")
                        continue
                    _ok, _detail = _verify_session(_api_sess, _api_method)
                    if _ok:
                        return _api_sess, (
                            f"auto-detect → {_api_method} "
                            f"(discovered API: {_api_url}): "
                            f"{_api_info} — verified: {_detail}")
                    _errors.append(
                        f"{_api_method} (discovered: {_api_url}): {_detail}")

        return sess, "ERROR: auto-detect exhausted all methods — " + "; ".join(_errors)

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
    # Inject target URL for auto-detect's 401 probe
    auth["_target_url"] = url
    sess, auth_info = build_auth_session(auth, timeout, proxy, verify_ssl)
    auth_method = (auth.get("method") or auth.get("auth_method") or auth.get("auth_type") or "form_login").strip().lower()

    # ── Auto-detect: build_auth_session already ran the full test loop ────────
    if auth_method == "auto":
        failed = auth_info.startswith("ERROR:")
        result = {
            "success":     not failed,
            "message":     auth_info,
            "status_code": None,
            "auth_info":   auth_info,
        }
        # When auto-detect discovers a working endpoint, return its
        # method and URL so the caller (Crucible) can persist them —
        # fracture.py can then use the proven endpoint directly
        # instead of re-running the discovery.
        if not failed:
            import re as _re2
            _disc_m = _re2.search(
                r'auto-detect\s*→\s*(\w+)', auth_info)
            _disc_u = _re2.search(
                r'(?:discovered API:\s*|→\s*\w+\s*\()'
                r'(https?://\S+?)[\s):]',
                auth_info)
            if _disc_m:
                result["discovered_method"] = _disc_m.group(1)
            if _disc_u:
                result["discovered_login_url"] = _disc_u.group(1)
            # testConnection always defaults to application/json for
            # login POSTs.  Surface that so the caller (Crucible Apply
            # button) can set Fracture's content-type to match.
            if result.get("discovered_login_url"):
                result["discovered_content_type"] = "application/json"
        return result

    # ── Login-based methods: POST result is the definitive answer ─────────────
    if auth_method in ("form_login", "token_login", "totp_mfa", "saml_assertion"):
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

    # ── session_cookie / kerberos / kerberos_delegation: probe with GET ─────
    if auth_method in ("session_cookie", "kerberos", "kerberos_delegation"):
        try:
            resp = sess.request("GET", url, timeout=timeout)
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
# AuthProbe integration
# ─────────────────────────────────────────────────────────────────────────────

def run_probe(url: str, timeout: int, proxy: str, verify_ssl: bool) -> dict:
    """Run AuthProbe against the URL and return its result dict."""
    try:
        import sys as _sys
        _ap_path = "/opt/pr0t31n/AuthProbe"
        if _ap_path not in _sys.path:
            _sys.path.insert(0, _ap_path)
        from authprobe import AuthProbe  # type: ignore[import]
        ap = AuthProbe(timeout=timeout, proxy=proxy, verify_ssl=verify_ssl)
        return ap.probe(url)
    except ImportError:
        return {"error": "AuthProbe not available at /opt/pr0t31n/AuthProbe"}
    except Exception as exc:
        return {"error": str(exc)}


def _print_probe_result(result: dict) -> None:
    print(f"\n[AuthProbe] URL type  : {result.get('url_type','?')} "
          f"(confidence {result.get('url_type_confidence',0)}%)")
    sw = result.get("software", [])
    if sw:
        for s in sw:
            print(f"[AuthProbe] Software  : {s['name']} (conf {s.get('confidence',0)}%)")
    methods = result.get("auth_methods", [])
    if methods:
        print("[AuthProbe] Auth methods detected:")
        for m in methods:
            print(f"  • {m['method']:<25} confidence={m.get('confidence',0)}% — {m.get('reason','')}")
    recs = result.get("recommendations", [])
    if recs:
        print(f"[AuthProbe] Recommendation: {recs[0]}")
    print()


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
    ap.add_argument("--probe",        action="store_true",
                    help="Run AuthProbe to auto-detect auth method for the URL")
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
    ap.add_argument("--oauth-client-auth",   metavar="METHOD", choices=["body", "basic"],
                    default="body", help="OAuth2 client auth method: body (default) or basic")

    # OAuth 1.0a
    ap.add_argument("--oauth1-consumer-key",    metavar="KEY",    help="OAuth 1.0a consumer key")
    ap.add_argument("--oauth1-consumer-secret", metavar="SECRET", help="OAuth 1.0a consumer secret")
    ap.add_argument("--oauth1-access-token",    metavar="TOKEN",  help="OAuth 1.0a access token")
    ap.add_argument("--oauth1-token-secret",    metavar="SECRET", help="OAuth 1.0a token secret")

    # SAML
    ap.add_argument("--saml-acs-url",    metavar="URL",      help="SAML ACS (AssertionConsumerService) URL")
    ap.add_argument("--saml-assertion",  metavar="BASE64",   help="Base64-encoded SAMLResponse assertion")
    ap.add_argument("--saml-relay-state",metavar="VALUE",    help="SAML RelayState (optional)")

    # OIDC
    ap.add_argument("--oidc-id-token",    metavar="TOKEN",   help="Pre-obtained OIDC id_token")
    ap.add_argument("--oidc-userinfo-url",metavar="URL",     help="OIDC userinfo endpoint URL")

    # mTLS
    ap.add_argument("--mtls-cert",      metavar="FILE",  help="PEM client certificate file (mTLS)")
    ap.add_argument("--mtls-key",       metavar="FILE",  help="PEM private key file (mTLS)")
    ap.add_argument("--mtls-ca-bundle", metavar="FILE",  help="PEM CA bundle for server verification (mTLS)")

    # TOTP MFA
    ap.add_argument("--totp-secret",    metavar="SECRET", help="Base32 TOTP secret for MFA")
    ap.add_argument("--totp-mfa-url",   metavar="URL",    help="URL to POST the TOTP OTP code")
    ap.add_argument("--totp-field",     metavar="FIELD",  default="otp",
                    help="Form field name for OTP submission (default: otp)")

    # WebAuthn probe
    ap.add_argument("--webauthn-probe-url", metavar="URL",
                    help="URL to probe for WebAuthn/FIDO2 support indicators")

    # Kerberos delegation
    ap.add_argument("--kerberos-impersonate", metavar="PRINCIPAL",
                    help="Service principal to impersonate (Kerberos S4U2Proxy delegation)")

    # API key
    ap.add_argument("--api-key",        metavar="KEY",  help="API key value")
    ap.add_argument("--api-key-header", metavar="HDR",  default="X-API-Key",
                    help="Header name for apikey_header (default: X-API-Key)")
    ap.add_argument("--api-key-cookie", metavar="NAME",
                    help="Cookie name for apikey_cookie")

    # Proxy / gateway auth header
    ap.add_argument("--proxy-header-name",  metavar="HDR",   default="X-Remote-User",
                    help="Proxy auth header name (default: X-Remote-User)")
    ap.add_argument("--proxy-header-value", metavar="VALUE",
                    help="Value to inject into the proxy auth header")

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
    if args.oauth_token_url:          auth["oauth_token_url"]        = args.oauth_token_url
    if args.oauth_client_id:          auth["oauth_client_id"]        = args.oauth_client_id
    if args.oauth_client_secret:      auth["oauth_client_secret"]    = args.oauth_client_secret
    if args.oauth_scope:              auth["oauth_scope"]             = args.oauth_scope
    if args.oauth_client_auth:        auth["client_auth_method"]     = args.oauth_client_auth
    if args.oauth1_consumer_key:      auth["oauth1_consumer_key"]    = args.oauth1_consumer_key
    if args.oauth1_consumer_secret:   auth["oauth1_consumer_secret"] = args.oauth1_consumer_secret
    if args.oauth1_access_token:      auth["oauth1_access_token"]    = args.oauth1_access_token
    if args.oauth1_token_secret:      auth["oauth1_token_secret"]    = args.oauth1_token_secret
    if args.saml_acs_url:             auth["saml_acs_url"]           = args.saml_acs_url
    if args.saml_assertion:           auth["saml_assertion"]         = args.saml_assertion
    if args.saml_relay_state:         auth["saml_relay_state"]       = args.saml_relay_state
    if args.oidc_id_token:            auth["oidc_id_token"]          = args.oidc_id_token
    if args.oidc_userinfo_url:        auth["oidc_userinfo_url"]      = args.oidc_userinfo_url
    if args.mtls_cert:                auth["mtls_cert"]              = args.mtls_cert
    if args.mtls_key:                 auth["mtls_key"]               = args.mtls_key
    if args.mtls_ca_bundle:           auth["mtls_ca_bundle"]         = args.mtls_ca_bundle
    if args.totp_secret:              auth["totp_secret"]            = args.totp_secret
    if args.totp_mfa_url:             auth["totp_mfa_url"]           = args.totp_mfa_url
    if args.totp_field:               auth["totp_field"]             = args.totp_field
    if args.webauthn_probe_url:       auth["webauthn_probe_url"]     = args.webauthn_probe_url
    if args.kerberos_impersonate:     auth["kerberos_impersonate"]   = args.kerberos_impersonate
    if args.api_key:                  auth["api_key"]                = args.api_key
    if args.api_key_header:           auth["api_key_header"]         = args.api_key_header
    if args.api_key_cookie:           auth["api_key_cookie"]         = args.api_key_cookie
    if args.proxy_header_name:        auth["proxy_header_name"]      = args.proxy_header_name
    if args.proxy_header_value:       auth["proxy_header_value"]     = args.proxy_header_value
    if args.no_verify:                verify_ssl                     = False

    if not url:
        print(
            "ERROR: no URL specified. Use --url, --settings FILE, or --json '{...}'.",
            file=sys.stderr,
        )
        sys.exit(1)

    # ── AuthProbe ────────────────────────────────────────────────────────────
    if args.probe:
        probe_result = run_probe(url, timeout, proxy, verify_ssl)
        if args.output_json:
            print(json.dumps({"probe": probe_result}))
            sys.exit(0)
        _print_probe_result(probe_result)
        if not auth.get("method"):
            methods = probe_result.get("auth_methods", [])
            if methods:
                suggested = methods[0]["method"]
                auth["method"] = suggested
                print(f"[AuthProbe] Using suggested method: {suggested}\n")

    if not auth.get("method"):
        auth["method"] = auth.get("auth_method") or "form_login"

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
