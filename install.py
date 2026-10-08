#!/usr/bin/env python3
"""
Fracture — Web Application Penetration Testing Orchestrator
Install script
Location: /Users/pr0t31n/Fracture/
Symlinks: fracture → fracture.py
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
import urllib.request

# ---------------------------------------------------------------------------
# ANSI colours
# ---------------------------------------------------------------------------
R  = "\033[1;31m"
G  = "\033[1;32m"
Y  = "\033[1;33m"
B  = "\033[1;34m"
C  = "\033[1;36m"
W  = "\033[0m"


def banner(msg):   print(f"\n{B}{'='*60}{W}\n{C}  {msg}{W}\n{B}{'='*60}{W}")
def info(msg):     print(f"{G}[+]{W} {msg}")
def warn(msg):     print(f"{Y}[!]{W} {msg}")
def error(msg):    print(f"{R}[x]{W} {msg}")
def step(msg):     print(f"{B}[>]{W} {msg}")


# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------
def detect_os():
    system = platform.system()
    if system == "Darwin":
        return "macos"
    if system == "Windows":
        return "windows"
    try:
        with open("/etc/os-release") as f:
            data = f.read().lower()
    except FileNotFoundError:
        return "linux-unknown"
    if "kali" in data or "debian" in data or "ubuntu" in data:
        return "apt"
    if "rhel" in data or "centos" in data or "rocky" in data or "fedora" in data:
        return "dnf"
    if "suse" in data or "opensuse" in data:
        return "zypper"
    return "linux-unknown"


OS = detect_os()


# ---------------------------------------------------------------------------
# Privilege helpers
# ---------------------------------------------------------------------------
def is_root():
    return os.getuid() == 0 if hasattr(os, "getuid") else False


def get_sudo_user():
    return os.environ.get("SUDO_USER", "")


def require_root():
    """Ensure the installer runs with root/admin privileges.

    On Unix: re-executes the script under sudo if not already root.
    On Windows: checks for Administrator rights and exits with guidance.
    """
    if platform.system() == "Windows":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                error("This installer requires Administrator privileges.")
                error("Right-click the terminal and choose 'Run as administrator'.")
                sys.exit(1)
        except Exception:
            warn("Could not verify Windows admin status — continuing.")
        return
    if not is_root():
        warn("Installer requires root privileges. Re-running with sudo ...")
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def run(cmd, check=True, capture=False, env=None, cwd=None):
    step(" ".join(cmd) if isinstance(cmd, list) else cmd)
    kwargs = dict(check=check)
    if capture:
        kwargs["capture_output"] = True
        kwargs["text"] = True
    if env:
        kwargs["env"] = env
    if cwd:
        kwargs["cwd"] = cwd
    return subprocess.run(cmd, **kwargs)


# ---------------------------------------------------------------------------
# Pre-install guards
# ---------------------------------------------------------------------------
def _pip_installed(pkg_spec):
    import importlib.util
    name = pkg_spec.split(">=")[0].split("==")[0].split("[")[0].split("<")[0].strip()
    _IMPORT_MAP = {
        "python-nmap": "nmap", "beautifulsoup4": "bs4", "python-docx": "docx",
        "python-whois": "whois", "Pillow": "PIL", "pyOpenSSL": "OpenSSL",
        "dnspython": "dns", "pyyaml": "yaml", "scikit-learn": "sklearn",
        "python-dateutil": "dateutil", "python-magic": "magic",
        "flask-socketio": "flask_socketio", "flask-cors": "flask_cors",
        "python-engineio": "engineio", "python-socketio": "socketio",
        "charset-normalizer": "charset_normalizer",
        "ruamel.yaml": "ruamel", "lxml-html-clean": "lxml_html_clean",
        "pyserial": "serial", "python-can": "can",
        "python-multipart": "multipart", "graphql-core": "graphql",
        "sqlmap": "sqlmap",
    }
    mod = _IMPORT_MAP.get(name, name.replace("-", "_"))
    return importlib.util.find_spec(mod) is not None


def _brew_installed_set():
    try:
        r = subprocess.run(["brew", "list", "--formula", "-1"],
                           capture_output=True, text=True, timeout=15)
        return set(r.stdout.split())
    except Exception:
        return set()


# ---------------------------------------------------------------------------
# brew helper — NEVER run as root
# ---------------------------------------------------------------------------
def brew_install(pkg):
    brew_path = shutil.which("brew")
    if not brew_path:
        for p in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]:
            if os.path.isfile(p):
                brew_path = p
                break
    if not brew_path:
        warn(f"brew not found — skipping {pkg}")
        return
    cmd = [brew_path, "install", pkg]
    if is_root():
        sudo_user = get_sudo_user()
        if not sudo_user:
            warn(f"Running as root without SUDO_USER — cannot run brew safely. Skipping {pkg}.")
            return
        cmd = ["sudo", "-u", sudo_user] + cmd
    run(cmd, check=False)


# ---------------------------------------------------------------------------
# Package managers
# ---------------------------------------------------------------------------
_apt_updated = False


def apt_install(packages):
    global _apt_updated
    if not _apt_updated:
        info("Running apt update ...")
        run(["apt-get", "update", "-y"])
        _apt_updated = True
    run(["apt-get", "install", "-y"] + packages)


def apt_install_optional(packages):
    """Install each package individually — never fail the whole install.

    Used for packages whose names vary across Debian/Ubuntu/Kali releases
    (e.g. firefox vs firefox-esr) or that may be missing from a given apt
    source list. A missing optional package emits a warning and continues.
    """
    global _apt_updated
    if not _apt_updated:
        info("Running apt update ...")
        run(["apt-get", "update", "-y"], check=False)
        _apt_updated = True
    for pkg in packages:
        try:
            run(["apt-get", "install", "-y", pkg], check=True)
            info(f"  installed (optional): {pkg}")
        except subprocess.CalledProcessError:
            warn(f"  optional package not available: {pkg} — skipping")


def dnf_install(packages):
    run(["dnf", "install", "-y"] + packages)


def dnf_install_optional(packages):
    for pkg in packages:
        try:
            run(["dnf", "install", "-y", pkg], check=True)
            info(f"  installed (optional): {pkg}")
        except subprocess.CalledProcessError:
            warn(f"  optional package not available: {pkg} — skipping")


def zypper_install(packages):
    run(["zypper", "install", "-y"] + packages)


# ---------------------------------------------------------------------------
# System packages
# ---------------------------------------------------------------------------
APT_PACKAGES = [
    "gobuster", "nikto", "sqlmap", "sslscan", "whatweb",
    "feroxbuster", "ffuf", "exploitdb",
    "python3-pip", "python3-dev",
    "git", "golang-go",
    "ruby", "ruby-dev", "ruby-bundler",
    "libssl-dev", "libcurl4-openssl-dev",
    # Java 17+ runtime required by OWASP ZAP (21 is current on Kali)
    "openjdk-21-jre-headless",
    # Headless browser for SPA crawl (chromium-driver provides chromedriver)
    "chromium", "chromium-driver",
    # mitmproxy via apt (pip build fails on ARM/Pi — Rust native deps)
    "mitmproxy",
]
# Best-effort browsers/drivers — names vary across distros and releases.
# Kali ships firefox-esr (not firefox) and geckodriver (no firefox- prefix).
# Older Debian/Ubuntu use firefox-geckodriver. Try each; tolerate misses.
APT_PACKAGES_OPTIONAL = [
    "firefox-esr", "firefox", "geckodriver", "firefox-geckodriver",
]
DNF_PACKAGES = [
    "nikto", "sqlmap", "sslscan", "whatweb", "ffuf",
    "python3-pip", "python3-devel",
    "git", "golang",
    "ruby", "ruby-devel",
    "openssl-devel", "libcurl-devel",
    # Java 17+ runtime required by OWASP ZAP
    "java-21-openjdk-headless",
    # Headless browser for SPA crawl
    "chromium", "chromedriver",
    "mitmproxy",
]
DNF_PACKAGES_OPTIONAL = [
    "firefox", "geckodriver",
]
BREW_PACKAGES = [
    "gobuster", "nikto", "sslscan", "git",
    "ffuf", "feroxbuster", "exploitdb",
    # Java 17+ runtime required by OWASP ZAP
    "openjdk",
    # Headless browser for SPA crawl (chromedriver auto-managed via webdriver-manager)
    "chromium",
    # Firefox fallback for SPA crawl
    "geckodriver",
]


def install_system():
    banner("Phase: system packages")
    if OS == "apt":
        apt_install(APT_PACKAGES)
        info("Installing optional Firefox / geckodriver (Chromium remains primary)...")
        apt_install_optional(APT_PACKAGES_OPTIONAL)
    elif OS == "dnf":
        dnf_install(DNF_PACKAGES)
        info("Installing optional Firefox / geckodriver (Chromium remains primary)...")
        dnf_install_optional(DNF_PACKAGES_OPTIONAL)
    elif OS == "zypper":
        zypper_install(["nikto", "python3-pip", "git", "golang", "ruby"])
    elif OS == "macos":
        try:
            _brew_path = shutil.which("brew") or "/opt/homebrew/bin/brew"
            _installed = set(subprocess.run(
                [_brew_path, "list", "--formula", "-1"],
                capture_output=True, text=True, check=True).stdout.strip().splitlines())
        except (subprocess.CalledProcessError, FileNotFoundError):
            _installed = set()
        _missing = [p for p in BREW_PACKAGES if p not in _installed]
        for p in BREW_PACKAGES:
            if p in _installed:
                info(f"✓ {p} already installed")
        if _missing:
            info(f"Installing brew packages: {' '.join(_missing)}")
            for pkg in _missing:
                brew_install(pkg)
        else:
            info("All brew packages already installed.")
    elif OS == "windows":
        warn("Windows: install tools manually — gobuster, nikto, sqlmap, sslscan.")
    else:
        warn(f"Unknown OS '{OS}' — skipping system packages.")


# ---------------------------------------------------------------------------
# pip
# ---------------------------------------------------------------------------
PIP_PACKAGES = [
    "requests>=2.28.0",
    "colorama>=0.4.6",
    "beautifulsoup4>=4.12.0",
    "sqlmap",
    "termcolor>=2.0.0",
    "dnspython>=2.4.0",
]

OFFLINE_BUNDLE_URLS = {
    "beautifulsoup4": "https://raw.githubusercontent.com/pr0t31n/OfflineInstallers/main/beautifulsoup4_offline_kali.tar.gz",
    "selenium":       "https://raw.githubusercontent.com/pr0t31n/OfflineInstallers/main/selenium_offline_kali.tar.gz",
    "sqlmap":         "https://raw.githubusercontent.com/pr0t31n/OfflineInstallers/main/sqlmap_offline_kali.tar.gz",
    "dalfox":         "https://raw.githubusercontent.com/pr0t31n/OfflineInstallers/main/dalfox_offline_kali.tar.gz",
}

_OFFLINE_REPO_DIR = "/opt/OfflineInstallers"
_OFFLINE_REPO_URL = "https://github.com/pr0t31n/OfflineInstallers"

GIT_PIP_URLS = {
    "termcolor": "https://github.com/termcolor/termcolor",
}


def _install_from_git_pip(pkg_name: str, repo_url: str) -> bool:
    """Clone a Python package from GitHub and install it with pip."""
    _git = shutil.which("git")
    if not _git:
        warn(f"git not found — cannot install {pkg_name} from source")
        return False
    info(f"Installing {pkg_name} from git source ...")
    _clone_dir = f"/tmp/_gitpip_{pkg_name}"
    if os.path.isdir(_clone_dir):
        shutil.rmtree(_clone_dir, ignore_errors=True)
    r_clone = subprocess.run([_git, "clone", "--depth=1", repo_url, _clone_dir], check=False)
    if r_clone.returncode != 0:
        warn(f"git clone failed for {pkg_name}")
        shutil.rmtree(_clone_dir, ignore_errors=True)
        return False
    r_pip = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--break-system-packages", _clone_dir],
        check=False,
    )
    shutil.rmtree(_clone_dir, ignore_errors=True)
    if r_pip.returncode == 0:
        info(f"{pkg_name} installed from git source")
        return True
    warn(f"git source install failed for {pkg_name}")
    return False


def _install_from_local_repo(pkg_name: str, tarball: str) -> bool:
    """Copy/reassemble a bundle from the already-cloned OfflineInstallers repo.
    Returns True if *tarball* was written successfully."""
    _local_tar = os.path.join(_OFFLINE_REPO_DIR, f"{pkg_name}_offline_kali.tar.gz")
    if os.path.isfile(_local_tar):
        shutil.copy2(_local_tar, tarball)
        return True
    _repo_parts = sorted([
        os.path.join(_OFFLINE_REPO_DIR, f)
        for f in os.listdir(_OFFLINE_REPO_DIR)
        if f.startswith(f"{pkg_name}_offline_kali.part.")
    ])
    if _repo_parts:
        info(f"  Reassembling {len(_repo_parts)} part(s) from cloned repo ...")
        with open(tarball, "wb") as _out:
            for _p in _repo_parts:
                with open(_p, "rb") as _f:
                    _out.write(_f.read())
        return True
    warn(f"{pkg_name} not found in cloned OfflineInstallers repo")
    return False


def _install_from_bundle(pkg_name: str, url: str) -> bool:
    """Download a pre-built offline bundle from GitHub and run install_offline.sh.
    Handles both single .tar.gz files and split .part.* files.
    If the OfflineInstallers repo is already cloned at /opt/OfflineInstallers, installs
    directly from there without attempting any network downloads."""
    _tmp = f"/tmp/_offline_bundle_{pkg_name}"
    if os.path.isdir(_tmp):
        shutil.rmtree(_tmp, ignore_errors=True)
    os.makedirs(_tmp)
    _tarball = os.path.join(_tmp, f"{pkg_name}_offline_kali.tar.gz")
    _downloaded = False

    # Fast path: OfflineInstallers repo already cloned — skip all network attempts
    if os.path.isdir(os.path.join(_OFFLINE_REPO_DIR, ".git")):
        info(f"OfflineInstallers repo already cloned — installing {pkg_name} directly ...")
        _downloaded = _install_from_local_repo(pkg_name, _tarball)
    else:
        info(f"Downloading offline bundle for {pkg_name} ...")
        try:
            urllib.request.urlretrieve(url, _tarball)
            _downloaded = True
        except Exception:
            # Single file unavailable — try split parts (.part.aa, .part.ab, ...)
            _base = url.rsplit("/", 1)[0]
            _parts = []
            _found_gap = False
            for _a in "abcdefghijklmnopqrstuvwxyz":
                if _found_gap:
                    break
                for _b in "abcdefghijklmnopqrstuvwxyz":
                    _sfx = _a + _b
                    _pu = f"{_base}/{pkg_name}_offline_kali.part.{_sfx}"
                    _pp = os.path.join(_tmp, f"part.{_sfx}")
                    try:
                        urllib.request.urlretrieve(_pu, _pp)
                        _parts.append(_pp)
                    except Exception:
                        _found_gap = True
                        break
            if _parts:
                info(f"  Reassembling {len(_parts)} part(s) ...")
                with open(_tarball, "wb") as _out:
                    for _p in sorted(_parts):
                        with open(_p, "rb") as _f:
                            _out.write(_f.read())
                _downloaded = True

        if not _downloaded:
            # Final fallback: clone the OfflineInstallers repo to /opt/ and install from there
            _git = shutil.which("git")
            if _git:
                info("githubusercontent.com inaccessible — cloning OfflineInstallers to /opt/ ...")
                if os.path.isdir(os.path.join(_OFFLINE_REPO_DIR, ".git")):
                    subprocess.run([_git, "-C", _OFFLINE_REPO_DIR, "pull", "--ff-only"], check=False)
                else:
                    subprocess.run([_git, "clone", "--depth=1", _OFFLINE_REPO_URL, _OFFLINE_REPO_DIR], check=False)
                if os.path.isdir(_OFFLINE_REPO_DIR):
                    _downloaded = _install_from_local_repo(pkg_name, _tarball)

    if not _downloaded:
        warn(f"Could not download offline bundle for {pkg_name}")
        shutil.rmtree(_tmp, ignore_errors=True)
        return False

    if subprocess.run(["tar", "xzf", _tarball, "-C", _tmp], check=False).returncode != 0:
        warn(f"Failed to extract offline bundle for {pkg_name}")
        shutil.rmtree(_tmp, ignore_errors=True)
        return False

    _install_sh = None
    for _root, _dirs, _files in os.walk(_tmp):
        if "install_offline.sh" in _files:
            _install_sh = os.path.join(_root, "install_offline.sh")
            break

    if not _install_sh:
        warn(f"install_offline.sh not found in {pkg_name} bundle")
        shutil.rmtree(_tmp, ignore_errors=True)
        return False

    os.chmod(_install_sh, 0o755)
    _ok = subprocess.run(["bash", _install_sh], check=False).returncode == 0
    shutil.rmtree(_tmp, ignore_errors=True)
    if _ok:
        info(f"{pkg_name} installed from offline bundle")
    else:
        warn(f"Offline bundle install failed for {pkg_name}")
    return _ok


def install_pip():
    banner("Phase: pip packages")
    _to_install = []
    for _pkg in PIP_PACKAGES:
        if _pip_installed(_pkg):
            info(f"✓ {_pkg} already installed")
        else:
            _to_install.append(_pkg)
    if not _to_install:
        info("All pip packages already installed.")
        return
    for _pkg in _to_install:
        _r = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--break-system-packages", _pkg],
            check=False,
        )
        if _r.returncode != 0:
            _name = _pkg.split(">=")[0].split("==")[0].split("[")[0].strip()
            if _name in OFFLINE_BUNDLE_URLS:
                warn(f"pip install failed for {_name} — trying offline bundle ...")
                _install_from_bundle(_name, OFFLINE_BUNDLE_URLS[_name])
            elif _name in GIT_PIP_URLS:
                warn(f"pip install failed for {_name} — trying git source ...")
                _install_from_git_pip(_name, GIT_PIP_URLS[_name])
            else:
                warn(f"pip install failed for {_name}")


def install_selenium():
    """
    Install the Selenium Python binding using the best available method.

    Priority order:
      1. GitHub source — pip install git+https://github.com/seleniumhq/selenium.git#subdirectory=py
      2. pip (PyPI)    — pip install selenium>=4.0.0
      3. System pkg    — apt-get / dnf / zypper (last resort)

    webdriver-manager is not available in any system repo; it is always
    installed via pip after the Selenium binding is in place.
    """
    banner("Phase: Selenium (browser-assisted login)")

    # Check if already importable
    try:
        import selenium as _sel
        info(f"selenium already installed ({_sel.__version__}) — checking webdriver-manager")
        _sel_installed = True
    except ImportError:
        _sel_installed = False

    if not _sel_installed:
        _installed = False

        # 1. GitHub source via git clone → pip install local py/ subdir
        _git = shutil.which("git")
        if _git:
            info("Trying selenium from GitHub source (git clone) ...")
            _clone_dir = "/tmp/_selenium_src"
            if os.path.isdir(_clone_dir):
                shutil.rmtree(_clone_dir, ignore_errors=True)
            r_clone = subprocess.run(
                [_git, "clone", "--depth=1",
                 "https://github.com/seleniumhq/selenium.git", _clone_dir],
                check=False,
            )
            if r_clone.returncode == 0:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install",
                     "--break-system-packages", "--quiet", "hatchling"],
                    check=False,
                )
                r_pip = subprocess.run(
                    [sys.executable, "-m", "pip", "install",
                     "--break-system-packages",
                     os.path.join(_clone_dir, "py")],
                    check=False,
                )
                if r_pip.returncode == 0:
                    _installed = True
                    info("selenium installed from GitHub source")
            shutil.rmtree(_clone_dir, ignore_errors=True)
        else:
            warn("git not found — skipping GitHub source install")

        # 2. pip (PyPI)
        if not _installed:
            warn("GitHub source install failed — trying pip (PyPI) ...")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--break-system-packages",
                 "selenium>=4.0.0"],
                check=False,
            )
            if result.returncode == 0:
                _installed = True
                info("selenium installed via pip (PyPI)")

        # 3. System package manager (last resort)
        if not _installed:
            if OS == "apt" and shutil.which("apt-get"):
                warn("pip install failed — trying apt-get (last resort) ...")
                global _apt_updated
                if not _apt_updated:
                    run(["apt-get", "update", "-y"], check=False)
                    _apt_updated = True
                result = subprocess.run(
                    ["apt-get", "install", "-y", "python3-selenium"],
                    check=False,
                )
                if result.returncode == 0:
                    _installed = True
                    info("python3-selenium installed via apt-get")
            elif OS == "dnf" and shutil.which("dnf"):
                warn("pip install failed — trying dnf (last resort) ...")
                result = subprocess.run(
                    ["dnf", "install", "-y", "python3-selenium"],
                    check=False,
                )
                if result.returncode == 0:
                    _installed = True
                    info("python3-selenium installed via dnf")
            elif OS == "zypper" and shutil.which("zypper"):
                warn("pip install failed — trying zypper (last resort) ...")
                result = subprocess.run(
                    ["zypper", "install", "-y", "python3-selenium"],
                    check=False,
                )
                if result.returncode == 0:
                    _installed = True
                    info("python3-selenium installed via zypper")

        if not _installed:
            warn("All selenium install methods failed — trying offline bundle ...")
            _installed = _install_from_bundle("selenium", OFFLINE_BUNDLE_URLS["selenium"])
        if not _installed:
            warn("selenium unavailable — browser-assisted login will not work")

    # webdriver-manager is pip-only (not in any system repo)
    try:
        import webdriver_manager  # noqa: F401
        info("webdriver-manager already installed — skipping")
    except ImportError:
        info("Installing webdriver-manager via pip ...")
        _wdm_r = subprocess.run(
            [sys.executable, "-m", "pip", "install",
             "--break-system-packages", "webdriver-manager>=4.0.0"],
            check=False,
        )
        if _wdm_r.returncode != 0:
            warn("pip install failed for webdriver-manager — trying selenium offline bundle ...")
            _install_from_bundle("selenium", OFFLINE_BUNDLE_URLS["selenium"])


# ---------------------------------------------------------------------------
# Go tools
# ---------------------------------------------------------------------------
GO_TOOLS = [
    ("github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "nuclei"),
    ("github.com/hahwul/dalfox/v2@latest",                      "dalfox"),
    ("github.com/OJ/gobuster/v3@latest",                        "gobuster"),
    ("github.com/ffuf/ffuf/v2@latest",                          "ffuf"),
    ("github.com/projectdiscovery/tlsx/cmd/tlsx@latest",       "tlsx"),
    ("github.com/rverton/webanalyze/cmd/webanalyze@latest",    "webanalyze"),
]


def find_go():
    go = shutil.which("go")
    if go:
        return go
    for p in ["/usr/local/go/bin/go", "/usr/lib/go/bin/go"]:
        if os.path.isfile(p):
            return p
    return None


def install_go():
    banner("Phase: go tools")
    go_bin = find_go()
    if not go_bin:
        warn("go not found in PATH — skipping Go tool installation.")
        warn("Install Go from https://go.dev/dl/ and re-run with --skip-go")
        return
    env = os.environ.copy()
    env["GOBIN"] = "/usr/local/bin"
    for pkg, name in GO_TOOLS:
        if shutil.which(name):
            info(f"{name} already installed — skipping")
            continue
        info(f"Installing {name} via go install ...")
        run([go_bin, "install", pkg], check=False, env=env)


# ---------------------------------------------------------------------------
# Ruby gems / git-based Ruby tools
# ---------------------------------------------------------------------------
def _bundler():
    """Return path to a bundler binary, preferring Homebrew Ruby (>= 3.0) on macOS."""
    # Homebrew Ruby installs a modern bundler separately from the system Ruby
    brew_bundles = [
        "/opt/homebrew/opt/ruby/bin/bundle",   # Apple Silicon
        "/usr/local/opt/ruby/bin/bundle",       # Intel
    ]
    for p in brew_bundles:
        if os.path.isfile(p):
            return p
    # rbenv shim for the real (non-root) user
    sudo_user = get_sudo_user()
    if sudo_user:
        for home in [f"/Users/{sudo_user}", f"/home/{sudo_user}"]:
            rbenv_bundle = os.path.join(home, ".rbenv", "shims", "bundle")
            if os.path.isfile(rbenv_bundle):
                return rbenv_bundle
    return shutil.which("bundle") or shutil.which("bundler")


def _bundle_install(dest, without=None):
    """Run bundle install in *dest*, as SUDO_USER when running as root.

    Running bundler as root corrupts gem paths for regular users and triggers
    Bundler's own warning.  We also chown the clone directory to the real user
    first so Bundler can write Gemfile.lock.

    ``without`` — if set (e.g. ``"test"``), runs
    ``bundle config set --local without <without>`` before ``bundle install``
    using the modern Bundler 4.x API (the old ``--without`` flag was removed).

    Gemfile.lock is deleted before install to prevent Bundler from
    auto-downgrading to the version pinned in the lockfile (e.g. 1.17.2),
    which crashes on Ruby 3.2+ due to the removed ``String#untaint`` method.
    """
    bundler = _bundler()
    if not bundler:
        warn(f"No bundler found — run manually: cd {dest} && bundle install")
        warn("Install Homebrew Ruby first: brew install ruby")
        return

    # Remove Gemfile.lock so Bundler uses the current (modern) version
    # rather than auto-installing the obsolete version pinned in the lockfile.
    gemfile_lock = os.path.join(dest, "Gemfile.lock")
    if os.path.isfile(gemfile_lock):
        info("Removing Gemfile.lock to prevent bundler version downgrade")
        os.remove(gemfile_lock)

    sudo_user = get_sudo_user()
    # Only sudo-drop when SUDO_USER is set to a real (non-root) user name.
    use_sudo = is_root() and bool(sudo_user) and sudo_user != "root"

    if use_sudo:
        run(["chown", "-R", sudo_user, dest], check=False)

    def _run(args):
        if use_sudo:
            run(["sudo", "-u", sudo_user, bundler] + args, check=False, cwd=dest)
        else:
            run([bundler] + args, check=False, cwd=dest)

    # Bundler 4.x removed the --without flag; use bundle config instead.
    if without:
        _run(["config", "set", "--local", "without", without])

    _run(["install"])


def _install_whatweb_git():
    """Clone WhatWeb from GitHub into /opt/whatweb and symlink."""
    info("Installing whatweb via git ...")
    git_clone_or_update("https://github.com/urbanadventurer/WhatWeb.git", "/opt/whatweb")
    whatweb_bin = "/opt/whatweb/whatweb"
    if not os.path.isfile(whatweb_bin):
        warn("WhatWeb entry point not found in /opt/whatweb — check the clone.")
        return
    os.chmod(whatweb_bin, 0o755)
    symlink_force(whatweb_bin, "/usr/local/bin/whatweb")
    info("whatweb symlinked to /usr/local/bin/whatweb")
    _bundle_install("/opt/whatweb")


def install_gems():
    banner("Phase: Ruby tools")
    if OS == "macos":
        # macOS ships Ruby 2.6 which can't satisfy modern gem requirements.
        # Install whatweb from source via git instead.
        _install_whatweb_git()
        return
    gem = shutil.which("gem")
    if not gem:
        warn("gem not found — falling back to git install for whatweb ...")
        _install_whatweb_git()
        return
    _r = run([gem, "install", "whatweb"], check=False)
    if _r.returncode != 0:
        warn("gem install failed for whatweb — falling back to git ...")
        _install_whatweb_git()
    # wpscan — WordPress vulnerability scanner
    if shutil.which("wpscan"):
        info("wpscan already installed — skipping")
    elif gem:
        info("Installing wpscan via gem ...")
        _wr = run([gem, "install", "wpscan"], check=False)
        if _wr.returncode != 0:
            warn("gem install wpscan failed — install manually: gem install wpscan")


# ---------------------------------------------------------------------------
# Git tools
# ---------------------------------------------------------------------------
def git_clone_or_update(url, dest):
    if os.path.isdir(dest):
        info(f"Updating existing clone: {dest}")
        run(["git", "-C", dest, "pull", "--ff-only"], check=False)
    else:
        run(["git", "clone", url, dest])


def install_git():
    banner("Phase: git tools")
    # testssl.sh
    git_clone_or_update("https://github.com/drwetter/testssl.sh.git", "/opt/testssl.sh")
    testssl_bin = "/opt/testssl.sh/testssl.sh"
    if os.path.isfile(testssl_bin):
        os.chmod(testssl_bin, 0o755)
        symlink_force(testssl_bin, "/usr/local/bin/testssl.sh")
        info("testssl.sh symlinked to /usr/local/bin/testssl.sh")

    # OWASP ZAP — automated web vulnerability scanner
    _zap_bin = shutil.which("zaproxy") or shutil.which("zap.sh")
    if _zap_bin:
        info(f"  ✓ ZAP already installed: {_zap_bin}")
    else:
        info("Installing OWASP ZAP …")
        if OS == "apt":
            try:
                run(["apt-get", "install", "-y", "zaproxy"])
                info("  ✓ ZAP installed via apt")
            except Exception as _ze:
                warn(f"ZAP install failed (non-fatal): {_ze}")
        elif OS == "brew":
            try:
                run(["brew", "install", "--cask", "zap"])
                info("  ✓ ZAP installed via brew")
            except Exception as _ze:
                warn(f"ZAP install failed (non-fatal): {_ze}")
        else:
            warn("ZAP: install manually from https://www.zaproxy.org/download/")

    # jwt_tool
    git_clone_or_update("https://github.com/ticarpi/jwt_tool.git", "/opt/jwt_tool")
    jwt_bin = "/opt/jwt_tool/jwt_tool.py"
    if os.path.isfile(jwt_bin):
        os.chmod(jwt_bin, 0o755)
        symlink_force(jwt_bin, "/usr/local/bin/jwt_tool")
        info("jwt_tool symlinked to /usr/local/bin/jwt_tool")
        req = "/opt/jwt_tool/requirements.txt"
        if os.path.isfile(req):
            run([sys.executable, "-m", "pip", "install", "--break-system-packages",
                 "-r", req], check=False)

    # exploitdb / searchsploit (fallback if not installed via package manager)
    if not shutil.which("searchsploit"):
        git_clone_or_update("https://github.com/exploit-db/exploitdb.git", "/opt/exploitdb")
        ss_bin = "/opt/exploitdb/searchsploit"
        if os.path.isfile(ss_bin):
            os.chmod(ss_bin, 0o755)
            symlink_force(ss_bin, "/usr/local/bin/searchsploit")
            info("searchsploit symlinked to /usr/local/bin/searchsploit")
    elif os.path.isdir("/opt/exploitdb"):
        info("searchsploit installed — pulling latest exploitdb…")
        git_clone_or_update("https://github.com/exploit-db/exploitdb.git", "/opt/exploitdb")

    # shcheck
    if not shutil.which("shcheck") and not shutil.which("shcheck.py") \
            and not os.path.isfile("/opt/shcheck/shcheck.py"):
        git_clone_or_update("https://github.com/santoru/shcheck.git", "/opt/shcheck")
    elif os.path.isdir("/opt/shcheck"):
        info("shcheck installed — pulling latest…")
        git_clone_or_update("https://github.com/santoru/shcheck.git", "/opt/shcheck")
    shcheck_bin = "/opt/shcheck/shcheck.py"
    if os.path.isfile(shcheck_bin):
        os.chmod(shcheck_bin, 0o755)
        symlink_force(shcheck_bin, "/usr/local/bin/shcheck")
        info("shcheck symlinked to /usr/local/bin/shcheck")

    # nuclei-templates
    git_clone_or_update(
        "https://github.com/projectdiscovery/nuclei-templates.git",
        "/opt/nuclei-templates",
    )


# ---------------------------------------------------------------------------
# Wordlists
# ---------------------------------------------------------------------------
_WORDLIST_URLS = [
    (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master"
        "/Discovery/Web-Content/burp-parameter-names.txt",
        "burp-parameter-names.txt",
    ),
    (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master"
        "/Discovery/Web-Content/raft-large-files.txt",
        "raft-large-files.txt",
    ),
    (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master"
        "/Discovery/Web-Content/raft-large-directories.txt",
        "raft-large-directories.txt",
    ),
    (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master"
        "/Discovery/DNS/namelist.txt",
        "namelist.txt",
    ),
]


def wordlists_dir():
    if platform.system() == "Windows":
        return r"C:\wordlists"
    if platform.system() == "Darwin":
        # /usr/share is SIP-protected on macOS even as root
        return "/usr/local/share/wordlists"
    return "/usr/share/wordlists"


def install_wordlists():
    banner("Phase: wordlists")
    dest_dir = wordlists_dir()
    if not os.path.isdir(dest_dir):
        info(f"Creating wordlist directory: {dest_dir}")
        if is_root():
            os.makedirs(dest_dir, exist_ok=True)
        else:
            # Belt-and-suspenders: use sudo in case we somehow lack write access
            run(["sudo", "mkdir", "-p", dest_dir], check=False)
            run(["sudo", "chmod", "755", dest_dir], check=False)
    if not os.path.isdir(dest_dir):
        error(f"Could not create {dest_dir} — wordlist installation aborted.")
        return
    info(f"Wordlist directory: {dest_dir}")
    for url, filename in _WORDLIST_URLS:
        dest = os.path.join(dest_dir, filename)
        if os.path.isfile(dest):
            info(f"{filename:45s} already present — skipping")
            continue
        info(f"Downloading {filename} ...")
        step(url)
        try:
            urllib.request.urlretrieve(url, dest)
            size_kb = os.path.getsize(dest) // 1024
            info(f"{filename:45s} saved ({size_kb} KB)")
        except Exception as exc:
            error(f"Failed to download {filename}: {exc}")


# ---------------------------------------------------------------------------
# Symlinks
# ---------------------------------------------------------------------------
APP_DIR  = os.path.dirname(os.path.abspath(__file__))
APP_FILE = os.path.join(APP_DIR, "fracture.py")
SYMLINKS = {
    "/usr/local/bin/fracture": APP_FILE,
}


def symlink_force(src, dest):
    try:
        if os.path.islink(dest) or os.path.exists(dest):
            os.remove(dest)
        os.symlink(src, dest)
        info(f"Symlink: {dest} -> {src}")
    except PermissionError:
        warn(f"Cannot create symlink {dest} — not root.")
    except Exception as e:
        warn(f"Symlink {dest} failed: {e}")


def install_symlinks():
    banner("Creating symlinks")
    if not os.path.isfile(APP_FILE):
        warn(f"{APP_FILE} not found — symlinks will point to a missing target.")
    for dest, src in SYMLINKS.items():
        symlink_force(src, dest)


# ---------------------------------------------------------------------------
# Check / verify
# ---------------------------------------------------------------------------
VERIFY_TOOLS = [
    "gobuster", "nikto", "sqlmap", "nuclei", "dalfox",
    "sslscan", "testssl.sh",
    "whatweb", "wpscan", "ffuf", "feroxbuster", "searchsploit", "jwt_tool", "shcheck",
    "mitmdump",
]
VERIFY_PYTHON = ["requests", "colorama", "bs4", "selenium", "termcolor", "dns"]


def run_check():
    banner("Post-install verification")
    print(f"\n{C}Binary tools:{W}")
    for tool in VERIFY_TOOLS:
        found = shutil.which(tool)
        if found:
            info(f"{tool:30s} {G}FOUND{W} ({found})")
        else:
            warn(f"{tool:30s} {Y}NOT FOUND{W}")

    print(f"\n{C}Python imports:{W}")
    for pkg in VERIFY_PYTHON:
        try:
            __import__(pkg)
            info(f"{pkg:30s} {G}OK{W}")
        except ImportError:
            warn(f"{pkg:30s} {Y}MISSING{W}")

    print(f"\n{C}Git tools:{W}")
    for path, label in [
        ("/opt/testssl.sh",        "testssl.sh"),
        ("/opt/jwt_tool",          "jwt_tool"),
        ("/opt/nuclei-templates",  "nuclei-templates"),
        ("/opt/whatweb",           "whatweb (macOS git install)"),
        ("/opt/shcheck",           "shcheck"),
    ]:
        if os.path.isdir(path):
            info(f"{label:30s} {G}PRESENT{W} ({path})")
        else:
            warn(f"{label:30s} {Y}NOT FOUND{W}")
    # exploitdb: may be installed via apt (searchsploit on PATH) or git clone
    _ss = shutil.which("searchsploit") or ("" if not os.path.isdir("/opt/exploitdb") else "/opt/exploitdb")
    if _ss:
        info(f"{'exploitdb (searchsploit)':30s} {G}PRESENT{W} ({_ss})")
    else:
        warn(f"{'exploitdb (searchsploit)':30s} {Y}NOT FOUND{W}")

    print(f"\n{C}Wordlists ({wordlists_dir()}):{W}")
    for _, filename in _WORDLIST_URLS:
        dest = os.path.join(wordlists_dir(), filename)
        if os.path.isfile(dest):
            size_kb = os.path.getsize(dest) // 1024
            info(f"{filename:45s} {G}PRESENT{W} ({size_kb} KB)")
        else:
            warn(f"{filename:45s} {Y}MISSING{W}")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
def print_summary(skips):
    banner("Post-install summary")
    info(f"Application : Fracture — Web App Pentest Orchestrator")
    info(f"Location    : {APP_DIR}")
    info(f"Symlinks    : fracture → {APP_FILE}")
    info(f"OS detected : {OS}")
    print()
    phases = ["system", "pip", "go", "gems", "git", "wordlists"]
    for p in phases:
        status = f"{Y}SKIPPED{W}" if p in skips else f"{G}DONE{W}"
        print(f"  {p:10s} {status}")
    print()
    info("Run: fracture --help")
    warn("testssl.sh installed from git (/opt/testssl.sh) — use the git version.")
    warn("jwt_tool installed from git (/opt/jwt_tool) — available as /usr/local/bin/jwt_tool.")
    warn("searchsploit: installed via exploitdb package or git (/opt/exploitdb).")
    warn("shcheck: installed from git (/opt/shcheck) — available as /usr/local/bin/shcheck.")
    warn("feroxbuster: apt/brew only — install manually on dnf/other systems (cargo install feroxbuster).")
    if OS == "macos":
        warn("whatweb: installed from git (/opt/whatweb) — requires bundler (gem install bundler).")
    info(f"Wordlists  : installed to {wordlists_dir()}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Fracture installer")
    parser.add_argument("--skip-apt",       "--skip-system", dest="skip_system", action="store_true")
    parser.add_argument("--skip-pip",       action="store_true")
    parser.add_argument("--skip-go",        action="store_true")
    parser.add_argument("--skip-gems",      action="store_true")
    parser.add_argument("--skip-git",       action="store_true")
    parser.add_argument("--skip-wordlists", action="store_true")
    parser.add_argument("--check",          action="store_true", help="Verify installation only")
    args = parser.parse_args()

    require_root()

    banner("Fracture — Web App Pentest Orchestrator — Installer")
    info(f"Detected OS : {OS}")
    info(f"Python      : {sys.executable}")
    info(f"Running as  : {'root' if is_root() else os.environ.get('USER','?')}")

    if args.check:
        run_check()
        return

    skips = set()

    if not args.skip_system:
        install_system()
    else:
        skips.add("system")
        warn("Skipping system packages.")

    if not args.skip_pip:
        install_pip()
    else:
        skips.add("pip")
        warn("Skipping pip packages.")

    install_selenium()

    if not args.skip_go:
        install_go()
    else:
        skips.add("go")
        warn("Skipping go tools.")

    if not args.skip_gems:
        install_gems()
    else:
        skips.add("gems")
        warn("Skipping Ruby gems.")

    if not args.skip_git:
        install_git()
    else:
        skips.add("git")
        warn("Skipping git tools.")

    if not args.skip_wordlists:
        install_wordlists()
    else:
        skips.add("wordlists")
        warn("Skipping wordlists.")

    install_symlinks()
    run_check()
    print_summary(skips)


if __name__ == "__main__":
    main()
