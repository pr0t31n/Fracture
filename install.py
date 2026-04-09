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


def dnf_install(packages):
    run(["dnf", "install", "-y"] + packages)


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
]
DNF_PACKAGES = [
    "nikto", "sqlmap", "sslscan", "whatweb", "ffuf",
    "python3-pip", "python3-devel",
    "git", "golang",
    "ruby", "ruby-devel",
    "openssl-devel", "libcurl-devel",
]
BREW_PACKAGES = [
    "gobuster", "nikto", "sslscan", "git",
    "ffuf", "feroxbuster", "exploitdb",
]


def install_system():
    banner("Phase: system packages")
    if OS == "apt":
        apt_install(APT_PACKAGES)
    elif OS == "dnf":
        dnf_install(DNF_PACKAGES)
    elif OS == "zypper":
        zypper_install(["nikto", "python3-pip", "git", "golang", "ruby"])
    elif OS == "macos":
        for pkg in BREW_PACKAGES:
            brew_install(pkg)
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
    "selenium>=4.0.0",
    "webdriver-manager>=4.0.0",
]


def install_pip():
    banner("Phase: pip packages")
    run([sys.executable, "-m", "pip", "install", "--break-system-packages"] + PIP_PACKAGES,
        check=False)


# ---------------------------------------------------------------------------
# Go tools
# ---------------------------------------------------------------------------
GO_TOOLS = [
    ("github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "nuclei"),
    ("github.com/hahwul/dalfox/v2@latest",                      "dalfox"),
    ("github.com/OJ/gobuster/v3@latest",                        "gobuster"),
    ("github.com/ffuf/ffuf/v2@latest",                          "ffuf"),
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


def _install_wpscan_git():
    """Clone WPScan from GitHub into /opt/wpscan and symlink."""
    info("Installing wpscan via git ...")
    git_clone_or_update("https://github.com/wpscanteam/wpscan.git", "/opt/wpscan")
    wpscan_bin = "/opt/wpscan/bin/wpscan"
    if not os.path.isfile(wpscan_bin):
        warn("WPScan binary not found at /opt/wpscan/bin/wpscan — check the clone.")
        return
    os.chmod(wpscan_bin, 0o755)
    symlink_force(wpscan_bin, "/usr/local/bin/wpscan")
    info("wpscan symlinked to /usr/local/bin/wpscan")
    _bundle_install("/opt/wpscan", without="test")


def install_gems():
    banner("Phase: Ruby tools")
    if OS == "macos":
        # macOS ships Ruby 2.6 which can't satisfy modern gem requirements.
        # Install whatweb and wpscan from source via git instead.
        _install_whatweb_git()
        _install_wpscan_git()
        return
    gem = shutil.which("gem")
    if not gem:
        warn("gem not found — skipping Ruby gem installation.")
        return
    for gem_name in ["wpscan", "whatweb"]:
        info(f"Installing {gem_name} ...")
        run([gem, "install", gem_name], check=False)


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

    # tplmap
    git_clone_or_update("https://github.com/epinna/tplmap.git", "/opt/tplmap")
    tplmap_bin = "/opt/tplmap/tplmap.py"
    if os.path.isfile(tplmap_bin):
        os.chmod(tplmap_bin, 0o755)
        symlink_force(tplmap_bin, "/usr/local/bin/tplmap")
        info("tplmap symlinked to /usr/local/bin/tplmap")

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
APP_DIR  = "/Users/pr0t31n/Fracture"
APP_FILE = f"{APP_DIR}/fracture.py"
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
    "wpscan", "sslscan", "testssl.sh", "tplmap",
    "whatweb", "ffuf", "feroxbuster", "searchsploit", "jwt_tool",
]
VERIFY_PYTHON = ["requests", "colorama", "bs4"]


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
        ("/opt/tplmap",            "tplmap"),
        ("/opt/jwt_tool",          "jwt_tool"),
        ("/opt/exploitdb",         "exploitdb (searchsploit)"),
        ("/opt/nuclei-templates",  "nuclei-templates"),
        ("/opt/whatweb",           "whatweb (macOS git install)"),
        ("/opt/wpscan",            "wpscan  (macOS git install)"),
    ]:
        if os.path.isdir(path):
            info(f"{label:30s} {G}PRESENT{W} ({path})")
        else:
            warn(f"{label:30s} {Y}NOT FOUND{W}")

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
    warn("tplmap installed from git (/opt/tplmap) — available as /usr/local/bin/tplmap.")
    warn("jwt_tool installed from git (/opt/jwt_tool) — available as /usr/local/bin/jwt_tool.")
    warn("searchsploit: installed via exploitdb package or git (/opt/exploitdb).")
    warn("feroxbuster: apt/brew only — install manually on dnf/other systems (cargo install feroxbuster).")
    if OS == "macos":
        warn("whatweb: installed from git (/opt/whatweb) — requires bundler (gem install bundler).")
        warn("wpscan:  installed from git (/opt/wpscan)  — requires bundler (gem install bundler).")
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
