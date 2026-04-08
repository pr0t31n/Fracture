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


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def run(cmd, check=True, capture=False, env=None):
    step(" ".join(cmd) if isinstance(cmd, list) else cmd)
    kwargs = dict(check=check)
    if capture:
        kwargs["capture_output"] = True
        kwargs["text"] = True
    if env:
        kwargs["env"] = env
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
# Ruby gems
# ---------------------------------------------------------------------------
def install_gems():
    banner("Phase: Ruby gems")
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
    ]:
        if os.path.isdir(path):
            info(f"{label:30s} {G}PRESENT{W} ({path})")
        else:
            warn(f"{label:30s} {Y}NOT FOUND{W}")


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
    phases = ["system", "pip", "go", "gems", "git"]
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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Fracture installer")
    parser.add_argument("--skip-apt",    "--skip-system", dest="skip_system", action="store_true")
    parser.add_argument("--skip-pip",    action="store_true")
    parser.add_argument("--skip-go",     action="store_true")
    parser.add_argument("--skip-gems",   action="store_true")
    parser.add_argument("--skip-git",    action="store_true")
    parser.add_argument("--check",       action="store_true", help="Verify installation only")
    args = parser.parse_args()

    banner("Fracture — Web App Pentest Orchestrator — Installer")
    info(f"Detected OS : {OS}")
    info(f"Python      : {sys.executable}")

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

    install_symlinks()
    run_check()
    print_summary(skips)


if __name__ == "__main__":
    main()
