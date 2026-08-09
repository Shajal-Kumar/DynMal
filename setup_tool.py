"""
APK Threat Orchestrator — Setup Automation Script
==================================================
Automates the one-time device setup:
  1. Installs Magisk modules from a local zip directory
  2. Pushes and chmod's frida-server (renamed for stealth)
  3. Pushes inotifywait binary (optional)
  4. Verifies all binaries are executable on device
  5. Confirms ADB + root are working

Usage:
    python setup_tool.py
    python setup_tool.py --zips ./my_zips       # custom zip directory
    python setup_tool.py --serial emulator-5554 # specific device
    python setup_tool.py --skip-modules         # skip Magisk module install
    python setup_tool.py --check-only           # just verify, don't push anything

Place all your .zip files in the zips/ directory (or --zips path):
    frida-server-*.xz  or  frida-server-*-android-arm64   (binary, already extracted)
    Shamiko-*.zip
    DisableFlagSecure-*.zip  or  NoFlagSecure-*.zip
    MagiskTrustUserCerts-*.zip  or  ConscryptTrustUserCerts-*.zip
    inotifywait  (binary, no extension)

The script identifies each file by pattern — exact filenames don't matter.
"""

import os
import re
import sys
import time
import shutil
import subprocess
from pathlib import Path

# ─────────────────────────────────────────────────────────────
# Colour helpers (no external deps)
# ─────────────────────────────────────────────────────────────
try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
except ImportError:
    class Fore:
        GREEN = RED = YELLOW = CYAN = WHITE = MAGENTA = ""
    class Style:
        RESET_ALL = ""

def ok(msg):   print(f"  {Fore.GREEN}✓{Style.RESET_ALL}  {msg}")
def err(msg):  print(f"  {Fore.RED}✗{Style.RESET_ALL}  {msg}")
def warn(msg): print(f"  {Fore.YELLOW}⚠{Style.RESET_ALL}  {msg}")
def info(msg): print(f"  {Fore.CYAN}→{Style.RESET_ALL}  {msg}")
def skip(msg): print(f"  {Fore.MAGENTA}↷{Style.RESET_ALL}  {msg}")
def hdr(msg):
    bar = "─" * 62
    print(f"\n{Fore.CYAN}{bar}\n  {msg}\n{bar}{Style.RESET_ALL}")

# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────
FRIDA_DEVICE_PATH   = "/data/local/tmp/com.android.providers.media.module"
INOTIFY_DEVICE_PATH = "/data/local/tmp/inotifywait"

# Module name patterns → what we call them
MODULE_PATTERNS = {
    "shamiko":              r"(?i)shamiko",
    "disableflagsecure":    r"(?i)(disable.?flag.?secure|noflagsecure)",
    "trustusercerts":       r"(?i)(magisk.?trust|conscrypt.?trust|trustuser)",
    "frida_server":         r"(?i)frida.?server.*android",
    "frida_binary":         r"(?i)^com\.android\.providers\.media\.module$",
    "inotifywait":          r"(?i)^inotifywait$",
}

FRIENDLY = {
    "shamiko":           "Shamiko",
    "disableflagsecure": "DisableFlagSecure",
    "trustusercerts":    "TrustUserCerts (Magisk or Conscrypt)",
    "frida_server":      "frida-server",
    "frida_binary":      "frida-server (pre-renamed)",
    "inotifywait":       "inotifywait",
}

# ─────────────────────────────────────────────────────────────
# ADB wrapper
# ─────────────────────────────────────────────────────────────
_serial = None

def adb(*args):
    cmd = ["adb"]
    if _serial:
        cmd += ["-s", _serial]
    cmd += list(args)
    return subprocess.run(cmd, capture_output=True, text=True)


# ─────────────────────────────────────────────────────────────
# Step helpers
# ─────────────────────────────────────────────────────────────

def check_adb() -> bool:
    hdr("Step 1 // ADB + Device Check")
    r = subprocess.run(["adb", "devices"], capture_output=True, text=True)
    lines = [l for l in r.stdout.strip().splitlines()[1:] if l.strip()]
    devices = [l for l in lines if "\tdevice" in l]
    unauthorized = [l for l in lines if "unauthorized" in l]

    if unauthorized:
        err("Device found but UNAUTHORIZED. Accept the RSA prompt on the device screen.")
        return False
    if not devices:
        err("No ADB device found. Connect the device and enable USB Debugging.")
        return False

    serial = devices[0].split("\t")[0]
    global _serial
    if _serial is None:
        _serial = serial
    ok(f"Device connected: {serial}")
    return True


def check_root() -> bool:
    hdr("Step 2 // Root Check")
    r = adb("shell", "su", "-c", "id")
    if "uid=0" in r.stdout:
        ok("Root confirmed: uid=0(root)")
        return True
    err("Root not available. Grant ADB shell root access in Magisk app → SuperUser.")
    return False


def check_magisk() -> bool:
    hdr("Step 3 // Magisk Check")
    r = adb("shell", "su", "-c", "ls /data/adb/magisk/ 2>/dev/null")
    if r.returncode == 0 and r.stdout.strip():
        ok("Magisk installation found at /data/adb/magisk/")
        return True
    r2 = adb("shell", "su", "-c", "which magisk 2>/dev/null")
    if r2.stdout.strip():
        ok(f"Magisk binary found: {r2.stdout.strip()}")
        return True
    err("Magisk not found. Install Magisk before running this script.")
    return False


def scan_zips(zip_dir: Path) -> dict:
    """
    Scan zip_dir for known files. Returns a dict mapping role → Path.
    Roles: shamiko, disableflagsecure, trustusercerts,
           frida_server (xz or raw binary), inotifywait
    """
    found = {}
    if not zip_dir.exists():
        return found

    for f in zip_dir.iterdir():
        name = f.name
        for role, pattern in MODULE_PATTERNS.items():
            if re.search(pattern, name) and role not in found:
                found[role] = f
                break

    return found


def install_module(zip_path: Path, role: str) -> bool:
    """Push a Magisk module zip and install it via Magisk CLI."""
    friendly = FRIENDLY.get(role, role)
    device_path = f"/sdcard/{zip_path.name}"
    info(f"Pushing {friendly}: {zip_path.name}")
    push = adb("push", str(zip_path), device_path)
    if push.returncode != 0:
        err(f"Push failed for {friendly}: {push.stderr.strip()}")
        return False

    # Try magisk --install-module first (Magisk 24+)
    r = adb("shell", "su", "-c", f"magisk --install-module {device_path}")
    if r.returncode == 0:
        ok(f"{friendly} installed via magisk --install-module")
        adb("shell", "rm", "-f", device_path)
        return True

    # Fallback: unzip directly into /data/adb/modules/<name>/
    module_name = zip_path.stem.replace("-", "_").lower()
    module_dir  = f"/data/adb/modules/{module_name}"
    r2 = adb("shell", "su", "-c",
             f"mkdir -p {module_dir} && unzip -o {device_path} -d {module_dir}")
    adb("shell", "rm", "-f", device_path)
    if r2.returncode == 0:
        ok(f"{friendly} installed by unzipping to {module_dir}")
        return True

    err(f"Could not install {friendly}. Try manually via Magisk app → Modules.")
    return False


def push_frida(frida_path: Path) -> bool:
    """Extract (if .xz) and push frida-server with stealth rename."""
    hdr("Step 5 // frida-server")

    local_binary = frida_path

    # Extract .xz if needed
    if frida_path.suffix == ".xz":
        info(f"Extracting {frida_path.name}...")
        extracted = frida_path.with_suffix("")
        if not extracted.exists():
            r = subprocess.run(["unxz", "--keep", str(frida_path)],
                               capture_output=True, text=True)
            if r.returncode != 0:
                # Try Python fallback
                try:
                    import lzma
                    data = lzma.open(str(frida_path)).read()
                    extracted.write_bytes(data)
                except Exception as e:
                    err(f"Failed to extract {frida_path.name}: {e}")
                    return False
        local_binary = extracted
        ok(f"Extracted to {local_binary.name}")

    info(f"Pushing {local_binary.name} → {FRIDA_DEVICE_PATH}")
    push = adb("push", str(local_binary), FRIDA_DEVICE_PATH)
    if push.returncode != 0:
        err(f"Push failed: {push.stderr.strip()}")
        return False

    adb("shell", "su", "-c", f"chmod +x {FRIDA_DEVICE_PATH}")
    ok(f"frida-server pushed and chmod +x: {FRIDA_DEVICE_PATH}")
    return True


def push_inotifywait(inotify_path: Path) -> bool:
    """Push inotifywait binary."""
    hdr("Step 6 // inotifywait")
    info(f"Pushing {inotify_path.name} → {INOTIFY_DEVICE_PATH}")
    push = adb("push", str(inotify_path), INOTIFY_DEVICE_PATH)
    if push.returncode != 0:
        err(f"Push failed: {push.stderr.strip()}")
        return False
    adb("shell", "su", "-c", f"chmod +x {INOTIFY_DEVICE_PATH}")
    ok(f"inotifywait pushed and chmod +x: {INOTIFY_DEVICE_PATH}")
    return True


def verify_device_state() -> None:
    """Final verification pass — checks every expected binary and module."""
    hdr("Step 7 // Final Verification")

    # frida-server
    r = adb("shell", "su", "-c", f"ls -la {FRIDA_DEVICE_PATH} 2>/dev/null")
    if FRIDA_DEVICE_PATH.split("/")[-1] in r.stdout:
        ok(f"frida-server  : {FRIDA_DEVICE_PATH}")
    else:
        warn(f"frida-server  : NOT FOUND at {FRIDA_DEVICE_PATH}")

    # inotifywait
    r = adb("shell", "su", "-c", f"ls -la {INOTIFY_DEVICE_PATH} 2>/dev/null")
    if INOTIFY_DEVICE_PATH.split("/")[-1] in r.stdout:
        ok(f"inotifywait   : {INOTIFY_DEVICE_PATH}")
    else:
        warn(f"inotifywait   : NOT FOUND (polling fallback will be used)")

    # Magisk modules
    r = adb("shell", "su", "-c", "ls /data/adb/modules/ 2>/dev/null")
    modules = [m.strip() for m in r.stdout.strip().splitlines() if m.strip()]
    if modules:
        ok(f"Magisk modules: {', '.join(modules)}")
        for role, pattern in {
            "Shamiko":           r"(?i)shamiko",
            "DisableFlagSecure": r"(?i)(disable.?flag|noflag)",
            "TrustUserCerts":    r"(?i)(trust|conscrypt)",
        }.items():
            if any(re.search(pattern, m) for m in modules):
                ok(f"  └─ {role}: FOUND")
            else:
                warn(f"  └─ {role}: not found in /data/adb/modules/")
    else:
        warn("No Magisk modules found in /data/adb/modules/")

    # Zygisk
    r = adb("shell", "su", "-c",
            "grep -i zygisk /data/adb/magisk.db 2>/dev/null || "
            "cat /data/adb/magisk/.magisk_zygisk 2>/dev/null || echo 'unknown'")
    info("Zygisk status  : verify manually in Magisk app → Settings → Zygisk")

    print()
    info("Run the test harness to confirm logic is intact:")
    info("  python test_orchestrator.py")
    info("Then run Phase 1:")
    info("  python static_analysis.py target.apk")


def print_manual_steps(zip_dir: Path, found: dict) -> None:
    """Print what couldn't be automated for the user to do manually."""
    print(f"\n{Fore.YELLOW}{'─'*62}")
    print("  MANUAL STEPS REQUIRED")
    print(f"{'─'*62}{Style.RESET_ALL}")

    missing_modules = [
        role for role in ["shamiko","disableflagsecure","trustusercerts"]
        if role not in found
    ]
    if missing_modules:
        warn("The following modules were not found in the zips directory:")
        for m in missing_modules:
            print(f"       • {FRIENDLY[m]}")
        info(f"Download the zips and place them in: {zip_dir.resolve()}")
        info("Then re-run this script.")

    print()
    warn("Always do these steps manually after any module installation:")
    print("  1. Magisk app → Settings → Zygisk → ON")
    print("  2. Magisk app → Settings → Enable DenyList → ON")
    print("  3. Magisk app → Configure DenyList → add your target app package")
    print("  4. Reboot the device")
    print("  5. Install mitmproxy CA cert (see setup guide — Section 2E)")
    print("  6. Configure device WiFi proxy → your PC IP : 8080")
    print()


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    global _serial

    # ── Parse args ───────────────────────────────────────────
    zip_dir      = Path("zips")
    check_only   = "--check-only"   in sys.argv
    skip_modules = "--skip-modules" in sys.argv

    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--zips" and i < len(sys.argv) - 1:
            zip_dir = Path(sys.argv[sys.argv.index("--zips") + 1])
        if arg == "--serial" and i < len(sys.argv) - 1:
            _serial = sys.argv[sys.argv.index("--serial") + 1]

    print(f"\n{Fore.GREEN}{'═'*62}")
    print("  APK THREAT ORCHESTRATOR // SETUP AUTOMATION")
    print(f"{'═'*62}{Style.RESET_ALL}")
    info(f"Zip directory : {zip_dir.resolve()}")
    if check_only:
        info("Mode          : check only (no changes)")
    print()

    # ── Step 1-3: device prereqs ─────────────────────────────
    if not check_adb():
        sys.exit(1)
    if not check_root():
        sys.exit(1)
    if not check_magisk():
        sys.exit(1)

    if check_only:
        verify_device_state()
        return

    # ── Step 4: scan zip directory ────────────────────────────
    hdr("Step 4 // Scanning Zip Directory")
    if not zip_dir.exists():
        warn(f"Zip directory '{zip_dir}' not found — creating it.")
        zip_dir.mkdir(parents=True)
    
    found = scan_zips(zip_dir)
    if found:
        ok(f"Found {len(found)} file(s) in {zip_dir}/:")
        for role, path in found.items():
            ok(f"  {FRIENDLY.get(role, role):30s} ← {path.name}")
    else:
        warn(f"No recognised files found in {zip_dir}/")
        info("Expected files matching patterns like:")
        info("  Shamiko-*.zip, DisableFlagSecure-*.zip,")
        info("  ConscryptTrustUserCerts-*.zip or MagiskTrustUserCerts-*.zip,")
        info("  frida-server-*-android-arm64 (or .xz), inotifywait")

    # ── Step 5: Magisk modules ────────────────────────────────
    if not skip_modules:
        hdr("Step 4b // Installing Magisk Modules")
        module_roles = ["shamiko", "disableflagsecure", "trustusercerts"]
        needs_reboot = False

        for role in module_roles:
            if role in found:
                if install_module(found[role], role):
                    needs_reboot = True
            else:
                warn(f"{FRIENDLY[role]}: not in zips directory — skipping")

        if needs_reboot:
            warn("Modules installed — a REBOOT is required before they activate.")
            info("Run:  adb reboot")
            info("After rebooting, re-run this script with --check-only to verify.")
    else:
        skip("Module installation skipped (--skip-modules)")

    # ── Step 5: frida-server ──────────────────────────────────
    frida_key = next((k for k in ["frida_binary", "frida_server"] if k in found), None)
    if frida_key:
        push_frida(found[frida_key])
    else:
        hdr("Step 5 // frida-server")
        warn("frida-server binary not found in zips directory.")
        info("Download from: github.com/frida/frida/releases")
        info("File: frida-server-<version>-android-arm64.xz")
        info(f"Place in: {zip_dir.resolve()}")

    # ── Step 6: inotifywait ───────────────────────────────────
    if "inotifywait" in found:
        push_inotifywait(found["inotifywait"])
    else:
        hdr("Step 6 // inotifywait")
        skip("inotifywait not found — sentry.py will use polling fallback (POLL_INTERVAL=1.0)")
        info("Optional download: github.com/tytydraco/inotify-tools-android/releases")

    # ── Step 7: verify ────────────────────────────────────────
    verify_device_state()

    # ── Manual steps reminder ─────────────────────────────────
    print_manual_steps(zip_dir, found)


if __name__ == "__main__":
    main()