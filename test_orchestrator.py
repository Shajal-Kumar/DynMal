"""
APK Threat Orchestrator — Real Integration Test Harness
========================================================
Imports and tests the ACTUAL static_analysis.py and sentry.py.
All hardware dependencies are mocked at the sys.modules level
before import, so the real functions run against controlled fake
ADB responses, a fake APK, and simulated network data.

If a bug exists in the real code, this will catch it.
If the logic in either file drifts from what the tests expect,
this will catch it.

Usage:
    python test_orchestrator.py           # all tests
    python test_orchestrator.py --phase1  # Phase 1 only
    python test_orchestrator.py --phase2  # Phase 2 only
    python test_orchestrator.py -v        # verbose (show all passes)

Requirements (same as the main tool — minus the hardware libs):
    pip install colorama python-dotenv
"""

import os
import re
import sys
import json
import time
import queue
import hashlib
import tempfile
import threading
import importlib
import subprocess
import zipfile
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock, call

# ─────────────────────────────────────────────────────────────
# STEP 1 — Inject mock modules into sys.modules BEFORE any
#           import of static_analysis or sentry happens.
#           Python caches imports — these stubs will be what
#           both real files see when they do their own imports.
# ─────────────────────────────────────────────────────────────

def _build_mock_androguard():
    """Fake androguard package. AnalyzeAPK patched per-test."""
    pkg                    = MagicMock(name="androguard")
    pkg.misc               = MagicMock(name="androguard.misc")
    pkg.misc.AnalyzeAPK    = MagicMock(name="AnalyzeAPK")
    return pkg


def _build_mock_frida():
    """Fake frida package. Device/session/script patched per-test."""
    pkg          = MagicMock(name="frida")
    device       = MagicMock(name="frida.device")
    session      = MagicMock(name="frida.session")
    script       = MagicMock(name="frida.script")
    script.load  = MagicMock(return_value=None)
    session.create_script = MagicMock(return_value=script)
    device.attach         = MagicMock(return_value=session)
    pkg.get_device_manager.return_value.add_remote_device.return_value = device
    return pkg


def _build_mock_mitmproxy():
    """Fake mitmproxy package tree."""
    mitm        = MagicMock(name="mitmproxy")
    opts_mod    = MagicMock(name="mitmproxy.options")
    http_mod    = MagicMock(name="mitmproxy.http")
    tools_mod   = MagicMock(name="mitmproxy.tools")
    dump_mod    = MagicMock(name="mitmproxy.tools.dump")
    master      = MagicMock(name="DumpMaster")
    master.run  = MagicMock(return_value=None)
    dump_mod.DumpMaster = MagicMock(return_value=master)
    tools_mod.dump      = dump_mod

    # mitmproxy.http.HTTPFlow used by ExfiltrationAddon.request()
    http_mod.HTTPFlow = MagicMock
    return mitm, opts_mod, http_mod, tools_mod, dump_mod


def _build_mock_adbutils():
    return MagicMock(name="adbutils")


# Inject everything BEFORE any real-module import
_mock_androguard = _build_mock_androguard()
_mock_frida      = _build_mock_frida()
_mock_adbutils   = _build_mock_adbutils()
_mock_mitm, _mock_mitm_opts, _mock_mitm_http, _mock_mitm_tools, _mock_mitm_dump = _build_mock_mitmproxy()

sys.modules.setdefault("androguard",              _mock_androguard)
sys.modules.setdefault("androguard.misc",         _mock_androguard.misc)
sys.modules.setdefault("frida",                   _mock_frida)
sys.modules.setdefault("adbutils",                _mock_adbutils)
sys.modules.setdefault("mitmproxy",               _mock_mitm)
sys.modules.setdefault("mitmproxy.options",       _mock_mitm_opts)
sys.modules.setdefault("mitmproxy.http",          _mock_mitm_http)
sys.modules.setdefault("mitmproxy.tools",         _mock_mitm_tools)
sys.modules.setdefault("mitmproxy.tools.dump",    _mock_mitm_dump)

# ─────────────────────────────────────────────────────────────
# STEP 2 — Now import the real files.
#           sys.path must include the directory they live in.
# ─────────────────────────────────────────────────────────────

_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

import static_analysis   # the real Phase 1 file
import sentry            # the real Phase 2 file

# ─────────────────────────────────────────────────────────────
# COLORAMA (optional)
# ─────────────────────────────────────────────────────────────

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    class Fore:
        GREEN = RED = YELLOW = CYAN = WHITE = MAGENTA = ""
    class Style:
        RESET_ALL = ""
    HAS_COLOR = False


# ─────────────────────────────────────────────────────────────
# TEST RUNNER
# ─────────────────────────────────────────────────────────────

class Results:
    def __init__(self):
        self.passed = []
        self.failed = []
        self.start  = time.time()

    def record(self, suite, name, ok, msg=""):
        (self.passed if ok else self.failed).append((suite, name, msg))

    def summary(self):
        elapsed = time.time() - self.start
        total   = len(self.passed) + len(self.failed)
        print(f"\n{Fore.GREEN}{'═' * 64}{Style.RESET_ALL}")
        print(f"  TEST RESULTS  —  {elapsed:.2f}s")
        print(f"{'═' * 64}")
        print(f"  {Fore.GREEN}PASSED : {len(self.passed)}{Style.RESET_ALL}")
        if self.failed:
            print(f"  {Fore.RED}FAILED : {len(self.failed)}{Style.RESET_ALL}")
        print(f"  TOTAL  : {total}")
        if self.failed:
            print(f"\n{Fore.RED}FAILURES:{Style.RESET_ALL}")
            for suite, name, msg in self.failed:
                print(f"  ✗  [{suite}]  {name}")
                if msg:
                    print(f"       {Fore.RED}{msg}{Style.RESET_ALL}")
        verdict = "ALL TESTS PASSED" if not self.failed else f"{len(self.failed)} FAILED"
        color   = Fore.GREEN if not self.failed else Fore.RED
        print(f"\n  {color}{verdict}{Style.RESET_ALL}")
        print(f"{'═' * 64}\n")
        return not self.failed


RESULTS = Results()
VERBOSE = "-v" in sys.argv


def run(suite, name, fn):
    try:
        fn()
        RESULTS.record(suite, name, True)
        if VERBOSE:
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL}  {name}")
    except AssertionError as e:
        RESULTS.record(suite, name, False, str(e))
        print(f"  {Fore.RED}✗{Style.RESET_ALL}  {name}")
        print(f"       {Fore.RED}AssertionError: {e}{Style.RESET_ALL}")
    except Exception as e:
        RESULTS.record(suite, name, False, f"{type(e).__name__}: {e}")
        print(f"  {Fore.RED}✗{Style.RESET_ALL}  {name}")
        print(f"       {Fore.RED}{type(e).__name__}: {e}{Style.RESET_ALL}")


def section(title):
    print(f"\n{Fore.CYAN}── {title} {'─' * max(0, 54 - len(title))}{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────
# FIXTURES — shared fake data and ADB response builders
# ─────────────────────────────────────────────────────────────

FAKE_PACKAGE  = "com.evil.malware"
FAKE_ACTIVITY = "com.evil.malware.MainActivity"
FAKE_SERIAL   = "emulator-5554"

MOCK_PERMISSIONS = [
    "android.permission.SEND_SMS",
    "android.permission.READ_SMS",
    "android.permission.INTERNET",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
    "com.evil.malware.CUSTOM_PERMISSION",
]

MOCK_DEX_STRINGS = [
    "https://evil-c2.ru/upload",
    "https://cdn.google.com/api",
    "http://185.220.101.47/payload",
    "192.168.1.1",           # private — should be filtered
    "10.0.0.1",              # private — should be filtered
    'api_key="AAABBBCCC123456789012345"',
    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    "normal string without indicators",
]


def adb_ok(stdout="", returncode=0):
    """Build a fake subprocess.CompletedProcess for a successful ADB call."""
    r            = MagicMock()
    r.stdout     = stdout
    r.returncode = returncode
    r.stderr     = ""
    return r


def adb_fail(stdout="", stderr="error", returncode=1):
    """Build a fake subprocess.CompletedProcess for a failed ADB call."""
    r            = MagicMock()
    r.stdout     = stdout
    r.returncode = returncode
    r.stderr     = stderr
    return r


def make_mock_apk(permissions=None, receivers=None):
    """
    Build a fake androguard APK object.
    Returned by mocked AnalyzeAPK — drives parse_apk() in Phase 1.
    """
    apk = MagicMock(name="MockAPK")
    apk.get_package.return_value       = FAKE_PACKAGE
    apk.get_main_activity.return_value = FAKE_ACTIVITY
    apk.get_activities.return_value    = [FAKE_ACTIVITY, "com.evil.malware.OverlayService"]
    apk.get_permissions.return_value   = permissions or MOCK_PERMISSIONS

    receiver_names = receivers or ["com.evil.malware.BootReceiver"]
    apk.get_receivers.return_value     = receiver_names
    apk.get_intent_filters.return_value = {
        "intent-filter-0": {"action": ["android.intent.action.BOOT_COMPLETED"]}
    }
    return apk


def make_mock_dvm(strings=None):
    """
    Build a fake dalvik VM object whose strings drive scan_indicators().
    """
    dvm = MagicMock(name="MockDVM")
    string_objs = []
    for s in (strings or MOCK_DEX_STRINGS):
        m = MagicMock()
        m.get_data.return_value = s
        string_objs.append(m)
    dvm.get_strings.return_value = string_objs
    return dvm


def make_analyze_apk_return(permissions=None, strings=None, receivers=None):
    """Return value tuple for AnalyzeAPK(path) → (apk, [dvm], analysis)."""
    return (
        make_mock_apk(permissions=permissions, receivers=receivers),
        [make_mock_dvm(strings=strings)],
        MagicMock(name="analysis"),
    )


# ─────────────────────────────────────────────────────────────
# ADB RESPONSE ROUTER
# Returns appropriate fake stdout based on which ADB subcommand
# was called.  Passed as side_effect to patch("subprocess.run").
# ─────────────────────────────────────────────────────────────

def make_adb_router(overrides=None):
    """
    Returns a side_effect function for subprocess.run that inspects
    the command list and returns a plausible fake response.
    overrides: dict mapping a substring of the cmd string → adb_ok(stdout=...)
    """
    overrides = overrides or {}

    def router(cmd, **kwargs):
        cmd_str = " ".join(str(c) for c in cmd)

        # Check caller-provided overrides first
        for key, response in overrides.items():
            if key in cmd_str:
                return response

        # Default responses by command content
        if "adb devices"            in cmd_str: return adb_ok(f"List of devices attached\n{FAKE_SERIAL}\tdevice\n")
        if "getprop ro.build"       in cmd_str: return adb_ok("13")
        if "su -c id"               in cmd_str: return adb_ok("uid=0(root) gid=0(root)")
        if "ls /data/adb/modules"   in cmd_str: return adb_ok("shamiko\nnoflagsecure\nMagiskTrustUserCerts\n")
        if f"ls {static_analysis.Config.FRIDA_SERVER}" in cmd_str: return adb_ok(static_analysis.Config.FRIDA_SERVER)
        if "ps -A" in cmd_str and "grep" in cmd_str and FAKE_PACKAGE in cmd_str:
            # _resolve_pids ps-A fallback: return empty by default
            # (tests that need a process here should use overrides)
            return adb_ok()
        if "ps -A"                  in cmd_str: return adb_ok("root   1234  frida-server")
        if "which" in cmd_str and "pidof" in cmd_str:
            # pidof exists on device by default — suppresses the fallback path
            return adb_ok("/system/bin/pidof")
        if "ls /data/local/tmp/inotifywait" in cmd_str: return adb_ok("/data/local/tmp/inotifywait")
        if "grep -rl 'mitmproxy'"   in cmd_str: return adb_ok("/system/etc/security/cacerts/c8750f0d.0")
        if "cacerts-added"          in cmd_str: return adb_ok("c8750f0d.0")
        if "am start"               in cmd_str: return adb_ok("Starting: Intent { cmp=com.evil.malware/.MainActivity }")
        if "pidof"                  in cmd_str: return adb_ok("1234 1235 1236")
        if "nohup"                  in cmd_str: return adb_ok()
        if "netstat"                in cmd_str: return adb_ok("tcp   0   0   0.0.0.0:54321   185.220.101.47:443   ESTABLISHED\n")
        if "pm list packages"       in cmd_str: return adb_ok(f"package:{FAKE_PACKAGE}\n")
        if "pm path"                in cmd_str: return adb_ok(f"package:/data/app/{FAKE_PACKAGE}-xxx/base.apk")
        return adb_ok()

    return router


# ═════════════════════════════════════════════════════════════
#  PHASE 1 — REAL FUNCTION TESTS
# ═════════════════════════════════════════════════════════════

# ── P1.1: Device Readiness ────────────────────────────────────

def test_p1_readiness_all_checks_pass():
    """check_device_readiness() returns a fully ready DeviceReadiness."""
    with patch("static_analysis.subprocess.run", side_effect=make_adb_router()):
        dr = static_analysis.check_device_readiness()
    assert dr.adb_connected,        "ADB should be connected"
    assert dr.is_rooted,            "Should detect root"
    assert dr.shamiko_active,       "Should find Shamiko module"
    assert dr.flag_secure_disabled, "Should find No FLAG_SECURE module"
    assert dr.frida_server_running, "Should confirm frida-server running"
    assert dr.ready_for_analysis,   "Device should be ready"
    assert dr.screenshot_tier == 1, f"Expected tier 1, got {dr.screenshot_tier}"


def test_p1_readiness_no_device():
    """No ADB device → not ready, adb_connected=False."""
    def no_device(cmd, **kwargs):
        if "devices" in " ".join(str(c) for c in cmd):
            return adb_ok("List of devices attached\n")  # no entries
        return adb_ok()

    with patch("static_analysis.subprocess.run", side_effect=no_device):
        dr = static_analysis.check_device_readiness()
    assert not dr.adb_connected
    assert not dr.ready_for_analysis


def test_p1_readiness_no_root():
    """No root → is_rooted=False, ready_for_analysis=False."""
    def no_root(cmd, **kwargs):
        cmd_str = " ".join(str(c) for c in cmd)
        if "su -c id" in cmd_str:
            return adb_ok("uid=1000(shell) gid=1000(shell)")  # not root
        return make_adb_router()(cmd, **kwargs)

    with patch("static_analysis.subprocess.run", side_effect=no_root):
        dr = static_analysis.check_device_readiness()
    assert dr.adb_connected
    assert not dr.is_rooted
    assert not dr.ready_for_analysis


def test_p1_readiness_no_shamiko():
    """Missing Shamiko → shamiko_active=False, warning recorded."""
    def no_shamiko(cmd, **kwargs):
        cmd_str = " ".join(str(c) for c in cmd)
        if "ls /data/adb/modules" in cmd_str:
            return adb_ok("noflagsecure\nMagiskTrustUserCerts\n")  # no shamiko
        return make_adb_router()(cmd, **kwargs)

    with patch("static_analysis.subprocess.run", side_effect=no_shamiko):
        dr = static_analysis.check_device_readiness()
    assert not dr.shamiko_active
    assert any("Shamiko" in w or "shamiko" in w.lower() for w in dr.warnings), \
        "Expected a Shamiko warning"


def test_p1_readiness_screenshot_tier_2():
    """No FLAG_SECURE module but Frida running → tier 2."""
    def no_flag_secure(cmd, **kwargs):
        cmd_str = " ".join(str(c) for c in cmd)
        if "ls /data/adb/modules" in cmd_str:
            return adb_ok("shamiko\nMagiskTrustUserCerts\n")  # no noflagsecure
        return make_adb_router()(cmd, **kwargs)

    with patch("static_analysis.subprocess.run", side_effect=no_flag_secure):
        dr = static_analysis.check_device_readiness()
    assert not dr.flag_secure_disabled
    assert dr.frida_server_running
    assert dr.screenshot_tier == 2


def test_p1_readiness_screenshot_tier_3():
    """No FLAG_SECURE, no Frida running → tier 3."""
    def tier3(cmd, **kwargs):
        cmd_str = " ".join(str(c) for c in cmd)
        if "ls /data/adb/modules" in cmd_str:
            return adb_ok("shamiko\nMagiskTrustUserCerts\n")
        if "ps -A" in cmd_str:
            return adb_ok("root 9999 some_other_process")  # frida not in output
        return make_adb_router()(cmd, **kwargs)

    with patch("static_analysis.subprocess.run", side_effect=tier3):
        dr = static_analysis.check_device_readiness()
    assert dr.screenshot_tier == 3


# ── P1.2: APK Parsing ────────────────────────────────────────

def _tmp_apk():
    """Create a real temp .apk file so parse_apk()'s path.exists() check passes."""
    import tempfile as _tf
    f = _tf.NamedTemporaryFile(suffix=".apk", delete=False)
    f.write(b"PK\x03\x04")
    f.close()
    return f.name


def test_p1_parse_apk_package_and_activity():
    """parse_apk() extracts correct package name and main activity."""
    p = _tmp_apk()
    try:
        with patch("static_analysis.AnalyzeAPK", return_value=make_analyze_apk_return()):
            report = static_analysis.parse_apk(p)
        assert report.package_name  == FAKE_PACKAGE,  f"Got: {report.package_name}"
        assert report.main_activity == FAKE_ACTIVITY,  f"Got: {report.main_activity}"
        assert len(report.all_activities) == 2
        assert report.has_launcher is True
    finally:
        Path(p).unlink(missing_ok=True)


def test_p1_parse_apk_no_main_activity():
    """APK with no main activity sets has_launcher=False."""
    p   = _tmp_apk()
    apk = make_mock_apk()
    apk.get_main_activity.return_value = None
    try:
        with patch("static_analysis.AnalyzeAPK",
                   return_value=(apk, [make_mock_dvm()], MagicMock())):
            report = static_analysis.parse_apk(p)
        assert report.has_launcher is False
        assert report.main_activity == ""
    finally:
        Path(p).unlink(missing_ok=True)


def test_p1_parse_apk_permissions_categorised():
    """parse_apk() categorises permissions into DANGEROUS/NORMAL/UNKNOWN."""
    p = _tmp_apk()
    try:
        with patch("static_analysis.AnalyzeAPK", return_value=make_analyze_apk_return()):
            report = static_analysis.parse_apk(p)
        levels = {perm.name: perm.level for perm in report.permissions}
        assert levels["android.permission.SEND_SMS"]        == "DANGEROUS"
        assert levels["android.permission.INTERNET"]        == "DANGEROUS"
        assert levels["android.permission.VIBRATE"]         == "NORMAL"
        assert levels["com.evil.malware.CUSTOM_PERMISSION"] == "UNKNOWN"
    finally:
        Path(p).unlink(missing_ok=True)


def test_p1_parse_apk_permission_short_names():
    """Permission.short is the last dot-segment of the full name."""
    p = _tmp_apk()
    try:
        with patch("static_analysis.AnalyzeAPK", return_value=make_analyze_apk_return()):
            report = static_analysis.parse_apk(p)
        shorts = {perm.name: perm.short for perm in report.permissions}
        assert shorts["android.permission.SEND_SMS"] == "SEND_SMS"
        assert shorts["android.permission.CAMERA"]   == "CAMERA"
    finally:
        Path(p).unlink(missing_ok=True)


def test_p1_parse_apk_no_permissions_lost():
    """Every permission in the mock appears exactly once in the report."""
    p = _tmp_apk()
    try:
        with patch("static_analysis.AnalyzeAPK", return_value=make_analyze_apk_return()):
            report = static_analysis.parse_apk(p)
        names = [perm.name for perm in report.permissions]
        assert len(names) == len(MOCK_PERMISSIONS), \
            f"Expected {len(MOCK_PERMISSIONS)} permissions, got {len(names)}"
        assert len(set(names)) == len(names), "Duplicate permissions in report"
    finally:
        Path(p).unlink(missing_ok=True)


def test_p1_parse_apk_receivers():
    """parse_apk() extracts receivers and their intent actions."""
    p = _tmp_apk()
    try:
        with patch("static_analysis.AnalyzeAPK", return_value=make_analyze_apk_return()):
            report = static_analysis.parse_apk(p)
        assert len(report.receivers) == 1
        assert report.receivers[0].name == "com.evil.malware.BootReceiver"
        assert "android.intent.action.BOOT_COMPLETED" in report.receivers[0].actions
    finally:
        Path(p).unlink(missing_ok=True)


def test_p1_parse_apk_file_not_found():
    """parse_apk() records an error when the APK path doesn't exist."""
    # Don't patch AnalyzeAPK — let the path check fail first
    report = static_analysis.parse_apk("/nonexistent/path/fake.apk")
    assert len(report.errors) > 0
    assert any("not found" in e.lower() or "nonexistent" in e.lower()
               for e in report.errors)


def test_p1_parse_apk_androguard_exception():
    """parse_apk() records an error when androguard raises."""
    # Make the file appear to exist, but androguard fails
    with patch("static_analysis.Path.exists", return_value=True), \
         patch("static_analysis.AnalyzeAPK", side_effect=Exception("corrupt APK")):
        report = static_analysis.parse_apk("/fake/malware.apk")
    assert any("androguard" in e.lower() or "corrupt" in e.lower()
               for e in report.errors)


# ── P1.3: Indicator Scan ─────────────────────────────────────

def test_p1_scan_indicators_urls():
    """scan_indicators() extracts C2 URLs from DEX strings."""
    report = static_analysis.StaticReport(apk_path=FAKE_PACKAGE, package_name=FAKE_PACKAGE)
    with patch("static_analysis.AnalyzeAPK", return_value=make_analyze_apk_return()):
        static_analysis.scan_indicators(FAKE_PACKAGE, report)
    assert "https://evil-c2.ru/upload" in report.indicators["url"], \
        f"C2 URL not found. Got: {report.indicators['url']}"


def test_p1_scan_indicators_public_ip():
    """scan_indicators() extracts public IPs."""
    report = static_analysis.StaticReport(apk_path=FAKE_PACKAGE, package_name=FAKE_PACKAGE)
    with patch("static_analysis.AnalyzeAPK", return_value=make_analyze_apk_return()):
        static_analysis.scan_indicators(FAKE_PACKAGE, report)
    assert "185.220.101.47" in report.indicators["ipv4"]


def test_p1_scan_indicators_private_ip_filtered():
    """scan_indicators() strips RFC1918 addresses."""
    report = static_analysis.StaticReport(apk_path=FAKE_PACKAGE, package_name=FAKE_PACKAGE)
    with patch("static_analysis.AnalyzeAPK", return_value=make_analyze_apk_return()):
        static_analysis.scan_indicators(FAKE_PACKAGE, report)
    assert "192.168.1.1" not in report.indicators["ipv4"], "Private IP leaked"
    assert "10.0.0.1"    not in report.indicators["ipv4"], "Private IP leaked"


def test_p1_scan_indicators_ipv6():
    """scan_indicators() finds IPv6 addresses."""
    report = static_analysis.StaticReport(apk_path=FAKE_PACKAGE, package_name=FAKE_PACKAGE)
    with patch("static_analysis.AnalyzeAPK", return_value=make_analyze_apk_return()):
        static_analysis.scan_indicators(FAKE_PACKAGE, report)
    assert len(report.indicators["ipv6"]) > 0


def test_p1_scan_indicators_api_key():
    """scan_indicators() extracts API key patterns."""
    report = static_analysis.StaticReport(apk_path=FAKE_PACKAGE, package_name=FAKE_PACKAGE)
    with patch("static_analysis.AnalyzeAPK", return_value=make_analyze_apk_return()):
        static_analysis.scan_indicators(FAKE_PACKAGE, report)
    assert len(report.indicators["api_key"]) > 0


def test_p1_scan_indicators_deduplication():
    """Duplicate strings produce exactly one entry per unique value."""
    doubled = MOCK_DEX_STRINGS + MOCK_DEX_STRINGS
    report  = static_analysis.StaticReport(apk_path=FAKE_PACKAGE, package_name=FAKE_PACKAGE)
    with patch("static_analysis.AnalyzeAPK",
               return_value=make_analyze_apk_return(strings=doubled)):
        static_analysis.scan_indicators(FAKE_PACKAGE, report)
    assert report.indicators["url"].count("https://evil-c2.ru/upload") == 1, \
        "Duplicate URL not deduplicated"


def test_p1_scan_indicators_fallback_binary_scan():
    """When AnalyzeAPK fails, scan_indicators() falls back to raw binary scan."""
    report = static_analysis.StaticReport(apk_path=FAKE_PACKAGE, package_name=FAKE_PACKAGE)
    # APK "file" contains an ASCII URL embedded in fake binary
    fake_apk_bytes = b"\x00\x00" + b"https://evil-c2.ru/upload" + b"\x00\x00"
    with patch("static_analysis.AnalyzeAPK", side_effect=Exception("DEX parse failed")), \
         patch("static_analysis.Path.read_bytes", return_value=fake_apk_bytes):
        static_analysis.scan_indicators(FAKE_PACKAGE, report)
    assert len(report.indicators["url"]) > 0, \
        "Fallback binary scan did not find the URL"


# ── P1.4: FIX 2 — Multi-PID via launch_apk() ─────────────────

def test_p1_launch_apk_multi_pid_captured():
    """launch_apk() captures all PIDs when pidof returns multiple values."""
    dr = static_analysis.DeviceReadiness(adb_connected=True, is_rooted=True)
    report = static_analysis.StaticReport(
        apk_path=FAKE_PACKAGE,
        package_name=FAKE_PACKAGE,
        main_activity=FAKE_ACTIVITY,
        has_launcher=True,
    )
    with patch("static_analysis.subprocess.run", side_effect=make_adb_router()):
        static_analysis.launch_apk(report, dr)
    assert report.pid      == 1234,             f"Primary PID wrong: {report.pid}"
    assert report.all_pids == [1234, 1235, 1236], f"All PIDs wrong: {report.all_pids}"


def test_p1_launch_apk_single_pid():
    """launch_apk() works correctly with a single PID response."""
    dr = static_analysis.DeviceReadiness(adb_connected=True, is_rooted=True)
    report = static_analysis.StaticReport(
        apk_path=FAKE_PACKAGE,
        package_name=FAKE_PACKAGE,
        main_activity=FAKE_ACTIVITY,
        has_launcher=True,
    )
    router = make_adb_router(overrides={"pidof": adb_ok("4321")})
    with patch("static_analysis.subprocess.run", side_effect=router):
        static_analysis.launch_apk(report, dr)
    assert report.pid     == 4321
    assert report.all_pids == [4321]


def test_p1_launch_apk_no_launcher_skipped():
    """Background APK: _trigger_background_apk() tries broadcast + service, records warning on failure."""
    dr = static_analysis.DeviceReadiness(adb_connected=True, is_rooted=True)
    report = static_analysis.StaticReport(
        apk_path=FAKE_PACKAGE,
        package_name=FAKE_PACKAGE,
        main_activity="",
        has_launcher=False,
        all_activities=[f"{FAKE_PACKAGE}.BackgroundService"],
    )
    # pidof always returns nothing — every trigger strategy fails
    router = make_adb_router(overrides={"pidof": adb_ok("")})
    with patch("static_analysis.subprocess.run", side_effect=router) as mock_run,          patch("static_analysis.time.sleep"):
        static_analysis.launch_apk(report, dr)

    # pid should remain None — no process appeared
    assert report.pid is None, "pid should be None when all trigger strategies fail"

    # A warning about the failed trigger should have been recorded
    assert any("trigger" in w.lower() or "background" in w.lower()
               for w in report.warnings),         f"Expected background trigger warning, got: {report.warnings}"

    # BOOT_COMPLETED broadcast should have been attempted
    all_calls = " ".join(" ".join(str(a) for a in c.args[0]) for c in mock_run.call_args_list)
    assert "BOOT_COMPLETED" in all_calls, "Expected BOOT_COMPLETED broadcast attempt"


def test_p1_launch_apk_pid_none_on_failure():
    """launch_apk() sets pid=None when pidof returns nothing after retries."""
    dr = static_analysis.DeviceReadiness(adb_connected=True, is_rooted=True)
    report = static_analysis.StaticReport(
        apk_path=FAKE_PACKAGE,
        package_name=FAKE_PACKAGE,
        main_activity=FAKE_ACTIVITY,
        has_launcher=True,
    )
    router = make_adb_router(overrides={"pidof": adb_ok("")})
    with patch("static_analysis.subprocess.run", side_effect=router), \
         patch("static_analysis.time.sleep"):   # skip real sleeps in test
        static_analysis.launch_apk(report, dr)
    assert report.pid is None
    assert len(report.all_pids) == 0


def test_p1_resolve_pids_ps_fallback():
    """_resolve_pids() falls back to ps -A when pidof is missing on the device."""
    ps_output = (
        "u0_a99  1234  567  12345  6789  0  0  S  " + FAKE_PACKAGE + "\n"
        "u0_a99  1235  1234 11111  5678  0  0  S  " + FAKE_PACKAGE + ":push\n"
    )

    def mock_run(cmd, **kwargs):
        cmd_str = " ".join(str(c) for c in cmd)
        if "pidof" in cmd_str:
            return adb_ok("")          # pidof returns nothing
        if "which" in cmd_str and "pidof" in cmd_str:
            return adb_ok("")          # pidof not found on device
        if "ps -A" in cmd_str:
            return adb_ok(ps_output)   # ps -A returns two processes
        return adb_ok()

    with patch("static_analysis.subprocess.run", side_effect=mock_run):
        pids = static_analysis._resolve_pids(FAKE_PACKAGE)

    assert pids == [1234, 1235], f"Expected [1234, 1235] from ps -A, got {pids}"


def test_p1_resolve_pids_pidof_takes_priority():
    """_resolve_pids() uses pidof result and never calls ps -A when pidof works."""
    call_log = []

    def mock_run(cmd, **kwargs):
        cmd_str = " ".join(str(c) for c in cmd)
        call_log.append(cmd_str)
        if "pidof" in cmd_str and "which" not in cmd_str:
            return adb_ok("9999")
        return adb_ok()

    with patch("static_analysis.subprocess.run", side_effect=mock_run):
        pids = static_analysis._resolve_pids(FAKE_PACKAGE)

    assert pids == [9999], f"Expected [9999] from pidof, got {pids}"
    assert not any("ps -A" in c for c in call_log),         "ps -A should not be called when pidof succeeds"


# ── P1.5: FIX 4 — ensure_frida_server() ─────────────────────

def test_p1_frida_server_already_running():
    """ensure_frida_server() skips start when Frida is already running."""
    dr = static_analysis.DeviceReadiness(frida_server_running=True)
    with patch("static_analysis.subprocess.run") as mock_run:
        result = static_analysis.ensure_frida_server(dr)
    assert result is True
    # nohup start must NOT have been called
    calls_str = " ".join(str(c) for c in mock_run.call_args_list)
    assert "nohup" not in calls_str, "Should not start frida-server if already running"


def test_p1_frida_server_starts_successfully():
    """ensure_frida_server() starts binary and confirms via ps -A."""
    dr = static_analysis.DeviceReadiness(frida_server_running=False)
    with patch("static_analysis.subprocess.run", side_effect=make_adb_router()), \
         patch("static_analysis.time.sleep"):
        result = static_analysis.ensure_frida_server(dr)
    assert result is True
    assert dr.frida_server_running is True


def test_p1_frida_server_binary_missing():
    """ensure_frida_server() returns False when binary not on device."""
    dr = static_analysis.DeviceReadiness(frida_server_running=False)
    def no_binary(cmd, **kwargs):
        cmd_str = " ".join(str(c) for c in cmd)
        if f"ls {static_analysis.Config.FRIDA_SERVER}" in cmd_str:
            return adb_fail(returncode=1)
        return adb_ok()

    with patch("static_analysis.subprocess.run", side_effect=no_binary):
        result = static_analysis.ensure_frida_server(dr)
    assert result is False
    assert dr.frida_server_running is False


# ── P1.6: save_report() ───────────────────────────────────────

def test_p1_save_report_creates_json():
    """save_report() writes valid JSON to disk with all expected keys."""
    report = static_analysis.StaticReport(
        apk_path=FAKE_PACKAGE,
        package_name=FAKE_PACKAGE,
        main_activity=FAKE_ACTIVITY,
        pid=1234,
        all_pids=[1234, 1235],
        env="dev",
        model="phi3.5-mini",
    )
    report.permissions = [
        static_analysis.Permission("android.permission.SEND_SMS", "DANGEROUS"),
        static_analysis.Permission("android.permission.VIBRATE",  "NORMAL"),
    ]
    report.device = static_analysis.DeviceReadiness(
        adb_connected=True, is_rooted=True,
        flag_secure_disabled=True, frida_server_running=True,
    )

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name
    try:
        static_analysis.save_report(report, out_path)
        loaded = json.loads(Path(out_path).read_text())
        assert loaded["package_name"]              == FAKE_PACKAGE
        assert loaded["pid"]                       == 1234
        assert loaded["all_pids"]                  == [1234, 1235]
        assert loaded["summary"]["screenshot_tier"] == 1
        assert loaded["summary"]["frida_ready"]    is True
        assert "SEND_SMS" in loaded["summary"]["dangerous_permissions"]
        assert "VIBRATE"  in loaded["summary"]["normal_permissions"]
    finally:
        Path(out_path).unlink(missing_ok=True)


def test_p1_save_report_summary_total_permissions():
    """Summary total_permissions counts all levels."""
    report = static_analysis.StaticReport(apk_path=FAKE_PACKAGE, package_name=FAKE_PACKAGE)
    report.permissions = [
        static_analysis.Permission("android.permission.SEND_SMS", "DANGEROUS"),
        static_analysis.Permission("android.permission.VIBRATE",  "NORMAL"),
        static_analysis.Permission("com.evil.CUSTOM",             "UNKNOWN"),
    ]
    report.device = static_analysis.DeviceReadiness()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name
    try:
        static_analysis.save_report(report, out_path)
        loaded = json.loads(Path(out_path).read_text())
        assert loaded["summary"]["total_permissions"] == 3
    finally:
        Path(out_path).unlink(missing_ok=True)


# ═════════════════════════════════════════════════════════════
#  PHASE 2 — REAL FUNCTION TESTS
# ═════════════════════════════════════════════════════════════

# ── P2.1: Session startup helpers ─────────────────────────────

def _write_fake_p1_report(tmp_dir):
    """Write a minimal valid Phase 1 report to disk and return the path."""
    report = {
        "package_name":  FAKE_PACKAGE,
        "main_activity": FAKE_ACTIVITY,
        "has_launcher":  True,
        "pid":           1234,
        "all_pids":      [1234, 1235, 1236],
        "env":           "dev",
        "model":         "phi3.5-mini",
        "permissions":   [],
        "receivers":     [],
        "indicators":    {"ipv4": [], "ipv6": [], "url": [], "api_key": []},
        "device":        {"adb_connected": True, "is_rooted": True,
                          "flag_secure_disabled": True, "frida_server_running": True,
                          "shamiko_active": True, "device_serial": FAKE_SERIAL,
                          "android_version": "13", "warnings": []},
        "summary": {
            "screenshot_tier": 1, "frida_ready": True, "root_confirmed": True,
            "shamiko_active": True, "flag_secure_disabled": True,
            "env": "dev", "model": "phi3.5-mini",
            "dangerous_permissions": [], "normal_permissions": [],
            "total_permissions": 0, "total_indicators": 0,
            "has_receivers": False, "has_launcher": True,
        }
    }
    p = Path(tmp_dir) / "static_report.json"
    p.write_text(json.dumps(report))
    return str(p)


def test_p2_load_phase1_report_valid():
    """load_phase1_report() reads a valid report without error."""
    with tempfile.TemporaryDirectory() as tmp:
        path   = _write_fake_p1_report(tmp)
        result = sentry.load_phase1_report(path)
    assert result["package_name"] == FAKE_PACKAGE
    assert result["pid"]          == 1234
    assert result["all_pids"]     == [1234, 1235, 1236]


def test_p2_load_phase1_report_missing_file():
    """load_phase1_report() calls sys.exit when file is absent."""
    import sys as _sys
    with patch.object(_sys, "exit", side_effect=SystemExit):
        try:
            sentry.load_phase1_report("/nonexistent/report.json")
            assert False, "Should have raised SystemExit"
        except SystemExit:
            pass  # expected


def test_p2_load_phase1_report_missing_fields():
    """load_phase1_report() calls sys.exit when required fields are absent."""
    import sys as _sys
    with tempfile.TemporaryDirectory() as tmp:
        bad = Path(tmp) / "bad.json"
        bad.write_text(json.dumps({"package_name": FAKE_PACKAGE}))  # missing pid/all_pids/summary
        with patch.object(_sys, "exit", side_effect=SystemExit):
            try:
                sentry.load_phase1_report(str(bad))
                assert False, "Should have raised SystemExit"
            except SystemExit:
                pass


def test_p2_verify_mitmproxy_cert_found():
    """verify_mitmproxy_cert() returns True when cert is in system store."""
    router = make_adb_router()
    with patch("sentry.subprocess.run", side_effect=router):
        result = sentry.verify_mitmproxy_cert()
    assert result is True


def test_p2_verify_mitmproxy_cert_missing():
    """verify_mitmproxy_cert() returns False and warns when cert absent."""
    def no_cert(cmd, **kwargs):
        cmd_str = " ".join(str(c) for c in cmd)
        if "grep" in cmd_str or "cacerts-added" in cmd_str:
            return adb_ok("")  # empty = not found
        return adb_ok()

    with patch("sentry.subprocess.run", side_effect=no_cert):
        result = sentry.verify_mitmproxy_cert()
    assert result is False


def test_p2_check_inotifywait_present():
    """check_inotifywait() returns True when binary is on device."""
    with patch("sentry.subprocess.run", side_effect=make_adb_router()):
        result = sentry.check_inotifywait()
    assert result is True


def test_p2_check_inotifywait_missing():
    """check_inotifywait() returns False when binary absent."""
    def no_inotify(cmd, **kwargs):
        cmd_str = " ".join(str(c) for c in cmd)
        if "inotifywait" in cmd_str:
            return adb_fail(returncode=1)
        return adb_ok()

    with patch("sentry.subprocess.run", side_effect=no_inotify):
        result = sentry.check_inotifywait()
    assert result is False


# ── P2.2: tag_permission() ───────────────────────────────────

def test_p2_tag_internet_okhttp():
    r = sentry.tag_permission("D/OkHttp: connect() to evil-c2.ru")
    assert r == "android.permission.INTERNET"

def test_p2_tag_send_sms():
    r = sentry.tag_permission("D/SMSLib: SmsManager.sendText called to +1234567890")
    assert r == "android.permission.SEND_SMS"

def test_p2_tag_read_sms_distinct_from_send():
    """READ_SMS is tagged correctly and NOT confused with SEND_SMS."""
    r = sentry.tag_permission("D/ContentProvider: content://sms query executed")
    assert r == "android.permission.READ_SMS", \
        f"Expected READ_SMS, got: {r}"

def test_p2_tag_location():
    r = sentry.tag_permission("D/Location: requestLocationUpdates GPS_PROVIDER")
    assert r == "android.permission.ACCESS_FINE_LOCATION"

def test_p2_tag_camera():
    r = sentry.tag_permission("D/Camera2: takePicture invoked")
    assert r == "android.permission.CAMERA"

def test_p2_tag_no_match():
    r = sentry.tag_permission("D/ActivityManager: App resumed normally")
    assert r == ""


# ── P2.3: is_private_ip() ────────────────────────────────────

def test_p2_private_ips_filtered():
    assert sentry.is_private_ip("192.168.1.1")  is True
    assert sentry.is_private_ip("10.0.0.5")     is True
    assert sentry.is_private_ip("127.0.0.1")    is True
    assert sentry.is_private_ip("172.16.0.1")   is True

def test_p2_public_ips_not_filtered():
    assert sentry.is_private_ip("185.220.101.47") is False
    assert sentry.is_private_ip("8.8.8.8")        is False
    assert sentry.is_private_ip("1.1.1.1")        is False


# ── P2.4: NetstatPoller._parse_netstat_line() ─────────────────

def _make_netstat_poller():
    """Build a NetstatPoller with a mocked baseline (no real ADB)."""
    session    = sentry.SentrySession(package_name=FAKE_PACKAGE)
    stop_event = threading.Event()
    with patch("sentry.subprocess.run", return_value=adb_ok("")):
        poller = sentry.NetstatPoller(session, stop_event)
    return poller


def test_p2_netstat_established_parsed():
    poller = _make_netstat_poller()
    line   = "tcp   0   0   0.0.0.0:54321   185.220.101.47:443   ESTABLISHED"
    conn   = poller._parse_netstat_line(line)
    assert conn is not None
    assert conn.remote_ip   == "185.220.101.47"
    assert conn.remote_port == 443
    assert conn.protocol    == "TCP"

def test_p2_netstat_private_excluded():
    poller = _make_netstat_poller()
    line   = "tcp   0   0   0.0.0.0:54321   192.168.1.100:80   ESTABLISHED"
    assert poller._parse_netstat_line(line) is None

def test_p2_netstat_listen_ignored():
    poller = _make_netstat_poller()
    line   = "tcp   0   0   0.0.0.0:8080   0.0.0.0:*   LISTEN"
    assert poller._parse_netstat_line(line) is None

def test_p2_netstat_syn_sent_captured():
    poller = _make_netstat_poller()
    line   = "tcp   0   0   0.0.0.0:54321   1.2.3.4:8080   SYN_SENT"
    conn   = poller._parse_netstat_line(line)
    assert conn is not None
    assert conn.remote_ip == "1.2.3.4"

def test_p2_netstat_ipv6_mapped_stripped():
    poller = _make_netstat_poller()
    line   = "tcp6   0   0   :::54321   ::ffff:185.220.101.47:443   ESTABLISHED"
    conn   = poller._parse_netstat_line(line)
    assert conn is not None
    assert "::ffff:" not in conn.remote_ip
    assert conn.remote_ip == "185.220.101.47"

def test_p2_netstat_malformed_ignored():
    poller = _make_netstat_poller()
    for bad in ["", "not a line", "tcp 0 0"]:
        assert poller._parse_netstat_line(bad) is None, \
            f"Should return None for malformed: {bad!r}"


# ── P2.5: NetstatPoller discovers new connections during run ──

def test_p2_netstat_poller_appends_new_connections():
    """NetstatPoller.run() appends new foreign connections to session."""
    session    = sentry.SentrySession(package_name=FAKE_PACKAGE)
    stop_event = threading.Event()

    netstat_output = (
        "tcp   0   0   0.0.0.0:54321   185.220.101.47:443   ESTABLISHED\n"
        "tcp   0   0   0.0.0.0:54322   8.8.8.8:53            ESTABLISHED\n"
    )
    call_count = [0]
    def mock_run(cmd, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return adb_ok("")             # seed baseline — empty
        stop_event.set()                  # stop after first poll
        return adb_ok(netstat_output)

    with patch("sentry.subprocess.run", side_effect=mock_run), \
         patch("sentry.time.sleep"):
        poller = sentry.NetstatPoller(session, stop_event)
        poller.run()

    ips = {c.remote_ip for c in session.network_connections}
    assert "185.220.101.47" in ips, f"Expected 185.220.101.47 in {ips}"
    assert "8.8.8.8"        in ips, f"Expected 8.8.8.8 in {ips}"


# ── P2.6: ExfiltrationAddon ──────────────────────────────────

def _make_fake_flow(url, method, body, scheme="https"):
    """Build a fake mitmproxy HTTPFlow for ExfiltrationAddon testing."""
    flow = MagicMock()
    flow.request.pretty_host = url.split("/")[2] if "/" in url else url
    flow.request.pretty_url  = url
    flow.request.method      = method
    flow.request.scheme      = scheme
    flow.request.get_text.return_value = body
    return flow


def test_p2_exfil_contacts_detected():
    session = sentry.SentrySession(package_name=FAKE_PACKAGE)
    addon   = sentry.ExfiltrationAddon(session)
    flow    = _make_fake_flow("https://evil.ru/upload", "POST",
                              '{"data": "victim@gmail.com,other@yahoo.com"}')
    addon.request(flow)
    assert any(e.data_type == "contacts" for e in session.exfiltration_events), \
        "Contacts exfiltration not detected"


def test_p2_exfil_location_detected():
    session = sentry.SentrySession(package_name=FAKE_PACKAGE)
    addon   = sentry.ExfiltrationAddon(session)
    flow    = _make_fake_flow("https://evil.ru/loc", "POST",
                              '{"lat": 51.5074, "lng": -0.1278}')
    addon.request(flow)
    assert any(e.data_type == "location" for e in session.exfiltration_events)


def test_p2_exfil_sms_detected():
    session = sentry.SentrySession(package_name=FAKE_PACKAGE)
    addon   = sentry.ExfiltrationAddon(session)
    flow    = _make_fake_flow("https://evil.ru/sms", "POST",
                              '{"message": "Your OTP code is 123456"}')
    addon.request(flow)
    assert any(e.data_type == "sms" for e in session.exfiltration_events)


def test_p2_exfil_imei_detected():
    session = sentry.SentrySession(package_name=FAKE_PACKAGE)
    addon   = sentry.ExfiltrationAddon(session)
    flow    = _make_fake_flow("https://evil.ru/reg", "POST",
                              '{"device_id": "358742089234671"}')
    addon.request(flow)
    assert any(e.data_type == "imei" for e in session.exfiltration_events)


def test_p2_exfil_credentials_detected():
    session = sentry.SentrySession(package_name=FAKE_PACKAGE)
    addon   = sentry.ExfiltrationAddon(session)
    flow    = _make_fake_flow("https://evil.ru/login", "POST",
                              '{"password": "hunter2", "user": "victim"}')
    addon.request(flow)
    assert any(e.data_type == "credentials" for e in session.exfiltration_events)


def test_p2_exfil_clean_body_no_alert():
    session = sentry.SentrySession(package_name=FAKE_PACKAGE)
    addon   = sentry.ExfiltrationAddon(session)
    flow    = _make_fake_flow("https://evil.ru/ping", "GET",
                              '{"status": "ok", "version": "1.0.0"}')
    addon.request(flow)
    assert len(session.exfiltration_events) == 0, \
        f"Clean body triggered false positive: {session.exfiltration_events}"


def test_p2_exfil_ssl_pinning_flag_set():
    """ExfiltrationAddon marks ssl_pinning_bypassed=True for HTTPS requests."""
    session = sentry.SentrySession(package_name=FAKE_PACKAGE)
    addon   = sentry.ExfiltrationAddon(session)
    flow    = _make_fake_flow("https://evil.ru/upload", "POST",
                              '{"email": "victim@evil.com"}', scheme="https")
    addon.request(flow)
    assert session.exfiltration_events[0].ssl_pinning_bypassed is True


def test_p2_exfil_multiple_types_same_request():
    """Multiple exfiltration types in one request body are all detected."""
    session = sentry.SentrySession(package_name=FAKE_PACKAGE)
    addon   = sentry.ExfiltrationAddon(session)
    flow    = _make_fake_flow("https://evil.ru/dump", "POST",
                              '{"email": "a@b.com", "lat": 51.5, "password": "secret1"}')
    addon.request(flow)
    types = {e.data_type for e in session.exfiltration_events}
    assert "contacts"    in types
    assert "location"    in types
    assert "credentials" in types


def test_p2_exfil_permission_mapped():
    """ExfiltrationAddon maps exfiltration type to the correct permission."""
    session = sentry.SentrySession(package_name=FAKE_PACKAGE)
    addon   = sentry.ExfiltrationAddon(session)
    flow    = _make_fake_flow("https://evil.ru/contacts", "POST",
                              '{"email": "victim@gmail.com"}')
    addon.request(flow)
    evt = next(e for e in session.exfiltration_events if e.data_type == "contacts")
    assert evt.permission_implicated == "android.permission.READ_CONTACTS"


# ── P2.7: DropperHandler ─────────────────────────────────────

def test_p2_dropper_step1_sdcard_pull():
    """DropperHandler pulls from /sdcard/ path when step 1 succeeds."""
    with tempfile.TemporaryDirectory() as tmp:
        session = sentry.SentrySession(package_name=FAKE_PACKAGE)
        handler = sentry.DropperHandler(session, tmp)

        # Step 1 succeeds: adb pull writes a real file to the LOCAL destination
        # adb pull <device_src> <local_dest>  — local dest is always cmd[-1]
        def mock_run(cmd, **kwargs):
            cmd_str = " ".join(str(c) for c in cmd)
            if any(c == "pull" for c in cmd):
                # adb pull <device_src> <local_dest> — always write to cmd[-1]
                local_dest = str(cmd[-1])
                if local_dest.endswith(".apk"):
                    Path(local_dest).write_bytes(b"PK\x03\x04fake_apk_content")
                return adb_ok()
            if "pm list packages" in cmd_str:
                return adb_ok(f"package:{FAKE_PACKAGE}\n")
            if "pm path" in cmd_str:
                return adb_ok(f"package:/data/app/{FAKE_PACKAGE}-xxx/base.apk")
            return adb_ok()

        with patch("sentry.subprocess.run",  side_effect=mock_run), \
             patch("sentry.subprocess.Popen", MagicMock()), \
             patch("sentry.time.sleep"):
            evt = handler.handle("inotifywait", "/sdcard/Download/payload.apk")

        assert evt is not None, "Expected a DropperEvent, got None"
        assert evt.trigger      == "inotifywait"
        assert evt.device_path  == "/sdcard/Download/payload.apk"
        assert len(evt.sha256)  == 64
        assert "sdcard" in evt.pull_method


def test_p2_dropper_step2_data_app_fallback():
    """DropperHandler falls back to /data/app/ when /sdcard/ pull fails."""
    with tempfile.TemporaryDirectory() as tmp:
        session = sentry.SentrySession(package_name=FAKE_PACKAGE)
        handler = sentry.DropperHandler(session, tmp)

        new_pkg = "com.evil.dropped"
        call_count = [0]

        def mock_run(cmd, **kwargs):
            cmd_str = " ".join(str(c) for c in cmd)
            if "pm list packages" in cmd_str:
                call_count[0] += 1
                if call_count[0] == 1:
                    return adb_ok(f"package:{FAKE_PACKAGE}\n")
                return adb_ok(f"package:{FAKE_PACKAGE}\npackage:{new_pkg}\n")
            if "pm path" in cmd_str and new_pkg in cmd_str:
                return adb_ok(f"package:/data/app/{new_pkg}-abc/base.apk")
            if any(c == "pull" for c in cmd) and "tmp_pull" in cmd_str:
                # Backup pull (adb pull /sdcard/tmp_pull... <local_dest>)
                local_dest = str(cmd[-1])
                if local_dest.endswith(".apk"):
                    Path(local_dest).write_bytes(b"PK\x03\x04fake_dropper_apk")
                return adb_ok()
            if any(c == "pull" for c in cmd):
                return adb_fail()  # /sdcard/ direct pull fails
            return adb_ok()

        with patch("sentry.subprocess.run",  side_effect=mock_run), \
             patch("sentry.subprocess.Popen", MagicMock()), \
             patch("sentry.time.sleep"):
            evt = handler.handle("inotifywait", "/sdcard/Download/payload.apk")

        assert evt is not None, "Expected DropperEvent even when step 1 fails"
        assert "data_app" in evt.pull_method, \
            f"Expected data_app pull, got: {evt.pull_method}"
        assert evt.package_name == new_pkg


def test_p2_dropper_both_pulls_fail_returns_none():
    """DropperHandler returns None and records warning when both pulls fail."""
    with tempfile.TemporaryDirectory() as tmp:
        session = sentry.SentrySession(package_name=FAKE_PACKAGE)
        handler = sentry.DropperHandler(session, tmp)

        def mock_run(cmd, **kwargs):
            cmd_str = " ".join(str(c) for c in cmd)
            if "pm list packages" in cmd_str:
                return adb_ok(f"package:{FAKE_PACKAGE}\n")  # no new package appears
            if "pull" in cmd_str:
                return adb_fail()
            return adb_ok()

        with patch("sentry.subprocess.run",  side_effect=mock_run), \
             patch("sentry.subprocess.Popen", MagicMock()), \
             patch("sentry.time.sleep"):
            evt = handler.handle("inotifywait", "/sdcard/Download/payload.apk")

        assert evt is None
        assert len(session.warnings) > 0, "Expected warning when pull fails"


def test_p2_dropper_counter_increments():
    """Each dropper gets a sequentially incremented index."""
    with tempfile.TemporaryDirectory() as tmp:
        session = sentry.SentrySession(package_name=FAKE_PACKAGE)
        handler = sentry.DropperHandler(session, tmp)

        call_count = [0]
        new_pkgs   = ["com.evil.dropped1", "com.evil.dropped2"]

        def mock_run(cmd, **kwargs):
            cmd_str = " ".join(str(c) for c in cmd)
            if "pm list packages" in cmd_str:
                call_count[0] += 1
                base = f"package:{FAKE_PACKAGE}\n"
                if call_count[0] > 1:
                    base += f"package:{new_pkgs[min(call_count[0]//2, 1)]}\n"
                return adb_ok(base)
            if "pm path" in cmd_str:
                return adb_ok(f"package:/data/app/dropped-xxx/base.apk")
            if any(c == "pull" for c in cmd):
                # Write to local destination = cmd[-1]
                local_dest = str(cmd[-1])
                if local_dest.endswith(".apk"):
                    Path(local_dest).write_bytes(b"PK\x03\x04")
                return adb_ok()
            return adb_ok()

        with patch("sentry.subprocess.run",  side_effect=mock_run), \
             patch("sentry.subprocess.Popen", MagicMock()), \
             patch("sentry.time.sleep"):
            evt1 = handler.handle("inotifywait", "/sdcard/d1.apk")
            evt2 = handler.handle("polling",     "/sdcard/d2.apk")

        if evt1 and evt2:
            assert evt1.index == 1, f"First dropper should be index 1, got {evt1.index}"
            assert evt2.index == 2, f"Second dropper should be index 2, got {evt2.index}"


# ── P2.8: save_sentry_session() ──────────────────────────────

def test_p2_save_sentry_session_json():
    """save_sentry_session() writes valid JSON with all summary fields."""
    session = sentry.SentrySession(
        package_name=FAKE_PACKAGE,
        session_start="2025-01-01 12:00:00.000",
        session_end  ="2025-01-01 12:05:00.000",
        all_pids=[1234, 1235],
    )
    session.log_events.append(sentry.LogEvent(
        timestamp="2025-01-01 12:00:01.000",
        pid=1234, tag="SMSLib", level="D",
        message="SmsManager.sendText called",
        permission_implicated="android.permission.SEND_SMS",
    ))
    session.log_events.append(sentry.LogEvent(
        timestamp="2025-01-01 12:00:02.000",
        pid=1234, tag="OkHttp", level="D",
        message="connect() to evil-c2.ru",
        permission_implicated="android.permission.INTERNET",
    ))
    session.network_connections.append(sentry.NetworkConnection(
        timestamp="...", remote_ip="185.220.101.47",
        remote_port=443, local_port=54321,
    ))

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name
    try:
        sentry.save_sentry_session(session, out_path)
        loaded = json.loads(Path(out_path).read_text())

        assert loaded["package_name"]                     == FAKE_PACKAGE
        assert loaded["summary"]["total_log_events"]      == 2
        assert loaded["summary"]["total_network_connections"] == 1
        assert "android.permission.SEND_SMS" in loaded["summary"]["permission_hit_counts"]
        assert "android.permission.INTERNET" in loaded["summary"]["permission_hit_counts"]
        assert len(loaded["summary"]["unique_remote_ips"]) == 1
    finally:
        Path(out_path).unlink(missing_ok=True)


def test_p2_save_sentry_session_abuse_scores():
    """Abuse scores in saved report are correct (hits × weight)."""
    session = sentry.SentrySession(package_name=FAKE_PACKAGE)
    # SEND_SMS: weight=10. Add 5 log events tagging it.
    for _ in range(5):
        session.log_events.append(sentry.LogEvent(
            timestamp="...", pid=1234, tag="SMS", level="D",
            message="SmsManager.sendText called",
            permission_implicated="android.permission.SEND_SMS",
        ))

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name
    try:
        sentry.save_sentry_session(session, out_path)
        loaded = json.loads(Path(out_path).read_text())
        scores = loaded["summary"]["abuse_scores"]
        assert scores["android.permission.SEND_SMS"] == 50, \
            f"Expected 50 (5 hits × weight 10), got {scores.get('android.permission.SEND_SMS')}"
    finally:
        Path(out_path).unlink(missing_ok=True)


def test_p2_save_sentry_session_top_permissions_ranked():
    """Top abused permissions in summary are ranked highest-score first."""
    session = sentry.SentrySession(package_name=FAKE_PACKAGE)
    # INTERNET: weight=6, 20 hits → score 120
    # SEND_SMS: weight=10, 3 hits → score 30
    for _ in range(20):
        session.log_events.append(sentry.LogEvent(
            timestamp="...", pid=1234, tag="Net", level="D",
            message="OkHttp connect()",
            permission_implicated="android.permission.INTERNET",
        ))
    for _ in range(3):
        session.log_events.append(sentry.LogEvent(
            timestamp="...", pid=1234, tag="SMS", level="D",
            message="SmsManager.sendText called",
            permission_implicated="android.permission.SEND_SMS",
        ))

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name
    try:
        sentry.save_sentry_session(session, out_path)
        loaded = json.loads(Path(out_path).read_text())
        top    = loaded["summary"]["top_abused_permissions"]
        assert top[0] == "android.permission.INTERNET", \
            f"INTERNET should rank #1 (score 120), got: {top[0]}"
    finally:
        Path(out_path).unlink(missing_ok=True)


# ── P2.9: RootDetectionMonitor ───────────────────────────────

def test_p2_root_detection_fires_within_window():
    """RootDetectionMonitor fires when app dies within ROOT_DETECT_WINDOW."""
    session    = sentry.SentrySession(package_name=FAKE_PACKAGE)
    stop_event = threading.Event()
    fired      = threading.Event()

    def on_root_detected():
        fired.set()

    # pidof returns empty → process not alive
    with patch("sentry.subprocess.run", return_value=adb_ok("")):
        monitor = sentry.RootDetectionMonitor(
            package_name=FAKE_PACKAGE, primary_pid=1234,
            session=session, stop_event=stop_event,
            on_root_detected=on_root_detected,
        )
        monitor.start()
        fired.wait(timeout=5)
        monitor.join(timeout=3)

    assert session.root_detected is True,   "root_detected should be True"
    assert fired.is_set(),                  "on_root_detected callback should have fired"


def test_p2_root_detection_does_not_fire_when_alive():
    """RootDetectionMonitor does NOT fire when process stays alive."""
    session    = sentry.SentrySession(package_name=FAKE_PACKAGE)
    stop_event = threading.Event()
    fired      = threading.Event()

    def on_root_detected():
        fired.set()

    # pidof returns a PID → still alive
    with patch("sentry.subprocess.run", return_value=adb_ok("1234")):
        monitor = sentry.RootDetectionMonitor(
            package_name=FAKE_PACKAGE, primary_pid=1234,
            session=session, stop_event=stop_event,
            on_root_detected=on_root_detected,
        )
        # Simulate that the ROOT_DETECT_WINDOW has already passed
        monitor.launch_time = time.time() - (sentry.Config.ROOT_DETECT_WINDOW + 1)
        monitor.start()
        monitor.join(timeout=3)

    assert session.root_detected is False
    assert not fired.is_set()


# ─────────────────────────────────────────────────────────────
# INTEGRATION — Phase 1 JSON → Phase 2 startup chain
# ─────────────────────────────────────────────────────────────

def test_integration_p1_report_consumed_by_p2():
    """Full handoff: Phase 1 writes report, Phase 2 reads and validates it."""
    # Phase 1 side: build and save a real report
    p1_report = static_analysis.StaticReport(
        apk_path=FAKE_PACKAGE,
        package_name=FAKE_PACKAGE,
        main_activity=FAKE_ACTIVITY,
        pid=1234,
        all_pids=[1234, 1235, 1236],
        env="dev",
        model="phi3.5-mini",
    )
    p1_report.permissions = [
        static_analysis.Permission("android.permission.SEND_SMS", "DANGEROUS"),
    ]
    p1_report.device = static_analysis.DeviceReadiness(
        adb_connected=True, is_rooted=True,
        flag_secure_disabled=True, frida_server_running=True,
    )

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        report_path = f.name

    try:
        static_analysis.save_report(p1_report, report_path)
        # Phase 2 side: load and validate
        loaded = sentry.load_phase1_report(report_path)

        assert loaded["package_name"]              == FAKE_PACKAGE
        assert loaded["all_pids"]                  == [1234, 1235, 1236]
        assert loaded["summary"]["frida_ready"]    is True
        assert loaded["summary"]["screenshot_tier"] == 1
    finally:
        Path(report_path).unlink(missing_ok=True)


def test_integration_all_pids_flow_to_logcat_filter():
    """PIDs from Phase 1 report correctly populate the Phase 2 PID filter set."""
    with tempfile.TemporaryDirectory() as tmp:
        path   = _write_fake_p1_report(tmp)
        loaded = sentry.load_phase1_report(path)

    all_pids      = set(str(p) for p in loaded["all_pids"])
    should_keep   = {"1234": True, "1235": True, "1236": True, "9999": False}

    for pid_str, expected in should_keep.items():
        assert (pid_str in all_pids) == expected, \
            f"PID filter wrong for {pid_str} (expected {expected})"


def test_integration_exfil_event_ties_to_permission():
    """An exfiltration event's permission_implicated is present in Phase 1 dangerous perms."""
    session = sentry.SentrySession(package_name=FAKE_PACKAGE)
    addon   = sentry.ExfiltrationAddon(session)
    flow    = _make_fake_flow("https://evil.ru/sms", "POST",
                              '{"message": "OTP is 9876"}')
    addon.request(flow)

    p2_perm = session.exfiltration_events[0].permission_implicated
    assert p2_perm == "android.permission.READ_SMS"
    # That permission exists in Phase 1's PERMISSION_TAXONOMY  [v3-5]
    assert p2_perm in static_analysis.PERMISSION_TAXONOMY


# ═════════════════════════════════════════════════════════════
#  PHASE 1 v3 — NEW FUNCTION TESTS
# ═════════════════════════════════════════════════════════════

# ── Shared manifest XML builder ───────────────────────────────

def make_mock_manifest_xml(
    debuggable="false",
    allow_backup="true",
    cleartext_traffic="false",
    has_nsc=False,
    target_sdk="33",
    min_sdk="21",
    exported_activity=None,
    exported_service=None,
    single_task_activity=None,
):
    """
    Build a minimal AndroidManifest.xml string for scan_manifest_security() tests.
    Returns a minidom Document via xml.dom.minidom so it can be used as
    the return value of apk_obj.get_android_manifest_xml().
    """
    from xml.dom.minidom import parseString

    ns = "http://schemas.android.com/apk/res/android"
    nsc_attr = f' android:networkSecurityConfig="@xml/nsc"' if has_nsc else ""
    exported_act_xml = ""
    if exported_activity:
        exported_act_xml = (
            f'<activity android:name="{exported_activity}" android:exported="true" />'
        )
    exported_svc_xml = ""
    if exported_service:
        exported_svc_xml = (
            f'<service android:name="{exported_service}" android:exported="true" />'
        )
    single_task_xml = ""
    if single_task_activity:
        single_task_xml = (
            f'<activity android:name="{single_task_activity}" '
            f'android:launchMode="singleTask" android:exported="true" />'
        )

    xml_str = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ns}"
    package="{FAKE_PACKAGE}">
  <uses-sdk
      android:minSdkVersion="{min_sdk}"
      android:targetSdkVersion="{target_sdk}" />
  <application
      android:debuggable="{debuggable}"
      android:allowBackup="{allow_backup}"
      android:usesCleartextTraffic="{cleartext_traffic}"{nsc_attr}>
    {exported_act_xml}
    {exported_svc_xml}
    {single_task_xml}
  </application>
</manifest>"""
    return parseString(xml_str)


def _make_mock_apk_for_manifest(manifest_doc):
    """
    Return a mock APK object whose get_android_manifest_xml() returns
    the given minidom Document. Used by scan_manifest_security() tests.
    """
    mock_apk = MagicMock(name="MockAPKManifest")
    mock_apk.get_android_manifest_xml.return_value = manifest_doc
    return mock_apk


# ── P1.7: Permission taxonomy [v3-5] ─────────────────────────

def test_p1_taxonomy_dangerous_perms_have_risk_score():
    """Every entry in PERMISSION_TAXONOMY has a non-zero risk_score."""
    for perm, data in static_analysis.PERMISSION_TAXONOMY.items():
        assert data.get("risk_score", 0) > 0, \
            f"Permission {perm} has no risk_score"
        assert data.get("description"), \
            f"Permission {perm} has no description"
        assert data.get("level") == "DANGEROUS", \
            f"Permission {perm} level should be DANGEROUS"


def test_p1_taxonomy_permission_object_carries_risk_fields():
    """Permission objects built from DANGEROUS perms carry risk_score + description."""
    p = _tmp_apk()
    try:
        with patch("static_analysis.AnalyzeAPK", return_value=make_analyze_apk_return()):
            report = static_analysis.parse_apk(p)
        sms = next(
            perm for perm in report.permissions
            if perm.name == "android.permission.SEND_SMS"
        )
        assert sms.risk_score > 0, "SEND_SMS should have a non-zero risk_score"
        assert sms.description,    "SEND_SMS should have a description"
    finally:
        Path(p).unlink(missing_ok=True)


def test_p1_taxonomy_normal_perm_has_zero_risk_score():
    """NORMAL permissions have risk_score=0 (not in taxonomy)."""
    p = _tmp_apk()
    try:
        with patch("static_analysis.AnalyzeAPK", return_value=make_analyze_apk_return()):
            report = static_analysis.parse_apk(p)
        vibrate = next(
            perm for perm in report.permissions
            if perm.name == "android.permission.VIBRATE"
        )
        assert vibrate.risk_score == 0, "NORMAL perms should have risk_score=0"
    finally:
        Path(p).unlink(missing_ok=True)


def test_p1_save_report_includes_permission_risk_summary():
    """save_report() summary includes permission_risk_score and top_risk_permissions."""
    report = static_analysis.StaticReport(
        apk_path=FAKE_PACKAGE, package_name=FAKE_PACKAGE
    )
    report.permissions = [
        static_analysis.Permission(
            "android.permission.SEND_SMS", "DANGEROUS",
            description="Send SMS", risk_score=9,
        ),
        static_analysis.Permission(
            "android.permission.RECORD_AUDIO", "DANGEROUS",
            description="Record audio", risk_score=10,
        ),
        static_analysis.Permission("android.permission.VIBRATE", "NORMAL"),
    ]
    report.device = static_analysis.DeviceReadiness()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name
    try:
        static_analysis.save_report(report, out_path)
        loaded = json.loads(Path(out_path).read_text())
        summary = loaded["summary"]
        assert summary["permission_risk_score"] == 19, \
            f"Expected 19, got {summary['permission_risk_score']}"
        assert len(summary["top_risk_permissions"]) == 2
        # RECORD_AUDIO (10) should rank above SEND_SMS (9)
        top = summary["top_risk_permissions"]
        assert top[0]["short"] == "RECORD_AUDIO", \
            f"Expected RECORD_AUDIO first, got {top[0]['short']}"
    finally:
        Path(out_path).unlink(missing_ok=True)


# ── P1.8: URL regex fix [v3-1] ───────────────────────────────

def test_p1_url_regex_rejects_css_noise():
    """[v3-1] Tightened URL regex does NOT match CSS/HTML junk strings."""
    noise = [
        "http://style=",
        "http://www./div",
        "https://",
        "http://x",                   # no TLD
        "https://nodot",              # no dot at all
    ]
    pattern = static_analysis.INDICATORS["url"]
    for s in noise:
        matches = pattern.findall(s)
        assert not matches, \
            f"URL regex should NOT match CSS noise: {s!r}  got: {matches}"


def test_p1_url_regex_accepts_real_urls():
    """[v3-1] Tightened URL regex still matches real C2 and CDN URLs."""
    valid = [
        "https://evil-c2.ru/upload",
        "https://cdn.google.com/api",
        "http://185.220.101.47/payload",   # bare IP with path — matched via host label
        "https://sub.domain.co.uk/path?q=1",
        "http://malware.biz",
    ]
    pattern = static_analysis.INDICATORS["url"]
    for s in valid:
        matches = pattern.findall(s)
        assert matches, f"URL regex should match real URL: {s!r}"


def test_p1_scan_indicators_no_css_false_positives():
    """scan_indicators() does not emit CSS/HTML junk as URLs."""
    css_strings = [
        "http://style=color:red",
        "https://",
        "http://www./floatingdiv",
        "http://x",
        "normal string",
        "https://evil-c2.ru/upload",    # this one SHOULD appear
    ]
    report = static_analysis.StaticReport(apk_path=FAKE_PACKAGE, package_name=FAKE_PACKAGE)
    with patch("static_analysis.AnalyzeAPK",
               return_value=make_analyze_apk_return(strings=css_strings)):
        static_analysis.scan_indicators(FAKE_PACKAGE, report)

    urls = report.indicators["url"]
    assert "https://evil-c2.ru/upload" in urls, "Real C2 URL should be present"
    for u in urls:
        assert "style=" not in u, f"CSS noise leaked into indicators: {u}"
        assert u.count(".") >= 1,  f"URL without TLD leaked: {u}"


# ── P1.9: scan_manifest_security [v3-2] ──────────────────────

def _run_manifest_scan(manifest_doc, apk_path="fake.apk"):
    """Helper: patch AnalyzeAPK for manifest scan and run scan_manifest_security()."""
    report = static_analysis.StaticReport(apk_path=apk_path, package_name=FAKE_PACKAGE)
    mock_apk = _make_mock_apk_for_manifest(manifest_doc)
    with patch("static_analysis.AnalyzeAPK", return_value=(mock_apk, [], MagicMock())):
        static_analysis.scan_manifest_security(apk_path, report)
    return report


def test_p1_manifest_debuggable_flagged():
    """debuggable=true produces a HIGH manifest issue."""
    doc    = make_mock_manifest_xml(debuggable="true")
    report = _run_manifest_scan(doc)
    ms     = report.manifest_security
    assert ms.debuggable is True
    high_rules = [i.rule for i in ms.issues if i.severity == "high"]
    assert "app_is_debuggable" in high_rules, \
        f"Expected app_is_debuggable in high issues, got: {high_rules}"


def test_p1_manifest_not_debuggable_no_issue():
    """debuggable=false produces no debuggable issue."""
    doc    = make_mock_manifest_xml(debuggable="false")
    report = _run_manifest_scan(doc)
    assert report.manifest_security.debuggable is False
    assert not any(i.rule == "app_is_debuggable" for i in report.manifest_security.issues)


def test_p1_manifest_allow_backup_flagged():
    """allowBackup=true produces a WARNING manifest issue."""
    doc    = make_mock_manifest_xml(allow_backup="true")
    report = _run_manifest_scan(doc)
    ms     = report.manifest_security
    assert ms.allow_backup is True
    warning_rules = [i.rule for i in ms.issues if i.severity == "warning"]
    assert "app_allowbackup" in warning_rules, \
        f"Expected app_allowbackup in warnings, got: {warning_rules}"


def test_p1_manifest_cleartext_traffic_flagged():
    """usesCleartextTraffic=true produces a WARNING issue."""
    doc    = make_mock_manifest_xml(cleartext_traffic="true")
    report = _run_manifest_scan(doc)
    assert report.manifest_security.cleartext_traffic is True
    warning_rules = [i.rule for i in report.manifest_security.issues if i.severity == "warning"]
    assert "clear_text_traffic" in warning_rules


def test_p1_manifest_exported_activity_no_permission_flagged():
    """Exported activity with no permission produces a HIGH issue."""
    doc    = make_mock_manifest_xml(exported_activity="com.evil.malware.HiddenActivity")
    report = _run_manifest_scan(doc)
    ms     = report.manifest_security
    assert "com.evil.malware.HiddenActivity" in ms.exported_activities
    high_rules = [i.rule for i in ms.issues if i.severity == "high"]
    assert "exported_no_permission" in high_rules, \
        f"Expected exported_no_permission in high issues, got: {high_rules}"


def test_p1_manifest_exported_service_no_permission_flagged():
    """Exported service with no permission produces a HIGH issue."""
    doc    = make_mock_manifest_xml(exported_service="com.evil.malware.SpyService")
    report = _run_manifest_scan(doc)
    ms     = report.manifest_security
    assert "com.evil.malware.SpyService" in ms.exported_services


def test_p1_manifest_task_hijacking_flagged():
    """singleTask activity on targetSdk < 28 produces a HIGH task_hijacking issue."""
    doc    = make_mock_manifest_xml(
        target_sdk="27",
        single_task_activity="com.evil.malware.MainActivity",
    )
    report = _run_manifest_scan(doc)
    ms     = report.manifest_security
    assert "com.evil.malware.MainActivity" in ms.task_hijacking_activities
    high_rules = [i.rule for i in ms.issues if i.severity == "high"]
    assert "task_hijacking" in high_rules


def test_p1_manifest_task_hijacking_not_flagged_on_high_sdk():
    """singleTask on targetSdk >= 28 does NOT produce task_hijacking issue."""
    doc    = make_mock_manifest_xml(
        target_sdk="33",
        single_task_activity="com.evil.malware.MainActivity",
    )
    report = _run_manifest_scan(doc)
    assert "task_hijacking" not in [i.rule for i in report.manifest_security.issues]


def test_p1_manifest_network_security_config_recorded():
    """networkSecurityConfig presence is recorded in manifest_security."""
    doc    = make_mock_manifest_xml(has_nsc=True)
    report = _run_manifest_scan(doc)
    assert report.manifest_security.has_network_security_config is True
    assert report.manifest_security.network_security_config_ref != ""


def test_p1_manifest_low_target_sdk_flagged():
    """targetSdkVersion < 28 produces a low_target_sdk WARNING."""
    doc    = make_mock_manifest_xml(target_sdk="25", min_sdk="16")
    report = _run_manifest_scan(doc)
    warning_rules = [i.rule for i in report.manifest_security.issues if i.severity == "warning"]
    assert "low_target_sdk" in warning_rules, \
        f"Expected low_target_sdk warning, got: {warning_rules}"


def test_p1_manifest_summary_in_save_report():
    """save_report() includes manifest_issues block with issue counts."""
    report = static_analysis.StaticReport(
        apk_path=FAKE_PACKAGE, package_name=FAKE_PACKAGE
    )
    report.device = static_analysis.DeviceReadiness()
    # Manually inject a manifest issue
    report.manifest_security.debuggable = True
    report.manifest_security.issues.append(
        static_analysis.ManifestIssue(
            rule="app_is_debuggable",
            title="Application is debuggable",
            severity="high",
            description="...",
        )
    )
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name
    try:
        static_analysis.save_report(report, out_path)
        loaded = json.loads(Path(out_path).read_text())
        mi = loaded["summary"]["manifest_issues"]
        assert mi["debuggable"] is True
        assert mi["high_count"] == 1
        assert any(i["rule"] == "app_is_debuggable" for i in mi["issues"])
    finally:
        Path(out_path).unlink(missing_ok=True)


# ── P1.10: scan_certificate [v3-3] ───────────────────────────

def _make_self_signed_cert_der() -> bytes:
    """
    Generate a minimal self-signed DER certificate using only stdlib.
    Uses a pre-baked DER blob (RSA, SHA-1, self-signed) that is
    small enough to embed here but parseable by ssl._test_decode_cert.
    If cert generation is unavailable, return None to skip the test.
    """
    try:
        # cryptography library preferred if available
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from datetime import timedelta

        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Evil Malware"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2021, 1, 1, tzinfo=timezone.utc))  # expired
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)
    except ImportError:
        return None


def _make_fake_apk_with_cert(tmp_dir: str, cert_der: bytes) -> str:
    """Write a minimal ZIP file that looks like an APK with a signing cert."""
    apk_path = str(Path(tmp_dir) / "fake.apk")
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("META-INF/CERT.RSA", cert_der)
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
        zf.writestr("classes.dex", b"dex\n035\x00")
    return apk_path


def test_p1_cert_self_signed_detected():
    """scan_certificate() detects self-signed certificates."""
    cert_der = _make_self_signed_cert_der()
    if cert_der is None:
        return  # cryptography library not available — skip gracefully

    with tempfile.TemporaryDirectory() as tmp:
        apk_path = _make_fake_apk_with_cert(tmp, cert_der)
        report   = static_analysis.StaticReport(apk_path=apk_path, package_name=FAKE_PACKAGE)
        static_analysis.scan_certificate(apk_path, report)

    ci = report.certificate
    assert ci.error == "", f"Unexpected cert error: {ci.error}"
    assert ci.is_self_signed is True, "Expected self-signed detection"
    assert ci.sha256_fingerprint != "", "Expected SHA-256 fingerprint"


def test_p1_cert_expired_detected():
    """scan_certificate() flags an expired certificate."""
    cert_der = _make_self_signed_cert_der()
    if cert_der is None:
        return

    with tempfile.TemporaryDirectory() as tmp:
        apk_path = _make_fake_apk_with_cert(tmp, cert_der)
        report   = static_analysis.StaticReport(apk_path=apk_path, package_name=FAKE_PACKAGE)
        static_analysis.scan_certificate(apk_path, report)

    # The fake cert expires 2021-01-01 — always expired now
    assert report.certificate.is_expired is True


def test_p1_cert_no_meta_inf_graceful():
    """scan_certificate() handles APKs with no META-INF cert gracefully."""
    with tempfile.TemporaryDirectory() as tmp:
        apk_path = str(Path(tmp) / "no_cert.apk")
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
        report = static_analysis.StaticReport(apk_path=apk_path, package_name=FAKE_PACKAGE)
        static_analysis.scan_certificate(apk_path, report)

    assert report.certificate.error != "", "Expected error message when no cert found"
    assert len(report.certificate.sha256_fingerprint) == 0


def test_p1_cert_summary_in_save_report():
    """save_report() includes certificate block in summary."""
    report = static_analysis.StaticReport(
        apk_path=FAKE_PACKAGE, package_name=FAKE_PACKAGE
    )
    report.device = static_analysis.DeviceReadiness()
    report.certificate = static_analysis.CertificateInfo(
        subject="CN=Evil Corp",
        issuer="CN=Evil Corp",
        is_self_signed=True,
        is_expired=True,
        sig_algorithm="SHA1withRSA",
        weak_sig_algorithm=True,
        not_after="Jan  1 00:00:00 2021 GMT",
        sha256_fingerprint="AA:BB:CC",
    )
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name
    try:
        static_analysis.save_report(report, out_path)
        loaded = json.loads(Path(out_path).read_text())
        cert = loaded["summary"]["certificate"]
        assert cert["is_self_signed"] is True
        assert cert["is_expired"]     is True
        assert "self_signed" in cert["flags"]
        assert "expired"     in cert["flags"]
        assert any("weak_sig" in f for f in cert["flags"])
    finally:
        Path(out_path).unlink(missing_ok=True)


# ── P1.11: scan_code_patterns [v3-4] ─────────────────────────

def _run_code_scan(dex_strings: list[str]):
    """Helper: run scan_code_patterns() against a controlled string list."""
    report = static_analysis.StaticReport(apk_path=FAKE_PACKAGE, package_name=FAKE_PACKAGE)
    with patch("static_analysis.AnalyzeAPK",
               return_value=make_analyze_apk_return(strings=dex_strings)):
        static_analysis.scan_code_patterns(FAKE_PACKAGE, report)
    return report


def test_p1_code_pattern_aes_ecb_detected():
    """scan_code_patterns() flags AES/ECB usage as high severity."""
    report = _run_code_scan(['Cipher.getInstance("AES/ECB/NoPadding")'])
    rules  = {h.rule for h in report.code_patterns if h.severity == "high"}
    assert "aes_ecb" in rules, f"Expected aes_ecb, got: {rules}"


def test_p1_code_pattern_weak_hash_md5_detected():
    """scan_code_patterns() flags MD5 as warning."""
    report = _run_code_scan(['.getInstance("MD5")'])
    rules  = {h.rule for h in report.code_patterns if h.severity == "warning"}
    assert "weak_hash_md5" in rules, f"Expected weak_hash_md5, got: {rules}"


def test_p1_code_pattern_dex_class_loader_detected():
    """scan_code_patterns() flags DexClassLoader as high severity."""
    report = _run_code_scan(["DexClassLoader(dexPath, optimizedDirectory, null, classLoader)"])
    rules  = {h.rule for h in report.code_patterns if h.severity == "high"}
    assert "dex_class_loader" in rules, f"Expected dex_class_loader, got: {rules}"


def test_p1_code_pattern_runtime_exec_detected():
    """scan_code_patterns() flags Runtime.exec() shell execution as high."""
    report = _run_code_scan(["Runtime.getRuntime().exec(new String[]{/system/bin/sh})"])
    rules  = {h.rule for h in report.code_patterns if h.severity == "high"}
    assert "runtime_exec" in rules, f"Expected runtime_exec, got: {rules}"


def test_p1_code_pattern_ssl_pinning_is_good():
    """scan_code_patterns() tags SSL pinning as a 'good' defence indicator."""
    report = _run_code_scan(["CertificatePinner.Builder()"])
    rules  = {h.rule for h in report.code_patterns if h.severity == "good"}
    assert "ssl_pinning" in rules, f"Expected ssl_pinning in good, got: {rules}"


def test_p1_code_pattern_root_detection_is_good():
    """scan_code_patterns() tags root detection as a 'good' indicator."""
    report = _run_code_scan(["/system/bin/su", "isDeviceRooted()"])
    rules  = {h.rule for h in report.code_patterns if h.severity == "good"}
    assert "root_detection" in rules, f"Expected root_detection in good, got: {rules}"


def test_p1_code_pattern_clean_strings_no_hits():
    """scan_code_patterns() produces zero hits on benign DEX strings."""
    benign = [
        "com.example.myapp.MainActivity",
        "android.intent.action.MAIN",
        "Hello World",
        "https://example.com/api",
        "1.0.0",
    ]
    report = _run_code_scan(benign)
    threat_hits = [h for h in report.code_patterns if h.severity != "good"]
    assert len(threat_hits) == 0, \
        f"Benign strings triggered false positives: {[h.rule for h in threat_hits]}"


def test_p1_code_pattern_summary_in_save_report():
    """save_report() includes code_patterns block with correct counts."""
    report = static_analysis.StaticReport(
        apk_path=FAKE_PACKAGE, package_name=FAKE_PACKAGE
    )
    report.device = static_analysis.DeviceReadiness()
    report.code_patterns = [
        static_analysis.CodePatternHit(rule="aes_ecb",      title="AES/ECB", severity="high",    match_count=2),
        static_analysis.CodePatternHit(rule="weak_hash_md5", title="MD5",    severity="warning",  match_count=1),
        static_analysis.CodePatternHit(rule="ssl_pinning",   title="Pinning", severity="good",    match_count=1),
    ]
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name
    try:
        static_analysis.save_report(report, out_path)
        loaded = json.loads(Path(out_path).read_text())
        cp = loaded["summary"]["code_patterns"]
        assert cp["total_hits"]    == 3
        assert cp["high_severity"] == 1
        assert "aes_ecb" in cp["high_rules"]
        assert len(cp["defences"])  == 1
        assert cp["defences"][0]["rule"] == "ssl_pinning"
    finally:
        Path(out_path).unlink(missing_ok=True)


def test_p1_code_pattern_exception_in_dex_extract_is_graceful():
    """scan_code_patterns() records a warning and returns cleanly when AnalyzeAPK fails."""
    report = static_analysis.StaticReport(apk_path=FAKE_PACKAGE, package_name=FAKE_PACKAGE)
    with patch("static_analysis.AnalyzeAPK", side_effect=Exception("DEX corrupt")):
        static_analysis.scan_code_patterns(FAKE_PACKAGE, report)
    assert len(report.warnings) > 0, "Expected warning on DEX extract failure"
    # Should NOT have raised — function must return cleanly
    assert isinstance(report.code_patterns, list)


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    run_p1    = "--phase1" in sys.argv or "--phase2" not in sys.argv
    run_p2    = "--phase2" in sys.argv or "--phase1" not in sys.argv
    run_integ = run_p1 and run_p2

    print(f"\n{Fore.GREEN}{'═' * 64}")
    print("  APK THREAT ORCHESTRATOR // REAL INTEGRATION TEST HARNESS")
    print(f"  Testing: actual static_analysis.py + sentry.py")
    print(f"  Phases : {'1 ' if run_p1 else ''}{'2 ' if run_p2 else ''}{'+ Integration' if run_integ else ''}")
    print(f"{'═' * 64}{Style.RESET_ALL}")

    if run_p1:
        section("PHASE 1 — Device Readiness (real check_device_readiness)")
        run("P1", "All checks pass → fully ready",          test_p1_readiness_all_checks_pass)
        run("P1", "No ADB device → not ready",              test_p1_readiness_no_device)
        run("P1", "No root → not ready",                    test_p1_readiness_no_root)
        run("P1", "No Shamiko → warning recorded",          test_p1_readiness_no_shamiko)
        run("P1", "No FLAG_SECURE → tier 2",                test_p1_readiness_screenshot_tier_2)
        run("P1", "No FLAG_SECURE + no Frida → tier 3",    test_p1_readiness_screenshot_tier_3)

        section("PHASE 1 — APK Parsing (real parse_apk)")
        run("P1", "Package name + activity extracted",      test_p1_parse_apk_package_and_activity)
        run("P1", "No main activity → has_launcher=False", test_p1_parse_apk_no_main_activity)
        run("P1", "Permissions categorised correctly",      test_p1_parse_apk_permissions_categorised)
        run("P1", "Permission short names correct",         test_p1_parse_apk_permission_short_names)
        run("P1", "No permissions lost or duplicated",      test_p1_parse_apk_no_permissions_lost)
        run("P1", "Receivers + intent actions extracted",   test_p1_parse_apk_receivers)
        run("P1", "Missing APK file → error recorded",      test_p1_parse_apk_file_not_found)
        run("P1", "Androguard exception → error recorded",  test_p1_parse_apk_androguard_exception)

        section("PHASE 1 — Indicator Scan (real scan_indicators)")
        run("P1", "C2 URL detected",                        test_p1_scan_indicators_urls)
        run("P1", "Public IP detected",                     test_p1_scan_indicators_public_ip)
        run("P1", "Private IPs filtered (RFC1918)",         test_p1_scan_indicators_private_ip_filtered)
        run("P1", "IPv6 detected",                          test_p1_scan_indicators_ipv6)
        run("P1", "API key detected",                       test_p1_scan_indicators_api_key)
        run("P1", "Duplicates deduplicated",                test_p1_scan_indicators_deduplication)
        run("P1", "Binary fallback scan works",             test_p1_scan_indicators_fallback_binary_scan)

        section("PHASE 1 — FIX 2: Multi-PID (real launch_apk)")
        run("P1", "Multiple PIDs captured, first=primary", test_p1_launch_apk_multi_pid_captured)
        run("P1", "Single PID works correctly",             test_p1_launch_apk_single_pid)
        run("P1", "Background APK skips am start",          test_p1_launch_apk_no_launcher_skipped)
        run("P1", "PID=None when pidof returns nothing",    test_p1_launch_apk_pid_none_on_failure)
        run("P1", "ps -A fallback when pidof unavailable",  test_p1_resolve_pids_ps_fallback)
        run("P1", "pidof takes priority over ps -A",        test_p1_resolve_pids_pidof_takes_priority)

        section("PHASE 1 — FIX 4: Frida Server (real ensure_frida_server)")
        run("P1", "Already running → skip start",           test_p1_frida_server_already_running)
        run("P1", "Starts successfully via nohup",          test_p1_frida_server_starts_successfully)
        run("P1", "Binary missing → returns False",         test_p1_frida_server_binary_missing)

        section("PHASE 1 — Report Serialisation (real save_report)")
        run("P1", "JSON written with all fields",           test_p1_save_report_creates_json)
        run("P1", "total_permissions counts all levels",    test_p1_save_report_summary_total_permissions)

        section("PHASE 1 v3 — Permission Taxonomy [v3-5]")
        run("P1", "All taxonomy entries have risk_score + description",  test_p1_taxonomy_dangerous_perms_have_risk_score)
        run("P1", "Permission object carries risk fields",               test_p1_taxonomy_permission_object_carries_risk_fields)
        run("P1", "NORMAL perm has risk_score=0",                        test_p1_taxonomy_normal_perm_has_zero_risk_score)
        run("P1", "save_report includes permission_risk_score",          test_p1_save_report_includes_permission_risk_summary)

        section("PHASE 1 v3 — URL Regex Fix [v3-1]")
        run("P1", "Regex rejects CSS/HTML noise strings",               test_p1_url_regex_rejects_css_noise)
        run("P1", "Regex accepts real C2/CDN URLs",                     test_p1_url_regex_accepts_real_urls)
        run("P1", "scan_indicators emits no CSS false positives",       test_p1_scan_indicators_no_css_false_positives)

        section("PHASE 1 v3 — Manifest Security [v3-2]")
        run("P1", "debuggable=true → HIGH issue",                       test_p1_manifest_debuggable_flagged)
        run("P1", "debuggable=false → no issue",                        test_p1_manifest_not_debuggable_no_issue)
        run("P1", "allowBackup=true → WARNING issue",                   test_p1_manifest_allow_backup_flagged)
        run("P1", "cleartext traffic → WARNING issue",                  test_p1_manifest_cleartext_traffic_flagged)
        run("P1", "Exported activity, no perm → HIGH issue",            test_p1_manifest_exported_activity_no_permission_flagged)
        run("P1", "Exported service, no perm → HIGH issue",             test_p1_manifest_exported_service_no_permission_flagged)
        run("P1", "singleTask + targetSdk<28 → task_hijacking HIGH",    test_p1_manifest_task_hijacking_flagged)
        run("P1", "singleTask + targetSdk>=28 → no task_hijacking",     test_p1_manifest_task_hijacking_not_flagged_on_high_sdk)
        run("P1", "networkSecurityConfig ref recorded",                  test_p1_manifest_network_security_config_recorded)
        run("P1", "Low targetSdk < 28 → WARNING issue",                 test_p1_manifest_low_target_sdk_flagged)
        run("P1", "save_report includes manifest_issues block",          test_p1_manifest_summary_in_save_report)

        section("PHASE 1 v3 — Certificate Analysis [v3-3]")
        run("P1", "Self-signed cert detected",                           test_p1_cert_self_signed_detected)
        run("P1", "Expired cert flagged",                                test_p1_cert_expired_detected)
        run("P1", "No META-INF cert → graceful error",                   test_p1_cert_no_meta_inf_graceful)
        run("P1", "save_report includes certificate block",              test_p1_cert_summary_in_save_report)

        section("PHASE 1 v3 — Code Pattern Analysis [v3-4]")
        run("P1", "AES/ECB → high severity hit",                         test_p1_code_pattern_aes_ecb_detected)
        run("P1", "MD5 hash → warning severity hit",                     test_p1_code_pattern_weak_hash_md5_detected)
        run("P1", "DexClassLoader → high severity hit",                  test_p1_code_pattern_dex_class_loader_detected)
        run("P1", "Runtime.exec() → high severity hit",                  test_p1_code_pattern_runtime_exec_detected)
        run("P1", "CertificatePinner → good defence indicator",          test_p1_code_pattern_ssl_pinning_is_good)
        run("P1", "Root detection strings → good defence indicator",     test_p1_code_pattern_root_detection_is_good)
        run("P1", "Benign strings → zero threat hits",                   test_p1_code_pattern_clean_strings_no_hits)
        run("P1", "save_report includes code_patterns block",            test_p1_code_pattern_summary_in_save_report)
        run("P1", "DEX extract failure → graceful warning",              test_p1_code_pattern_exception_in_dex_extract_is_graceful)

    if run_p2:
        section("PHASE 2 — Startup (real load_phase1_report + checks)")
        run("P2", "Valid report loaded cleanly",            test_p2_load_phase1_report_valid)
        run("P2", "Missing file → sys.exit",               test_p2_load_phase1_report_missing_file)
        run("P2", "Missing fields → sys.exit",             test_p2_load_phase1_report_missing_fields)
        run("P2", "mitmproxy cert found → True",           test_p2_verify_mitmproxy_cert_found)
        run("P2", "mitmproxy cert missing → False",        test_p2_verify_mitmproxy_cert_missing)
        run("P2", "inotifywait present → True",            test_p2_check_inotifywait_present)
        run("P2", "inotifywait missing → False",           test_p2_check_inotifywait_missing)

        section("PHASE 2 — Permission Tagger (real tag_permission)")
        run("P2", "INTERNET tagged from OkHttp",           test_p2_tag_internet_okhttp)
        run("P2", "SEND_SMS tagged correctly",             test_p2_tag_send_sms)
        run("P2", "READ_SMS distinct from SEND_SMS",       test_p2_tag_read_sms_distinct_from_send)
        run("P2", "ACCESS_FINE_LOCATION tagged",           test_p2_tag_location)
        run("P2", "CAMERA tagged",                         test_p2_tag_camera)
        run("P2", "No match → empty string",               test_p2_tag_no_match)

        section("PHASE 2 — Network (real is_private_ip)")
        run("P2", "Private IPs filtered",                  test_p2_private_ips_filtered)
        run("P2", "Public IPs not filtered",               test_p2_public_ips_not_filtered)

        section("PHASE 2 — NetstatPoller (real _parse_netstat_line + run)")
        run("P2", "ESTABLISHED TCP parsed",                test_p2_netstat_established_parsed)
        run("P2", "Private IP excluded",                   test_p2_netstat_private_excluded)
        run("P2", "LISTEN state ignored",                  test_p2_netstat_listen_ignored)
        run("P2", "SYN_SENT captured",                     test_p2_netstat_syn_sent_captured)
        run("P2", "IPv6-mapped ::ffff: stripped",          test_p2_netstat_ipv6_mapped_stripped)
        run("P2", "Malformed lines don't crash",           test_p2_netstat_malformed_ignored)
        run("P2", "New connections appended during run()", test_p2_netstat_poller_appends_new_connections)

        section("PHASE 2 — ExfiltrationAddon (real request())")
        run("P2", "Contacts (email) detected",             test_p2_exfil_contacts_detected)
        run("P2", "Location (lat/lng) detected",           test_p2_exfil_location_detected)
        run("P2", "SMS body detected",                     test_p2_exfil_sms_detected)
        run("P2", "IMEI detected",                         test_p2_exfil_imei_detected)
        run("P2", "Credentials detected",                  test_p2_exfil_credentials_detected)
        run("P2", "Clean body → no false positive",        test_p2_exfil_clean_body_no_alert)
        run("P2", "ssl_pinning_bypassed flag set",         test_p2_exfil_ssl_pinning_flag_set)
        run("P2", "Multiple types in one request",         test_p2_exfil_multiple_types_same_request)
        run("P2", "Permission correctly mapped",           test_p2_exfil_permission_mapped)

        section("PHASE 2 — DropperHandler (real handle())")
        run("P2", "Step 1 /sdcard/ pull succeeds",         test_p2_dropper_step1_sdcard_pull)
        run("P2", "Step 2 /data/app/ fallback used",       test_p2_dropper_step2_data_app_fallback)
        run("P2", "Both pulls fail → None + warning",      test_p2_dropper_both_pulls_fail_returns_none)
        run("P2", "Dropper index increments per event",    test_p2_dropper_counter_increments)

        section("PHASE 2 — RootDetectionMonitor (real thread)")
        run("P2", "Fires when app dies in window",         test_p2_root_detection_fires_within_window)
        run("P2", "Silent when app survives window",       test_p2_root_detection_does_not_fire_when_alive)

        section("PHASE 2 — Session Report (real save_sentry_session)")
        run("P2", "JSON written with all fields",          test_p2_save_sentry_session_json)
        run("P2", "Abuse scores calculated correctly",     test_p2_save_sentry_session_abuse_scores)
        run("P2", "Top permissions ranked by score",       test_p2_save_sentry_session_top_permissions_ranked)

    if run_integ:
        section("INTEGRATION — Phase 1 → Phase 2 Handoff")
        run("INT", "P1 report consumed correctly by P2",   test_integration_p1_report_consumed_by_p2)
        run("INT", "All PIDs flow to logcat filter",       test_integration_all_pids_flow_to_logcat_filter)
        run("INT", "Exfil permission ties to P1 DANGEROUS",test_integration_exfil_event_ties_to_permission)

    return RESULTS.summary()


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)