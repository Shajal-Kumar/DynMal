"""
APK Threat Orchestrator — Phase 1: Static Analysis (v3.5)
==========================================================
Changes from v3.4:
  [v3.5-1] _try_aapt_package_name() — new helper. Calls `aapt2` then
            `aapt` (whichever is on PATH) to parse package name directly
            from binary AndroidManifest.xml, independent of androguard.
            Succeeds on many packed APKs where both androguard and zip
            structure inference fail. Tries aapt2 first, falls back to
            aapt. Returns "" if neither tool is available or readable.
  [v3.5-2] _extract_package_from_zip() — escalates to aapt fallback when
            lib/ and assets/ path inference yield no package name. Also
            calls aapt if zipfile itself raises (e.g. zip64 / custom
            format that Python's zipfile cannot open at all).
  [v3.5-3] Session directory renamed from <package_name>_<ts> to
            <apk_stem>_<ts> (APK filename without extension). Guarantees
            a valid, human-readable directory name even when the package
            name cannot be determined at parse time.
  [v3.5-4] _partial flag now keyed on __already_installed__ sentinel —
            cleaner and unambiguous versus substring-matching warnings.
  [v3.5-5] scan_manifest_security() accepts optional apk_obj kwarg —
            eliminates second AnalyzeAPK() call when called from main().
            AnalyzeAPK() is now guaranteed to run exactly once per Phase 1.
            apk_obj from _extract_dex_strings() is forwarded to both
            scan_manifest_security() and is available for scan_certificate().
  [v3.5-6] Removed dead launch_apk() and _trigger_background_apk()
            functions. Phase 1 launch was removed in v3.3-2; these had
            no callers and were a misleading maintenance hazard.

Changes from v3.3 (v3.4):
  [v3.4-1] _extract_dex_strings() shared helper — AnalyzeAPK() called
            once and DEX strings passed to both scan_indicators() and
            scan_code_patterns(). Eliminates redundant double-parse.
  [v3.4-2] scan_code_patterns() rewritten for speed + correctness:
            • Per-string scan loop replaces single-giant-blob approach.
              Avoids catastrophic backtracking on DOTALL regexes.
            • _RULE_ANCHORS pre-filter: each rule declares a required
              literal keyword. If the keyword is absent from the full
              blob, the regex is skipped entirely — O(1) fast-path.
            • DOTALL multi-token rules (insecure_ssl, sql_raw_query,
              webview_js_interface, clipboard_listen, webview_ignore_ssl)
              rewritten as two-phase checks: fast __contains__ guard on
              both required tokens, then regex on a small context window.
              No more scanning 5MB+ blob with a DOTALL lookahead.
            • match_count now counts unique matching strings (not regex
              group captures within one blob), reducing false-positive
              inflation.
            • Timing logged per-run for future profiling.
  [v3.4-3] Encrypted / packed APK fallback: zip-level metadata
            extraction when androguard raises on parse.

Changes from v3.2:
  [v3.3-1] install_apk() now uses direct `adb install` (no push+pm).
            Fallback to --bypass-low-target-sdk-block on deprecated SDK.
  [v3.3-2] App launch REMOVED from Phase 1. Phase 2 (sentry.py) now
            owns the launch so monitors are active before the app starts.
  [v3.3-3] scan_manifest_security() uses get_android_manifest_axml().get_xml()
            — fixes lxml/toprettyxml() crash on all androguard versions.
  [v3.3-4] scan_indicators() and scan_code_patterns() use get_value()
            with str() fallback — fixes 'str has no attribute get_data' crash.
  [v3.3-5] REQUEST_INSTALL_PACKAGES moved from NORMAL_PERMISSIONS to
            PERMISSION_TAXONOMY with risk_score=9 (dropper/packer capability).

Changes from v2 (v3.x series):
  [v3-1] URL regex tightened.
  [v3-2] ManifestSecurity dataclass + scan_manifest_security().
  [v3-3] CertificateInfo dataclass + scan_certificate().
  [v3-4] CodePatterns dataclass + scan_code_patterns().
  [v3-5] PERMISSION_TAXONOMY replaces DANGEROUS_PERMISSIONS flat set.
  [v3-6] StaticReport, save_report(), summary block extended.
  [v3.1-1] Session directory created at Phase 1.

Usage:
    python static_analysis.py <path_to_apk>
    python static_analysis.py <path_to_apk> --child   # for dropped APKs

Requirements:
    pip install androguard colorama frida-tools python-dotenv
    apt install aapt  # or aapt2 — used as fallback for packed APKs
"""

import re
import sys
import json
import time
import hashlib
import zipfile
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

from androguard.misc import AnalyzeAPK
from colorama import Fore, Style, init as colorama_init
from dotenv import load_dotenv
import os

colorama_init(autoreset=True)
load_dotenv()   # loads .env from current working directory


# ─────────────────────────────────────────────────────────────
# CONFIG — single source of truth for all phases
# ─────────────────────────────────────────────────────────────

class Config:
    """
    Read once from .env at startup. All phases import this object.
    Switch between dev and prod by changing ENV= in .env only.
    """
    ENV: str          = os.getenv("ENV", "dev")
    OLLAMA_HOST: str  = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    FRIDA_SERVER: str = os.getenv("FRIDA_SERVER_PATH", "/data/local/tmp/frida-server")
    ADB_SERIAL: str   = os.getenv("ADB_SERIAL", "")

    OLLAMA_MODEL: str = (
        os.getenv("OLLAMA_MODEL_PROD", "llama3.3:70b")
        if ENV == "prod"
        else os.getenv("OLLAMA_MODEL_DEV", "phi3.5-mini")
    )

    SHAMIKO_NAMES: tuple     = ("shamiko", "zygisk_shamiko")
    FLAG_SECURE_NAMES: tuple = ("noflagsecure", "no_flag_secure", "flagsecure", "no-flagsecure")

    @classmethod
    def display(cls) -> None:
        info(f"Environment   : {Fore.WHITE}{cls.ENV.upper()}")
        info(f"Ollama model  : {Fore.WHITE}{cls.OLLAMA_MODEL}")
        info(f"Ollama host   : {Fore.WHITE}{cls.OLLAMA_HOST}")
        info(f"Frida server  : {Fore.WHITE}{cls.FRIDA_SERVER}")
        info(f"ADB serial    : {Fore.WHITE}{cls.ADB_SERIAL or 'auto (first connected device)'}")


# ─────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────

# [v3-5] Permission taxonomy — replaces flat DANGEROUS_PERMISSIONS set.
# Each entry: (level, description, risk_score 1-10)
# Sourced from MobSF android_permissions.yaml + AOSP documentation.
PERMISSION_TAXONOMY: dict[str, dict] = {
    # ── Telephony / SMS ──────────────────────────────────────
    "android.permission.READ_SMS": {
        "level": "DANGEROUS",
        "description": "Read SMS messages stored on device. High exfiltration risk — OTPs and 2FA codes.",
        "risk_score": 9,
    },
    "android.permission.SEND_SMS": {
        "level": "DANGEROUS",
        "description": "Send SMS messages, potentially incurring charges or exfiltrating data via SMS.",
        "risk_score": 9,
    },
    "android.permission.RECEIVE_SMS": {
        "level": "DANGEROUS",
        "description": "Intercept incoming SMS before they reach the user. Common in banking trojans.",
        "risk_score": 10,
    },
    "android.permission.RECEIVE_MMS": {
        "level": "DANGEROUS",
        "description": "Intercept incoming MMS messages.",
        "risk_score": 8,
    },
    "android.permission.READ_PHONE_STATE": {
        "level": "DANGEROUS",
        "description": "Access IMEI, IMSI, call state. Used for device fingerprinting and tracking.",
        "risk_score": 7,
    },
    "android.permission.CALL_PHONE": {
        "level": "DANGEROUS",
        "description": "Initiate phone calls without user interaction. Can make calls to premium numbers.",
        "risk_score": 8,
    },
    "android.permission.PROCESS_OUTGOING_CALLS": {
        "level": "DANGEROUS",
        "description": "Intercept and redirect outgoing calls. Used in call-forwarding malware.",
        "risk_score": 8,
    },
    "android.permission.READ_CALL_LOG": {
        "level": "DANGEROUS",
        "description": "Access complete call history including contact numbers and duration.",
        "risk_score": 7,
    },
    "android.permission.WRITE_CALL_LOG": {
        "level": "DANGEROUS",
        "description": "Modify or delete call log entries, enabling evidence destruction.",
        "risk_score": 6,
    },
    # ── Contacts / Accounts ──────────────────────────────────
    "android.permission.READ_CONTACTS": {
        "level": "DANGEROUS",
        "description": "Read entire contact list. Primary exfiltration target for spyware.",
        "risk_score": 8,
    },
    "android.permission.WRITE_CONTACTS": {
        "level": "DANGEROUS",
        "description": "Modify or inject malicious contacts (e.g., for phishing redirect).",
        "risk_score": 6,
    },
    "android.permission.GET_ACCOUNTS": {
        "level": "DANGEROUS",
        "description": "Enumerate all accounts on device (Google, Facebook, etc.).",
        "risk_score": 7,
    },
    # ── Location ─────────────────────────────────────────────
    "android.permission.ACCESS_FINE_LOCATION": {
        "level": "DANGEROUS",
        "description": "Precise GPS location. Core stalkerware capability.",
        "risk_score": 9,
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "level": "DANGEROUS",
        "description": "Network-based approximate location.",
        "risk_score": 7,
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "level": "DANGEROUS",
        "description": "Location access when app is not in foreground. Persistent tracking.",
        "risk_score": 10,
    },
    # ── Media / Sensors ──────────────────────────────────────
    "android.permission.RECORD_AUDIO": {
        "level": "DANGEROUS",
        "description": "Access microphone. Can be used for ambient audio recording.",
        "risk_score": 10,
    },
    "android.permission.CAMERA": {
        "level": "DANGEROUS",
        "description": "Access camera hardware. Can capture images/video without UI.",
        "risk_score": 9,
    },
    "android.permission.BODY_SENSORS": {
        "level": "DANGEROUS",
        "description": "Access heart rate and other body sensor data.",
        "risk_score": 5,
    },
    "android.permission.ACTIVITY_RECOGNITION": {
        "level": "DANGEROUS",
        "description": "Detect physical activity (walking, running). Behavioural profiling.",
        "risk_score": 5,
    },
    # ── Storage ──────────────────────────────────────────────
    "android.permission.READ_EXTERNAL_STORAGE": {
        "level": "DANGEROUS",
        "description": "Read all files on external storage including photos and documents.",
        "risk_score": 7,
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "level": "DANGEROUS",
        "description": "Write files to external storage. Can drop payloads or encrypt files.",
        "risk_score": 7,
    },
    "android.permission.READ_MEDIA_IMAGES": {
        "level": "DANGEROUS",
        "description": "Access photo library (Android 13+).",
        "risk_score": 6,
    },
    "android.permission.READ_MEDIA_VIDEO": {
        "level": "DANGEROUS",
        "description": "Access video library (Android 13+).",
        "risk_score": 6,
    },
    "android.permission.READ_MEDIA_AUDIO": {
        "level": "DANGEROUS",
        "description": "Access audio files (Android 13+).",
        "risk_score": 5,
    },
    # ── Biometrics ───────────────────────────────────────────
    "android.permission.USE_BIOMETRIC": {
        "level": "DANGEROUS",
        "description": "Use biometric hardware (fingerprint/face). Can bypass auth prompts.",
        "risk_score": 7,
    },
    "android.permission.USE_FINGERPRINT": {
        "level": "DANGEROUS",
        "description": "Legacy fingerprint API access.",
        "risk_score": 7,
    },
    # ── Bluetooth ────────────────────────────────────────────
    "android.permission.BLUETOOTH_CONNECT": {
        "level": "DANGEROUS",
        "description": "Connect to paired Bluetooth devices (Android 12+).",
        "risk_score": 5,
    },
    "android.permission.BLUETOOTH_SCAN": {
        "level": "DANGEROUS",
        "description": "Scan for nearby Bluetooth devices. Can be used for proximity tracking.",
        "risk_score": 6,
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "level": "DANGEROUS",
        "description": "Install arbitrary APKs without Play Store. Core dropper/packer capability.",
        "risk_score": 9,
    },
    # ── Network / Persistence ────────────────────────────────
    "android.permission.INTERNET": {
        "level": "DANGEROUS",
        "description": "Full network access. Primary exfiltration and C2 communication channel.",
        "risk_score": 6,
    },
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "level": "DANGEROUS",
        "description": "Auto-start on device boot. Core persistence mechanism for malware.",
        "risk_score": 8,
    },
}

# Normal system permissions — no risk score, just classification
NORMAL_PERMISSIONS: set[str] = {
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.USE_FULL_SCREEN_INTENT",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.DISABLE_KEYGUARD",
    "android.permission.NFC",
    "android.permission.FLASHLIGHT",
}

# RFC 1918 / loopback IPs — filtered from indicator results
PRIVATE_IP_PREFIXES = (
    "10.", "192.168.", "127.", "0.0.0.0",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)

# [v3-1] Tightened URL regex — requires proper hostname with TLD segment.
# Previous: r'https?://[^\s\'"<>{}\[\]\\]{4,}'  — matched HTML/CSS junk.
# Now requires: scheme + hostname (label.label) + optional path.
# Excludes bare words, http://style= CSS noise, and malformed fragments.
INDICATORS = {
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    "ipv6": re.compile(
        r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'
    ),
    "url": re.compile(                                      # [v3-1] FIX
        r'https?://[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z]{2,})+(/[^\s\'"<>{}\\]*)?'
    ),
    "api_key": re.compile(
        r'(?i)(?:api[_\-]?key|secret|token|bearer|auth)["\s:=]+["\']?([A-Za-z0-9\-_\.]{20,})["\']?'
    ),
}

# [v3-4] Code pattern rules — sourced from MobSF android_rules.yaml.
# Each entry: (rule_id, display_name, severity, compiled_regex)
# Severity mirrors MobSF: "high" | "warning" | "info" | "good"
CODE_PATTERN_RULES: list[tuple[str, str, str, re.Pattern]] = [
    # ── Crypto weaknesses ────────────────────────────────────
    (
        "aes_ecb",
        "AES/ECB mode — weak block cipher",
        "high",
        re.compile(r'Cipher\.getInstance\(\s*["\']?\s*AES/ECB', re.IGNORECASE),
    ),
    (
        "aes_default_ecb",
        'Cipher.getInstance("AES") — defaults to ECB',
        "high",
        re.compile(r'Cipher\.getInstance\(["\']AES["\']'),
    ),
    (
        "rsa_no_oaep",
        "RSA without OAEP padding",
        "high",
        re.compile(r'Cipher\.getInstance\(["\']rsa/.{1,48}/nopadding["\']', re.IGNORECASE),
    ),
    (
        "cbc_padding_oracle",
        "CBC/PKCS5 or PKCS7 — padding oracle risk",
        "high",
        re.compile(r'\.getInstance\(.{0,48}/CBC/PKCS[57]Padding'),
    ),
    (
        "weak_cipher",
        "Weak cipher algorithm (RC2/RC4/DES/Blowfish)",
        "high",
        re.compile(
            r'Cipher\.getInstance\(.{0,48}(?:RC2|RC4|rc2|rc4|blowfish|BLOWFISH|DES(?!ede)|des(?!ede))'
        ),
    ),
    (
        "weak_hash_md5",
        "MD5 hash — known collision vulnerabilities",
        "warning",
        re.compile(r'\.getInstance\(.{0,48}(?:MD5|md5)|DigestUtils\.md5\('),
    ),
    (
        "weak_hash_sha1",
        "SHA-1 hash — known collision vulnerabilities",
        "warning",
        re.compile(r'\.getInstance\(.{0,48}(?:SHA-?1|sha-?1)|DigestUtils\.sha\('),
    ),
    (
        "weak_iv",
        "Hardcoded weak IV (null bytes / sequential)",
        "high",
        re.compile(r'0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00|0x01,0x02,0x03,0x04,0x05,0x06,0x07'),
    ),
    (
        "insecure_random",
        "java.util.Random — not cryptographically secure",
        "warning",
        re.compile(r'java\.util\.Random(?!Access)'),
    ),
    (
        "hardcoded_secret",
        "Hardcoded credential (password/secret/key assignment)",
        "warning",
        re.compile(
            r'(?:password|pass|username|secret|key)\s*=\s*[\'"].{1,100}[\'"]',
            re.IGNORECASE,
        ),
    ),
    # ── Network / SSL ────────────────────────────────────────
    (
        "insecure_ssl",
        "Insecure SSL — trusts all certs or disables hostname verification",
        "high",
        re.compile(
            r'(?=.*javax\.net\.ssl)'
            r'(?=.*(?:TrustAllSSLSocket|AllTrustSSLSocketFactory|NonValidatingSSLSocketFactory'
            r'|ALLOW_ALL_HOSTNAME_VERIFIER|\.setDefaultHostnameVerifier\(|NullHostnameVerifier\())',
            re.DOTALL,
        ),
    ),
    (
        "webview_ignore_ssl",
        "WebView ignores SSL errors (onReceivedSslError + proceed)",
        "high",
        re.compile(r'onReceivedSslError\(WebView.*?\.proceed\(\)', re.DOTALL),
    ),
    (
        "ssl_pinning",
        "SSL certificate pinning detected (defence indicator)",
        "good",
        re.compile(
            r'CertificatePinner\.Builder\(|PinningHelper\.|PinningSSLSocketFactory'
            r'|\.setCertificateEntry\('
        ),
    ),
    # ── Dynamic code execution ───────────────────────────────
    (
        "dex_class_loader",
        "DexClassLoader — dynamic DEX loading",
        "high",
        re.compile(r'DexClassLoader\s*\('),
    ),
    (
        "reflection",
        "Java reflection — dynamic method invocation",
        "warning",
        re.compile(r'getDeclaredMethod\s*\(|loadClass\s*\(|forName\s*\('),
    ),
    (
        "runtime_exec",
        "Runtime.exec() or ProcessBuilder — shell command execution",
        "high",
        re.compile(r'Runtime\.getRuntime\(\)\.exec\(|ProcessBuilder\s*\('),
    ),
    (
        "native_library",
        "System.loadLibrary() — native code loaded",
        "warning",
        re.compile(r'System\.loadLibrary\s*\('),
    ),
    # ── WebView ──────────────────────────────────────────────
    (
        "webview_js_interface",
        "WebView JS interface + JS enabled — remote code execution risk",
        "warning",
        re.compile(r'setJavaScriptEnabled\(true\).*?addJavascriptInterface\(', re.DOTALL),
    ),
    (
        "webview_external_storage",
        "WebView loads file from external storage",
        "high",
        re.compile(r'\.loadUrl\(.{0,48}getExternalStorageDirectory\('),
    ),
    (
        "webview_debug",
        "WebView remote debugging enabled",
        "high",
        re.compile(r'setWebContentsDebuggingEnabled\(true\)'),
    ),
    # ── Storage / Data ───────────────────────────────────────
    (
        "world_readable",
        "File or SharedPreference is world-readable",
        "high",
        re.compile(r'MODE_WORLD_READABLE|openFileOutput\(\s*".{1,48}"\s*,\s*1\s*\)'),
    ),
    (
        "world_writable",
        "File or SharedPreference is world-writable",
        "high",
        re.compile(r'MODE_WORLD_WRITABLE|openFileOutput\(\s*".{1,48}"\s*,\s*2\s*\)'),
    ),
    (
        "external_storage_rw",
        "Read/write to external storage",
        "warning",
        re.compile(r'\.getExternalStorage|\.getExternalFilesDir\('),
    ),
    (
        "sql_raw_query",
        "Raw SQL query — potential SQL injection vector",
        "warning",
        re.compile(r'(?=.*android\.database\.sqlite)(?=.*(?:rawQuery\(|execSQL\())', re.DOTALL),
    ),
    # ── Evasion / Anti-analysis ──────────────────────────────
    (
        "root_detection",
        "Root detection code present (resilience indicator)",
        "good",
        re.compile(
            r'test-keys|/system/app/Superuser\.apk|isDeviceRooted\(\)'
            r'|/system/bin/su|/system/xbin/su|RootTools\.isAccessGiven\(\)'
        ),
    ),
    (
        "frida_detection",
        "Frida server detection code present",
        "good",
        re.compile(r'fridaserver|LIBFRIDA'),
    ),
    (
        "clipboard_listen",
        "Clipboard change listener — reads clipboard data",
        "info",
        re.compile(r'content\.ClipboardManager.*?OnPrimaryClipChangedListener', re.DOTALL),
    ),
    (
        "hidden_ui",
        "Hidden UI elements — View.GONE/INVISIBLE used",
        "high",
        re.compile(r'setVisibility\(View\.GONE\)|setVisibility\(View\.INVISIBLE\)'),
    ),
]

# [v3.4-2] Pre-filter anchors — one required literal per rule.
# If this string is absent from the full DEX blob, the regex is
# skipped with zero regex overhead. Must be a substring that is
# always present when the pattern can match.  Keep lowercase where
# the pattern is IGNORECASE so the anchor check matches too.
_RULE_ANCHORS: dict[str, str] = {
    "aes_ecb":                  "AES/ECB",
    "aes_default_ecb":          "AES",
    "rsa_no_oaep":              "nopadding",
    "cbc_padding_oracle":       "CBC/PKCS",
    "weak_cipher":              "Cipher.getInstance",
    "weak_hash_md5":            "MD5",
    "weak_hash_sha1":           "SHA",
    "weak_iv":                  "0x00,0x00,0x00,0x00",
    "insecure_random":          "java.util.Random",
    "hardcoded_secret":         "password",        # broadest anchor in the alternation
    "insecure_ssl":             "javax.net.ssl",
    "webview_ignore_ssl":       "onReceivedSslError",
    "ssl_pinning":              "CertificatePinner",
    "dex_class_loader":         "DexClassLoader",
    "reflection":               "getDeclaredMethod",
    "runtime_exec":             "Runtime.getRuntime",
    "native_library":           "loadLibrary",
    "webview_js_interface":     "setJavaScriptEnabled",
    "webview_external_storage": "getExternalStorageDirectory",
    "webview_debug":            "setWebContentsDebuggingEnabled",
    "world_readable":           "MODE_WORLD_READABLE",
    "world_writable":           "MODE_WORLD_WRITABLE",
    "external_storage_rw":      "getExternalStorage",
    "sql_raw_query":            "android.database.sqlite",
    "root_detection":           "test-keys",
    "frida_detection":          "fridaserver",
    "clipboard_listen":         "ClipboardManager",
    "hidden_ui":                "setVisibility",
}


# ─────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────

@dataclass
class Permission:
    name: str
    level: str          # "DANGEROUS" | "NORMAL" | "UNKNOWN"
    short: str      = ""
    description: str = ""   # [v3-5] from PERMISSION_TAXONOMY
    risk_score: int  = 0    # [v3-5] 1-10, 0 = not rated

    def __post_init__(self):
        self.short = self.name.split(".")[-1]


@dataclass
class Receiver:
    name: str
    actions: list[str] = field(default_factory=list)


@dataclass
class ManifestIssue:
    """Single finding from manifest security scan."""
    rule: str       # e.g. "app_is_debuggable"
    title: str
    severity: str   # "high" | "warning" | "info" | "good"
    description: str
    component: str = ""     # component name if applicable


@dataclass
class ManifestSecurity:
    """[v3-2] Results of the manifest security scan."""
    debuggable: bool                        = False
    allow_backup: bool                      = False
    backup_not_set: bool                    = False
    cleartext_traffic: bool                 = False
    has_network_security_config: bool       = False
    network_security_config_ref: str        = ""
    test_only: bool                         = False
    target_sdk: int                         = 0
    min_sdk: int                            = 0
    exported_activities: list[str]          = field(default_factory=list)
    exported_services: list[str]            = field(default_factory=list)
    exported_receivers: list[str]           = field(default_factory=list)
    exported_providers: list[str]           = field(default_factory=list)
    task_hijacking_activities: list[str]    = field(default_factory=list)
    issues: list[ManifestIssue]             = field(default_factory=list)

    @property
    def issue_count_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {"high": 0, "warning": 0, "info": 0, "good": 0}
        for issue in self.issues:
            counts[issue.severity] = counts.get(issue.severity, 0) + 1
        return counts


@dataclass
class CertificateInfo:
    """[v3-3] APK signing certificate metadata."""
    subject: str            = ""
    issuer: str             = ""
    serial_number: str      = ""
    not_before: str         = ""    # ISO-8601
    not_after: str          = ""    # ISO-8601
    is_expired: bool        = False
    is_self_signed: bool    = False
    sig_algorithm: str      = ""
    weak_sig_algorithm: bool = False    # MD5/SHA1 signatures
    sha256_fingerprint: str = ""
    error: str              = ""    # populated if extraction failed


@dataclass
class CodePatternHit:
    """Single code pattern match from scan_code_patterns()."""
    rule: str
    title: str
    severity: str   # "high" | "warning" | "info" | "good"
    match_count: int = 0


@dataclass
class DeviceReadiness:
    """Result of the pre-flight device check. Passed into StaticReport."""
    adb_connected: bool        = False
    device_serial: str         = ""
    android_version: str       = ""
    is_rooted: bool            = False
    shamiko_active: bool       = False
    flag_secure_disabled: bool = False
    frida_server_running: bool = False
    warnings: list[str]        = field(default_factory=list)

    @property
    def ready_for_analysis(self) -> bool:
        return self.adb_connected and self.is_rooted

    @property
    def screenshot_tier(self) -> int:
        """Which screenshot tier is available."""
        if self.flag_secure_disabled:
            return 1
        if self.frida_server_running:
            return 2
        return 3


@dataclass
class StaticReport:
    apk_path: str
    is_child: bool              = False
    package_name: str           = ""
    main_activity: str          = ""
    all_activities: list[str]   = field(default_factory=list)
    has_launcher: bool          = True
    permissions: list[Permission]   = field(default_factory=list)
    receivers: list[Receiver]   = field(default_factory=list)
    indicators: dict            = field(default_factory=lambda: {
        "ipv4": [], "ipv6": [], "url": [], "api_key": []
    })
    # [v3-2] Manifest security
    manifest_security: ManifestSecurity = field(default_factory=ManifestSecurity)
    # [v3-3] Certificate info
    certificate: CertificateInfo        = field(default_factory=CertificateInfo)
    # [v3-4] Code patterns
    code_patterns: list[CodePatternHit] = field(default_factory=list)

    device: DeviceReadiness     = field(default_factory=DeviceReadiness)
    env: str                    = Config.ENV
    model: str                  = Config.OLLAMA_MODEL
    pid: Optional[int]          = None
    all_pids: list[int]         = field(default_factory=list)
    frida_attached: bool        = False
    errors: list[str]           = field(default_factory=list)
    warnings: list[str]         = field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def adb(*args) -> subprocess.CompletedProcess:
    """Run an adb command, targeting specific serial if configured."""
    cmd = ["adb"]
    if Config.ADB_SERIAL:
        cmd += ["-s", Config.ADB_SERIAL]
    cmd += list(args)
    return subprocess.run(cmd, capture_output=True, text=True)


def banner(text: str, char: str = "─") -> None:
    width = 62
    print(f"\n{Fore.GREEN}{char * width}")
    print(f"  {text}")
    print(f"{char * width}{Style.RESET_ALL}")


def ok(msg: str)   -> None: print(f"  {Fore.GREEN}✓{Style.RESET_ALL}  {msg}")
def warn(msg: str) -> None: print(f"  {Fore.YELLOW}⚠{Style.RESET_ALL}  {msg}")
def err(msg: str)  -> None: print(f"  {Fore.RED}✗{Style.RESET_ALL}  {msg}")
def info(msg: str) -> None: print(f"  {Fore.CYAN}→{Style.RESET_ALL}  {msg}")
def skip(msg: str) -> None: print(f"  {Fore.MAGENTA}↷{Style.RESET_ALL}  {msg}")

_SEVERITY_COLOURS = {
    "high":    Fore.RED,
    "warning": Fore.YELLOW,
    "info":    Fore.CYAN,
    "good":    Fore.GREEN,
}
def severity_colour(s: str) -> str:
    return _SEVERITY_COLOURS.get(s, Fore.WHITE)


# ─────────────────────────────────────────────────────────────
# [v3.4-1] SHARED DEX STRING EXTRACTOR
# ─────────────────────────────────────────────────────────────

def _extract_dex_strings(apk_path: str) -> tuple[object, list, list, list[str]]:
    """
    Parse the APK with androguard once and return:
        (apk_obj, dvms, analysis, all_strings)

    Callers (scan_indicators, scan_code_patterns) receive the pre-built
    string list and never call AnalyzeAPK() themselves.  This eliminates
    the redundant double-parse that was costing ~50% of Phase 1 runtime.

    Falls back to raw ASCII extraction on parse failure; in that case
    apk_obj / dvms / analysis are all None.

    Returns (None, [], [], strings) on fallback so callers can still run.
    """
    try:
        apk_obj, dvms, analysis = AnalyzeAPK(apk_path)
        strings: list[str] = []
        for dvm in dvms:
            for s in dvm.get_strings():
                try:
                    strings.append(str(s.get_value()))
                except Exception:
                    try:
                        strings.append(str(s))
                    except Exception:
                        pass
        return apk_obj, dvms, analysis, strings
    except Exception as e:
        warn(f"DEX extraction failed ({e}). Falling back to raw binary scan.")
        raw = Path(apk_path).read_bytes()
        raw_strings = re.findall(rb'[\x20-\x7e]{6,}', raw)
        strings = [s.decode('ascii', errors='ignore') for s in raw_strings]
        return None, [], [], strings


# ─────────────────────────────────────────────────────────────
# PHASE 1A — DEVICE READINESS CHECK
# ─────────────────────────────────────────────────────────────

def check_device_readiness() -> DeviceReadiness:
    """
    Pre-flight check before any analysis begins.
    Verifies: ADB connection, root access, Shamiko,
    No-FLAG_SECURE Magisk module, and frida-server.
    Warns but does not abort on non-critical failures.
    """
    banner("PHASE 1A // Device Readiness Check", "═")
    dr = DeviceReadiness()

    # ── 1. ADB connection ────────────────────────────────────
    result = adb("devices")
    lines = [l for l in result.stdout.strip().splitlines() if "\tdevice" in l]
    if not lines:
        err("No ADB device connected. Plug in device and enable USB debugging.")
        return dr

    dr.adb_connected = True
    dr.device_serial = lines[0].split("\t")[0]
    ok(f"ADB device     : {Fore.WHITE}{dr.device_serial}")

    # ── 2. Android version ───────────────────────────────────
    ver = adb("shell", "getprop", "ro.build.version.release")
    dr.android_version = ver.stdout.strip()
    ok(f"Android version: {Fore.WHITE}{dr.android_version}")

    # ── 3. Root access ───────────────────────────────────────
    root_test = adb("shell", "su", "-c", "id")
    if "uid=0" in root_test.stdout:
        dr.is_rooted = True
        ok("Root access    : CONFIRMED (uid=0)")
    else:
        err("Root access    : NOT AVAILABLE")
        dr.warnings.append(
            "Root unavailable. Cannot guarantee screenshot bypass or Frida injection. "
            "Consider AVD fallback."
        )

    # ── 4. Magisk modules ────────────────────────────────────
    magisk_modules = adb("shell", "su", "-c", "ls /data/adb/modules/")
    modules_out = magisk_modules.stdout.lower()

    if any(m in modules_out for m in Config.SHAMIKO_NAMES):
        dr.shamiko_active = True
        ok("Shamiko        : ACTIVE — root hidden from target apps")
    else:
        warn("Shamiko        : NOT FOUND — malware may detect root and self-terminate")
        dr.warnings.append("Shamiko not detected. Install via Magisk Manager → Modules.")

    if any(m in modules_out for m in Config.FLAG_SECURE_NAMES):
        dr.flag_secure_disabled = True
        ok("FLAG_SECURE    : GLOBALLY DISABLED — Tier 1 screenshot active")
    else:
        warn("FLAG_SECURE    : Global disable NOT found — Frida hook will be Tier 2")
        dr.warnings.append(
            "No FLAG_SECURE Magisk module found. "
            "Screenshots fall back to Frida hook (Tier 2). "
            "Install 'No FLAG_SECURE' via Magisk Manager for best results."
        )

    # ── 5. frida-server binary ───────────────────────────────
    frida_check = adb("shell", "su", "-c", f"ls {Config.FRIDA_SERVER}")
    if "No such file" in frida_check.stderr or frida_check.returncode != 0:
        err(f"frida-server   : NOT FOUND at {Config.FRIDA_SERVER}")
        dr.warnings.append(
            f"frida-server binary missing at {Config.FRIDA_SERVER}. "
            "Download matching version from github.com/frida/frida/releases "
            f"and run: adb push frida-server {Config.FRIDA_SERVER}"
        )
    else:
        ok(f"frida-server   : Found at {Config.FRIDA_SERVER}")
        ps_check = adb("shell", "su", "-c", "ps -A | grep frida-server")
        if "frida-server" in ps_check.stdout:
            dr.frida_server_running = True
            ok("frida-server   : ALREADY RUNNING")
        else:
            info("frida-server   : Binary present, not yet running (will start before launch)")

    # ── 6. Readiness summary ─────────────────────────────────
    print()
    if not dr.ready_for_analysis:
        err("Device NOT ready for analysis. Fix errors above and retry.")
    else:
        tier_labels = {
            1: "Tier 1 — Magisk Global Disable (best)",
            2: "Tier 2 — Frida Hook fallback",
            3: "Tier 3 — XML-only mode (no screenshots)",
        }
        ok(f"Device READY   : {tier_labels[dr.screenshot_tier]}")

    if dr.warnings:
        print()
        info(f"{len(dr.warnings)} warning(s) — non-fatal, recorded in report:")
        for w in dr.warnings:
            warn(w)

    return dr


# ─────────────────────────────────────────────────────────────
# [v3.5] AAPT FALLBACK — package name from binary manifest
# ─────────────────────────────────────────────────────────────

def _try_aapt_package_name(apk_path: str) -> str:
    """
    Use aapt (Android Asset Packaging Tool) to extract the package name
    directly from the binary AndroidManifest.xml inside the APK.

    aapt reads the manifest using its own AXML parser — independent of
    androguard — and succeeds on many packed/protected APKs where
    androguard fails (different compression formats, custom AXML encodings).

    Returns the package name string, or "" on failure.
    Tried in order: aapt2, then aapt (whichever is on PATH first).
    Never raises — all errors are swallowed and logged via warn().
    """
    for tool in ("aapt2", "aapt"):
        try:
            result = subprocess.run(
                [tool, "dump", "badging", apk_path],
                capture_output=True, text=True, timeout=15
            )
            for line in result.stdout.splitlines():
                if line.startswith("package:"):
                    # e.g. package: name='com.evil.app' versionCode='1' ...
                    m = re.search(r"name='([^']+)'", line)
                    if m:
                        return m.group(1)
        except FileNotFoundError:
            continue   # tool not installed — try next
        except Exception as e:
            warn(f"aapt fallback ({tool}) error: {e}")
            continue
    return ""


def _install_and_discover_package(apk_path: str, report: StaticReport) -> str:
    """
    [v3.5] Last-resort package name discovery: install the APK via adb,
    then diff 'pm list packages' before/after to find what appeared.

    This is the nuclear option — bypasses all manifest parsing entirely.
    Works on any APK regardless of encryption, custom compression, or
    packer protection, because adb install uses the device's own package
    manager which can handle formats that androguard and aapt cannot.

    Side-effect: the APK is installed on the device.
    Sets report.warnings to record what happened.
    Returns package name string, or "" if install itself failed.
    """
    banner("PHASE 1B₃ // Install-and-Discover (encrypted APK fallback)", "─")
    warn("All static extraction methods failed — falling back to install + pm diff.")

    # Snapshot packages BEFORE install
    before_result = adb("shell", "pm", "list", "packages")
    before = set(
        line.replace("package:", "").strip()
        for line in before_result.stdout.splitlines()
        if line.startswith("package:")
    )

    # Attempt install
    info(f"Installing {Path(apk_path).name} via adb install ...")
    result = adb("install", "-r", "-t", apk_path)
    combined = (result.stdout + result.stderr).strip()

    if result.returncode != 0 and (
        "INSTALL_FAILED_DEPRECATED_SDK_VERSION" in combined
        or "deprecated" in combined.lower()
    ):
        warn("Low targetSdkVersion — retrying with --bypass-low-target-sdk-block ...")
        result = adb("install", "--bypass-low-target-sdk-block", "-r", "-t", apk_path)
        combined = (result.stdout + result.stderr).strip()

    if result.returncode != 0 and "Success" not in combined:
        err(f"Install failed: {combined}")
        report.errors.append(f"install_and_discover: adb install failed: {combined}")
        return ""

    ok(f"Install result : {combined or 'Success'}")

    # Give PackageManager a moment to register the new package
    time.sleep(2)

    # Snapshot AFTER install and diff
    after_result = adb("shell", "pm", "list", "packages")
    after = set(
        line.replace("package:", "").strip()
        for line in after_result.stdout.splitlines()
        if line.startswith("package:")
    )

    new_packages = after - before
    if not new_packages:
        warn("pm list packages diff returned no new packages — install may have silently failed.")
        report.warnings.append(
            "install_and_discover: APK installed but no new package appeared in pm list. "
            "The APK may be a re-install of an existing package, or a packer that registers "
            "under an existing namespace."
        )
        return ""

    if len(new_packages) > 1:
        warn(f"Multiple new packages appeared: {new_packages}. Using first found.")

    pkg = sorted(new_packages)[0]
    ok(f"Package discovered via pm diff: {Fore.WHITE}{pkg}")
    report.warnings.append(
        f"Package name '{pkg}' discovered by install + pm list diff (static parse failed). "
        "APK is already installed on device — skip install step in Phase 1F₂."
    )
    # Mark that we've already installed so main() doesn't try again
    report.warnings.append("__already_installed__")
    return pkg


# ─────────────────────────────────────────────────────────────
# [v3.4] ZIP-LEVEL FALLBACK FOR ENCRYPTED / PACKED APKs
# ─────────────────────────────────────────────────────────────

def _extract_package_from_zip(apk_path: str,
                               report: StaticReport) -> tuple[str, str]:
    """
    Last-resort metadata extraction when androguard cannot parse the APK.
    Reads the zip central directory (which is rarely encrypted) to:
      - Infer the package name from lib/<abi>/<package>.so or assets paths
      - List contained file names as structural evidence
      - Record file count and DEX presence as packer signals

    Returns (package_name, main_activity) — both may be empty strings.
    Populates report.warnings with structural observations.
    """
    pkg  = ""
    act  = ""
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            names = zf.namelist()

        report.warnings.append(
            f"ZIP directory readable: {len(names)} entries. "
            "AndroidManifest.xml encrypted — package name inferred only."
        )

        # Structural signals — each is a packer/protector indicator
        has_dex      = any(n.endswith(".dex") for n in names)
        has_odex     = any(n.endswith(".odex") for n in names)
        has_so       = any(n.startswith("lib/") and n.endswith(".so") for n in names)
        has_manifest = "AndroidManifest.xml" in names
        # Encrypted manifest is present but unreadable
        encrypted_manifest = has_manifest  # we know it failed

        if not has_dex and not has_odex:
            report.warnings.append(
                "No .dex or .odex files visible — all code may be inside an "
                "encrypted container (very strong packer signal)."
            )
        if has_so:
            # lib/<abi>/lib<package>.so → crude package inference
            so_names = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
            for so in so_names:
                parts = so.split("/")
                if len(parts) >= 3:
                    libname = parts[-1]          # e.g. libcom.evil.app.so
                    if libname.startswith("lib") and "." in libname:
                        candidate = libname[3:].replace(".so", "")
                        if candidate.count(".") >= 1:
                            pkg = candidate
                            break

        # Try assets/ path for package hint
        if not pkg:
            for n in names:
                if n.startswith("assets/") and "/" in n[len("assets/"):]:
                    sub = n[len("assets/"):]
                    parts = sub.split("/")
                    if len(parts) >= 1 and "." in parts[0]:
                        candidate = parts[0]
                        if candidate.count(".") >= 1 and not candidate.endswith("."):
                            pkg = candidate
                            break

        if pkg:
            report.warnings.append(f"Package inferred from zip structure: {pkg}")
        else:
            # [v3.5] Zip structure gave nothing — try aapt before giving up
            warn("Zip structure yielded no package name. Trying aapt fallback...")
            pkg = _try_aapt_package_name(apk_path)
            if pkg:
                report.warnings.append(f"Package name recovered via aapt: {pkg}")
                warn(f"aapt fallback    : {pkg}")
            else:
                report.warnings.append(
                    "Could not infer package name from zip structure or aapt. "
                    "Supply it manually with: sentry.py --apk <package_name>"
                )

    except Exception as e:
        report.warnings.append(f"Zip fallback also failed: {e}")
        # [v3.5] Even if zipfile itself raised, aapt works on the raw file
        warn("Zip fallback raised — trying aapt as last resort...")
        pkg = _try_aapt_package_name(apk_path)
        if pkg:
            report.warnings.append(f"Package name recovered via aapt (after zip error): {pkg}")
            warn(f"aapt fallback    : {pkg}")

    return pkg, act


# ─────────────────────────────────────────────────────────────
# PHASE 1B — APK PARSING
# ─────────────────────────────────────────────────────────────

def parse_apk(apk_path: str, is_child: bool = False) -> StaticReport:
    """Core androguard parse. Returns a populated StaticReport."""
    report = StaticReport(apk_path=apk_path, is_child=is_child)
    path   = Path(apk_path)
    label  = "DROPPED APK" if is_child else "MAIN APK"

    banner(f"PHASE 1B // Manifest Inspection ({label})", "═")

    if not path.exists():
        report.errors.append(f"File not found: {apk_path}")
        err(f"File not found: {apk_path}")
        return report

    if path.suffix.lower() != ".apk":
        warn(f"Extension '{path.suffix}' — expected .apk. Proceeding anyway.")

    print(f"  Parsing: {Fore.WHITE}{apk_path}{Style.RESET_ALL}\n")

    try:
        apk, dalvik_files, analysis = AnalyzeAPK(apk_path)
    except Exception as e:
        err(f"androguard parse failed: {e}")
        # ── [v3.4] Encrypted / packed APK fallback ─────────────
        # Common causes: encrypted AndroidManifest.xml, unsupported
        # compression method (e.g. Deflate64), integrity-checked DEX.
        # These are themselves strong packer/protector signals.
        # We fall back to zip-level metadata extraction so sentry.py
        # can still run directly with --apk <path>.
        _enc_hint = str(e).lower()
        if any(k in _enc_hint for k in ("encrypt", "password", "compress",
                                         "not support", "axml", "badzip")):
            warn("APK appears to use encryption or unsupported compression.")
            warn("Attempting zip-level metadata extraction as fallback...")
            _pkg, _act = _extract_package_from_zip(apk_path, report)
            if _pkg:
                report.package_name  = _pkg
                report.main_activity = _act
                report.has_launcher  = bool(_act)
                warn(f"Fallback package : {_pkg}")
                warn("Static analysis incomplete — Phase 2 can still run with --apk flag.")
                report.warnings.append(
                    "Encrypted/packed APK: AndroidManifest.xml not parsed. "
                    "Static report is partial. Dynamic analysis unaffected."
                )
            else:
                # [v3.5] androguard + zip + aapt all failed.
                # Final escalation: install the APK and diff pm list packages.
                # Only viable in non-child mode (we need a real device).
                if not is_child:
                    _pkg = _install_and_discover_package(apk_path, report)
                    if _pkg:
                        report.package_name = _pkg
                        report.has_launcher = False   # unknown until pm dump
                        warn(f"Package recovered via install+diff: {_pkg}")
                        warn("Static analysis incomplete — Phase 2 can still run with --apk flag.")
                        report.warnings.append(
                            "Encrypted/packed APK: package name recovered by install + "
                            "pm list diff. Static report is partial. "
                            "Dynamic analysis unaffected."
                        )
                    else:
                        report.errors.append(f"androguard parse failed: {e}")
                        report.warnings.append(
                            "All extraction methods failed including install+diff. "
                            "Use --apk <package_name> with sentry.py manually."
                        )
                else:
                    report.errors.append(f"androguard parse failed: {e}")
                    report.warnings.append(
                        "APK parse completely failed (child mode). "
                        "Cannot install child APK for package discovery."
                    )
        else:
            report.errors.append(f"androguard parse failed: {e}")
        return report

    # ── Package & Activity ───────────────────────────────────
    report.package_name   = apk.get_package()
    report.main_activity  = apk.get_main_activity() or ""
    report.all_activities = apk.get_activities()
    report.has_launcher   = bool(report.main_activity)

    ok(f"Package name  : {Fore.WHITE}{report.package_name}")

    if report.has_launcher:
        ok(f"Main activity : {Fore.WHITE}{report.main_activity}")
        info(f"All activities ({len(report.all_activities)} total):")
        for act in report.all_activities:
            print(f"       {Fore.CYAN}{act}")
    else:
        warn("No LAUNCHER activity — this is a background service APK (no UI)")
        warn("Phase 3 Explorer will be skipped. Phase 2 Sentry will monitor by PID only.")

    # ── Permissions ──────────────────────────────────────────
    banner("PHASE 1C // Permission Analysis")
    raw_perms = apk.get_permissions()
    dangerous, normal, unknown = [], [], []

    for p in raw_perms:
        if p in PERMISSION_TAXONOMY:
            taxonomy = PERMISSION_TAXONOMY[p]
            perm = Permission(
                name=p,
                level="DANGEROUS",
                description=taxonomy["description"],
                risk_score=taxonomy["risk_score"],
            )
            dangerous.append(perm)
        elif p in NORMAL_PERMISSIONS or p.startswith("android.permission."):
            perm = Permission(name=p, level="NORMAL")
            normal.append(perm)
        else:
            perm = Permission(name=p, level="UNKNOWN")
            unknown.append(perm)
        report.permissions.append(perm)

    if dangerous:
        print(f"\n  {Fore.RED}[DANGEROUS — {len(dangerous)} found]{Style.RESET_ALL}")
        for p in dangerous:
            score_str = f"  risk:{p.risk_score}/10" if p.risk_score else ""
            print(f"    {Fore.RED}⬡ {p.short}{Style.RESET_ALL}{Fore.WHITE}{score_str}{Style.RESET_ALL}")
    if normal:
        print(f"\n  {Fore.YELLOW}[NORMAL — {len(normal)} found]{Style.RESET_ALL}")
        for p in normal:
            print(f"    {Fore.YELLOW}○ {p.short}{Style.RESET_ALL}")
    if unknown:
        print(f"\n  {Fore.CYAN}[CUSTOM/UNKNOWN — {len(unknown)} found]{Style.RESET_ALL}")
        for p in unknown:
            print(f"    {Fore.CYAN}? {p.name}{Style.RESET_ALL}")

    # ── Receivers & Intent Filters ───────────────────────────
    banner("PHASE 1D // Receivers & Intent Filters")
    try:
        for r_name in apk.get_receivers():
            intents = apk.get_intent_filters("receiver", r_name)
            actions = []
            if intents:
                for filter_data in intents.values():
                    actions.extend(filter_data.get("action", []))
            report.receivers.append(Receiver(name=r_name, actions=actions))
            ok(f"{r_name}")
            for a in actions:
                print(f"       {Fore.CYAN}→ {a}")
    except Exception as e:
        warn(f"Receiver extraction partial: {e}")

    if not report.receivers:
        info("No broadcast receivers found.")

    return report


# ─────────────────────────────────────────────────────────────
# [v3-2] PHASE 1D₂ — MANIFEST SECURITY ANALYSIS
# ─────────────────────────────────────────────────────────────

def scan_manifest_security(apk_path: str, report: StaticReport,
                           apk_obj=None) -> None:
    """
    Analyse AndroidManifest.xml for security misconfigurations.
    Checks derived from MobSF manifest_analysis.py:
      - debuggable, allowBackup, cleartext traffic, testOnly
      - targetSdkVersion / minSdkVersion thresholds
      - exported components (activities, services, receivers, providers)
        classified by whether a permission guards them
      - task hijacking (StrandHogg 1.0) on singleTask activities
      - network security config presence
    Populates report.manifest_security.

    [v3.4-1] Accepts pre-parsed apk_obj from _extract_dex_strings() so that
    AnalyzeAPK() is never called more than once per Phase 1 run. When
    apk_obj is None (standalone call or test), falls back to parsing apk_path.
    """
    banner("PHASE 1D₂ // Manifest Security Analysis")
    ms = report.manifest_security

    def _add_issue(rule: str, title: str, severity: str,
                   description: str, component: str = "") -> None:
        ms.issues.append(ManifestIssue(
            rule=rule, title=title, severity=severity,
            description=description, component=component,
        ))

    import xml.etree.ElementTree as ET

    try:
        if apk_obj is None:
            # Standalone call (e.g. from tests) — parse here.
            apk_obj, _, _ = AnalyzeAPK(apk_path)
        # get_android_manifest_xml() returns a minidom Document on some
        # androguard versions and an lxml Element on others.
        # Use get_android_manifest_axml().get_xml() which always gives
        # raw bytes, then parse with stdlib ET — no minidom/lxml needed.
        raw_xml: bytes = apk_obj.get_android_manifest_axml().get_xml()
        root = ET.fromstring(raw_xml)
    except Exception as e:
        warn(f"Manifest security scan failed: {e}")
        report.warnings.append(f"Manifest security scan failed: {e}")
        return

    NS = "http://schemas.android.com/apk/res/android"

    def attr(node, name: str) -> str:
        return node.get(f"{{{NS}}}{name}", "")

    # ── SDK versions ─────────────────────────────────────────
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        try:
            ms.min_sdk    = int(attr(uses_sdk, "minSdkVersion") or 0)
            ms.target_sdk = int(attr(uses_sdk, "targetSdkVersion") or 0)
        except ValueError:
            pass

    if ms.min_sdk and ms.min_sdk < 26:      # < Android 8.0
        _add_issue(
            "vulnerable_os_version",
            f"Low minSdkVersion ({ms.min_sdk}) — supports Android below 8.0",
            "warning",
            "App supports Android versions below 8.0 (API 26). Many security "
            "improvements (network security config defaults, autofill protections) "
            "are unavailable on older versions.",
        )
    if ms.target_sdk and ms.target_sdk < 28:   # < Android 9 (P)
        _add_issue(
            "low_target_sdk",
            f"Low targetSdkVersion ({ms.target_sdk}) — below Android 9 (API 28)",
            "warning",
            "Targeting below API 28 opts out of strict network security defaults "
            "and cleartext traffic restrictions introduced in Android P.",
        )

    # ── Application-level attributes ─────────────────────────
    app_node = root.find("application")
    if app_node is None:
        warn("No <application> element found in manifest.")
        return

    # debuggable
    if attr(app_node, "debuggable") == "true":
        ms.debuggable = True
        _add_issue(
            "app_is_debuggable",
            "Application is debuggable",
            "high",
            "android:debuggable=true allows attackers to attach a debugger, "
            "extract runtime secrets, and bypass security controls. "
            "Must be false in production builds.",
        )
    ok("debuggable      : " + ("⚠ TRUE" if ms.debuggable else "false"))

    # allowBackup
    backup_val = attr(app_node, "allowBackup")
    if backup_val == "true":
        ms.allow_backup = True
        _add_issue(
            "app_allowbackup",
            "allowBackup=true — app data accessible via ADB backup",
            "warning",
            "android:allowBackup=true enables ADB backup extraction of app data "
            "including databases, shared preferences, and files without root.",
        )
    elif backup_val == "":
        ms.backup_not_set = True
        _add_issue(
            "allowbackup_not_set",
            "allowBackup not explicitly set (defaults to true on API < 31)",
            "info",
            "If allowBackup is not explicitly set to false, ADB backup may be "
            "permitted on devices running Android 11 and below.",
        )
    ok("allowBackup     : " + (backup_val if backup_val else "not set (⚠ defaults true on API<31)"))

    # cleartext traffic
    if attr(app_node, "usesCleartextTraffic") == "true":
        ms.cleartext_traffic = True
        _add_issue(
            "clear_text_traffic",
            "Cleartext HTTP traffic permitted",
            "warning",
            "android:usesCleartextTraffic=true allows unencrypted HTTP. "
            "Sensitive data may be transmitted in plaintext.",
        )

    # network security config
    nsc_ref = attr(app_node, "networkSecurityConfig")
    if nsc_ref:
        ms.has_network_security_config = True
        ms.network_security_config_ref = nsc_ref
        ok(f"NetworkSecConfig: {nsc_ref}")
    else:
        _add_issue(
            "no_network_security_config",
            "No network security config defined",
            "info",
            "Without a network security config, the app relies on platform defaults. "
            "Defining one explicitly can prevent cleartext traffic and custom CA trust.",
        )

    # testOnly
    if attr(app_node, "testOnly") == "true":
        ms.test_only = True
        _add_issue(
            "app_in_test_mode",
            "Application is marked testOnly",
            "warning",
            "android:testOnly=true is intended for test builds. "
            "Should never be present in production APKs.",
        )

    # ── Component export analysis ─────────────────────────────
    _COMPONENT_MAP = {
        "activity":       ("Activity",          ms.exported_activities),
        "activity-alias": ("Activity-Alias",    ms.exported_activities),
        "service":        ("Service",           ms.exported_services),
        "receiver":       ("Broadcast Receiver",ms.exported_receivers),
        "provider":       ("Content Provider",  ms.exported_providers),
    }

    for child in app_node:
        tag = child.tag
        if tag not in _COMPONENT_MAP:
            continue
        component_type, export_list = _COMPONENT_MAP[tag]
        name = attr(child, "name")
        exported = attr(child, "exported")
        has_permission = bool(attr(child, "permission"))
        has_intent_filter = any(c.tag == "intent-filter" for c in child)

        # Explicitly exported with no guarding permission
        if exported == "true" and not has_permission:
            export_list.append(name)
            _add_issue(
                "exported_no_permission",
                f"Exported {component_type} without permission: {name}",
                "high",
                f"This {component_type} is exported (android:exported=true) with no "
                f"android:permission guard. Any installed app can invoke it directly.",
                component=name,
            )

        # Implicitly exported via intent-filter, no permission
        elif exported != "false" and has_intent_filter and not has_permission:
            export_list.append(name)
            _add_issue(
                "exported_intent_filter_no_permission",
                f"Implicitly exported {component_type} via intent-filter: {name}",
                "warning",
                f"This {component_type} has an intent-filter but no permission guard. "
                f"It is implicitly exported and can be invoked by external apps.",
                component=name,
            )

        # Task hijacking (StrandHogg 1.0) — singleTask + targetSdk < 28
        if tag in ("activity", "activity-alias"):
            launch_mode = attr(child, "launchMode")
            if (launch_mode == "singleTask"
                    and ms.target_sdk
                    and ms.target_sdk < 28):
                ms.task_hijacking_activities.append(name)
                _add_issue(
                    "task_hijacking",
                    f"Task hijacking risk (StrandHogg) on activity: {name}",
                    "high",
                    f"Activity uses launchMode=singleTask with targetSdk={ms.target_sdk} "
                    f"(< 28). This is vulnerable to the StrandHogg task hijacking attack.",
                    component=name,
                )

    # ── Print summary ─────────────────────────────────────────
    counts = ms.issue_count_by_severity
    print()
    for sev in ("high", "warning", "info", "good"):
        n = counts.get(sev, 0)
        if n:
            col = severity_colour(sev)
            print(f"  {col}[{sev.upper()}]{Style.RESET_ALL}  {n} issue(s)")

    exported_total = (len(ms.exported_activities) + len(ms.exported_services)
                      + len(ms.exported_receivers) + len(ms.exported_providers))
    if exported_total:
        warn(f"Exported components without permission: {exported_total} "
             f"(activities:{len(ms.exported_activities)} "
             f"services:{len(ms.exported_services)} "
             f"receivers:{len(ms.exported_receivers)} "
             f"providers:{len(ms.exported_providers)})")
    else:
        ok("No unguarded exported components found")


# ─────────────────────────────────────────────────────────────
# [v3-3] PHASE 1B₂ — CERTIFICATE ANALYSIS
# ─────────────────────────────────────────────────────────────

def scan_certificate(apk_path: str, report: StaticReport) -> None:
    """
    Extract and analyse the APK signing certificate.
    Uses zipfile to pull META-INF/*.RSA / *.DSA / *.EC then
    parses the DER-encoded certificate with the stdlib ssl module
    (via a temporary file). Falls back gracefully if unavailable.
    Populates report.certificate.
    """
    banner("PHASE 1B₂ // Certificate Analysis")
    ci = report.certificate

    try:
        import ssl
        import tempfile
        import struct

        cert_der: bytes | None = None

        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                upper = name.upper()
                if (upper.startswith("META-INF/")
                        and any(upper.endswith(ext) for ext in (".RSA", ".DSA", ".EC", ".SF"))):
                    if upper.endswith(".SF"):
                        continue
                    cert_der = zf.read(name)
                    break

        if cert_der is None:
            ci.error = "No signing certificate found in META-INF/"
            warn(ci.error)
            return

        # SHA-256 fingerprint of raw DER bytes
        ci.sha256_fingerprint = hashlib.sha256(cert_der).hexdigest().upper()
        ci.sha256_fingerprint = ":".join(
            ci.sha256_fingerprint[i:i+2] for i in range(0, len(ci.sha256_fingerprint), 2)
        )

        # Write to temp file and use ssl.DER_cert_to_PEM_cert + parse
        pem = ssl.DER_cert_to_PEM_cert(cert_der)

        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False, mode="w") as f:
            f.write(pem)
            tmp_path = f.name

        try:
            cert_info = ssl._ssl._test_decode_cert(tmp_path)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        # Subject / issuer
        def _dict_to_str(d) -> str:
            if isinstance(d, (list, tuple)):
                parts = []
                for item in d:
                    if isinstance(item, (list, tuple)):
                        for k, v in item:
                            parts.append(f"{k}={v}")
                    else:
                        parts.append(str(item))
                return ", ".join(parts)
            return str(d)

        ci.subject = _dict_to_str(cert_info.get("subject", ""))
        ci.issuer  = _dict_to_str(cert_info.get("issuer", ""))
        ci.serial_number = str(cert_info.get("serialNumber", ""))
        ci.sig_algorithm = cert_info.get("signatureAlgorithm", "")

        # Validity
        not_before_str = cert_info.get("notBefore", "")
        not_after_str  = cert_info.get("notAfter",  "")
        ci.not_before  = not_before_str
        ci.not_after   = not_after_str

        # Expiry check
        try:
            not_after_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            not_after_dt = not_after_dt.replace(tzinfo=timezone.utc)
            ci.is_expired = not_after_dt < datetime.now(timezone.utc)
        except ValueError:
            pass

        # Self-signed: issuer == subject
        ci.is_self_signed = (ci.subject == ci.issuer)

        # Weak signature algorithm
        weak_algos = ("md2", "md4", "md5", "sha1", "sha-1")
        ci.weak_sig_algorithm = any(
            w in ci.sig_algorithm.lower() for w in weak_algos
        )

        # ── Print ─────────────────────────────────────────────
        ok(f"Subject        : {ci.subject}")
        ok(f"Issuer         : {ci.issuer}")
        ok(f"Sig algorithm  : {ci.sig_algorithm}")
        ok(f"Valid until    : {ci.not_after}")
        ok(f"Fingerprint    : {ci.sha256_fingerprint[:29]}…")

        if ci.is_self_signed:
            warn("Self-signed certificate — not trusted by app stores. Normal for malware.")
        if ci.is_expired:
            warn("Certificate is EXPIRED.")
        if ci.weak_sig_algorithm:
            warn(f"Weak signature algorithm: {ci.sig_algorithm}")

    except Exception as e:
        ci.error = f"Certificate extraction failed: {e}"
        warn(ci.error)
        report.warnings.append(ci.error)


# ─────────────────────────────────────────────────────────────
# PHASE 1E — HARDCODED INDICATOR SCAN  [v3-1 URL regex fix]
# ─────────────────────────────────────────────────────────────

def scan_indicators(apk_path: str, report: StaticReport,
                    all_strings: list[str] | None = None) -> None:
    """
    Scan for hardcoded IPs, URLs, and API key patterns.
    [v3-1] URL regex now requires a proper TLD-bearing hostname,
    eliminating HTML/CSS false positives.
    Private/RFC1918 IPs are filtered to reduce noise.
    [v3.4-1] Accepts pre-extracted all_strings from _extract_dex_strings()
    to avoid calling AnalyzeAPK() twice.
    """
    banner("PHASE 1E // Hardcoded Indicator Extraction")

    if all_strings is None:
        # Standalone call (e.g. from tests) — extract strings here
        _, _, _, all_strings = _extract_dex_strings(apk_path)

    info(f"Scanning {len(all_strings):,} strings from DEX...")

    seen: dict[str, set] = {k: set() for k in INDICATORS}

    for s in all_strings:
        for kind, pattern in INDICATORS.items():
            for match in pattern.findall(s):
                val = match.strip() if isinstance(match, str) else match
                if not val or val in seen[kind]:
                    continue
                if kind == "ipv4" and any(val.startswith(p) for p in PRIVATE_IP_PREFIXES):
                    continue
                seen[kind].add(val)
                report.indicators[kind].append(val)

    for kind, values in report.indicators.items():
        label = kind.upper().replace("_", " ")
        if values:
            print(f"\n  {Fore.YELLOW}[{label} — {len(values)} found]{Style.RESET_ALL}")
            for v in values[:20]:
                print(f"    {Fore.YELLOW}• {v}{Style.RESET_ALL}")
            if len(values) > 20:
                info(f"  ... and {len(values) - 20} more (full list in JSON)")
        else:
            ok(f"{label}: none found")


# ─────────────────────────────────────────────────────────────
# [v3-4] PHASE 1E₂ — CODE PATTERN SCAN
# ─────────────────────────────────────────────────────────────

def scan_code_patterns(apk_path: str, report: StaticReport,
                       all_strings: list[str] | None = None) -> None:
    """
    Scan DEX strings for known-dangerous code patterns.
    Rules sourced from MobSF android_rules.yaml, adapted for
    string-level matching (not source code).

    Severity key:
      high    — directly exploitable or highly suspicious
      warning — concerning, requires review
      info    — neutral observation
      good    — defence/hardening indicator (lowers threat signal)

    [v3.4-2] Performance rewrite — three key changes:
      1. Accepts pre-extracted all_strings from _extract_dex_strings()
         so AnalyzeAPK() is never called twice in a single run.
      2. _RULE_ANCHORS pre-filter: if a rule's anchor literal is absent
         from the full blob, the regex is skipped entirely (O(n) string
         scan replaced by O(1) 'in' check on the blob).
      3. DOTALL multi-token rules rewritten as two-phase checks:
         fast __contains__ guard on both required tokens, then regex
         only on a small ±_CTX_WINDOW character context window around
         the first token hit.  No more scanning 5MB+ blob with a
         DOTALL lookahead.
      4. Per-string scan for all other rules — no monolithic blob,
         no catastrophic backtracking, match_count = unique strings hit.
    """
    banner("PHASE 1E₂ // Code Pattern Analysis")

    t0 = time.monotonic()

    if all_strings is None:
        _, _, _, all_strings = _extract_dex_strings(apk_path)

    if not all_strings:
        warn("No DEX strings available for code pattern scan.")
        report.warnings.append("Code pattern scan: no strings extracted.")
        return

    info(f"Scanning {len(all_strings):,} DEX strings against "
         f"{len(CODE_PATTERN_RULES)} rules...")

    # Full blob for anchor checks and DOTALL context extraction only.
    # Never run heavy regexes directly against this.
    blob: str = "\n".join(all_strings)

    # ── Window size for DOTALL context extraction ─────────────
    # Enough to span a typical smali method body. Larger = safer
    # against false negatives; smaller = faster. 4000 chars covers
    # ~100 smali lines which is more than enough for any paired call.
    _CTX_WINDOW: int = 4_000

    def _dotall_two_phase(
        token_a: str,
        token_b: str,
        pattern: re.Pattern,
        blob: str,
    ) -> int:
        """
        Count matches for a DOTALL rule that requires two tokens to
        appear near each other.

        Phase 1: check both tokens are present at all (fast literal
                 search — no regex).
        Phase 2: for each occurrence of token_a, extract a context
                 window of ±_CTX_WINDOW chars and run the regex only
                 on that slice.  Returns match count.
        """
        if token_a not in blob or token_b not in blob:
            return 0
        count = 0
        start = 0
        while True:
            pos = blob.find(token_a, start)
            if pos == -1:
                break
            lo  = max(0, pos - _CTX_WINDOW)
            hi  = min(len(blob), pos + _CTX_WINDOW)
            if pattern.search(blob[lo:hi]):
                count += 1
            start = pos + 1
        return count

    hits_by_sev: dict[str, list[CodePatternHit]] = {
        "high": [], "warning": [], "info": [], "good": []
    }

    for rule_id, title, severity, pattern in CODE_PATTERN_RULES:
        try:
            # ── Step 1: anchor pre-filter (fast literal check) ─
            anchor = _RULE_ANCHORS.get(rule_id)
            if anchor and anchor not in blob:
                continue  # rule cannot possibly match — skip entirely

            flags = pattern.flags

            # ── Step 2: route to the right scan strategy ───────

            if flags & re.DOTALL:
                # DOTALL rules require two tokens to appear near each
                # other in smali. Route each rule to its two-phase check.
                if rule_id == "insecure_ssl":
                    count = _dotall_two_phase(
                        "javax.net.ssl",
                        "ALLOW_ALL_HOSTNAME_VERIFIER",   # representative token
                        pattern, blob,
                    )
                    # Also try the other SSL bypass variants if first gave 0
                    if not count:
                        for alt_b in ("TrustAllSSLSocket", "AllTrustSSLSocketFactory",
                                      "NonValidatingSSLSocketFactory",
                                      "setDefaultHostnameVerifier",
                                      "NullHostnameVerifier"):
                            count = _dotall_two_phase("javax.net.ssl", alt_b, pattern, blob)
                            if count:
                                break

                elif rule_id == "webview_ignore_ssl":
                    count = _dotall_two_phase(
                        "onReceivedSslError", ".proceed()", pattern, blob
                    )

                elif rule_id == "webview_js_interface":
                    count = _dotall_two_phase(
                        "setJavaScriptEnabled", "addJavascriptInterface", pattern, blob
                    )

                elif rule_id == "sql_raw_query":
                    count = _dotall_two_phase(
                        "android.database.sqlite", "rawQuery", pattern, blob
                    )
                    if not count:
                        count = _dotall_two_phase(
                            "android.database.sqlite", "execSQL", pattern, blob
                        )

                elif rule_id == "clipboard_listen":
                    count = _dotall_two_phase(
                        "ClipboardManager", "OnPrimaryClipChangedListener", pattern, blob
                    )

                else:
                    # Unknown DOTALL rule — fall back to full-blob scan
                    # (safe default for future rule additions)
                    matches = pattern.findall(blob)
                    count = len(matches)

            else:
                # ── Per-string scan for all non-DOTALL rules ───
                # Each string is tested independently. match_count =
                # number of unique strings that contain at least one
                # match. This prevents a single concatenated blob from
                # inflating counts with phantom cross-string matches.
                count = 0
                for s in all_strings:
                    if anchor and anchor not in s:
                        # Secondary per-string anchor micro-filter
                        continue
                    if pattern.search(s):
                        count += 1

            if count:
                hit = CodePatternHit(
                    rule=rule_id,
                    title=title,
                    severity=severity,
                    match_count=count,
                )
                report.code_patterns.append(hit)
                hits_by_sev.setdefault(severity, []).append(hit)

        except Exception:
            continue    # malformed match — non-fatal

    # ── Print results ─────────────────────────────────────────
    for sev in ("high", "warning", "info", "good"):
        hits = hits_by_sev.get(sev, [])
        if not hits:
            continue
        col = severity_colour(sev)
        print(f"\n  {col}[{sev.upper()} — {len(hits)} pattern(s)]{Style.RESET_ALL}")
        for h in hits:
            print(f"    {col}• {h.title}{Style.RESET_ALL}  (matches: {h.match_count})")

    elapsed = time.monotonic() - t0
    total = len(report.code_patterns)
    high_count = len(hits_by_sev.get("high", []))
    if total == 0:
        ok(f"No code patterns matched  [{elapsed:.1f}s]")
    elif high_count:
        warn(f"{total} pattern(s) matched — {high_count} HIGH severity  [{elapsed:.1f}s]")
    else:
        info(f"{total} pattern(s) matched  [{elapsed:.1f}s]")


# ─────────────────────────────────────────────────────────────
# PHASE 1F — START FRIDA-SERVER ON DEVICE
# ─────────────────────────────────────────────────────────────

def ensure_frida_server(dr: DeviceReadiness) -> bool:
    """
    Start frida-server on device if not already running.
    Called BEFORE app launch so Phase 3 never waits on black-frame detection.
    Returns True if frida-server is confirmed running after this call.
    """
    if dr.frida_server_running:
        skip("frida-server already running — nothing to do")
        return True

    check = adb("shell", "su", "-c", f"ls {Config.FRIDA_SERVER}")
    if check.returncode != 0:
        warn("frida-server binary not found — Tier 2 screenshot bypass unavailable")
        return False

    info(f"Starting frida-server at {Config.FRIDA_SERVER}...")
    adb("shell", "su", "-c",
        f"nohup {Config.FRIDA_SERVER} > /dev/null 2>&1 &")

    time.sleep(2)
    ps = adb("shell", "su", "-c", "ps -A | grep frida-server")
    if "frida-server" in ps.stdout:
        dr.frida_server_running = True
        ok("frida-server   : STARTED — Tier 2 screenshot bypass READY")
        return True
    else:
        warn("frida-server failed to start. Verify binary arch matches device CPU.")
        warn("Check: adb shell getprop ro.product.cpu.abi")
        return False


# ─────────────────────────────────────────────────────────────
# PHASE 1G — SHARED PID RESOLUTION HELPER
# ─────────────────────────────────────────────────────────────

def _resolve_pids(package: str) -> list[int]:
    """
    Attempt to find all PIDs for a running package.
    Strategy 1 — pidof <package>
    Strategy 2 — ps -A | grep <package>  (fallback for ROMs missing pidof,
                 also catches isolated child processes :push, :remote).
    Returns a list of integer PIDs (empty list if process not found).
    """
    res = adb("shell", "pidof", package)
    raw = res.stdout.strip()
    if raw:
        parts = [p for p in raw.split() if p.isdigit()]
        if parts:
            return [int(p) for p in parts]

    which = adb("shell", "which", "pidof")
    pidof_missing = not which.stdout.strip()
    if pidof_missing:
        info("pidof not found on device — falling back to ps -A")

    ps = adb("shell", "su", "-c", f"ps -A 2>/dev/null | grep {package}")
    pids = []
    for line in ps.stdout.strip().splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1].isdigit():
            pids.append(int(fields[1]))

    if pids and pidof_missing:
        info(f"ps -A fallback found {len(pids)} PID(s) for {package}")

    return pids


# ─────────────────────────────────────────────────────────────
# PHASE 1F₂ — PUSH & INSTALL APK ON DEVICE
# ─────────────────────────────────────────────────────────────

def install_apk(apk_path: str, report: StaticReport) -> bool:
    """
    Install the APK on the device using adb install.
    Uses direct adb install (no push needed).

    Strategy:
      1. adb install -r -t <apk_path>
      2. On INSTALL_FAILED_DEPRECATED_SDK_VERSION fallback:
         adb install --bypass-low-target-sdk-block -r -t <apk_path>
      3. Verify package is known to pm after install.

    Returns True on success, False on failure.
    Skipped automatically in --child mode (called from main() only).
    """
    banner("PHASE 1F₂ // APK Install", "═")

    path = Path(apk_path)
    if not path.exists():
        err(f"APK not found at {apk_path} — cannot install.")
        report.errors.append(f"install_apk: file not found: {apk_path}")
        return False

    info(f"Installing {path.name} via adb install ...")

    result = adb("install", "-r", "-t", str(path))
    combined = (result.stdout + result.stderr).strip()

    # Fallback for low-targetSdk APKs blocked by newer Android versions
    if result.returncode != 0 and (
        "INSTALL_FAILED_DEPRECATED_SDK_VERSION" in combined
        or "deprecated" in combined.lower()
    ):
        warn("Low targetSdkVersion blocked — retrying with --bypass-low-target-sdk-block ...")
        result = adb("install", "--bypass-low-target-sdk-block", "-r", "-t", str(path))
        combined = (result.stdout + result.stderr).strip()

    if "Success" in combined or result.returncode == 0:
        ok(f"Install result : {combined or 'Success'}")
    else:
        err(f"Install failed : {combined}")
        report.errors.append(f"install_apk: adb install failed: {combined}")
        return False

    # Verify the package is now registered
    check = adb("shell", "pm", "list", "packages", report.package_name)
    if report.package_name in check.stdout:
        ok(f"Package verified: {report.package_name} is installed on device")
    else:
        warn(f"pm list packages did not confirm {report.package_name} — may still be installing")

    return True


# ─────────────────────────────────────────────────────────────
# OUTPUT — SAVE REPORT JSON  [v3-6]
# ─────────────────────────────────────────────────────────────

def save_report(report: StaticReport,
                output_path: str = "static_report.json",
                session_dir: Optional[Path] = None) -> str:
    """
    Serialise StaticReport to JSON for downstream phases.
    [v3-6] summary block extended with manifest_issues, cert_flags,
    code_pattern_hits, and permission risk scores for Phase 4 LLM.
    [v4] If session_dir is provided, writes into that directory regardless
    of output_path — used by main() to co-locate all phase reports.
    """
    if session_dir is not None:
        output_path = str(session_dir / "static_report.json")
    data = asdict(report)

    # Explicitly write pid and all_pids (asdict() gotcha — see CLAUDE.md §7)
    data["pid"]      = report.pid
    data["all_pids"] = report.all_pids if report.all_pids else (
        [report.pid] if report.pid else []
    )

    # screenshot_tier is a @property — must be written explicitly
    tier = report.device.screenshot_tier
    if isinstance(data.get("device"), dict):
        data["device"]["screenshot_tier"] = tier

    # ── Manifest issue summary ────────────────────────────────
    ms = report.manifest_security
    manifest_issue_counts = ms.issue_count_by_severity   # dict

    # ── Certificate flags ─────────────────────────────────────
    ci = report.certificate
    cert_flags: list[str] = []
    if ci.is_self_signed:
        cert_flags.append("self_signed")
    if ci.is_expired:
        cert_flags.append("expired")
    if ci.weak_sig_algorithm:
        cert_flags.append(f"weak_sig_algo:{ci.sig_algorithm}")

    # ── Code pattern summary ──────────────────────────────────
    # Separate defensive indicators from threat indicators
    code_threats  = [asdict(h) for h in report.code_patterns if h.severity != "good"]
    code_defences = [asdict(h) for h in report.code_patterns if h.severity == "good"]
    high_code_hits = [h["rule"] for h in code_threats if h["severity"] == "high"]

    # ── Permission risk summary ───────────────────────────────
    dangerous_perms = [p for p in report.permissions if p.level == "DANGEROUS"]
    top_risk_perms  = sorted(dangerous_perms, key=lambda p: p.risk_score, reverse=True)
    total_risk_score = sum(p.risk_score for p in dangerous_perms)

    # ── Exported component summary ────────────────────────────
    exported_summary = {
        "activities": ms.exported_activities,
        "services":   ms.exported_services,
        "receivers":  ms.exported_receivers,
        "providers":  ms.exported_providers,
    }
    total_exported = sum(len(v) for v in exported_summary.values())

    data["summary"] = {
        # ── Core (unchanged from v2) ──────────────────────────
        "dangerous_permissions": [
            p["short"] for p in data["permissions"] if p["level"] == "DANGEROUS"
        ],
        "normal_permissions": [
            p["short"] for p in data["permissions"] if p["level"] == "NORMAL"
        ],
        "total_permissions":    len(report.permissions),
        "total_indicators":     sum(len(v) for v in report.indicators.values()),
        "has_receivers":        bool(report.receivers),
        "has_launcher":         report.has_launcher,
        "screenshot_tier":      tier,
        "frida_ready":          report.device.frida_server_running,
        "root_confirmed":       report.device.is_rooted,
        "shamiko_active":       report.device.shamiko_active,
        "flag_secure_disabled": report.device.flag_secure_disabled,
        "env":                  report.env,
        "model":                report.model,

        # ── [v3-5] Permission risk ────────────────────────────
        "permission_risk_score":    total_risk_score,
        "top_risk_permissions": [
            {"short": p.short, "risk_score": p.risk_score, "description": p.description}
            for p in top_risk_perms[:5]
        ],

        # ── [v3-2] Manifest security ──────────────────────────
        "manifest_issues": {
            "debuggable":           ms.debuggable,
            "allow_backup":         ms.allow_backup,
            "cleartext_traffic":    ms.cleartext_traffic,
            "target_sdk":           ms.target_sdk,
            "min_sdk":              ms.min_sdk,
            "exported_components":  total_exported,
            "exported_detail":      exported_summary,
            "task_hijacking":       ms.task_hijacking_activities,
            "high_count":           manifest_issue_counts.get("high", 0),
            "warning_count":        manifest_issue_counts.get("warning", 0),
            "issues": [
                {"rule": i.rule, "title": i.title,
                 "severity": i.severity, "component": i.component}
                for i in ms.issues if i.severity in ("high", "warning")
            ],
        },

        # ── [v3-3] Certificate ────────────────────────────────
        "certificate": {
            "subject":              ci.subject,
            "issuer":               ci.issuer,
            "is_self_signed":       ci.is_self_signed,
            "is_expired":           ci.is_expired,
            "sig_algorithm":        ci.sig_algorithm,
            "weak_sig_algorithm":   ci.weak_sig_algorithm,
            "not_after":            ci.not_after,
            "sha256_fingerprint":   ci.sha256_fingerprint,
            "flags":                cert_flags,
        },

        # ── [v3-4] Code patterns ──────────────────────────────
        "code_patterns": {
            "total_hits":       len(report.code_patterns),
            "high_severity":    len([h for h in report.code_patterns if h.severity == "high"]),
            "high_rules":       high_code_hits,
            "threats":          code_threats,
            "defences":         code_defences,
        },
    }

    Path(output_path).write_text(json.dumps(data, indent=2))
    return output_path


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    is_child = "--child" in sys.argv
    args     = [a for a in sys.argv[1:] if not a.startswith("--")]

    if not args:
        print(f"\n{Fore.RED}Usage:{Style.RESET_ALL}")
        print("  python static_analysis.py <path_to_apk>")
        print("  python static_analysis.py <path_to_apk> --child")
        print(f"\nExamples:")
        print("  python static_analysis.py ./samples/malware.apk")
        print("  python static_analysis.py ./dropped/dropped1.apk --child\n")
        sys.exit(1)

    apk_path = args[0]

    print(f"\n{Fore.GREEN}{'═' * 62}")
    print("  APK THREAT ORCHESTRATOR // PHASE 1: STATIC ANALYSIS v3.5")
    print(f"{'═' * 62}{Style.RESET_ALL}")

    banner("CONFIG", "─")
    Config.display()

    # Pre-flight device check
    dr = check_device_readiness()
    if not dr.ready_for_analysis:
        err("Aborting — device not ready. Fix errors above and retry.")
        sys.exit(1)

    # Phase 1B — APK parsing + permissions + receivers
    report        = parse_apk(apk_path, is_child=is_child)
    report.device = dr

    # [v3.4] Encrypted/packed APK: parse errors are warnings, not hard stops.
    # A partial report (with package_name) still allows sentry.py to run.
    # A report with no package_name at all is unrecoverable — abort.
    if report.errors:
        for e in report.errors:
            err(e)
        if not report.package_name:
            err("Cannot determine package name — cannot continue.")
            err("If you know the package name, use: sentry.py --apk <package_name>")
            sys.exit(1)
        warn("Parse errors above — proceeding with partial static report.")
        warn("Dynamic analysis (sentry.py) can still run.")

    # Remaining scans are skipped if androguard failed (no apk object).
    # [v3.5] Also partial when package was recovered via install+diff —
    # _install_and_discover_package() sets the __already_installed__ sentinel
    # in report.warnings as an unambiguous signal that no apk object exists.
    _partial = bool(report.errors) or ("__already_installed__" in report.warnings)

    # Phase 1E / 1E₂ / 1B₂ / 1D₂ — Extract DEX strings ONCE via AnalyzeAPK(),
    # share apk_obj and all_strings with every downstream scanner. [v3.4-1]
    # This guarantees AnalyzeAPK() is called exactly once per Phase 1 run.
    if not _partial:
        apk_obj_shared, _, _, dex_strings = _extract_dex_strings(apk_path)

        # Phase 1B₂ — Certificate analysis  [v3-3]
        scan_certificate(apk_path, report)

        # Phase 1D₂ — Manifest security     [v3-2]
        # Pass pre-parsed apk_obj so it doesn't call AnalyzeAPK() again.
        scan_manifest_security(apk_path, report, apk_obj=apk_obj_shared)

        # Phase 1E — Indicator scan         [v3-1 URL fix]
        scan_indicators(apk_path, report, all_strings=dex_strings)

        # Phase 1E₂ — Code patterns         [v3-4, v3.4-2 perf rewrite]
        scan_code_patterns(apk_path, report, all_strings=dex_strings)

    # Phase 1F₂ — Push & install APK on device  [v3.2]
    # [v3.5] Skip install if _install_and_discover_package() already installed it.
    _already_installed = "__already_installed__" in report.warnings
    if _already_installed:
        # Clean sentinel out of warnings so it doesn't appear in the report
        report.warnings = [w for w in report.warnings if w != "__already_installed__"]
        ok("APK already installed (done during package discovery step — skipping reinstall).")
    elif not is_child and not _partial:
        install_ok = install_apk(apk_path, report)
        if not install_ok:
            err("APK installation failed — aborting. Fix errors above and retry.")
            sys.exit(1)
    elif not is_child and _partial:
        warn("Skipping APK install — static parse failed (encrypted/packed APK).")
        warn("Install manually: adb install -r -t " + apk_path)

    # Phase 1F — Frida-server start
    banner("PHASE 1F // Frida-Server Preparation", "─")
    ensure_frida_server(dr)

    # NOTE: App is NOT launched here. Phase 2 (sentry.py) owns launch so that
    # monitoring threads are active before the app starts. This ensures no
    # network connections or permission dialogs are missed at startup.
    info("→ App launch deferred to Phase 2 (sentry.py) — monitors start first.")

    # Persist handoff JSON for Phase 2
    if is_child:
        # Child (dropped APK) reports stay in working directory
        out_path = save_report(report, "static_report_dropped.json")
        sess_dir = None
    else:
        # Create session directory — all phase outputs go here
        # [v3.5] Named after APK filename stem (not package name) so the dir
        # is always identifiable even when the package name cannot be parsed.
        apk_stem  = Path(apk_path).stem          # e.g. "PNBONE" from "PNBONE.apk"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        sess_dir  = Path(f"sessions/{apk_stem}_{timestamp}")
        sess_dir.mkdir(parents=True, exist_ok=True)
        out_path = save_report(report, session_dir=sess_dir)

    # ── Final summary ─────────────────────────────────────────
    banner("PHASE 1 COMPLETE // Summary", "═")
    ok(f"Package        : {report.package_name}")
    ok(f"Has UI         : {'Yes — Explorer will run' if report.has_launcher else 'No — background service'}")
    ok(f"Dangerous perms: {len([p for p in report.permissions if p.level == 'DANGEROUS'])}  "
       f"(risk score: {sum(p.risk_score for p in report.permissions if p.level == 'DANGEROUS')})")
    ok(f"Indicators     : {sum(len(v) for v in report.indicators.values())} hardcoded strings")

    ms = report.manifest_security
    issue_counts = ms.issue_count_by_severity
    ok(f"Manifest issues: {issue_counts.get('high',0)} high  "
       f"{issue_counts.get('warning',0)} warning  "
       f"(exported components: {len(ms.exported_activities)+len(ms.exported_services)+len(ms.exported_receivers)+len(ms.exported_providers)})")

    ci = report.certificate
    cert_summary = "self-signed" if ci.is_self_signed else "CA-signed"
    if ci.is_expired:
        cert_summary += " EXPIRED"
    if ci.weak_sig_algorithm:
        cert_summary += f" weak-algo:{ci.sig_algorithm}"
    ok(f"Certificate    : {cert_summary}")

    code_high = len([h for h in report.code_patterns if h.severity == "high"])
    code_good = len([h for h in report.code_patterns if h.severity == "good"])
    ok(f"Code patterns  : {len(report.code_patterns)} matched  ({code_high} high, {code_good} defence indicators)")

    ok(f"Screenshot tier: {dr.screenshot_tier}")
    ok(f"Frida ready    : {'Yes' if dr.frida_server_running else 'No'}")
    ok(f"ENV / Model    : {report.env.upper()} / {report.model}")
    ok(f"Report saved   : {out_path}")
    if sess_dir:
        ok(f"Session dir    : {sess_dir}")
        info(f"→ Now run Phase 2: python sentry.py --report {out_path}")
        info(f"  Phase 2 will launch the app, monitor behaviour, and run UI exploration.")

    if report.warnings:
        print()
        warn(f"{len(report.warnings)} warning(s) in report — review before proceeding.")

    print()


if __name__ == "__main__":
    main()