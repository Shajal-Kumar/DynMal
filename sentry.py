"""
APK Threat Orchestrator — Phase 2: Sentry (Behavioural Monitoring) v2.10
========================================================================
Changes from v2.9:
  [v2.10-1] LogcatStreamer: added -b radio and -b events buffers.
            The radio buffer is where Android logs DNS resolutions and
            cellular-stack TCP open events.  The events buffer captures
            Android connectivity/network-state change events.  Both were
            silently missing from all prior captures — C2 beacons and
            Firebase RTDB WebSocket handshakes live here.

  [v2.10-2] LogcatStreamer: added *:V Verbose floor to adb logcat command.
            Many ROM builds default to Info, silently dropping D/V lines.
            Malware C2 beacons are frequently logged at Debug or Verbose.

  [v2.10-3] LogcatStreamer: dual-pass PID filter.
            Lines are now accepted when (a) PID is in all_pids, OR (b) the
            line is network-relevant regardless of PID.  This catches:
            dropper process lines (different PID, not in tracked set),
            radio/events buffer lines (emitted by system daemons), and
            Firebase/OkHttp library lines logged under a service PID.
            _is_network_log_line() implements the context-anchored check.

  [v2.10-4] NetstatPoller: switched from `netstat -an` to `ss -tupn`.
            `netstat` truncates IPv6 addresses and long IPv4 octets at
            column boundaries, producing addresses like "125.21.240." and
            "2404:6800:4002:831:".  `ss` has no column width limit.
            Falls back to `netstat` if `ss` is absent on the ROM.

  [v2.10-5] NetstatPoller: reverse DNS lookup per new IP via nslookup.
            NetworkConnection.domain is now populated with the resolved
            hostname so Phase 4 IOC extraction classifies by name rather
            than raw IP.  Firebase RTDB domains, C2 hostnames, and CDN
            endpoints become visible.

  [v2.10-6] New FRIDA_URL_INTERCEPTOR_JS + _attach_url_interceptor().
            Hooks URL.<init>, OkHttp Request.Builder.url, OkHttp
            HttpUrl.parse, FirebaseDatabase.getInstance(url),
            FirebaseDatabase.getReference(path), and Retrofit.baseUrl.
            Intercepts plaintext hostnames BEFORE TLS negotiation — works
            even when mitmproxy cannot decrypt the connection.  Intercepted
            URLs are written to session.network_connections with
            protocol='URL' and domain=hostname so they flow directly into
            the Phase 4 IOC extractor.  Attached immediately after SSL
            bypass in main().  Session detached at shutdown.

Changes from v2.7:
  [v2.8-1] --explore is now the default. Add --no-explore to disable.
  [v2.8-2] _check_new_packages() race-condition fix + root-aware pull.
  [v2.8-3] Packer DEX extraction via Frida (FRIDA_DEX_EXTRACTOR_JS).

Changes from v2.6:
  [v2.7-1] Phase A budget cap in _explore_with_stop().
  [v2.7-2] Phase A/B/C progress logging.
  [v2.7-3] p1 dangerous_permissions injected into ExplorerEngine.

Changes from v2.4:
  [v2.6-1] handle_startup_dialogs() screencaps every new dialog screen.
  [v2.4-1] launch_apk_sentry() escalation for launcher-less APKs.
  [v2.4-2] handle_startup_dialogs() PID-gate.

Changes from v2.2:
  [v2.3-1] --apk <package_name> flag: run without a Phase 1 static report.
  [v2.3-2] load_phase1_report() required fields reduced to package_name.
  [v2.3-3] _build_synthetic_p1(): constructs valid p1 from package name only.

Usage:
    python sentry.py                              # explore ON by default (3-pass)
    python sentry.py --no-explore                 # [v2.8] monitor only
    python sentry.py --report path/to/report      # explicit static report path
    python sentry.py --apk com.evil.package       # skip Phase 1 entirely
    python sentry.py --apk com.evil.package --duration 300
    python sentry.py --duration 300               # run for 300s then stop

    Dropper/packer payloads are NOT explored automatically (v2.9).
    After analysis, copy-pasteable commands are printed for each payload.

Requirements:
    pip install androguard colorama frida-tools python-dotenv mitmproxy
"""

import os
import re
import sys
import json
import time
import queue
import hashlib
import asyncio
import logging
import tempfile
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional

import frida
from colorama import Fore, Style, init as colorama_init
from dotenv import load_dotenv

# mitmproxy inline API
from mitmproxy import options, http
from mitmproxy.tools import dump as mitm_dump

colorama_init(autoreset=True)
load_dotenv()

# Silence mitmproxy's verbose logging — we handle output ourselves
logging.getLogger("mitmproxy").setLevel(logging.CRITICAL)


# ─────────────────────────────────────────────────────────────
# CONFIG  (mirrors Phase 1 — reads same .env)
# ─────────────────────────────────────────────────────────────

class Config:
    ENV: str           = os.getenv("ENV", "dev")
    ADB_SERIAL: str    = os.getenv("ADB_SERIAL", "")
    FRIDA_SERVER: str  = os.getenv("FRIDA_SERVER_PATH", "/data/local/tmp/frida-server")
    FRIDA_PORT: int    = int(os.getenv("FRIDA_PORT", "17392"))
    MITM_PORT: int     = int(os.getenv("MITM_PORT", "8080"))
    INOTIFY_PATH: str  = os.getenv("INOTIFY_PATH", "/data/local/tmp/inotifywait")
    POLL_INTERVAL: float = float(os.getenv("POLL_INTERVAL", "3.0"))  # seconds
    NETSTAT_INTERVAL: float = float(os.getenv("NETSTAT_INTERVAL", "2.0"))
    # Directories to watch for dropped APKs
    WATCH_DIRS: list   = [
        "/sdcard/",
        "/sdcard/Download/",
        "/sdcard/Android/obb/",
        "/data/local/tmp/",
        "/cache/",
    ]
    # Root detection — if app dies within this many seconds, flag it
    ROOT_DETECT_WINDOW: float = float(os.getenv("ROOT_DETECT_WINDOW", "8.0"))


# ─────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────

@dataclass
class NetworkConnection:
    timestamp: str
    remote_ip: str
    remote_port: int
    local_port: int
    protocol: str = "TCP"
    domain: str   = ""    # reverse DNS if resolved

    def key(self) -> str:
        return f"{self.remote_ip}:{self.remote_port}"


@dataclass
class ExfiltrationEvent:
    timestamp: str
    url: str
    method: str
    data_type: str          # "contacts" | "location" | "sms" | "imei" | "credentials" | "file"
    destination_host: str
    payload_snippet: str    # first 300 chars of body
    permission_implicated: str = ""
    ssl_pinning_bypassed: bool = False


@dataclass
class DropperEvent:
    index: int
    timestamp: str
    trigger: str            # "inotifywait" | "polling" | "packageinstaller"
    device_path: str        # path on device where APK was found
    local_path: str         # where we saved it on PC
    sha256: str
    package_name: str = ""  # filled after child Phase 1 parse
    pull_method: str  = ""  # "sdcard" | "data_app" | "sdcard+data_app"
    child_report: str = ""  # path to child static_report json


@dataclass
class LogEvent:
    timestamp: str
    pid: int
    tag: str
    level: str
    message: str
    permission_implicated: str = ""   # filled by permission tagger


@dataclass
class SentrySession:
    """Complete output of Phase 2. Passed to Phase 3 Explorer."""
    package_name: str
    session_start: str        = ""
    session_end: str          = ""
    all_pids: list[int]       = field(default_factory=list)
    log_file: str             = ""    # path to raw logcat file
    log_events: list[LogEvent] = field(default_factory=list)
    network_connections: list[NetworkConnection] = field(default_factory=list)
    exfiltration_events: list[ExfiltrationEvent] = field(default_factory=list)
    dropper_events: list[DropperEvent]   = field(default_factory=list)
    packer_events: list[DropperEvent]    = field(default_factory=list)   # [v2.2-3]
    root_detected: bool       = False
    crashed: bool             = False
    crash_timestamp: str      = ""
    restart_attempts: int     = 0
    startup_dialogs_handled: int = 0   # [v2.2-2]
    inotifywait_available: bool = False
    mitm_active: bool         = False
    ssl_bypass_active: bool   = False
    errors: list[str]         = field(default_factory=list)
    warnings: list[str]       = field(default_factory=list)
    suggested_commands: list[str] = field(default_factory=list)  # [v2.9-3]


# ─────────────────────────────────────────────────────────────
# PERMISSION SIGNATURE MAP
# Maps logcat keywords → the permission they implicate
# Used to tag log events and compute abuse scores in Phase 4
# ─────────────────────────────────────────────────────────────

PERMISSION_SIGNATURES: dict[str, list[str]] = {
    "android.permission.INTERNET":               ["Socket", "connect(", "HttpURLConnection", "OkHttp", "DNS", "SSLSocket", "TcpSocket"],
    "android.permission.SEND_SMS":               ["SmsManager.sendText", "SmsManager.sendMultipart", "sendSms"],
    "android.permission.READ_SMS":               ["content://sms", "Telephony.Sms", "readSms", "getSmsMessages"],
    "android.permission.RECEIVE_SMS":            ["SMS_RECEIVED", "SmsMessage", "receiveSms"],
    "android.permission.READ_CONTACTS":          ["content://contacts", "ContactsContract", "readContacts"],
    "android.permission.RECORD_AUDIO":           ["AudioRecord", "MediaRecorder", "startRecording", "RECORD_AUDIO"],
    "android.permission.CAMERA":                 ["Camera", "CameraManager", "takePicture", "startPreview", "CameraDevice"],
    "android.permission.ACCESS_FINE_LOCATION":   ["LocationManager", "GPS_PROVIDER", "requestLocationUpdates", "getLastKnownLocation", "FusedLocationProvider"],
    "android.permission.READ_CALL_LOG":          ["content://call_log", "CallLog", "readCallLog"],
    "android.permission.PROCESS_OUTGOING_CALLS": ["NEW_OUTGOING_CALL", "outgoingCall"],
    "android.permission.READ_PHONE_STATE":       ["TelephonyManager", "getDeviceId", "getImei", "getSubscriberId", "getSimSerialNumber"],
    "android.permission.READ_EXTERNAL_STORAGE":  ["Environment.getExternalStorage", "EXTERNAL_CONTENT_URI", "readExternal"],
    "android.permission.WRITE_EXTERNAL_STORAGE": ["Environment.getExternalStorage", "createNewFile", "FileOutputStream", "writeExternal"],
    "android.permission.GET_ACCOUNTS":           ["AccountManager", "getAccounts", "getAccountsByType"],
    "android.permission.RECEIVE_BOOT_COMPLETED": ["BOOT_COMPLETED", "onReceive.*BOOT", "startService.*boot"],
}

# Sensitivity weights for abuse scoring (Phase 4 input)
SENSITIVITY_WEIGHTS: dict[str, int] = {
    "android.permission.SEND_SMS":               10,
    "android.permission.READ_SMS":               10,
    "android.permission.RECORD_AUDIO":           9,
    "android.permission.CAMERA":                 8,
    "android.permission.ACCESS_FINE_LOCATION":   8,
    "android.permission.READ_CALL_LOG":          7,
    "android.permission.READ_CONTACTS":          7,
    "android.permission.PROCESS_OUTGOING_CALLS": 7,
    "android.permission.READ_PHONE_STATE":       7,
    "android.permission.INTERNET":               6,
    "android.permission.GET_ACCOUNTS":           6,
    "android.permission.READ_EXTERNAL_STORAGE":  5,
    "android.permission.WRITE_EXTERNAL_STORAGE": 5,
    "android.permission.RECEIVE_BOOT_COMPLETED": 4,
}

# Patterns to detect data exfiltration in mitmproxy request bodies
EXFIL_PATTERNS: dict[str, re.Pattern] = {
    "contacts":    re.compile(r'[\w._%+\-]+@[\w.\-]+\.[a-zA-Z]{2,}'),
    "location":    re.compile(r'(?i)(?:lat(?:itude)?|lng|lon(?:gitude)?)["\s:=]+[-\d.]{3,}'),
    "sms":         re.compile(r'(?i)"(?:body|message|sms|text)"\s*:\s*"[^"]{5,}"'),
    "imei":        re.compile(r'\b\d{15,17}\b'),
    "credentials": re.compile(r'(?i)"(?:password|passwd|pin|token|secret)"\s*:\s*"[^"]{3,}"'),
    "file":        re.compile(r'filename=["\']?[\w\-. ]+\.[a-z]{2,5}'),
}

# Private IPs to exclude from network connection tracking
PRIVATE_IP_PREFIXES = (
    "10.", "192.168.", "127.", "0.0.0.0", "::1",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)


# ─────────────────────────────────────────────────────────────
# NETWORK LOG LINE DETECTOR  [v2.10]
# Used by LogcatStreamer to pass-through lines that contain
# actionable network indicators even when the emitting PID is
# not in the tracked set (radio/events buffer lines, dropper
# process lines, system connectivity daemon lines).
#
# Architecture rule: keep this context-anchored — we require at
# least one concrete network prefix before the hostname token so
# that Java package names (com.foo.bar) are never misidentified
# as hostnames.  This mirrors the _NETWORK_CONTEXT_RE rule in
# llm_analysis.py (Phase 4).
# ─────────────────────────────────────────────────────────────

# Tags whose lines are always network-relevant regardless of content.
# Exact-match set — fast O(1) lookup for the common case.
_NET_TAGS = frozenset({
    "OkHttp", "OkHttpClient", "Retrofit", "Volley",
    "HttpURLConnection", "URLConnection",
    "WebSocketClient", "WebSocket",
    "Firebase", "FirebaseDatabase", "FirebaseApp",
    "FirebaseMessaging", "FCM", "FirebaseInstallations",
    "FirebaseMessagingKeepAliveService",   # seen in this malware family
    "GCM", "GoogleFirebase",
    "MinerCommunicator",                   # seen in this malware family
    "chromium",                             # WebView network stack
    "SSLSocket", "SSLContext", "TLS",
    "ConnectivityService", "NetworkMonitor",
    "resolv", "netd", "DnsResolver",       # radio buffer DNS daemon tags
    "WifiStateMachine", "TelephonyManager",
})

# Tag prefixes for compound service names like FirebaseMessagingKeepAliveService.
# Checked only when the exact-match set misses, so it has negligible cost.
_NET_TAG_PREFIXES = ("Firebase", "Gcm", "GCM", "OkHttp", "Retrofit", "Volley")

# Regex for bare URLs or hostnames in log message bodies.
# Context-anchored to prevent false matches on Java package names.
_NET_BODY_RE = re.compile(
    r'(?:'
    r'https?://'                           # explicit URL scheme
    r'|wss?://'                            # WebSocket scheme
    r'|(?:connect(?:ing|ed)?\s+to\s+)'    # "connecting to host"
    r'|(?:failed\s+to\s+connect\s+to\s+)'
    r'|(?:hostname\s*=\s*)'
    r'|(?:url\s*=\s*)'
    r'|(?:host\s*=\s*)'
    r'|(?:firebaseio\.com)'               # Firebase RTDB always relevant
    r'|(?:\.firebaseapp\.com)'
    r'|(?:cloudfunctions\.net)'
    r'|(?:googleapis\.com)'
    r')',
    re.IGNORECASE
)


def _is_network_log_line(raw_line: str) -> bool:
    """
    Return True if raw_line is likely a network-relevant log line that
    should be captured regardless of which PID emitted it.

    Two-step check:
      1. Tag-based: exact match against _NET_TAGS, then prefix match for
         compound service names (e.g. FirebaseMessagingKeepAliveService).
      2. Body-based: does the message body contain a context-anchored
         network indicator (URL, Firebase domain, connection prefix)?

    This function is intentionally liberal — false positives here only
    mean a few extra log lines in logcat.txt; false negatives mean missing
    a C2 URL entirely.
    """
    parts = raw_line.split(None, 7)  # split on whitespace, max 8 fields
    if len(parts) >= 6:
        tag = parts[5].rstrip(":")
        if tag in _NET_TAGS:
            return True
        # Compound service names: FirebaseMessagingKeepAliveService etc.
        if tag.startswith(_NET_TAG_PREFIXES):
            return True
    return bool(_NET_BODY_RE.search(raw_line))


# ─────────────────────────────────────────────────────────────
# FRIDA URL INTERCEPTOR SCRIPT  [v2.10]
# Hooks the four URL construction / connection entry points that
# Android HTTP stacks use before TLS is negotiated.  This catches
# C2 and RTDB hostnames even when the app obfuscates them in
# strings and only assembles the final URL at runtime.
#
# Hooks:
#   • java.net.URL.<init>               — raw URL construction
#   • java.net.HttpURLConnection.connect — stdlib HTTP open
#   • okhttp3.Request.Builder.url(String) — OkHttp request builder
#   • com.google.firebase.database.FirebaseDatabase.getInstance(String)
#                                        — explicit RTDB URL override
#
# Each hook sends a "url_intercepted" message with the full URL
# string BEFORE the connection is opened, so we get the plaintext
# hostname even for SSL-pinned connections.
#
# Architecture rules:
#   • All hooks wrapped in try/catch — a missing class never
#     crashes the target process.
#   • Called only when frida_ready is True (same guard as SSL bypass).
#   • The Frida session is stored in frida_session alongside the SSL
#     bypass session (one attach, two scripts loaded on same session).
#   • Never add I/O inside hooks — only send() so the hook path is
#     as fast as possible and does not block the app's network thread.
# ─────────────────────────────────────────────────────────────

FRIDA_URL_INTERCEPTOR_JS = """
Java.perform(function() {

    // ── java.net.URL constructor ───────────────────────────────────
    // Catches all URL objects created anywhere in the app, including
    // dynamically assembled C2 URLs and obfuscated RTDB endpoints.
    try {
        var URL = Java.use('java.net.URL');
        URL.$init.overload('java.lang.String').implementation = function(spec) {
            if (spec && (spec.startsWith('http') || spec.startsWith('ws'))) {
                send({type: 'url_intercepted', hook: 'URL.<init>', url: spec});
            }
            return this.$init(spec);
        };
    } catch(e) {}

    // ── OkHttp3 Request.Builder.url(String) ───────────────────────
    // OkHttp is the dominant HTTP client in Android malware.
    // Hooking the builder catches the URL before the request fires.
    try {
        var RequestBuilder = Java.use('okhttp3.Request$Builder');
        RequestBuilder.url.overload('java.lang.String').implementation =
            function(url) {
                if (url) {
                    send({type: 'url_intercepted', hook: 'OkHttp.Builder.url', url: url});
                }
                return this.url(url);
            };
    } catch(e) {}

    // ── OkHttp3 HttpUrl.parse / get (used internally) ─────────────
    try {
        var HttpUrl = Java.use('okhttp3.HttpUrl');
        HttpUrl.parse.implementation = function(url) {
            if (url) {
                send({type: 'url_intercepted', hook: 'OkHttp.HttpUrl.parse', url: url});
            }
            return this.parse(url);
        };
    } catch(e) {}

    // ── Firebase Realtime Database explicit URL ────────────────────
    // FirebaseDatabase.getInstance(String url) is called when the app
    // overrides the default RTDB URL — common in C2-over-Firebase setups.
    try {
        var FDB = Java.use('com.google.firebase.database.FirebaseDatabase');
        FDB.getInstance.overload('java.lang.String').implementation =
            function(url) {
                send({type: 'url_intercepted', hook: 'FirebaseDatabase.getInstance', url: url});
                return this.getInstance(url);
            };
    } catch(e) {}

    // ── Firebase Realtime Database reference paths ─────────────────
    // getReference(path) reveals the full C2 command node path,
    // e.g. /bots/<id>/commands  — critical for understanding C2 structure.
    try {
        var FDB2 = Java.use('com.google.firebase.database.FirebaseDatabase');
        FDB2.getReference.overload('java.lang.String').implementation =
            function(path) {
                send({type: 'url_intercepted', hook: 'FirebaseDatabase.getReference', url: 'rtdb_path:' + path});
                return this.getReference(path);
            };
    } catch(e) {}

    // ── Retrofit 2 baseUrl ────────────────────────────────────────
    // Retrofit.Builder.baseUrl(String) is called once at client init —
    // gives us the C2 base URL before any request is built.
    try {
        var RetrofitBuilder = Java.use('retrofit2.Retrofit$Builder');
        RetrofitBuilder.baseUrl.overload('java.lang.String').implementation =
            function(url) {
                send({type: 'url_intercepted', hook: 'Retrofit.baseUrl', url: url});
                return this.baseUrl(url);
            };
    } catch(e) {}

});
"""


def _attach_url_interceptor(package_name: str,
                             session: SentrySession) -> Optional[object]:
    """
    [v2.10] Attach FRIDA_URL_INTERCEPTOR_JS to the running target package.

    Intercepted URLs are appended directly to session.network_connections
    with protocol='URL' so they flow into llm_analysis.py's IOC extractor
    as first-class NetworkConnection entries with a populated domain field.

    Returns the live Frida session or None on failure.
    Caller stores it alongside frida_session for clean detach at shutdown.
    """
    def _on_message(message, _data):
        if message.get("type") != "send":
            return
        payload = message.get("payload", {})
        if payload.get("type") != "url_intercepted":
            return

        raw_url  = payload.get("url", "")
        hook     = payload.get("hook", "?")
        if not raw_url:
            return

        # Extract hostname for the domain field
        try:
            # Works for http/https/ws/wss and rtdb_path: prefix
            if raw_url.startswith("rtdb_path:"):
                host = ""         # path only — store full string as domain
                domain = raw_url  # analyst-visible path e.g. rtdb_path:/bots/…
                port   = 0
            else:
                from urllib.parse import urlparse
                parsed = urlparse(raw_url)
                host   = parsed.hostname or ""
                port   = parsed.port or (
                    443 if parsed.scheme in ("https", "wss") else 80
                )
                domain = host
        except Exception:
            host   = ""
            domain = raw_url
            port   = 0

        if host and is_private_ip(host):
            return   # skip loopback/LAN addresses

        conn = NetworkConnection(
            timestamp=ts(),
            remote_ip=host,
            remote_port=port,
            local_port=0,
            protocol="URL",
            domain=domain,
        )

        # Deduplicate by domain:port key so we don't flood the list with
        # repeated calls to the same endpoint.
        key = f"{domain}:{port}"
        existing_keys = {
            f"{c.domain}:{c.remote_port}"
            for c in session.network_connections
        }
        if key not in existing_keys:
            session.network_connections.append(conn)
            ok(f"[FridaURL] {hook} → {raw_url[:120]}")
        else:
            # Still log at debug level so logcat.txt has the full URL
            pass

    try:
        device  = frida.get_device_manager().add_remote_device(
            f"localhost:{Config.FRIDA_PORT}"
        )
        session_obj = device.attach(package_name)
        script  = session_obj.create_script(FRIDA_URL_INTERCEPTOR_JS)
        script.on("message", _on_message)
        script.load()
        ok(f"[FridaURL] URL interceptor attached to {package_name} "
           f"(URL.<init> + OkHttp + Firebase + Retrofit hooked)")
        return session_obj
    except Exception as exc:
        warn(f"[FridaURL] Could not attach URL interceptor to {package_name}: {exc}")
        warn("[FridaURL] Runtime URL interception skipped — logcat + netstat still active")
        return None


# ─────────────────────────────────────────────────────────────
# FRIDA SSL BYPASS SCRIPT
# Embedded here so sentry.py is self-contained.
# Patches: OkHttp3, TrustManager, HttpsURLConnection,
#          WebViewClient, and native SSL_CTX.
# ─────────────────────────────────────────────────────────────

FRIDA_SSL_BYPASS_JS = """
Java.perform(function() {

    // ── OkHttp3 CertificatePinner ──────────────────────────
    try {
        var CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner.check.overload('java.lang.String', 'java.util.List')
            .implementation = function(a, b) { return; };
        CertPinner.check.overload('java.lang.String', 'java.security.cert.Certificate[]')
            .implementation = function(a, b) { return; };
    } catch(e) {}

    // ── TrustManager (X509) ────────────────────────────────
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext       = Java.use('javax.net.ssl.SSLContext');
        var TrustAllCerts = Java.registerClass({
            name: 'com.analysis.TrustAllCerts',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        var sc = SSLContext.getInstance('TLS');
        sc.init(null, [TrustAllCerts.$new()], null);
        var noCheckFactory = sc.getSocketFactory();
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultSSLSocketFactory(noCheckFactory);
        HttpsURLConnection.setDefaultHostnameVerifier(
            Java.use('javax.net.ssl.HttpsURLConnection').getDefaultHostnameVerifier()
        );
    } catch(e) {}

    // ── HostnameVerifier bypass ────────────────────────────
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var AllowAllHostnames = Java.registerClass({
            name: 'com.analysis.AllowAllHostnames',
            implements: [HostnameVerifier],
            methods: { verify: function(hostname, session) { return true; } }
        });
        var HttpsConn = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsConn.setDefaultHostnameVerifier(AllowAllHostnames.$new());
    } catch(e) {}

    // ── WebViewClient SSL error bypass ────────────────────
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(wv, handler, error) {
            handler.proceed();
        };
    } catch(e) {}

    // ── OkHttp3 okhttp3.internal.tls.OkHostnameVerifier ───
    try {
        var OkHostnameVerifier = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
        OkHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession')
            .implementation = function(a, b) { return true; };
    } catch(e) {}

    // ── Conscrypt / Android internal SSL ─────────────────
    try {
        var ConscryptHostnameVerifier = Java.use('com.android.org.conscrypt.OkHostnameVerifier');
        ConscryptHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession')
            .implementation = function(a, b) { return true; };
    } catch(e) {}

});
"""


# ─────────────────────────────────────────────────────────────
# FRIDA DEX EXTRACTOR SCRIPT  [v2.8-3]
# Hooks the three class-loader entry points packers use to load
# DEX at runtime. Each hooked loader writes its DEX bytes to
# /data/local/tmp/ on the device; on_message() in
# _attach_dex_extractor() pulls each file immediately via adb.
#
# Architecture rules:
#  • Never called for droppers — they write APKs to disk; that
#    is handled by DropperHandler._pull_from_path / _pull_from_data_app.
#  • Only invoked when frida_ready is True (same guard as SSL bypass).
#  • Per-package Frida session opened in _attach_dex_extractor();
#    caller stores it in _dex_sessions for clean shutdown.
#  • All hooks wrapped in try/catch — missing class never crashes
#    the packer process or the Frida runtime.
# ─────────────────────────────────────────────────────────────

FRIDA_DEX_EXTRACTOR_JS = r"""
Java.perform(function() {
    var _written = 0;
    var _destDir = DEST_DIR_PLACEHOLDER;

    function _dumpBytes(tag, javaByteArray) {
        try {
            var idx  = ++_written;
            var path = _destDir + '/dex_dump_' + idx + '.dex';
            var f    = Java.use('java.io.File').$new(path);
            var fos  = Java.use('java.io.FileOutputStream').$new(f);
            fos.write(javaByteArray);
            fos.flush();
            fos.close();
            send({type: 'dex_dumped', path: path, tag: tag, index: idx});
        } catch(e) {
            send({type: 'dex_error', tag: tag, msg: '' + e});
        }
    }

    function _readFileBytes(path) {
        // Returns a Java byte[] for the given on-device path, or null.
        try {
            var f = Java.use('java.io.File').$new(path);
            if (!f.exists()) return null;
            var len  = parseInt(f.length());
            var fis  = Java.use('java.io.FileInputStream').$new(f);
            var buf  = Java.array('byte', new Array(len).fill(0));
            fis.read(buf);
            fis.close();
            return buf;
        } catch(e) { return null; }
    }

    // ── DexClassLoader(dexPath, optimizedDir, libPath, parent) ──
    try {
        var DexCL = Java.use('dalvik.system.DexClassLoader');
        DexCL.$init.overload(
            'java.lang.String','java.lang.String',
            'java.lang.String','java.lang.ClassLoader'
        ).implementation = function(dexPath, optDir, libPath, parent) {
            send({type: 'hook_hit', loader: 'DexClassLoader', dexPath: dexPath});
            var bytes = _readFileBytes(dexPath);
            if (bytes) _dumpBytes('DexClassLoader', bytes);
            return this.$init(dexPath, optDir, libPath, parent);
        };
    } catch(e) {}

    // ── InMemoryDexClassLoader(ByteBuffer, ClassLoader) ──────────
    // ByteBuffer.get(byte[]) consumes the buffer position, so we
    // rewind() after reading so the real loader still sees the bytes.
    try {
        var InMemCL = Java.use('dalvik.system.InMemoryDexClassLoader');
        InMemCL.$init.overload(
            'java.nio.ByteBuffer','java.lang.ClassLoader'
        ).implementation = function(dexBuf, parent) {
            send({type: 'hook_hit', loader: 'InMemoryDexClassLoader'});
            try {
                var remaining = dexBuf.remaining();
                var buf = Java.array('byte', new Array(remaining).fill(0));
                dexBuf.get(buf);
                dexBuf.rewind();   // restore position for the real loader
                _dumpBytes('InMemoryDexClassLoader', buf);
            } catch(e) {
                send({type: 'dex_error', tag: 'InMemoryDexClassLoader', msg: '' + e});
            }
            return this.$init(dexBuf, parent);
        };
    } catch(e) {}

    // ── PathClassLoader(dexPath, ClassLoader) ────────────────────
    // Some packers reuse PathClassLoader for on-disk DEX loads.
    try {
        var PathCL = Java.use('dalvik.system.PathClassLoader');
        PathCL.$init.overload(
            'java.lang.String','java.lang.ClassLoader'
        ).implementation = function(dexPath, parent) {
            send({type: 'hook_hit', loader: 'PathClassLoader', dexPath: dexPath});
            var bytes = _readFileBytes(dexPath);
            if (bytes) _dumpBytes('PathClassLoader', bytes);
            return this.$init(dexPath, parent);
        };
    } catch(e) {}
});
"""

# Device directory where DEX dumps are written before adb pull
_DEX_DUMP_DIR = "/data/local/tmp"


def _attach_dex_extractor(package_name: str, pkg_label: str,
                           dropped_dir: Path) -> Optional[object]:
    """
    [v2.8-3] Attach FRIDA_DEX_EXTRACTOR_JS to a running packer package.

    Each dex_dumped message triggers an immediate adb pull of the dumped
    DEX file from _DEX_DUMP_DIR into dropped_dir as
    <pkg_label>_dex_<N>.dex.

    Returns the live Frida session so the caller can keep it alive until
    shutdown. Returns None on any failure — DEX extraction is best-effort
    and must never block packer APK pull or report writing.

    Caller responsibility:
      • Store the returned session in _dex_sessions.
      • Call session.detach() for each entry in _dex_sessions at shutdown.
    """
    script_src = FRIDA_DEX_EXTRACTOR_JS.replace(
        "DEST_DIR_PLACEHOLDER", f"'{_DEX_DUMP_DIR}'"
    )
    dex_counter = [0]   # mutable int captured by closure

    def _on_message(message, _data):
        if message.get("type") != "send":
            return
        payload = message.get("payload", {})
        kind    = payload.get("type", "")

        if kind == "dex_dumped":
            dex_counter[0] += 1
            device_path = payload["path"]
            local_name  = f"{pkg_label}_dex_{dex_counter[0]}.dex"
            local_path  = str(dropped_dir / local_name)
            info(f"[DEX] {payload['tag']} dumped DEX #{payload['index']}: "
                 f"{device_path}")
            pull = adb("pull", device_path, local_path)
            adb("shell", "rm", "-f", device_path)
            if pull.returncode == 0 and Path(local_path).exists():
                sz = Path(local_path).stat().st_size
                ok(f"[DEX] Pulled: {local_name} ({sz:,} bytes)")
            else:
                warn(f"[DEX] adb pull failed for {device_path}")

        elif kind == "hook_hit":
            loader   = payload.get("loader", "?")
            dex_path = payload.get("dexPath", "(in-memory)")
            info(f"[DEX] {loader} hook fired — dexPath: {dex_path}")

        elif kind == "dex_error":
            warn(f"[DEX] Extraction error in {payload.get('tag','?')}: "
                 f"{payload.get('msg','')}")

    try:
        device  = frida.get_device_manager().add_remote_device(
            f"localhost:{Config.FRIDA_PORT}"
        )
        session = device.attach(package_name)
        script  = session.create_script(script_src)
        script.on("message", _on_message)
        script.load()
        ok(f"[DEX] Frida DEX extractor attached to {package_name} "
           f"(DexClassLoader + InMemoryDexClassLoader + PathClassLoader hooked)")
        return session
    except Exception as exc:
        warn(f"[DEX] Could not attach DEX extractor to {package_name}: {exc}")
        warn("[DEX] DEX extraction skipped — APK pull result still valid")
        return None


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def adb(*args) -> subprocess.CompletedProcess:
    cmd = ["adb"]
    if Config.ADB_SERIAL:
        cmd += ["-s", Config.ADB_SERIAL]
    cmd += list(args)
    return subprocess.run(cmd, capture_output=True, text=True)


def ts() -> str:
    """ISO timestamp for log entries."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def sha256_file(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def is_private_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_IP_PREFIXES)


def tag_permission(log_line: str) -> str:
    """Return the most specific permission implicated by a log line."""
    for perm, keywords in PERMISSION_SIGNATURES.items():
        if any(kw in log_line for kw in keywords):
            return perm
    return ""


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
def alert(msg: str) -> None:
    print(f"\n  {Fore.RED}{'!' * 58}")
    print(f"  !! {msg}")
    print(f"  {'!' * 58}{Style.RESET_ALL}\n")


# ─────────────────────────────────────────────────────────────
# LAUNCH HELPERS  [v2.2-1]
# Phase 2 now owns app launch — monitors start before the app,
# so no events are missed from the first millisecond.
# ─────────────────────────────────────────────────────────────

def _resolve_pids(package: str) -> list[int]:
    """
    Find all PIDs for a running package.
    Strategy 1 — pidof <package>
    Strategy 2 — ps -A | grep <package>  (fallback for ROMs missing pidof,
                 also catches isolated child processes :push / :remote).
    """
    result = adb("shell", "pidof", package)
    if result.stdout.strip():
        try:
            return [int(p) for p in result.stdout.strip().split()]
        except ValueError:
            pass

    # Check if pidof is even available
    which = adb("shell", "which", "pidof")
    if not which.stdout.strip():
        # pidof absent — go straight to ps -A
        ps = adb("shell", "ps", "-A")
        pids = []
        for line in ps.stdout.splitlines():
            if package in line:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        pids.append(int(parts[1]))
                    except ValueError:
                        pass
        return pids

    return []


def launch_apk_sentry(p1: dict) -> tuple[Optional[int], list[int]]:
    """
    Launch the APK and resolve its PIDs.
    Called from main() after all threads are started.

    Launcher APKs  : am start -n <package>/<main_activity>
                     → monkey fallback if PID doesn't appear
    Background APKs: five escalating strategies (see below)

    [v2.4-1] Added monkey (strategy 2) and Settings App-Info → Open
    (strategy 5, last resort) to cover APKs that intentionally omit
    android.intent.category.LAUNCHER from their manifest.

    Returns (primary_pid, all_pids).
    """
    package        = p1["package_name"]
    main_activity  = p1.get("main_activity", "")
    all_activities = p1.get("all_activities", [])
    has_launcher   = p1.get("has_launcher", bool(main_activity))

    banner("PHASE 2A // Launching APK", "─")

    def _poll_pids(attempts: int = 6) -> list[int]:
        for i in range(attempts):
            pids = _resolve_pids(package)
            if pids:
                return pids
            info(f"Waiting for process... attempt {i+1}/{attempts}")
            time.sleep(1)
        return []

    def _try_monkey() -> list[int]:
        """
        [v2.4-1] monkey -p <pkg> fires any LAUNCHER-category entry point
        the OS knows about, including hidden ones not listed in the manifest
        LAUNCHER category. More aggressive than am start alone.
        """
        info("[Monkey] monkey -p {package} -c android.intent.category.LAUNCHER 1")
        adb("shell", "monkey", "-p", package,
            "-c", "android.intent.category.LAUNCHER", "1")
        return _poll_pids(attempts=4)

    def _try_settings_open() -> list[int]:
        """
        [v2.4-1] Last-resort launch via Settings App-Info → Open button.
        Automates the manual flow: Settings → Apps → [target] → Open.
        Works for APKs with no LAUNCHER intent that only start this way.
        """
        info("[Settings] Opening App-Info page for package")
        adb("shell", "am", "start", "-a",
            "android.settings.APPLICATION_DETAILS_SETTINGS",
            "-d", f"package:{package}")
        time.sleep(2.5)

        # Dump the settings UI and look for the Open / Launch button
        tmp_device = "/sdcard/_sentry_settings_tmp.xml"
        tmp_local  = "/tmp/_sentry_settings_tmp.xml"
        adb("shell", "uiautomator", "dump", tmp_device)
        pull = adb("pull", tmp_device, tmp_local)
        adb("shell", "rm", "-f", tmp_device)

        if pull.returncode != 0:
            warn("[Settings] Could not pull settings XML")
            return []

        try:
            import xml.etree.ElementTree as ET
            settings_xml = Path(tmp_local).read_text(
                encoding="utf-8", errors="replace")
            root = ET.fromstring(settings_xml)
            for node in root.iter("node"):
                label = (node.attrib.get("text", "") + " " +
                         node.attrib.get("content-desc", "")).lower()
                if ("open" in label or "launch" in label) and \
                        node.attrib.get("clickable") == "true":
                    nums = re.findall(r'\d+', node.attrib.get("bounds", ""))
                    if len(nums) == 4:
                        cx = (int(nums[0]) + int(nums[2])) // 2
                        cy = (int(nums[1]) + int(nums[3])) // 2
                        info(f"[Settings] Tapping Open button at ({cx}, {cy})")
                        adb("shell", "input", "tap", str(cx), str(cy))
                        time.sleep(3.0)
                        pids = _poll_pids(attempts=5)
                        if pids:
                            ok(f"[Settings] App launched via Settings Open: {pids}")
                        else:
                            warn("[Settings] Tapped Open but no PID appeared")
                        return pids
        except Exception as e:
            warn(f"[Settings] XML parse error: {e}")

        warn("[Settings] Could not find Open button on App-Info page")
        return []

    # ── Launcher APKs ─────────────────────────────────────────
    if has_launcher and main_activity:
        component = f"{package}/{main_activity}"
        info(f"Strategy 1: am start -n {component}")
        r = adb("shell", "am", "start", "-n", component)
        if "Error" not in r.stdout and r.returncode == 0:
            ok("am start accepted")
        else:
            warn(f"am start returned: {r.stdout.strip()}")
        pids = _poll_pids()

        # [v2.4-1] Monkey fallback if am start produced no PID
        if not pids:
            info("Strategy 2 (fallback): monkey — am start produced no PID")
            pids = _try_monkey()

    # ── Background / launcher-less APKs ──────────────────────
    else:
        info("No LAUNCHER activity — trying escalating background strategies")
        pids = []

        # Strategy 1: BOOT_COMPLETED broadcast
        info("Strategy 1: BOOT_COMPLETED broadcast")
        adb("shell", "am", "broadcast", "-a",
            "android.intent.action.BOOT_COMPLETED", "-p", package)
        pids = _poll_pids(attempts=4)

        # Strategy 2: [v2.4-1] monkey — often triggers hidden entry points
        if not pids:
            info("Strategy 2: monkey")
            pids = _try_monkey()

        # Strategy 3: am start-foreground-service
        if not pids:
            info("Strategy 3: am start-foreground-service")
            adb("shell", "am", "start-foreground-service", "-n",
                f"{package}/{package}.MainService")
            pids = _poll_pids(attempts=4)

        # Strategy 4: try all declared activities
        if not pids:
            info("Strategy 4: am start on all declared activities")
            for act in all_activities:
                if act.startswith(package):
                    adb("shell", "am", "start", "-n", f"{package}/{act}")
                    pids = _poll_pids(attempts=4)
                    if pids:
                        break

        # Strategy 5: [v2.4-1] Settings App-Info → Open (last resort)
        if not pids:
            warn("Strategy 5 (last resort): Settings App-Info → Open")
            pids = _try_settings_open()

    if pids:
        ok(f"Primary PID : {pids[0]}")
        if len(pids) > 1:
            warn(f"Multiple PIDs: {pids} — all monitored")
        return pids[0], pids
    else:
        warn("All launch strategies exhausted. App may be:")
        warn("  • Waiting for a trigger the tool can't reproduce")
        warn("  • Performing root detection and self-terminating")
        warn("  • Requiring manual interaction before it will start")
        warn("Monitoring will continue. Use --wait if you can open it manually.")
        return None, []


# ─────────────────────────────────────────────────────────────
# STARTUP DIALOG HANDLER  [v2.2-2]
# After launch, many malicious APKs immediately show:
#   - VPN permission requests
#   - Accessibility service requests
#   - Overlay / draw-over-apps permission
#   - Fake "update available" screens with a single button
#   - Android permission dialogs (location, contacts, camera…)
# This handler polls for 30s and auto-dismisses all of them.
# ─────────────────────────────────────────────────────────────

# Packages that host permission grant dialogs
_PERM_DIALOG_PKGS = {
    "com.android.permissioncontroller",
    "com.android.packageinstaller",
    "com.google.android.permissioncontroller",
}

# Button text that means "accept / proceed"
_ACCEPT_KEYWORDS = [
    "allow", "accept", "ok", "yes", "permit", "grant", "enable",
    "proceed", "continue", "next", "update", "install", "agree",
    "authorise", "authorize", "got it",
]

# Button text that means "dismiss / deny" for overlays we want to skip
_DISMISS_OVERLAY_KEYWORDS = [
    "not now", "skip", "later", "cancel", "no thanks", "deny",
]


def _parse_xml_for_dialog(xml_str: str) -> Optional[tuple[int, int]]:
    """
    Parse uiautomator XML and return (cx, cy) of the best accept button.
    Returns None if no accept button found.
    """
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    candidates = []
    for node in root.iter("node"):
        text = (node.attrib.get("text", "") +
                " " + node.attrib.get("content-desc", "")).lower()
        clickable = node.attrib.get("clickable", "false") == "true"
        if not clickable:
            continue
        for kw in _ACCEPT_KEYWORDS:
            if kw in text:
                bounds = node.attrib.get("bounds", "")
                nums = re.findall(r'\d+', bounds)
                if len(nums) == 4:
                    cx = (int(nums[0]) + int(nums[2])) // 2
                    cy = (int(nums[1]) + int(nums[3])) // 2
                    candidates.append((cx, cy, text))
                break
    if candidates:
        return candidates[0][0], candidates[0][1]
    return None


def _is_permission_or_overlay(xml_str: str, package_name: str) -> bool:
    """Return True if the current screen needs auto-accept."""
    # System permission dialog packages
    for pkg in _PERM_DIALOG_PKGS:
        if pkg in xml_str:
            return True
    # VPN / Accessibility / Overlay dialogs (shown as system dialogs)
    system_markers = [
        "VpnDialogActivity", "GrantPermissionsActivity",
        "AccessibilityService", "com.android.settings",
        "overlay", "draw over other apps",
    ]
    xml_lower = xml_str.lower()
    if any(m.lower() in xml_lower for m in system_markers):
        return True
    # Fake update screen: the app's own package showing a single-button screen
    if package_name in xml_str:
        accept_hits = sum(1 for kw in _ACCEPT_KEYWORDS if kw in xml_lower)
        deny_hits   = sum(1 for kw in _DISMISS_OVERLAY_KEYWORDS if kw in xml_lower)
        # Looks like an update/proceed screen if only accept words present
        if accept_hits >= 1 and deny_hits == 0:
            return True
    return False


def _take_dialog_screenshot(
    screenshots_dir: "Path",
    screenshot_tier: int,
    label: str,
) -> bool:
    """
    [v2.6] Capture a screencap of a pre-launch dialog and save it to
    screenshots_dir.  Called BEFORE tapping accept so the dialog is
    still visible in the image.

    Tier 1 — FLAG_SECURE disabled via Magisk: screencap works natively.
    Tier 2 — Frida hook active: screencap also works (hook patched flags).
    Tier 3 — No bypass: screencap would return a blank frame; skip it.

    Unlike the explorer's take_screenshot() this function is self-contained
    (no Frida session reference needed) because FLAG_SECURE is typically not
    active on system dialogs such as the Google Play update prompt or the
    install-unknown-apps permission screen — those are rendered by system
    processes that do not set FLAG_SECURE.  Even on Tier 3 devices we still
    attempt the capture for system-dialog screens and fall back gracefully.

    Returns True if the screenshot was saved, False otherwise.
    """
    import hashlib as _hl
    device_path = "/sdcard/_sentry_dialog.png"
    local_path  = str(screenshots_dir / f"{label}.png")

    r = adb("shell", "screencap", "-p", device_path)
    if r.returncode != 0:
        warn(f"[DialogScreenshot] screencap failed: {r.stderr.strip()}")
        return False

    pull = adb("pull", device_path, local_path)
    adb("shell", "rm", "-f", device_path)

    if pull.returncode == 0 and Path(local_path).exists():
        ok(f"[DialogScreenshot] Saved → {local_path}")
        return True

    warn(f"[DialogScreenshot] Pull failed: {pull.stderr.strip()}")
    return False


def handle_startup_dialogs(
    package_name: str,
    window: float = 30.0,
    screenshots_dir: Optional["Path"] = None,
    screenshot_tier: int = 3,
) -> int:
    """
    Poll the UI for permission/VPN/overlay/update dialogs for `window` seconds
    after app launch and auto-accept them.

    [v2.6] screenshots_dir / screenshot_tier: when provided, a screencap is
    taken of every new dialog screen BEFORE the accept tap is sent, so the
    full dialog is visible in the saved image.  Screenshots are written to
    screenshots_dir as dialog_NNN_<hash>.png.  Screencaps are attempted on
    all tiers because system dialogs (Google Play, packageinstaller,
    permissioncontroller) are rendered by system processes that do not set
    FLAG_SECURE regardless of the target APK's flags.

    Returns count of dialogs handled.
    """
    import hashlib
    banner("PHASE 2B // Startup Dialog Handling", "─")
    info(f"Watching for startup dialogs for {window:.0f}s ...")
    if screenshots_dir is not None:
        info(f"Dialog screenshots → {screenshots_dir}/")

    handled   = 0
    deadline  = time.time() + window
    last_hash = ""

    while time.time() < deadline:
        # Dump current UI
        r = adb("shell", "uiautomator", "dump", "/sdcard/_sentry_startup.xml")
        pull = adb("pull", "/sdcard/_sentry_startup.xml",
                   "/tmp/_sentry_startup.xml")
        adb("shell", "rm", "-f", "/sdcard/_sentry_startup.xml")

        if pull.returncode != 0:
            time.sleep(1.0)
            continue

        try:
            xml_str = Path("/tmp/_sentry_startup.xml").read_text(
                encoding="utf-8", errors="replace")
        except Exception:
            time.sleep(1.0)
            continue

        # Avoid re-handling the exact same screen
        cur_hash = hashlib.md5(xml_str.encode()).hexdigest()[:8]
        if cur_hash == last_hash:
            time.sleep(1.0)
            continue
        last_hash = cur_hash

        if not _is_permission_or_overlay(xml_str, package_name):
            time.sleep(1.5)
            continue

        # [v2.6] New dialog screen detected — screenshot BEFORE tapping.
        # We always attempt the capture regardless of tier because system
        # dialog packages do not set FLAG_SECURE.  Tier-3 fallback is
        # graceful (warn + continue) so a failed screencap never blocks the
        # accept tap.
        if screenshots_dir is not None:
            _take_dialog_screenshot(
                screenshots_dir=screenshots_dir,
                screenshot_tier=screenshot_tier,
                label=f"dialog_{handled + 1:03d}_{cur_hash}",
            )

        # Found a dialog — try to tap the accept button
        coords = _parse_xml_for_dialog(xml_str)
        if coords:
            cx, cy = coords
            info(f"[StartupDialog] Tapping accept at ({cx}, {cy})")
            adb("shell", "input", "tap", str(cx), str(cy))
            handled += 1
            ok(f"[StartupDialog] Dialog #{handled} accepted")
            time.sleep(1.5)
        else:
            # Fallback: tap bottom-right quadrant (where Allow usually sits)
            sz = adb("shell", "wm", "size")
            m  = re.search(r'(\d+)x(\d+)', sz.stdout)
            if m:
                w, h = int(m.group(1)), int(m.group(2))
                adb("shell", "input", "tap",
                    str(int(w * 0.75)), str(int(h * 0.85)))
                handled += 1
                ok(f"[StartupDialog] Dialog #{handled} accepted (fallback tap)")
                time.sleep(1.5)

    if handled:
        ok(f"Startup dialogs handled: {handled}")
    else:
        info("No startup dialogs detected")
    return handled


# ─────────────────────────────────────────────────────────────
# SESSION STARTUP
# ─────────────────────────────────────────────────────────────

def load_phase1_report(report_path: str) -> dict:
    """
    Load static_report.json from Phase 1.
    [v2.3-2] Only 'package_name' is truly required. 'pid'/'all_pids' are
    always null in v3.3+ reports (Phase 2 owns launch) — no longer validated.
    'summary' degrades gracefully to an empty dict if absent.
    """
    path = Path(report_path)
    if not path.exists():
        err(f"Phase 1 report not found: {report_path}")
        err("Run static_analysis.py first, OR use: sentry.py --apk <package_name>")
        sys.exit(1)

    data = json.loads(path.read_text())

    # Only package_name is truly required
    if not data.get("package_name"):
        err("Phase 1 report has no package_name. Cannot continue.")
        err("Use: sentry.py --apk <package_name>  to bypass Phase 1 entirely.")
        sys.exit(1)

    # Ensure summary key always exists
    if "summary" not in data:
        data["summary"] = {}
        warn("Phase 1 report has no 'summary' block — using defaults.")

    summary = data["summary"]

    ok(f"Phase 1 report loaded  : {report_path}")
    ok(f"Package                : {data['package_name']}")
    ok(f"Screenshot tier        : {summary.get('screenshot_tier', 'unknown')}")
    ok(f"Frida ready            : {summary.get('frida_ready', 'unknown')}")
    ok(f"Shamiko active         : {summary.get('shamiko_active', 'unknown')}")

    if data.get("warnings"):
        for w in data["warnings"]:
            warn(f"[Phase 1 warning] {w}")

    return data


def _build_synthetic_p1(package_name: str) -> dict:
    """
    [v2.3-1] Build a minimal p1 dict from just a package name.
    Used when sentry is invoked with --apk <package_name> and no
    static_report.json is available (encrypted APK, manual install, etc.).

    Probes the connected device to fill in as many fields as possible
    (frida readiness, screenshot tier) so the monitoring session is
    as complete as it would be after a real Phase 1 run.
    """
    banner("STARTUP // Building Synthetic Phase 1 Context", "─")
    warn(f"No static report — running in direct-APK mode for: {package_name}")

    # Check if frida-server is running on the device
    frida_check = adb("shell", "su", "-c",
                      f"ls {os.getenv('FRIDA_SERVER_PATH', '/data/local/tmp/frida-server')} 2>/dev/null")
    frida_ready = frida_check.returncode == 0 and frida_check.stdout.strip() != ""

    # Check if FLAG_SECURE is disabled (Magisk module)
    flag_secure_disabled = False
    magisk_modules = adb("shell", "su", "-c", "ls /data/adb/modules/ 2>/dev/null")
    modules_out = magisk_modules.stdout.lower()
    if any(m in modules_out for m in ("noflagsecure", "no_flag_secure",
                                       "flagsecure", "no-flagsecure")):
        flag_secure_disabled = True

    screenshot_tier = 1 if flag_secure_disabled else (2 if frida_ready else 3)

    # Try to infer main_activity from dumpsys if app is already running
    main_activity = ""
    dumpsys = adb("shell", "dumpsys", "package", package_name)
    for line in dumpsys.stdout.splitlines():
        line = line.strip()
        if "android.intent.action.MAIN" in line:
            # Next line usually has the activity component
            pass
        if line.startswith("android.intent.category.LAUNCHER"):
            pass
    # Simpler: check pm dump
    pm_dump = adb("shell", "pm", "dump", package_name)
    for line in pm_dump.stdout.splitlines():
        if "android.intent.action.MAIN" in line and "/" in line:
            parts = line.strip().split()
            for p in parts:
                if "/" in p and package_name in p:
                    main_activity = p.split("/")[-1]
                    if not main_activity.startswith("."):
                        # fully qualified
                        pass
                    break

    synthetic = {
        "package_name":    package_name,
        "main_activity":   main_activity,
        "all_activities":  [],
        "has_launcher":    bool(main_activity),
        "pid":             None,
        "all_pids":        [],
        "permissions":     [],
        "indicators":      {"ipv4": [], "ipv6": [], "url": [], "api_key": []},
        "manifest_security": {},
        "certificate":     {},
        "code_patterns":   [],
        "warnings":        ["Synthetic p1 context — static analysis was not run."],
        "errors":          [],
        "summary": {
            "screenshot_tier":      screenshot_tier,
            "frida_ready":          frida_ready,
            "flag_secure_disabled": flag_secure_disabled,
            "shamiko_active":       False,
            "has_launcher":         bool(main_activity),
            "dangerous_permissions": [],
            "permission_risk_score": 0,
            "top_risk_permissions":  [],
            "total_indicators":      0,
            "manifest_issues":       {},
            "certificate":           {},
            "code_patterns":         {"total_hits": 0},
            "env":                   os.getenv("ENV", "dev"),
        },
    }

    ok(f"Package name    : {package_name}")
    ok(f"Main activity   : {main_activity or '(unknown — will probe at launch)'}")
    ok(f"Screenshot tier : {screenshot_tier}")
    ok(f"Frida ready     : {frida_ready}")
    info("Static analysis fields will be empty. Dynamic monitoring fully active.")
    return synthetic


def verify_mitmproxy_cert() -> bool:
    """
    Verify mitmproxy CA cert is installed in Android system store.
    Supports both MagiskTrustUserCerts and ConscryptTrustUserCerts module
    layouts. Without this, HTTPS traffic interception silently fails.
    """
    # Primary check: grep system cert store for mitmproxy issuer string
    grep = adb("shell", "su", "-c",
               "grep -rl 'mitmproxy' /system/etc/security/cacerts/ 2>/dev/null")
    if grep.stdout.strip():
        ok("mitmproxy CA cert      : FOUND in system store")
        return True

    # MagiskTrustUserCerts: copies user certs to
    #   /data/misc/user/0/cacerts-added/
    magisk_check = adb("shell", "su", "-c",
                       "ls /data/misc/user/0/cacerts-added/ 2>/dev/null")
    if magisk_check.stdout.strip():
        ok("mitmproxy CA cert      : Found via MagiskTrustUserCerts")
        return True

    # ConscryptTrustUserCerts: symlinks user certs into the Conscrypt
    # trust store at /apex/com.android.conscrypt/cacerts/
    # Check both the apex path and the alternate /data/apex mirror.
    for conscrypt_path in (
        "/apex/com.android.conscrypt/cacerts/",
        "/data/apex/active/com.android.conscrypt/cacerts/",
    ):
        conscrypt_grep = adb("shell", "su", "-c",
                             f"grep -rl 'mitmproxy' {conscrypt_path} 2>/dev/null")
        if conscrypt_grep.stdout.strip():
            ok(f"mitmproxy CA cert      : Found via ConscryptTrustUserCerts ({conscrypt_path})")
            return True

    # Last resort: check if any user cert file exists at all
    # (handles cases where the cert issuer string wasn't 'mitmproxy')
    user_cert_check = adb("shell", "su", "-c",
                          "ls /data/misc/user/0/cacerts-added/ 2>/dev/null")
    if user_cert_check.stdout.strip():
        ok("mitmproxy CA cert      : User cert found (assuming mitmproxy — verify manually)")
        return True

    warn("mitmproxy CA cert      : NOT FOUND in system store")
    warn("HTTPS traffic interception will be partial.")
    warn("Re-install cert via MagiskTrustUserCerts or ConscryptTrustUserCerts module")
    return False


def check_inotifywait() -> bool:
    """Check if inotifywait static binary is on device."""
    result = adb("shell", "su", "-c", f"ls {Config.INOTIFY_PATH}")
    if result.returncode == 0 and "No such file" not in result.stderr:
        ok(f"inotifywait            : Found at {Config.INOTIFY_PATH}")
        return True
    warn(f"inotifywait            : NOT FOUND at {Config.INOTIFY_PATH}")
    warn(f"Falling back to polling ({Config.POLL_INTERVAL}s interval)")
    return False


def attach_frida_ssl_bypass(package_name: str) -> Optional[object]:
    """
    Attach Frida to running app and load SSL pinning bypass script.
    Frida is already running (started in Phase 1) — we just attach.
    Returns the Frida session so it stays alive during monitoring.
    """
    try:
        device  = frida.get_device_manager().add_remote_device(
            f"localhost:{Config.FRIDA_PORT}"
        )
        session = device.attach(package_name)
        script  = session.create_script(FRIDA_SSL_BYPASS_JS)
        script.load()
        ok(f"Frida SSL bypass       : ACTIVE (OkHttp + TrustManager + WebView patched)")
        return session
    except Exception as e:
        warn(f"Frida SSL bypass failed: {e}")
        warn("SSL-pinned connections will not be intercepted")
        return None


# ─────────────────────────────────────────────────────────────
# THREAD 1 — LOGCAT STREAMER
# Streams logcat filtered to all PIDs from Phase 1.
# Tags each line with implicated permission.
# ─────────────────────────────────────────────────────────────

class LogcatStreamer(threading.Thread):
    """
    Streams logcat for all PIDs in all_pids.
    Android logcat only accepts one --pid filter, so we filter
    by PID in Python when monitoring multiple processes.
    """
    def __init__(self, all_pids: list[int], session: SentrySession,
                 log_file_path: str, stop_event: threading.Event):
        super().__init__(daemon=True, name="LogcatStreamer")
        self.all_pids     = set(str(p) for p in all_pids)
        self.session      = session
        self.log_file     = open(log_file_path, "w", buffering=1)
        self.stop_event   = stop_event
        self.line_count   = 0

    def run(self):
        cmd = ["adb"]
        if Config.ADB_SERIAL:
            cmd += ["-s", Config.ADB_SERIAL]
        cmd += [
            "logcat",
            # [v2.10] All buffers: main+system+crash catch app logs; radio catches
            # DNS resolutions and cellular-stack TCP open events; events catches
            # Android connectivity/network-state change events. Together these are
            # the four buffers Android Studio reads by default. Without radio and
            # events, Firebase RTDB WebSocket handshakes and C2 DNS lookups are
            # silently missing from the capture.
            "-b", "main",
            "-b", "system",
            "-b", "crash",
            "-b", "radio",
            "-b", "events",
            "-v", "threadtime",       # includes timestamp, PID, TID
            # [v2.10] Verbose floor: malware C2 beacons are often logged at D or V.
            # Without this, the adb client applies a default minimum of Info on many
            # ROM builds and those lines are dropped before we ever see them.
            "*:V",
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        try:
            for raw_line in proc.stdout:
                if self.stop_event.is_set():
                    break

                # threadtime format:
                # MM-DD HH:MM:SS.mmm  PID   TID  LEVEL TAG  : MESSAGE
                parts = raw_line.split()
                if len(parts) < 7:
                    continue

                # PID is the 3rd field (index 2)
                line_pid = parts[2].strip()

                # [v2.10] Accept lines from: (a) all tracked PIDs, OR (b) any
                # line that contains a URL/hostname/Firebase keyword regardless of
                # PID.  Rationale: the dropper package runs under a different PID
                # that is not in all_pids at LogcatStreamer start time, and the
                # radio/events buffers emit network lines under system PIDs that are
                # never in our tracked set.  Filtering purely by PID caused us to
                # miss every C2 and RTDB connection log.
                pid_match = line_pid in self.all_pids
                net_match = _is_network_log_line(raw_line)
                if not pid_match and not net_match:
                    continue

                self.log_file.write(raw_line)
                self.line_count += 1

                # Parse into structured LogEvent
                try:
                    timestamp = f"{parts[0]} {parts[1]}"
                    level     = parts[4]
                    tag       = parts[5].rstrip(":")
                    message   = " ".join(parts[7:])
                    perm      = tag_permission(raw_line)

                    evt = LogEvent(
                        timestamp=timestamp,
                        pid=int(line_pid) if line_pid.isdigit() else 0,
                        tag=tag, level=level,
                        message=message,
                        permission_implicated=perm,
                    )
                    self.session.log_events.append(evt)
                except (ValueError, IndexError):
                    pass   # malformed line — skip structured parse, raw line saved

        except Exception as e:
            self.session.errors.append(f"LogcatStreamer error: {e}")
        finally:
            proc.terminate()
            self.log_file.close()


# ─────────────────────────────────────────────────────────────
# THREAD 2 — ROOT DETECTION MONITOR
# Watches if the app self-terminates within ROOT_DETECT_WINDOW
# seconds. If it does, flags ROOT_DETECTED and recommends AVD.
# ─────────────────────────────────────────────────────────────

class RootDetectionMonitor(threading.Thread):
    def __init__(self, package_name: str, primary_pid: int,
                 session: SentrySession, stop_event: threading.Event,
                 on_root_detected: callable):
        super().__init__(daemon=True, name="RootDetectionMonitor")
        self.package_name    = package_name
        self.primary_pid     = primary_pid
        self.session         = session
        self.stop_event      = stop_event
        self.on_root_detected = on_root_detected
        self.launch_time     = time.time()

    def run(self):
        # If no PID was resolved in Phase 1 (e.g. background-only APK that was
        # never launched), skip root detection entirely — there is no process to
        # monitor and an immediate "not alive" result would be a false positive.
        if not self.primary_pid:
            info("[RootDetectionMonitor] No PID — skipping root detection "
                 "(app was not launched by Phase 1)")
            return

        # Only monitor during the root-detection window
        while not self.stop_event.is_set():
            elapsed = time.time() - self.launch_time

            # Check if process is still alive
            result = adb("shell", "pidof", self.package_name)
            still_alive = bool(result.stdout.strip())

            if not still_alive and elapsed < Config.ROOT_DETECT_WINDOW:
                # App died within the window — likely root detection
                self.session.root_detected = True
                alert(
                    f"ROOT DETECTION LIKELY — app terminated after {elapsed:.1f}s "
                    f"(within {Config.ROOT_DETECT_WINDOW}s window)"
                )
                warn("Recommendation: Re-run on Android Studio AVD fallback environment")
                warn("Check: Shamiko active? frida-server renamed? Custom port configured?")
                self.session.warnings.append(
                    f"App self-terminated {elapsed:.1f}s after launch — possible root/Frida detection. "
                    "AVD fallback recommended."
                )
                self.on_root_detected()
                return

            if elapsed > Config.ROOT_DETECT_WINDOW:
                # Survived the window — root detection not triggered
                ok(f"Root detection window passed ({Config.ROOT_DETECT_WINDOW}s) — app running normally")
                return

            time.sleep(0.5)


# ─────────────────────────────────────────────────────────────
# THREAD 3 — FILESYSTEM WATCHER
# Watches for new APK files in dropper drop directories.
# Uses inotifywait if available, polling fallback otherwise.
# ─────────────────────────────────────────────────────────────

class FilesystemWatcher(threading.Thread):
    def __init__(self, session: SentrySession, stop_event: threading.Event,
                 dropper_queue: queue.Queue, inotifywait_available: bool):
        super().__init__(daemon=True, name="FilesystemWatcher")
        self.session               = session
        self.stop_event            = stop_event
        self.dropper_queue         = dropper_queue
        self.inotifywait_available = inotifywait_available
        self.seen_paths: set[str]  = set()
        # Seed seen_paths with existing files to avoid false positives
        self._seed_existing()

    def _seed_existing(self):
        """Record files already present so we don't treat them as drops."""
        for d in Config.WATCH_DIRS:
            result = adb("shell", "su", "-c", f"find {d} -name '*.apk' 2>/dev/null")
            for line in result.stdout.strip().splitlines():
                if line.strip():
                    self.seen_paths.add(line.strip())

    def run(self):
        if self.inotifywait_available:
            self._run_inotifywait()
        else:
            self._run_polling()

    def _run_inotifywait(self):
        """Real-time file creation events via inotifywait."""
        dirs  = " ".join(Config.WATCH_DIRS)
        cmd   = ["adb"]
        if Config.ADB_SERIAL:
            cmd += ["-s", Config.ADB_SERIAL]
        cmd  += ["shell", "su", "-c",
                 f"{Config.INOTIFY_PATH} -m -r -e create,moved_to "
                 f"--format '%w%f' {dirs} 2>/dev/null"]

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        try:
            for line in proc.stdout:
                if self.stop_event.is_set():
                    break
                path = line.strip()
                if path.endswith(".apk") and path not in self.seen_paths:
                    self.seen_paths.add(path)
                    info(f"[FilesystemWatcher] New APK detected: {path}")
                    self.dropper_queue.put(("inotifywait", path))
        except Exception as e:
            self.session.errors.append(f"inotifywait watcher error: {e}")
        finally:
            proc.terminate()

    def _run_polling(self):
        """Poll watch directories every POLL_INTERVAL seconds."""
        while not self.stop_event.is_set():
            for d in Config.WATCH_DIRS:
                result = adb("shell", "su", "-c",
                             f"find {d} -name '*.apk' 2>/dev/null")
                for line in result.stdout.strip().splitlines():
                    path = line.strip()
                    if path and path not in self.seen_paths:
                        self.seen_paths.add(path)
                        info(f"[FilesystemWatcher/poll] New APK detected: {path}")
                        self.dropper_queue.put(("polling", path))
            time.sleep(Config.POLL_INTERVAL)


# ─────────────────────────────────────────────────────────────
# THREAD 4 — PACKAGEINSTALLER WATCHER
# Second dropper detection channel via logcat PackageInstaller tag.
# Catches installs that happen before inotifywait can fire.
# ─────────────────────────────────────────────────────────────

class PackageInstallerWatcher(threading.Thread):
    # Logcat signatures that indicate a new package is being installed
    TRIGGERS = [
        "PackageInstaller: created session",
        "PackageInstaller: Submitted package",
        "Installer: Copying",
        "PackageManager: Considering upgrading",
        "PackageManager: New package installed",
    ]

    def __init__(self, session: SentrySession, stop_event: threading.Event,
                 dropper_queue: queue.Queue):
        super().__init__(daemon=True, name="PackageInstallerWatcher")
        self.session      = session
        self.stop_event   = stop_event
        self.dropper_queue = dropper_queue
        self.seen_sessions: set[str] = set()

    def run(self):
        cmd = ["adb"]
        if Config.ADB_SERIAL:
            cmd += ["-s", Config.ADB_SERIAL]
        cmd += ["logcat", "-s",
                "PackageInstaller:V",
                "PackageManager:V",
                "Installer:V",
                "-v", "threadtime"]

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        try:
            for line in proc.stdout:
                if self.stop_event.is_set():
                    break

                for trigger in self.TRIGGERS:
                    if trigger in line:
                        # Deduplicate — same session may log multiple trigger lines
                        sig = line[:80]
                        if sig not in self.seen_sessions:
                            self.seen_sessions.add(sig)
                            info(f"[PkgInstallWatcher] {line.strip()}")
                            # Signal dropper handler — path resolved by pm path later
                            self.dropper_queue.put(("packageinstaller", ""))
        except Exception as e:
            self.session.errors.append(f"PackageInstaller watcher error: {e}")
        finally:
            proc.terminate()


# ─────────────────────────────────────────────────────────────
# THREAD 5 — NETSTAT POLLER
# Polls `adb shell ss -tupn` every NETSTAT_INTERVAL seconds.
# Extracts new foreign connections, excludes private IPs.
#
# [v2.10] Switched from `netstat -an` to `ss -tupn`:
#   • `netstat` on Android truncates long IPv6 addresses and long
#     IPv4 octets at column boundaries — the last group is silently
#     cut off, producing addresses like "125.21.240." and
#     "2404:6800:4002:831:".  `ss` outputs the full address with no
#     column width limit.
#   • `ss -tupn` also emits the process name alongside each socket,
#     giving us an extra confirmation that the connection belongs to
#     the target package even before PID matching.
#
# [v2.10] Reverse DNS:
#   Each new IP is looked up via `adb shell nslookup <ip>` (synchronous,
#   best-effort, 2s timeout).  The resolved hostname is written to the
#   NetworkConnection.domain field so Phase 4 IOC extraction can classify
#   Firebase RTDB URLs, CDN endpoints, and C2 domains by name rather
#   than by raw IP.
# ─────────────────────────────────────────────────────────────

class NetstatPoller(threading.Thread):
    def __init__(self, session: SentrySession, stop_event: threading.Event):
        super().__init__(daemon=True, name="NetstatPoller")
        self.session    = session
        self.stop_event = stop_event
        self.seen_keys: set[str] = set()
        # Seed with baseline connections at startup
        self._seed_baseline()

    def _seed_baseline(self):
        # [v2.10] Use ss; fall back to netstat if ss is absent on the ROM
        for line in self._run_ss().splitlines():
            conn = self._parse_ss_line(line)
            if conn:
                self.seen_keys.add(conn.key())

    def _run_ss(self) -> str:
        """
        Run `ss -tupn` on device.  Returns stdout string.
        Falls back to `netstat -an` if ss is not available
        (some old ROMs ship without iproute2).
        """
        result = adb("shell", "ss", "-tupn")
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
        # Fallback
        result = adb("shell", "netstat", "-an")
        return result.stdout

    # ------------------------------------------------------------------
    # `ss -tupn` output format (Linux iproute2):
    #
    # Netid  State   Recv-Q Send-Q  Local Address:Port  Peer Address:Port
    # tcp    ESTAB   0      0       192.168.1.5:54321   64.89.163.3:443
    # tcp    ESTAB   0      0       [::]:60001          [2404:6800::1]:443
    # udp    UNCONN  0      0       0.0.0.0:5353        0.0.0.0:*
    #
    # IPv6 addresses are enclosed in brackets: [2404:6800:4002:831::1]:443
    # The full address is always on one untruncated line.
    # ------------------------------------------------------------------

    _SS_ESTAB_STATES = {"ESTAB", "ESTABLISHED", "SYN-SENT", "SYN_SENT",
                        "CLOSE-WAIT", "CLOSE_WAIT"}

    def _parse_ss_line(self, line: str) -> Optional[NetworkConnection]:
        """Parse a single `ss -tupn` line into a NetworkConnection."""
        parts = line.split()
        # Minimum: Netid State Recv-Q Send-Q Local Peer
        if len(parts) < 6:
            return None

        netid = parts[0].upper()
        if netid not in ("TCP", "UDP", "TCP6", "UDP6", "TCP", "UDP"):
            return None
        proto = "TCP" if "TCP" in netid else "UDP"

        state = parts[1].upper()
        # For UDP ss may show UNCONN — we still want to see it if it has a
        # real peer address (sendto-style connectionless sockets).
        if proto == "TCP" and state not in self._SS_ESTAB_STATES:
            return None

        peer_field = parts[5]   # "Peer Address:Port" column

        # Skip wildcard peers (listening sockets)
        if peer_field in ("*:*", "0.0.0.0:*", "[::]:*"):
            return None

        remote_ip, remote_port = self._split_addr_port(peer_field)
        if remote_ip is None:
            return None

        if is_private_ip(remote_ip):
            return None

        local_field = parts[4]
        local_ip, local_port = self._split_addr_port(local_field)
        if local_port is None:
            local_port = 0

        return NetworkConnection(
            timestamp=ts(),
            remote_ip=remote_ip,
            remote_port=remote_port,
            local_port=local_port,
            protocol=proto,
        )

    @staticmethod
    def _split_addr_port(field: str) -> tuple[Optional[str], Optional[int]]:
        """
        Split an address:port field that may be:
          • IPv4:  64.89.163.3:443
          • IPv6 bracketed: [2404:6800:4002:831::1]:443
          • bare IPv6 (old netstat fallback): 2404:6800:4002:831::1.443
        Returns (ip_string, port_int) or (None, None) on parse failure.
        """
        if not field or field in ("*", "*:*"):
            return None, None

        # Bracketed IPv6: [addr]:port
        if field.startswith("["):
            bracket_end = field.rfind("]")
            if bracket_end == -1:
                return None, None
            ip = field[1:bracket_end]
            rest = field[bracket_end + 1:]  # ":443" or ""
            if rest.startswith(":"):
                try:
                    port = int(rest[1:])
                except ValueError:
                    return None, None
            else:
                return None, None
            return ip, port

        # IPv4 or plain host: last colon separates port
        last_colon = field.rfind(":")
        if last_colon == -1:
            # No colon at all — unrecognised format
            return None, None

        ip = field[:last_colon]
        # Strip IPv6-mapped IPv4 prefix ::ffff:
        ip = ip.replace("::ffff:", "").replace("::FFFF:", "")

        try:
            port = int(field[last_colon + 1:])
        except ValueError:
            return None, None

        if not ip:
            return None, None

        return ip, port

    def _resolve_domain(self, ip: str) -> str:
        """
        [v2.10] Best-effort reverse DNS lookup via `adb shell nslookup`.
        Returns the resolved hostname or "" on any failure.
        Synchronous — called only when a genuinely new IP is first seen,
        so the one-off latency (~0.5–2s per lookup) does not slow the poll loop.
        """
        try:
            result = subprocess.run(
                (["adb", "-s", Config.ADB_SERIAL] if Config.ADB_SERIAL
                 else ["adb"]) + ["shell", "nslookup", ip],
                capture_output=True, text=True, timeout=2.0
            )
            # nslookup output on Android:
            # Server:  ...
            # Address: ...
            # Name:    some.hostname.com
            # Address: <ip>
            for out_line in result.stdout.splitlines():
                stripped = out_line.strip()
                if stripped.lower().startswith("name:"):
                    hostname = stripped.split(":", 1)[-1].strip()
                    if hostname:
                        return hostname
        except Exception:
            pass
        return ""

    def run(self):
        while not self.stop_event.is_set():
            for line in self._run_ss().splitlines():
                conn = self._parse_ss_line(line)
                if conn and conn.key() not in self.seen_keys:
                    self.seen_keys.add(conn.key())
                    # [v2.10] Resolve hostname so Phase 4 gets a domain name
                    # not just a bare IP.  This is the single highest-value
                    # enrichment for C2/RTDB identification.
                    conn.domain = self._resolve_domain(conn.remote_ip)
                    self.session.network_connections.append(conn)
                    domain_str = f" ({conn.domain})" if conn.domain else ""
                    info(f"[NetstatPoller] New connection: "
                         f"{conn.remote_ip}:{conn.remote_port}"
                         f"{domain_str} ({conn.protocol})")
            time.sleep(Config.NETSTAT_INTERVAL)


# ─────────────────────────────────────────────────────────────
# THREAD 6 — MITMPROXY RUNNER
# Runs mitmproxy inline using its Python API.
# The ExfiltrationAddon intercepts all HTTP/HTTPS requests
# and scans body content for exfiltration patterns.
# ─────────────────────────────────────────────────────────────

class ExfiltrationAddon:
    """mitmproxy addon that detects data exfiltration patterns in request bodies."""

    def __init__(self, session: SentrySession):
        self.session = session

    def request(self, flow: http.HTTPFlow) -> None:
        try:
            body = flow.request.get_text(strict=False) or ""
            host = flow.request.pretty_host
            url  = flow.request.pretty_url
            method = flow.request.method

            # Skip our own proxy traffic
            if "mitmproxy" in host.lower():
                return

            # Scan body for exfiltration patterns
            for data_type, pattern in EXFIL_PATTERNS.items():
                if pattern.search(body):
                    evt = ExfiltrationEvent(
                        timestamp=ts(),
                        url=url,
                        method=method,
                        data_type=data_type,
                        destination_host=host,
                        payload_snippet=body[:300],
                        ssl_pinning_bypassed=flow.request.scheme == "https",
                        permission_implicated=self._map_to_permission(data_type),
                    )
                    self.session.exfiltration_events.append(evt)
                    alert(
                        f"EXFILTRATION DETECTED: {data_type.upper()} → {host} "
                        f"[{method} {url[:60]}]"
                    )

        except Exception:
            pass   # never crash the proxy on a malformed request

    @staticmethod
    def _map_to_permission(data_type: str) -> str:
        mapping = {
            "contacts":    "android.permission.READ_CONTACTS",
            "location":    "android.permission.ACCESS_FINE_LOCATION",
            "sms":         "android.permission.READ_SMS",
            "imei":        "android.permission.READ_PHONE_STATE",
            "credentials": "",
            "file":        "android.permission.READ_EXTERNAL_STORAGE",
        }
        return mapping.get(data_type, "")


class MitmproxyRunner(threading.Thread):
    """Runs mitmproxy in a background thread using its async Python API."""

    def __init__(self, session: SentrySession, stop_event: threading.Event):
        super().__init__(daemon=True, name="MitmproxyRunner")
        self.session    = session
        self.stop_event = stop_event
        self.master     = None

    def run(self):
        async def _run():
            opts = options.Options(
                listen_host="127.0.0.1",
                listen_port=Config.MITM_PORT,
                ssl_insecure=True,
            )
            self.master = mitm_dump.DumpMaster(opts, with_termlog=False, with_dumper=False)
            self.master.addons.add(ExfiltrationAddon(self.session))
            try:
                await self.master.run()
            except Exception:
                pass

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_run())
        except Exception as e:
            self.session.errors.append(f"mitmproxy error: {e}")
        finally:
            loop.close()

    def stop(self):
        if self.master:
            self.master.shutdown()


# ─────────────────────────────────────────────────────────────
# DROPPER HANDLER
# Two-step pull strategy:
#   Step 1 — pull from known device path (inotifywait/polling catch)
#   Step 2 — guaranteed /data/app/ backup via pm path
# ─────────────────────────────────────────────────────────────

class DropperHandler:
    def __init__(self, session: SentrySession, dropped_dir: str):
        self.session     = session
        self.dropped_dir = Path(dropped_dir)
        self.dropped_dir.mkdir(parents=True, exist_ok=True)
        self.counter     = 0
        self._lock       = threading.Lock()

    def handle(self, trigger: str, device_path: str) -> Optional[DropperEvent]:
        """
        Pull dropped APK, run Phase 1 child analysis.
        Returns a DropperEvent record.
        """
        with self._lock:
            self.counter += 1
            idx = self.counter

        local_name = f"dropped{idx}.apk"
        local_path = str(self.dropped_dir / local_name)
        pull_method = ""

        alert(f"DROPPER #{idx} DETECTED — trigger: {trigger.upper()}")

        # ── Step 1: Pull from detected path ─────────────────
        if device_path and self._pull_from_path(device_path, local_path):
            pull_method = "sdcard"
            ok(f"Dropper #{idx} pulled from: {device_path}")
        else:
            if device_path:
                warn(f"Pull from {device_path} failed — trying /data/app/ backup")
            else:
                info(f"No device path from {trigger} — going straight to /data/app/ pull")

        # ── Step 2: Guaranteed /data/app/ backup ─────────────
        # Runs REGARDLESS of Step 1 success.
        # Waits for PackageInstaller to finish copying (up to 10s).
        pkg_name = self._wait_for_new_package(ignore_packages={self.session.package_name})
        backup_path = local_path.replace(".apk", "_backup.apk")

        if pkg_name:
            if self._pull_from_data_app(pkg_name, backup_path):
                pull_method = "sdcard+data_app" if pull_method else "data_app"
                ok(f"Dropper #{idx} backup pulled from /data/app/ (pkg: {pkg_name})")

                # If Step 1 failed, promote backup to primary
                if not Path(local_path).exists():
                    Path(backup_path).rename(local_path)
                    backup_path = ""

        if not Path(local_path).exists():
            err(f"Dropper #{idx}: both pull methods failed. APK not recoverable.")
            self.session.warnings.append(
                f"Dropper #{idx} could not be pulled. "
                "It may have been installed from a protected path."
            )
            return None

        # ── Hash and record ──────────────────────────────────
        sha = sha256_file(local_path)
        ok(f"Dropper #{idx} SHA256: {sha}")

        evt = DropperEvent(
            index=idx,
            timestamp=ts(),
            trigger=trigger,
            device_path=device_path,
            local_path=local_path,
            sha256=sha,
            package_name=pkg_name or "",
            pull_method=pull_method,
        )
        self.session.dropper_events.append(evt)

        # ── Spawn child Phase 1 ──────────────────────────────
        self._spawn_child_analysis(local_path, evt)

        return evt

    def _pull_from_path(self, device_path: str, local_path: str) -> bool:
        """Pull APK from a known device path."""
        # Need root for paths under /data/
        if "/data/" in device_path:
            adb("shell", "su", "-c", f"cp {device_path} /sdcard/tmp_pull_sentry.apk")
            result = adb("pull", "/sdcard/tmp_pull_sentry.apk", local_path)
            adb("shell", "rm", "/sdcard/tmp_pull_sentry.apk")
        else:
            result = adb("pull", device_path, local_path)
        return result.returncode == 0 and Path(local_path).exists()

    def _wait_for_new_package(self, ignore_packages: set[str],
                               timeout: float = 10.0) -> Optional[str]:
        """
        Poll pm list packages to detect a newly installed package.
        Returns the package name once it appears, or None on timeout.
        """
        # Get baseline package list
        baseline_result = adb("shell", "pm", "list", "packages")
        baseline = set(
            line.replace("package:", "").strip()
            for line in baseline_result.stdout.splitlines()
            if line.startswith("package:")
        )
        baseline |= ignore_packages

        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(1.0)
            current_result = adb("shell", "pm", "list", "packages")
            current = set(
                line.replace("package:", "").strip()
                for line in current_result.stdout.splitlines()
                if line.startswith("package:")
            )
            new_pkgs = current - baseline
            if new_pkgs:
                return next(iter(new_pkgs))  # return first new package
        return None

    def _pull_from_data_app(self, package_name: str, local_path: str) -> bool:
        """
        Pull base.apk from /data/app/<pkg>-<hash>/base.apk via pm path.
        Requires root. This is the guaranteed backup pull — works even
        after the dropper deletes the original from /sdcard/.
        """
        pm_result = adb("shell", "pm", "path", package_name)
        # Returns: "package:/data/app/com.evil.app-abc123==/base.apk"
        if "package:" not in pm_result.stdout:
            return False

        device_path = pm_result.stdout.strip().replace("package:", "")
        info(f"/data/app/ path resolved: {device_path}")

        # Root copy to sdcard (data/app is not adb-readable directly)
        adb("shell", "su", "-c", f"cp {device_path} /sdcard/tmp_pull_sentry.apk")
        result = adb("pull", "/sdcard/tmp_pull_sentry.apk", local_path)
        adb("shell", "rm", "/sdcard/tmp_pull_sentry.apk")

        return result.returncode == 0 and Path(local_path).exists()

    def _spawn_child_analysis(self, apk_path: str, evt: DropperEvent):
        """Spawn Phase 1 static analysis on the dropped APK as a child process."""
        child_report = apk_path.replace(".apk", "_static_report.json")
        info(f"Spawning child Phase 1 for: {apk_path}")
        subprocess.Popen([
            sys.executable, "static_analysis.py",
            apk_path, "--child",
            "--output", child_report,
        ])
        evt.child_report = child_report
        ok(f"Child analysis launched → {child_report}")


# ─────────────────────────────────────────────────────────────
# CRASH RECOVERY
# Detects app crash via crash buffer, captures state,
# attempts restart from last known condition.
# ─────────────────────────────────────────────────────────────

class CrashRecovery(threading.Thread):
    # Logcat signatures indicating a crash
    CRASH_SIGNATURES = [
        "FATAL EXCEPTION",
        "Process died",
        "art: Unhandled exception",
        "Signal 11 (SIGSEGV)",
        "Signal 6 (SIGABRT)",
        "ANR in",
        "beginning of crash",
    ]

    def __init__(self, package_name: str, main_activity: str,
                 session: SentrySession, stop_event: threading.Event,
                 on_crash: callable):
        super().__init__(daemon=True, name="CrashRecovery")
        self.package_name  = package_name
        self.main_activity = main_activity
        self.session       = session
        self.stop_event    = stop_event
        self.on_crash      = on_crash

    def run(self):
        cmd = ["adb"]
        if Config.ADB_SERIAL:
            cmd += ["-s", Config.ADB_SERIAL]
        cmd += ["logcat", "-b", "crash", "-v", "threadtime"]

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        try:
            for line in proc.stdout:
                if self.stop_event.is_set():
                    break
                if self.package_name in line:
                    for sig in self.CRASH_SIGNATURES:
                        if sig in line:
                            self._handle_crash(line.strip())
                            break
        except Exception as e:
            self.session.errors.append(f"CrashRecovery error: {e}")
        finally:
            proc.terminate()

    def _handle_crash(self, crash_line: str):
        if self.session.crashed:
            return  # already handling a crash

        self.session.crashed         = True
        self.session.crash_timestamp = ts()
        self.session.restart_attempts += 1

        alert(f"APP CRASH DETECTED: {crash_line[:80]}")
        info("Waiting 3s for system to stabilise...")
        time.sleep(3)

        if self.main_activity:
            component = f"{self.package_name}/{self.main_activity}"
            info(f"Attempting restart: {component}")
            result = adb("shell", "am", "start", "-n", component)
            if result.returncode == 0 and "Error" not in result.stdout:
                ok(f"App restarted (attempt {self.session.restart_attempts})")
                self.session.crashed = False  # reset for next potential crash
                self.on_crash(crash_line)
            else:
                err("Restart failed. Stopping monitoring.")
                self.session.errors.append(
                    f"Crash recovery restart failed: {result.stdout.strip()}"
                )
        else:
            warn("No main activity — cannot restart background service APK")

        self.on_crash(crash_line)


# ─────────────────────────────────────────────────────────────
# DROPPER QUEUE CONSUMER
# Reads from the shared dropper queue and dispatches to handler.
# Deduplicates events that fire on both channels simultaneously.
# ─────────────────────────────────────────────────────────────

class DropperQueueConsumer(threading.Thread):
    def __init__(self, dropper_queue: queue.Queue, handler: DropperHandler,
                 stop_event: threading.Event):
        super().__init__(daemon=True, name="DropperQueueConsumer")
        self.q          = dropper_queue
        self.handler    = handler
        self.stop_event = stop_event
        self.seen_paths: set[str] = set()
        self.recent_pkginstall_ts: float = 0.0

    def run(self):
        while not self.stop_event.is_set():
            try:
                trigger, device_path = self.q.get(timeout=1.0)

                # Deduplicate: both channels may fire for the same install
                if device_path and device_path in self.seen_paths:
                    continue
                if device_path:
                    self.seen_paths.add(device_path)

                # Deduplicate packageinstaller events (can fire multiple times)
                if trigger == "packageinstaller":
                    now = time.time()
                    if now - self.recent_pkginstall_ts < 5.0:
                        continue
                    self.recent_pkginstall_ts = now

                self.handler.handle(trigger, device_path)

            except queue.Empty:
                continue
            except Exception as e:
                err(f"DropperQueueConsumer error: {e}")


# ─────────────────────────────────────────────────────────────
# SESSION OUTPUT
# ─────────────────────────────────────────────────────────────

def save_sentry_session(session: SentrySession, output_path: str = "sentry_report.json") -> str:
    """
    Serialise SentrySession to JSON for Phase 3 Explorer.
    Includes summary statistics for quick Phase 4 consumption.
    """
    # Compute permission abuse counts from log events
    perm_hits: dict[str, int] = {}
    for evt in session.log_events:
        if evt.permission_implicated:
            perm_hits[evt.permission_implicated] = \
                perm_hits.get(evt.permission_implicated, 0) + 1

    # Compute abuse scores
    abuse_scores = {
        perm: hits * SENSITIVITY_WEIGHTS.get(perm, 1)
        for perm, hits in perm_hits.items()
    }
    sorted_abuse = sorted(abuse_scores.items(), key=lambda x: x[1], reverse=True)

    data = asdict(session)
    data["summary"] = {
        "total_log_events":       len(session.log_events),
        "total_network_connections": len(session.network_connections),
        "total_exfiltration_events": len(session.exfiltration_events),
        "total_dropper_events":   len(session.dropper_events),
        "total_packer_events":    len(session.packer_events),      # [v2.2-3]
        "startup_dialogs_handled": session.startup_dialogs_handled, # [v2.2-2]
        "root_detected":          session.root_detected,
        "crashed":                session.crashed,
        "restart_attempts":       session.restart_attempts,
        "inotifywait_used":       session.inotifywait_available,
        "mitm_active":            session.mitm_active,
        "ssl_bypass_active":      session.ssl_bypass_active,
        "permission_hit_counts":  perm_hits,
        "abuse_scores":           dict(sorted_abuse),
        "top_abused_permissions": [p for p, _ in sorted_abuse[:5]],
        "unique_remote_ips":      list({c.remote_ip for c in session.network_connections}),
        "exfiltration_types":     list({e.data_type for e in session.exfiltration_events}),
        "dropper_chain": [
            {
                "index":       d.index,
                "local_path":  d.local_path,
                "sha256":      d.sha256,
                "pkg_name":    d.package_name,
                "pull_method": d.pull_method,
                "child_report": d.child_report,
            }
            for d in session.dropper_events
        ],
        "packer_chain": [
            {
                "index":       d.index,
                "local_path":  d.local_path,
                "sha256":      d.sha256,
                "pkg_name":    d.package_name,
                "pull_method": d.pull_method,
                "child_report": d.child_report,
            }
            for d in session.packer_events
        ],
    }

    # [v2.9-3] Write suggested_commands at top level (already in data via asdict,
    # but we overwrite here to guarantee it reflects the final computed list).
    data["suggested_commands"] = session.suggested_commands

    Path(output_path).write_text(json.dumps(data, indent=2))
    return output_path


# ─────────────────────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────

def main():
    # ── Argument parsing ─────────────────────────────────────
    args         = sys.argv[1:]
    report_path  = None
    apk_pkg      = None       # [v2.3-1] --apk <package_name> direct mode
    duration_sec = None
    do_explore   = True       # [v2.8-1] explore is ON by default; use --no-explore to disable

    i = 0
    while i < len(args):
        if args[i] == "--report" and i + 1 < len(args):
            report_path = args[i + 1]; i += 2
        elif args[i] == "--apk" and i + 1 < len(args):
            apk_pkg = args[i + 1]; i += 2
        elif args[i] == "--duration" and i + 1 < len(args):
            duration_sec = float(args[i + 1]); i += 2
        elif args[i] == "--no-explore":
            do_explore = False; i += 1    # [v2.8-1] opt-out flag
        elif args[i] == "--explore":
            do_explore = True; i += 1     # kept for backward-compat, now a no-op
        else:
            i += 1

    print(f"\n{Fore.GREEN}{'═' * 62}")
    print("  APK THREAT ORCHESTRATOR // PHASE 2: SENTRY v2.10")
    print(f"{'═' * 62}{Style.RESET_ALL}")

    # ── Load or synthesise Phase 1 context ───────────────────
    # [v2.3-1] --apk bypasses the static report entirely.
    # Also used automatically when a partial static report exists
    # (encrypted APK path from static_analysis v3.4).
    if apk_pkg:
        banner("STARTUP // Direct-APK Mode (no static report)", "═")
        p1 = _build_synthetic_p1(apk_pkg)
        # No report file exists — session dir will be created fresh
        p1_path = Path(f"sessions/{apk_pkg}_{datetime.now().strftime('%Y%m%d_%H%M%S')}") / "static_report.json"
    else:
        # ── Resolve Phase 1 report path ──────────────────────
        if report_path is None:
            sessions_root = Path("sessions")
            if sessions_root.exists():
                candidates = sorted(
                    [d for d in sessions_root.iterdir()
                     if d.is_dir() and (d / "static_report.json").exists()],
                    key=lambda d: d.stat().st_mtime, reverse=True,
                )
                if candidates:
                    report_path = str(candidates[0] / "static_report.json")
            if report_path is None:
                report_path = "static_report.json"

        banner("STARTUP // Loading Phase 1 Report", "═")
        p1 = load_phase1_report(report_path)
        p1_path = Path(report_path).resolve()

    package_name  = p1["package_name"]
    main_activity = p1.get("main_activity", "")

    # ── Initialise session ───────────────────────────────────
    session = SentrySession(
        package_name=package_name,
        session_start=ts(),
        all_pids=[],          # filled after launch below
    )

    # ── Pre-session checks ───────────────────────────────────
    banner("STARTUP // Pre-Session Checks", "─")
    mitm_cert_ok  = verify_mitmproxy_cert()
    inotify_ok    = check_inotifywait()
    session.inotifywait_available = inotify_ok

    # ── Output directories ───────────────────────────────────
    p1_parent = p1_path.parent
    if (p1_parent.name.startswith(package_name)
            and p1_parent.parent.name == "sessions"
            and p1_parent.exists()):
        session_dir = p1_parent
        ok(f"Reusing Phase 1 session dir : {session_dir}")
    else:
        session_dir = Path(f"sessions/{package_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        ok(f"Creating new session dir    : {session_dir}")
    dropped_dir     = session_dir / "dropped"
    screenshots_dir = session_dir / "screenshots"   # [v2.6] pre-launch dialog screenshots
    log_file        = str(session_dir / "logcat.txt")
    session_dir.mkdir(parents=True, exist_ok=True)
    dropped_dir.mkdir(parents=True, exist_ok=True)
    screenshots_dir.mkdir(parents=True, exist_ok=True)
    ok(f"Session directory      : {session_dir}")
    ok(f"Logcat file            : {log_file}")

    # [v2.6] Resolve screenshot tier now so handle_startup_dialogs can use it.
    # p1["summary"] is populated for both normal and --apk (synthetic) modes.
    _dialog_ss_tier: int = p1["summary"].get("screenshot_tier", 3)

    # ── Shared state ─────────────────────────────────────────
    stop_event    = threading.Event()
    dropper_queue = queue.Queue()

    # ── Root detected callback ───────────────────────────────
    def on_root_detected():
        info("Stopping monitoring — root detection confirmed.")
        stop_event.set()

    def on_crash(crash_line: str):
        info("Crash noted — Explorer will restart from last XML hash")

    # ── Launch all monitor threads FIRST ─────────────────────
    # Monitors start before app launch so no events are missed.
    banner("PHASE 2 // Launching All Monitors", "═")

    dropper_handler  = DropperHandler(session, str(dropped_dir))

    # Placeholder PID list — updated after launch below
    logcat_thread    = LogcatStreamer([], session, log_file, stop_event)
    root_thread      = RootDetectionMonitor(package_name, None,
                                             session, stop_event, on_root_detected)
    fs_thread        = FilesystemWatcher(session, stop_event,
                                          dropper_queue, inotify_ok)
    pkg_thread       = PackageInstallerWatcher(session, stop_event, dropper_queue)
    netstat_thread   = NetstatPoller(session, stop_event)
    mitm_thread      = MitmproxyRunner(session, stop_event)
    dropper_consumer = DropperQueueConsumer(dropper_queue, dropper_handler, stop_event)
    crash_thread     = CrashRecovery(package_name, main_activity,
                                      session, stop_event, on_crash)

    threads = [
        logcat_thread, root_thread, fs_thread, pkg_thread,
        netstat_thread, mitm_thread, dropper_consumer, crash_thread,
    ]

    for t in threads:
        t.start()
        ok(f"Started: {t.name}")

    session.mitm_active = True
    ok(f"\nmitmproxy listening on 127.0.0.1:{Config.MITM_PORT}")

    # ── [v2.2-1] Launch the APK ──────────────────────────────
    primary_pid, all_pids = launch_apk_sentry(p1)
    session.all_pids = all_pids

    # Update logcat streamer with real PIDs (live update of set)
    if all_pids:
        logcat_thread.all_pids = set(str(p) for p in all_pids)
    # Update root monitor with primary PID
    root_thread.primary_pid = primary_pid

    # ── [v2.2-3] Baseline package list for packer detection ──
    _baseline_pkgs_result = adb("shell", "pm", "list", "packages")
    _baseline_pkgs: set[str] = set(
        line.replace("package:", "").strip()
        for line in _baseline_pkgs_result.stdout.splitlines()
        if line.startswith("package:")
    )
    _baseline_pkgs.add(package_name)

    # ── [v2.2-4] Frida SSL bypass ────────────────────────────
    banner("STARTUP // Frida SSL Bypass", "─")
    frida_session = None
    frida_url_session = None   # [v2.10] URL interceptor session
    _dex_sessions: list = []   # [v2.8-3] per-packer DEX extractor sessions
    _frida_ready  = p1["summary"].get("frida_ready", False)
    if _frida_ready:
        frida_session = attach_frida_ssl_bypass(package_name)
        session.ssl_bypass_active = frida_session is not None
        # [v2.10] Attach URL interceptor regardless of SSL bypass success.
        # Even when the SSL bypass fails, the URL hooks fire at the Java
        # layer before TLS is negotiated, so they still capture plaintext
        # hostnames from URL.<init>, OkHttp builder, and Firebase APIs.
        frida_url_session = _attach_url_interceptor(package_name, session)

    # ── [v2.2-2] Handle startup dialogs (30s window) ─────────
    # [v2.4-2] PID-gate: if no process appeared after all launch strategies,
    # skip the dialog window entirely. Running it against the home screen
    # wastes 30s, finds nothing, then explorer starts on the launcher and
    # opens random apps. Only run dialogs if the app is actually running.
    if primary_pid is not None:
        dialogs_handled = handle_startup_dialogs(
            package_name,
            window=30.0,
            screenshots_dir=screenshots_dir,       # [v2.6]
            screenshot_tier=_dialog_ss_tier,       # [v2.6]
        )
        session.startup_dialogs_handled = dialogs_handled
    else:
        warn("[v2.4-2] PID-gate: skipping startup dialog window — no process detected.")
        warn("  The app did not start. Check the launch strategies above.")
        warn("  If the app requires manual interaction, re-run with --wait.")
        session.startup_dialogs_handled = 0

    # ── 10s settle delay before exploration / monitoring ─────
    # [v2.4-2] Reduce settle delay to 3s when PID is None — no traffic to
    # capture and no UI to settle. Full 10s still used when app is running.
    SETTLE_DELAY = 10 if primary_pid is not None else 3
    info(f"All monitors running. {SETTLE_DELAY}s settle delay before "
         f"{'exploration' if do_explore else 'monitoring'} begins ...")
    info(f"Duration: {f'{duration_sec}s' if duration_sec else 'until Ctrl+C'}")

    settle_start = time.time()
    try:
        while not stop_event.is_set() and (time.time() - settle_start) < SETTLE_DELAY:
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop_event.set()

    # ── [v2.2-4] Interleaved Explorer ────────────────────────
    explorer_report_path: Optional[str] = None
    if do_explore and not stop_event.is_set():
        try:
            import importlib.util, importlib
            spec = importlib.util.spec_from_file_location(
                "explorer", Path(__file__).parent / "explorer.py")
            explorer_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(explorer_mod)

            # [v2.3-1] Use p1 dict directly — works in both normal and --apk mode.
            # Do NOT read from p1_path file here; in --apk mode that path is
            # synthetic and the file may not exist on disk.
            screenshot_tier = p1["summary"].get("screenshot_tier", 3)
            frida_ready     = p1["summary"].get("frida_ready", False)
            if screenshot_tier == 2 and not frida_ready:
                screenshot_tier = 3

            # [v2.7] Pull dangerous permissions for stuck-state alert in explorer
            _p1_dangerous_perms: list[str] = p1.get("summary", {}).get(
                "dangerous_permissions", [])

            exp_session = explorer_mod.ExplorerSession(
                package_name=package_name,
                session_start=ts(),
                screenshot_tier=screenshot_tier,
            )
            engine = explorer_mod.ExplorerEngine(
                package_name=package_name,
                main_activity=main_activity,
                screenshot_tier=screenshot_tier,
                session_dir=session_dir,
                session=exp_session,
                p1_dangerous_permissions=_p1_dangerous_perms,
            )
            if screenshot_tier == 2:
                engine.setup_frida()

            banner("PHASE 2E // Interleaved UI Exploration", "─")
            info("Explorer running while monitors stay active...")

            # [v2.9-1] Severed Phase B/C: sentry no longer explores droppers/packers.
            # Dropper/packer detection and logging still runs (session.dropper_events
            # and session.packer_events are populated as before). At shutdown, sentry
            # emits copy-pasteable CLI commands for the analyst to run each payload
            # as a fresh, isolated analysis target.
            #
            # [v2.9-2] Three-pass continuation exploration for the main APK.
            # State is NOT reset between passes — state_mgr.visited, interaction_map,
            # and _filled_fields persist. A single MAIN_APP_TIMEOUT budget ticks down
            # across all three passes. The existing HumanInterventionMonitor stuck-
            # handler fires as the natural inter-pass gate: when _dfs(0) exhausts at
            # the root, pass N+1's _dfs(0) immediately enters stuck mode and opens
            # the human review window (heartbeat loop). Per-pass intervention state
            # (_stuck_entry_hash, _intervention_active, _retry_cancel,
            # _intervention_entry_hash) is reset so the stuck handler can re-fire.
            def _explore_with_stop():
                try:
                    # Patch engine timeout to also respect stop_event
                    original_timed_out = engine._timed_out
                    def _patched_timed_out():
                        return stop_event.is_set() or original_timed_out()
                    engine._timed_out = _patched_timed_out

                    # Single shared budget across all three passes. The deadline is
                    # set once here and never reset — passes 2 and 3 consume from
                    # whatever budget remains after pass 1.
                    engine._phase_deadline = (time.time()
                                              + explorer_mod.Config.MAIN_APP_TIMEOUT)
                    total_budget = explorer_mod.Config.MAIN_APP_TIMEOUT

                    for pass_num in range(1, 4):
                        if stop_event.is_set():
                            break

                        # Calculate remaining budget for the log line
                        remaining = max(0.0, engine._phase_deadline - time.time())
                        info(f"[EXPLORE] Pass {pass_num}/3: main app DFS starting "
                             f"(budget remaining: {remaining:.0f}s / {total_budget}s) "
                             f"— {package_name}")

                        # ── Reset per-pass intervention state ──────────────────
                        # This allows the stuck-handler (= inter-pass review gate)
                        # to fire fresh on each pass. State manager and fill
                        # blacklist are intentionally NOT reset — full persistence.
                        engine._stuck_entry_hash    = None
                        engine._intervention_active = False
                        engine._intervention_entry_hash = None
                        # Fresh retry-cancel event so previous pass's fired state
                        # doesn't immediately wake sleeping retry loops in pass N+1.
                        engine._retry_cancel = threading.Event()

                        # ── Between-pass app health check ───────────────────────
                        # Pass 1 skips this — app is freshly launched.
                        # Passes 2/3: if PID is gone, silent relaunch (no state
                        # clear). If PID alive, stay on current screen — the state
                        # manager will find no untried elements there, enter stuck
                        # mode, and open the review window for the analyst.
                        if pass_num > 1:
                            live_pids = _resolve_pids(package_name)
                            if not live_pids:
                                warn(f"[EXPLORE] Pass {pass_num}/3: app PID gone — "
                                     f"silent relaunch (state preserved)")
                                # Relaunch guard: _relaunch() is a no-op while
                                # _intervention_active is set, which we just cleared,
                                # so this call is safe.
                                engine._relaunch()
                            else:
                                info(f"[EXPLORE] Pass {pass_num}/3: app alive "
                                     f"(PID {live_pids[0]}) — continuing from "
                                     f"current screen")

                        # ── Run the DFS pass ────────────────────────────────────
                        engine.explore()

                        states_this_pass = exp_session.states_visited
                        info(f"[EXPLORE] Pass {pass_num}/3 complete — "
                             f"{states_this_pass} total states visited")

                        if stop_event.is_set():
                            break
                        if engine._phase_timed_out():
                            info(f"[EXPLORE] Shared budget exhausted after pass "
                                 f"{pass_num}/3 — stopping early")
                            break

                    # Clear deadline now that all passes are done
                    engine._phase_deadline = None

                    # [v2.9-1] Log detected droppers/packers for the record.
                    # Exploration of these is deliberately NOT performed here.
                    detected = (
                        [e.package_name for e in session.dropper_events if e.package_name]
                        + [e.package_name for e in session.packer_events if e.package_name]
                    )
                    if detected:
                        info(f"[EXPLORE] Detected {len(detected)} dropper/packer "
                             f"package(s) — NOT explored (see suggested_commands "
                             f"in sentry_report.json and the shutdown summary)")
                    info("[EXPLORE] Main app exploration complete")

                except Exception as e:
                    session.errors.append(f"Explorer error: {e}")
                    import traceback
                    session.errors.append(traceback.format_exc())

            _explore_thread = threading.Thread(
                target=_explore_with_stop, daemon=True, name="ExplorerEngine")
            _explore_thread.start()

            # Main thread waits for duration / Ctrl+C while explorer runs
            start = time.time()
            try:
                while not stop_event.is_set():
                    if duration_sec and (time.time() - start) >= duration_sec:
                        info(f"Duration {duration_sec}s reached — stopping.")
                        stop_event.set()
                    # [v2.2-3] Live packer check every 5s
                    _check_new_packages(session, _baseline_pkgs, dropped_dir,
                                        dropper_handler,
                                        frida_ready=_frida_ready,
                                        _dex_sessions=_dex_sessions)
                    time.sleep(5.0)
            except KeyboardInterrupt:
                info("\nCtrl+C received — shutting down...")
                stop_event.set()

            _explore_thread.join(timeout=10)
            exp_session.session_end = ts()

            explorer_report_path = str(session_dir / "explorer_report.json")
            explorer_mod.save_explorer_session(exp_session, explorer_report_path)
            ok(f"Explorer report saved: {explorer_report_path}")

        except Exception as e:
            err(f"Interleaved explorer failed to load: {e}")
            session.errors.append(f"Explorer load error: {e}")
            do_explore = False  # fall through to normal wait loop

    # ── Normal monitoring loop (no --explore, or explore failed) ─
    if not do_explore:
        try:
            start = time.time()
            while not stop_event.is_set():
                if duration_sec and (time.time() - start) >= duration_sec:
                    info(f"Duration {duration_sec}s reached — stopping.")
                    stop_event.set()
                # [v2.2-3] Live packer check every 5s
                _check_new_packages(session, _baseline_pkgs, dropped_dir,
                                    dropper_handler,
                                    frida_ready=_frida_ready,
                                    _dex_sessions=_dex_sessions)
                time.sleep(5.0)
        except KeyboardInterrupt:
            info("\nCtrl+C received — shutting down monitors...")
            stop_event.set()

    # ── Graceful shutdown ────────────────────────────────────
    banner("SHUTDOWN // Stopping All Monitors", "─")
    mitm_thread.stop()

    for t in threads:
        t.join(timeout=5)
        skip(f"Stopped: {t.name}")

    if frida_session:
        try:
            frida_session.detach()
            skip("Frida session detached")
        except Exception:
            pass

    # [v2.10] Detach URL interceptor session
    if frida_url_session:
        try:
            frida_url_session.detach()
            skip("Frida URL interceptor session detached")
        except Exception:
            pass

    # [v2.8-3] Detach all per-packer DEX extractor sessions
    for _ds in _dex_sessions:
        try:
            _ds.detach()
        except Exception:
            pass
    if _dex_sessions:
        skip(f"DEX extractor sessions detached ({len(_dex_sessions)})")

    session.session_end = ts()

    # ── [v2.9-3] Build suggested_commands for dropper/packer payloads ───────
    # Sentry no longer explores droppers automatically. Instead it emits
    # fully-formed shell commands so the analyst can re-run each payload as
    # a fresh, isolated analysis target.  Commands are written both to the
    # terminal (below) and to sentry_report.json["suggested_commands"].
    session.suggested_commands = []
    all_payload_events = []

    for evt in session.dropper_events:
        if evt.package_name:
            all_payload_events.append(("Dropper", evt))
    for evt in session.packer_events:
        if evt.package_name:
            all_payload_events.append(("Packer", evt))

    for label, evt in all_payload_events:
        if evt.local_path and Path(evt.local_path).exists():
            cmd = (
                f"python3 static_analysis.py --apk {evt.local_path} && "
                f"python3 sentry.py --apk {evt.package_name}"
            )
        else:
            # APK pull failed — static analysis not possible
            cmd = (
                f"# [WARNING: APK not recovered — static analysis skipped]\n"
                f"python3 sentry.py --apk {evt.package_name}"
            )
        session.suggested_commands.append(cmd)

    out_path = save_sentry_session(session, str(session_dir / "sentry_report.json"))

    # ── Final summary ────────────────────────────────────────
    banner("PHASE 2 COMPLETE // Summary", "═")
    ok(f"Package          : {package_name}")
    ok(f"Primary PID      : {primary_pid or 'N/A'}")
    ok(f"All PIDs         : {all_pids or 'N/A'}")
    ok(f"Log events       : {len(session.log_events):,}")
    ok(f"Network conns    : {len(session.network_connections)}")
    ok(f"Exfil events     : {len(session.exfiltration_events)}")
    ok(f"Dropper APKs     : {len(session.dropper_events)}")
    ok(f"Packer payloads  : {len(session.packer_events)}")
    ok(f"Startup dialogs  : {session.startup_dialogs_handled}")
    ok(f"Root detected    : {'YES — AVD fallback recommended' if session.root_detected else 'No'}")
    ok(f"App crashed      : {'Yes ×' + str(session.restart_attempts) if session.crashed else 'No'}")
    ok(f"SSL bypass       : {'Active' if session.ssl_bypass_active else 'Not active'}")
    ok(f"inotifywait used : {'Yes' if inotify_ok else 'No — used polling fallback'}")
    ok(f"Explorer ran     : {'Yes — 3-pass continuation' if do_explore else 'No'}")
    ok(f"Session dir      : {session_dir}")
    ok(f"Report saved     : {out_path}")
    if explorer_report_path:
        ok(f"Explorer report  : {explorer_report_path}")

    if session.root_detected:
        alert("ROOT DETECTION CONFIRMED — Re-run on Android Studio AVD for this sample")

    if session.exfiltration_events:
        alert(f"{len(session.exfiltration_events)} EXFILTRATION EVENT(S) DETECTED — Review sentry_report.json")

    if session.packer_events:
        alert(f"{len(session.packer_events)} PACKER PAYLOAD(S) DETECTED — new packages installed by the APK itself")

    # ── [v2.9-3] Dropper/packer analysis command block ────────────────────
    if all_payload_events:
        print()
        print(f"{Fore.CYAN}{'═' * 62}")
        print(f"  DROPPER/PACKER PAYLOADS DETECTED — NEXT STEPS")
        print(f"  Run each command individually to analyse each payload.")
        print(f"  Each payload is treated as a fresh, isolated APK target.")
        print(f"{'═' * 62}{Style.RESET_ALL}")
        for idx, (label, evt) in enumerate(all_payload_events, 1):
            cmd = session.suggested_commands[idx - 1]
            apk_status = (
                f"APK on disk: {evt.local_path}"
                if evt.local_path and Path(evt.local_path).exists()
                else "APK NOT recovered — static analysis unavailable"
            )
            print(f"\n{Fore.YELLOW}  [{label} {idx}] {evt.package_name}{Style.RESET_ALL}")
            print(f"  {apk_status}")
            print(f"{Fore.WHITE}  {cmd}{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}  Commands also saved to: {out_path} → suggested_commands[]")
        print(f"{'═' * 62}{Style.RESET_ALL}")

    if not do_explore:
        info("→ Run Phase 3: python explorer.py  (or re-run without --no-explore for combined mode)")
    print()


def _check_new_packages(session: SentrySession, baseline: set[str],
                         dropped_dir: Path, handler: "DropperHandler",
                         frida_ready: bool = False,
                         _dex_sessions: Optional[list] = None) -> None:
    """
    [v2.2-3] Packer detection: diff pm list packages against the post-launch
    baseline to find packages installed by the APK itself.

    [v2.8-2] Race-condition fix:
      Previously called handler.handle("packer","") which internally ran
      _wait_for_new_package() only AFTER detection, and used plain adb pull
      which fails on /data/app/ without root.

      Fixed behaviour:
        1. baseline.add(pkg) immediately on first detection so re-entrancy
           from the 5-second poll loop never double-alerts on the same package.
        2. A dedicated 20-second retry loop polls `pm path <pkg>` every 2s —
           PackageInstaller sometimes finishes the /data/app/ write after we
           first see the package in pm list packages.
        3. Pull uses su -c cp → /sdcard/ → adb pull (root-aware, mirrors
           _pull_from_data_app). Plain adb pull on /data/app/ fails without
           this.
        4. DropperEvent is constructed directly so package_name is always
           populated from the first moment the event exists (not backfilled).
        5. Child Phase 1 spawned via handler._spawn_child_analysis() only
           when the APK file is actually on disk.

    [v2.8-3] DEX extraction:
      When frida_ready is True, _attach_dex_extractor() is called for the
      packer package immediately after APK pull (regardless of pull success —
      packers that delete their APK still load DEX into memory).
      Per-package Frida sessions are appended to _dex_sessions so main()
      can detach them cleanly on shutdown.
    """
    result = adb("shell", "pm", "list", "packages")
    current = set(
        line.replace("package:", "").strip()
        for line in result.stdout.splitlines()
        if line.startswith("package:")
    )
    new_pkgs = current - baseline
    for pkg in new_pkgs:
        # Update baseline immediately — prevents double-alert if the 5s poll
        # fires again before this function returns (rare but possible).
        baseline.add(pkg)

        alert(f"PACKER PAYLOAD DETECTED — new package installed: {pkg}")
        info(f"[Packer] Attempting APK pull for: {pkg}")

        evt_index  = len(session.packer_events) + 1
        local_path = str(dropped_dir / f"packer_{evt_index}.apk")
        pulled     = False

        # ── [v2.8-2] 20s retry loop for pm path ─────────────────
        # PackageInstaller finishes the /data/app/ entry asynchronously;
        # polling every 2s covers the typical 2–8s completion window.
        deadline = time.time() + 20.0
        while time.time() < deadline:
            pm_result = adb("shell", "pm", "path", pkg)
            if "package:" in pm_result.stdout:
                device_apk = pm_result.stdout.strip().replace("package:", "").strip()
                info(f"[Packer] pm path resolved: {device_apk}")
                # Root-aware pull — /data/app/ is not adb-readable without su
                cp = adb("shell", "su", "-c",
                         f"cp '{device_apk}' /sdcard/_sentry_packer_tmp.apk")
                pull = adb("pull", "/sdcard/_sentry_packer_tmp.apk", local_path)
                adb("shell", "rm", "-f", "/sdcard/_sentry_packer_tmp.apk")
                if pull.returncode == 0 and Path(local_path).exists():
                    pulled = True
                    ok(f"[Packer] APK pulled: {local_path}")
                    break
                else:
                    warn(f"[Packer] pull failed (cp rc={cp.returncode}, "
                         f"pull rc={pull.returncode}) — retrying")
            else:
                info(f"[Packer] pm path not yet available for {pkg} — "
                     "retrying in 2s")
            time.sleep(2.0)

        if not pulled:
            warn(f"[Packer] Could not pull APK for {pkg} after 20s. "
                 "Package may have self-deleted post-install.")
            session.warnings.append(
                f"Packer payload {pkg}: APK pull failed after 20s retry."
            )

        sha = sha256_file(local_path) if Path(local_path).exists() else ""
        if sha:
            ok(f"[Packer] SHA256: {sha}")

        evt = DropperEvent(
            index=evt_index,
            timestamp=ts(),
            trigger="packer",
            device_path="",
            local_path=local_path if pulled else "",
            sha256=sha,
            package_name=pkg,           # always set — never backfilled
            pull_method="data_app" if pulled else "",
        )
        session.packer_events.append(evt)

        # Spawn child Phase 1 only when we have the APK on disk
        if pulled:
            handler._spawn_child_analysis(local_path, evt)

        # ── [v2.8-3] Frida DEX extraction ───────────────────────
        # Run even when APK pull failed — packers that self-delete still
        # load DEX into memory and the hooks capture those bytes.
        if frida_ready:
            pkg_label = pkg.replace(".", "_")
            dex_sess  = _attach_dex_extractor(pkg, pkg_label, dropped_dir)
            if dex_sess is not None and _dex_sessions is not None:
                _dex_sessions.append(dex_sess)


if __name__ == "__main__":
    main()