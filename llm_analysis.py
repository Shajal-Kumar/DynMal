"""
llm_analysis.py — Phase 4: LLM Abuse Score Analysis
APK Threat Orchestrator (DynMalTool) v1.0

Reads static_report.json (optional), sentry_report.json, explorer_report.json
from a session directory. Extracts URLs and network IOCs from logcat.txt and
sentry network events. Builds a structured Ollama prompt and outputs
phase4_report.json.

Usage:
    python llm_analysis.py sessions/<session_dir>
    python llm_analysis.py sessions/<session_dir> --dry-run   # extract only, skip LLM

Entry point for app.py integration:
    from llm_analysis import run_phase4
    result = run_phase4(Path("sessions/PNBONE_20260407_143022"))
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from colorama import Fore, Style, init as colorama_init
from dotenv import load_dotenv

load_dotenv()
colorama_init(autoreset=True)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

class Config:
    OLLAMA_HOST: str        = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    OLLAMA_MODEL_DEV: str   = os.getenv("OLLAMA_MODEL_DEV", "phi3.5-mini")
    OLLAMA_MODEL_PROD: str  = os.getenv("OLLAMA_MODEL_PROD", "llama3.3:70b")
    ENV: str                = os.getenv("ENV", "dev")
    OLLAMA_TIMEOUT: int     = int(os.getenv("OLLAMA_TIMEOUT", "180"))
    OLLAMA_MAX_TOKENS: int  = int(os.getenv("OLLAMA_MAX_TOKENS", "2048"))

    @classmethod
    def model(cls) -> str:
        return cls.OLLAMA_MODEL_DEV if cls.ENV == "dev" else cls.OLLAMA_MODEL_PROD


# ---------------------------------------------------------------------------
# Terminal helpers (mirrors other phase files)
# ---------------------------------------------------------------------------

def info(msg: str) -> None:
    print(f"{Fore.CYAN}[P4]{Style.RESET_ALL} {msg}")

def ok(msg: str) -> None:
    print(f"{Fore.GREEN}[P4] ✓{Style.RESET_ALL} {msg}")

def warn(msg: str) -> None:
    print(f"{Fore.YELLOW}[P4] ⚠{Style.RESET_ALL} {msg}")

def alert(msg: str) -> None:
    print(f"{Fore.RED}[P4] ✗{Style.RESET_ALL} {msg}")

def banner(title: str) -> None:
    line = "─" * 60
    print(f"\n{Fore.MAGENTA}{line}")
    print(f"  {title}")
    print(f"{line}{Style.RESET_ALL}\n")


# ---------------------------------------------------------------------------
# URL / hostname extraction
# ---------------------------------------------------------------------------

# Matches hostnames preceded by explicit network-context markers.
# Intentionally strict: we only want endpoints the app actually contacted,
# not Java package names or filesystem paths that happen to contain dots.
_NETWORK_CONTEXT_RE = re.compile(
    r"(?:"
    r"https?://"                          # full URL
    r"|Failed to connect to "             # Java connection error
    r"|connecting to "                    # generic connect log
    r"|connect to "
    r"|host(?:name)?[=: ]+\"?"
    r"|api[-_.]"                          # api.example.com shorthand
    r")"
    r"("
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+)"
    r"(?:/[^\s\"'<>]*)?",
    re.IGNORECASE,
)

# Full https?:// URLs for separate capture
_URL_RE = re.compile(
    r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+",
    re.IGNORECASE,
)

# Suspicious TLDs that are common in malware C2 infrastructure
_SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "xyz", "top", "club", "online", "site", "icu", "fun", "pw",
    "tk", "ml", "ga", "cf", "gq", "ru", "cn", "su", "cc",
})

_KNOWN_BENIGN_DOMAINS: frozenset[str] = frozenset({
    "google.com", "googleapis.com", "gstatic.com", "android.com",
    "firebase.io", "firebaseio.com", "crashlytics.com",
    "facebook.com", "instagram.com", "whatsapp.com",
    "microsoft.com", "apple.com", "icloud.com",
    "amazon.com", "amazonaws.com",
    "telegram.org", "t.me",
})

def _is_known_benign(domain: str) -> bool:
    d = domain.lower()
    return any(d == b or d.endswith("." + b) for b in _KNOWN_BENIGN_DOMAINS)

def _tld_of(domain: str) -> str:
    parts = domain.rsplit(".", 1)
    return parts[-1].lower() if len(parts) > 1 else ""

def _classify_domain(domain: str) -> str:
    """Return 'benign' | 'suspicious' | 'unknown'."""
    if _is_known_benign(domain):
        return "benign"
    if _tld_of(domain) in _SUSPICIOUS_TLDS:
        return "suspicious"
    return "unknown"

def extract_urls_from_text(text: str) -> tuple[list[str], list[str]]:
    """
    Returns (full_urls, hostnames) extracted from arbitrary text.
    Both lists are deduplicated and sorted.
    """
    full_urls: set[str] = set()
    hostnames: set[str] = set()

    for m in _URL_RE.finditer(text):
        full_urls.add(m.group(0).rstrip(".,;)>\"'"))

    for m in _NETWORK_CONTEXT_RE.finditer(text):
        h = m.group(1).lower().rstrip(".")
        # Skip if it looks like a Java/Android package path component
        if h.startswith("java.") or h.startswith("android.") or h.startswith("com.android."):
            continue
        hostnames.add(h)

    return sorted(full_urls), sorted(hostnames)


@dataclass
class NetworkIOC:
    """A single network indicator of compromise."""
    value: str                  # hostname or IP
    ioc_type: str               # "hostname" | "ip" | "url"
    classification: str         # "benign" | "suspicious" | "unknown"
    ports: list[int]            = field(default_factory=list)
    sources: list[str]          = field(default_factory=list)   # "logcat" | "sentry_log" | "sentry_network"


def _extract_network_iocs(
    sentry: dict,
    logcat_text: str,
) -> list[NetworkIOC]:
    """
    Deduplicated network IOC list from all sources:
      1. sentry network_connections (IP + port)
      2. sentry log_events messages (hostname extraction)
      3. logcat.txt (hostname + URL extraction)
    """
    ioc_map: dict[str, NetworkIOC] = {}

    def _upsert(value: str, ioc_type: str, source: str, port: Optional[int] = None) -> None:
        key = value.lower()
        if key not in ioc_map:
            ioc_map[key] = NetworkIOC(
                value=value,
                ioc_type=ioc_type,
                classification=_classify_domain(value) if ioc_type in ("hostname", "url") else "unknown",
                ports=[],
                sources=[],
            )
        ioc = ioc_map[key]
        if source not in ioc.sources:
            ioc.sources.append(source)
        if port is not None and port not in ioc.ports:
            ioc.ports.append(port)

    # Source 1 — sentry network_connections
    for nc in sentry.get("network_connections", []):
        ip = nc.get("remote_ip", "").strip()
        port = nc.get("remote_port")
        domain = nc.get("domain", "").strip()
        if ip:
            _upsert(ip, "ip", "sentry_network", port)
        if domain:
            _upsert(domain, "hostname", "sentry_network", port)

    # Source 2 — sentry log_events
    sentry_log_blob = "\n".join(
        e.get("message", "") for e in sentry.get("log_events", [])
    )
    _, sentry_hostnames = extract_urls_from_text(sentry_log_blob)
    sentry_urls, _ = extract_urls_from_text(sentry_log_blob)
    for h in sentry_hostnames:
        _upsert(h, "hostname", "sentry_log")
    for u in sentry_urls:
        _upsert(u, "url", "sentry_log")

    # Source 3 — logcat.txt
    logcat_urls, logcat_hostnames = extract_urls_from_text(logcat_text)
    for h in logcat_hostnames:
        _upsert(h, "hostname", "logcat")
    for u in logcat_urls:
        _upsert(u, "url", "logcat")

    return sorted(ioc_map.values(), key=lambda x: x.value)


# ---------------------------------------------------------------------------
# Report loading — all optional / graceful
# ---------------------------------------------------------------------------

def _load_json_report(path: Path, label: str) -> Optional[dict]:
    if not path.exists():
        warn(f"{label} not found at {path} — skipping")
        return None
    try:
        with open(path) as f:
            data = json.load(f)
        ok(f"Loaded {label} ({path.stat().st_size // 1024} KB)")
        return data
    except (json.JSONDecodeError, OSError) as e:
        warn(f"Failed to read {label}: {e}")
        return None


def _load_logcat(session_dir: Path) -> str:
    logcat_path = session_dir / "logcat.txt"
    if not logcat_path.exists():
        warn("logcat.txt not found — URL extraction from logcat skipped")
        return ""
    try:
        text = logcat_path.read_text(errors="replace")
        ok(f"Loaded logcat.txt ({len(text)} chars)")
        return text
    except OSError as e:
        warn(f"Failed to read logcat.txt: {e}")
        return ""


# ---------------------------------------------------------------------------
# Evidence builder
# ---------------------------------------------------------------------------

@dataclass
class Phase4Evidence:
    """All pre-computed inputs for the LLM prompt. All fields optional."""
    package_name: str                           = ""
    session_dir: str                            = ""

    # Static analysis
    static_available: bool                      = False
    dangerous_permissions: list[str]            = field(default_factory=list)
    permission_risk_score: int                  = 0
    top_risk_permissions: list[str]             = field(default_factory=list)
    total_indicators: int                       = 0
    manifest_issues: list[dict]                 = field(default_factory=list)
    certificate_flags: list[str]                = field(default_factory=list)
    code_patterns: list[dict]                   = field(default_factory=list)
    defence_indicators: list[dict]              = field(default_factory=list)  # severity == "good"
    dex_strings_sample: list[str]               = field(default_factory=list)  # subset of IOC strings

    # Sentry / runtime
    sentry_available: bool                      = False
    abuse_scores: dict[str, int]                = field(default_factory=dict)
    top_abused_permissions: list[str]           = field(default_factory=list)
    exfiltration_events: list[dict]             = field(default_factory=list)
    exfiltration_types: list[str]               = field(default_factory=list)
    unique_remote_ips: list[str]                = field(default_factory=list)
    dropper_chain: list[dict]                   = field(default_factory=list)
    packer_chain: list[dict]                    = field(default_factory=list)
    startup_dialogs_handled: int                = 0
    mitm_active: bool                           = False
    ssl_bypass_active: bool                     = False
    root_detected: bool                         = False
    dex_dumps_present: list[str]                = field(default_factory=list)  # filenames

    # Explorer / UI
    explorer_available: bool                    = False
    permission_dialogs_accepted: int            = 0
    forms_filled: int                           = 0
    form_submits_attempted: int                 = 0
    form_submits_succeeded: int                 = 0
    form_submit_failures: list[dict]            = field(default_factory=list)
    unique_activities: list[str]                = field(default_factory=list)
    states_visited: int                         = 0
    human_interventions: int                    = 0

    # Network IOCs (merged from all sources)
    network_iocs: list[NetworkIOC]              = field(default_factory=list)
    suspicious_iocs: list[NetworkIOC]           = field(default_factory=list)


def _collect_dex_dumps(session_dir: Path, packer_chain: list[dict]) -> list[str]:
    """Find DEX dump files in the dropped/ subdirectory."""
    dropped_dir = session_dir / "dropped"
    if not dropped_dir.exists():
        return []
    return [f.name for f in sorted(dropped_dir.glob("*_dex_*.dex"))]


def build_evidence(
    session_dir: Path,
    static: Optional[dict],
    sentry: Optional[dict],
    explorer: Optional[dict],
    logcat_text: str,
) -> Phase4Evidence:
    ev = Phase4Evidence()
    ev.session_dir = str(session_dir)

    # Package name — sentry is most reliable, fall back to others
    for src in (sentry, explorer, static):
        if src and src.get("package_name"):
            ev.package_name = src["package_name"]
            break

    # --- Static ---
    if static:
        ev.static_available = True
        summary = static.get("summary", {})
        ev.dangerous_permissions    = summary.get("dangerous_permissions", [])
        ev.permission_risk_score    = summary.get("permission_risk_score", 0)
        ev.top_risk_permissions     = summary.get("top_risk_permissions", [])
        ev.total_indicators         = summary.get("total_indicators", 0)
        ev.manifest_issues          = static.get("manifest_issues", [])
        cert = static.get("certificate", {})
        ev.certificate_flags = _extract_cert_flags(cert)
        all_patterns = static.get("code_patterns", [])
        ev.defence_indicators = [p for p in all_patterns if p.get("severity") == "good"]
        ev.code_patterns      = [p for p in all_patterns if p.get("severity") != "good"]
        # Sample of hardcoded indicator strings (IOCs from DEX scan)
        indicators = static.get("indicators", {})
        ev.dex_strings_sample = _sample_ioc_strings(indicators)
    else:
        ev.static_available = False

    # --- Sentry ---
    if sentry:
        ev.sentry_available = True
        summary = sentry.get("summary", {})
        ev.abuse_scores             = summary.get("abuse_scores", {})
        ev.top_abused_permissions   = summary.get("top_abused_permissions", [])
        ev.exfiltration_events      = sentry.get("exfiltration_events", [])
        ev.exfiltration_types       = summary.get("exfiltration_types", [])
        ev.unique_remote_ips        = summary.get("unique_remote_ips", [])
        ev.dropper_chain            = summary.get("dropper_chain", [])
        ev.packer_chain             = summary.get("packer_chain", [])
        ev.startup_dialogs_handled  = sentry.get("startup_dialogs_handled", 0)
        ev.mitm_active              = sentry.get("mitm_active", False)
        ev.ssl_bypass_active        = sentry.get("ssl_bypass_active", False)
        ev.root_detected            = sentry.get("root_detected", False)
        ev.dex_dumps_present        = _collect_dex_dumps(session_dir, ev.packer_chain)
    else:
        ev.sentry_available = False

    # --- Explorer ---
    if explorer:
        ev.explorer_available = True
        summary = explorer.get("summary", {})
        ev.permission_dialogs_accepted  = explorer.get("permission_dialogs_accepted", 0)
        ev.forms_filled                 = explorer.get("forms_filled", 0)
        ev.form_submits_attempted       = summary.get("form_submits_attempted", 0)
        ev.form_submits_succeeded       = summary.get("form_submits_succeeded", 0)
        ev.form_submit_failures         = summary.get("form_submit_failures", [])
        ev.unique_activities            = summary.get("unique_activities", [])
        ev.states_visited               = summary.get("states_visited", 0)
        ev.human_interventions          = summary.get("human_interventions", 0)
    else:
        ev.explorer_available = False

    # --- Network IOCs (merged from all sources) ---
    sentry_data = sentry or {}
    ev.network_iocs = _extract_network_iocs(sentry_data, logcat_text)
    ev.suspicious_iocs = [
        ioc for ioc in ev.network_iocs
        if ioc.classification == "suspicious"
    ]

    return ev


def _extract_cert_flags(cert: dict) -> list[str]:
    """Pull human-readable certificate warning flags from the cert block."""
    flags: list[str] = []
    if not cert:
        return flags
    if cert.get("self_signed"):
        flags.append("self_signed_certificate")
    if cert.get("debug_cert"):
        flags.append("debug_certificate")
    if cert.get("expired"):
        flags.append("expired_certificate")
    subject = cert.get("subject", "")
    if "debug" in subject.lower() or "test" in subject.lower() or "android" in subject.lower():
        flags.append(f"suspicious_subject:{subject}")
    return flags


def _sample_ioc_strings(indicators: dict, max_per_type: int = 8) -> list[str]:
    """Return a capped sample of hardcoded indicator strings for context."""
    samples: list[str] = []
    for category, entries in indicators.items():
        if isinstance(entries, list):
            for entry in entries[:max_per_type]:
                if isinstance(entry, str):
                    samples.append(f"[{category}] {entry}")
                elif isinstance(entry, dict):
                    val = entry.get("value") or entry.get("string") or str(entry)
                    samples.append(f"[{category}] {val}")
    return samples[:40]  # global cap


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

def _fmt_list(items: list, empty: str = "none") -> str:
    if not items:
        return empty
    return "\n".join(f"  - {i}" for i in items)


def _fmt_network_iocs(iocs: list[NetworkIOC]) -> str:
    if not iocs:
        return "  none detected"
    lines: list[str] = []
    for ioc in iocs:
        ports_str = f" ports={ioc.ports}" if ioc.ports else ""
        flag = " *** SUSPICIOUS TLD ***" if ioc.classification == "suspicious" else ""
        lines.append(f"  [{ioc.ioc_type}] {ioc.value}{ports_str} (sources: {', '.join(ioc.sources)}){flag}")
    return "\n".join(lines)


def _fmt_dropper_packer(chain: list[dict], label: str) -> str:
    if not chain:
        return f"  no {label} activity"
    lines: list[str] = []
    for entry in chain:
        pkg = entry.get("pkg_name") or entry.get("package_name") or "unknown_pkg"
        sha = entry.get("sha256", "")[:16] or "no_hash"
        method = entry.get("pull_method", "unknown")
        child = "yes" if entry.get("child_report") else "no"
        lines.append(
            f"  [{entry.get('index', '?')}] pkg={pkg} sha256={sha}... "
            f"method={method} child_analysis={child}"
        )
    return "\n".join(lines)


def _fmt_form_submissions(ev: Phase4Evidence) -> str:
    parts: list[str] = [
        f"  attempted={ev.form_submits_attempted}",
        f"  succeeded={ev.form_submits_succeeded}",
        f"  failed={len(ev.form_submit_failures)}",
    ]
    if ev.form_submit_failures:
        for f in ev.form_submit_failures[:3]:
            btn = f.get("button", "?")
            retries = f.get("retries", 0)
            empty = len(f.get("empty_fields", []))
            errors = [n.get("text","") for n in f.get("error_nodes", [])]
            parts.append(
                f"  failure: button='{btn}' retries={retries} "
                f"empty_fields={empty} errors={errors}"
            )
    return "\n".join(parts)


def build_prompt(ev: Phase4Evidence) -> str:
    """Construct the full LLM system+user prompt pair as a single string."""

    static_note = (
        "NOTE: Static analysis report was unavailable (encrypted/packed APK). "
        "Permissions, code patterns, and certificate data are absent — "
        "do not penalise confidence for missing static data.\n\n"
        if not ev.static_available else ""
    )

    dex_dump_note = ""
    if ev.dex_dumps_present:
        dex_dump_note = (
            f"DEX DUMPS RECOVERED ({len(ev.dex_dumps_present)} file(s) via Frida hook): "
            f"{', '.join(ev.dex_dumps_present)}\n"
            "This confirms in-memory DEX loading — strong packer/loader signal.\n\n"
        )

    dropper_str = _fmt_dropper_packer(ev.dropper_chain, "dropper")
    packer_str  = _fmt_dropper_packer(ev.packer_chain, "packer")

    abuse_str = _fmt_list(
        [f"{perm}: score={score}" for perm, score in ev.abuse_scores.items()]
    )

    code_patterns_str = _fmt_list(
        [f"[{p.get('severity','?')}] {p.get('rule','?')}: {p.get('match','')[:80]}"
         for p in ev.code_patterns[:15]]
    )
    defence_str = _fmt_list(
        [f"{p.get('rule','?')}" for p in ev.defence_indicators]
    )

    cert_str  = _fmt_list(ev.certificate_flags)
    manif_str = _fmt_list(
        [f"[{m.get('severity','?')}] {m.get('issue','?')}: {m.get('detail','')[:80]}"
         for m in ev.manifest_issues[:10]]
    )

    ioc_str = _fmt_network_iocs(ev.network_iocs)
    suspicious_domains = [
        ioc.value for ioc in ev.suspicious_iocs
        if ioc.ioc_type in ("hostname", "url")
    ]

    prompt = f"""You are a senior Android malware analyst. Analyse the following dynamic and static evidence collected from running the APK on a real rooted device, and produce a structured threat assessment.

PACKAGE: {ev.package_name or "unknown"}
SESSION: {ev.session_dir}

{static_note}{dex_dump_note}════════════════════════════════════════════════
STATIC ANALYSIS
════════════════════════════════════════════════
Static report available: {ev.static_available}
Dangerous permissions declared ({len(ev.dangerous_permissions)}):
{_fmt_list(ev.dangerous_permissions)}

Permission risk score: {ev.permission_risk_score}
Top risk permissions: {_fmt_list(ev.top_risk_permissions)}

Certificate flags:
{cert_str}

Manifest security issues:
{manif_str}

Code patterns detected (non-defence):
{code_patterns_str}

Defence/hardening indicators (lower threat signal):
{defence_str}

Hardcoded IOC strings from DEX scan:
{_fmt_list(ev.dex_strings_sample[:20])}

════════════════════════════════════════════════
RUNTIME BEHAVIOUR (SENTRY)
════════════════════════════════════════════════
Sentry report available: {ev.sentry_available}
MITM proxy active: {ev.mitm_active}
SSL bypass detected: {ev.ssl_bypass_active}
Root detected by app: {ev.root_detected}
Startup dialogs handled: {ev.startup_dialogs_handled}

Permission abuse scores (higher = more suspicious):
{abuse_str}
Top abused: {_fmt_list(ev.top_abused_permissions)}

Exfiltration event types: {_fmt_list(ev.exfiltration_types)}
Exfiltration event count: {len(ev.exfiltration_events)}

Dropper activity:
{dropper_str}

Packer/loader activity:
{packer_str}

DEX dumps recovered: {len(ev.dex_dumps_present)} ({', '.join(ev.dex_dumps_present) or 'none'})

════════════════════════════════════════════════
NETWORK IOCs (extracted from sentry + logcat)
════════════════════════════════════════════════
{ioc_str}

Suspicious-TLD domains: {suspicious_domains or 'none'}

════════════════════════════════════════════════
UI EXPLORATION (EXPLORER)
════════════════════════════════════════════════
Explorer report available: {ev.explorer_available}
States visited: {ev.states_visited}
Permission dialogs accepted: {ev.permission_dialogs_accepted}
Forms filled: {ev.forms_filled}
Unique activities reached: {_fmt_list(ev.unique_activities) if ev.unique_activities else 'none recorded'}

Form submission analysis:
{_fmt_form_submissions(ev)}

════════════════════════════════════════════════
YOUR TASK
════════════════════════════════════════════════
Based on ALL evidence above, respond with ONLY a valid JSON object — no preamble, no markdown fences. Use exactly this schema:

{{
  "threat_class": "<one of: BANKER | SPYWARE | RAT | DROPPER | INFOSTEALER | ADWARE | FAKE_APP | CLEAN | UNKNOWN>",
  "confidence": "<one of: HIGH | MEDIUM | LOW>",
  "threat_score": <integer 0-100>,
  "kill_chain_stage": "<one of: DELIVERY | INSTALLATION | EXECUTION | C2 | EXFILTRATION | PERSISTENCE | UNKNOWN>",
  "evidence": [
    "<key evidence point 1>",
    "<key evidence point 2>"
  ],
  "iocs": {{
    "domains": ["<domain1>", ...],
    "ips": ["<ip1>", ...],
    "urls": ["<url1>", ...],
    "permissions": ["<permission1>", ...],
    "code_patterns": ["<pattern1>", ...]
  }},
  "data_collected": ["<type of data the app harvests, e.g. camera_feed, contacts, sms>"],
  "recommended_actions": [
    "<action 1>",
    "<action 2>"
  ],
  "analyst_notes": "<free text: anything unusual, caveats, or gaps in evidence>"
}}"""

    return prompt


# ---------------------------------------------------------------------------
# Ollama client
# ---------------------------------------------------------------------------

class OllamaError(Exception):
    pass


def _check_ollama_alive() -> bool:
    """Ping the Ollama health endpoint. Returns True if reachable."""
    try:
        req = urllib.request.urlopen(
            f"{Config.OLLAMA_HOST}/api/tags",
            timeout=5,
        )
        return req.status == 200
    except Exception:
        return False


def _call_ollama(prompt: str) -> dict:
    """
    POST to Ollama /api/generate (non-streaming).
    Returns the parsed JSON verdict dict.
    Raises OllamaError on any failure.
    """
    payload = json.dumps({
        "model": Config.model(),
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,        # low temp for structured output
            "num_predict": Config.OLLAMA_MAX_TOKENS,
        },
    }).encode()

    req = urllib.request.Request(
        f"{Config.OLLAMA_HOST}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=Config.OLLAMA_TIMEOUT) as resp:
            raw = resp.read().decode()
    except urllib.error.URLError as e:
        raise OllamaError(f"Connection failed: {e}") from e

    try:
        outer = json.loads(raw)
    except json.JSONDecodeError as e:
        raise OllamaError(f"Ollama returned non-JSON: {e}") from e

    response_text: str = outer.get("response", "")

    # Strip markdown fences if the model wrapped its output
    response_text = re.sub(r"^```(?:json)?\s*", "", response_text.strip())
    response_text = re.sub(r"\s*```$", "", response_text.strip())

    try:
        verdict = json.loads(response_text)
    except json.JSONDecodeError as e:
        raise OllamaError(
            f"Model response was not valid JSON: {e}\nRaw response:\n{response_text[:500]}"
        ) from e

    return verdict


# ---------------------------------------------------------------------------
# Report dataclass + serialiser
# ---------------------------------------------------------------------------

@dataclass
class Phase4Report:
    package_name: str
    session_dir: str
    generated_at: str
    model_used: str

    # Source availability
    static_available: bool
    sentry_available: bool
    explorer_available: bool

    # Extracted evidence (always populated)
    network_iocs: list[dict]         # serialised NetworkIOC dicts
    suspicious_iocs: list[dict]
    dex_dumps_present: list[str]
    dropper_chain: list[dict]
    packer_chain: list[dict]
    form_submit_summary: dict

    # LLM output
    llm_status: str                  # "ok" | "ollama_unavailable" | "error" | "dry_run"
    llm_verdict: Optional[dict]
    llm_error: str

    errors: list[str]
    warnings: list[str]


def _save_report(report: Phase4Report, session_dir: Path) -> Path:
    out_path = session_dir / "phase4_report.json"
    data = asdict(report)
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)
    ok(f"Saved phase4_report.json → {out_path}")
    return out_path


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_phase4(session_dir: Path, dry_run: bool = False) -> dict:
    """
    Main Phase 4 entry point.

    Args:
        session_dir: Path to the session directory containing phase report JSONs.
        dry_run:     If True, skip LLM call — extract evidence only.

    Returns:
        The Phase4Report as a plain dict (same structure as phase4_report.json).
    """
    banner("Phase 4 — LLM Abuse Score Analysis")
    session_dir = Path(session_dir)

    if not session_dir.exists():
        alert(f"Session directory not found: {session_dir}")
        raise FileNotFoundError(f"Session directory not found: {session_dir}")

    errors:   list[str] = []
    warnings: list[str] = []

    # Load reports
    info("Loading phase reports…")
    static   = _load_json_report(session_dir / "static_report.json",   "static_report")
    sentry   = _load_json_report(session_dir / "sentry_report.json",   "sentry_report")
    explorer = _load_json_report(session_dir / "explorer_report.json", "explorer_report")
    logcat   = _load_logcat(session_dir)

    if not sentry and not static and not explorer:
        msg = "No phase reports found — nothing to analyse"
        alert(msg)
        errors.append(msg)

    # Build evidence
    info("Building evidence context…")
    ev = build_evidence(session_dir, static, sentry, explorer, logcat)

    # Log IOC summary
    info(f"Network IOCs extracted: {len(ev.network_iocs)} total, "
         f"{len(ev.suspicious_iocs)} with suspicious TLDs")
    for ioc in ev.suspicious_iocs:
        alert(f"  Suspicious IOC: [{ioc.ioc_type}] {ioc.value}  (ports={ioc.ports})")

    if ev.dex_dumps_present:
        alert(f"DEX dumps present: {ev.dex_dumps_present}")

    if ev.dropper_chain:
        alert(f"Dropper chain depth: {len(ev.dropper_chain)}")

    if ev.packer_chain:
        alert(f"Packer chain depth: {len(ev.packer_chain)}")

    # Build prompt
    info("Building LLM prompt…")
    prompt = build_prompt(ev)

    # Form submit summary block for report
    form_submit_summary = {
        "attempted":  ev.form_submits_attempted,
        "succeeded":  ev.form_submits_succeeded,
        "failed":     len(ev.form_submit_failures),
        "failures":   ev.form_submit_failures,
    }

    # Serialise IOCs for report
    iocs_serialised      = [asdict(ioc) for ioc in ev.network_iocs]
    suspicious_serialised = [asdict(ioc) for ioc in ev.suspicious_iocs]

    # LLM call
    llm_status  = "ok"
    llm_verdict = None
    llm_error   = ""

    if dry_run:
        info("Dry-run mode — skipping Ollama call")
        llm_status = "dry_run"
    else:
        info(f"Checking Ollama at {Config.OLLAMA_HOST}…")
        if not _check_ollama_alive():
            llm_status = "ollama_unavailable"
            llm_error  = (
                f"Ollama not reachable at {Config.OLLAMA_HOST}. "
                "Evidence extracted successfully. Re-run when Ollama is available."
            )
            warn(llm_error)
            warnings.append(llm_error)
        else:
            ok(f"Ollama reachable — model: {Config.model()}")
            info("Sending prompt to Ollama (this may take a while)…")
            t0 = time.time()
            try:
                llm_verdict = _call_ollama(prompt)
                elapsed = time.time() - t0
                ok(f"Ollama responded in {elapsed:.1f}s")
                ok(f"Threat class: {llm_verdict.get('threat_class','?')}  "
                   f"Confidence: {llm_verdict.get('confidence','?')}  "
                   f"Score: {llm_verdict.get('threat_score','?')}/100")
            except OllamaError as e:
                llm_status = "error"
                llm_error  = str(e)
                alert(f"Ollama error: {e}")
                errors.append(f"Ollama error: {e}")

    # Assemble and save report
    report = Phase4Report(
        package_name       = ev.package_name,
        session_dir        = str(session_dir),
        generated_at       = datetime.now().isoformat(timespec="seconds"),
        model_used         = Config.model() if llm_status == "ok" else "",
        static_available   = ev.static_available,
        sentry_available   = ev.sentry_available,
        explorer_available = ev.explorer_available,
        network_iocs       = iocs_serialised,
        suspicious_iocs    = suspicious_serialised,
        dex_dumps_present  = ev.dex_dumps_present,
        dropper_chain      = ev.dropper_chain,
        packer_chain       = ev.packer_chain,
        form_submit_summary= form_submit_summary,
        llm_status         = llm_status,
        llm_verdict        = llm_verdict,
        llm_error          = llm_error,
        errors             = errors,
        warnings           = warnings,
    )

    _save_report(report, session_dir)
    banner("Phase 4 complete")
    return asdict(report)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="DynMalTool Phase 4 — LLM Abuse Score Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python llm_analysis.py sessions/PNBONE_20260407_143022
  python llm_analysis.py sessions/PNBONE_20260407_143022 --dry-run
""",
    )
    parser.add_argument(
        "session_dir",
        help="Path to the session directory (e.g. sessions/PNBONE_20260407_143022)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Extract evidence and build prompt but skip the Ollama call",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> None:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    try:
        run_phase4(Path(args.session_dir), dry_run=args.dry_run)
    except FileNotFoundError as e:
        alert(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        warn("Interrupted by user")
        sys.exit(130)


if __name__ == "__main__":
    main()