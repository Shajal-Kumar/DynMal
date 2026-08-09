"""
APK Threat Orchestrator -- Phase 5: Master Report Generator v1.0
=================================================================
Generates a professional analyst-grade Word (.docx) report from all
phase outputs using a three-stage LLM synthesis pipeline.

Stage A  — Per-artifact summarisation (XML screens, log batches)
Stage B  — Domain consolidation (UI flow, network, permissions)
Stage C  — Final synthesis into structured report sections via 70B model

Pipeline handles sessions of any size by never exceeding context window:
  - Each XML file → one short paragraph (Stage A, parallel)
  - Log lines    → batched 60 lines at a time (Stage A)
  - All summaries → domain narratives (Stage B)
  - Domain narratives + all JSON reports → final Word doc (Stage C)

Usage:
    python report.py sessions/PNBONE_20260407_143022/
    python report.py sessions/PNBONE_20260407_143022/ --no-vision
    python report.py sessions/PNBONE_20260407_143022/ --out report.docx

Dependencies:
    pip install python-docx python-dotenv
    Ollama running locally with llama3.3:70b (prod) or phi3.5-mini (dev)
    Optional: llama3.2-vision for screenshot analysis
"""

import os
import re
import sys
import json
import time
import base64
import hashlib
import textwrap
import threading
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from docx import Document
from docx.shared import Inches, Pt, RGBColor, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

load_dotenv()

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────

class Config:
    ENV: str             = os.getenv("ENV", "dev")
    OLLAMA_HOST: str     = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    MODEL_PROD: str      = os.getenv("OLLAMA_MODEL_PROD", "llama3.3:70b")
    MODEL_DEV: str       = os.getenv("OLLAMA_MODEL_DEV", "phi3.5-mini")
    MODEL_VISION: str    = os.getenv("OLLAMA_MODEL_VISION", "llama3.2-vision")
    OLLAMA_TIMEOUT: int  = int(os.getenv("OLLAMA_TIMEOUT", "300"))
    # Stage A: parallel XML summarisers
    XML_WORKERS: int     = int(os.getenv("PHASE5_XML_WORKERS", "4"))
    # Log lines per batch for Stage A
    LOG_BATCH_SIZE: int  = int(os.getenv("PHASE5_LOG_BATCH", "60"))
    # Max XML files to summarise (None = all)
    MAX_XML: Optional[int] = (
        int(os.getenv("PHASE5_MAX_XML")) if os.getenv("PHASE5_MAX_XML") else None
    )

    @classmethod
    def synthesis_model(cls) -> str:
        return cls.MODEL_PROD if cls.ENV == "prod" else cls.MODEL_DEV


# ─────────────────────────────────────────────────────────────
# TERMINAL HELPERS
# ─────────────────────────────────────────────────────────────

try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
    def ok(m):   print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {m}")
    def info(m): print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {m}")
    def warn(m): print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {m}")
    def err(m):  print(f"{Fore.RED}[-]{Style.RESET_ALL} {m}")
    def banner(m):
        print(f"\n{Fore.BLUE}{'═'*60}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}  {m}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}{'═'*60}{Style.RESET_ALL}")
except ImportError:
    def ok(m):   print(f"[+] {m}")
    def info(m): print(f"[*] {m}")
    def warn(m): print(f"[!] {m}")
    def err(m):  print(f"[-] {m}")
    def banner(m):
        print(f"\n{'='*60}\n  {m}\n{'='*60}")


# ─────────────────────────────────────────────────────────────
# OLLAMA CLIENT
# ─────────────────────────────────────────────────────────────

class OllamaError(Exception):
    pass


def _ollama_generate(prompt: str, model: str,
                     images: list[str] | None = None,
                     max_tokens: int = 800) -> str:
    """
    Call Ollama /v1/messages (non-streaming).
    images: list of base64-encoded image strings (for vision models).
    Returns the response text. Raises OllamaError on failure.
    """
    payload: dict = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"num_predict": max_tokens, "temperature": 0.1},
    }
    if images:
        payload["images"] = images

    data = json.dumps(payload).encode()
    req  = urllib.request.Request(
        f"{Config.OLLAMA_HOST}/api/generate",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=Config.OLLAMA_TIMEOUT) as resp:
            outer = json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        raise OllamaError(f"Ollama unreachable: {e}")
    except json.JSONDecodeError as e:
        raise OllamaError(f"Ollama response not JSON: {e}")

    text = outer.get("response", "")
    if not text:
        raise OllamaError(f"Empty response from model {model}")
    return text.strip()


def _check_ollama(model: str) -> bool:
    try:
        req = urllib.request.Request(
            f"{Config.OLLAMA_HOST}/api/tags",
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            tags = json.loads(resp.read().decode())
        names = [m.get("name", "") for m in tags.get("models", [])]
        if not any(model.split(":")[0] in n for n in names):
            warn(f"Model '{model}' not found in Ollama. Run: ollama pull {model}")
            return False
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────
# STAGE A — PER-ARTIFACT SUMMARISATION
# ─────────────────────────────────────────────────────────────

def _summarise_xml_file(xml_path: Path, model: str) -> tuple[str, str]:
    """
    Summarise a single uiautomator XML dump into one short paragraph.
    Returns (filename, summary_text).
    """
    try:
        raw = xml_path.read_text(encoding="utf-8", errors="replace")
        # Extract just the node attributes — strip bounds/index noise
        tree   = ET.fromstring(raw)
        lines  = []
        for node in tree.iter("node"):
            a = node.attrib
            pkg      = a.get("package", "")
            cls      = a.get("class", "").split(".")[-1]
            text     = a.get("text", "").strip()
            desc     = a.get("content-desc", "").strip()
            res_id   = a.get("resource-id", "").split("/")[-1]
            clickable= a.get("clickable") == "true"
            is_input = "EditText" in a.get("class", "")
            if text or desc or (clickable and cls) or is_input:
                label = text or desc or res_id or cls
                role  = "input" if is_input else ("button" if clickable else "label")
                lines.append(f"  [{role}] {label}")
        if not lines:
            return xml_path.name, "(empty or unreadable screen)"

        condensed = "\n".join(lines[:60])  # cap at 60 elements
        prompt = (
            "You are a mobile malware analyst. Below is a condensed UI element list "
            "from an Android screen dump. In 2–3 sentences, describe: what screen this "
            "appears to be (e.g. login, OTP, bank transfer, permission dialog), what "
            "sensitive fields or actions are present, and any deceptive or suspicious UI "
            "patterns. Be concise and factual.\n\n"
            f"UI Elements:\n{condensed}\n\nDescription:"
        )
        summary = _ollama_generate(prompt, model, max_tokens=200)
        return xml_path.name, summary
    except Exception as e:
        return xml_path.name, f"(summarisation failed: {e})"


def summarise_xml_files(xml_dir: Path, model: str,
                        max_files: Optional[int] = None) -> dict[str, str]:
    """
    Parallel Stage A: summarise all XML files in xml_dir.
    Returns {filename: summary}.
    """
    xml_files = sorted(xml_dir.glob("*.xml"))
    # Skip temp/scratch files created by the engine
    xml_files = [f for f in xml_files if not f.stem.startswith(
        ("tmp_", "_safeback", "_intervention", "_pretap", "_posttap",
         "_retry", "_postretry", "_spinner", "resume_")
    )]
    if max_files:
        xml_files = xml_files[:max_files]
    if not xml_files:
        return {}

    info(f"Stage A — summarising {len(xml_files)} XML files with {Config.XML_WORKERS} workers ...")
    summaries: dict[str, str] = {}
    lock = threading.Lock()
    done = [0]

    def _worker(path: Path):
        result = _summarise_xml_file(path, model)
        with lock:
            summaries[result[0]] = result[1]
            done[0] += 1
            if done[0] % 10 == 0 or done[0] == len(xml_files):
                info(f"  XML progress: {done[0]}/{len(xml_files)}")
        return result

    with ThreadPoolExecutor(max_workers=Config.XML_WORKERS) as ex:
        futures = [ex.submit(_worker, f) for f in xml_files]
        for fut in as_completed(futures):
            fut.result()  # surface exceptions

    ok(f"Stage A XML complete — {len(summaries)} screens summarised")
    return summaries


def summarise_logs(logcat_path: Path, model: str,
                   network_iocs: list) -> str:
    """
    Stage A: batch-summarise logcat.txt and return a unified log narrative.
    Also incorporates already-extracted IOCs from Phase 4 to avoid re-processing.
    """
    if not logcat_path.exists():
        if network_iocs:
            return (
                "No raw logcat available. Phase 4 extracted the following network "
                f"IOCs: {', '.join(str(i.get('value','')) for i in network_iocs[:20])}."
            )
        return "No logcat data available."

    lines = logcat_path.read_text(
        encoding="utf-8", errors="replace"
    ).splitlines()
    info(f"Stage A — log batching: {len(lines)} lines in batches of {Config.LOG_BATCH_SIZE}")

    batch_summaries = []
    batches = [
        lines[i: i + Config.LOG_BATCH_SIZE]
        for i in range(0, len(lines), Config.LOG_BATCH_SIZE)
    ]
    for i, batch in enumerate(batches):
        chunk = "\n".join(batch)
        prompt = (
            "You are a mobile malware analyst. Below is a batch of Android logcat output. "
            "Extract ONLY security-relevant events: network connections, IPs/domains contacted, "
            "permissions accessed, suspicious API calls, errors revealing app internals, "
            "data exfiltration indicators. Ignore unrelated noise. "
            "Respond with 2–4 bullet points or 'nothing suspicious' if clean.\n\n"
            f"Logcat batch {i+1}/{len(batches)}:\n{chunk}\n\nFindings:"
        )
        try:
            summary = _ollama_generate(prompt, model, max_tokens=250)
            if "nothing suspicious" not in summary.lower():
                batch_summaries.append(f"Batch {i+1}: {summary}")
        except OllamaError as e:
            warn(f"  Log batch {i+1} failed: {e}")
        if (i + 1) % 5 == 0:
            info(f"  Log progress: {i+1}/{len(batches)} batches")

    if not batch_summaries:
        return "Log analysis found no significant security-relevant events."

    # Consolidate batch summaries into one narrative
    consolidated = "\n\n".join(batch_summaries)
    prompt = (
        "You are a mobile malware analyst. Below are findings from batched logcat analysis. "
        "Consolidate into a single coherent 3–5 sentence paragraph describing the app's "
        "runtime network behaviour, any suspicious API usage, and data exfiltration indicators.\n\n"
        f"Batch findings:\n{consolidated}\n\nConsolidated log narrative:"
    )
    try:
        return _ollama_generate(prompt, model, max_tokens=400)
    except OllamaError:
        return "\n\n".join(batch_summaries[:10])


def summarise_screenshots(screenshots_dir: Path,
                          vision_model: str) -> dict[str, str]:
    """
    Stage A (optional): run vision model on each screenshot.
    Returns {filename: description}.
    """
    if not screenshots_dir.exists():
        return {}
    images = sorted([
        f for f in screenshots_dir.iterdir()
        if f.suffix.lower() in (".png", ".jpg", ".jpeg")
        and not f.stem.startswith("intervention_")
    ])
    if not images:
        return {}

    info(f"Stage A — vision analysis: {len(images)} screenshots")
    descriptions: dict[str, str] = {}

    for i, img_path in enumerate(images):
        try:
            img_b64 = base64.b64encode(img_path.read_bytes()).decode()
            prompt = (
                "You are a mobile malware analyst examining an Android app screenshot. "
                "Describe: (1) what screen/activity this is, (2) any visible text including "
                "bank names, logos, or brand impersonation, (3) sensitive fields visible "
                "(password, OTP, card number, Aadhaar, PIN), (4) any deceptive or "
                "suspicious UI elements. Be concise — 2–4 sentences."
            )
            desc = _ollama_generate(prompt, vision_model,
                                    images=[img_b64], max_tokens=200)
            descriptions[img_path.name] = desc
            if (i + 1) % 5 == 0:
                info(f"  Vision progress: {i+1}/{len(images)}")
        except OllamaError as e:
            descriptions[img_path.name] = f"(vision analysis failed: {e})"

    ok(f"Stage A vision complete — {len(descriptions)} screenshots described")
    return descriptions


# ─────────────────────────────────────────────────────────────
# STAGE B — DOMAIN CONSOLIDATION
# ─────────────────────────────────────────────────────────────

def consolidate_ui_flow(xml_summaries: dict[str, str], model: str) -> str:
    """Consolidate all screen summaries into a UI traversal narrative."""
    if not xml_summaries:
        return "No UI traversal data available."

    # Group screens by hash prefix to detect unique vs duplicate states
    entries = [f"Screen {i+1} ({name}): {desc}"
               for i, (name, desc) in enumerate(xml_summaries.items())]
    block = "\n\n".join(entries[:80])  # cap at 80 screens

    prompt = (
        "You are a mobile malware analyst. Below are per-screen descriptions from an "
        "automated UI traversal of an Android malware sample. Write a coherent 5–8 sentence "
        "narrative describing: the overall app flow, what sensitive user data the app attempts "
        "to collect (in order), any fake UI or social engineering screens, and the most "
        "suspicious screens encountered.\n\n"
        f"Screen summaries:\n{block}\n\nUI Traversal Narrative:"
    )
    try:
        return _ollama_generate(prompt, model, max_tokens=500)
    except OllamaError as e:
        return f"UI flow consolidation failed: {e}"


def consolidate_static(static: dict, model: str) -> str:
    """Summarise static analysis findings."""
    if not static:
        return "Static analysis report unavailable (encrypted APK)."
    summary = static.get("summary", {})
    perms   = summary.get("dangerous_permissions", [])
    issues  = static.get("manifest_issues", [])
    code    = static.get("code_patterns", [])

    block = json.dumps({
        "package": static.get("package_name"),
        "dangerous_permissions": perms[:20],
        "manifest_issues": issues[:15],
        "code_patterns": [
            {"name": c.get("name"), "severity": c.get("severity"),
             "description": c.get("description")}
            for c in code[:15]
        ],
        "cert": static.get("certificate", {}),
    }, indent=2)

    prompt = (
        "You are a mobile malware analyst. Below is a structured static analysis of an "
        "Android APK. Write a 4–6 sentence paragraph covering: the most dangerous permissions "
        "and what they enable, key manifest vulnerabilities, suspicious code patterns "
        "(emphasise any C2, exfiltration, or dropper patterns), and certificate anomalies.\n\n"
        f"Static Analysis:\n{block}\n\nStatic Summary:"
    )
    try:
        return _ollama_generate(prompt, model, max_tokens=500)
    except OllamaError as e:
        return f"Static summarisation failed: {e}"


def consolidate_runtime(sentry: dict, model: str) -> str:
    """Summarise sentry runtime findings."""
    if not sentry:
        return "Sentry runtime report unavailable."
    block = json.dumps({
        "package":              sentry.get("package_name"),
        "network_connections":  sentry.get("network_connections", [])[:20],
        "dropper_events":       sentry.get("dropper_events", [])[:10],
        "packer_events":        sentry.get("packer_events", [])[:10],
        "permission_abuse":     sentry.get("permission_abuse", [])[:15],
        "root_detected":        sentry.get("root_detected", False),
        "startup_dialogs":      sentry.get("startup_dialogs_handled", 0),
    }, indent=2)

    prompt = (
        "You are a mobile malware analyst. Below is the runtime sentry report for an Android "
        "malware sample. Write a 4–6 sentence paragraph covering: network connections made "
        "(IPs, ports, protocols), dropper/packer payload activity, permission abuse events, "
        "anti-analysis behaviour (root detection, emulator checks), and startup dialog "
        "manipulation.\n\n"
        f"Sentry Report:\n{block}\n\nRuntime Summary:"
    )
    try:
        return _ollama_generate(prompt, model, max_tokens=500)
    except OllamaError as e:
        return f"Runtime summarisation failed: {e}"


def consolidate_explorer(explorer: dict, model: str) -> str:
    """Summarise explorer UI traversal findings."""
    if not explorer:
        return "Explorer report unavailable."
    summary = explorer.get("summary", {})
    block = json.dumps({
        "states_visited":              summary.get("states_visited", 0),
        "unique_activities":           summary.get("unique_activities", [])[:20],
        "permission_dialogs_accepted": summary.get("permission_dialogs_accepted", 0),
        "forms_filled":                summary.get("forms_filled", 0),
        "form_submits_attempted":      summary.get("form_submits_attempted", 0),
        "form_submits_succeeded":      summary.get("form_submits_succeeded", 0),
        "form_submit_failures":        summary.get("form_submit_failures", [])[:5],
        "human_interventions":         summary.get("human_interventions", 0),
        "crashes_recovered":           explorer.get("crashes_recovered", 0),
    }, indent=2)

    prompt = (
        "You are a mobile malware analyst. Below is the UI explorer report. "
        "Write a 3–5 sentence paragraph covering: how many unique app states were "
        "explored, what activities were discovered, what forms were filled with synthetic "
        "credentials (and whether submissions succeeded — indicating the app actually "
        "transmits data), and any notable crashes or human intervention points.\n\n"
        f"Explorer Report:\n{block}\n\nExplorer Summary:"
    )
    try:
        return _ollama_generate(prompt, model, max_tokens=400)
    except OllamaError as e:
        return f"Explorer summarisation failed: {e}"


# ─────────────────────────────────────────────────────────────
# STAGE C — FINAL SYNTHESIS PER SECTION
# ─────────────────────────────────────────────────────────────

def _build_master_context(
    static: dict, sentry: dict, explorer: dict, phase4: dict,
    static_summary: str, runtime_summary: str, explorer_summary: str,
    ui_narrative: str, log_narrative: str, screenshot_notes: dict,
) -> str:
    """Build the master context block fed into Stage C prompts."""
    pkg  = (static or sentry or explorer or phase4 or {}).get("package_name", "unknown")
    p4v  = (phase4 or {}).get("llm_verdict") or {}
    iocs = (phase4 or {}).get("network_iocs", [])
    sus  = (phase4 or {}).get("suspicious_iocs", [])

    vision_block = ""
    if screenshot_notes:
        lines = [f"  {k}: {v}" for k, v in list(screenshot_notes.items())[:20]]
        vision_block = "Visual Evidence (screenshots):\n" + "\n".join(lines)

    return textwrap.dedent(f"""
        PACKAGE: {pkg}
        ANALYSIS DATE: {datetime.now().strftime('%Y-%m-%d %H:%M')}

        === PHASE 4 LLM VERDICT ===
        Threat Class:   {p4v.get('threat_class', 'unknown')}
        Confidence:     {p4v.get('confidence', 'unknown')}
        Threat Score:   {p4v.get('threat_score', 'N/A')}/100
        Kill Chain:     {p4v.get('kill_chain_stage', 'unknown')}
        Evidence:       {p4v.get('evidence', '')}
        Data Collected: {p4v.get('data_collected', '')}

        === NETWORK IOCs ===
        All IOCs ({len(iocs)} total): {', '.join(i.get('value','') for i in iocs[:30])}
        Suspicious IOCs: {', '.join(i.get('value','') for i in sus[:15])}

        === STATIC ANALYSIS SUMMARY ===
        {static_summary}

        === RUNTIME BEHAVIOUR SUMMARY ===
        {runtime_summary}

        === UI TRAVERSAL SUMMARY ===
        {ui_narrative}

        === EXPLORER METRICS ===
        {explorer_summary}

        === LOG ANALYSIS ===
        {log_narrative}

        {vision_block}
    """).strip()


def _synthesise_section(section_name: str, instructions: str,
                        context: str, model: str,
                        max_tokens: int = 600) -> str:
    """Generate one report section via Stage C LLM call."""
    prompt = (
        f"You are a Senior Malware Analyst writing a formal threat intelligence report. "
        f"Using ONLY the evidence provided below, write the '{section_name}' section. "
        f"{instructions}\n\n"
        f"Evidence Context:\n{context}\n\n"
        f"{section_name}:"
    )
    try:
        return _ollama_generate(prompt, model, max_tokens=max_tokens)
    except OllamaError as e:
        return f"[Section generation failed: {e}]"


def generate_all_sections(context: str, model: str) -> dict[str, str]:
    """Stage C: Generate all report sections."""
    sections = {
        "Executive Summary": (
            "Write 3–5 sentences suitable for a non-technical manager. Cover: what the app "
            "is impersonating (if anything), what data it attempts to steal, whether it "
            "successfully exfiltrated data during analysis, and the overall threat level. "
            "Be direct and use plain language.", 400
        ),
        "Threat Classification": (
            "State the threat class (e.g. banking trojan, spyware, dropper), confidence "
            "level, threat score, and kill chain stage. Explain in 2–3 sentences why this "
            "classification was assigned, citing specific observed behaviours.", 350
        ),
        "Technical Analysis": (
            "Write 5–8 sentences covering: APK structure and obfuscation, dangerous permissions "
            "and their abuse, dropper/packer chain if present, C2 infrastructure observed, "
            "anti-analysis techniques detected (root detection, emulator checks), and any "
            "notable code patterns (reflective loading, dynamic DEX, crypto routines).", 700
        ),
        "UI Deception Tactics": (
            "Write 4–6 sentences describing how the app's UI deceives users: what legitimate "
            "app or institution it impersonates, the sequence of screens shown to extract "
            "credentials, any fake permission rationale dialogs, urgency/pressure messaging, "
            "and which specific sensitive fields (OTP, PIN, card number, Aadhaar) were "
            "presented to the victim.", 600
        ),
        "Network & Exfiltration Analysis": (
            "Write 4–6 sentences covering: all C2 endpoints contacted (IPs, domains, ports), "
            "protocols used, whether form submissions succeeded (data actually transmitted), "
            "suspicious TLDs or hosting patterns, and any SSL/certificate anomalies. "
            "Mention specific IOC values from the evidence.", 600
        ),
        "Dropper & Payload Chain": (
            "If no dropper/packer activity was observed, write one sentence saying so. "
            "Otherwise write 3–5 sentences describing: what payloads were dropped, "
            "how they were installed, what packages were spawned, and whether DEX was "
            "extracted from memory. Include package names where available.", 400
        ),
        "Indicators of Compromise": (
            "List all network IOCs from the evidence. Format as: "
            "IP addresses (one per line), Domains (one per line), Package names. "
            "Do not add commentary — this section is a clean IOC list only.", 400
        ),
        "Analyst Recommendations": (
            "Write 4–6 actionable bullet-style recommendations for: "
            "(1) immediate containment if device is compromised, "
            "(2) specific IOCs to block at the network perimeter, "
            "(3) detection rules to write (permission combos, domains, package names), "
            "(4) user awareness guidance relevant to this specific threat, "
            "(5) further forensic steps if a real infection is suspected.", 500
        ),
    }

    results = {}
    total = len(sections)
    for i, (name, (instructions, max_tok)) in enumerate(sections.items(), 1):
        info(f"Stage C — [{i}/{total}] Generating: {name} ...")
        results[name] = _synthesise_section(name, instructions, context, model, max_tok)
        ok(f"  ✓ {name}")

    return results


# ─────────────────────────────────────────────────────────────
# REPORT DATA LOADING
# ─────────────────────────────────────────────────────────────

def _load_json(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            warn(f"Could not parse {path.name}: {e}")
    return {}


def load_all_reports(session_dir: Path) -> dict:
    return {
        "static":   _load_json(session_dir / "static_report.json"),
        "sentry":   _load_json(session_dir / "sentry_report.json"),
        "explorer": _load_json(session_dir / "explorer_report.json"),
        "phase4":   _load_json(session_dir / "phase4_report.json"),
    }


# ─────────────────────────────────────────────────────────────
# WORD DOCUMENT BUILDER
# ─────────────────────────────────────────────────────────────

# Colour palette — professional threat-intel blue/red/grey scheme
COLOUR_TITLE      = RGBColor(0x1F, 0x39, 0x64)  # dark navy
COLOUR_H1         = RGBColor(0x1F, 0x39, 0x64)  # dark navy
COLOUR_H2         = RGBColor(0x2E, 0x75, 0xB6)  # medium blue
COLOUR_ACCENT     = RGBColor(0xC0, 0x00, 0x00)  # threat red
COLOUR_TABLE_HDR  = RGBColor(0x1F, 0x39, 0x64)  # navy
COLOUR_TABLE_ALT  = RGBColor(0xED, 0xF2, 0xFA)  # light blue tint
COLOUR_RULE       = RGBColor(0x2E, 0x75, 0xB6)  # blue rule


def _set_cell_bg(cell, hex_colour: str):
    """Set table cell background via XML shading."""
    tc   = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd  = OxmlElement("w:shd")
    shd.set(qn("w:val"),   "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"),  hex_colour)
    tcPr.append(shd)


def _set_para_border_bottom(para, colour_hex: str = "2E75B6", size: int = 12):
    """Add a bottom border rule to a paragraph."""
    pPr  = para._p.get_or_add_pPr()
    pBdr = OxmlElement("w:pBdr")
    bot  = OxmlElement("w:bottom")
    bot.set(qn("w:val"),   "single")
    bot.set(qn("w:sz"),    str(size))
    bot.set(qn("w:space"), "1")
    bot.set(qn("w:color"), colour_hex)
    pBdr.append(bot)
    pPr.append(pBdr)


def _add_heading1(doc: Document, text: str):
    """Section heading with bottom rule."""
    para = doc.add_paragraph()
    run  = para.add_run(text.upper())
    run.bold      = True
    run.font.size = Pt(14)
    run.font.color.rgb = COLOUR_H1
    run.font.name = "Calibri"
    para.paragraph_format.space_before = Pt(18)
    para.paragraph_format.space_after  = Pt(4)
    _set_para_border_bottom(para, "1F3964", 8)
    return para


def _add_heading2(doc: Document, text: str):
    para = doc.add_paragraph()
    run  = para.add_run(text)
    run.bold      = True
    run.font.size = Pt(12)
    run.font.color.rgb = COLOUR_H2
    run.font.name = "Calibri"
    para.paragraph_format.space_before = Pt(12)
    para.paragraph_format.space_after  = Pt(3)
    return para


def _add_body(doc: Document, text: str, italic: bool = False):
    """Add body paragraph with clean formatting."""
    para = doc.add_paragraph()
    run  = para.add_run(text)
    run.font.size   = Pt(10.5)
    run.font.name   = "Calibri"
    run.font.italic = italic
    para.paragraph_format.space_after   = Pt(6)
    para.paragraph_format.line_spacing  = Pt(14)
    return para


def _add_bullet(doc: Document, text: str, level: int = 0):
    para = doc.add_paragraph(style="List Bullet")
    run  = para.add_run(text)
    run.font.size = Pt(10.5)
    run.font.name = "Calibri"
    para.paragraph_format.space_after = Pt(3)
    return para


def _add_kv_table(doc: Document, rows: list[tuple[str, str]]):
    """
    Two-column key-value table. Column 1 = key (navy bg, white text),
    column 2 = value (alternating white/light-blue bg).
    """
    col1_w = 2300  # ~1.6 inches in EMU-like units (twips * 20)
    col2_w = 7060  # ~4.9 inches
    table = doc.add_table(rows=0, cols=2)
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.LEFT

    for i, (key, val) in enumerate(rows):
        row     = table.add_row()
        k_cell  = row.cells[0]
        v_cell  = row.cells[1]

        # Key cell — navy background
        _set_cell_bg(k_cell, "1F3964")
        k_para  = k_cell.paragraphs[0]
        k_run   = k_para.add_run(key)
        k_run.bold            = True
        k_run.font.color.rgb  = RGBColor(0xFF, 0xFF, 0xFF)
        k_run.font.size       = Pt(9.5)
        k_run.font.name       = "Calibri"
        k_cell.width          = col1_w

        # Value cell — alternating bg
        bg = "EDF2FA" if i % 2 == 0 else "FFFFFF"
        _set_cell_bg(v_cell, bg)
        v_para  = v_cell.paragraphs[0]
        v_run   = v_para.add_run(str(val))
        v_run.font.size       = Pt(9.5)
        v_run.font.name       = "Calibri"
        v_cell.width          = col2_w

    doc.add_paragraph()  # spacer


def _add_ioc_table(doc: Document, iocs: list[dict]):
    """Colour-coded IOC table: suspicious = red highlight."""
    if not iocs:
        _add_body(doc, "No network IOCs extracted.", italic=True)
        return

    headers = ["IOC Value", "Type", "Classification", "Ports", "Sources"]
    col_ws  = [3500, 1100, 1400, 1000, 2360]

    table = doc.add_table(rows=1, cols=len(headers))
    table.style     = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.LEFT

    # Header row
    hdr_row = table.rows[0]
    for j, (h, w) in enumerate(zip(headers, col_ws)):
        cell = hdr_row.cells[j]
        _set_cell_bg(cell, "1F3964")
        cell.width = w
        run = cell.paragraphs[0].add_run(h)
        run.bold           = True
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        run.font.size      = Pt(9)
        run.font.name      = "Calibri"

    for i, ioc in enumerate(iocs[:60]):
        row   = table.add_row()
        is_sus = ioc.get("classification") == "suspicious"
        bg     = "FFE6E6" if is_sus else ("FFFFFF" if i % 2 == 0 else "EDF2FA")
        vals = [
            ioc.get("value", ""),
            ioc.get("ioc_type", ""),
            ioc.get("classification", "unknown"),
            ", ".join(str(p) for p in (ioc.get("ports") or [])[:5]),
            ", ".join(ioc.get("sources") or []),
        ]
        for j, (v, w) in enumerate(zip(vals, col_ws)):
            cell = row.cells[j]
            _set_cell_bg(cell, bg)
            cell.width = w
            run = cell.paragraphs[0].add_run(str(v))
            run.font.size = Pt(8.5)
            run.font.name = "Calibri"
            if is_sus and j == 0:
                run.bold = True
                run.font.color.rgb = COLOUR_ACCENT

    doc.add_paragraph()


def _add_permission_table(doc: Document, perms: list):
    """Dangerous permissions table."""
    if not perms:
        _add_body(doc, "No dangerous permissions declared.", italic=True)
        return

    table = doc.add_table(rows=1, cols=2)
    table.style     = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.LEFT

    hdr = table.rows[0]
    for j, h in enumerate(["Permission", "Risk"]):
        _set_cell_bg(hdr.cells[j], "1F3964")
        run = hdr.cells[j].paragraphs[0].add_run(h)
        run.bold = True
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        run.font.size = Pt(9)
        run.font.name = "Calibri"

    for i, perm in enumerate(perms[:30]):
        if isinstance(perm, dict):
            name = perm.get("permission", str(perm))
            risk = str(perm.get("risk_score", ""))
        else:
            name = str(perm)
            risk = "HIGH"

        row  = table.add_row()
        bg   = "FFE6E6" if "SEND_SMS" in name or "CALL" in name or "READ_CONTACTS" in name \
               else ("FFFFFF" if i % 2 == 0 else "EDF2FA")
        for j, val in enumerate([name, risk]):
            _set_cell_bg(row.cells[j], bg)
            run = row.cells[j].paragraphs[0].add_run(val)
            run.font.size = Pt(9)
            run.font.name = "Calibri"

    doc.add_paragraph()


def _add_cover_page(doc: Document, pkg: str, session_dir: str,
                    threat_class: str, threat_score,
                    analysis_date: str):
    """Professional cover page."""
    # Top colour bar — simulate with a heavily-bordered paragraph
    bar = doc.add_paragraph()
    bar.paragraph_format.space_before = Pt(0)
    bar.paragraph_format.space_after  = Pt(0)
    pPr  = bar._p.get_or_add_pPr()
    pBdr = OxmlElement("w:pBdr")
    for side in ("top", "bottom"):
        el = OxmlElement(f"w:{side}")
        el.set(qn("w:val"),   "single")
        el.set(qn("w:sz"),    "48")
        el.set(qn("w:space"), "1")
        el.set(qn("w:color"), "1F3964")
        pBdr.append(el)
    pPr.append(pBdr)
    bar.add_run(" " * 80)

    doc.add_paragraph()
    doc.add_paragraph()

    # REPORT TYPE label
    lbl = doc.add_paragraph()
    lbl.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = lbl.add_run("THREAT INTELLIGENCE REPORT")
    r.font.name  = "Calibri"
    r.font.size  = Pt(11)
    r.font.color.rgb = COLOUR_H2
    r.bold       = True
    r.font.all_caps = True

    doc.add_paragraph()

    # Title
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = title.add_run("Android Malware Analysis")
    r.font.name  = "Calibri"
    r.font.size  = Pt(28)
    r.font.color.rgb = COLOUR_TITLE
    r.bold       = True

    # Package name subtitle
    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = sub.add_run(pkg)
    r.font.name  = "Calibri"
    r.font.size  = Pt(14)
    r.font.color.rgb = COLOUR_H2
    r.italic     = True

    doc.add_paragraph()
    doc.add_paragraph()

    # Threat classification box — kv table centred
    _add_kv_table(doc, [
        ("Threat Classification", threat_class.upper() if threat_class else "ANALYSING"),
        ("Threat Score",          f"{threat_score}/100" if threat_score else "N/A"),
        ("Analysis Date",         analysis_date),
        ("Session Directory",     session_dir),
        ("Classification",        "TLP:AMBER — For authorised analysts only"),
    ])

    doc.add_page_break()


def _add_screenshot_gallery(doc: Document, screenshots_dir: Path,
                             vision_notes: dict, max_images: int = 12):
    """
    Embed screenshots into the document as a gallery with captions.
    max_images limits total embedded to keep doc size reasonable.
    """
    if not screenshots_dir.exists():
        return
    images = sorted([
        f for f in screenshots_dir.iterdir()
        if f.suffix.lower() in (".png", ".jpg", ".jpeg")
        and not f.stem.startswith("intervention_")
    ])[:max_images]

    if not images:
        _add_body(doc, "No screenshots available.", italic=True)
        return

    # Two-column layout via a table
    table = doc.add_table(rows=0, cols=2)
    table.style     = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.LEFT

    for i in range(0, len(images), 2):
        row = table.add_row()
        for col_idx in range(2):
            if i + col_idx >= len(images):
                break
            img_path = images[i + col_idx]
            cell     = row.cells[col_idx]
            _set_cell_bg(cell, "FFFFFF")
            try:
                para = cell.paragraphs[0]
                run  = para.add_run()
                # Scale to fit column (approx 3 inches wide)
                run.add_picture(str(img_path), width=Inches(3.0))
                # Caption
                cap_para = cell.add_paragraph()
                cap_run  = cap_para.add_run(img_path.name)
                cap_run.font.size  = Pt(7.5)
                cap_run.font.name  = "Calibri"
                cap_run.font.color.rgb = RGBColor(0x60, 0x60, 0x60)
                cap_run.italic     = True
                # Vision note
                note = vision_notes.get(img_path.name, "")
                if note:
                    note_para = cell.add_paragraph()
                    note_run  = note_para.add_run(note[:200])
                    note_run.font.size = Pt(8)
                    note_run.font.name = "Calibri"
            except Exception as e:
                cell.paragraphs[0].add_run(f"[Image error: {e}]")

    doc.add_paragraph()


def build_word_report(
    session_dir: Path,
    reports: dict,
    sections: dict[str, str],
    static_summary: str,
    runtime_summary: str,
    explorer_summary: str,
    ui_narrative: str,
    log_narrative: str,
    xml_summaries: dict[str, str],
    vision_notes: dict[str, str],
    output_path: Path,
):
    """Assemble the final Word document from all generated content."""
    static  = reports["static"]
    sentry  = reports["sentry"]
    explorer= reports["explorer"]
    phase4  = reports["phase4"]

    pkg = (
        static.get("package_name")
        or sentry.get("package_name")
        or explorer.get("package_name")
        or "unknown.package"
    )
    p4v          = (phase4 or {}).get("llm_verdict") or {}
    threat_class = p4v.get("threat_class", "Unknown")
    threat_score = p4v.get("threat_score", "N/A")
    analysis_date= datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    doc = Document()

    # ── Page setup ─────────────────────────────────────────────
    section = doc.sections[0]
    section.page_width  = Cm(21)   # A4
    section.page_height = Cm(29.7)
    section.top_margin    = Cm(2.5)
    section.bottom_margin = Cm(2.5)
    section.left_margin   = Cm(2.5)
    section.right_margin  = Cm(2.5)

    # Default style
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(10.5)

    # ── Cover Page ─────────────────────────────────────────────
    _add_cover_page(doc, pkg, str(session_dir),
                    threat_class, threat_score, analysis_date)

    # ── Table of Contents placeholder ─────────────────────────
    _add_heading1(doc, "Table of Contents")
    _add_body(doc, "(Update fields in Word: Right-click → Update Field after opening)", italic=True)
    toc_para = doc.add_paragraph()
    fldChar  = OxmlElement("w:fldChar")
    fldChar.set(qn("w:fldCharType"), "begin")
    instrText = OxmlElement("w:instrText")
    instrText.text = 'TOC \\o "1-2" \\h \\z \\u'
    fldChar2 = OxmlElement("w:fldChar")
    fldChar2.set(qn("w:fldCharType"), "end")
    run = toc_para.add_run()
    run._r.append(fldChar)
    run._r.append(instrText)
    run._r.append(fldChar2)
    doc.add_page_break()

    # ══════════════════════════════════════════════════════════
    # SECTION 1 — EXECUTIVE SUMMARY
    # ══════════════════════════════════════════════════════════
    _add_heading1(doc, "1. Executive Summary")
    _add_body(doc, sections.get("Executive Summary", ""))
    doc.add_paragraph()

    # Quick-reference metadata table
    _add_heading2(doc, "Sample Metadata")
    meta_rows = [
        ("Package Name",      pkg),
        ("Threat Class",      threat_class),
        ("Threat Score",      f"{threat_score}/100"),
        ("Confidence",        p4v.get("confidence", "N/A")),
        ("Kill Chain Stage",  p4v.get("kill_chain_stage", "N/A")),
        ("States Explored",   (explorer.get("summary") or {}).get("states_visited", "N/A")),
        ("Forms Filled",      (explorer.get("summary") or {}).get("forms_filled", "N/A")),
        ("Submissions OK",    f"{(explorer.get('summary') or {}).get('form_submits_succeeded', 0)}"
                              f" / {(explorer.get('summary') or {}).get('form_submits_attempted', 0)}"),
        ("Network IOCs",      len((phase4 or {}).get("network_iocs", []))),
        ("Suspicious IOCs",   len((phase4 or {}).get("suspicious_iocs", []))),
        ("Dropper Events",    len((sentry or {}).get("dropper_events", []))),
        ("Packer Events",     len((sentry or {}).get("packer_events", []))),
        ("Root Detected",     str((sentry or {}).get("root_detected", "N/A"))),
        ("Analysis Date",     analysis_date),
    ]
    _add_kv_table(doc, meta_rows)

    # ══════════════════════════════════════════════════════════
    # SECTION 2 — THREAT CLASSIFICATION
    # ══════════════════════════════════════════════════════════
    _add_heading1(doc, "2. Threat Classification")
    _add_body(doc, sections.get("Threat Classification", ""))

    if p4v.get("evidence"):
        doc.add_paragraph()
        _add_heading2(doc, "Supporting Evidence")
        ev = p4v.get("evidence")
        if isinstance(ev, list):
            for e in ev:
                _add_bullet(doc, str(e))
        else:
            _add_body(doc, str(ev))

    # ══════════════════════════════════════════════════════════
    # SECTION 3 — TECHNICAL ANALYSIS
    # ══════════════════════════════════════════════════════════
    _add_heading1(doc, "3. Technical Analysis")

    _add_heading2(doc, "3.1 Static Analysis")
    _add_body(doc, static_summary)

    # Dangerous permissions table
    doc.add_paragraph()
    _add_heading2(doc, "3.2 Dangerous Permissions")
    perms = (static or {}).get("summary", {}).get("dangerous_permissions", [])
    _add_permission_table(doc, perms)

    _add_heading2(doc, "3.3 Runtime Behaviour")
    _add_body(doc, runtime_summary)

    _add_heading2(doc, "3.4 Deep Technical Analysis")
    _add_body(doc, sections.get("Technical Analysis", ""))

    # ══════════════════════════════════════════════════════════
    # SECTION 4 — UI DECEPTION TACTICS
    # ══════════════════════════════════════════════════════════
    _add_heading1(doc, "4. UI Deception Tactics")
    _add_body(doc, sections.get("UI Deception Tactics", ""))

    doc.add_paragraph()
    _add_heading2(doc, "4.1 UI Traversal Narrative")
    _add_body(doc, ui_narrative)

    doc.add_paragraph()
    _add_heading2(doc, "4.2 Explorer Metrics")
    _add_body(doc, explorer_summary)

    # Screen-by-screen summary (top 20 most interesting)
    if xml_summaries:
        doc.add_paragraph()
        _add_heading2(doc, "4.3 Key Screens Encountered")
        for i, (name, desc) in enumerate(list(xml_summaries.items())[:20]):
            _add_bullet(doc, f"[{name}] {desc}")

    # ══════════════════════════════════════════════════════════
    # SECTION 5 — SCREENSHOT GALLERY
    # ══════════════════════════════════════════════════════════
    _add_heading1(doc, "5. Screenshot Evidence")
    screens_dir = session_dir / "screenshots"
    if not screens_dir.exists() or not any(screens_dir.iterdir()):
        _add_body(doc, "No screenshots captured (XML-only tier or screenshots directory empty).",
                  italic=True)
    else:
        _add_body(doc, "Screenshots captured during automated UI traversal. "
                  "Vision analysis annotations shown below each image where available.")
        doc.add_paragraph()
        _add_screenshot_gallery(doc, screens_dir, vision_notes, max_images=12)

    # Dropper screenshots
    droppers_dir = session_dir / "droppers"
    if droppers_dir.exists():
        for dropper_pkg in droppers_dir.iterdir():
            dropper_ss = dropper_pkg / "screenshots"
            if dropper_ss.exists() and any(dropper_ss.iterdir()):
                _add_heading2(doc, f"Dropper: {dropper_pkg.name}")
                _add_screenshot_gallery(doc, dropper_ss, vision_notes, max_images=6)

    # ══════════════════════════════════════════════════════════
    # SECTION 6 — NETWORK & EXFILTRATION
    # ══════════════════════════════════════════════════════════
    _add_heading1(doc, "6. Network & Exfiltration Analysis")
    _add_body(doc, sections.get("Network & Exfiltration Analysis", ""))

    doc.add_paragraph()
    _add_heading2(doc, "6.1 Log Analysis Summary")
    _add_body(doc, log_narrative)

    doc.add_paragraph()
    _add_heading2(doc, "6.2 Network IOC Table")
    all_iocs = (phase4 or {}).get("network_iocs", [])
    _add_ioc_table(doc, all_iocs)

    # ══════════════════════════════════════════════════════════
    # SECTION 7 — DROPPER & PAYLOAD CHAIN
    # ══════════════════════════════════════════════════════════
    _add_heading1(doc, "7. Dropper & Payload Chain")
    _add_body(doc, sections.get("Dropper & Payload Chain", ""))

    dropper_events = (sentry or {}).get("dropper_events", [])
    packer_events  = (sentry or {}).get("packer_events",  [])

    if dropper_events:
        doc.add_paragraph()
        _add_heading2(doc, "7.1 Dropper Events")
        for ev in dropper_events[:10]:
            pkg_name = ev.get("package_name", "unknown")
            path     = ev.get("local_path", "not recovered")
            _add_bullet(doc, f"{pkg_name}  →  {path}")

    if packer_events:
        doc.add_paragraph()
        _add_heading2(doc, "7.2 Packer / In-Memory Payload Events")
        for ev in packer_events[:10]:
            pkg_name = ev.get("package_name", "unknown")
            _add_bullet(doc, pkg_name)

    suggested = (sentry or {}).get("suggested_commands", [])
    if suggested:
        doc.add_paragraph()
        _add_heading2(doc, "7.3 Suggested Follow-up Commands")
        for cmd in suggested[:6]:
            para = doc.add_paragraph()
            run  = para.add_run(cmd)
            run.font.name = "Courier New"
            run.font.size = Pt(8.5)
            run.font.color.rgb = RGBColor(0xC0, 0x00, 0x00)

    # ══════════════════════════════════════════════════════════
    # SECTION 8 — INDICATORS OF COMPROMISE
    # ══════════════════════════════════════════════════════════
    _add_heading1(doc, "8. Indicators of Compromise")
    _add_body(doc, sections.get("Indicators of Compromise", ""))

    sus_iocs = (phase4 or {}).get("suspicious_iocs", [])
    if sus_iocs:
        doc.add_paragraph()
        _add_heading2(doc, "Suspicious / High-Priority IOCs")
        for ioc in sus_iocs[:20]:
            _add_bullet(doc, f"{ioc.get('value','')}  [{ioc.get('ioc_type','')}]  "
                             f"— {ioc.get('classification','')}")

    # ══════════════════════════════════════════════════════════
    # SECTION 9 — ANALYST RECOMMENDATIONS
    # ══════════════════════════════════════════════════════════
    _add_heading1(doc, "9. Analyst Recommendations")
    rec_text = sections.get("Analyst Recommendations", "")
    # Try to render as bullets if the model returned a list
    for line in rec_text.splitlines():
        line = line.strip().lstrip("-•*123456789. ")
        if line:
            _add_bullet(doc, line)

    # ══════════════════════════════════════════════════════════
    # SECTION 10 — APPENDICES
    # ══════════════════════════════════════════════════════════
    doc.add_page_break()
    _add_heading1(doc, "Appendix A — All Network IOCs")
    _add_ioc_table(doc, all_iocs)

    _add_heading1(doc, "Appendix B — Code Pattern Findings")
    code_patterns = (static or {}).get("code_patterns", [])
    if code_patterns:
        table = doc.add_table(rows=1, cols=3)
        table.style = "Table Grid"
        for j, h in enumerate(["Pattern", "Severity", "Description"]):
            _set_cell_bg(table.rows[0].cells[j], "1F3964")
            run = table.rows[0].cells[j].paragraphs[0].add_run(h)
            run.bold = True
            run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
            run.font.size = Pt(9)
            run.font.name = "Calibri"
        for i, cp in enumerate(code_patterns[:30]):
            row = table.add_row()
            bg  = "FFFFFF" if i % 2 == 0 else "EDF2FA"
            for j, val in enumerate([
                cp.get("name", ""),
                cp.get("severity", ""),
                cp.get("description", "")[:120],
            ]):
                _set_cell_bg(row.cells[j], bg)
                run = row.cells[j].paragraphs[0].add_run(str(val))
                run.font.size = Pt(8.5)
                run.font.name = "Calibri"
        doc.add_paragraph()
    else:
        _add_body(doc, "No code patterns recorded.", italic=True)

    _add_heading1(doc, "Appendix C — Unique Activities Discovered")
    activities = (explorer.get("summary") or {}).get("unique_activities", [])
    if activities:
        for act in activities:
            _add_bullet(doc, act)
    else:
        _add_body(doc, "No activity data.", italic=True)

    _add_heading1(doc, "Appendix D — Screen Summary Index")
    if xml_summaries:
        for name, desc in xml_summaries.items():
            _add_body(doc, f"[{name}]  {desc}")
    else:
        _add_body(doc, "No XML screen data.", italic=True)

    # ── Save ───────────────────────────────────────────────────
    doc.save(str(output_path))
    ok(f"Report saved: {output_path}")


# ─────────────────────────────────────────────────────────────
# MAIN PIPELINE
# ─────────────────────────────────────────────────────────────

def run_phase5(session_dir: Path,
               output_path: Path,
               enable_vision: bool = True) -> Path:
    """
    Full three-stage pipeline. Returns path to generated .docx.
    """
    banner("PHASE 5 // Master Report Generator")
    info(f"Session : {session_dir}")
    info(f"Output  : {output_path}")
    info(f"Model   : {Config.synthesis_model()} (synthesis)")
    if enable_vision:
        info(f"Vision  : {Config.MODEL_VISION}")

    # ── Load all JSON reports ──────────────────────────────────
    banner("Loading Phase Reports")
    reports = load_all_reports(session_dir)
    for name, data in reports.items():
        status = "✓" if data else "✗ missing"
        info(f"  {name}_report.json : {status}")

    phase4  = reports["phase4"]
    static  = reports["static"]
    sentry  = reports["sentry"]
    explorer= reports["explorer"]

    # ── Check Ollama ───────────────────────────────────────────
    synth_model = Config.synthesis_model()
    banner(f"Checking Ollama — {synth_model}")
    if not _check_ollama(synth_model):
        warn(f"Synthesis model '{synth_model}' may not be available. Proceeding anyway.")

    vision_model = Config.MODEL_VISION if enable_vision else None
    if enable_vision and not _check_ollama(Config.MODEL_VISION):
        warn(f"Vision model '{Config.MODEL_VISION}' not found — disabling vision pass.")
        vision_model = None

    # ── Stage A: Per-artifact summarisation ───────────────────
    banner("STAGE A // Per-Artifact Summarisation")

    # XML files (main app)
    xml_dir = session_dir / "xml"
    xml_summaries = summarise_xml_files(xml_dir, synth_model, Config.MAX_XML)

    # XML files (droppers)
    dropper_xml_summaries: dict[str, str] = {}
    droppers_dir = session_dir / "droppers"
    if droppers_dir.exists():
        for dpkg in droppers_dir.iterdir():
            d_xml = dpkg / "xml"
            if d_xml.exists():
                info(f"  Summarising dropper XML: {dpkg.name}")
                d_sums = summarise_xml_files(d_xml, synth_model, max_files=30)
                dropper_xml_summaries.update(
                    {f"{dpkg.name}/{k}": v for k, v in d_sums.items()}
                )
    xml_summaries.update(dropper_xml_summaries)

    # Logs
    network_iocs = (phase4 or {}).get("network_iocs", [])
    logcat_path  = session_dir / "logcat.txt"
    log_narrative = summarise_logs(logcat_path, synth_model, network_iocs)
    ok("Stage A log narrative complete")

    # Screenshots — vision pass (optional)
    vision_notes: dict[str, str] = {}
    if vision_model:
        screens_dir = session_dir / "screenshots"
        vision_notes = summarise_screenshots(screens_dir, vision_model)
        # Also dropper screenshots
        if droppers_dir.exists():
            for dpkg in droppers_dir.iterdir():
                d_ss = dpkg / "screenshots"
                v2 = summarise_screenshots(d_ss, vision_model)
                vision_notes.update({f"{dpkg.name}/{k}": v for k, v in v2.items()})

    # ── Stage B: Domain consolidation ─────────────────────────
    banner("STAGE B // Domain Consolidation")

    info("Consolidating UI flow narrative ...")
    ui_narrative = consolidate_ui_flow(xml_summaries, synth_model)
    ok("UI flow narrative complete")

    info("Consolidating static analysis ...")
    static_summary = consolidate_static(static, synth_model)
    ok("Static summary complete")

    info("Consolidating runtime behaviour ...")
    runtime_summary = consolidate_runtime(sentry, synth_model)
    ok("Runtime summary complete")

    info("Consolidating explorer metrics ...")
    explorer_summary = consolidate_explorer(explorer, synth_model)
    ok("Explorer summary complete")

    # ── Stage C: Final synthesis ───────────────────────────────
    banner("STAGE C // Final Report Synthesis")

    context = _build_master_context(
        static, sentry, explorer, phase4,
        static_summary, runtime_summary, explorer_summary,
        ui_narrative, log_narrative, vision_notes,
    )
    info(f"Master context: ~{len(context)//4} tokens estimated")

    sections = generate_all_sections(context, synth_model)

    # ── Build Word document ────────────────────────────────────
    banner("Building Word Document")
    build_word_report(
        session_dir=session_dir,
        reports=reports,
        sections=sections,
        static_summary=static_summary,
        runtime_summary=runtime_summary,
        explorer_summary=explorer_summary,
        ui_narrative=ui_narrative,
        log_narrative=log_narrative,
        xml_summaries=xml_summaries,
        vision_notes=vision_notes,
        output_path=output_path,
    )

    return output_path


# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────

def main():
    args        = sys.argv[1:]
    session_arg = None
    out_arg     = None
    no_vision   = False

    i = 0
    while i < len(args):
        if args[i] in ("--out", "-o") and i + 1 < len(args):
            out_arg = args[i + 1]; i += 2
        elif args[i] == "--no-vision":
            no_vision = True; i += 1
        elif not args[i].startswith("--"):
            session_arg = args[i]; i += 1
        else:
            i += 1

    if not session_arg:
        err("Usage: python phase5_report.py <session_dir> [--out report.docx] [--no-vision]")
        sys.exit(1)

    session_dir = Path(session_arg).resolve()
    if not session_dir.exists():
        err(f"Session directory not found: {session_dir}")
        sys.exit(1)

    pkg = "unknown"
    for report_name in ("sentry_report.json", "static_report.json", "explorer_report.json"):
        rp = session_dir / report_name
        if rp.exists():
            try:
                pkg = json.loads(rp.read_text()).get("package_name", "unknown")
                if pkg and pkg != "unknown":
                    break
            except Exception:
                pass

    if out_arg:
        output_path = Path(out_arg).resolve()
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_pkg = re.sub(r"[^\w\-.]", "_", pkg)
        output_path = session_dir / f"phase5_report_{safe_pkg}_{ts}.docx"

    start = time.time()
    run_phase5(session_dir, output_path, enable_vision=not no_vision)
    elapsed = time.time() - start

    banner("PHASE 5 COMPLETE")
    ok(f"Report : {output_path}")
    ok(f"Time   : {elapsed:.0f}s ({elapsed/60:.1f} min)")
    info("Open in Microsoft Word and update the Table of Contents field.")
    info("Right-click the TOC → 'Update Field' → 'Update entire table'.")


if __name__ == "__main__":
    main()