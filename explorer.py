"""
APK Threat Orchestrator -- Phase 3: Explorer (UI Traversal) v2.14
==================================================================
Changes from v2.13:
  [v2.14-1] Exploration robustness overhaul — addresses "state explosion" /
            "budget exhaustion on single branch" failure pattern common in
            malicious APKs (launcher-less, dropper shells, form-trap screens).

  [v2.14-2] _tombed_states: set[str] on ExplorerEngine. A one-way ratchet —
            once a state hash is confirmed dead (relaunch to same screen, or
            all surface tiers exhausted), it is added here and never entered
            again this session. Cleared only on explore_package() switch.
            Guard inserted at top of _dfs(): tombed states trigger _safe_back()
            and immediate return instead of re-exploring.

  [v2.14-3] _verified_relaunch(context) replaces all bare self._relaunch()
            calls in DFS and pass-boundary paths. Verifies post-launch state
            hash differs from pre-launch hash AND app is in foreground before
            declaring success. On same-screen relaunch: tombs the stuck state.
            The underlying _relaunch() is still called internally — only one
            legitimate call site remains (_verified_relaunch itself).

  [v2.14-4] _emergency_surface() — 4-tier escape from stuck/lost state.
            Tier 1: back-walk up to 5 times (cheapest, handles modals).
            Tier 2: _verified_relaunch() — standard am start path.
            Tier 3: am force-stop + cold _verified_relaunch() (skipped when
                    _intervention_active to protect analyst navigation).
            Tier 4: return False — caller must invoke _suspend().
            Always tombs the pre-surface state before returning False so the
            next pass cannot re-enter the dead screen even if human help fails.

  [v2.14-5] _suspend(reason, context) — structured human handoff. Invoked
            immediately when _emergency_surface() returns False or a dropper
            UI is detected mid-DFS. Reason-specific terminal messages:
              "launcher_less" — app requires manual Settings → Open launch.
              "stuck_form"    — automated escape exhausted, navigate manually.
              "dropper_ui"    — dropped APK UI detected in foreground.
                               Prints exact sentry.py --apk command.
              "wrong_screen"  — pass start state is tombed, navigate to home.
            Uses existing HumanInterventionMonitor with budget-gated timeout
            (see [v2.14-7]). No new blocking primitives introduced.

  [v2.14-6] _validate_start_state(pass_num) — gate called before each
            _dfs(0) in the three-pass loop. Three checks in order:
              Gate 1: MAX_STATES reached → skip pass.
              Gate 2: App not in foreground → _verified_relaunch(); on fail
                      → _suspend("launcher_less") + re-check.
              Gate 3: Current state is tombed → _emergency_surface(); on fail
                      → _suspend("wrong_screen") + re-check.
            Returns True only when safe to start a DFS pass.

  [v2.14-7] _intervention_timeout() — budget-gated stuck timeout. Returns
            min(STUCK_TIMEOUT, remaining_budget * 0.20), floored at 15s.
            Replaces hardcoded Config.INTERVENTION_TIMEOUT in the stuck
            handler so a single stuck episode never consumes more than 20%
            of the remaining phase budget. _handle_global_pause() and the
            manual foreground handoff blocks intentionally retain the full
            Config.INTERVENTION_TIMEOUT (analyst-initiated, not budget-critical).

  [v2.14-8] _consecutive_stale_visits counter on ExplorerEngine. Incremented
            each time _dfs() enters an already-visited state; reset on any
            genuinely new state and between passes. When threshold
            (EXPLORER_STALE_THRESHOLD, default 5) is reached: tombs the
            current state and calls _emergency_surface() → _suspend() cascade.
            Catches "lost not stuck" oscillation that classic stuck detection
            (no untried elements) misses.

  [v2.14-9] _branch_ledger: dict[str, str] on ExplorerEngine. Maps depth-0
            element key (resource_id or text) → "pending"|"exhausted"|"tombed".
            Marked "pending" before recursing into a home-screen element;
            "exhausted" after recursion returns. Persists across passes so
            passes 2/3 can skip branches already fully explored in pass 1.
            Cleared on explore_package() switch.

  [v2.14-10] Graduated per-pass depth ceiling via _current_max_depth.
             Pass 1: MAX_DEPTH_PASS1 (default 6) — broad sweep, fast backtrack.
             Pass 2: MAX_DEPTH_PASS2 (default 10) — medium depth.
             Pass 3: MAX_DEPTH_PASS3 (default 15) — deep revisit.
             Config keys: EXPLORER_MAX_DEPTH_PASS1/2/3.
             _dfs() guard changed from Config.MAX_DEPTH to self._current_max_depth.

  [v2.14-11] Home-screen anchor between passes. Before passes 2 and 3,
             explore() calls _emergency_surface() to bring the app to its
             root state before _validate_start_state() + _dfs(0) run. Ensures
             DFS always starts from the home screen on each new pass rather
             than resuming mid-activity from wherever the previous pass ended.

  [v2.14-12] Foreground-shift detection in _dfs(). After every foreground
             check, get_foreground_package() (new module-level helper parsing
             dumpsys window) is called. If a known dropped package is in
             foreground: _suspend("dropper_ui") with sentry --apk command.
             If an unknown package is in foreground: _emergency_surface().

  [v2.14-13] get_foreground_package() — new module-level helper. Parses
             mCurrentFocus from dumpsys window with mFocusedApp fallback.
             Returns "" on parse failure so callers silently skip rather than
             false-positive on devices with non-standard dumpsys output.

  [v2.14-14] ExplorerEngine.__init__ new kwarg: known_dropper_packages
             (list[str] | None). Populated from sentry dropper_events at
             construction time. explore_package() also registers each dropper
             package so foreground-shift detection works for payloads
             discovered during the session.

  [v2.14-15] Stuck handler updated: deadline now uses _intervention_timeout()
             (budget-gated). Timeout branch replaced bare _safe_back() +
             _relaunch() with _emergency_surface() → _suspend("stuck_form")
             cascade, tombing the dead state before any manual handoff.

  [v2.14-16] New Config keys (all .env-backed):
             EXPLORER_MAX_DEPTH_PASS1 (default 6)
             EXPLORER_MAX_DEPTH_PASS2 (default 10)
             EXPLORER_MAX_DEPTH_PASS3 (default 15)
             EXPLORER_STALE_THRESHOLD (default 5)

  [v2.14-17] explore_package() updated: registers package in
             _known_dropper_packages; clears _tombed_states, _branch_ledger,
             _consecutive_stale_visits, _current_max_depth on package switch
             (extends the existing v2.10 per-package reset contract).

  [v2.14-fix-1] _interact_with_element() now accepts xml_str kwarg.
             is_submit is suppressed when the current screen is an install
             dialog (_is_install_dialog()) or permission dialog
             (is_permission_dialog()). Previously, buttons like "Install"
             and "Allow" matched POSITIVE_ACTION_KEYWORDS and triggered the
             full form-submit machinery — the tap hands off to
             PackageInstaller / permission controller which navigates away,
             leaving the same dialog hash, producing false FormSubmit failure
             logs and two wasted retry cycles per dialog. Call site in _dfs()
             updated to pass xml_str.

Changes from v2.12:
  [v2.13-1] DoubleTapDetector: added ready_event parameter (threading.Event).
            Fires after the first line is received from the getevent subprocess,
            confirming the kernel input stream is actually open. GlobalInterrupt
            Listener now waits on ready_event (up to 2s) before announcing
            "armed" to the analyst. Eliminates the failure mode where the first
            double-tap was silently missed because getevent hadn't started
            streaming yet (300-800ms startup latency on most devices).

  [v2.13-2] DoubleTapDetector: STARTUP_GRACE window removed in favour of
            correct last_up_time=0.0 handling. The existing else branch already
            records the first UP event as last_up_time=now and continues. The
            only change is making the MIN_GAP check a `continue` (not `pass`)
            and the 0.0 case an explicit `continue` — same logic, cleaner flow.

  [v2.13-3] GlobalInterruptListener: single persistent stdin reader thread.
            Previous design spawned a new _reader thread inside _enter_watcher
            on every re-arm cycle, leading to N accumulated threads competing
            for sys.stdin. The current cycle's enter_detected event was never
            fired because the winning reader belonged to a stale prior cycle.
            Now a single GIL-stdin-reader thread runs for the lifetime of the
            listener and feeds all Enter keypresses into a shared _stdin_queue
            that each cycle's detection loop drains non-blocking.

  [v2.13-4] GlobalInterruptListener: dead-zone extended from 1.0s to
            DOUBLE_TAP_WINDOW + 0.3s (default 0.8s). The previous 1.0s was
            longer than DOUBLE_TAP_WINDOW, but the dead-zone started at
            pause_event.clear() time — which is BEFORE _handle_global_pause
            returns. The new dead-zone starts after pause_event is observed
            to be cleared (i.e. after DFS confirms it has resumed), so it
            reliably covers the tail of the analyst's "done" double-tap gesture.

  [v2.13-5] GlobalInterruptListener: last_enter_time reset to 0.0 at the
            start of every cycle AND after every dead-zone. Prevents a stale
            timestamp from a prior cycle's last Enter keypress producing a
            gap within DOUBLE_TAP_WINDOW when the first Enter of the new
            cycle arrives (which would look like a double-Enter false-positive).

Changes from v2.11:
  [v2.12-1] Global interrupt: GlobalInterruptListener daemon thread runs
            throughout the entire explore() / explore_package() session.
            Double-tap or double-Enter at any time to pause the DFS and
            enter human intervention mode. The engine resumes when the
            analyst double-taps or presses Enter again (same done-signal
            as the stuck handler). GlobalInterruptListener re-arms itself
            after each pause, ready for subsequent interrupts.

  [v2.12-2] DoubleTapDetector false-positive fix: added DOUBLE_TAP_MIN_GAP
            (default 0.08s). Two UP events separated by less than MIN_GAP
            are treated as the same physical tap's paired events and ignored.
            Fixes the gap=0.000s false-positive seen when BTN_TOUCH UP and
            ABS_MT_TRACKING_ID ffffffff both fired for a single finger lift.

  [v2.12-3] New Config key: EXPLORER_DOUBLE_TAP_MIN_GAP (default: 0.08s).
            Add to .env template alongside EXPLORER_DOUBLE_TAP_WINDOW.

  [v2.12-4] _handle_global_pause() method on ExplorerEngine. Reuses
            HumanInterventionMonitor + _enter_intervention_mode() /
            _exit_intervention_mode() for full parity with stuck-handler
            behaviour (screenshots, state pruning, action log, heartbeat).

  [v2.12-5] _dfs() checkpoints: global pause checked at top of each
            _dfs() call and before every element interaction in
            _interact_with_element().

Changes from v2.9/v2.10:
  [v2.11-1] Three-pass continuation loop in explore().
            explore() now runs up to 3 DFS passes over the main app.
            State is persistent across passes — state_mgr.visited,
            state_mgr.interaction_map, and _filled_fields are never
            cleared between passes. A single _phase_deadline (set
            externally by sentry before explore() is called) spans all
            three passes — no per-pass budget reset.

            Inter-pass gate: when _dfs(0) exhausts the DFS tree at the
            root, pass N+1's _dfs(0) finds no untried elements at the
            current screen, immediately enters stuck mode, and fires the
            existing HumanInterventionMonitor heartbeat loop. This IS the
            ~15s human review window — no new method is needed. The analyst
            double-taps the device (or presses Enter) to signal they have
            navigated to a missed branch; the engine resumes from the new
            screen and continues exploring from there.

            Per-pass intervention state is reset between passes so the
            stuck handler can re-fire on each pass:
              _stuck_entry_hash    → None
              _intervention_active → False
              _intervention_entry_hash → ""
              _retry_cancel        → fresh threading.Event()
            Persistent state (never reset between passes):
              state_mgr.visited, state_mgr.interaction_map, _filled_fields,
              _human_visited_states, _post_stuck_hashes

            Between-pass app health check:
              Pass 1: skipped (app freshly launched by sentry).
              Pass 2/3: if PID alive, stay on current screen. If PID gone,
              silent relaunch only (no state clear) — home screen is already
              visited so DFS immediately finds no untried elements, enters
              stuck mode, and opens the review window.

            Early exit: if _phase_timed_out() returns True after any pass,
            remaining passes are skipped. If stop_event is set (via the
            monkey-patched _timed_out()), the loop exits immediately.

  [v2.11-2] explore() progress logging for pass transitions.
            Emits: [EXPLORE] Pass N/3 starting (budget remaining: Xs/Ys) — pkg
                   [EXPLORE] Pass N/3 complete — M total states visited
                   [EXPLORE] Shared budget exhausted after pass N/3 — stopping

  [v2.11-3] Version banner updated to v2.11.

  Note: explore_package() is UNCHANGED. It is still called when the
  analyst runs sentry against a dropper directly (sentry --apk <pkg>).
  The severing of automatic dropper exploration is in sentry.py v2.9.

Changes from v2.8:
  [v2.9-1] Focus-aware field tap -- _tap_and_focus() replaces v2.7 IME-skip.
  [v2.9-2] Error-first form submit check -- PopupWindow setError() fix.
  [v2.9-3] Explicit human intervention signals -- DoubleTapDetector +
           CliDoneListener; passive hash-poller retained as fallback.
  [v2.9-4] generate_input() numeric fallback + sibling label resolution.
"""

import os
import re
import sys
import json
import time
import queue
import random
import hashlib
import threading
import subprocess
import xml.etree.ElementTree as ET
from collections import deque
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional

import frida
from colorama import Fore, Style, init as colorama_init
from dotenv import load_dotenv

colorama_init(autoreset=True)
load_dotenv()


# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────

class Config:
    ENV: str          = os.getenv("ENV", "dev")
    ADB_SERIAL: str   = os.getenv("ADB_SERIAL", "")
    FRIDA_SERVER: str = os.getenv("FRIDA_SERVER_PATH", "/data/local/tmp/frida-server")
    FRIDA_PORT: int   = int(os.getenv("FRIDA_PORT", "17392"))

    # Traversal limits
    MAX_DEPTH: int        = int(os.getenv("EXPLORER_MAX_DEPTH", "15"))   # [v2.5-E] raised from 6
    MAX_STATES: int       = int(os.getenv("EXPLORER_MAX_STATES", "80"))
    MAX_ACTIONS_PER_STATE: int = int(os.getenv("EXPLORER_MAX_ACTIONS", "12"))
    ACTION_DELAY: float   = float(os.getenv("EXPLORER_ACTION_DELAY", "1.2"))
    SETTLE_DELAY: float   = float(os.getenv("EXPLORER_SETTLE_DELAY", "1.2"))  # [v2.5-E] raised from 0.8
    TIMEOUT: int          = int(os.getenv("EXPLORER_TIMEOUT", "600"))   # seconds

    # Input generation seeds
    FAKE_EMAIL: str        = os.getenv("FAKE_EMAIL",        "testuser@analysis.lab")
    FAKE_PHONE: str        = os.getenv("FAKE_PHONE",        "9876543210")   # 10-digit Indian mobile
    FAKE_NAME: str         = os.getenv("FAKE_NAME",         "Test User")
    FAKE_PASSWORD: str     = os.getenv("FAKE_PASSWORD",     "Analyse99!")
    FAKE_USERNAME: str     = os.getenv("FAKE_USERNAME",     "testuser")

    # Financial cybercrime field seeds  [v2.6]
    FAKE_ATM_PIN: str      = os.getenv("FAKE_ATM_PIN",      "1234")           # 4-digit ATM/debit PIN
    FAKE_MPIN: str         = os.getenv("FAKE_MPIN",         "123456")         # 6-digit MPIN / app PIN
    FAKE_OTP: str          = os.getenv("FAKE_OTP",          "123456")         # 6-digit OTP
    FAKE_CARD_NUMBER: str  = os.getenv("FAKE_CARD_NUMBER",  "4111111111111111")  # Luhn-valid Visa test
    FAKE_CVV: str          = os.getenv("FAKE_CVV",          "123")
    FAKE_EXPIRY: str       = os.getenv("FAKE_EXPIRY",       "12/29")          # MM/YY
    FAKE_ACCOUNT: str      = os.getenv("FAKE_ACCOUNT",      "9876543210")     # 10-digit bank account
    FAKE_IFSC: str         = os.getenv("FAKE_IFSC",         "SBIN0001234")
    FAKE_UPI: str          = os.getenv("FAKE_UPI",          "testuser@upi")
    FAKE_AADHAAR: str      = os.getenv("FAKE_AADHAAR",      "222233334444")   # 12-digit
    FAKE_PAN: str          = os.getenv("FAKE_PAN",          "ABCDE1234F")
    FAKE_INCOME: str       = os.getenv("FAKE_INCOME",       "500000")         # annual income INR

    # [v2.3-2] How long to wait for manual app launch (--wait flag)
    WAIT_TIMEOUT: int  = int(os.getenv("EXPLORER_WAIT_TIMEOUT", "120"))  # seconds

    # [v2.7] Phase-specific timeouts -- cap Phase A so Phase B/C always run
    MAIN_APP_TIMEOUT: int    = int(os.getenv("EXPLORER_MAIN_APP_TIMEOUT", "300"))   # seconds for main app DFS
    DROPPER_TIMEOUT: int     = int(os.getenv("EXPLORER_DROPPER_TIMEOUT",  "180"))   # seconds per dropper DFS

    # [v2.7] Short settle delay for screens with no interactive elements
    SETTLE_DELAY_SHORT: float = float(os.getenv("EXPLORER_SETTLE_DELAY_SHORT", "0.5"))

    # [v2.7] Seconds in same state with no untried elements before stuck alarm
    STUCK_TIMEOUT: int       = int(os.getenv("EXPLORER_STUCK_TIMEOUT", "45"))

    # [v2.8] Form-submit retry config
    FORM_SUBMIT_RETRIES: int  = int(os.getenv("EXPLORER_FORM_SUBMIT_RETRIES", "2"))
    FORM_RETRY_DELAY: float   = float(os.getenv("EXPLORER_FORM_RETRY_DELAY", "1.5"))

    # [v2.9] Fake date-of-birth (was missing from Config, referenced in generate_input)
    FAKE_DOB: str             = os.getenv("FAKE_DOB", "01/01/1990")

    # [v2.9-3] Human intervention explicit-signal config
    # Seconds between two taps to count as a double-tap
    DOUBLE_TAP_WINDOW: float  = float(os.getenv("EXPLORER_DOUBLE_TAP_WINDOW", "0.5"))
    # [v2.12] Minimum gap between two UP events to count as separate taps.
    # Below this threshold = two events from the same physical tap (false-positive guard).
    DOUBLE_TAP_MIN_GAP: float = float(os.getenv("EXPLORER_DOUBLE_TAP_MIN_GAP", "0.08"))
    # How long to wait for getevent subprocess to confirm a tap event (ms budget)
    GETEVENT_FOCUS_WAIT: float = float(os.getenv("EXPLORER_GETEVENT_FOCUS_WAIT", "0.15"))

    # [v2.10] Intervention safety: max seconds to wait in intervention before
    # auto-aborting the current DFS branch and continuing.
    INTERVENTION_TIMEOUT: int   = int(os.getenv("EXPLORER_INTERVENTION_TIMEOUT", "360"))
    # Seconds between heartbeat "still waiting" prints during intervention.
    INTERVENTION_HEARTBEAT: int = int(os.getenv("EXPLORER_INTERVENTION_HEARTBEAT", "30"))

    # [v2.14] Graduated depth limits per pass (broad sweep → deep revisit)
    MAX_DEPTH_PASS1: int = int(os.getenv("EXPLORER_MAX_DEPTH_PASS1", "6"))
    MAX_DEPTH_PASS2: int = int(os.getenv("EXPLORER_MAX_DEPTH_PASS2", "10"))
    MAX_DEPTH_PASS3: int = int(os.getenv("EXPLORER_MAX_DEPTH_PASS3", "15"))

    # [v2.14] Consecutive stale-visit threshold before emergency surface
    STALE_VISIT_THRESHOLD: int = int(os.getenv("EXPLORER_STALE_THRESHOLD", "5"))


# ─────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────

@dataclass
class UIElement:
    """A single interactive element extracted from the UI XML hierarchy."""
    index:         int
    elem_class:    str        # e.g. "android.widget.Button"
    resource_id:   str        # e.g. "com.evil.app:id/login_btn"
    text:          str
    content_desc:  str
    bounds:        str        # "[x1,y1][x2,y2]"
    clickable:     bool
    long_clickable: bool
    scrollable:    bool
    checkable:     bool
    checked:       bool
    enabled:       bool
    is_text_field: bool       # EditText or subclass
    hint:          str        # resource hint text if available
    input_type:    str = ""   # [v2.9-4a] android:inputType attribute value
    center_x:      int = 0
    center_y:      int = 0
    interest_score: float = 0.0   # higher = more interesting to tap

    def label(self) -> str:
        """Human-readable element label for logging."""
        parts = [p for p in [self.text, self.content_desc,
                              self.resource_id.split("/")[-1]] if p]
        return parts[0] if parts else self.elem_class.split(".")[-1]

    def key(self) -> str:
        """Stable identifier for deduplication within a state."""
        return f"{self.resource_id}|{self.text}|{self.bounds}"


@dataclass
class UIAction:
    """A single action taken during traversal."""
    timestamp:      str
    action_type:    str       # "tap" | "long_tap" | "scroll_down" | "scroll_up"
                              # "input_text" | "back" | "accept_permission"
                              # "human_navigation" | "form_submit_success"
                              # "form_submit_failure"
    element_label:  str
    element_class:  str
    bounds:         str
    input_value:    str = ""  # for input_text actions
    new_state_hash: str = ""  # state hash AFTER the action
    triggered_network: bool = False
    triggered_dialog:  bool = False
    source:         str = "explorer"  # [v2.8-C] "explorer" | "human"


@dataclass
class UIState:
    """A unique UI state encountered during traversal."""
    state_hash:     str
    timestamp:      str
    activity:       str
    screenshot_path: str      # "" if tier 3
    xml_path:       str
    elements:       list[UIElement]  = field(default_factory=list)
    actions_taken:  list[str] = field(default_factory=list)  # element keys tried
    depth:          int  = 0
    is_dialog:      bool = False
    is_permission_dialog: bool = False


@dataclass
class ExplorerSession:
    """Complete output of Phase 3. Passed to Phase 4."""
    package_name:   str
    session_start:  str = ""
    session_end:    str = ""
    screenshot_tier: int = 3
    states_visited: int  = 0
    total_actions:  int  = 0
    unique_activities: list[str]   = field(default_factory=list)
    permission_dialogs_accepted: int = 0
    forms_filled:   int  = 0
    crashes_recovered: int = 0
    # [v2.8-A] Form-submit outcome tracking
    form_submits_attempted:  int = 0
    form_submits_succeeded:  int = 0
    form_submit_failures:    list[dict] = field(default_factory=list)
    states:         list[UIState]  = field(default_factory=list)
    actions:        list[UIAction] = field(default_factory=list)
    errors:         list[str]      = field(default_factory=list)
    warnings:       list[str]      = field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# FRIDA FLAG_SECURE BYPASS SCRIPT (Tier 2 screenshots)
# Hooks Window.setFlags and WindowManager.addView to strip
# FLAG_SECURE (0x2000) so screencap works without global disable.
# ─────────────────────────────────────────────────────────────

FRIDA_FLAG_SECURE_JS = """
Java.perform(function() {
    // Hook Window.setFlags -- strip FLAG_SECURE on every call
    try {
        var Window = Java.use('android.view.Window');
        Window.setFlags.implementation = function(flags, mask) {
            flags = flags & ~0x2000;  // remove FLAG_SECURE
            mask  = mask  & ~0x2000;
            return this.setFlags(flags, mask);
        };
    } catch(e) {}

    // Hook WindowManager.addView -- strip FLAG_SECURE from LayoutParams
    try {
        var WM = Java.use('android.view.WindowManagerImpl');
        WM.addView.overload(
            'android.view.View',
            'android.view.ViewGroup$LayoutParams'
        ).implementation = function(view, params) {
            try { params.flags.value = params.flags.value & ~0x2000; } catch(e) {}
            return this.addView(view, params);
        };
    } catch(e) {}

    // Hook Activity.onCreate to clear the flag early
    try {
        var Activity = Java.use('android.app.Activity');
        Activity.onCreate.overload('android.os.Bundle').implementation = function(b) {
            this.onCreate(b);
            try {
                this.getWindow().clearFlags(0x2000);
            } catch(e) {}
        };
    } catch(e) {}
});
"""


# ─────────────────────────────────────────────────────────────
# ELEMENT INTEREST SCORING
# Higher score = more likely to surface new behaviour
# ─────────────────────────────────────────────────────────────

# Class names that are highly likely to do something interesting
HIGH_INTEREST_CLASSES = {
    "android.widget.Button",
    "android.widget.ImageButton",
    "androidx.appcompat.widget.AppCompatButton",
    "android.widget.CheckBox",
    "android.widget.RadioButton",
    "android.widget.Switch",
    "android.widget.ToggleButton",
    "android.widget.Spinner",
}

# Resource ID keywords that suggest security-relevant actions
SENSITIVE_ID_KEYWORDS = [
    "login", "signin", "sign_in", "register", "signup", "submit",
    "send", "upload", "share", "permission", "allow", "grant",
    "access", "enable", "activate", "confirm", "verify", "agree",
    "accept", "continue", "next", "proceed", "ok", "yes",
    "camera", "mic", "location", "contact", "storage", "sms",
    "record", "capture", "photo", "video",
]

# Text content that suggests a permission or security action
SENSITIVE_TEXT_KEYWORDS = [
    "allow", "accept", "agree", "ok", "yes", "continue", "next",
    "permit", "grant", "enable", "proceed", "confirm",
    "send", "share", "upload", "submit",
]

# Permission dialog package
PERMISSION_DIALOG_PACKAGES = [
    "com.android.permissioncontroller",
    "com.android.packageinstaller",
    "com.google.android.permissioncontroller",
]

# [v2.4-1] Button text that should be acted on BEFORE negative actions.
# Matched case-insensitively against elem.text and elem.content_desc.
POSITIVE_ACTION_KEYWORDS = [
    "install", "update", "allow", "accept", "proceed", "ok", "yes",
    "continue", "confirm", "agree", "permit", "grant", "enable",
    "next", "open", "launch", "start", "activate",
]

# Button text that should be deprioritised (tried last or skipped first).
NEGATIVE_ACTION_KEYWORDS = [
    "cancel", "deny", "skip", "close", "dismiss", "no", "not now",
    "decline", "refuse", "block", "back",
]


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
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def banner(text: str, char: str = "─") -> None:
    width = 62
    print(f"\n{Fore.GREEN}{char * width}\n  {text}\n{char * width}{Style.RESET_ALL}")


def ok(msg: str)    -> None: print(f"  {Fore.GREEN}v{Style.RESET_ALL}  {msg}")
def warn(msg: str)  -> None: print(f"  {Fore.YELLOW}!{Style.RESET_ALL}  {msg}")
def err(msg: str)   -> None: print(f"  {Fore.RED}x{Style.RESET_ALL}  {msg}")
def info(msg: str)  -> None: print(f"  {Fore.CYAN}->{Style.RESET_ALL}  {msg}")
def skip(msg: str)  -> None: print(f"  {Fore.MAGENTA}>>{Style.RESET_ALL}  {msg}")


def _is_soft_keyboard_shown() -> bool:
    """
    [v2.7] Check whether the Android soft keyboard (IME) is currently visible.

    Uses `dumpsys input_method` and looks for `mInputShown=true`.
    This is a fast single-ADB-call check (~50ms) with no false positives on
    physical devices running Android 9-14.

    Returns True if the keyboard is up, False otherwise or on parse failure.
    """
    r = adb("shell", "dumpsys", "input_method")
    # The line format is:  mInputShown=true  (or false)
    m = re.search(r'mInputShown\s*=\s*(true|false)', r.stdout)
    if m:
        return m.group(1) == "true"
    return False


def _settle(elements: list | None = None) -> None:
    """
    [v2.7] Dynamic settle delay.

    Short path (SETTLE_DELAY_SHORT, default 0.5s): used when the caller
    passes the current element list AND no interactive elements are present
    (nothing to wait for -- page is static or loading indicator only).

    Normal path (SETTLE_DELAY, default 1.2s): used for all interactive
    screens and when no element list is provided.

    The short path avoids accumulating 1.2s × many non-interactive transitions
    which visibly slows the explorer on splash/loading screens.
    """
    if elements is not None:
        has_interactive = any(
            e.clickable or e.long_clickable or e.is_text_field or e.scrollable
            for e in elements
        )
        if not has_interactive:
            time.sleep(Config.SETTLE_DELAY_SHORT)
            return
    time.sleep(Config.SETTLE_DELAY)


def state(msg: str) -> None: print(f"  {Fore.WHITE}*{Style.RESET_ALL}  {msg}")
def action(msg: str)-> None: print(f"  {Fore.CYAN}>{Style.RESET_ALL}  {msg}")
def alert(msg: str) -> None:
    print(f"\n  {Fore.RED}{'!' * 58}\n  !! {msg}\n  {'!' * 58}{Style.RESET_ALL}\n")


# ─────────────────────────────────────────────────────────────
# [v2.9-1] FOCUS-AWARE FIELD TAP HELPER
# ─────────────────────────────────────────────────────────────

def _tap_and_focus(elem: "UIElement", xml_dir: Path) -> bool:
    """
    [v2.9-1] Tap a text field and verify that focus actually transferred to it.

    The v2.8 batch pre-pass skipped the tap whenever the soft keyboard was
    showing.  This was the wrong heuristic: IME visible means a DIFFERENT field
    has focus.  Skipping the tap sent input_text() output to that other field,
    corrupting it.

    Correct rule:
      - If the TARGET field already has focused="true" in the current XML:
          skip the tap, the field is ready, return True.
      - Otherwise: ALWAYS tap the field, even when the keyboard is visible.
          Wait briefly, then dump XML and check focused="true" on the target.
          If focus confirmed: return True.
          If focus NOT confirmed after one retry tap: return False (skip field).

    This prevents the keyboard-overlay tap-landing bug (v2.7 fix) while also
    preventing the blind-input-to-wrong-field bug (v2.9-1 fix).
    """
    # ── Check if already focused ──────────────────────────────
    check_path = str(xml_dir / f"_focus_check_{int(time.time() * 1000)}.xml")
    current_xml = dump_ui_xml(check_path)
    if current_xml:
        try:
            root = ET.fromstring(current_xml)
            for node in root.iter("node"):
                if (node.attrib.get("resource-id", "") == elem.resource_id
                        and node.attrib.get("focused", "false") == "true"):
                    info(f"  [Focus] '{elem.label()}' already focused -- typing directly")
                    return True
        except ET.ParseError:
            pass

    # ── Tap and verify focus transferred ─────────────────────
    for attempt in range(2):
        adb("shell", "input", "tap", str(elem.center_x), str(elem.center_y))
        time.sleep(Config.GETEVENT_FOCUS_WAIT + 0.15)   # short settle for focus transfer

        verify_path = str(xml_dir / f"_focus_verify_{int(time.time() * 1000)}.xml")
        verify_xml = dump_ui_xml(verify_path)
        if not verify_xml:
            return attempt == 0  # if first attempt and no XML, proceed optimistically

        try:
            root = ET.fromstring(verify_xml)
            for node in root.iter("node"):
                if (node.attrib.get("resource-id", "") == elem.resource_id
                        and node.attrib.get("focused", "false") == "true"):
                    info(f"  [Focus] '{elem.label()}' focus confirmed (attempt {attempt+1})")
                    return True
        except ET.ParseError:
            pass

        if attempt == 0:
            warn(f"  [Focus] '{elem.label()}' focus not confirmed -- retrying tap")

    warn(f"  [Focus] '{elem.label()}' could not acquire focus -- skipping field")
    return False


# ─────────────────────────────────────────────────────────────
# [v2.9-4b] SIBLING LABEL RESOLVER
# ─────────────────────────────────────────────────────────────

def _get_sibling_label(xml_str: str, elem: "UIElement") -> str:
    """
    [v2.9-4b] Walk backwards through an EditText's sibling nodes to find the
    nearest preceding TextView with non-empty, non-hint text.

    Many Indian fintech malware APKs place the field label in a separate
    TextView above the EditText rather than using android:hint.  When the
    EditText has a generic resource_id (e.g. "edit_text_1"), generate_input()
    has no signal to map the field -- unless we provide the label text.

    Returns the label string (stripped), or "" if none found.
    """
    if not xml_str:
        return ""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return ""

    # Flatten the tree preserving document order
    all_nodes = list(root.iter("node"))

    # Find the index of our target EditText
    target_idx = -1
    for i, node in enumerate(all_nodes):
        if (node.attrib.get("resource-id", "") == elem.resource_id
                and "EditText" in node.attrib.get("class", "")):
            target_idx = i
            break

    if target_idx < 0:
        return ""

    # Walk backwards to find nearest preceding non-empty TextView
    for i in range(target_idx - 1, max(target_idx - 8, -1), -1):
        node = all_nodes[i]
        cls  = node.attrib.get("class", "")
        txt  = node.attrib.get("text", "").strip()
        if "TextView" in cls and txt and txt != node.attrib.get("hint", ""):
            return txt.lower()

    return ""


# ─────────────────────────────────────────────────────────────
# REPORT LOADERS
# ─────────────────────────────────────────────────────────────

def load_sentry_report(path: str) -> dict:
    """
    [v2.3-3] No longer aborts on missing file -- returns {} so --apk mode
    works without a prior Phase 2 run.
    """
    p = Path(path)
    if not p.exists():
        warn(f"Sentry report not found: {path} -- running without Phase 2 context.")
        return {}
    data = json.loads(p.read_text())
    ok(f"Sentry report loaded   : {path}")
    ok(f"Package                : {data.get('package_name', '?')}")
    s = data.get("summary", {})
    ok(f"Network connections    : {s.get('total_network_connections', 0)}")
    ok(f"Exfil events (Phase 2) : {s.get('total_exfiltration_events', 0)}")
    if s.get("root_detected"):
        warn("Phase 2 reported root detection -- app may behave differently")
    return data


def load_static_report(path: str) -> dict:
    """[v2.3-3] Already non-fatal -- returns {} on missing file."""
    p = Path(path)
    if not p.exists():
        warn(f"Static report not found: {path} -- some fields will be empty")
        return {}
    data = json.loads(p.read_text())
    ok(f"Static report loaded   : {path}")
    return data


# ─────────────────────────────────────────────────────────────
# [v2.3-4] MANUAL LAUNCH WAIT HELPER
# ─────────────────────────────────────────────────────────────

def _wait_for_process(package_name: str,
                      timeout: int = 120,
                      poll_interval: float = 2.0) -> list[int]:
    """
    Poll for the app process until it appears or timeout is reached.
    Used when --wait is passed: the analyst opens the app manually
    (or via notification/link tap) and explorer starts the moment
    the process is detected.

    Prints a live countdown line that overwrites itself in the terminal.
    Returns list of PIDs on success, empty list on timeout.
    """
    banner("STARTUP // Waiting for Manual App Launch", "─")
    print(f"  {Fore.YELLOW}Open {package_name} on the device now.{Style.RESET_ALL}")
    print(f"  Watching for process -- timeout: {timeout}s\n")

    deadline = time.time() + timeout
    last_line_len = 0

    while time.time() < deadline:
        remaining = int(deadline - time.time())

        # Try pidof first
        r = adb("shell", "pidof", package_name)
        raw = r.stdout.strip()
        if raw:
            pids = [int(p) for p in raw.split() if p.isdigit()]
            if pids:
                # Clear the countdown line
                print(f"\r{' ' * last_line_len}\r", end="", flush=True)
                ok(f"Process detected! PID(s): {pids}")
                return pids

        # ps -A fallback
        ps = adb("shell", "ps", "-A")
        if package_name in ps.stdout:
            pids = []
            for line in ps.stdout.splitlines():
                if package_name in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        pids.append(int(parts[1]))
            if pids:
                print(f"\r{' ' * last_line_len}\r", end="", flush=True)
                ok(f"Process detected via ps -A! PID(s): {pids}")
                return pids

        # Countdown display
        msg = f"  Waiting for {package_name}... {remaining}s remaining"
        print(f"\r{msg}", end="", flush=True)
        last_line_len = len(msg)
        time.sleep(poll_interval)

    print(f"\r{' ' * last_line_len}\r", end="", flush=True)
    warn(f"Timeout after {timeout}s -- {package_name} process not detected.")
    warn("If the app is running but not detected, check: adb shell ps -A | grep <pkg>")
    return []


# ─────────────────────────────────────────────────────────────
# SCREENSHOT CAPTURE
# ─────────────────────────────────────────────────────────────

def capture_screenshot(save_path: str, tier: int,
                       frida_session=None) -> bool:
    """
    Capture the current screen.

    Tier 1 -- FLAG_SECURE globally disabled by Magisk:
      adb screencap works directly.

    Tier 2 -- Frida FLAG_SECURE hook active:
      Frida has already patched Window.setFlags, so screencap works
      the same as Tier 1 from ADB's perspective.  The difference is
      that the Frida hook must be loaded before this is called.

    Tier 3 -- No bypass available:
      Returns False immediately; caller records XML-only state.
    """
    if tier == 3:
        return False

    device_path = "/sdcard/_explorer_screen.png"
    r = adb("shell", "screencap", "-p", device_path)
    if r.returncode != 0:
        warn(f"screencap failed: {r.stderr.strip()}")
        return False

    pull = adb("pull", device_path, save_path)
    adb("shell", "rm", "-f", device_path)

    if pull.returncode == 0 and Path(save_path).exists():
        return True

    warn(f"Screenshot pull failed: {pull.stderr.strip()}")
    return False


# ─────────────────────────────────────────────────────────────
# UI XML DUMP
# ─────────────────────────────────────────────────────────────

def dump_ui_xml(save_path: str) -> Optional[str]:
    """
    Dump the current UI hierarchy via uiautomator.
    Returns the XML string if successful, None on failure.
    """
    device_path = "/sdcard/_explorer_ui.xml"
    r = adb("shell", "uiautomator", "dump", device_path)
    if r.returncode != 0 or "ERROR" in r.stdout:
        # Fallback: some devices need --compressed flag removed
        r = adb("shell", "uiautomator", "dump", "--compressed", device_path)
        if r.returncode != 0:
            warn(f"uiautomator dump failed: {r.stdout.strip()}")
            return None

    pull = adb("pull", device_path, save_path)
    adb("shell", "rm", "-f", device_path)

    if pull.returncode != 0 or not Path(save_path).exists():
        warn("XML pull failed")
        return None

    return Path(save_path).read_text(encoding="utf-8", errors="replace")


def hash_xml(xml_str: str) -> str:
    """
    Canonical hash of a UI state. Strips dynamic attributes (scroll position,
    index) so functionally identical states hash the same regardless of
    minor rendering differences.
    """
    # Strip volatile attributes
    clean = re.sub(r'scrollX="\d+"', '', xml_str)
    clean = re.sub(r'scrollY="\d+"', '', clean)
    clean = re.sub(r' index="\d+"', '', clean)
    # Collapse any runs of whitespace left by the removals
    clean = re.sub(r'  +', ' ', clean)
    return hashlib.md5(clean.encode()).hexdigest()[:16]


# ─────────────────────────────────────────────────────────────
# ELEMENT FINDER
# ─────────────────────────────────────────────────────────────

def _parse_bounds(bounds_str: str) -> tuple[int, int, int, int]:
    """Parse '[x1,y1][x2,y2]' -> (x1, y1, x2, y2)."""
    nums = re.findall(r'\d+', bounds_str)
    if len(nums) == 4:
        return int(nums[0]), int(nums[1]), int(nums[2]), int(nums[3])
    return 0, 0, 0, 0


def _score_element(elem: UIElement) -> float:
    score = 0.0

    # Base score by action type
    if elem.is_text_field:
        score += 3.0
    elif elem.clickable:
        score += 2.0
    elif elem.scrollable:
        score += 1.0

    # High-interest class
    if elem.elem_class in HIGH_INTEREST_CLASSES:
        score += 2.0

    # Sensitive resource ID
    rid_lower = elem.resource_id.lower()
    for kw in SENSITIVE_ID_KEYWORDS:
        if kw in rid_lower:
            score += 3.0
            break

    # Sensitive text
    text_lower = (elem.text + " " + elem.content_desc).lower()
    for kw in SENSITIVE_TEXT_KEYWORDS:
        if kw in text_lower:
            score += 2.5
            break

    # Penalise system chrome elements
    if "status_bar" in rid_lower or "navigation" in rid_lower:
        score -= 5.0

    # Penalise disabled elements
    if not elem.enabled:
        score -= 10.0

    # Penalise zero-size elements
    x1, y1, x2, y2 = _parse_bounds(elem.bounds)
    if (x2 - x1) <= 0 or (y2 - y1) <= 0:
        score -= 10.0

    return score


def parse_elements(xml_str: str) -> list[UIElement]:
    """
    Parse a uiautomator XML hierarchy into a list of UIElement objects.
    Only returns elements that are potentially interactive.
    """
    elements = []
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        warn(f"XML parse error: {e}")
        return elements

    idx = 0
    for node in root.iter("node"):
        a = node.attrib
        clickable      = a.get("clickable", "false") == "true"
        long_clickable = a.get("long-clickable", "false") == "true"
        scrollable     = a.get("scrollable", "false") == "true"
        checkable      = a.get("checkable", "false") == "true"
        enabled        = a.get("enabled", "true") == "true"
        is_text_field  = "EditText" in a.get("class", "")

        # Skip elements that can't do anything
        if not any([clickable, long_clickable, scrollable, checkable, is_text_field]):
            continue

        bounds  = a.get("bounds", "[0,0][0,0]")
        x1, y1, x2, y2 = _parse_bounds(bounds)
        cx = (x1 + x2) // 2
        cy = (y1 + y2) // 2

        elem = UIElement(
            index=idx,
            elem_class=a.get("class", ""),
            resource_id=a.get("resource-id", ""),
            text=a.get("text", ""),
            content_desc=a.get("content-desc", ""),
            bounds=bounds,
            clickable=clickable,
            long_clickable=long_clickable,
            scrollable=scrollable,
            checkable=checkable,
            checked=a.get("checked", "false") == "true",
            enabled=enabled,
            is_text_field=is_text_field,
            hint=a.get("hint", ""),
            input_type=a.get("inputType", ""),   # [v2.9-4a]
            center_x=cx,
            center_y=cy,
        )
        elem.interest_score = _score_element(elem)
        elements.append(elem)
        idx += 1

    # Sort by interest score descending
    elements.sort(key=lambda e: e.interest_score, reverse=True)
    return elements


def get_current_activity() -> str:
    """Get the foreground activity via dumpsys."""
    r = adb("shell", "dumpsys", "activity", "activities")
    # Look for mResumedActivity or mFocusedActivity
    for pattern in [r'mResumedActivity.*ActivityRecord\{[^}]+\s+([\w./]+)\s',
                    r'mFocusedActivity.*ActivityRecord\{[^}]+\s+([\w./]+)\s',
                    r'realActivity=([\w./]+)']:
        m = re.search(pattern, r.stdout)
        if m:
            return m.group(1)
    return ""


def get_foreground_package() -> str:
    """
    [v2.14] Return the package name currently in the foreground.

    Parses mCurrentFocus from dumpsys window.  Returns "" on parse failure
    so callers can silently skip rather than false-positive.
    """
    r = adb("shell", "dumpsys", "window", "windows")
    m = re.search(r'mCurrentFocus=Window\{[^}]+\s+([\w.]+)/[\w.]+\}', r.stdout)
    if m:
        return m.group(1)
    # Fallback: mFocusedApp
    m = re.search(r'mFocusedApp=.*Token\{[^}]+\s+([\w.]+)/', r.stdout)
    if m:
        return m.group(1)
    return ""


def is_permission_dialog(xml_str: str) -> bool:
    """Detect if the current screen is an Android permission dialog."""
    for pkg in PERMISSION_DIALOG_PACKAGES:
        if pkg in xml_str:
            return True
    # Content-based detection
    permission_markers = [
        "Allow", "ALLOW", "Deny", "DENY", "permission",
        "grant", "access to your", "access your",
    ]
    xml_lower = xml_str.lower()
    hits = sum(1 for m in permission_markers if m.lower() in xml_lower)
    return hits >= 2


def is_dialog_overlay(xml_str: str) -> bool:
    """Detect any overlay dialog (AlertDialog, BottomSheet, etc.)."""
    return any(c in xml_str for c in [
        "FrameLayout", "AlertController", "BottomSheet",
        "PopupWindow", "Dialog",
    ])


def _is_install_dialog(xml_str: str) -> bool:
    """
    [v2.4-3] Detect an APK install confirmation dialog
    ("Do you want to install this app?" / "Install unknown apps").
    Used to deduplicate -- once acted on, never act again for same state.
    """
    markers = ["install unknown apps", "do you want to install",
               "install this app", "install anyway"]
    xml_lower = xml_str.lower()
    return any(m in xml_lower for m in markers)


def _prioritise_elements(elements: list) -> list:
    """
    [v2.4-1] Re-sort elements so positive-action buttons (Install, Allow,
    Proceed, OK ...) always come before negative-action buttons (Cancel,
    Deny, Skip ...), while preserving the relative interest-score ordering
    within each group.

    [v2.5-B] Context-aware penalty: if there are still unfilled EditText
    fields on screen (text == "" or text == hint), positive-action/submit
    buttons are demoted below neutral elements. This prevents the engine
    from tapping PROCEED before the form is filled, which would either
    trigger a validation error or navigate away from an incomplete state.

    Groups (ascending priority):
      0 = negative action  (tried last)
      1 = neutral          (no keyword match)
      2 = positive action  (tried first, unless form is incomplete)
    """
    # [v2.5-B] Detect empty text fields -- text="" or text matches hint text
    has_empty_fields = any(
        e.is_text_field and (e.text == "" or e.text == e.hint)
        for e in elements
    )

    def _group(elem) -> int:
        label = (elem.text + " " + elem.content_desc).lower()
        if any(k in label for k in POSITIVE_ACTION_KEYWORDS):
            # [v2.5-B] Demote submit/proceed buttons when form is still empty
            if has_empty_fields:
                return 1   # treat as neutral until fields are filled
            return 2
        if any(k in label for k in NEGATIVE_ACTION_KEYWORDS):
            return 0
        return 1

    # Stable sort: primary key = group (desc), secondary = interest_score (desc)
    return sorted(elements, key=lambda e: (_group(e), e.interest_score),
                  reverse=True)


# ─────────────────────────────────────────────────────────────
# INPUT GENERATOR
# ─────────────────────────────────────────────────────────────

def generate_input(elem: UIElement, sibling_label: str = "") -> str:
    """
    Generate a plausible input value for an EditText element based on its
    resource ID, hint, content description, and current text.

    Covers standard fields, Indian identity fields, and the full range of
    fields encountered in financial-cybercrime APKs (banking, UPI, card,
    loan, insurance, wallet, crypto, KYC, and social-engineering flows).

    [v2.6] Ordering is intentional -- more specific patterns must appear
    BEFORE broader ones that share substrings (e.g. "atm pin" before
    "password"; "card number" before generic "number"; "contact" before
    the generic phone branch so it resolves to digits not a name).

    [v2.9-4b] sibling_label: optional label text from the nearest preceding
    TextView sibling (resolved by _get_sibling_label).  Appended to hints
    so fields with generic resource_ids but descriptive labels are mapped.

    [v2.9-4a] Numeric inputType fallback: if no keyword matched but the
    field's inputType attribute signals numeric input, return FAKE_PHONE
    (10-digit) instead of "testvalue".
    """
    hints = " ".join([
        elem.resource_id.lower(),
        elem.hint.lower(),
        elem.content_desc.lower(),
        elem.text.lower(),
        sibling_label.lower(),   # [v2.9-4b] sibling label injected here
    ])

    # ── Email ──────────────────────────────────────────────────────────────
    if any(k in hints for k in ["email", "e-mail", "mail id", "mailid"]):
        return Config.FAKE_EMAIL

    # ── ATM / Debit / Credit card PIN  (must precede generic "pin/password") ─
    if any(k in hints for k in [
        "atm pin", "atm_pin", "atmpin",
        "debit pin", "debit_pin", "card pin", "card_pin",
        "transaction pin", "txn pin", "t-pin", "tpin",
    ]):
        return Config.FAKE_ATM_PIN    # 4-digit numeric

    # ── MPIN / App PIN / Login PIN  (6-digit; before "password") ───────────
    if any(k in hints for k in [
        "mpin", "m-pin", "m pin",
        "app pin", "apppin", "login pin",
        "security pin", "secpin",
    ]):
        return Config.FAKE_MPIN       # 6-digit numeric

    # ── Generic PIN  (4-digit; still before "password") ────────────────────
    if "pin" in hints.split() or any(k in hints for k in [
        " pin", "_pin", "pin ", "pin_", "enterpin", "enter pin",
    ]):
        return Config.FAKE_ATM_PIN    # 4-digit numeric

    # ── OTP / verification code  (before generic "code") ───────────────────
    if any(k in hints for k in [
        "otp", "one time", "onetime", "one-time",
        "verification code", "verificationcode", "verify code",
        "auth code", "authcode", "sms code", "smscode",
    ]):
        return Config.FAKE_OTP        # 6-digit numeric

    # ── Password / passphrase / secret ────────────────────────────────────
    if any(k in hints for k in [
        "password", "passwd", "passcode", "passphrase",
        "pass ", " pass", "secret", "credential",
        "new password", "confirm password", "re-enter",
    ]):
        return Config.FAKE_PASSWORD

    # ── Card number  (16-digit; before generic "number") ───────────────────
    if any(k in hints for k in [
        "card number", "cardnumber", "card_number", "card no",
        "card_no", "cardno", "debit card", "credit card",
        "card detail", "card digit",
        "pan number",   # card PAN (not income-tax PAN -- context differs)
    ]):
        return Config.FAKE_CARD_NUMBER  # 16-digit Luhn-valid

    # ── CVV / CVC / security code ──────────────────────────────────────────
    if any(k in hints for k in [
        "cvv", "cvc", "csc", "cvv2", "cvc2",
        "security code", "securitycode", "card security",
        "3 digit", "3digit", "back of card",
    ]):
        return Config.FAKE_CVV        # 3-digit numeric

    # ── Card expiry ────────────────────────────────────────────────────────
    if any(k in hints for k in [
        "expiry", "expiry date", "expirydate", "expiry_date",
        "expiration", "expire", "valid thru", "valid till",
        "valid upto", "mm/yy", "mm / yy", "mmyy", "exp", "exp date",
        "expdate", "card valid",
    ]):
        return Config.FAKE_EXPIRY     # MM/YY

    # ── UPI / VPA ──────────────────────────────────────────────────────────
    if any(k in hints for k in [
        "upi", "vpa", "upi id", "upiid", "upi_id",
        "upi address", "upi handle", "virtual payment",
        "bhim", "gpay", "phonepe id", "paytm upi",
    ]):
        return Config.FAKE_UPI

    # ── Phone / Mobile / Contact  (10-digit numeric) ───────────────────────
    if any(k in hints for k in [
        "phone", "mobile", "mobile number", "mobile no", "mobile_no", "mob no",
        "mob_no", "mobno", "mob", "phone no", "phone_no", "phoneno",
        "contact no", "contact_no", "contactno",
        "contact number", "contact_number",
        "ph no", "ph_no", "phno", "ph.", "cell",
        "tel", "telephone", "whatsapp", "registered number",
    ]):
        return Config.FAKE_PHONE      # 10-digit

    # ── Bank account number  (10-digit; before generic "number") ───────────
    if any(k in hints for k in [
        "account number", "account_number", "accountnumber",
        "account no", "account_no", "accountno",
        "acc number", "acc_number", "accnumber",
        "acc no", "acc_no", "accno",
        "bank account", "bankaccount", "bank_account",
        "beneficiary account", "savings account", "current account",
    ]):
        return Config.FAKE_ACCOUNT    # 10-digit numeric

    # ── IFSC code ──────────────────────────────────────────────────────────
    if any(k in hints for k in [
        "ifsc", "ifsc code", "ifsccode", "ifsc_code",
        "bank code", "branch code",
    ]):
        return Config.FAKE_IFSC

    # ── Aadhaar ────────────────────────────────────────────────────────────
    if any(k in hints for k in [
        "aadhaar", "aadhar", "adhar", "adhaar",
        "aadhaar number", "uid number", "uidai",
        "aadhaar card", "aadhar card",
    ]):
        return Config.FAKE_AADHAAR    # 12-digit numeric

    # ── Income-tax PAN  (alphanumeric; after card-PAN above) ───────────────
    if any(k in hints for k in [
        "pan card", "pancard", "pan_card",
        "income tax pan", "it pan", "pan number",
        "permanent account",
    ]) or (hints.strip() == "pan"):
        return Config.FAKE_PAN

    # ── GST / GSTIN ────────────────────────────────────────────────────────
    if any(k in hints for k in ["gst", "gstin", "gst number", "gstnumber"]):
        return "27ABCDE1234F1Z5"

    # ── Username / User ID ─────────────────────────────────────────────────
    if any(k in hints for k in [
        "username", "user name", "user_name",
        "user id", "userid", "user_id",
        "login id", "loginid", "customer id", "customerid",
        "member id", "memberid", "client id",
    ]):
        return Config.FAKE_USERNAME

    # ── Name fields ────────────────────────────────────────────────────────
    if any(k in hints for k in ["first name", "firstname", "fname", "first_name"]):
        return Config.FAKE_NAME.split()[0]
    if any(k in hints for k in [
        "last name", "lastname", "lname", "last_name",
        "surname", "family name",
    ]):
        return Config.FAKE_NAME.split()[-1]
    if any(k in hints for k in [
        "full name", "fullname", "full_name",
        "account name", "account holder",
        "nominee name", "beneficiary name",
        "guardian name",
    ]):
        return Config.FAKE_NAME
    if any(k in hints for k in ["name"]):
        return Config.FAKE_NAME

    # ── Relation / nominee relationship ────────────────────────────────────
    if any(k in hints for k in [
        "relation", "relationship", "nominee relation",
        "relation with", "relation to",
    ]):
        return "Self"

    # ── Parent / guardian name ─────────────────────────────────────────────
    if any(k in hints for k in [
        "mother", "father", "parent", "guardian",
        "spouse", "husband", "wife",
    ]):
        return "Test Parent"

    # ── Date of birth ──────────────────────────────────────────────────────
    if any(k in hints for k in [
        "dob", "date of birth", "dateofbirth", "birth date",
        "birthdate", "birthday", "born", "birth_date",
        "dd/mm/yyyy", "dd-mm-yyyy",
    ]):
        return Config.FAKE_DOB        # 01/01/1990

    # ── Generic date / year ────────────────────────────────────────────────
    if any(k in hints for k in ["date", "year", "month"]):
        return Config.FAKE_DOB

    # ── Age ────────────────────────────────────────────────────────────────
    if any(k in hints for k in ["age", "your age", "age years"]):
        return "25"

    # ── Income / salary / financial capacity ───────────────────────────────
    if any(k in hints for k in [
        "income", "annual income", "annual_income",
        "salary", "ctc", "in hand", "monthly income",
        "turnover", "revenue", "net worth", "networth",
        "loan amount", "loan_amount", "required amount",
    ]):
        return Config.FAKE_INCOME     # 500000

    # ── Amount / price (generic transaction) ───────────────────────────────
    if any(k in hints for k in [
        "amount", "money", "price", "cost",
        "transfer amount", "send amount", "pay amount",
        "enter amount", "transaction amount",
    ]):
        return "100"

    # ── Address / location ─────────────────────────────────────────────────
    if any(k in hints for k in [
        "address", "street", "locality", "area",
        "flat", "house", "building", "plot",
        "landmark", "line 1", "line 2",
    ]):
        return "123 Analysis Lane"
    if any(k in hints for k in ["zip", "postal", "postcode", "pincode"]):
        return "400001"
    if any(k in hints for k in ["city", "town", "district"]):
        return "Mumbai"
    if any(k in hints for k in ["state", "province", "region"]):
        return "Maharashtra"
    if any(k in hints for k in ["country", "nation"]):
        return "India"

    # ── Occupation / employer ──────────────────────────────────────────────
    if any(k in hints for k in [
        "occupation", "profession", "job", "employment",
        "employer", "company", "organization", "organisation",
        "business", "designation",
    ]):
        return "Self Employed"

    # ── Referral / promo / coupon ──────────────────────────────────────────
    if any(k in hints for k in [
        "referral", "refer code", "refercode", "promo",
        "coupon", "voucher", "invite code",
    ]):
        return "ANALYSIS10"

    # ── Generic verification / captcha / token code ────────────────────────
    if any(k in hints for k in [
        "code", "verification", "token", "captcha",
        "auth", "confirm code",
    ]):
        return "123456"

    # ── Vehicle / registration ─────────────────────────────────────────────
    if any(k in hints for k in [
        "vehicle", "registration", "reg no", "reg_no",
        "vehicle no", "car number", "bike number",
    ]):
        return "MH01AB1234"

    # ── URL / website ──────────────────────────────────────────────────────
    if any(k in hints for k in ["url", "website", "link", "http"]):
        return "http://analysis.lab"

    # ── Search / query ─────────────────────────────────────────────────────
    if any(k in hints for k in ["search", "query", "find"]):
        return "test"

    # ── Generic number fallback  (catches remaining "number" fields) ────────
    if any(k in hints for k in ["number", "no.", " no ", "_no"]):
        return "1234567890"

    # ── [v2.9-4a] inputType numeric fallback ──────────────────────────────
    # If no keyword matched but the field's XML inputType signals numeric
    # input, return a 10-digit number.  Prevents "testvalue" being injected
    # into any field that only accepts digits (guaranteed validation failure).
    input_type = getattr(elem, "input_type", "").lower()
    if any(k in input_type for k in ["number", "phone", "decimal"]):
        return Config.FAKE_PHONE   # 10-digit numeric safe default

    # ── Generic fallback ───────────────────────────────────────────────────
    return "testvalue"


# ─────────────────────────────────────────────────────────────
# ACTION EXECUTOR
# ─────────────────────────────────────────────────────────────

class ActionExecutor:
    """Wraps all ADB shell input commands."""

    def tap(self, x: int, y: int) -> bool:
        r = adb("shell", "input", "tap", str(x), str(y))
        return r.returncode == 0

    def long_tap(self, x: int, y: int, duration_ms: int = 1500) -> bool:
        r = adb("shell", "input", "swipe",
                str(x), str(y), str(x), str(y), str(duration_ms))
        return r.returncode == 0

    def input_text(self, text: str) -> bool:
        # Clear existing content first
        adb("shell", "input", "keyevent", "KEYCODE_CTRL_A")
        adb("shell", "input", "keyevent", "KEYCODE_DEL")
        # Escape special characters for shell
        safe = text.replace("'", "\\'").replace(" ", "%s")
        r = adb("shell", "input", "text", safe)
        return r.returncode == 0

    def scroll_down(self, x: int = 540, y: int = 900) -> bool:
        r = adb("shell", "input", "swipe",
                str(x), str(y), str(x), str(y - 600), "300")
        return r.returncode == 0

    def scroll_up(self, x: int = 540, y: int = 300) -> bool:
        r = adb("shell", "input", "swipe",
                str(x), str(y), str(x), str(y + 600), "300")
        return r.returncode == 0

    def back(self) -> bool:
        r = adb("shell", "input", "keyevent", "KEYCODE_BACK")
        return r.returncode == 0

    def home(self) -> bool:
        r = adb("shell", "input", "keyevent", "KEYCODE_HOME")
        return r.returncode == 0

    def enter(self) -> bool:
        r = adb("shell", "input", "keyevent", "KEYCODE_ENTER")
        return r.returncode == 0

    def dismiss_keyboard(self) -> bool:
        r = adb("shell", "input", "keyevent", "KEYCODE_ESCAPE")
        return r.returncode == 0

    def accept_permission_dialog(self, xml_str: str) -> bool:
        """
        Tap the allow/accept button in a permission dialog.
        Tries several strategies to find the right button.
        """
        # Strategy 1: find button with allow/accept text
        try:
            root = ET.fromstring(xml_str)
            for node in root.iter("node"):
                text = (node.attrib.get("text", "") +
                        node.attrib.get("content-desc", "")).lower()
                if any(k in text for k in ["allow", "accept", "ok", "permit", "grant"]):
                    bounds = node.attrib.get("bounds", "")
                    if bounds:
                        x1, y1, x2, y2 = _parse_bounds(bounds)
                        cx, cy = (x1 + x2) // 2, (y1 + y2) // 2
                        return self.tap(cx, cy)
        except ET.ParseError:
            pass

        # Strategy 2: tap bottom-right quadrant (where Allow usually is)
        r = adb("shell", "wm", "size")
        m = re.search(r'(\d+)x(\d+)', r.stdout)
        if m:
            w, h = int(m.group(1)), int(m.group(2))
            return self.tap(int(w * 0.75), int(h * 0.85))

        return False


# ─────────────────────────────────────────────────────────────
# FRIDA ATTACH FOR TIER 2
# ─────────────────────────────────────────────────────────────

def attach_flag_secure_bypass(package_name: str):
    """
    Attach Frida and inject the FLAG_SECURE removal script.
    Returns the Frida session (must stay alive) or None.
    """
    try:
        device  = frida.get_device_manager().add_remote_device(
            f"localhost:{Config.FRIDA_PORT}"
        )
        session = device.attach(package_name)
        script  = session.create_script(FRIDA_FLAG_SECURE_JS)
        script.load()
        ok("Frida FLAG_SECURE bypass : ACTIVE")
        return session
    except Exception as e:
        warn(f"Frida FLAG_SECURE bypass failed: {e}")
        warn("Screenshot tier degraded to 3 (XML only)")
        return None


# ─────────────────────────────────────────────────────────────
# UI STATE MANAGER
# ─────────────────────────────────────────────────────────────

class UIStateManager:
    """Tracks all visited states and their interaction history."""

    def __init__(self):
        self.visited: dict[str, UIState] = {}       # hash -> UIState
        self.interaction_map: dict[str, set[str]] = {}  # hash -> set of elem.key()

    def is_visited(self, state_hash: str) -> bool:
        return state_hash in self.visited

    def register(self, state: UIState) -> None:
        self.visited[state.state_hash] = state
        if state.state_hash not in self.interaction_map:
            self.interaction_map[state.state_hash] = set()

    def mark_action(self, state_hash: str, elem_key: str) -> None:
        if state_hash not in self.interaction_map:
            self.interaction_map[state_hash] = set()
        self.interaction_map[state_hash].add(elem_key)

    def get_untried(self, state_hash: str,
                    elements: list[UIElement]) -> list[UIElement]:
        """Return elements in this state not yet interacted with."""
        tried = self.interaction_map.get(state_hash, set())
        return [e for e in elements if e.key() not in tried]

    def total_states(self) -> int:
        return len(self.visited)


# ─────────────────────────────────────────────────────────────
# FORM-SUBMIT DETECTION HELPERS  [v2.8-A]
# ─────────────────────────────────────────────────────────────

# Keywords that appear in error indicator nodes (text or content-desc)
_FORM_ERROR_TOKENS = [
    "required", "invalid", "incorrect", "enter valid", "must be",
    "cannot be empty", "please enter", "mandatory", "not valid",
    "wrong", "error", "mismatch", "does not match", "already exists",
    "already registered", "not found", "try again",
]

# Keywords that appear in success-toast nodes (short-lived FrameLayout text)
_FORM_SUCCESS_TOKENS = [
    "success", "successfully", "submitted", "registered", "sent",
    "otp sent", "verified", "thank you", "welcome", "proceed",
    "approved", "completed",
]


def _scan_form_errors(xml_str: str) -> list[dict]:
    """
    [v2.8-A / v2.9-2] Scan the current UI XML for visible error indicators.

    [v2.9-2] Also scans PopupWindow nodes at ANY depth in the tree.
    Android's native setError() creates a PopupWindow subtree that appears
    as a top-level node in the UIAutomator dump -- the v2.8 scan missed
    these because it only checked text/content-desc on all nodes, which
    works for inline error TextViews but not for the PopupWindow container
    whose OWN text attribute is empty (the error text lives in a child node).

    Scan strategy:
      1. Every node: check text + content-desc against _FORM_ERROR_TOKENS.
      2. Every PopupWindow node: check ALL descendant text nodes too.
         This catches setError() tooltips regardless of nesting depth.

    Returns a list of dicts: {element, text, bounds} for each error node.
    Empty list = no errors detected (does NOT guarantee success).
    """
    errors_found = []
    try:
        root = ET.fromstring(xml_str)
        for node in root.iter("node"):
            cls = node.attrib.get("class", "")
            txt = (node.attrib.get("text", "") + " " +
                   node.attrib.get("content-desc", "")).lower().strip()

            # Standard error indicator on any node
            if txt and any(tok in txt for tok in _FORM_ERROR_TOKENS):
                errors_found.append({
                    "element": cls,
                    "text":    (node.attrib.get("text", "") or
                                node.attrib.get("content-desc", "")),
                    "bounds":  node.attrib.get("bounds", ""),
                })

            # [v2.9-2] PopupWindow: also scan all descendants for error text
            # (setError() tooltip text lives in a child TextView inside the popup)
            if "PopupWindow" in cls:
                for child in node.iter("node"):
                    if child is node:
                        continue
                    child_txt = (child.attrib.get("text", "") + " " +
                                 child.attrib.get("content-desc", "")).lower().strip()
                    if child_txt and any(tok in child_txt for tok in _FORM_ERROR_TOKENS):
                        errors_found.append({
                            "element": "PopupWindow>" + child.attrib.get("class", ""),
                            "text":    (child.attrib.get("text", "") or
                                        child.attrib.get("content-desc", "")),
                            "bounds":  child.attrib.get("bounds", ""),
                        })
                    # Even if text doesn't match an error token, any non-empty
                    # PopupWindow child text that wasn't there before is suspicious --
                    # caller (_interact_with_element) will also pass before_xml to
                    # distinguish new vs pre-existing popups.

    except ET.ParseError:
        pass
    return errors_found


def _scan_empty_fields(xml_str: str) -> list[dict]:
    """
    [v2.8-A] Find EditText fields that are visibly empty or still showing
    their hint text (indicating the user has not filled them).

    Returns list of dicts: {resource_id, hint, bounds}.
    """
    empty = []
    try:
        root = ET.fromstring(xml_str)
        for node in root.iter("node"):
            if "EditText" not in node.attrib.get("class", ""):
                continue
            txt  = node.attrib.get("text", "").strip()
            hint = node.attrib.get("hint", "").strip()
            # Empty or text == hint means field was never filled
            if txt == "" or (hint and txt == hint):
                empty.append({
                    "resource_id": node.attrib.get("resource-id", ""),
                    "hint":        hint,
                    "bounds":      node.attrib.get("bounds", ""),
                })
    except ET.ParseError:
        pass
    return empty


def _detect_success_toast(before_xml: str, after_xml: str) -> bool:
    """
    [v2.8-A] Detect a transient success toast that appeared AFTER the tap.

    Strategy: find FrameLayout / Toast nodes in after_xml whose text was
    absent in before_xml and matches a success token.  This distinguishes
    "stayed on screen because success toast" from "stayed because failure".
    """
    before_texts: set[str] = set()
    try:
        for node in ET.fromstring(before_xml).iter("node"):
            t = node.attrib.get("text", "").strip()
            if t:
                before_texts.add(t.lower())
    except ET.ParseError:
        pass

    try:
        for node in ET.fromstring(after_xml).iter("node"):
            cls = node.attrib.get("class", "")
            txt = node.attrib.get("text", "").strip().lower()
            if not txt or txt in before_texts:
                continue
            # New text node that wasn't there before
            if any(tok in txt for tok in _FORM_SUCCESS_TOKENS):
                return True
            # FrameLayout or Toast class with any new text = likely toast
            if "FrameLayout" in cls or "Toast" in cls:
                return True
    except ET.ParseError:
        pass
    return False


# ─────────────────────────────────────────────────────────────
# [v2.9-3] DOUBLE-TAP DETECTOR
# ─────────────────────────────────────────────────────────────

class DoubleTapDetector(threading.Thread):
    """
    [v2.9-3] Daemon thread that detects a physical double-tap on the device
    screen by parsing raw input events from `adb shell getevent -lt`.

    Detection logic:
      - Watches for ABS_MT_TRACKING_ID events with value ffffffff (finger UP).
      - Two UP events within DOUBLE_TAP_WINDOW seconds = double-tap.
      - Fires signal_event when detected and exits immediately.

    [v2.13] Reliability fixes:
      - ready_event: set after the first line is received from getevent,
        confirming the subprocess is streaming. Callers that need to know
        the detector is live before announcing "ready" should wait on this.
      - STARTUP_GRACE: if the very first UP event arrives within
        STARTUP_GRACE seconds of the thread starting, it is treated as a
        legitimate first tap (not discarded). This handles the case where
        the analyst taps immediately after the detector is announced as armed.
      - Tighter stop-check: _stop_event is checked after every line, not
        only at the top of the loop, preventing a 1-line lookahead delay.

    Used for TWO purposes (same detection, different signal_event):
      (a) START signal: analyst double-taps to tell engine "I am helping now"
      (b) DONE  signal: analyst double-taps again to tell engine "I am done"

    Falls back gracefully: if getevent is not available or returns no events
    within the timeout, the thread exits silently without firing the event.
    The passive XML-hash poller in HumanInterventionMonitor handles the fallback.
    """

    # Seconds after thread start within which the first UP event is treated
    # as a genuine first tap even though last_up_time was 0.0 (i.e. getevent
    # had only just started streaming). This covers the ~300-800ms getevent
    # startup latency so the analyst's first tap is never lost.
    STARTUP_GRACE: float = 1.5

    def __init__(self, signal_event: threading.Event,
                 timeout: float = 60.0,
                 label: str = "double-tap",
                 ready_event: Optional[threading.Event] = None):
        super().__init__(daemon=True, name=f"DoubleTapDetector-{label}")
        self.signal_event = signal_event
        self.timeout      = timeout
        self.label        = label
        self._stop_event  = threading.Event()
        # [v2.13] Fires after first line received from getevent subprocess.
        # Allows callers to wait until the detector is confirmed streaming
        # before announcing "armed" to the analyst.
        self.ready_event  = ready_event or threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        cmd = ["adb"]
        if Config.ADB_SERIAL:
            cmd += ["-s", Config.ADB_SERIAL]
        cmd += ["shell", "getevent", "-lt"]

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except Exception as e:
            warn(f"[DoubleTap-{self.label}] getevent failed to start: {e}")
            self.ready_event.set()   # unblock any waiter even on failure
            return

        last_up_time: float = 0.0
        thread_start: float = time.time()
        deadline = thread_start + self.timeout
        first_line_received = False

        try:
            for line in proc.stdout:  # type: ignore[union-attr]
                # [v2.13] Signal ready on first byte from getevent.
                if not first_line_received:
                    first_line_received = True
                    self.ready_event.set()

                if self._stop_event.is_set() or time.time() > deadline:
                    break

                # getevent -lt output format:
                # [  123.456789]  /dev/input/eventN  ABS_MT_TRACKING_ID  ffffffff
                # ffffffff = -1 = finger lifted (UP event)
                # Also match BTN_TOUCH UP (device-dependent alternative)
                is_up_event = (
                    ("ABS_MT_TRACKING_ID" in line and "ffffffff" in line)
                    or ("BTN_TOUCH" in line and " UP" in line)
                )
                if not is_up_event:
                    continue

                now = time.time()
                gap = now - last_up_time

                # MIN_GAP guard: two events < MIN_GAP apart = paired events
                # from the same physical finger-lift. Ignore; do NOT update
                # last_up_time so the next genuine tap compares correctly.
                if gap < Config.DOUBLE_TAP_MIN_GAP:
                    continue

                # [v2.13] Startup grace: if last_up_time is still 0.0 AND we
                # are within STARTUP_GRACE seconds of thread start, this is
                # the analyst's first tap arriving while getevent was warming
                # up. Accept it as the first tap of a potential pair.
                if last_up_time == 0.0:
                    last_up_time = now
                    continue

                if gap <= Config.DOUBLE_TAP_WINDOW:
                    # Valid double-tap: gap is in [MIN_GAP, DOUBLE_TAP_WINDOW]
                    ok(f"[DoubleTap-{self.label}] Double-tap detected "
                       f"(gap={gap:.3f}s)")
                    self.signal_event.set()
                    break
                else:
                    # Too slow — becomes the new first tap
                    last_up_time = now

        except Exception:
            pass
        finally:
            self.ready_event.set()   # always unblock waiters
            try:
                proc.kill()
                proc.wait(timeout=1.0)
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────
# [v2.9-3] CLI DONE LISTENER
# ─────────────────────────────────────────────────────────────

class CliDoneListener(threading.Thread):
    """
    [v2.9-3] Daemon thread that waits for the analyst to press Enter in the
    terminal to signal "I am done helping".

    This is the lowest-friction signal path: the analyst doesn't need to
    interact with the device at all -- just press Enter on the keyboard
    connected to the analysis workstation.

    Fires done_event and exits immediately on Enter.
    Exits silently if stop() is called (e.g. because DoubleTapDetector fired
    first or the STUCK_TIMEOUT expired).

    Uses a non-blocking readline via a helper thread + queue so the main
    stop_event can interrupt the wait cleanly without blocking on sys.stdin.
    """

    def __init__(self, done_event: threading.Event):
        super().__init__(daemon=True, name="CliDoneListener")
        self.done_event  = done_event
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        # Print the prompt once -- the analyst sees this in the terminal
        print(f"\n  {Fore.YELLOW}┌─ HUMAN INTERVENTION MODE ─────────────────────────────────┐")
        print(f"  │  Double-tap device screen when done  OR  press Enter here  │")
        print(f"  └────────────────────────────────────────────────────────────┘{Style.RESET_ALL}\n",
              flush=True)

        # Use a queue + inner thread to make sys.stdin.readline() interruptible
        line_queue: "queue.Queue[str]" = queue.Queue()

        def _reader():
            try:
                line_queue.put(sys.stdin.readline())
            except Exception:
                line_queue.put("")

        reader_thread = threading.Thread(target=_reader, daemon=True,
                                         name="CliDoneListener-reader")
        reader_thread.start()

        # Poll queue until Enter arrives or stop_event fires
        while not self._stop_event.is_set():
            try:
                line_queue.get(timeout=0.25)
                if not self._stop_event.is_set():
                    ok("[CliDone] Enter pressed -- signalling done")
                    self.done_event.set()
                return
            except queue.Empty:
                continue




# ─────────────────────────────────────────────────────────────
# [v2.12] GLOBAL INTERRUPT LISTENER
# ─────────────────────────────────────────────────────────────

class GlobalInterruptListener(threading.Thread):
    """
    [v2.12] Background daemon thread that listens for the global interrupt
    signal throughout the entire explore() session.

    Detects two signals:
      (a) Double-tap on the device screen (via DoubleTapDetector)
      (b) Double-Enter in the terminal (two Enter presses within DOUBLE_TAP_WINDOW)

    On either signal: sets pause_event, then waits for DFS to clear it
    (i.e. _handle_global_pause finishes), then re-arms for the next interrupt.

    [v2.13] Reliability fixes:
      - Single persistent stdin reader thread across all cycles.
        Previous design spawned a new _reader thread every cycle, leading to
        N accumulated threads all competing for stdin bytes. The current cycle's
        enter_detected event would never fire because the winning reader belonged
        to a stale cycle. Now a single GIL-stdin-reader thread runs for the
        lifetime of GlobalInterruptListener and feeds a shared stdin_queue.
      - DoubleTapDetector ready_event: each new detector starts, then we wait
        for ready_event before announcing "armed" to the analyst. This ensures
        getevent is actually streaming before the analyst is told to tap,
        preventing the "first double-tap ignored" failure mode.
      - Dead-zone extended to DOUBLE_TAP_WINDOW + 0.3s after resume, ensuring
        the second tap of the analyst's "done" double-tap cannot be caught by
        the newly re-armed detector as the first tap of a new global interrupt.

    Lifecycle:
      - Started once at the top of explore().
      - Runs until stop() is called at the bottom of explore().
      - Never touches _intervention_active directly — that is ExplorerEngine's job.
    """

    def __init__(self, pause_event: threading.Event):
        super().__init__(daemon=True, name="GlobalInterruptListener")
        self.pause_event  = pause_event
        self._stop_event  = threading.Event()
        # [v2.13] Single persistent stdin queue shared across all re-arm cycles.
        # Populated by one long-lived _stdin_reader thread so there is never
        # more than one thread consuming sys.stdin at a time.
        self._stdin_queue: queue.Queue = queue.Queue()
        self._stdin_reader: Optional[threading.Thread] = None

    def stop(self) -> None:
        self._stop_event.set()

    def _ensure_stdin_reader(self) -> None:
        """
        [v2.13] Start the persistent stdin reader thread if not already running.
        Called once before the first cycle begins. The reader lives until
        _stop_event is set, feeding all Enter keypresses into _stdin_queue.
        """
        if self._stdin_reader is not None and self._stdin_reader.is_alive():
            return

        def _reader_body():
            while not self._stop_event.is_set():
                try:
                    line = sys.stdin.readline()
                    self._stdin_queue.put(line)
                    if not line:   # EOF on non-TTY
                        break
                except Exception:
                    break

        self._stdin_reader = threading.Thread(
            target=_reader_body, daemon=True, name="GIL-stdin-reader")
        self._stdin_reader.start()

    def run(self) -> None:
        self._ensure_stdin_reader()

        # Per-cycle state for the double-Enter detector.
        # Lives here (not inside the closure) so it persists across the single
        # reader thread's lifetime and can be reset cleanly each cycle.
        last_enter_time: list[float] = [0.0]

        while not self._stop_event.is_set():

            # ── Arm a fresh DoubleTapDetector for this cycle ──────
            tap_detected  = threading.Event()
            dtd_ready     = threading.Event()   # [v2.13] fires when getevent is streaming
            dtd = DoubleTapDetector(
                signal_event=tap_detected,
                timeout=float("inf"),
                label="global",
                ready_event=dtd_ready,
            )
            dtd.start()

            # [v2.13] Wait until getevent is confirmed streaming (or 2s max)
            # before announcing "armed". This prevents the "tap during startup"
            # miss that required a second full double-tap to actually trigger.
            dtd_ready.wait(timeout=2.0)
            if not self._stop_event.is_set():
                info("[GlobalInterrupt] Armed -- double-tap device or "
                     "double-Enter to pause DFS")

            # Reset enter-timing for this fresh cycle so a stale timestamp
            # from the previous cycle cannot accidentally produce a gap within
            # DOUBLE_TAP_WINDOW when the first Enter of the new cycle arrives.
            last_enter_time[0] = 0.0

            # ── Wait for either signal or stop ────────────────────
            triggered = False
            signal_type = ""
            while not self._stop_event.is_set():
                if tap_detected.is_set():
                    signal_type = "double-tap"
                    triggered = True
                    break

                # Drain accumulated stdin entries (non-blocking)
                try:
                    while True:
                        self._stdin_queue.get_nowait()
                        now = time.time()
                        gap = now - last_enter_time[0]
                        if (Config.DOUBLE_TAP_MIN_GAP < gap
                                <= Config.DOUBLE_TAP_WINDOW):
                            ok(f"[GlobalInterrupt] Double-Enter detected "
                               f"(gap={gap:.3f}s)")
                            signal_type = "double-Enter"
                            triggered = True
                            break
                        last_enter_time[0] = now
                except queue.Empty:
                    pass

                if triggered:
                    break
                time.sleep(0.05)

            dtd.stop()

            if self._stop_event.is_set():
                break

            if triggered:
                ok(f"[GlobalInterrupt] {signal_type} received -- pausing DFS")
                self.pause_event.set()

                # Wait for DFS to finish handling the pause before re-arming.
                # _handle_global_pause() clears pause_event as its last step.
                while self.pause_event.is_set() and not self._stop_event.is_set():
                    time.sleep(0.1)

                if self._stop_event.is_set():
                    break

                # [v2.13] Dead-zone: must be longer than DOUBLE_TAP_WINDOW so
                # the second tap of the analyst's "done" gesture cannot be
                # mistaken for the first tap of a new global interrupt.
                dead_zone = Config.DOUBLE_TAP_WINDOW + 0.3
                time.sleep(dead_zone)
                # Reset enter timing so stale timestamps don't bleed into the
                # new cycle's double-Enter window.
                last_enter_time[0] = 0.0


@dataclass
class HumanInterventionResult:
    """
    [v2.8-C] Returned by HumanInterventionMonitor after the analyst
    interacts with the device.  Contains everything needed to:
      (a) fill the action-log gap  (actions_inferred)
      (b) decide which hashes to keep vs. prune  (screens_visited)
      (c) know where to resume DFS  (final_hash)
    """
    screens_visited:  list[str]    # ordered hashes the human passed through
    actions_inferred: list[UIAction]  # synthetic UIAction entries, source="human"
    final_hash:       str          # hash at the moment resume_event fired


# ─────────────────────────────────────────────────────────────
# HUMAN INTERVENTION MONITOR  [v2.7 / updated v2.8-B/C]
# ─────────────────────────────────────────────────────────────

class HumanInterventionMonitor(threading.Thread):
    """
    [v2.7/v2.8/v2.9] Daemon thread that detects when a human has manually
    changed the UI while the explorer was stuck, and records every screen
    they visit for state-pruning and action-log purposes.

    v2.9-3 changes -- two-phase explicit signal model:

      PHASE 1 -- "I am starting to help" (START signal):
        The monitor launches a DoubleTapDetector for the START signal and
        simultaneously runs the passive XML-hash poller as a fallback.
        Whichever fires first is used:
          - Explicit: analyst double-taps the device screen.
          - Passive:  any XML hash change is detected (v2.8 behaviour).
        Once START is detected, the monitor enters PHASE 2.

      PHASE 2 -- "I am done helping" (DONE signal):
        The monitor records every screen the human visits (same as v2.8).
        It launches:
          (a) A second DoubleTapDetector for the DONE signal.
          (b) A CliDoneListener waiting for Enter in the terminal.
        Whichever fires first ends PHASE 2 and fires resume_event.
        If neither fires within STUCK_TIMEOUT, passive poller timeout applies.

    Backward compatibility: if getevent is unavailable (DoubleTapDetector
    exits silently), the passive poller remains the sole trigger -- identical
    to v2.8 behaviour.

    Lifecycle:
      1. ExplorerEngine._dfs() enters stuck mode.
      2. Creates and starts HumanInterventionMonitor.
      3. Monitor waits for START signal (explicit double-tap or passive hash change).
      4. On START: records screens, waits for DONE signal (double-tap or Enter).
      5. On DONE: fires resume_event, stores HumanInterventionResult, exits.
      6. _dfs() reads result via .get_result(), applies pruning + action log.
    """

    def __init__(self, xml_dir: Path,
                 resume_event: threading.Event,
                 dangerous_permissions: list[str] | None = None,
                 screens_dir: Optional[Path] = None,
                 screenshot_tier: int = 3,
                 frida_session=None):
        super().__init__(daemon=True, name="HumanInterventionMonitor")
        self.xml_dir          = xml_dir
        self.resume_event     = resume_event
        self._stop_event      = threading.Event()
        self._dangerous_perms = dangerous_permissions or []
        self._result: Optional[HumanInterventionResult] = None
        # [v2.10] Screenshot support during intervention
        self._screens_dir:    Optional[Path] = screens_dir
        self._screenshot_tier: int           = screenshot_tier
        self._frida_session                  = frida_session
        self._intervention_screen_n: int     = 0  # counter for naming

    def stop(self) -> None:
        self._stop_event.set()

    def get_result(self) -> Optional[HumanInterventionResult]:
        """Returns the intervention result after monitor has stopped."""
        return self._result

    def _capture_intervention_screenshot(self, screen_number: int) -> str:
        """
        [v2.10] Capture a screenshot of the current screen during human
        intervention and save it alongside normal DFS screenshots in the
        same session screenshots/ folder.

        Filename: intervention_NNNN_<unix_timestamp>.png
        Returns the saved path, or "" on failure / tier 3.
        """
        if self._screens_dir is None or self._screenshot_tier > 2:
            return ""
        ts_int  = int(time.time())
        fname   = f"intervention_{screen_number:04d}_{ts_int}.png"
        sp      = str(self._screens_dir / fname)
        success = capture_screenshot(sp, self._screenshot_tier, self._frida_session)
        if success:
            info(f"[HIM] Intervention screenshot saved: {fname}")
            return sp
        return ""

    def run(self) -> None:
        # ── Capture baseline ──────────────────────────────────
        baseline_xml = dump_ui_xml(
            str(self.xml_dir / f"_stuck_baseline_{int(time.time())}.xml"))
        reference_hash = hash_xml(baseline_xml) if baseline_xml else ""
        prev_hash  = reference_hash
        poll_n     = 0

        screens_visited:  list[str]       = []
        actions_inferred: list[UIAction]  = []

        # ── PHASE 1: Wait for START signal ────────────────────
        # Explicit: double-tap on device.  Passive fallback: any XML hash change.
        ok("[HIM] Waiting for START signal (double-tap device or just interact)...")

        start_detected = threading.Event()

        # Start the DoubleTapDetector for the START signal
        start_tap_detector = DoubleTapDetector(
            signal_event=start_detected,
            timeout=float(Config.STUCK_TIMEOUT),
            label="start",
        )
        start_tap_detector.start()

        # Passive hash-poller loop (also serves as the fallback start detector)
        phase1_deadline = time.time() + Config.STUCK_TIMEOUT
        started_explicitly = False

        while (not self._stop_event.is_set()
               and not self.resume_event.is_set()
               and time.time() < phase1_deadline):

            # Check explicit START signal
            if start_detected.is_set() and not started_explicitly:
                started_explicitly = True
                ok("[HIM] Explicit START signal received -- entering intervention mode")
                break

            time.sleep(0.5)
            poll_n += 1
            poll_xml = dump_ui_xml(
                str(self.xml_dir / f"_stuck_poll_{int(time.time())}_{poll_n}.xml"))
            if not poll_xml:
                continue
            current_hash = hash_xml(poll_xml)
            if not current_hash or current_hash == prev_hash:
                continue

            # Passive start: hash changed without explicit signal
            ok(f"[HIM] Passive START detected (hash change: "
               f"{prev_hash} → {current_hash})")
            screens_visited.append(current_hash)
            actions_inferred.append(UIAction(
                timestamp=ts(),
                action_type="human_navigation",
                element_label=f"human_screen_{len(screens_visited)}",
                element_class="",
                bounds="",
                new_state_hash=current_hash,
                source="human",
            ))
            prev_hash = current_hash
            started_explicitly = False  # passive start, no explicit done needed
            break

        start_tap_detector.stop()

        # If nothing happened at all (no explicit, no passive), exit
        if (not started_explicitly
                and not screens_visited
                and not start_detected.is_set()):
            info("[HIM] No START signal within timeout -- exiting")
            self._result = HumanInterventionResult(
                screens_visited=[],
                actions_inferred=[],
                final_hash=reference_hash,
            )
            return

        # ── PHASE 2: Record screens + wait for DONE signal ────
        # If we had a passive start, we already recorded the first screen above.
        # If we had an explicit start, we now poll until DONE.
        ok("[HIM] Intervention in progress -- watching screens...")

        done_event = threading.Event()

        # Launch DONE detectors
        done_tap_detector = DoubleTapDetector(
            signal_event=done_event,
            timeout=float(Config.STUCK_TIMEOUT),
            label="done",
        )
        done_tap_detector.start()

        cli_listener = CliDoneListener(done_event=done_event)
        cli_listener.start()

        phase2_deadline = time.time() + Config.STUCK_TIMEOUT

        while (not self._stop_event.is_set()
               and not done_event.is_set()
               and time.time() < phase2_deadline):

            time.sleep(0.5)
            poll_n += 1
            poll_xml = dump_ui_xml(
                str(self.xml_dir / f"_stuck_poll_{int(time.time())}_{poll_n}.xml"))
            if not poll_xml:
                continue
            current_hash = hash_xml(poll_xml)
            if not current_hash or current_hash == prev_hash:
                continue

            # New screen during intervention -- record it + take screenshot
            self._intervention_screen_n += 1
            scr_path = self._capture_intervention_screenshot(self._intervention_screen_n)
            screens_visited.append(current_hash)
            actions_inferred.append(UIAction(
                timestamp=ts(),
                action_type="human_navigation",
                element_label=f"human_screen_{len(screens_visited)}",
                element_class="",
                bounds="",
                new_state_hash=current_hash,
                source="human",
            ))
            ok(f"[HIM] Screen {len(screens_visited)} recorded: "
               f"{prev_hash} → {current_hash}"
               + (f" | screenshot: {Path(scr_path).name}" if scr_path else ""))
            prev_hash = current_hash

        # Clean up DONE detectors
        done_tap_detector.stop()
        cli_listener.stop()

        # Fire resume_event so _dfs() unblocks
        if screens_visited or done_event.is_set():
            if not self.resume_event.is_set():
                self.resume_event.set()
            ok(f"[HIM] Intervention complete: {len(screens_visited)} screen(s) visited")
        else:
            info("[HIM] Monitor stopped (no intervention detected)")

        final_hash = screens_visited[-1] if screens_visited else reference_hash
        self._result = HumanInterventionResult(
            screens_visited=screens_visited,
            actions_inferred=actions_inferred,
            final_hash=final_hash,
        )


# ─────────────────────────────────────────────────────────────
# EXPLORER ENGINE
# ─────────────────────────────────────────────────────────────

class ExplorerEngine:
    """
    DFS traversal loop. At each step:
      1. Dump UI XML -> hash -> check if visited
      2. Take screenshot
      3. Find interactive elements, score and sort them
      4. Handle permission dialogs immediately
      5. Interact with highest-scoring untried element
      6. Repeat from new state
      7. If no untried elements remain, press back
      8. Stop when max depth / max states / timeout reached
    """

    def __init__(self, package_name: str, main_activity: str,
                 screenshot_tier: int, session_dir: Path,
                 session: ExplorerSession,
                 p1_dangerous_permissions: list[str] | None = None,
                 known_dropper_packages: list[str] | None = None):
        self.package_name    = package_name
        self.main_activity   = main_activity
        self.tier            = screenshot_tier
        self.session_dir     = session_dir
        self.screens_dir     = session_dir / "screenshots"
        self.xml_dir         = session_dir / "xml"
        self.session         = session
        self.state_mgr       = UIStateManager()
        self.executor        = ActionExecutor()
        self.frida_session   = None
        self.depth           = 0
        self.start_time      = time.time()
        self.screens_dir.mkdir(parents=True, exist_ok=True)
        self.xml_dir.mkdir(parents=True, exist_ok=True)

        # [v2.7] Manifest dangerous permissions for stuck-state alert
        # Injected from sentry p1["summary"]["dangerous_permissions"] if available.
        self._p1_dangerous_permissions: list[str] = p1_dangerous_permissions or []

        # [v2.14] Known dropper packages (from sentry dropper_events).
        # Populated here; also extended by explore_package() on each call.
        self._known_dropper_packages: set[str] = set(known_dropper_packages or [])

        # [v2.4-2] Backtrack loop detection -- ring buffer of recent state hashes
        self._recent_states: deque[str] = deque(maxlen=6)
        # [v2.4-3] Install-dialog dedup -- set of state hashes already acted on
        self._install_dialog_seen: set[str] = set()

        # [v2.7] Session-scoped field-fill blacklist.
        # Key: (package_name, resource_id). Stable across re-renders -- unlike
        # state_hash which changes whenever a validation indicator appears.
        # Cleared only on explore_package() switch, never on relaunch.
        self._filled_fields: set[tuple[str, str]] = set()

        # [v2.7] Phase deadline for Phase A budget cap. Set externally by
        # sentry._explore_with_stop() before calling explore(). When None,
        # no extra deadline applies (standalone explorer.py usage).
        self._phase_deadline: Optional[float] = None

        # [v2.7] Human intervention monitor -- started lazily when stuck.
        self._intervention_monitor: Optional["HumanInterventionMonitor"] = None

        # [v2.8-B] Stuck-state pruning support.
        # _stuck_entry_hash: hash of the state where stuck was declared.
        # _post_stuck_hashes: hashes added to state_mgr DURING a stuck wait
        #   (i.e. the dead-end spin hashes). On resume, these are pruned from
        #   state_mgr.visited so the DFS re-explores them if the human has
        #   navigated away -- but human-visited hashes are NOT in this set.
        self._stuck_entry_hash: Optional[str]  = None
        self._post_stuck_hashes: set[str]      = set()

        # [v2.8-C] Human-visited states (separate from DFS-visited).
        # Populated on human intervention resume. Unioned into state_mgr.visited
        # so DFS never re-traverses screens the human already handled, but
        # tracked separately so pruning in [v2.8-B] can't accidentally remove them.
        self._human_visited_states: set[str] = set()

        # [v2.10] Intervention safety flags.
        # _intervention_active: True while human owns the device.
        #   Guards _relaunch() (no am force-stop / am start) and home() in _safe_back().
        # _retry_cancel: set() cancels any sleeping retry loop when intervention begins.
        # _intervention_entry_hash: state hash snapshot when intervention began.
        #   On resume, if current hash == entry hash, nothing fired -- safe to replay.
        self._intervention_active: bool         = False
        self._retry_cancel: threading.Event     = threading.Event()
        self._intervention_entry_hash: str      = ""

        # [v2.12] Global interrupt support.
        # _global_pause_event: set by GlobalInterruptListener when a double-tap or
        #   double-Enter is detected OUTSIDE a stuck window (i.e. during normal DFS).
        # _global_interrupt_listener: the background thread. Started in explore(),
        #   stopped in explore() after the 3-pass loop completes.
        self._global_pause_event: threading.Event        = threading.Event()
        self._global_interrupt_listener: Optional["GlobalInterruptListener"] = None

        # [v2.14] Exploration robustness fields.
        # _tombed_states: state hashes permanently blacklisted — never entered again
        #   this session. Cleared only on explore_package() package switch.
        # _branch_ledger: maps depth-0 element key → "pending"|"exhausted"|"tombed".
        #   Persists across passes. Gives pass 2/3 a reliable home-screen map.
        # _consecutive_stale_visits: counter of sequential _dfs() entries on
        #   already-visited states. Reset on any new state or between passes.
        # _current_max_depth: active depth ceiling, overridden per pass in explore().
        self._tombed_states: set[str]       = set()
        self._branch_ledger: dict[str, str] = {}
        self._consecutive_stale_visits: int = 0
        self._current_max_depth: int        = Config.MAX_DEPTH

    # ── [v2.10] Intervention safety helpers ───────────────────

    def _enter_intervention_mode(self, reason: str = "") -> None:
        """
        [v2.10] Called when the engine hands control to the human analyst.

        - Sets _intervention_active so _relaunch() and home() in _safe_back()
          are no-ops (prevents am force-stop / am start / KEYCODE_HOME firing
          while the analyst is navigating).
        - Cancels any sleeping retry loop via _retry_cancel.
        - Snapshots the current state hash so _exit_intervention_mode() can
          detect whether any automated action fired during the handover window.
        - Prints a clear analyst banner to the terminal.
        """
        self._intervention_active = True
        self._retry_cancel.set()          # cancel sleeping retry loops
        self._retry_cancel.clear()        # reset for next cycle

        # Snapshot entry state for resume comparison
        tmp = str(self.xml_dir / f"_intervention_entry_{int(time.time())}.xml")
        xml = dump_ui_xml(tmp)
        self._intervention_entry_hash = hash_xml(xml) if xml else ""

        label = f" ({reason})" if reason else ""
        print()
        print(f"{Fore.YELLOW}{'┌' + '─' * 58 + '┐'}")
        print(f"{Fore.YELLOW}│{'  ⚠  HUMAN INTERVENTION MODE' + label:^58}│")
        print(f"{Fore.YELLOW}│{'':^58}│")
        print(f"{Fore.YELLOW}│{'  Navigate the app manually on the device.':^58}│")
        print(f"{Fore.YELLOW}│{'  Double-tap screen OR press Enter when done.':^58}│")
        print(f"{Fore.YELLOW}│{'':^58}│")
        print(f"{Fore.YELLOW}│{'  Automated ADB commands (force-stop, home,':^58}│")
        print(f"{Fore.YELLOW}│{'  relaunch) are BLOCKED while you work.':^58}│")
        print(f"{Fore.YELLOW}{'└' + '─' * 58 + '┘'}{Style.RESET_ALL}")
        print()

    def _exit_intervention_mode(self) -> None:
        """
        [v2.10] Clears intervention guard and compares current state hash
        against the entry snapshot.  If they differ, some automated action
        may have fired -- logs a warning.  Caller decides how to proceed.
        """
        self._intervention_active = False
        tmp = str(self.xml_dir / f"_intervention_exit_{int(time.time())}.xml")
        xml = dump_ui_xml(tmp)
        exit_hash = hash_xml(xml) if xml else ""
        if (self._intervention_entry_hash
                and exit_hash
                and exit_hash != self._intervention_entry_hash):
            info("[Intervention] State changed during intervention handover "
                 f"({self._intervention_entry_hash} → {exit_hash})")
        self._intervention_entry_hash = ""

    # ── [v2.14] Robustness helpers ────────────────────────────

    def _intervention_timeout(self) -> float:
        """
        [v2.14] Budget-gated intervention timeout.

        Never spend more than 20% of the remaining phase budget waiting for
        the analyst. Floor at 15s (minimum reaction time); ceiling at the
        configured STUCK_TIMEOUT.
        """
        if self._phase_deadline is None:
            return float(Config.STUCK_TIMEOUT)
        remaining = max(0.0, self._phase_deadline - time.time())
        return max(15.0, min(float(Config.STUCK_TIMEOUT), remaining * 0.20))

    def _verified_relaunch(self, context: str = "") -> bool:
        """
        [v2.14] Relaunch the app and verify the state actually changed.

        A relaunch is only considered successful when:
          (a) the app is in the foreground, AND
          (b) the post-launch state hash differs from the pre-launch hash.

        On same-screen relaunch: tombs the stuck state so DFS never re-enters it.
        On foreground failure: logs but does NOT tomb (may be a timing issue).

        Returns True only on genuine new-state success.
        Replaces all bare self._relaunch() calls in DFS and pass-boundary paths.
        """
        tmp = str(self.xml_dir / f"_vrl_pre_{int(time.time())}.xml")
        pre_xml  = dump_ui_xml(tmp)
        pre_hash = hash_xml(pre_xml) if pre_xml else ""

        self._relaunch()
        time.sleep(Config.SETTLE_DELAY)

        tmp2      = str(self.xml_dir / f"_vrl_post_{int(time.time())}.xml")
        post_xml  = dump_ui_xml(tmp2)
        post_hash = hash_xml(post_xml) if post_xml else ""
        in_fg     = self._is_app_in_foreground()

        if in_fg and post_hash and pre_hash and post_hash != pre_hash:
            ok(f"[Relaunch] Verified success ({context}) — new state {post_hash[:8]}")
            return True

        if in_fg and post_hash and pre_hash and post_hash == pre_hash:
            warn(f"[Relaunch] Opened on same screen ({context}) — "
                 f"tombing {pre_hash[:8]}")
            self._tombed_states.add(pre_hash)
            return False

        warn(f"[Relaunch] App not in foreground after launch ({context})")
        return False

    def _emergency_surface(self) -> bool:
        """
        [v2.14] 4-tier escape from stuck / lost state.

        Tier 1: Back-walk up to 5 times (cheapest — handles modals / dialogs).
        Tier 2: _verified_relaunch() — standard am start path.
        Tier 3: am force-stop + cold _verified_relaunch().
        Tier 4: Return False — caller must invoke _suspend().

        Always tombs the stuck state before returning False (Tier 4), so
        even if human intervention does not arrive in time, the next pass
        will never re-enter the dead screen.

        Returns True if the engine reached a new navigable state.
        """
        tmp      = str(self.xml_dir / f"_es_pre_{int(time.time())}.xml")
        pre_xml  = dump_ui_xml(tmp)
        pre_hash = hash_xml(pre_xml) if pre_xml else ""

        # ── Tier 1: back-walk ─────────────────────────────────
        for i in range(5):
            self.executor.back()
            time.sleep(Config.SETTLE_DELAY_SHORT)
            if not self._is_app_in_foreground():
                break
            tmp2 = str(self.xml_dir / f"_es_back{i}_{int(time.time())}.xml")
            new_xml  = dump_ui_xml(tmp2)
            new_hash = hash_xml(new_xml) if new_xml else ""
            if new_hash and new_hash != pre_hash:
                info(f"[Surface] Tier 1 escaped on back #{i+1}")
                self._consecutive_stale_visits = 0
                return True

        # ── Tier 2: verified relaunch ─────────────────────────
        if self._verified_relaunch("surface-t2"):
            info("[Surface] Tier 2 relaunch succeeded")
            return True

        # ── Tier 3: force-stop + cold start ───────────────────
        if not self._intervention_active:
            warn("[Surface] Tier 2 failed — force-stopping app")
            adb("shell", "am", "force-stop", self.package_name)
            time.sleep(2.0)
            if self._verified_relaunch("surface-t3"):
                info("[Surface] Tier 3 cold launch succeeded")
                self._consecutive_stale_visits = 0
                return True
        else:
            warn("[Surface] Tier 3 skipped — intervention active "
                 "(force-stop blocked while analyst navigates)")

        # ── Tier 4: human required ────────────────────────────
        err("[Surface] All tiers failed — flagging for human intervention")
        if pre_hash:
            self._tombed_states.add(pre_hash)
        return False

    def _suspend(self, reason: str, context: dict | None = None) -> None:
        """
        [v2.14] Structured human handoff — invoked immediately when
        _emergency_surface() returns False or a dropper UI is detected.

        Prints a clear structured terminal message (reason-specific), then
        blocks on HumanInterventionMonitor using the budget-gated timeout.
        On resume: validates state changed, resets stale-visit counter.
        On timeout: logs and returns (DFS caller will handle the dead branch).
        """
        ctx = context or {}

        # ── Print reason-specific terminal message ─────────────
        if reason == "dropper_ui":
            dropped_pkg = ctx.get("dropped_pkg", "<unknown>")
            print()
            print(f"{Fore.YELLOW}{'=' * 62}")
            print(f"  ═══ DROPPED APK UI DETECTED ═══")
            print(f"  Package: {dropped_pkg}")
            print(f"  The dropped APK is now in foreground.")
            print(f"  Action: This package should be explored separately.")
            print(f"  Suggested: Run sentry.py --apk {dropped_pkg}")
            print(f"  Press Enter to skip and continue with outer APK exploration.")
            print(f"{'=' * 62}{Style.RESET_ALL}")
            print()
        elif reason == "launcher_less":
            pass_num = ctx.get("pass", "?")
            print()
            print(f"{Fore.YELLOW}{'=' * 62}")
            print(f"  ═══ MANUAL LAUNCH REQUIRED ═══")
            print(f"  Pass {pass_num}/3 cannot start — app not in foreground.")
            print(f"  Action: Open the app from Settings → Apps → Open.")
            print(f"  Then navigate to the main screen.")
            print(f"  Double-tap device or press Enter to resume.")
            print(f"{'=' * 62}{Style.RESET_ALL}")
            print()
        elif reason == "wrong_screen":
            pass_num = ctx.get("pass", "?")
            print()
            print(f"{Fore.YELLOW}{'=' * 62}")
            print(f"  ═══ UNRECOVERABLE SCREEN ═══")
            print(f"  Pass {pass_num}/3 is on a tombed/unnavigable screen.")
            print(f"  Action: Navigate to the app home screen manually.")
            print(f"  Double-tap device or press Enter to resume.")
            print(f"{'=' * 62}{Style.RESET_ALL}")
            print()
        else:  # stuck_form or generic
            print()
            print(f"{Fore.YELLOW}{'=' * 62}")
            print(f"  ═══ MANUAL NAVIGATION REQUIRED ═══")
            print(f"  Reason: {reason}")
            if self._phase_deadline:
                budget_remaining = max(0.0, self._phase_deadline - time.time())
                print(f"  Budget remaining: {budget_remaining:.0f}s")
            print(f"  Action: Navigate app to a different screen.")
            print(f"  Double-tap device or press Enter to resume.")
            print(f"{'=' * 62}{Style.RESET_ALL}")
            print()

        self._enter_intervention_mode(reason)

        resume_event = threading.Event()
        monitor = HumanInterventionMonitor(
            xml_dir=self.xml_dir,
            resume_event=resume_event,
            dangerous_permissions=self._p1_dangerous_permissions,
            screens_dir=self.screens_dir,
            screenshot_tier=self.tier,
            frida_session=self.frida_session,
        )
        self._intervention_monitor = monitor
        monitor.start()

        suspend_start         = time.time()
        timeout               = self._intervention_timeout()
        intervention_deadline = suspend_start + timeout
        heartbeat_next        = suspend_start + Config.INTERVENTION_HEARTBEAT

        while not resume_event.is_set() and time.time() < intervention_deadline:
            wait_remaining = min(Config.INTERVENTION_HEARTBEAT,
                                 intervention_deadline - time.time())
            resume_event.wait(timeout=max(0.1, wait_remaining))
            if resume_event.is_set():
                break
            if time.time() >= heartbeat_next:
                elapsed_s   = int(time.time() - suspend_start)
                remaining_s = int(intervention_deadline - time.time())
                warn(f"⏳ [Suspend/{reason}] {elapsed_s}s elapsed, "
                     f"{remaining_s}s remaining — double-tap or Enter to resume")
                heartbeat_next = time.time() + Config.INTERVENTION_HEARTBEAT

        monitor.stop()
        monitor.join(timeout=2.0)
        self._intervention_monitor = None
        self._exit_intervention_mode()

        if resume_event.is_set():
            waited = time.time() - suspend_start
            ok(f"[Suspend/{reason}] Resumed after {waited:.1f}s")
            self._consecutive_stale_visits = 0

            intervention = monitor.get_result()
            if intervention:
                for human_action in intervention.actions_inferred:
                    self.session.actions.append(human_action)
                    self.session.total_actions += 1
                for h in intervention.screens_visited:
                    self._human_visited_states.add(h)
                    if not self.state_mgr.is_visited(h):
                        placeholder = UIState(
                            state_hash=h,
                            timestamp=ts(),
                            activity="(human_navigation)",
                            screenshot_path="",
                            xml_path="",
                            elements=[],
                            depth=0,
                        )
                        self.state_mgr.register(placeholder)
        else:
            warn(f"[Suspend/{reason}] No human response within {timeout:.0f}s — "
                 "continuing automatically")

    def _handle_global_pause(self) -> None:
        """
        [v2.12] Handle a global interrupt signal (double-tap or double-Enter
        fired by GlobalInterruptListener while DFS was running normally).

        Enters intervention mode, waits for the analyst to signal done
        (double-tap or Enter), then resumes. Mirrors the stuck-handler logic
        but is triggered by the analyst rather than a stuck condition.

        Called from _dfs() at the checkpoint at the top of each recursion and
        before every tap()/input_text() call.
        """
        if not self._global_pause_event.is_set():
            return

        ok("[GlobalPause] Global interrupt detected -- pausing DFS for analyst")
        self._enter_intervention_mode("global interrupt")

        resume_event = threading.Event()
        monitor = HumanInterventionMonitor(
            xml_dir=self.xml_dir,
            resume_event=resume_event,
            dangerous_permissions=self._p1_dangerous_permissions,
            screens_dir=self.screens_dir,
            screenshot_tier=self.tier,
            frida_session=self.frida_session,
        )
        self._intervention_monitor = monitor
        monitor.start()

        # Heartbeat loop — same pattern as stuck handler
        pause_start            = time.time()
        intervention_deadline  = pause_start + Config.INTERVENTION_TIMEOUT
        heartbeat_next         = pause_start + Config.INTERVENTION_HEARTBEAT

        while not resume_event.is_set() and time.time() < intervention_deadline:
            wait_remaining = min(Config.INTERVENTION_HEARTBEAT,
                                 intervention_deadline - time.time())
            resume_event.wait(timeout=max(0.1, wait_remaining))
            if resume_event.is_set():
                break
            if time.time() >= heartbeat_next:
                elapsed_s   = int(time.time() - pause_start)
                remaining_s = int(intervention_deadline - time.time())
                warn(f"⏳ [GlobalPause] Intervention active — "
                     f"{elapsed_s}s elapsed, {remaining_s}s remaining "
                     f"(double-tap device or press Enter to resume)")
                heartbeat_next = time.time() + Config.INTERVENTION_HEARTBEAT
                if remaining_s <= Config.INTERVENTION_HEARTBEAT:
                    warn(f"⚠  [GlobalPause] Intervention timeout in ~{remaining_s}s "
                         f"-- resuming DFS automatically")

        monitor.stop()
        monitor.join(timeout=2.0)
        self._intervention_monitor = None

        self._exit_intervention_mode()

        # Apply pruning + action log (same as stuck handler)
        if resume_event.is_set():
            intervention = monitor.get_result()
            waited = time.time() - pause_start
            ok(f"[GlobalPause] Resuming DFS after analyst pause "
               f"(waited {waited:.1f}s, "
               f"{len(intervention.screens_visited) if intervention else 0} screen(s) visited)")
            self.session.warnings.append(
                f"Global interrupt pause -- resumed after {waited:.1f}s")

            if intervention:
                for human_action in intervention.actions_inferred:
                    self.session.actions.append(human_action)
                    self.session.total_actions += 1

                for h in intervention.screens_visited:
                    self._human_visited_states.add(h)
                    if not self.state_mgr.is_visited(h):
                        placeholder = UIState(
                            state_hash=h,
                            timestamp=ts(),
                            activity="(human_navigation)",
                            screenshot_path="",
                            xml_path="",
                            elements=[],
                            depth=0,
                        )
                        self.state_mgr.register(placeholder)

        # Clear the pause event AFTER the monitor is stopped and state applied.
        # GlobalInterruptListener re-arms itself once this clears.
        self._global_pause_event.clear()

    def setup_frida(self) -> None:
        if self.tier == 2:
            self.frida_session = attach_flag_secure_bypass(self.package_name)
            if not self.frida_session:
                self.tier = 3
                self.session.screenshot_tier = 3

    def _elapsed(self) -> float:
        return time.time() - self.start_time

    def _timed_out(self) -> bool:
        return self._elapsed() >= Config.TIMEOUT

    def _phase_timed_out(self) -> bool:
        """[v2.7] True if the Phase A/B deadline has been exceeded."""
        if self._phase_deadline is None:
            return False
        return time.time() >= self._phase_deadline

    def _capture_state(self, state_hash: str) -> tuple[str, str]:
        """
        Capture screenshot and XML for the current state.
        Returns (screenshot_path, xml_path) -- screenshot_path may be "".
        """
        screen_path = ""
        xml_path = str(self.xml_dir / f"{state_hash}.xml")

        if self.tier <= 2:
            sp = str(self.screens_dir / f"{state_hash}.png")
            if capture_screenshot(sp, self.tier, self.frida_session):
                screen_path = sp

        return screen_path, xml_path

    def _is_app_alive(self) -> bool:
        r = adb("shell", "pidof", self.package_name)
        if r.stdout.strip():
            return True
        # ps -A fallback
        ps = adb("shell", "ps", "-A")
        return self.package_name in ps.stdout

    def _is_app_in_foreground(self) -> bool:
        """
        Check the current foreground activity belongs to this package.
        Prevents the explorer from tapping on the launcher/home screen
        after the app has been accidentally backgrounded.
        """
        r = adb("shell", "dumpsys", "activity", "activities")
        # Look for mResumedActivity -- covers all Android versions
        for pattern in [
            r'mResumedActivity.*?(\S+)/(\S+)',
            r'mFocusedActivity.*?(\S+)/(\S+)',
            r'realActivity=(\S+)/(\S+)',
        ]:
            m = re.search(pattern, r.stdout)
            if m:
                # m.group(1) is the package name portion
                fg_pkg = m.group(1).split("/")[0]
                return fg_pkg == self.package_name or \
                       self.package_name in fg_pkg
        # If we can't determine foreground, assume app is there
        return True

    def _safe_back(self, context: str = "") -> bool:
        """
        [v2.5-C] Press Back and verify it actually navigated.

        Problem: when a soft keyboard is open, KEYCODE_BACK closes the
        keyboard rather than navigating -- the XML changes slightly (keyboard
        overlay disappears) but the app screen is unchanged. This fools the
        engine into thinking it backtracked when it only dismissed the IME,
        causing the oscillation loop described in the v2.5 bug report.

        Strategy:
          1. Capture state_hash_before (strips scroll/index volatility).
          2. Press Back and settle.
          3. Capture state_hash_after.
          4. If hashes are identical -> back was a true no-op.
             If hashes differ only by keyboard XML tokens -> also treat as no-op.
          5. On no-op: press Home then relaunch to force a real navigation.

        Returns True if navigation was genuine, False if no-op (home+relaunch
        was used as escape instead).
        """
        # Hash before
        xml_path_tmp = str(self.xml_dir / f"_safeback_{int(time.time())}.xml")
        xml_before   = dump_ui_xml(xml_path_tmp)
        hash_before  = hash_xml(xml_before) if xml_before else ""

        self.executor.back()
        time.sleep(Config.SETTLE_DELAY)

        xml_after = dump_ui_xml(xml_path_tmp)
        hash_after = hash_xml(xml_after) if xml_after else ""

        if hash_before and hash_after and hash_before == hash_after:
            # True no-op -- back did nothing (keyboard was already dismissed
            # or we're at the root of the task stack)
            label = f" [{context}]" if context else ""
            warn(f"[SafeBack]{label} back() was a no-op "
                 f"(state unchanged: {hash_before}) -- escaping via Home+relaunch")
            # [v2.10] Block KEYCODE_HOME and relaunch while human owns device
            if self._intervention_active:
                warn("[SafeBack] Intervention active -- skipping Home+relaunch "
                     "to avoid disrupting analyst navigation")
                return False
            self.executor.home()
            time.sleep(1.0)
            self._verified_relaunch("safe-back-escape")   # [v2.14]
            time.sleep(1.5)
            return False

        return True

    def _relaunch(self) -> bool:
        # [v2.10] Never fire am start / am force-stop while human owns the device.
        # This prevents the engine from wiping in-memory malware state mid-analysis.
        if self._intervention_active:
            warn("[Relaunch] Intervention active -- relaunch suppressed "
                 "(am force-stop / am start blocked while analyst navigates)")
            return False
        if not self.main_activity:
            warn("No main activity -- cannot relaunch")
            return False
        component = f"{self.package_name}/{self.main_activity}"
        r = adb("shell", "am", "start", "-n", component)
        if r.returncode == 0 and "Error" not in r.stdout:
            time.sleep(2.0)
            ok(f"App relaunched: {component}")
            self.session.crashes_recovered += 1
            return True
        err(f"Relaunch failed: {r.stdout.strip()}")
        return False

    def _launch_package(self, package_name: str) -> bool:
        """
        [v2.4-4] Best-effort launcher for packages with no declared
        LAUNCHER intent (background APKs / dropped payloads).

        Strategy order:
          1. am start on the main activity inferred from pm dump
          2. monkey -p <pkg> 1  (fires any LAUNCHER intent the OS knows)
          3. am start on every declared activity until one succeeds
          4. Last resort: open Settings -> App Info -> tap Open button

        Returns True if the process appears within 5s of a launch attempt.
        """
        def _proc_alive(pkg: str) -> bool:
            r = adb("shell", "pidof", pkg)
            if r.stdout.strip():
                return True
            ps = adb("shell", "ps", "-A")
            return pkg in ps.stdout

        # ── Strategy 1: main activity from pm dump ────────────
        main_act = ""
        pm = adb("shell", "pm", "dump", package_name)
        for line in pm.stdout.splitlines():
            line = line.strip()
            if "android.intent.action.MAIN" in line and "/" in line:
                for token in line.split():
                    if "/" in token and package_name in token:
                        main_act = token.split("/", 1)[-1]
                        break
            if main_act:
                break

        if main_act:
            info(f"[Launch] am start -n {package_name}/{main_act}")
            r = adb("shell", "am", "start", "-n",
                    f"{package_name}/{main_act}")
            time.sleep(3.0)
            if _proc_alive(package_name):
                ok(f"[Launch] Process alive after am start: {package_name}")
                return True

        # ── Strategy 2: monkey ────────────────────────────────
        info(f"[Launch] monkey -p {package_name} 1")
        adb("shell", "monkey", "-p", package_name,
            "-c", "android.intent.category.LAUNCHER", "1")
        time.sleep(3.0)
        if _proc_alive(package_name):
            ok(f"[Launch] Process alive after monkey: {package_name}")
            return True

        # ── Strategy 3: all declared activities ───────────────
        activities = []
        in_act_section = False
        for line in pm.stdout.splitlines():
            line = line.strip()
            if "Activity Resolver Table" in line:
                in_act_section = True
            if in_act_section and package_name + "/" in line:
                for token in line.split():
                    if token.startswith(package_name + "/"):
                        act = token.split("/", 1)[-1]
                        if act not in activities:
                            activities.append(act)
        for act in activities:
            info(f"[Launch] am start -n {package_name}/{act}")
            r = adb("shell", "am", "start", "-n",
                    f"{package_name}/{act}")
            time.sleep(2.5)
            if _proc_alive(package_name):
                ok(f"[Launch] Process alive after start {act}: {package_name}")
                return True

        # ── Strategy 4 (last resort): Settings App Info -> Open ─
        warn(f"[Launch] No launcher found for {package_name} -- trying Settings")
        adb("shell", "am", "start", "-a",
            "android.settings.APPLICATION_DETAILS_SETTINGS",
            "-d", f"package:{package_name}")
        time.sleep(2.5)
        xml_tmp = str(self.xml_dir / "_launch_settings_tmp.xml")
        r = adb("shell", "uiautomator", "dump", "/sdcard/_launch_tmp.xml")
        adb("pull", "/sdcard/_launch_tmp.xml", xml_tmp)
        adb("shell", "rm", "-f", "/sdcard/_launch_tmp.xml")
        try:
            settings_xml = Path(xml_tmp).read_text(encoding="utf-8",
                                                    errors="replace")
            root = ET.fromstring(settings_xml)
            for node in root.iter("node"):
                label = (node.attrib.get("text", "") +
                         node.attrib.get("content-desc", "")).lower()
                if "open" in label and node.attrib.get("clickable") == "true":
                    nums = re.findall(r'\d+', node.attrib.get("bounds", ""))
                    if len(nums) == 4:
                        cx = (int(nums[0]) + int(nums[2])) // 2
                        cy = (int(nums[1]) + int(nums[3])) // 2
                        self.executor.tap(cx, cy)
                        time.sleep(3.0)
                        if _proc_alive(package_name):
                            ok(f"[Launch] Process alive after Settings Open: {package_name}")
                            return True
        except Exception:
            pass

        err(f"[Launch] All strategies failed for {package_name}")
        return False

    def _handle_permission_dialog(self, xml_str: str,
                                   state_hash: str) -> bool:
        """
        Accept permission dialog and record the action.
        Returns True if a dialog was handled.
        """
        if not is_permission_dialog(xml_str):
            return False

        info("[PermissionDialog] Accepting permission request")
        ok_result = self.executor.accept_permission_dialog(xml_str)
        if ok_result:
            self.session.permission_dialogs_accepted += 1
            self.session.actions.append(UIAction(
                timestamp=ts(),
                action_type="accept_permission",
                element_label="permission_dialog",
                element_class="android.app.AlertDialog",
                bounds="",
                triggered_dialog=True,
            ))
        time.sleep(Config.SETTLE_DELAY)
        return True

    def _interact_with_element(self, elem: UIElement,
                                state_hash: str,
                                xml_str: str = "") -> bool:
        """
        Execute the most appropriate action for a given element.
        Returns True if the action was performed.

        xml_str: the current screen XML, used to suppress form-submit
        machinery on install/permission dialogs whose button labels
        ("Install", "Allow") match POSITIVE_ACTION_KEYWORDS but are
        NOT form submits — tapping them hands off to PackageInstaller
        or the permission controller, which always returns the same
        state hash on the dialog screen, producing false FormSubmit
        failure logs and wasted retry cycles.  [v2.14-fix-1]
        """
        if not elem.enabled:
            return False

        # [v2.12] Global interrupt checkpoint (mid-action)
        if self._global_pause_event.is_set():
            self._handle_global_pause()

        if elem.is_text_field:
            # [v2.7] Fill blacklist -- skip if already filled this session
            field_key = (self.package_name, elem.resource_id)
            if field_key in self._filled_fields:
                skip(f"[Interact] Skipping already-filled field: {elem.label()}")
                return False

            val = generate_input(elem)

            # [v2.9-1] Focus-aware tap (replaces v2.7 IME-skip logic).
            # Never skip the tap because the keyboard is showing -- that only
            # means a DIFFERENT field has focus.  Only skip if the target
            # field itself already has focused="true".
            focused = _tap_and_focus(elem, self.xml_dir)
            if not focused:
                warn(f"[Interact] Could not focus '{elem.label()}' -- skipping")
                return False

            self.executor.input_text(val)
            time.sleep(0.3)
            self.executor.dismiss_keyboard()

            self._filled_fields.add(field_key)
            self.session.forms_filled += 1
            action_type = "input_text"
            action(f"Input '{val}' -> {elem.label()} ({elem.elem_class.split('.')[-1]})")

        elif elem.scrollable:
            self.executor.scroll_down(elem.center_x, elem.center_y)
            time.sleep(Config.SETTLE_DELAY)
            # Also scroll up to reveal any above-fold elements
            self.executor.scroll_up(elem.center_x, elem.center_y)
            action_type = "scroll_down"
            action(f"Scroll -> {elem.label()}")

        elif elem.clickable:
            # Special handling for Spinner/dropdown -- tap it then select first option
            is_spinner = "Spinner" in elem.elem_class or "spinner" in elem.resource_id.lower()

            # [v2.8-A] Detect if this is a form-submit / PROCEED button.
            # If so, capture state hash before and after tap to determine success.
            elem_label_lower = (elem.text + " " + elem.content_desc).lower()
            is_submit = any(k in elem_label_lower for k in POSITIVE_ACTION_KEYWORDS)

            # [v2.14-fix-1] Suppress form-submit path on install/permission dialogs.
            # Buttons like "Install" and "Allow" match POSITIVE_ACTION_KEYWORDS but
            # are NOT form submits — they hand off to PackageInstaller / permission
            # controller, which navigates away from the dialog entirely.  The same-
            # hash check then fires a false validation failure and wastes two retries.
            if is_submit and xml_str and (
                _is_install_dialog(xml_str) or is_permission_dialog(xml_str)
            ):
                is_submit = False

            if is_submit and not is_spinner:
                # Capture pre-tap XML for toast comparison
                pre_tap_xml_path = str(self.xml_dir / f"_pretap_{int(time.time())}.xml")
                pre_tap_xml  = dump_ui_xml(pre_tap_xml_path) or ""
                hash_before  = hash_xml(pre_tap_xml) if pre_tap_xml else ""

                ok_result = self.executor.tap(elem.center_x, elem.center_y)
                if not ok_result:
                    return False

                time.sleep(Config.FORM_RETRY_DELAY)
                post_tap_xml_path = str(self.xml_dir / f"_posttap_{int(time.time())}.xml")
                post_tap_xml  = dump_ui_xml(post_tap_xml_path) or ""
                hash_after    = hash_xml(post_tap_xml) if post_tap_xml else ""

                self.session.form_submits_attempted += 1

                # [v2.9-2] ERROR-FIRST CHECK: scan for errors regardless of
                # whether hash changed.  A setError() tooltip creates a new
                # PopupWindow subtree that CHANGES the hash even though the
                # app is still on the same form showing a validation error.
                # We must check for errors before we can trust a hash change
                # as a navigation signal.
                error_nodes = _scan_form_errors(post_tap_xml) if post_tap_xml else []

                # Also check for new PopupWindow nodes not present before tap
                # (catches setError() even when error text is non-standard)
                new_popup = False
                if pre_tap_xml and post_tap_xml:
                    pre_popups  = pre_tap_xml.count("PopupWindow")
                    post_popups = post_tap_xml.count("PopupWindow")
                    if post_popups > pre_popups:
                        new_popup = True
                        warn(f"[FormSubmit] New PopupWindow detected after tap "
                             f"(was={pre_popups}, now={post_popups}) -- "
                             f"likely setError() tooltip")

                is_error_state = bool(error_nodes) or new_popup

                if is_error_state:
                    # Errors found -- treat as validation failure even if hash changed
                    empty_fields = _scan_empty_fields(post_tap_xml) if post_tap_xml else []
                    warn(f"[FormSubmit] Validation failure (error-first) after "
                         f"'{elem.label()}' -- {len(error_nodes)} error node(s), "
                         f"new_popup={new_popup}, "
                         f"{len(empty_fields)} empty field(s)")

                    self.session.form_submit_failures.append({
                        "timestamp":    ts(),
                        "button":       elem.label(),
                        "state_hash":   hash_before,
                        "error_nodes":  error_nodes,
                        "empty_fields": empty_fields,
                        "new_popup":    new_popup,
                        "retries":      0,
                    })
                    self.session.actions.append(UIAction(
                        timestamp=ts(),
                        action_type="form_submit_failure",
                        element_label=elem.label(),
                        element_class=elem.elem_class,
                        bounds=elem.bounds,
                        new_state_hash=hash_after,
                        source="explorer",
                    ))

                    # Retry loop (same as v2.8 but now also reached on hash-change
                    # with errors, not just same-hash)
                    retried = 0
                    for _retry in range(Config.FORM_SUBMIT_RETRIES):
                        if self._timed_out() or self._phase_timed_out():
                            break
                        retry_xml_path = str(self.xml_dir /
                                             f"_retry_{int(time.time())}.xml")
                        retry_xml = dump_ui_xml(retry_xml_path) or ""
                        retry_elements = parse_elements(retry_xml) if retry_xml else []
                        refilled = False
                        for rf_elem in retry_elements:
                            if not rf_elem.is_text_field:
                                continue
                            # Re-fill even if in _filled_fields -- this is a retry
                            sibling_lbl = _get_sibling_label(retry_xml, rf_elem)
                            val = generate_input(rf_elem, sibling_label=sibling_lbl)
                            # [v2.9-1] Use _tap_and_focus even in retry path
                            focused = _tap_and_focus(rf_elem, self.xml_dir)
                            if focused:
                                self.executor.input_text(val)
                                time.sleep(0.2)
                                field_key = (self.package_name, rf_elem.resource_id)
                                self._filled_fields.add(field_key)
                                self.session.forms_filled += 1
                                refilled = True
                                info(f"  [FormRetry] Re-filled: "
                                     f"{rf_elem.label()} = '{val}'"
                                     + (f" [label: '{sibling_lbl}']"
                                        if sibling_lbl else ""))
                        if refilled:
                            self.executor.dismiss_keyboard()
                            time.sleep(Config.SETTLE_DELAY)

                        # Re-tap submit
                        hash_retry_before = hash_xml(dump_ui_xml(retry_xml_path) or "")
                        self.executor.tap(elem.center_x, elem.center_y)
                        time.sleep(Config.FORM_RETRY_DELAY)
                        post_retry_path = str(self.xml_dir /
                                              f"_postretry_{int(time.time())}.xml")
                        post_retry_xml  = dump_ui_xml(post_retry_path) or ""
                        hash_retry_after = hash_xml(post_retry_xml) if post_retry_xml else ""

                        # [v2.9-2] Error-first check on retry too
                        retry_errors = _scan_form_errors(post_retry_xml) if post_retry_xml else []
                        retry_popup  = (post_retry_xml.count("PopupWindow") >
                                        (retry_xml or "").count("PopupWindow"))

                        retried += 1
                        self.session.form_submit_failures[-1]["retries"] = retried

                        if not retry_errors and not retry_popup and \
                           hash_retry_before and hash_retry_after and \
                           hash_retry_before != hash_retry_after:
                            ok(f"[FormSubmit] Retry {retried} succeeded "
                               f"(navigated, no errors)")
                            self.session.form_submits_succeeded += 1
                            self.session.actions.append(UIAction(
                                timestamp=ts(),
                                action_type="form_submit_success",
                                element_label=elem.label(),
                                element_class=elem.elem_class,
                                bounds=elem.bounds,
                                new_state_hash=hash_retry_after,
                                source="explorer",
                            ))
                            break
                        warn(f"[FormSubmit] Retry {retried} still failed "
                             f"(errors={len(retry_errors)}, popup={retry_popup})")
                    else:
                        warn(f"[FormSubmit] Giving up after "
                             f"{Config.FORM_SUBMIT_RETRIES} retries -- "
                             f"backing out to avoid spinning")

                elif hash_before and hash_after and hash_before == hash_after:
                    # Same hash, no errors -- check for success toast
                    toast_success = _detect_success_toast(pre_tap_xml, post_tap_xml)
                    if toast_success:
                        ok(f"[FormSubmit] Toast-success detected after tapping "
                           f"'{elem.label()}' -- counting as success")
                        self.session.form_submits_succeeded += 1
                        self.session.actions.append(UIAction(
                            timestamp=ts(),
                            action_type="form_submit_success",
                            element_label=elem.label(),
                            element_class=elem.elem_class,
                            bounds=elem.bounds,
                            new_state_hash=hash_after,
                            source="explorer",
                        ))
                    else:
                        # Same hash, no errors, no toast -- also a failure
                        empty_fields = _scan_empty_fields(post_tap_xml) if post_tap_xml else []
                        warn(f"[FormSubmit] Validation failure (same hash, "
                             f"no toast) after '{elem.label()}' -- "
                             f"{len(empty_fields)} empty field(s)")
                        self.session.form_submit_failures.append({
                            "timestamp":    ts(),
                            "button":       elem.label(),
                            "state_hash":   hash_before,
                            "error_nodes":  [],
                            "empty_fields": empty_fields,
                            "new_popup":    False,
                            "retries":      0,
                        })
                        self.session.actions.append(UIAction(
                            timestamp=ts(),
                            action_type="form_submit_failure",
                            element_label=elem.label(),
                            element_class=elem.elem_class,
                            bounds=elem.bounds,
                            new_state_hash=hash_after,
                            source="explorer",
                        ))
                        # Retry loop for same-hash-no-error case
                        retried = 0
                        for _retry in range(Config.FORM_SUBMIT_RETRIES):
                            if self._timed_out() or self._phase_timed_out():
                                break
                            retry_xml_path = str(self.xml_dir /
                                                 f"_retry_{int(time.time())}.xml")
                            retry_xml = dump_ui_xml(retry_xml_path) or ""
                            retry_elements = parse_elements(retry_xml) if retry_xml else []
                            refilled = False
                            for rf_elem in retry_elements:
                                if not rf_elem.is_text_field:
                                    continue
                                sibling_lbl = _get_sibling_label(retry_xml, rf_elem)
                                val = generate_input(rf_elem, sibling_label=sibling_lbl)
                                focused = _tap_and_focus(rf_elem, self.xml_dir)
                                if focused:
                                    self.executor.input_text(val)
                                    time.sleep(0.2)
                                    field_key = (self.package_name, rf_elem.resource_id)
                                    self._filled_fields.add(field_key)
                                    self.session.forms_filled += 1
                                    refilled = True
                                    info(f"  [FormRetry] Re-filled: "
                                         f"{rf_elem.label()} = '{val}'")
                            if refilled:
                                self.executor.dismiss_keyboard()
                                time.sleep(Config.SETTLE_DELAY)

                            hash_retry_before = hash_xml(dump_ui_xml(retry_xml_path) or "")
                            self.executor.tap(elem.center_x, elem.center_y)
                            time.sleep(Config.FORM_RETRY_DELAY)
                            post_retry_path = str(self.xml_dir /
                                                  f"_postretry_{int(time.time())}.xml")
                            post_retry_xml  = dump_ui_xml(post_retry_path) or ""
                            hash_retry_after = hash_xml(post_retry_xml) if post_retry_xml else ""
                            retry_errors = _scan_form_errors(post_retry_xml) if post_retry_xml else []
                            retry_popup  = (post_retry_xml.count("PopupWindow") >
                                            (retry_xml or "").count("PopupWindow"))

                            retried += 1
                            self.session.form_submit_failures[-1]["retries"] = retried

                            if not retry_errors and not retry_popup and \
                               hash_retry_before and hash_retry_after and \
                               hash_retry_before != hash_retry_after:
                                ok(f"[FormSubmit] Retry {retried} succeeded")
                                self.session.form_submits_succeeded += 1
                                self.session.actions.append(UIAction(
                                    timestamp=ts(),
                                    action_type="form_submit_success",
                                    element_label=elem.label(),
                                    element_class=elem.elem_class,
                                    bounds=elem.bounds,
                                    new_state_hash=hash_retry_after,
                                    source="explorer",
                                ))
                                break
                            warn(f"[FormSubmit] Retry {retried} still failed")
                        else:
                            warn(f"[FormSubmit] Giving up after "
                                 f"{Config.FORM_SUBMIT_RETRIES} retries -- "
                                 f"backing out to avoid spinning")

                else:
                    # Hash changed AND no errors -- genuine navigation success
                    ok(f"[FormSubmit] Success: '{elem.label()}' navigated "
                       f"from {hash_before} -> {hash_after}")
                    self.session.form_submits_succeeded += 1
                    self.session.actions.append(UIAction(
                        timestamp=ts(),
                        action_type="form_submit_success",
                        element_label=elem.label(),
                        element_class=elem.elem_class,
                        bounds=elem.bounds,
                        new_state_hash=hash_after,
                        source="explorer",
                    ))

                action_type = "tap"
                action(f"Tap [submit] -> {elem.label()} ({elem.elem_class.split('.')[-1]})")

            else:
                # Non-submit clickable (or spinner)
                ok_result = self.executor.tap(elem.center_x, elem.center_y)
                if not ok_result:
                    return False
                if is_spinner:
                    # Wait for dropdown list to appear then tap first non-empty item
                    time.sleep(Config.SETTLE_DELAY)
                    xml_tmp_path = str(self.xml_dir / "_spinner_tmp.xml")
                    r = adb("shell", "uiautomator", "dump", "/sdcard/_spinner_tmp.xml")
                    adb("pull", "/sdcard/_spinner_tmp.xml", xml_tmp_path)
                    adb("shell", "rm", "-f", "/sdcard/_spinner_tmp.xml")
                    try:
                        spinner_xml = Path(xml_tmp_path).read_text(
                            encoding="utf-8", errors="replace")
                        import xml.etree.ElementTree as ET
                        sroot = ET.fromstring(spinner_xml)
                        for node in sroot.iter("node"):
                            node_text = node.attrib.get("text", "").strip()
                            clickable  = node.attrib.get("clickable", "false") == "true"
                            if clickable and node_text and node_text.lower() not in (
                                "", "cancel", "none", "select"
                            ):
                                bounds = node.attrib.get("bounds", "")
                                nums = re.findall(r'\d+', bounds)
                                if len(nums) == 4:
                                    cx = (int(nums[0]) + int(nums[2])) // 2
                                    cy = (int(nums[1]) + int(nums[3])) // 2
                                    self.executor.tap(cx, cy)
                                    action(f"Spinner selected: '{node_text}'")
                                    break
                    except Exception:
                        pass
                action_type = "tap"
                action(f"Tap -> {elem.label()} ({elem.elem_class.split('.')[-1]})")

        elif elem.long_clickable:
            ok_result = self.executor.long_tap(elem.center_x, elem.center_y)
            if not ok_result:
                return False
            action_type = "long_tap"
            action(f"Long-tap -> {elem.label()}")

        elif elem.checkable:
            ok_result = self.executor.tap(elem.center_x, elem.center_y)
            if not ok_result:
                return False
            action_type = "tap"
            action(f"Toggle -> {elem.label()}")

        else:
            return False

        time.sleep(Config.ACTION_DELAY)
        self.state_mgr.mark_action(state_hash, elem.key())
        self.session.total_actions += 1
        return True

    def _process_state(self, xml_str: str, xml_path: str,
                        screen_path: str, depth: int) -> Optional[UIState]:
        """Build and register a UIState from the current XML."""
        state_hash  = hash_xml(xml_str)
        activity    = get_current_activity()
        elements    = parse_elements(xml_str)
        is_perm     = is_permission_dialog(xml_str)
        is_dlg      = is_dialog_overlay(xml_str)

        # Save XML to disk
        Path(xml_path).write_text(xml_str, encoding="utf-8")

        ui_state = UIState(
            state_hash=state_hash,
            timestamp=ts(),
            activity=activity,
            screenshot_path=screen_path,
            xml_path=xml_path,
            elements=elements,
            depth=depth,
            is_dialog=is_dlg,
            is_permission_dialog=is_perm,
        )

        if activity and activity not in self.session.unique_activities:
            self.session.unique_activities.append(activity)
            ok(f"New activity: {activity}")

        return ui_state

    def _validate_start_state(self, pass_num: int) -> bool:
        """
        [v2.14] Gate called at the top of each pass in explore() before
        _dfs(0) is invoked.  Prevents wasting a full pass budget when the
        engine is in a known-bad starting state.

        Gate 1: MAX_STATES already reached — skip pass entirely.
        Gate 2: App not in foreground — attempt _verified_relaunch(); if that
                fails, call _suspend(launcher_less) and re-check.
        Gate 3: Starting on a tombed state — call _emergency_surface(); if
                that fails, call _suspend(wrong_screen) and re-check.

        Returns True if it is safe to start a DFS pass.
        """
        # Gate 1: state ceiling already hit
        if self.state_mgr.total_states() >= Config.MAX_STATES:
            info(f"[PASS {pass_num}] MAX_STATES reached — skipping pass")
            return False

        # Gate 2: app not in foreground
        if not self._is_app_in_foreground():
            warn(f"[PASS {pass_num}] App not in foreground at pass start")
            if not self._verified_relaunch(f"pass-{pass_num}-start"):
                self._suspend(reason="launcher_less",
                              context={"pass": pass_num})
                # After human resumes, re-check
                if not self._is_app_in_foreground():
                    warn(f"[PASS {pass_num}] App still not in foreground "
                         "after suspension — skipping pass")
                    return False

        # Gate 3: starting on a tombed state
        tmp = str(self.xml_dir / f"_vss_p{pass_num}_{int(time.time())}.xml")
        xml = dump_ui_xml(tmp)
        current_hash = hash_xml(xml) if xml else ""
        if current_hash and current_hash in self._tombed_states:
            warn(f"[PASS {pass_num}] Starting on tombed state "
                 f"{current_hash[:8]} — surfacing")
            if not self._emergency_surface():
                self._suspend(reason="wrong_screen",
                              context={"pass": pass_num})
                # Re-check after suspension
                tmp2 = str(self.xml_dir /
                           f"_vss_p{pass_num}_post_{int(time.time())}.xml")
                xml2 = dump_ui_xml(tmp2)
                post_hash = hash_xml(xml2) if xml2 else ""
                if post_hash and post_hash in self._tombed_states:
                    warn(f"[PASS {pass_num}] Still on tombed state after "
                         "suspension — skipping pass")
                    return False

        return True

    def explore(self) -> None:
        """
        [v2.11] Main traversal loop — 3-pass continuation model.

        Runs up to 3 DFS passes. State is persistent across passes:
        state_mgr.visited, interaction_map, and _filled_fields are never
        cleared between passes so each pass picks up exactly where the
        previous one left off.

        A single _phase_deadline set by sentry spans all three passes.
        No per-pass budget reset — remaining budget shrinks continuously.

        Inter-pass gate: when _dfs(0) exhausts at the root, the next
        pass's _dfs(0) finds no untried elements, enters stuck mode, and
        fires the existing HumanInterventionMonitor heartbeat loop. The
        analyst double-taps the device or presses Enter to signal they've
        navigated to a missed branch. This IS the review window — no new
        method is needed.

        Per-pass reset (allows stuck handler to re-fire each pass):
          _stuck_entry_hash, _intervention_active,
          _intervention_entry_hash, _retry_cancel

        NOT reset between passes (full persistence):
          state_mgr.visited, state_mgr.interaction_map,
          _filled_fields, _human_visited_states, _post_stuck_hashes
        """
        banner("PHASE 3 // UI Traversal Starting (3-pass)", "═")
        info(f"Package     : {self.package_name}")
        info(f"Tier        : {self.tier} "
             f"({'Magisk' if self.tier==1 else 'Frida' if self.tier==2 else 'XML only'})")
        info(f"Max depth   : pass1={Config.MAX_DEPTH_PASS1}  "
             f"pass2={Config.MAX_DEPTH_PASS2}  "
             f"pass3={Config.MAX_DEPTH_PASS3}  [v2.14 graduated]")
        info(f"Max states  : {Config.MAX_STATES}")
        info(f"Timeout     : {Config.TIMEOUT}s")
        total_budget = Config.MAIN_APP_TIMEOUT
        if self._phase_deadline:
            remaining = max(0, self._phase_deadline - time.time())
            info(f"Phase budget: {remaining:.0f}s remaining / {total_budget}s total "
                 f"[v2.11 shared across 3 passes]")
        print()

        # [v2.10] Pre-DFS manual foreground handoff for stealth/dropper APKs.
        # Run once before the pass loop — only needed on first entry.
        if not self.main_activity and not self._is_app_in_foreground():
            warn("No main activity and app not in foreground -- requesting manual launch")
            self._enter_intervention_mode("pre-DFS: please launch the app manually on the device")
            handoff_deadline = time.time() + Config.INTERVENTION_TIMEOUT
            heartbeat_next   = time.time() + Config.INTERVENTION_HEARTBEAT
            brought_up = False
            while time.time() < handoff_deadline:
                if self._retry_cancel.wait(timeout=1.0):
                    break
                if self._is_app_in_foreground():
                    brought_up = True
                    break
                if time.time() >= heartbeat_next:
                    elapsed   = int(time.time() - (handoff_deadline - Config.INTERVENTION_TIMEOUT))
                    remaining = int(handoff_deadline - time.time())
                    warn(f"⏳ [Pre-DFS Handoff] Waiting for app to appear in foreground "
                         f"({elapsed}s elapsed, {remaining}s remaining) ...")
                    heartbeat_next = time.time() + Config.INTERVENTION_HEARTBEAT
            self._exit_intervention_mode()
            if not brought_up:
                warn(f"[Pre-DFS Handoff] App did not appear within "
                     f"{Config.INTERVENTION_TIMEOUT}s -- aborting traversal")
                return
            ok("[Pre-DFS Handoff] App now in foreground -- starting DFS")

        # ── [v2.12] Start global interrupt listener ────────────
        self._global_interrupt_listener = GlobalInterruptListener(
            pause_event=self._global_pause_event
        )
        self._global_interrupt_listener.start()
        ok("[GlobalInterrupt] Background interrupt listener started "
           "(double-tap device or double-Enter to pause DFS at any time)")

        # ── [v2.11 / v2.14] Three-pass continuation loop ─────
        # [v2.14] Each pass has a graduated depth ceiling (shallow→deep)
        # and is gated by _validate_start_state() before DFS runs.
        # Between passes 1→2 and 2→3: home-screen anchor via
        # _emergency_surface() ensures DFS starts from the root, not
        # mid-activity.  _branch_ledger persists so passes 2/3 skip
        # already-exhausted home-screen branches.
        _depth_limits = [
            Config.MAX_DEPTH_PASS1,
            Config.MAX_DEPTH_PASS2,
            Config.MAX_DEPTH_PASS3,
        ]

        for pass_num in range(1, 4):
            if self._timed_out():
                info(f"[EXPLORE] Pass {pass_num}/3: global timeout reached -- stopping")
                break

            # Budget check before starting pass
            if self._phase_timed_out():
                info(f"[EXPLORE] Shared budget exhausted before pass {pass_num}/3 "
                     f"-- stopping early")
                break

            # ── Per-pass state reset ────────────────────────────
            # Resets: stuck handler flags, stale-visit counter.
            # Persists: state_mgr, _filled_fields, _human_visited_states,
            #           _post_stuck_hashes, _tombed_states, _branch_ledger.
            self._stuck_entry_hash        = None
            self._intervention_active     = False
            self._intervention_entry_hash = ""
            self._retry_cancel            = threading.Event()
            self._consecutive_stale_visits = 0   # [v2.14] reset health counter

            # ── [v2.14] Set graduated depth for this pass ───────
            self._current_max_depth = _depth_limits[pass_num - 1]
            info(f"[EXPLORE] Pass {pass_num}/3: max depth = {self._current_max_depth}")

            # ── Between-pass home-screen anchor ─────────────────
            # Pass 1: skip — app freshly launched by sentry.
            # Pass 2/3: surface to home screen via _emergency_surface() so DFS
            #           always starts from the root, not mid-activity.
            #           If surface fails, _validate_start_state() handles it.
            if pass_num > 1:
                info(f"[EXPLORE] Pass {pass_num}/3: anchoring to home screen")
                surfaced = self._emergency_surface()
                if not surfaced:
                    # Surface failed — _validate_start_state will suspend/skip
                    warn(f"[EXPLORE] Pass {pass_num}/3: home-screen anchor failed "
                         f"— _validate_start_state will attempt recovery")
                else:
                    time.sleep(Config.SETTLE_DELAY)

            # ── [v2.14] Pass start state validation gate ─────────
            if not self._validate_start_state(pass_num):
                info(f"[EXPLORE] Pass {pass_num}/3: skipped (start state invalid)")
                continue

            # ── Log pass start ─────────────────────────────────
            remaining_budget = (
                max(0.0, self._phase_deadline - time.time())
                if self._phase_deadline else float("inf")
            )
            budget_str = (
                f"{remaining_budget:.0f}s / {total_budget}s"
                if self._phase_deadline else "unlimited"
            )
            info(f"[EXPLORE] Pass {pass_num}/3: starting "
                 f"(budget remaining: {budget_str}, depth cap: {self._current_max_depth})"
                 f" -- {self.package_name}")

            # ── Run the DFS pass ───────────────────────────────
            self._dfs(depth=0)

            states_so_far = self.session.states_visited
            info(f"[EXPLORE] Pass {pass_num}/3 complete -- "
                 f"{states_so_far} total states visited")

            # Budget / timeout check after pass
            if self._timed_out():
                info(f"[EXPLORE] Global timeout reached after pass {pass_num}/3 -- stopping")
                break
            if self._phase_timed_out():
                info(f"[EXPLORE] Shared budget exhausted after pass {pass_num}/3 -- stopping")
                break

        # ── [v2.12] Stop global interrupt listener ─────────────
        if self._global_interrupt_listener:
            self._global_interrupt_listener.stop()
            self._global_interrupt_listener.join(timeout=2.0)
            self._global_interrupt_listener = None

        # Phase deadline is cleared by the caller (sentry._explore_with_stop)
        # after explore() returns. Do not clear it here — sentry needs it to
        # detect whether the budget ran dry.
        info(f"[EXPLORE] 3-pass exploration complete -- "
             f"{self.session.states_visited} total states visited")

    def explore_package(self, package_name: str) -> None:
        """
        [v2.4-4] Explore a secondary package (dropper/packer payload)
        sequentially after the main app's DFS has completed.

        Saves the current package context, switches to the new package,
        attempts to launch it via _launch_package(), runs a fresh DFS
        with reset state tracking, then restores the original context
        so any further exploration returns to the main package.

        [v2.10] Dropper output directories are now created under the main
        app's session directory at:
            <session_dir>/droppers/<package_name>/screenshots/
            <session_dir>/droppers/<package_name>/xml/
        This keeps all artefacts for a single analysis run in one tree
        rooted at session_dir, instead of a separate top-level sessions/ path.

        Called by sentry.py after the main ExplorerEngine.explore() call
        returns, for each detected dropper/packer package.
        """
        if not package_name or package_name == self.package_name:
            return

        banner(f"PHASE 3E // Dropper Exploration: {package_name}", "─")
        info(f"Switching explorer to package: {package_name}")

        # [v2.14] Register the dropper package so _dfs() foreground-shift
        # detection can identify it if it later surfaces during main-app DFS.
        self._known_dropper_packages.add(package_name)

        # Save main-app context (including I/O directories)
        orig_pkg         = self.package_name
        orig_activity    = self.main_activity
        orig_states      = self.state_mgr
        orig_session     = self.session
        orig_session_dir = self.session_dir
        orig_screens_dir = self.screens_dir
        orig_xml_dir     = self.xml_dir

        # [v2.10] Create dropper-scoped output dirs under the main session dir
        dropper_dir     = self.session_dir / "droppers" / package_name
        dropper_screens = dropper_dir / "screenshots"
        dropper_xml     = dropper_dir / "xml"
        dropper_dir.mkdir(parents=True, exist_ok=True)
        dropper_screens.mkdir(parents=True, exist_ok=True)
        dropper_xml.mkdir(parents=True, exist_ok=True)
        info(f"Dropper output dir: {dropper_dir}")

        # Switch I/O dirs to dropper-scoped paths
        self.session_dir = dropper_dir
        self.screens_dir = dropper_screens
        self.xml_dir     = dropper_xml

        # Reset for child package
        self.package_name  = package_name
        self.main_activity = ""            # will be inferred by _launch_package
        self.state_mgr     = UIStateManager()
        self._recent_states.clear()
        self._install_dialog_seen.clear()
        self._filled_fields.clear()          # [v2.7] clear per-package field blacklist
        # [v2.8-B/C] clear intervention tracking for new package
        self._stuck_entry_hash    = None
        self._post_stuck_hashes.clear()
        self._human_visited_states.clear()
        # [v2.10] clear intervention safety flags for new package
        self._intervention_active = False
        self._retry_cancel.clear()
        self._global_pause_event.clear()   # [v2.12] clear any pending interrupt from prior package
        # [v2.14] clear per-package robustness fields
        self._tombed_states.clear()
        self._branch_ledger.clear()
        self._consecutive_stale_visits = 0
        self._current_max_depth = Config.MAX_DEPTH

        # Attempt launch
        launched = self._launch_package(package_name)
        if not launched:
            warn(f"Could not launch {package_name} -- skipping dropper exploration")
        else:
            time.sleep(2.0)
            # Infer main activity now that app is running
            pm = adb("shell", "pm", "dump", package_name)
            for line in pm.stdout.splitlines():
                line = line.strip()
                if "android.intent.action.MAIN" in line and "/" in line:
                    for token in line.split():
                        if "/" in token and package_name in token:
                            self.main_activity = token.split("/", 1)[-1]
                            break
                if self.main_activity:
                    break

            info(f"Dropper main activity: {self.main_activity or '(unknown)'}")
            # [v2.12] (Re)start global interrupt listener for this package's DFS
            _pkg_interrupt_listener = GlobalInterruptListener(
                pause_event=self._global_pause_event
            )
            _pkg_interrupt_listener.start()
            try:
                self._dfs(depth=0)
            finally:
                # [v2.12] Stop package-scoped global interrupt listener
                _pkg_interrupt_listener.stop()
                _pkg_interrupt_listener.join(timeout=2.0)

        ok(f"Dropper exploration complete: {package_name}")

        # Restore main-app context (including I/O directories)
        self.package_name  = orig_pkg
        self.main_activity = orig_activity
        self.state_mgr     = orig_states
        self.session_dir   = orig_session_dir
        self.screens_dir   = orig_screens_dir
        self.xml_dir       = orig_xml_dir
        self._recent_states.clear()
        self._install_dialog_seen.clear()

    def _dfs(self, depth: int) -> None:
        """Recursive DFS. Backtracks by pressing the back button."""
        if self._timed_out():
            warn("Timeout reached -- stopping traversal")
            return
        if self._phase_timed_out():
            warn("[v2.7] Phase budget exceeded -- handing off to next phase")
            return
        if self.state_mgr.total_states() >= Config.MAX_STATES:
            warn("Max states reached -- stopping traversal")
            return
        if depth > self._current_max_depth:
            skip(f"Max depth {self._current_max_depth} reached -- backtracking")
            return

        # [v2.12] Global interrupt checkpoint — pause here if analyst signalled
        if self._global_pause_event.is_set():
            self._handle_global_pause()

        # ── Check app is alive and in foreground ─────────────
        if not self._is_app_alive():
            warn("App not running -- attempting relaunch")
            if not self._verified_relaunch("dfs-app-not-alive"):
                return
            time.sleep(1.5)

        if not self._is_app_in_foreground():
            warn("App is not in foreground -- bringing back to front")
            if self.main_activity:
                adb("shell", "am", "start", "-n",
                    f"{self.package_name}/{self.main_activity}")
                time.sleep(2.0)
            else:
                # [v2.10] No launcher activity -- hand off to analyst instead of
                # silently returning (which produced 0 states in stealth-dropper APKs).
                warn("No main activity -- cannot bring app to foreground automatically")
                self._enter_intervention_mode("no-launcher: please foreground the app manually")

                # Manual foreground handoff: wait up to INTERVENTION_TIMEOUT seconds
                # for the analyst to bring the app up.  Heartbeat every HEARTBEAT secs.
                handoff_deadline = time.time() + Config.INTERVENTION_TIMEOUT
                heartbeat_next   = time.time() + Config.INTERVENTION_HEARTBEAT
                brought_up = False
                while time.time() < handoff_deadline:
                    if self._retry_cancel.wait(timeout=1.0):
                        break
                    if self._is_app_in_foreground():
                        brought_up = True
                        break
                    if time.time() >= heartbeat_next:
                        elapsed = int(time.time() - (handoff_deadline - Config.INTERVENTION_TIMEOUT))
                        remaining = int(handoff_deadline - time.time())
                        warn(f"[Handoff] Still waiting for analyst to foreground app "
                             f"({elapsed}s elapsed, {remaining}s remaining) ...")
                        heartbeat_next = time.time() + Config.INTERVENTION_HEARTBEAT

                self._exit_intervention_mode()

                if not brought_up:
                    warn("[Handoff] Analyst did not bring app to foreground within "
                         f"{Config.INTERVENTION_TIMEOUT}s -- aborting this DFS branch")
                    return
                ok("[Handoff] App now in foreground -- resuming DFS")

        # ── [v2.14] Foreground-shift detection ──────────────
        # If a dropped APK's UI is now active, suspend instead of exploring
        # the wrong package.  Unknown packages are surfaced via emergency escape.
        _fg_pkg = get_foreground_package()
        if _fg_pkg and _fg_pkg != self.package_name:
            if _fg_pkg in self._known_dropper_packages:
                warn(f"[DFS] Foreground shifted to dropped pkg: {_fg_pkg}")
                self._suspend(reason="dropper_ui",
                              context={"dropped_pkg": _fg_pkg})
                return
            else:
                warn(f"[DFS] Unknown package in foreground: {_fg_pkg} — surfacing")
                self._emergency_surface()
                return

        # ── Dump current UI ──────────────────────────────────
        state_hash_tmp = f"tmp_{int(time.time())}"
        xml_path_tmp   = str(self.xml_dir / f"{state_hash_tmp}.xml")
        screen_path, _ = self._capture_state(state_hash_tmp)

        xml_str = dump_ui_xml(xml_path_tmp)
        if not xml_str:
            warn("UI dump failed -- skipping state")
            return

        # ── Handle permission dialogs ────────────────────────
        if self._handle_permission_dialog(xml_str, ""):
            # After accepting, re-dump the UI and continue
            _settle()
            xml_str = dump_ui_xml(xml_path_tmp)
            if not xml_str:
                return

        # ── Compute canonical state hash ─────────────────────
        state_hash = hash_xml(xml_str)

        # ── [v2.4-2] Backtrack loop detection ────────────────
        # If this state has appeared 3+ times in the last 6 steps,
        # we are oscillating. Hard-reset instead of pressing Back again.
        self._recent_states.append(state_hash)
        if self._recent_states.count(state_hash) >= 3:
            warn(f"Loop detected -- state {state_hash} seen "
                 f"{self._recent_states.count(state_hash)}x in last "
                 f"{len(self._recent_states)} steps. Hard-resetting.")
            self._recent_states.clear()
            if not self._verified_relaunch("loop-detection"):
                # Verified relaunch failed (or same screen) — tomb and surface
                if not self._emergency_surface():
                    self._suspend(reason="stuck_form",
                                  context={"reason": "loop detected, relaunch failed"})
            time.sleep(1.5)
            return

        # ── [v2.4-3] Install-dialog dedup ────────────────────
        # If we have already acted on this install confirmation dialog,
        # skip it entirely. Do NOT press Back (that re-triggers the loop).
        if _is_install_dialog(xml_str):
            if state_hash in self._install_dialog_seen:
                skip(f"Install dialog {state_hash} already acted on -- skipping")
                return
            # Will act on it below; mark it now so recursion doesn't re-enter.
            self._install_dialog_seen.add(state_hash)

        # ── [v2.14] Tomb guard ───────────────────────────────
        # Never enter a confirmed-dead state. If we landed here after
        # a relaunch or back-press, escape immediately.
        if state_hash in self._tombed_states:
            warn(f"[DFS] Entered tombed state {state_hash[:8]} — forcing back")
            self._safe_back("tomb-escape")
            _settle()
            return

        if self.state_mgr.is_visited(state_hash):
            # [v2.14] Stale-visit health check — detect "lost not stuck".
            # If we keep landing on already-visited states without making
            # progress, the engine is oscillating without a classic stuck
            # condition.  Trigger _emergency_surface() at threshold.
            self._consecutive_stale_visits += 1
            if self._consecutive_stale_visits >= Config.STALE_VISIT_THRESHOLD:
                warn(f"[DFS] Health: {self._consecutive_stale_visits} consecutive "
                     f"stale visits — triggering emergency surface")
                self._tombed_states.add(state_hash)
                self._consecutive_stale_visits = 0
                if not self._emergency_surface():
                    self._suspend(reason="stuck_form",
                                  context={"depth": depth, "reason": "stale visits"})
                return

            # Already visited -- check for untried elements before backtracking
            untried = self.state_mgr.get_untried(
                state_hash, parse_elements(xml_str))
            if not untried:
                skip(f"State {state_hash} fully explored -- backtracking")
                self._safe_back("fully-explored")   # [v2.5-C]
                _settle()
                return
            # Has untried elements -- continue from here
            state(f"Revisiting {state_hash} -- {len(untried)} untried elements")
        else:
            # New state — reset stale-visit counter
            self._consecutive_stale_visits = 0

            # ── New state ────────────────────────────────────
            xml_path    = str(self.xml_dir / f"{state_hash}.xml")
            screen_path, _ = self._capture_state(state_hash)
            ui_state    = self._process_state(xml_str, xml_path,
                                               screen_path, depth)
            self.state_mgr.register(ui_state)
            self.session.states.append(ui_state)
            self.session.states_visited += 1
            # [v2.8-B] Track dead-end hashes that can be pruned on human intervention
            if self._stuck_entry_hash is not None:
                self._post_stuck_hashes.add(state_hash)
            state(f"New state {state_hash}  depth={depth}  "
                  f"elements={len(ui_state.elements)}  "
                  f"activity={ui_state.activity.split('.')[-1] if ui_state.activity else '?'}")

        # ── Get untried elements for this state ───────────────
        elements = parse_elements(xml_str)
        # [v2.4-1] Apply install/allow priority sort before filtering untried
        elements = _prioritise_elements(elements)
        untried  = self.state_mgr.get_untried(state_hash, elements)

        if not untried:
            # Try scrolling to reveal off-screen elements
            scroll_elem = next((e for e in elements if e.scrollable), None)
            if scroll_elem:
                action("Scrolling to reveal off-screen elements")
                self.executor.scroll_down(scroll_elem.center_x,
                                           scroll_elem.center_y)
                _settle()
                xml_str  = dump_ui_xml(xml_path_tmp) or xml_str
                elements = _prioritise_elements(parse_elements(xml_str))
                untried  = self.state_mgr.get_untried(state_hash, elements)

        if not untried:
            # [v2.7/v2.8] Stuck-state detection.
            # We've dumped, scrolled, and still have nothing to interact with.
            # Rather than immediately backtracking, wait INTERVENTION_TIMEOUT seconds
            # for a human to manually change the UI, then resume with full
            # state-pruning and action-log recording (v2.8-B/C).
            stuck_entry = time.time()
            _stuck_timeout = self._intervention_timeout()   # [v2.14] budget-gated
            warn(f"[Stuck] No actionable elements in state {state_hash} "
                 f"-- waiting up to {_stuck_timeout:.0f}s for human intervention")

            # Print manifest-permission alert so analyst knows what's at stake
            if self._p1_dangerous_permissions:
                alert("[Stuck] Relevant dangerous permissions on this APK: "
                      + ", ".join(self._p1_dangerous_permissions[:8]))

            # [v2.8-B] Record the stuck entry so we can prune dead-end hashes later
            self._stuck_entry_hash = state_hash
            self._post_stuck_hashes.clear()

            # [v2.10] Enter intervention mode: blocks relaunch/home, cancels retry loops
            self._enter_intervention_mode(f"stuck at state {state_hash}")

            resume_event = threading.Event()
            monitor = HumanInterventionMonitor(
                xml_dir=self.xml_dir,
                resume_event=resume_event,
                dangerous_permissions=self._p1_dangerous_permissions,
                screens_dir=self.screens_dir,
                screenshot_tier=self.tier,
                frida_session=self.frida_session,
            )
            self._intervention_monitor = monitor
            monitor.start()

            # [v2.10 / v2.14] Heartbeat loop: print progress every INTERVENTION_HEARTBEAT
            # seconds; abort branch at budget-gated _intervention_timeout().
            intervention_deadline = time.time() + _stuck_timeout
            heartbeat_next        = time.time() + Config.INTERVENTION_HEARTBEAT
            while (not resume_event.is_set()
                   and time.time() < intervention_deadline):
                wait_remaining = min(Config.INTERVENTION_HEARTBEAT,
                                     intervention_deadline - time.time())
                resume_event.wait(timeout=max(0.1, wait_remaining))
                if resume_event.is_set():
                    break
                if time.time() >= heartbeat_next:
                    elapsed_s   = int(time.time() - stuck_entry)
                    remaining_s = int(intervention_deadline - time.time())
                    warn(f"⏳ [Stuck] Intervention active — "
                         f"{elapsed_s}s elapsed, {remaining_s}s remaining "
                         f"(double-tap device or press Enter to signal done)")
                    heartbeat_next = time.time() + Config.INTERVENTION_HEARTBEAT
                    if remaining_s <= Config.INTERVENTION_HEARTBEAT:
                        warn(f"⚠  [Stuck] Intervention timeout in ~{remaining_s}s "
                             f"-- aborting branch if no signal")

            monitor.stop()
            monitor.join(timeout=2.0)
            self._intervention_monitor = None

            # [v2.10] Release intervention guard before resuming automated actions
            self._exit_intervention_mode()

            if resume_event.is_set():
                intervention = monitor.get_result()
                waited = time.time() - stuck_entry
                ok(f"[Stuck] Resuming after human intervention "
                   f"(waited {waited:.1f}s, "
                   f"{len(intervention.screens_visited) if intervention else 0} screen(s) visited)")

                self.session.warnings.append(
                    f"Human intervention at state {state_hash} -- "
                    f"resumed after {waited:.1f}s")

                if intervention:
                    # [v2.8-C] Append synthetic human actions to session log
                    # BEFORE resuming DFS so the action trace has no gaps.
                    for human_action in intervention.actions_inferred:
                        self.session.actions.append(human_action)
                        self.session.total_actions += 1

                    # [v2.8-B] Add human-visited hashes to the human_visited set
                    # AND to state_mgr.visited so DFS won't re-traverse them.
                    # These must NOT be pruned -- separate from post_stuck_hashes.
                    for h in intervention.screens_visited:
                        self._human_visited_states.add(h)
                        if not self.state_mgr.is_visited(h):
                            # Register a lightweight placeholder so is_visited() returns True
                            placeholder = UIState(
                                state_hash=h,
                                timestamp=ts(),
                                activity="(human_navigation)",
                                screenshot_path="",
                                xml_path="",
                                elements=[],
                                depth=0,
                            )
                            self.state_mgr.register(placeholder)

                    # [v2.8-B] Prune ONLY the dead-end stuck-spin hashes.
                    # These are hashes in _post_stuck_hashes that are NOT in
                    # _human_visited_states (human screens are always safe to keep).
                    hashes_to_prune = (
                        self._post_stuck_hashes - self._human_visited_states
                    )
                    if hashes_to_prune:
                        info(f"[Stuck] Pruning {len(hashes_to_prune)} dead-end "
                             f"state(s) so DFS can re-explore via human's path")
                        for h in hashes_to_prune:
                            self.state_mgr.visited.pop(h, None)
                            self.state_mgr.interaction_map.pop(h, None)

                # Capture the new state screenshot then resume DFS from depth 0
                new_hash_tmp = f"resume_{int(time.time())}"
                new_path_tmp = str(self.xml_dir / f"{new_hash_tmp}.xml")
                self._capture_state(new_hash_tmp)

                # Reset stuck tracking
                self._stuck_entry_hash  = None
                self._post_stuck_hashes.clear()

                self._dfs(0)
            else:
                # Timed out with no intervention — try to surface automatically
                skip(f"[Stuck] No intervention after {_stuck_timeout:.0f}s "
                     f"-- attempting emergency surface")
                self._stuck_entry_hash  = None
                self._post_stuck_hashes.clear()
                # [v2.14] Use _emergency_surface() instead of bare back+relaunch.
                # Tombs the stuck state so pass 2/3 never re-enter it.
                if not self._emergency_surface():
                    self._suspend(reason="stuck_form",
                                  context={"state": state_hash,
                                           "reason": "stuck timeout, surface failed"})
            return

        # ── Limit actions per state ───────────────────────────
        to_try = untried[:Config.MAX_ACTIONS_PER_STATE]

        # ── [v2.5-A / v2.9-1] Batch text-field pre-pass ─────
        # Fill ALL EditText fields in a single pass WITHOUT recursing.
        # This prevents each field from consuming a depth slot.
        #
        # [v2.9-1] Focus management fix: the v2.8 pre-pass skipped the field
        # tap whenever the soft keyboard was showing.  That was wrong -- IME
        # visible means a DIFFERENT field has focus.  Typing without
        # re-focusing sent input to the previously-focused field, corrupting
        # it AND leaving the intended field empty.
        #
        # Correct rule: skip the tap ONLY if the TARGET field already has
        # focused="true".  Otherwise always tap, then verify focus transferred
        # before typing.  _tap_and_focus() implements this precisely.
        #
        # [v2.9-4b] sibling_label: pass the nearest preceding TextView label
        # so generate_input() can map generic resource_ids (e.g. "edit_text_1"
        # with a "Mobile Number*" label above it).
        #
        # [v2.7] Fill blacklist: each field keyed by (package_name, resource_id).
        # State hash intentionally NOT used -- too volatile.
        text_fields = [e for e in to_try if e.is_text_field]
        if text_fields:
            action(f"[FormFill] Batch-filling {len(text_fields)} text field(s) "
                   f"without recursing")
            for tf in text_fields:
                if self._timed_out() or self._phase_timed_out():
                    return

                # [v2.7] Skip if already filled this session
                field_key = (self.package_name, tf.resource_id)
                if field_key in self._filled_fields:
                    skip(f"  [FormFill] Skipping already-filled field: "
                         f"{tf.label()} (resource_id={tf.resource_id})")
                    self.state_mgr.mark_action(state_hash, tf.key())
                    continue

                # [v2.9-4b] Resolve sibling label for generic resource_ids
                sibling_lbl = _get_sibling_label(xml_str, tf)

                val = generate_input(tf, sibling_label=sibling_lbl)

                # [v2.9-1] Focus-aware tap: always tap to acquire focus on
                # the target field; skip tap ONLY if target already focused.
                # Never skip the tap just because the keyboard is visible --
                # that only means a different field currently has focus.
                focused = _tap_and_focus(tf, self.xml_dir)
                if not focused:
                    warn(f"  [FormFill] Could not focus '{tf.label()}' -- skipping")
                    continue

                self.executor.input_text(val)
                time.sleep(0.2)

                action(f"  [FormFill] '{val}' -> {tf.label()} "
                       f"({tf.elem_class.split('.')[-1]})"
                       + (f" [label: '{sibling_lbl}']" if sibling_lbl else ""))
                self._filled_fields.add(field_key)
                self.state_mgr.mark_action(state_hash, tf.key())
                self.session.total_actions += 1
                self.session.forms_filled += 1

            # Dismiss keyboard once after last field, then settle
            self.executor.dismiss_keyboard()
            _settle()  # [v2.7] dynamic settle after form fill

            # Re-dump to capture validation-state changes (e.g. button enables)
            xml_str  = dump_ui_xml(xml_path_tmp) or xml_str
            elements = _prioritise_elements(parse_elements(xml_str))
            untried  = self.state_mgr.get_untried(state_hash, elements)
            to_try   = untried[:Config.MAX_ACTIONS_PER_STATE]

        # Non-text-field elements only from here -- each recurses normally
        non_text_to_try = [e for e in to_try if not e.is_text_field]

        for elem in non_text_to_try:
            if self._timed_out() or self._phase_timed_out():
                return
            if self.state_mgr.total_states() >= Config.MAX_STATES:
                return

            # [v2.14] Branch ledger: mark depth-0 element as pending before
            # recursing.  Marked exhausted after recursion returns.
            # Key uses resource_id when available (stable), text as fallback.
            _elem_key_ledger = elem.resource_id or elem.text or elem.key()
            if depth == 0 and _elem_key_ledger not in self._branch_ledger:
                self._branch_ledger[_elem_key_ledger] = "pending"

            did_act = self._interact_with_element(elem, state_hash, xml_str)
            if not did_act:
                self.state_mgr.mark_action(state_hash, elem.key())
                continue

            # ── Record the action ────────────────────────────
            _settle()  # [v2.7] dynamic: short if landing page is static

            # Quick check: did app crash?
            if not self._is_app_alive():
                alert(f"APP CRASH after tapping {elem.label()}")
                self.session.crashes_recovered += 1
                if self._verified_relaunch("post-crash"):
                    time.sleep(1.5)
                    continue
                else:
                    return

            # ── Recurse into new state ────────────────────────
            self._dfs(depth + 1)

            # [v2.14] Branch ledger: mark exhausted after recursion returns
            if depth == 0:
                self._branch_ledger[_elem_key_ledger] = "exhausted"

            # ── After returning from recursion, re-dump ───────
            if self._timed_out():
                return
            xml_str  = dump_ui_xml(xml_path_tmp) or xml_str
            elements = _prioritise_elements(parse_elements(xml_str))
            untried  = self.state_mgr.get_untried(state_hash, elements)
            if not untried:
                break

        # All elements in this state exhausted -- backtrack
        self._safe_back("state-exhausted")   # [v2.5-C]
        _settle()
        # Prevent drifting to launcher after backtracking from root state
        if not self._is_app_in_foreground() and self.main_activity:
            warn("Back exited the app -- relaunching to continue traversal")
            self._verified_relaunch("post-backtrack-root")
            time.sleep(1.5)


# ─────────────────────────────────────────────────────────────
# SESSION OUTPUT
# ─────────────────────────────────────────────────────────────

def save_explorer_session(session: ExplorerSession,
                          output_path: str = "explorer_report.json") -> str:
    data = asdict(session)
    data["summary"] = {
        "states_visited":             session.states_visited,
        "total_actions":              session.total_actions,
        "unique_activities":          session.unique_activities,
        "unique_activity_count":      len(session.unique_activities),
        "permission_dialogs_accepted": session.permission_dialogs_accepted,
        "forms_filled":               session.forms_filled,
        "crashes_recovered":          session.crashes_recovered,
        "screenshot_tier":            session.screenshot_tier,
        "has_screenshots":            session.screenshot_tier <= 2,
        # [v2.8-A] Form-submit outcomes
        "form_submits_attempted":     session.form_submits_attempted,
        "form_submits_succeeded":     session.form_submits_succeeded,
        "form_submit_failure_count":  len(session.form_submit_failures),
        "form_submit_failures":       session.form_submit_failures,
        # [v2.8-C] Human-intervention count
        "human_interventions": sum(
            1 for a in session.actions if a.action_type == "human_navigation"
               and getattr(a, "source", "explorer") == "human"
        ),
        "state_hashes": [
            s.state_hash for s in session.states
        ],
        "deepest_state": max(
            (s.depth for s in session.states), default=0
        ),
        "permission_dialog_states": [
            s.state_hash for s in session.states if s.is_permission_dialog
        ],
    }
    Path(output_path).write_text(json.dumps(data, indent=2))
    return output_path


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    # ── Argument parsing ─────────────────────────────────────
    args         = sys.argv[1:]
    sentry_path  = None
    static_path  = None
    apk_pkg      = None    # [v2.3-1] --apk <package_name>
    wait_mode    = False   # [v2.3-2] --wait
    wait_timeout = 120     # [v2.3-2] --wait-timeout <seconds>

    i = 0
    while i < len(args):
        if args[i] == "--sentry" and i + 1 < len(args):
            sentry_path = args[i + 1]; i += 2
        elif args[i] == "--static" and i + 1 < len(args):
            static_path = args[i + 1]; i += 2
        elif args[i] == "--apk" and i + 1 < len(args):
            apk_pkg = args[i + 1]; i += 2
        elif args[i] == "--wait":
            wait_mode = True; i += 1
        elif args[i] == "--wait-timeout" and i + 1 < len(args):
            wait_timeout = int(args[i + 1]); i += 2
        elif args[i] == "--depth" and i + 1 < len(args):
            Config.MAX_DEPTH = int(args[i + 1]); i += 2
        elif args[i] == "--timeout" and i + 1 < len(args):
            Config.TIMEOUT = int(args[i + 1]); i += 2
        elif args[i] == "--states" and i + 1 < len(args):
            Config.MAX_STATES = int(args[i + 1]); i += 2
        else:
            i += 1

    print(f"\n{Fore.GREEN}{'═' * 62}")
    print("  APK THREAT ORCHESTRATOR // PHASE 3: EXPLORER v2.14")
    print(f"{'═' * 62}{Style.RESET_ALL}")

    # ── Resolve mode ──────────────────────────────────────────
    # --apk mode: skip all report loading, just need package name
    # Normal mode: load sentry + static reports as before
    if apk_pkg:
        banner("STARTUP // Direct-APK Mode (no reports)", "═")
        package_name    = apk_pkg
        main_activity   = ""
        screenshot_tier = 3   # conservative default; upgraded below
        frida_ready     = False
        has_launcher    = True

        # Probe device for frida/tier info
        frida_check = adb("shell", "su", "-c",
                          f"ls {os.getenv('FRIDA_SERVER_PATH', '/data/local/tmp/frida-server')} 2>/dev/null")
        frida_ready = (frida_check.returncode == 0
                       and frida_check.stdout.strip() != "")
        magisk_mods = adb("shell", "su", "-c",
                          "ls /data/adb/modules/ 2>/dev/null").stdout.lower()
        flag_disabled = any(m in magisk_mods for m in (
            "noflagsecure", "no_flag_secure", "flagsecure", "no-flagsecure"))
        screenshot_tier = 1 if flag_disabled else (2 if frida_ready else 3)

        # Try to infer main_activity from pm dump
        pm = adb("shell", "pm", "dump", package_name)
        for line in pm.stdout.splitlines():
            line = line.strip()
            if "android.intent.action.MAIN" in line and "/" in line:
                for token in line.split():
                    if "/" in token and package_name in token:
                        main_activity = token.split("/", 1)[-1]
                        break
            if main_activity:
                break

        ok(f"Package name    : {package_name}")
        ok(f"Main activity   : {main_activity or '(unknown)'}")
        ok(f"Screenshot tier : {screenshot_tier}")
        ok(f"Frida ready     : {frida_ready}")

    else:
        # ── Resolve report paths from latest session if not given ─
        if sentry_path is None:
            sessions_root = Path("sessions")
            if sessions_root.exists():
                candidates = sorted(
                    [d for d in sessions_root.iterdir()
                     if d.is_dir() and (d / "sentry_report.json").exists()],
                    key=lambda d: d.stat().st_mtime, reverse=True,
                )
                if candidates:
                    sentry_path = str(candidates[0] / "sentry_report.json")
                    if static_path is None:
                        static_path = str(candidates[0] / "static_report.json")
        if sentry_path is None:
            sentry_path = "sentry_report.json"
        if static_path is None:
            static_path = "static_report.json"

        banner("STARTUP // Loading Reports", "═")
        sentry  = load_sentry_report(sentry_path)
        static  = load_static_report(static_path)

        package_name    = sentry.get("package_name", "") or static.get("package_name", "")
        main_activity   = static.get("main_activity", "")
        screenshot_tier = static.get("summary", {}).get("screenshot_tier", 3)
        frida_ready     = static.get("summary", {}).get("frida_ready", False)
        has_launcher    = static.get("has_launcher",
                                     static.get("summary", {}).get("has_launcher", True))

        if not package_name:
            err("package_name missing from all reports.")
            err("Use: python explorer.py --apk <package_name>")
            sys.exit(1)

        if not has_launcher:
            warn("Phase 1 reported no LAUNCHER activity.")
            warn("Explorer will still attempt traversal if the app is running.")

        if screenshot_tier == 2 and not frida_ready:
            warn("Screenshot tier is 2 but frida_ready is False -- degrading to tier 3")
            screenshot_tier = 3

        ok(f"Package name           : {package_name}")
        ok(f"Main activity          : {main_activity or 'unknown'}")
        ok(f"Screenshot tier        : {screenshot_tier}")

    # ── Device check ─────────────────────────────────────────
    banner("STARTUP // Device Check", "─")
    r = adb("devices")
    if "device" not in r.stdout:
        err("No ADB device found. Connect device and enable USB debugging.")
        sys.exit(1)
    ok("ADB device connected")

    # ── App process check / launch / wait ─────────────────────
    if wait_mode:
        # [v2.3-2] --wait: analyst opens the app manually.
        # We poll for the process instead of trying am start.
        pids = _wait_for_process(package_name, timeout=wait_timeout)
        if not pids:
            warn("No process found after wait. Proceeding anyway -- "
                 "explorer will attempt DFS from whatever is on screen.")
        else:
            ok(f"App running -- PID(s): {pids}")

    else:
        # Original behaviour: check if running, try to launch if not
        r = adb("shell", "pidof", package_name)
        if not r.stdout.strip():
            ps = adb("shell", "ps", "-A")
            if package_name not in ps.stdout:
                warn(f"{package_name} is not running.")
                if main_activity:
                    info(f"Attempting to launch: {main_activity}")
                    adb("shell", "am", "start", "-n",
                        f"{package_name}/{main_activity}")
                    time.sleep(2.0)
                else:
                    warn("No main activity available -- proceeding anyway")
            else:
                ok(f"{package_name} is running (found via ps -A)")
        else:
            ok(f"{package_name} is running  PID: {r.stdout.strip()}")

    # ── Session directory ─────────────────────────────────────
    # In --apk mode there is no sentry_path, so always create a new dir
    if not apk_pkg and sentry_path and sentry_path != "sentry_report.json":
        sentry_p      = Path(sentry_path).resolve()
        sentry_parent = sentry_p.parent
        if (sentry_parent.name.startswith(package_name)
                and sentry_parent.parent.name == "sessions"):
            session_dir = sentry_parent
            ok(f"Reusing Phase 1/2 session dir : {session_dir}")
        else:
            session_dir = Path(
                f"sessions/{package_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_explorer"
            )
            ok(f"Creating new session dir      : {session_dir}")
    else:
        session_dir = Path(
            f"sessions/{package_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        ok(f"Creating session dir : {session_dir}")
    session_dir.mkdir(parents=True, exist_ok=True)
    ok(f"Session directory      : {session_dir}")

    # ── Initialise session and engine ─────────────────────────
    session = ExplorerSession(
        package_name=package_name,
        session_start=ts(),
        screenshot_tier=screenshot_tier,
    )

    # [v2.7] Pull dangerous permissions from static report for stuck-state alert
    _dangerous_perms: list[str] = []
    if not apk_pkg:
        _dangerous_perms = static.get("summary", {}).get("dangerous_permissions", [])

    engine = ExplorerEngine(
        package_name=package_name,
        main_activity=main_activity,
        screenshot_tier=screenshot_tier,
        session_dir=session_dir,
        session=session,
        p1_dangerous_permissions=_dangerous_perms,
    )

    # ── Tier 2: attach Frida FLAG_SECURE bypass ───────────────
    if screenshot_tier == 2:
        banner("STARTUP // Frida FLAG_SECURE Bypass", "─")
        engine.setup_frida()

    # ── Run traversal ─────────────────────────────────────────
    try:
        engine.explore()
    except KeyboardInterrupt:
        info("\nCtrl+C received -- stopping traversal")
    except Exception as e:
        err(f"Explorer error: {e}")
        session.errors.append(str(e))
        import traceback
        session.errors.append(traceback.format_exc())
    finally:
        if engine.frida_session:
            try:
                engine.frida_session.detach()
            except Exception:
                pass

    session.session_end = ts()

    # ── Save report ───────────────────────────────────────────
    report_path = str(session_dir / "explorer_report.json")
    out_path = save_explorer_session(session, report_path)

    # ── Summary ───────────────────────────────────────────────
    banner("PHASE 3 COMPLETE // Summary", "═")
    ok(f"Package          : {package_name}")
    ok(f"States visited   : {session.states_visited}")
    ok(f"Total actions    : {session.total_actions}")
    ok(f"Unique activities: {len(session.unique_activities)}")
    ok(f"Permission dialogs accepted: {session.permission_dialogs_accepted}")
    ok(f"Forms filled     : {session.forms_filled}")
    ok(f"Form submits     : {session.form_submits_succeeded}/{session.form_submits_attempted} succeeded")
    if session.form_submit_failures:
        warn(f"Form submit failures: {len(session.form_submit_failures)} -- see report")
    ok(f"Crashes recovered: {session.crashes_recovered}")
    ok(f"Screenshot tier  : {session.screenshot_tier}")
    ok(f"Session dir      : {session_dir}")
    ok(f"Report saved     : {out_path}")

    if session.unique_activities:
        print()
        info("Activities reached:")
        for act in session.unique_activities:
            print(f"       {Fore.CYAN}{act}")

    if session.errors:
        print()
        warn(f"{len(session.errors)} error(s) during traversal -- see report")

    print()
    info("-> Pass explorer_report.json to Phase 4 to begin analysis.")
    print()


if __name__ == "__main__":
    main()