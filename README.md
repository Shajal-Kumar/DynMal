# DynMalTool — Android Malware Analysis Pipeline

> A local, physical-device pipeline for analysing Android APKs. Installs a target app on a rooted Android device, monitors its behaviour, maps its UI, and produces a professional analyst-grade threat report — entirely offline.

---

## Table of Contents

1. [What This Tool Does](#what-this-tool-does)
2. [What You Need Before You Start](#what-you-need-before-you-start)
3. [PC Setup](#pc-setup)
4. [Android Device Setup](#android-device-setup)
5. [Configuring the Tool](#configuring-the-tool)
6. [Running an Analysis](#running-an-analysis)
7. [Reading the Results](#reading-the-results)
8. [Known Limitations](#known-limitations)
9. [Troubleshooting](#troubleshooting)

---

## What This Tool Does

DynMalTool analyses Android APK files through five sequential phases, all running locally on your machine with no data sent to the cloud:

| Phase | Script | What it does |
|---|---|---|
| 1 — Static Analysis | `static_analysis.py` | Parses the APK without launching it. Extracts permissions, certificates, embedded strings, and manifest flags. |
| 2 — Runtime Monitor | `sentry.py` | Installs and launches the app. Eight parallel threads watch for network connections, file writes, permission requests, and dropper/packer activity. |
| 3 — UI Explorer | `explorer.py` | Systematically taps through every screen of the app, filling forms with synthetic data, to trigger hidden behaviour. |
| 4 — LLM Analysis | `llm_analysis.py` | Feeds all collected evidence to a local LLM (via Ollama) to produce a structured threat verdict with IOCs and kill-chain classification. |
| 5 — Report Generator | `report.py` | Synthesises everything into a professional Word (`.docx`) threat report with an IOC table, appendices, and analyst recommendations. |

The Streamlit web interface (`app.py`) lets you run all phases, view results, and download reports from a browser tab without touching the command line.

---

## What You Need Before You Start

### Hardware

- A **Linux PC** (Ubuntu 22.04 or later recommended) acting as the analysis workstation.
- A **rooted physical Android device** (Android 9–14) dedicated solely to malware analysis — use a burner device, never your personal phone.
- A **USB cable** connecting the two.

### Rooting Requirements (Android device)

Your Android device must have all of the following set up before DynMalTool will work correctly:

- **Magisk** — the root management framework.
- **Zygisk** enabled inside Magisk settings.
- **Shamiko** Magisk module — hides root from apps that detect and refuse to run on rooted devices.
- **DisableFlagSecure** Magisk module — allows screenshots to be taken inside apps that normally block them.
- **ConscryptTrustUserCerts** (or **MagiskTrustUserCerts**) Magisk module — makes the device trust the mitmproxy certificate so that encrypted HTTPS traffic can be intercepted.
- **Magisk DenyList** configured for the target apps.

> If any of these modules are missing, the tool will still run but you will lose visibility into root-detection evasion, screenshots, or SSL-encrypted traffic respectively.

---

## PC Setup

### Step 1 — Install system packages

Open a terminal and run:

```bash
sudo apt update
sudo apt install python3 python3-pip adb aapt
```

- `adb` is the Android Debug Bridge — the tool that talks to your device over USB.
- `aapt` is needed to parse certain obfuscated APKs.

### Step 2 — Install Python dependencies

```bash
pip install androguard==3.3.5 colorama frida-tools frida python-dotenv mitmproxy streamlit python-docx
```

> **Important:** `androguard` must be version `3.3.5` exactly. Do not upgrade it.

### Step 3 — Install Ollama (local LLM server)

Ollama runs the AI models that power Phases 4 and 5. It runs entirely on your PC — nothing is sent online.

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Once installed, start the Ollama server (it will run in the background):

```bash
ollama serve &
```

Then pull the required models. Pull at least one of:

```bash
# Faster, less thorough — good for development and quick checks
ollama pull phi3.5-mini

# Slower, much more thorough — recommended for final analyst reports
ollama pull llama3.3:70b
```

Optionally, if you want the report to include descriptions of app screenshots (requires ≥16 GB GPU/CPU memory):

```bash
ollama pull llama3.2-vision
```

### Step 4 — Set up mitmproxy certificate on your device

mitmproxy intercepts HTTPS traffic between the app and the internet.

1. Start mitmproxy on your PC once:
   ```bash
   mitmproxy
   ```
   Then exit it. This generates the certificate files in `~/.mitmproxy/`.

2. The certificate must be promoted to a system-trusted certificate on the Android device using the **ConscryptTrustUserCerts** or **MagiskTrustUserCerts** Magisk module. Follow the module's own installation instructions.

3. On the Android device, go to **Settings → Wi-Fi → (your network) → Proxy** and set:
   - **Proxy host:** your PC's local IP address (e.g. `192.168.1.10`)
   - **Proxy port:** `8080`

### Step 5 — Set up Frida server on the device

Frida is a dynamic instrumentation toolkit that hooks into the app's internals to intercept encrypted traffic and API calls.

1. Download the correct `frida-server` binary for your device's CPU architecture from [https://github.com/frida/frida/releases](https://github.com/frida/frida/releases). The version **must exactly match** the `frida-tools` version installed in Step 2. Check your version with:
   ```bash
   frida --version
   ```

2. Push it to the device and rename it to something inconspicuous (so the app doesn't detect it by filename):
   ```bash
   adb push frida-server-VERSION-android-ARCH /data/local/tmp/com.android.providers.media.module
   adb shell chmod 755 /data/local/tmp/com.android.providers.media.module
   ```

3. The tool starts Frida automatically during Phase 1. You do not need to start it manually.

---

## Android Device Setup

1. Enable **Developer Options** on your device (tap "Build Number" seven times in Settings → About Phone).
2. Enable **USB Debugging** in Developer Options.
3. Connect the device to your PC via USB. On the device, accept the "Allow USB Debugging" prompt.
4. Verify the connection:
   ```bash
   adb devices
   ```
   You should see your device listed as `device` (not `unauthorised`).
5. Verify root access:
   ```bash
   adb shell su -c id
   ```
   This should return `uid=0(root)`.

---

## Configuring the Tool

The tool reads all its settings from a file named `.env` in the same folder as the scripts. Create this file before your first run.

Copy the template below into a file called `.env` and adjust the values for your setup:

```
# LLM model selection
ENV=dev
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL_DEV=phi3.5-mini
OLLAMA_MODEL_PROD=llama3.3:70b
OLLAMA_TIMEOUT=180
OLLAMA_MAX_TOKENS=2048

# Frida server path on the device (must match what you uploaded in Step 5)
FRIDA_SERVER_PATH=/data/local/tmp/com.android.providers.media.module
FRIDA_PORT=17392

# mitmproxy port
MITM_PORT=8080

# ADB serial (leave blank if only one device is connected)
ADB_SERIAL=

# Phase 5 report generation
PHASE5_XML_WORKERS=4
PHASE5_LOG_BATCH=60
OLLAMA_MODEL_VISION=llama3.2-vision

# Synthetic identity data used to fill forms during UI exploration
FAKE_EMAIL=testuser@analysis.lab
FAKE_PHONE=9876543210
FAKE_NAME=Test User
FAKE_PASSWORD=Analyse99!
FAKE_USERNAME=testuser
FAKE_ATM_PIN=1234
FAKE_MPIN=123456
FAKE_OTP=123456
FAKE_CARD_NUMBER=4111111111111111
FAKE_CVV=123
FAKE_EXPIRY=12/29
FAKE_ACCOUNT=9876543210
FAKE_IFSC=SBIN0001234
FAKE_UPI=testuser@upi
FAKE_AADHAAR=222233334444
FAKE_PAN=ABCDE1234F
FAKE_INCOME=500000
```

> **ENV setting:** Change `ENV=dev` to `ENV=prod` when running final production-quality analyses. The `prod` setting uses `llama3.3:70b` for deeper LLM reasoning. Keep `dev` for faster day-to-day testing.

---

## Running an Analysis

### Using the Web Interface (recommended)

Start the dashboard in your terminal:

```bash
streamlit run app.py
```

Your browser will open automatically to `http://localhost:8501`. From here you can:

- Upload or select an APK to analyse.
- Run each phase in sequence using the **▶ Run Phase** buttons.
- View results for each phase as they complete.
- Download the final Word report.

### Using the Command Line

If you prefer to run phases individually from the terminal:

```bash
# Phase 1 — static analysis (no app launch)
python static_analysis.py apks/target.apk

# Phase 2 — launch and monitor (UI exploration is on by default)
python sentry.py --duration 300

# Phase 2 — monitor only, skip UI exploration
python sentry.py --no-explore --duration 300

# Phase 3 — UI explorer (run after Phase 2)
python explorer.py

# Phase 4 — LLM analysis
python llm_analysis.py sessions/<session-folder>

# Phase 5 — generate Word report
python report.py sessions/<session-folder>

# Phase 5 — skip vision screenshots (faster; use if llama3.2-vision is not loaded)
python report.py sessions/<session-folder> --no-vision
```

Replace `<session-folder>` with the folder name created inside `sessions/` during Phase 1 (named after the APK file).

### Running in sequence — a typical workflow

1. Place your APK in the `apks/` folder.
2. Run Phase 1 to parse the APK and start Frida.
3. Run Phase 2. The app launches on the device. Watch the terminal for activity. Phase 3 (UI exploration) runs automatically at the end of Phase 2 unless you used `--no-explore`.
4. Run Phase 4 to get the AI threat verdict.
5. Run Phase 5 to produce the final Word report.

---

## Reading the Results

All output is saved inside the `sessions/` folder, under a subfolder named after your APK. You will find:

| File | Contents |
|---|---|
| `static_report.json` | Permissions, certificates, manifest flags, code patterns found before launch |
| `sentry_report.json` | Network connections, logcat events, dropper/packer detections from runtime monitoring |
| `explorer_report.json` | UI screens visited, forms submitted, depth reached during automated exploration |
| `phase4_report.json` | LLM threat verdict: threat class, confidence, kill-chain stage, IOCs, recommended actions |
| `phase5_report_<pkg>_<timestamp>.docx` | Final analyst-grade Word report with cover page, IOC table, and appendices |
| `screenshots/` | Screenshots captured during monitoring and exploration |
| `droppers/<pkg>/` | Artifacts from any secondary APKs dropped by the target at runtime |

### Opening the Word report

Open the `.docx` file in Microsoft Word. After opening:

- Right-click the **Table of Contents** placeholder near the top.
- Select **Update Field → Update entire table**.

The TOC will populate with all section links.

---

## Known Limitations

- **No root (Shamiko missing):** Apps that detect root will self-terminate. Install Shamiko.
- **No Frida:** SSL/TLS decryption will not work. HTTPS traffic will appear encrypted.
- **Frida version mismatch:** Frida will fail to attach to the app silently. Always match `frida-server` version to `frida-tools` version.
- **Screenshot tier fallback:** If screenshots cannot be captured, the tool falls back to XML-only UI dumps. Vision analysis in Phase 5 is skipped automatically.
- **Large sessions:** Phase 5 with many XML files or a long logcat can take 10–30 minutes. Use `PHASE5_MAX_XML` in `.env` to cap the number of files processed.
- **Vision model memory:** `llama3.2-vision` requires at least 16 GB of GPU/CPU memory. Use `--no-vision` if your machine is constrained.
- **Ollama timeout:** If Phase 4 or Phase 5 times out on slow hardware when using `llama3.3:70b`, increase `OLLAMA_TIMEOUT` in `.env` (e.g. to `300` or `600`).
- **Word TOC:** The Table of Contents in the `.docx` output must be updated manually in Word (right-click → Update Field). It is not auto-populated.

---

## Troubleshooting

**`adb devices` shows nothing or `unauthorised`**
Accept the USB debugging prompt on the device. If the prompt does not appear, revoke and re-grant USB debugging in Developer Options.

**`adb shell su -c id` returns `Permission denied`**
Root is not working correctly. Open Magisk on the device and ensure root access is granted for the shell.

**Frida fails to attach**
Check that the `frida-server` version on the device exactly matches the output of `frida --version` on your PC. Re-download and re-push if there is a mismatch.

**Ollama is unavailable / Phase 4 returns `llm_status: "ollama_unavailable"`**
Ensure Ollama is running: `ollama serve`. Confirm the model is pulled: `ollama list`.

**App immediately closes during Phase 2**
The app is detecting root. Confirm Shamiko is installed, Zygisk is enabled in Magisk, and the app is on the DenyList.

**mitmproxy shows no traffic**
Confirm the Wi-Fi proxy on the device points to your PC's IP on port 8080. Confirm the mitmproxy certificate is installed as a system certificate via the Magisk module.

**Phase 5 Word report has blank sections**
Ollama may have timed out during synthesis. Increase `OLLAMA_TIMEOUT` in `.env`. Run `report.py` again — the report is always produced even if some LLM calls fail, with placeholder text for timed-out sections.
