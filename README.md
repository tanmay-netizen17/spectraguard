# SentinelAI 🛡️
### Production-Grade Multi-Threat Cyber Defense Platform
**IndiaNext Hackathon 2026** · Built in 24 hours

---

## What SentinelAI Does

SentinelAI is a real-time cyber defense platform that **detects, scores, and explains six categories of AI-powered threats** before they cause damage. It combines six independent AI/ML detectors, fuses their outputs with a custom algorithm, and produces a plain-English explanation that any non-technical user can act on.

### Threat Coverage

| # | Threat Type | Detector | Algorithm |
|---|---|---|---|
| 1 | **Phishing Email / Message** | NLP (RoBERTa) | Fine-tuned transformer + heuristic fallback |
| 2 | **Malicious URL** | URL Detector v2.0 (LightGBM) | 60+ lexical + structural features, homoglyph/IDN/IPv6 detection, async WHOIS, SHAP importance |
| 3 | **Deepfake Audio/Video** | Deepfake (EfficientNet-B0 + LSTM) | Spatial frame analysis + temporal consistency |
| 4 | **Prompt Injection** | NLP (shared pipeline) | Token pattern matching + classifier |
| 5 | **Behaviour Anomaly** | Anomaly Engine (Isolation Forest) | Statistical deviation from auth-log baseline |
| 6 | **AI-Generated Content** | NLP stylometric head | Perplexity + type-token ratio + marker detection |

### Security Capabilities

- **Real-time threat scoring** on every URL you visit (browser extension)
- **Passive email monitoring** via IMAP IDLE — intercepts phishing before you open it
- **Auth-log surveillance** — detects brute-force, credential stuffing, lateral movement
- **Multi-vector attack detection** — recognises when attackers combine email + URL + deepfake simultaneously
- **MITRE ATT&CK mapping** — every alert tagged to a kill-chain tactic
- **Fully explainable detections** — SHAP values, token highlights, Grad-CAM regions, GPT-4o-mini brief on every single detection
- **SPF/DKIM validation** — email authentication failures raise the threat score
- **Domain age checking** — newly registered domains (< 7 days) are flagged automatically (real async WHOIS lookup)
- **Digit-for-letter substitution detection** — catches g00gle.com, payp4l.com leet-speak spoofing
- **Unicode homoglyph spoofing detection** — catches Cyrillic/Greek characters masquerading as Latin (e.g. `pаypal.com`)
- **Internationalized Domain Name (IDN) detection** — Punycode / `xn--` prefixed domains flagged
- **IPv6 address detection** — `http://[::1]/` style C2 endpoints caught
- **Dangerous URL scheme detection** — `javascript:`, `data:`, `vbscript:`, `blob:` flagged
- **Double-extension detection** — `invoice.pdf.exe`, `photo.jpg.js` malware delivery patterns
- **Base64/hex payload detection** — encoded payloads in query strings flagged
- **Risk category tagging** — every malicious URL gets a category: `credential_harvesting`, `brand_spoofing`, `malware_delivery`, `code_execution`, etc.
- **Coordinated attack multiplier** — score amplifies when multiple detectors fire together

---

## The Sentinel Score — Custom Scoring Algorithm

**This is not an off-the-shelf score.** It was designed specifically to capture coordinated multi-vector attacks.

### Formula (Simple Explanation)

```
SentinelScore = (Σ detector_weight × detector_probability)
                × CoordinationMultiplier
                × (1 + ContextModifier)
```

**Step 1 — Weighted Sum** (`Σ wᵢ × pᵢ`)

Each detector returns a probability between 0 and 1. We multiply by its weight and add them up:

| Detector | Default Weight | Why |
|---|---|---|
| NLP (Phishing/Injection) | **0.30** | Most common AI-powered attack |
| URL Scorer | **0.25** | Reliable lexical signal |
| Deepfake | **0.20** | High-impact but rarer |
| Behaviour Anomaly | **0.15** | Strong signal but slower |
| AI-Generated | **0.10** | Supporting evidence |

**Step 2 — Coordination Multiplier**

When attackers combine multiple vectors (send a phishing email AND use a malicious URL), their attack is much more dangerous. This multiplier reflects that:

| Detectors Firing | Multiplier | Meaning |
|---|---|---|
| 1 | ×1.0 | Normal — could be false positive |
| 2 | ×1.25 | Coordinated attack signal |
| 3+ | ×1.50 | Multi-vector assault — treat as near-certain |

**Step 3 — Context Modifier** (environmental signals, capped at +0.20)

| Signal | Bonus | Why |
|---|---|---|
| Domain age < 7 days | +0.08 | Freshly registered = likely disposable phishing domain |
| SPF/DKIM email auth fail | +0.06 | Sender is not who they claim |
| Digit substitution in URL | +0.05 | Clear leet-speak spoofing attempt (g00gle, payp4l) |
| First login from new geo | +0.07 | Possible account takeover |
| After-hours access | +0.04 | Attackers exploit off-hours monitoring gaps |
| Unicode homoglyph spoofing | +0.07 | Cyrillic/Greek chars used to visually clone a brand domain |
| IDN / Punycode domain | +0.05 | Internationalised domain used to disguise the real host |
| Dangerous URL scheme | +0.09 | `javascript:` / `data:` URLs used for in-browser code execution |

**Final Score** is scaled 0–100 and placed into 4 bands:

| Score | Band | Colour | Meaning |
|---|---|---|---|
| 0–30 | CLEAN | 🟢 Green | Safe to proceed |
| 31–60 | SUSPICIOUS | 🟡 Yellow | Verify before acting |
| 61–80 | LIKELY MALICIOUS | 🟠 Orange | Block and investigate |
| 81–100 | CRITICAL | 🔴 Red | Immediate incident response |

**Full implementation**: [`backend/fusion_engine.py`](./backend/fusion_engine.py) — every line commented.

---

## Quick Start — All Running Commands

### Prerequisites

- Python 3.10+
- Node.js 18+
- pip, npm

---

### 1. Backend (FastAPI)

```bash
# Navigate to backend
cd sentinelai/backend

# Install Python dependencies
pip install -r requirements.txt

# Copy environment config
cp ../.env.example ../.env
# Edit .env and add your keys

# Run the backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

The API will be live at: **http://localhost:8000**
Interactive docs: **http://localhost:8000/docs**

---

### 2. Frontend (React + Vite)

```bash
# In a new terminal
cd sentinelai/frontend

# Install dependencies
npm install

# Start dev server
npm run dev
```

The dashboard will be live at: **http://localhost:5173**

> The frontend proxies `/api` → `http://localhost:8000` automatically.

---

### 3. Email Daemon (Optional — IMAP passive monitoring)

```bash
# In a new terminal, from project root
cd sentinelai

EMAIL_USER=you@gmail.com \
EMAIL_APP_PASSWORD=your_app_password \
EMAIL_IMAP_HOST=imap.gmail.com \
SENTINEL_API_URL=http://localhost:8000 \
python backend/agents/email_daemon.py
```

> For Gmail: Generate an App Password at [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)

---

### 4. Log Collector Agent (Optional — auth.log monitoring)

```bash
# In a new terminal (Linux/macOS)
LOG_PATHS=/var/log/auth.log,/var/log/syslog \
SENTINEL_API_URL=http://localhost:8000 \
python backend/agents/log_collector.py
```

---

### 5. Browser Extension

1. Open Chrome → `chrome://extensions`
2. Enable **Developer Mode** (toggle, top right)
3. Click **Load Unpacked**
4. Select the `sentinelai/browser-extension/` folder
5. The **SentinelAI Shield** icon appears in your toolbar ✓

---

### 6. Docker (Backend + Frontend together)

```bash
# Build and start everything
cd sentinelai
docker-compose up --build

# Stop all services
docker-compose down
```

---

### 7. Quick API Test

```bash
# Health check
curl http://localhost:8000/health

# Analyse a URL
curl -X POST http://localhost:8000/analyse \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypa1.com/verify-account"}'

# Analyse phishing text
curl -X POST http://localhost:8000/analyse \
  -H "Content-Type: application/json" \
  -d '{"text": "URGENT: Your account has been suspended. Verify immediately or lose access."}'

# Analyse behaviour log
curl -X POST http://localhost:8000/analyse \
  -H "Content-Type: application/json" \
  -d '{"log_data": "Failed password for root from 192.168.1.1 port 22\nFailed password for root from 10.0.0.1 port 22"}'

# View all incidents
curl http://localhost:8000/incidents
```

---

### 8. Test Phishing URLs (Safe — for dev/demo use only)

> ⚠️ These are **synthetic/controlled test URLs** crafted to exercise specific detection rules.  
> They are **not live phishing pages** — some domains do not exist or are registered safety-net domains.
> Use them to verify that the URL Detector v2.0 fires correctly.

| Test URL | Expected Signals Triggered | Expected Risk Category |
|---|---|---|
| `http://paypa1.com/verify-account` | digit_substitution, phishing_kw | `credential_harvesting` |
| `http://192.168.1.200/secure/login.php` | is_ip_address, phishing_kw | `ip_based_c2` |
| `http://bit.ly/3xF9qZp` | url_shortener | `url_obfuscation` |
| `http://g00gle-secure.tk/signin` | digit_sub, suspicious_tld, phishing_kw | `credential_harvesting` |
| `http://[::1]/admin/payload` | is_ipv6, is_ip_address | `ip_based_c2` |
| `javascript:alert(document.cookie)` | dangerous_scheme | `code_execution` |
| `http://xn--pypal-4ve.com/update` | is_idn, phishing_kw | `brand_spoofing` |
| `http://microsoft.account-verify.xyz/login` | suspicious_tld, phishing_kw, long_url | `credential_harvesting` |
| `http://support.apple.com-id-login.top/verify` | suspicious_tld, phishing_kw, subdomains | `credential_harvesting` |
| `http://dropbox.com.download-file.cc/invoice.pdf.exe` | suspicious_tld, double_ext, phishing_kw | `malware_delivery` |
| `http://secure-bank-login.pw/account?user=admin&redirect=http://evil.com` | suspicious_tld, redirect, phishing_kw | `credential_harvesting` |
| `https://amaz0n-prime.win/offer?token=dXNlcm5hbWU6cGFzc3dvcmQ=` | digit_sub, suspicious_tld, base64_payload | `credential_harvesting` |

**Quick batch test (PowerShell) — using `/analyse/url`:**
```powershell
$urls = @(
  "http://paypa1.com/verify-account",
  "http://g00gle-secure.tk/signin",
  "http://xn--pypal-4ve.com/update",
  "http://192.168.1.200/secure/login.php",
  "http://dropbox.com.download-file.cc/invoice.pdf.exe"
)
foreach ($url in $urls) {
  $body = @{ url = $url } | ConvertTo-Json
  $resp = Invoke-RestMethod -Uri http://localhost:8000/analyse/url -Method POST -ContentType 'application/json' -Body $body
  Write-Host "[$($resp.severity)] score=$($resp.sentinel_score) cat=$($resp.url_risk_category) → $url"
}
```

**Or using the general `/analyse` endpoint with `type` + `content`:**
```powershell
$urls = @(
  "http://paypa1.com/verify-account",
  "http://g00gle-secure.tk/signin",
  "http://192.168.1.200/secure/login.php"
)
foreach ($url in $urls) {
  $body = @{ type = "url"; content = $url } | ConvertTo-Json
  $resp = Invoke-RestMethod -Uri http://localhost:8000/analyse -Method POST -ContentType 'application/json' -Body $body
  Write-Host "[$($resp.severity)] score=$($resp.sentinel_score) → $url"
}
```

> ⚠️ **Never open these test URLs in your browser.** Paste them into the SentinelAI UI or API only.
> Fake/synthetic domains will return `DNS_PROBE_FINISHED_NXDOMAIN` — that's expected, they don't exist.

**Quick batch test (bash/curl) — using `/analyse/url`:**
```bash
for url in \
  "http://paypa1.com/verify-account" \
  "http://g00gle-secure.tk/signin" \
  "http://xn--pypal-4ve.com/update" \
  "http://192.168.1.200/secure/login.php" \
  "http://dropbox.com.download-file.cc/invoice.pdf.exe"
do
  echo "Testing: $url"
  curl -s -X POST http://localhost:8000/analyse \
    -H "Content-Type: application/json" \
    -d "{\"url\": \"$url\"}" | python3 -m json.tool | grep -E '"severity"|"sentinel_score"|"url_risk_category"'
  echo "---"
done
```

---

## Deployment

### Backend → Railway

1. Push to GitHub
2. [railway.app](https://railway.app) → New Project → Deploy from GitHub → select `sentinelai/backend`
3. Set environment variables (from `.env`) in the Railway dashboard
4. Railway will auto-deploy on every git push

### Frontend → Vercel

1. [vercel.com](https://vercel.com) → New Project → Import GitHub repo
2. Root directory: `sentinelai/frontend`
3. Set `VITE_API_URL` and `VITE_WS_URL` to your Railway backend URL
4. Vercel auto-deploys on every push

---

## Architecture

```
Browser Extension ──────────────────────┐
Email Daemon (IMAP IDLE) ───────────────┤
Log Collector (auth.log watcher) ───────┤
Manual Input (UI) ───────────────────────┼──→ FastAPI Gateway
                                         │        │
                                    dedup/queue   ▼
                                         │   Orchestrator
                                         │    ├── NLP Detector (RoBERTa)
                                         │    ├── URL Detector v2.0 (LightGBM 60+ features, homoglyph/IDN/IPv6)
                                         │    ├── Deepfake Detector (EfficientNet + LSTM)
                                         │    └── Anomaly Detector (Isolation Forest)
                                         │        │
                                         │        ▼
                                         │   Fusion Engine → SENTINEL SCORE
                                         │        │
                                         │        ▼
                                         │   XAI Synthesiser
                                         │    ├── SHAP feature importance
                                         │    ├── Token highlights
                                         │    ├── Grad-CAM regions
                                         │    └── GPT-4o-mini plain-English brief
                                         │        │
                                         └────────▼
                                         React Dashboard (WebSocket live feed)
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/analyse` | Full pipeline — any input type |
| `POST` | `/ingest/url` | From browser extension |
| `POST` | `/ingest/email` | From email daemon |
| `POST` | `/ingest/log` | From log collector |
| `POST` | `/ingest/file` | Image/video upload |
| `GET` | `/incidents` | Paginated incident list |
| `GET` | `/incidents/{id}` | Full incident detail |
| `POST` | `/feedback/{id}` | Mark as false positive |
| `GET` | `/health` | System health check |
| `WS` | `/ws/live` | WebSocket live feed |

---

## Project Structure

```
sentinelai/
├── backend/
│   ├── main.py                  # FastAPI entrypoint, all endpoints
│   ├── orchestrator.py          # Input router, detector fan-out
│   ├── fusion_engine.py         # ← SENTINEL SCORE algorithm (fully commented)
│   ├── xai_synthesiser.py       # SHAP + token highlights + GPT-4o-mini
│   ├── detectors/
│   │   ├── nlp_detector.py      # Phishing, prompt injection, AI-gen
│   │   ├── url_detector.py      # LightGBM + 60+ features, homoglyph, IDN, async WHOIS (v2.0)
│   │   ├── deepfake_detector.py # EfficientNet-B0 + LSTM temporal
│   │   └── anomaly_detector.py  # Isolation Forest on auth logs
│   ├── agents/
│   │   ├── email_daemon.py      # IMAP IDLE passive email monitor
│   │   ├── log_collector.py     # auth.log / syslog watcher
│   │   └── browser_relay.py     # Extension ↔ backend bridge
│   └── utils/
│       ├── mitre_mapper.py      # ATT&CK tactic mapping
│       └── response_generator.py # Mitigation recommendations
├── browser-extension/
│   ├── manifest.json            # Chrome Manifest V3
│   ├── background.js            # URL intercept + overlay injection
│   └── popup/                   # Extension popup UI
├── frontend/
│   └── src/
│       ├── App.jsx              # Root: routing, WebSocket, global state
│       ├── pages/               # Dashboard, ScanPage, IncidentLog, Settings
│       ├── components/          # SentinelGauge, EvidenceCard, ThreatBrief, ...
│       └── api/sentinelApi.js   # Axios wrapper + WebSocket factory
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## Changelog

### v2.0 — URL Detector Overhaul _(2026-03-16)_

#### `backend/detectors/url_detector.py`
- **+10 new detection signals**: Unicode homoglyph spoofing, Punycode/IDN domains, IPv6 address hosts, dangerous schemes (`javascript:`, `data:`, `vbscript:`), double-extension files, Base64 payload in query, new redirect tokens (`next=`, `goto=`), fragment length, query entropy, hyphen density
- **Async WHOIS lookup** — non-blocking domain-age resolution using `run_in_executor` with a 5 s timeout; no longer a static `-1` placeholder
- **`risk_category` field** — new categorical output: `credential_harvesting`, `brand_spoofing`, `malware_delivery`, `code_execution`, `ip_based_c2`, `url_obfuscation`, `redirect_chain`, `suspicious_domain`
- **Model path resolution** fixed to be relative to `__file__` — works regardless of working directory
- **URL normalisation** — missing `http://` scheme added automatically before parsing
- **Expanded datasets**: shorteners 25→31, suspicious TLDs 17→33, phishing keywords 23→42
- **60+ features total** (up from 34), all typed as `float` for LightGBM compatibility
- **`_explain_top_features`** expands to 12 entries covering all new detection signals

#### `backend/fusion_engine.py`
- Added 3 new `CONTEXT_MODIFIER_MAP` entries: `homoglyph_spoofing` (+0.07), `idn_domain` (+0.05), `dangerous_scheme` (+0.09)

#### `backend/orchestrator.py`
- Reads new URL flags (`has_homoglyph`, `is_idn`, `dangerous_scheme`) and forwards to Fusion Engine context signals
- Fixed `domain_age_new` to `0 <= age < 7` (prevents `-1` unknown age from triggering false `domain_age_new` signal)
- Incident payload now includes `url_risk_category`, `mitre_description`, `mitre_mitigations`

#### `backend/xai_synthesiser.py`
- `_url_evidence()` now surfaces all new flags + `risk_category`, `url`, `normalised_url`
- `_url_explain()` generates richer natural-language descriptions for homoglyph, IDN, scheme, TLD, `@`-sign, and domain age
- `_compute_shap_values()` updated with 18-feature weight table aligned to v2.0 feature set (top 12 returned)

---

## Built for IndiaNext Hackathon 2026

**Theme:** AI vs AI — defending against AI-powered cyber attacks  
**Team:** SentinelAI  
**Submission deadline:** March 17, 2026 12:00 PM
