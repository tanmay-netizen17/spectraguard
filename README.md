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
| 2 | **Malicious URL** | URL Scorer (LightGBM) | 50+ lexical features + SHAP importance |
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
- **Domain age checking** — newly registered domains (< 7 days) are flagged automatically
- **Digit-for-letter substitution detection** — catches g00gle.com-style URL spoofing
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
| Digit substitution in URL | +0.05 | Clear spoofing attempt |
| First login from new geo | +0.07 | Possible account takeover |
| After-hours access | +0.04 | Attackers exploit off-hours monitoring gaps |

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
                                         │    ├── URL Detector (LightGBM 50+ features)
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
│   │   ├── url_detector.py      # LightGBM + 50+ lexical features
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

## Built for IndiaNext Hackathon 2026

**Theme:** AI vs AI — defending against AI-powered cyber attacks  
**Team:** SentinelAI  
**Submission deadline:** March 17, 2026 12:00 PM
