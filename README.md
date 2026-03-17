# SpectraGuard

> AI-powered multi-threat cyber defense platform. Detects, explains, and blocks phishing URLs, malicious emails, deepfakes, prompt injections, and behaviour anomalies — in real time.

---

## What It Does

SpectraGuard runs as a local background service that passively monitors your environment:

- **Browser Extension** intercepts every URL before the page loads
- **Email Daemon** watches your inbox via IMAP and flags phishing attempts
- **Log Collector** reads system auth logs and detects intrusion patterns
- **Manual Scanner** lets you analyse any URL, text, file, or log on demand

Every detection comes with a plain-English explanation, a MITRE ATT&CK classification, and a specific recommended action. No black boxes.

---

## Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+
- Git

### 1. Clone
```bash
git clone https://github.com/yourusername/spectraguard
cd spectraguard
```

### 2. Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### 3. Train Models (first time only, ~3 minutes)
```bash
cd backend
python notebooks/train_url_model.py
python notebooks/train_email_model.py
python notebooks/train_log_model.py
```

### 4. Frontend
```bash
cd frontend
npm install
npm run dev
```
Dashboard: **http://localhost:5173**

### 5. Local Background Service (optional)
```bash
cd backend
python local_service.py
```
Runs silently in your system tray. Shows OS notifications when threats are detected.

### 6. Browser Extension
1. Open Chrome → `chrome://extensions/`
2. Enable **Developer Mode** (top right)
3. Click **Load unpacked** → select the `browser-extension/` folder
4. SpectraGuard Shield icon appears in toolbar

### One-click Start (Windows)
```
Double-click: start_spectraguard.bat
```

---

## Threat Coverage

| # | Threat Type | Detection Method | Model |
|---|------------|-----------------|-------|
| 1 | Phishing URL | Lexical features + domain analysis | LightGBM (25 features) |
| 2 | Phishing Email / Text | TF-IDF + keyword patterns | Logistic Regression |
| 3 | Malicious URL (subdomain trick) | Registrable domain extraction | LightGBM |
| 4 | Deepfake Image / Video | DCT + noise + ELA analysis | EfficientNet-B0 + Statistical |
| 5 | Behaviour Anomaly | Log pattern deviation | Isolation Forest |
| 6 | AI-Generated Content | Perplexity + stylometrics | RoBERTa classifier |
| 7 | Prompt Injection | Adversarial pattern matching | RoBERTa fine-tuned |

---

## Spectra Score Algorithm

Every threat gets a **0–100 Spectra Score** using a custom formula:

```
Score = Σ(wᵢ × pᵢ) × CoordinationMultiplier × ContextModifier
```

- **wᵢ** = per-detector weight (NLP: 30%, URL: 25%, Deepfake: 20%, Anomaly: 15%, AI: 10%)
- **CoordinationMultiplier**: 1.25× when 2 detectors fire, 1.5× when 3+ fire
- **ContextModifier**: +0.08 for domain age <7 days, +0.06 for SPF/DKIM fail, etc.

| Score | Severity | Action |
|-------|----------|--------|
| 0–30 | Clean | No action |
| 31–60 | Suspicious | Monitor |
| 61–80 | Likely Malicious | Quarantine / Block |
| 81–100 | Critical | Immediate action |

---

## Architecture

```
INGESTION LAYER
  Browser Extension (passive URL intercept)
  Email Daemon (IMAP IDLE monitoring)
  Log Collector (auth.log / syslog)
  Manual Scanner (UI input)
        │
        ▼
API GATEWAY (FastAPI, port 8000)
        │
        ▼
ORCHESTRATOR (routes input to detectors)
        │
   ┌────┼────┬────────┐
   ▼    ▼    ▼        ▼
  NLP  URL  Deep   Anomaly
  Det  Det  fake   Engine
        │
        ▼
FUSION ENGINE (Spectra Score)
        │
        ▼
XAI SYNTHESISER (SHAP + GPT-4o-mini)
        │
        ▼
DASHBOARD (React, port 5173)
```

---

## Project Structure

```
spectraguard/
├── backend/
│   ├── main.py                  # FastAPI app, all endpoints
│   ├── orchestrator.py          # Routes input to detectors
│   ├── fusion_engine.py         # Custom Spectra Score algorithm
│   ├── xai_synthesiser.py       # Explainability + GPT-4o-mini brief
│   ├── local_service.py         # Background tray agent + OS notifications
│   ├── local_server.py          # Air-gapped ONNX inference server (port 8001)
│   ├── detectors/
│   │   ├── nlp_detector.py
│   │   ├── url_detector.py
│   │   ├── deepfake_detector.py
│   │   └── anomaly_detector.py
│   ├── agents/
│   │   ├── email_daemon.py
│   │   ├── log_collector.py
│   │   └── browser_relay.py
│   ├── red_team/
│   │   ├── attacker.py
│   │   ├── robustness_evaluator.py
│   │   └── model_health.py
│   ├── models/
│   ├── notebooks/
│   └── utils/
├── browser-extension/
│   ├── manifest.json            # Chrome MV3
│   ├── background.js            # URL intercept + notifications
│   ├── content.js               # Warning overlay injection
│   └── popup/
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── api/spectraApi.js    # All API calls in one place
│   │   ├── components/
│   │   └── pages/
│   └── .env
├── start_spectraguard.bat       # Windows one-click start
├── start_spectraguard.sh        # Mac/Linux one-click start
└── README.md
```

---

## Environment Variables

Create `backend/.env`:
```env
OPENAI_API_KEY=sk-...          # GPT-4o-mini for XAI explanations
VIRUSTOTAL_API_KEY=...         # Optional: URL enrichment
EMAIL_APP_PASSWORD=...         # Gmail app password for email daemon
```

Create `frontend/.env`:
```env
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000
```

---

## Air-gapped / Local Mode

Toggle **Local Mode** in Settings to run all inference on your machine with zero external calls:

1. Start the local inference server: `python backend/local_server.py`
2. Toggle Air-gapped Mode in Settings
3. The 🔒 badge appears — all analysis now runs on ONNX models locally

---

## Red Team / Adversarial Testing

Red Team is an **automated adversarial stress test** for your own models.

1. **Baseline Ingestion**: You paste a known-malicious URL or text that you expect the model to correctly flag.
2. **Adversarial Mutation**: SpectraGuard generates 4 mutated versions of your input using different attack strategies:
   - **Homoglyph substitution** — replacing letters with Unicode lookalikes (e.g., `pаypal.com`).
   - **Synonym swap** — replacing phishing keywords with neutral synonyms.
   - **Zero-width space injection** — inserting invisible `\u200b` characters to break tokenisation.
   - **Combined** — applying all three attacks simultaneously.
3. **Execution**: It sends each mutation to the real `/red-team/run` endpoint which runs the full detector stack.
4. **Reporting**: It reports a **Resilience Score** — what % of attacks did the model still correctly detect after mutation?

| Resilience Score | Verdict | Recommendation |
|------------------|---------|----------------|
| **≥ 85** | Robust | Model is safe for production. |
| **50–84** | Needs work | Model is vulnerable to simple mutations. |
| **< 50** | Vulnerable | Model needs urgent retraining with adversarial examples. |

---

## Built At

**IndiaNext Hackathon 2026** · K.E.S. Shroff College, Mumbai · March 16–17, 2026

---

## License

MIT
