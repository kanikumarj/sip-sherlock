# 🔍 SIP Sherlock

> **Enterprise-grade SIP diagnostics platform** — upload raw SIP logs or PCAP files and get instant, evidence-based Root Cause Analysis (RCA) powered by AI.

---

## ✨ Features

- **Universal SIP Parser** — vendor-agnostic log ingestion (BroadWorks, Asterisk, Cisco CUCM, raw captures)
- **PCAP Support** — parse `.pcap` / `.pcapng` files directly
- **Ladder Diagram** — auto-generated interactive SIP message sequence diagrams
- **Evidence-based RCA** — deterministic, RFC 3261-compliant failure classification
- **SDP Visualisation** — codec, media path, and port extraction
- **AI RCA Layer** — optional Claude-powered deep-dive analysis
- **25+ Failure Scenarios** — covers registration failures, media errors, authentication issues, timeouts, and more

---

## 🗂 Project Structure

```
SIP SHERLOCK/
├── backend/                  # Python / FastAPI
│   ├── main.py               # API server & endpoints
│   ├── analyzer/
│   │   ├── analysis_engine.py
│   │   └── rca_engine.py
│   ├── parser/
│   │   ├── sip_parser.py
│   │   ├── sdp_parser.py
│   │   └── pcap_parser.py
│   ├── models/
│   │   └── schemas.py
│   ├── knowledge/            # SIP knowledge base
│   ├── requirements.txt
│   └── .env.example
└── frontend/                 # React / TypeScript / Vite
    ├── src/
    │   ├── App.tsx
    │   ├── components/
    │   │   ├── AnalysisInput.tsx
    │   │   ├── LadderDiagram.tsx
    │   │   ├── RCAPanel.tsx
    │   │   ├── ErrorPanel.tsx
    │   │   └── LoadingScreen.tsx
    │   └── services/
    │       └── api.ts
    ├── index.html
    └── vite.config.ts
```

---

## 🚀 Quick Start

### Prerequisites

| Tool | Version |
|------|---------|
| Python | ≥ 3.10 |
| Node.js | ≥ 18 |
| npm | ≥ 9 |

### 1. Backend

```bash
cd backend
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
cp .env.example .env          # fill in ANTHROPIC_API_KEY if using AI RCA
uvicorn main:app --reload --port 8000
```

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) — the UI connects to the backend at `http://localhost:8000`.

---

## ⚙️ Environment Variables

Create `backend/.env` from the example:

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | *(empty)* | Optional — enables Claude AI RCA |
| `MAX_FILE_SIZE_MB` | `10` | Max upload size |
| `CORS_ORIGIN` | `http://localhost:5173` | Frontend origin |

---

## 🧪 Running Tests

```bash
cd backend
python -m pytest test_rca_hardening.py -v
```

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.
