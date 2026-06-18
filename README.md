# ScamShield AI: Browser Scam Detection Extension

ScamShield AI is an internship-grade cybersecurity browser extension for Chrome and Edge designed to analyze visited websites in real time and detect potential scams, phishing pages, crypto giveaways, and brand impersonation attempts.

It combines standard heuristic analysis, third-party security databases (VirusTotal, Google Safe Browsing), WHOIS registration metadata, and an NLP-based text classifier to evaluate website risk scores from 0 to 100.

---

## Key Features

1. **Real-time URL Analysis**:
   - Detects typosquatting and brand impersonation (e.g., `amaz0n.com`, `paypal-security-verification.xyz`) using Levenshtein distance calculations.
   - Flags suspicious Top-Level Domains (TLDs) like `.xyz`, `.top`, `.cf`, `.ml`, and `.win`.
2. **Website Content NLP Classification**:
   - Parses webpage body text and runs it through an NLP classifier (TF-IDF + Logistic Regression) trained on common scam and phishing phrases.
   - Detects urgent, coercive scam language like *"Congratulations, you won!"*, *"Claim your reward now"*, and *"Verify your credentials"*.
3. **Visual Threat Indicators**:
   - Scans the DOM for intrusive overlay popups, fake countdown timers, and credentials/login forms hosted on untrusted domains.
4. **Third-Party Integrations**:
   - Runs asynchronous lookups for domain age (WHOIS registration), Google Safe Browsing API status, and VirusTotal vendor reputation checks.
5. **Cybersecurity-Themed Dashboard**:
   - Dynamic dark cyber-theme popup presenting current tab security status.
   - Comprehensive Threat Control Options Dashboard featuring historical scan audit logs, community scam reports, and whitelist/blacklist rule editors.

---

## Directory Structure

```text
browser-scam-detection/
├── backend/
│   ├── app/
│   │   ├── ml/
│   │   │   ├── train.py          # Trains the Logistic Regression TF-IDF model
│   │   │   ├── model.joblib      # Serialized ML classifier
│   │   │   └── vectorizer.joblib # Serialized TF-IDF vectorizer
│   │   ├── services/
│   │   │   ├── scam_detector.py  # Primary heuristic and ML scan coordinator
│   │   │   ├── safe_browsing.py  # Google Safe Browsing API v4 client
│   │   │   ├── virustotal_service.py # VirusTotal v3 URL analysis client
│   │   │   └── whois_service.py  # Domain age and registrar lookup
│   │   ├── config.py             # Application settings (SQLite, API Keys)
│   │   ├── database.py           # SQLAlchemy database engine connection
│   │   ├── models.py             # SQLAlchemy schemas (ScanHistory, Whitelist, Reports)
│   │   ├── schemas.py            # Pydantic validation request/response schemas
│   │   └── main.py               # FastAPI entrypoint and REST router
│   ├── requirements.txt          # Python package requirements
│   └── Dockerfile                # Multi-stage Docker deployment for the API
├── frontend/
│   ├── public/
│   │   ├── manifest.json         # Chrome Extension Manifest V3 configuration
│   │   └── icons/                # Extension action bar branding icons
│   ├── src/
│   │   ├── popup/                # React components for the toolbar popup
│   │   ├── dashboard/            # React components for the options dashboard page
│   │   ├── background.ts         # Background script coordinating navigation scans
│   │   ├── content.ts            # Content script evaluating page DOM indicators
│   │   ├── types.ts              # Shared TypeScript definitions
│   │   └── vite-env.d.ts
│   ├── popup.html                # Popup html frame
│   ├── options.html              # Options/Dashboard html frame
│   ├── tsconfig.json             # TypeScript rules
│   ├── vite.config.ts            # Rollup multi-input builder for Chrome extensions
│   └── package.json              # NPM package configurations
├── docker-compose.yml            # Local orchestration setup for backend
└── README.md                     # GitHub manual documentation
```

---

## Installation & Setup

### 1. Backend Service (FastAPI)

First, set up your Python environment and launch the FastAPI server.

#### Local Windows Setup:
```powershell
# Navigate to backend directory
cd backend

# Create virtual environment (if not present)
python -m venv venv

# Activate virtual environment
.\venv\Scripts\activate

# Install dependencies (automatically handles Windows binary wheels)
pip install -r requirements.txt

# Train the ML scam text classifier model
python -m app.ml.train

# Start the development API server (reloads on file changes)
python -m uvicorn app.main:app --reload
```
The backend API documentation will be available locally at [http://localhost:8000/docs](http://localhost:8000/docs).

*Note: Create a `.env` file in the `backend/` folder to configure VirusTotal (`VIRUSTOTAL_API_KEY`), Google Safe Browsing (`GOOGLE_SAFE_BROWSING_API_KEY`), or database URLs if running custom instances.*

---

### 2. Frontend Browser Extension (React + Vite + TypeScript)

Compile the React entrypoints and inject them unpacked into Chrome or Edge.

#### Build Instructions:
```powershell
# Navigate to frontend folder
cd frontend

# Install Node modules
npm install

# Compile the TypeScript files and build the extension directory
npm run build
```
Vite will compile the assets into the `frontend/dist/` directory.

#### Load the Extension in Chrome/Edge:
1. Open Google Chrome and navigate to `chrome://extensions/` (or Edge and navigate to `edge://extensions/`).
2. Toggle **Developer Mode** (top right corner of the page) to active.
3. Click the **Load unpacked** button (top left corner).
4. Select the `dist/` directory generated inside the `frontend/` folder.
5. Pin **ScamShield AI** to your toolbar!

---

### 3. Docker Deployment (Backend API)

Orchestrate the backend service inside a container mapping sqlite.

```bash
# Spin up the FastAPI API container on port 8000
docker-compose up --build -d
```

---

## Diagnostic Verdict Matrix

When a page completes loading, ScamShield scores risk from `0` to `100` based on the following diagnostic triggers:

| Threat Signal | Risk Increment | Reason Logged |
| :--- | :--- | :--- |
| **Whitelisted Domain** | Override to `0` | *"Domain is explicitly whitelisted."* |
| **Blacklisted Domain** | Override to `100` | *"Domain is blacklisted (source: community)."* |
| **Typosquatting** | `+50` | *"Domain resembles legitimate brand '{brand}' but differs by {n} character(s)."* |
| **Subdomain spoofing** | `+40` | *"Brand name '{brand}' detected in subdomain, but hosted on domain '{domain}'."* |
| **Suspicious Path Keywords** | `+10` per match (max `+30`) | *"Suspicious keyword(s) found in URL: login, giveaway, account"* |
| **Scam TLD (e.g. .xyz, .cf)** | `+15` | *"Domain uses a suspicious TLD frequently associated with spam or scams."* |
| **AI Content Match** | `+ (Confidence * 35)` | *"AI text classifier flagged scam content."* |
| **Intrusive Popups** | `+10` | *"Excessive or intrusive popups detected on page load."* |
| **Countdown Urgency** | `+15` | *"Count-down timer or artificial urgency elements detected."* |
| **Untrusted Login Forms** | `+20` | *"Login/credentials form found on an untrusted or unfamiliar domain."* |
| **WHOIS Young Registration** | `+35` (<30 days), `+15` (<180 days) | *"Domain is very young (created {n} days ago)."* |
| **VirusTotal Malicious Flags** | `+40` | *"VirusTotal security vendors flagged this URL as malicious."* |
| **Google Safe Browsing Match** | `+50` | *"Google Safe Browsing flagged this site as dangerous."* |

---

## License

This project is open-source and available under the MIT License.
