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

## Quick Start: Install & Run in 2 Minutes 🚀

Since the extension is already configured to use the live cloud backend on Render (`https://browser-scam-detection.onrender.com`), you do **not** need to install or run Python/databases locally to use it!

Follow these 3 simple steps to load the extension:

### Step 1: Clone the Repository
Clone this repository to your local computer:
```bash
git clone https://github.com/manikandanmp27/browser-scam-detection.git
cd browser-scam-detection
```

### Step 2: Build the Extension
Build the frontend assets using Node.js:
```bash
cd frontend
npm install
npm run build
```
*This compiles the React/TypeScript files and creates a `dist/` directory inside the `frontend` folder.*

### Step 3: Load the Extension in Your Browser
1. Open Google Chrome (or Edge) and go to **`chrome://extensions/`** (or `edge://extensions/`).
2. Toggle on **Developer Mode** in the top-right corner.
3. Click the **Load unpacked** button in the top-left corner.
4. Select the **`frontend/dist/`** directory.
5. Pin **ScamShield AI** to your toolbar and start scanning! Open `scam_test.html` to see the warning in action.

---

## Developer Guide: Local Backend Setup 🛠️

If you want to run the backend server locally on your machine (instead of the live Render cloud), follow these steps:

### 1. Run the FastAPI Server Locally
```powershell
# Navigate to backend directory
cd backend

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\activate

# Install requirements
pip install -r requirements.txt

# Pre-train the ML scam text classifier model
python -m app.ml.train

# Start the local API server (runs on port 8000)
python -m uvicorn app.main:app --reload
```
*The local API docs will be available at http://localhost:8000/docs.*

### 2. Connect the Extension to Local Backend
1. Open `frontend/src/background.ts` and `frontend/src/dashboard/Dashboard.tsx`.
2. Change the `BACKEND_URL` from the Render URL back to `'http://localhost:8000'`.
3. Re-run `npm run build` in the `frontend` directory.
4. Go to `chrome://extensions/` and click the **Reload (↻)** button on the ScamShield AI extension card.

---

### 3. Running with Docker
You can also orchestrate the local backend using Docker Compose:
```bash
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
