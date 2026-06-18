# ScamShield AI: Simplified Project Review Guide

A quick, simple guide to help you explain your project during the review.

---

## 1. What is ScamShield AI?
It is a Chrome/Edge browser extension that detects scam and phishing websites in real-time. 
* **Frontend**: React, TypeScript (the extension UI and page scanner).
* **Backend**: FastAPI (Python server that calculates the risk).
* **Database**: SQLite (saves scan history and block lists).

---

## 2. How Does It Spot Scams? (The 4-Step Check)

1. **URL & Domain Check**:
   * Looks for fake domains like `amaz0n.com` or `paypa1.com` using a formula called **Levenshtein Distance** (checks if letters were swapped/replaced).
   * Flags sketchy endings like `.xyz` or `.top`.
2. **AI Text Scanning**:
   * Scans the text of the page using a **Machine Learning model** (Logistic Regression + TF-IDF) trained to spot scam phrases like *"Congratulations, you won!"* or *"Double your crypto"*.
3. **Visual Triggers (DOM Check)**:
   * Flags if a page asks for a password/seed phrase on an untrusted website.
   * Flags fake countdown timers and annoying popups.
4. **Third-Party Lookups**:
   * Checks how old the website is (new websites are highly suspicious).
   * Asks **Google Safe Browsing** and **VirusTotal** if the link is already marked as dangerous.

---

## 3. How it Flags `scam_test.html` (Example)
When you open `scam_test.html`, the tool flags it as **100% Confirmed Scam** because:
* It has `"Metamask"` in the title but is not hosted on the official `metamask.io` domain.
* It asks for a password/seed phrase on an untrusted domain.
* It has a countdown timer showing urgency (*"04m 12s left"*).
* The AI scans the text and recognizes giveaway scam words.

---

## 4. Quick Q&A (Top 5 Questions to Prepare For)

### Q1: Why use a Python FastAPI backend instead of putting the AI directly in the extension?
* **Answer**: It keeps the extension very lightweight and fast, protects API keys (VirusTotal/Google) from being stolen, and allows you to update the AI model on the server without having to update the extension.

### Q2: What is "Levenshtein Distance"?
* **Answer**: A method that counts the number of letter edits needed to turn one word into another. We use it to detect brand typos (e.g. `g00gle.com` differs from `google.com` by 2 character edits).

### Q3: How do you prevent false positives (tagging real sites as scams)?
* **Answer**: We use an explicit **Whitelist**. Whitelisted domains (like `google.com`, `github.com`) bypass the scanning engine entirely and get a `0` risk score.

### Q4: What database and ORM did you use?
* **Answer**: **SQLite** for database storage and **SQLAlchemy** (Object Relational Mapper) in Python to save scan history, community scam reports, and whitelist/blacklist rules.

### Q5: What happens when a user reports a scam?
* **Answer**: The report is saved to the database, and the reported website is automatically added to the **Blacklist** so it will be blocked immediately for all subsequent scans.
