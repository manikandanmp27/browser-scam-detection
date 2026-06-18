import os
import joblib
import tldextract
from sqlalchemy.orm import Session
from datetime import datetime

from app.config import settings
from app.models import WhitelistedDomain, BlacklistedDomain, ScanHistory
from app.schemas import UrlScanRequest, UrlScanResponse
from app.services.whois_service import get_domain_age_days
from app.services.virustotal_service import check_url_virustotal
from app.services.safe_browsing import check_url_google_safe_browsing

# Known brands to detect typosquatting and brand impersonation
KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "twitter": "twitter.com",
    "yahoo": "yahoo.com",
    "bankofamerica": "bankofamerica.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "binance": "binance.com",
    "coinbase": "coinbase.com",
    "metamask": "metamask.io"
}

# Suspicious TLDs
SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "work", "click", "win", "loan", 
    "gq", "cf", "tk", "ml", "country", "stream", "download", 
    "bid", "date", "party", "science"
}

# Suspicious keywords in URL
SUSPICIOUS_URL_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account", 
    "banking", "claim", "gift", "free", "reward", "prize", "wallet", 
    "airdrop", "giveaway", "double-crypto", "support-desk", "billing"
]

# Scam phrases for fallback analysis
SCAM_PHRASES = [
    "congratulations, you won",
    "congratulations! you won",
    "claim your reward",
    "limited time offer",
    "double your crypto",
    "verify your credentials",
    "unusual login activity",
    "deposit funds",
    "fill in details to claim",
    "free iphone",
    "viruses detected",
    "account suspended"
]

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein distance between two strings."""
    if len(s1) > len(s2):
        s1, s2 = s2, s1
    distances = range(len(s1) + 1)
    for i2, c2 in enumerate(s2):
        distances_ = [i2+1]
        for i1, c1 in enumerate(s1):
            if c1 == c2:
                distances_.append(distances[i1])
            else:
                distances_.append(1 + min((distances[i1], distances[i1 + 1], distances_[-1])))
        distances = distances_
    return distances[-1]

def analyze_url(db: Session, request: UrlScanRequest) -> dict:
    url = request.url
    
    # 1. Parse domain
    extracted = tldextract.extract(url)
    subdomain = extracted.subdomain
    registered_domain = extracted.domain  # e.g. "amaz0n"
    suffix = extracted.suffix  # e.g. "com"
    domain = f"{registered_domain}.{suffix}" if suffix else registered_domain
    
    # Initialize threat factors
    reasons = []
    risk_score = 0.0
    
    # Details dictionary for response
    details = {
        "typosquatting_detected": False,
        "impersonated_brand": None,
        "suspicious_url_keywords": [],
        "suspicious_tld": False,
        "ml_scam_probability": 0.0,
        "keyword_matches": [],
        "whois_age_days": None,
        "virustotal_flagged": False,
        "google_safe_browsing_flagged": False,
        "login_form_on_untrusted_domain": False
    }

    # 2. Check Whitelist
    whitelisted = db.query(WhitelistedDomain).filter(WhitelistedDomain.domain == domain).first()
    if whitelisted:
        return {
            "url": url,
            "domain": domain,
            "risk_score": 0.0,
            "category": "Safe",
            "reasons": ["Domain is explicitly whitelisted."],
            "details": {"whitelisted": True},
            "scanned_at": datetime.utcnow()
        }

    # 3. Check Blacklist
    blacklisted = db.query(BlacklistedDomain).filter(BlacklistedDomain.domain == domain).first()
    if blacklisted:
        return {
            "url": url,
            "domain": domain,
            "risk_score": 100.0,
            "category": "Confirmed Scam",
            "reasons": [f"Domain is blacklisted (source: {blacklisted.source})."],
            "details": {"blacklisted": True},
            "scanned_at": datetime.utcnow()
        }

    # --- Feature 1: URL Analysis ---
    # Typosquatting / Brand Spoofing Check
    for brand, brand_domain in KNOWN_BRANDS.items():
        if brand_domain == domain:
            # Official domain, skip check
            continue
            
        # Case A: Brand name is in the domain name but it is not the official domain
        # (e.g. paypal-verification-login.com, chase-security.org)
        if brand in registered_domain and domain != brand_domain:
            reasons.append(f"Domain name contains registered brand '{brand}' but is not official.")
            risk_score += 45
            details["typosquatting_detected"] = True
            details["impersonated_brand"] = brand
            break
            
        # Case B: Typosquatting via edit distance (Levenshtein distance of 1 or 2)
        # (e.g. amaz0n, paypa1, g00gle)
        dist = levenshtein_distance(registered_domain, brand)
        if dist in (1, 2) and len(registered_domain) >= 4:
            reasons.append(f"Domain resembles legitimate brand '{brand}' but differs by {dist} character(s) (typosquatting).")
            risk_score += 50
            details["typosquatting_detected"] = True
            details["impersonated_brand"] = brand
            break

        # Case C: Subdomain spoofing
        # (e.g. paypal.com.scam-site.com)
        if subdomain:
            subdomain_parts = subdomain.split('.')
            if brand_domain in subdomain_parts or brand in subdomain_parts:
                reasons.append(f"Brand name '{brand}' detected in subdomain, but hosted on domain '{domain}'.")
                risk_score += 40
                details["typosquatting_detected"] = True
                details["impersonated_brand"] = brand
                break

    # Suspicious keywords in URL path/params
    matched_keywords = []
    lower_url = url.lower()
    for keyword in SUSPICIOUS_URL_KEYWORDS:
        if keyword in lower_url:
            # If it's part of the domain name itself and already caught by typosquatting, don't double count
            # but count if it's in the path
            matched_keywords.append(keyword)
            
    if matched_keywords:
        risk_score += min(len(matched_keywords) * 10, 30)
        reasons.append(f"Suspicious keyword(s) found in URL: {', '.join(matched_keywords)}.")
        details["suspicious_url_keywords"] = matched_keywords

    # Suspicious TLD check
    if suffix in SUSPICIOUS_TLDS:
        risk_score += 15
        reasons.append(f"Domain uses a suspicious TLD (.{suffix}) frequently associated with spam or scams.")
        details["suspicious_tld"] = True

    # --- Feature 2: Content Analysis ---
    content_analyzed = False
    if request.page_text:
        text_content = request.page_text.strip()
        if len(text_content) > 10:
            content_analyzed = True
            ml_scored = False
            
            # Try running ML classifier
            if os.path.exists(settings.MODEL_PATH) and os.path.exists(settings.VECTORIZER_PATH):
                try:
                    classifier = joblib.load(settings.MODEL_PATH)
                    vectorizer = joblib.load(settings.VECTORIZER_PATH)
                    
                    # Transform and predict probability of class 1 (scam)
                    features = vectorizer.transform([text_content])
                    prob = classifier.predict_proba(features)[0][1]
                    
                    details["ml_scam_probability"] = float(prob)
                    ml_scored = True
                    
                    if prob > 0.6:
                        # Heavy weight for ML score
                        score_increment = int(prob * 35)
                        risk_score += score_increment
                        reasons.append(f"AI text classifier flagged scam content (scam confidence: {prob*100:.1f}%).")
                except Exception as e:
                    # Log error and fall back to keyword matching
                    pass
            
            # Fallback or supplementary keyword matching
            matched_phrases = []
            lower_text = text_content.lower()
            for phrase in SCAM_PHRASES:
                if phrase in lower_text:
                    matched_phrases.append(phrase)
                    
            if matched_phrases:
                details["keyword_matches"] = matched_phrases
                if not ml_scored:
                    # If ML didn't run, score via keywords
                    risk_score += min(len(matched_phrases) * 15, 35)
                    reasons.append(f"Scam phrases detected on page: {', '.join([f'\"{p}\"' for p in matched_phrases])}.")
                elif len(matched_phrases) >= 2 and details["ml_scam_probability"] <= 0.6:
                    # If ML missed it but we see strong keywords, add a small boost
                    risk_score += 15
                    reasons.append(f"Scam indicator phrases found: {', '.join([f'\"{p}\"' for p in matched_phrases])}.")

    # --- Feature 3: Brand Impersonation (Title check) ---
    if request.page_title:
        title_lower = request.page_title.lower()
        for brand, brand_domain in KNOWN_BRANDS.items():
            if brand in title_lower and domain != brand_domain:
                # Page claims to be brand in title but is not official
                reasons.append(f"Page title contains '{brand}' but domain is unofficial ({domain}).")
                risk_score += 35
                details["impersonated_brand"] = brand
                break

    # --- Feature 4: Visual Risk Indicators & Forms ---
    if request.login_form_detected:
        # Check if the domain is a known safe domain that usually has logins
        is_safe_login_provider = False
        for brand_domain in KNOWN_BRANDS.values():
            if domain == brand_domain:
                is_safe_login_provider = True
                break
        
        # If it's not a known brand domain, flags login form on untrusted site
        if not is_safe_login_provider and domain not in ["github.com", "linkedin.com", "stackoverflow.com", "reddit.com"]:
            risk_score += 20
            reasons.append("Login/credentials form found on an untrusted or unfamiliar domain.")
            details["login_form_on_untrusted_domain"] = True

    if request.popups_detected:
        risk_score += 10
        reasons.append("Excessive or intrusive popups detected on page load.")
        
    if request.countdowns_detected:
        risk_score += 15
        reasons.append("Count-down timer or artificial urgency elements detected.")

    # --- Feature 5: Advanced APIs (WHOIS, VT, GS) ---
    # 5a. WHOIS Age
    whois_info = get_domain_age_days(domain)
    if whois_info["age_days"] is not None:
        details["whois_age_days"] = whois_info["age_days"]
        if whois_info["age_days"] < 30:
            risk_score += 35
            reasons.append(f"Domain is very young (created {whois_info['age_days']} days ago).")
        elif whois_info["age_days"] < 180:
            risk_score += 15
            reasons.append(f"Domain is relatively new (created {whois_info['age_days']} days ago).")
    elif whois_info["error"] and "WHOIS error" in whois_info["error"]:
        # If WHOIS error is 'no match' or 'not found', it might be unregistered/brand new
        if "not found" in whois_info["error"].lower() or "no match" in whois_info["error"].lower():
            risk_score += 20
            reasons.append("WHOIS record is missing or not found (potential newly registered domain).")

    # 5b. VirusTotal
    vt_result = check_url_virustotal(url)
    if vt_result["is_flagged"]:
        risk_score += 40
        reasons.append(f"VirusTotal security vendors flagged this URL as malicious ({vt_result['malicious']} detection(s)).")
        details["virustotal_flagged"] = True

    # 5c. Google Safe Browsing
    gs_result = check_url_google_safe_browsing(url)
    if gs_result["is_flagged"]:
        risk_score += 50
        reasons.append(f"Google Safe Browsing flagged this site as dangerous ({', '.join(gs_result['threat_types'])}).")
        details["google_safe_browsing_flagged"] = True

    # Capping and categorization
    risk_score = min(max(0.0, risk_score), 100.0)
    
    if risk_score <= 30.0:
        category = "Safe"
    elif risk_score <= 60.0:
        category = "Suspicious"
    elif risk_score <= 85.0:
        category = "High Risk"
    else:
        category = "Confirmed Scam"
        
    # If no reasons were triggered but score is 0, give a default reason
    if not reasons and risk_score == 0:
        reasons.append("No threat indicators or suspicious features detected.")

    return {
        "url": url,
        "domain": domain,
        "risk_score": risk_score,
        "category": category,
        "reasons": reasons,
        "details": details,
        "scanned_at": datetime.utcnow()
    }
