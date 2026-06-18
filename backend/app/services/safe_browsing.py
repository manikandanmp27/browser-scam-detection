import requests
import logging
from app.config import settings

logger = logging.getLogger(__name__)

def check_url_google_safe_browsing(url: str) -> dict:
    """
    Check URL against Google Safe Browsing API v4.
    """
    result = {
        "is_flagged": False,
        "threat_types": [],
        "error": None
    }
    
    api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
    if not api_key:
        return result
        
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        
        body = {
            "client": {
                "clientId": "browser-scam-detection",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", 
                    "SOCIAL_ENGINEERING", 
                    "UNWANTED_SOFTWARE", 
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        response = requests.post(endpoint, json=body, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            matches = data.get("matches", [])
            
            if matches:
                result["is_flagged"] = True
                result["threat_types"] = list(set([match.get("threatType") for match in matches]))
        else:
            result["error"] = f"Safe Browsing API error: {response.status_code}"
            logger.error(f"Google Safe Browsing error {response.status_code}: {response.text}")
            
    except Exception as e:
        logger.error(f"Google Safe Browsing request exception: {str(e)}")
        result["error"] = str(e)
        
    return result
