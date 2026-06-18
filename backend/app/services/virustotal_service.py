import base64
import requests
import logging
from app.config import settings

logger = logging.getLogger(__name__)

def check_url_virustotal(url: str) -> dict:
    """
    Check VirusTotal V3 URL analysis using base64 URL identifier.
    """
    result = {
        "harmless": 0,
        "malicious": 0,
        "suspicious": 0,
        "undetected": 0,
        "is_flagged": False,
        "error": None
    }
    
    api_key = settings.VIRUSTOTAL_API_KEY
    if not api_key:
        # Gracefully return empty if key not provided
        return result
        
    try:
        # VirusTotal V3 requires URL identifier to be urlsafe base64 without '=' padding
        url_bytes = url.encode('utf-8')
        url_id = base64.urlsafe_b64encode(url_bytes).decode('utf-8').rstrip('=')
        
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(endpoint, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            
            result["harmless"] = stats.get("harmless", 0)
            result["malicious"] = stats.get("malicious", 0)
            result["suspicious"] = stats.get("suspicious", 0)
            result["undetected"] = stats.get("undetected", 0)
            
            # Flag if 2 or more vendors mark it as malicious or suspicious
            if result["malicious"] >= 2 or (result["malicious"] + result["suspicious"]) >= 3:
                result["is_flagged"] = True
                
        elif response.status_code == 404:
            # Domain/URL not scanned yet on VirusTotal, we could trigger a scan,
            # but for real-time responses we just return a neutral response
            pass
        else:
            result["error"] = f"VirusTotal API error: {response.status_code}"
            logger.error(f"VirusTotal error {response.status_code}: {response.text}")
            
    except Exception as e:
        logger.error(f"VirusTotal request exception: {str(e)}")
        result["error"] = str(e)
        
    return result
