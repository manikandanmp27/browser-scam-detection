import whois
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def get_domain_age_days(domain: str) -> dict:
    """
    Query WHOIS for the domain creation date and calculate its age in days.
    Returns a dictionary with details.
    """
    result = {
        "creation_date": None,
        "age_days": None,
        "registrar": None,
        "is_young": False,
        "error": None
    }
    
    try:
        # Perform WHOIS lookup
        w = whois.whois(domain)
        
        creation_date = w.creation_date
        
        # Sometimes creation_date is a list (e.g. [datetime, datetime])
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            # Parse datetime if it's a string, though python-whois usually returns datetime objects
            if isinstance(creation_date, str):
                for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
                    try:
                        creation_date = datetime.strptime(creation_date, fmt)
                        break
                    except ValueError:
                        pass
            
            if isinstance(creation_date, datetime):
                result["creation_date"] = creation_date.isoformat()
                delta = datetime.utcnow() - creation_date
                result["age_days"] = max(0, delta.days)
                result["registrar"] = w.registrar
                
                # A domain less than 30 days old is a major risk indicator.
                # A domain less than 180 days (6 months) is a minor risk indicator.
                result["is_young"] = result["age_days"] < 180
                
        else:
            result["error"] = "Creation date not found in WHOIS data"
            
    except Exception as e:
        logger.error(f"WHOIS lookup failed for {domain}: {str(e)}")
        result["error"] = f"WHOIS error: {str(e)}"
        
    return result
