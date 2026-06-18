from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Dict, Any
import tldextract

from app.config import settings
from app.database import get_db, engine, Base
from app.models import WhitelistedDomain, BlacklistedDomain, ScanHistory, ScamReport
from app.schemas import (
    UrlScanRequest, UrlScanResponse, ScamReportCreate, ScamReportResponse,
    WhitelistCreate, BlacklistCreate, DashboardStats
)
from app.services.scam_detector import analyze_url

# Initialize DB tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# Set CORS origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "online"
    }

@app.post(f"{settings.API_V1_STR}/scan", response_model=UrlScanResponse)
def scan_url(request: UrlScanRequest, db: Session = Depends(get_db)):
    try:
        # Run detection engine
        result = analyze_url(db, request)
        
        # Save scan to history
        db_scan = ScanHistory(
            url=result["url"],
            domain=result["domain"],
            risk_score=result["risk_score"],
            category=result["category"],
            reasons=result["reasons"],
            details=result["details"],
            scanned_at=result["scanned_at"]
        )
        db.add(db_scan)
        db.commit()
        db.refresh(db_scan)
        
        return db_scan
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error executing scan: {str(e)}"
        )

@app.get(f"{settings.API_V1_STR}/history", response_model=List[UrlScanResponse])
def get_scan_history(limit: int = 100, skip: int = 0, db: Session = Depends(get_db)):
    try:
        scans = db.query(ScanHistory).order_by(ScanHistory.scanned_at.desc()).offset(skip).limit(limit).all()
        return scans
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving scan history: {str(e)}"
        )

@app.post(f"{settings.API_V1_STR}/report", response_model=ScamReportResponse)
def report_scam(report: ScamReportCreate, db: Session = Depends(get_db)):
    try:
        extracted = tldextract.extract(report.url)
        domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        
        # Save report
        db_report = ScamReport(
            url=report.url,
            domain=domain,
            reason=report.reason,
            description=report.description
        )
        db.add(db_report)
        
        # Automatically blacklist domain from community report
        existing_blacklist = db.query(BlacklistedDomain).filter(BlacklistedDomain.domain == domain).first()
        if not existing_blacklist:
            db_blacklist = BlacklistedDomain(
                domain=domain,
                source="community"
            )
            db.add(db_blacklist)
            
        db.commit()
        db.refresh(db_report)
        return db_report
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error filing report: {str(e)}"
        )

@app.get(f"{settings.API_V1_STR}/stats", response_model=DashboardStats)
def get_stats(db: Session = Depends(get_db)):
    try:
        total_scans = db.query(ScanHistory).count()
        total_scams_detected = db.query(ScanHistory).filter(ScanHistory.risk_score >= 60.0).count()
        total_reports = db.query(ScamReport).count()
        
        # 10 recent scans
        recent_scans = db.query(ScanHistory).order_by(ScanHistory.scanned_at.desc()).limit(10).all()
        
        # Top threat domains (risk_score >= 60, grouped by domain, ordered by frequency desc)
        threat_query = db.query(
            ScanHistory.domain,
            func.count(ScanHistory.id).label("count"),
            func.max(ScanHistory.risk_score).label("max_risk")
        ).filter(
            ScanHistory.risk_score >= 60.0
        ).group_by(
            ScanHistory.domain
        ).order_by(
            func.count(ScanHistory.id).desc()
        ).limit(5).all()
        
        top_threats = [
            {"domain": t.domain, "count": t.count, "max_risk": t.max_risk}
            for t in threat_query
        ]
        
        return {
            "total_scans": total_scans,
            "total_scams_detected": total_scams_detected,
            "total_reports": total_reports,
            "recent_scans": recent_scans,
            "top_threats": top_threats
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error compiling dashboard stats: {str(e)}"
        )

# Whitelist endpoints
@app.get(f"{settings.API_V1_STR}/whitelist", response_model=List[str])
def get_whitelist(db: Session = Depends(get_db)):
    domains = db.query(WhitelistedDomain).all()
    return [d.domain for d in domains]

@app.post(f"{settings.API_V1_STR}/whitelist")
def add_to_whitelist(item: WhitelistCreate, db: Session = Depends(get_db)):
    try:
        existing = db.query(WhitelistedDomain).filter(WhitelistedDomain.domain == item.domain).first()
        if existing:
            return {"message": "Domain already whitelisted."}
        
        # Delete from blacklist if exists
        blacklist_entry = db.query(BlacklistedDomain).filter(BlacklistedDomain.domain == item.domain).first()
        if blacklist_entry:
            db.delete(blacklist_entry)
            
        db_whitelist = WhitelistedDomain(domain=item.domain)
        db.add(db_whitelist)
        db.commit()
        return {"message": f"Domain {item.domain} successfully whitelisted."}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error adding to whitelist: {str(e)}"
        )

@app.delete(f"{settings.API_V1_STR}/whitelist/{{domain}}")
def remove_from_whitelist(domain: str, db: Session = Depends(get_db)):
    try:
        db_item = db.query(WhitelistedDomain).filter(WhitelistedDomain.domain == domain).first()
        if not db_item:
            raise HTTPException(status_code=404, detail="Domain not found in whitelist.")
        db.delete(db_item)
        db.commit()
        return {"message": f"Domain {domain} removed from whitelist."}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error removing from whitelist: {str(e)}"
        )

# Blacklist endpoints
@app.get(f"{settings.API_V1_STR}/blacklist")
def get_blacklist(db: Session = Depends(get_db)):
    try:
        domains = db.query(BlacklistedDomain).all()
        return [{"domain": d.domain, "source": d.source, "added_at": d.added_at} for d in domains]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error fetching blacklist: {str(e)}"
        )

@app.post(f"{settings.API_V1_STR}/blacklist")
def add_to_blacklist(item: BlacklistCreate, db: Session = Depends(get_db)):
    try:
        existing = db.query(BlacklistedDomain).filter(BlacklistedDomain.domain == item.domain).first()
        if existing:
            return {"message": "Domain already blacklisted."}
            
        # Delete from whitelist if exists
        whitelist_entry = db.query(WhitelistedDomain).filter(WhitelistedDomain.domain == item.domain).first()
        if whitelist_entry:
            db.delete(whitelist_entry)
            
        db_blacklist = BlacklistedDomain(domain=item.domain, source=item.source)
        db.add(db_blacklist)
        db.commit()
        return {"message": f"Domain {item.domain} successfully blacklisted."}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error adding to blacklist: {str(e)}"
        )

@app.delete(f"{settings.API_V1_STR}/blacklist/{{domain}}")
def remove_from_blacklist(domain: str, db: Session = Depends(get_db)):
    try:
        db_item = db.query(BlacklistedDomain).filter(BlacklistedDomain.domain == domain).first()
        if not db_item:
            raise HTTPException(status_code=404, detail="Domain not found in blacklist.")
        db.delete(db_item)
        db.commit()
        return {"message": f"Domain {domain} removed from blacklist."}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error removing from blacklist: {str(e)}"
        )
