from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class UrlScanRequest(BaseModel):
    url: str = Field(..., description="The URL of the webpage to scan")
    page_text: Optional[str] = Field(None, description="The visible text content of the webpage")
    page_title: Optional[str] = Field(None, description="The title tag of the webpage")
    popups_detected: Optional[bool] = Field(False, description="Whether excessive popups were detected")
    countdowns_detected: Optional[bool] = Field(False, description="Whether countdown timers were detected")
    login_form_detected: Optional[bool] = Field(False, description="Whether a login/credentials form was found")

class UrlScanResponse(BaseModel):
    url: str
    domain: str
    risk_score: float
    category: str
    reasons: List[str]
    details: Dict[str, Any]
    scanned_at: datetime

    class Config:
        from_attributes = True

class ScamReportCreate(BaseModel):
    url: str
    reason: str
    description: Optional[str] = None

class ScamReportResponse(BaseModel):
    id: int
    url: str
    domain: str
    reason: str
    description: Optional[str]
    reported_at: datetime

    class Config:
        from_attributes = True

class WhitelistCreate(BaseModel):
    domain: str

class BlacklistCreate(BaseModel):
    domain: str
    source: str = "admin"

class DashboardStats(BaseModel):
    total_scans: int
    total_scams_detected: int
    total_reports: int
    recent_scans: List[UrlScanResponse]
    top_threats: List[Dict[str, Any]]
