import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, JSON
from app.database import Base

class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True, nullable=False)
    domain = Column(String, index=True, nullable=False)
    risk_score = Column(Float, nullable=False)
    category = Column(String, nullable=False)  # Safe, Suspicious, High Risk, Confirmed Scam
    reasons = Column(JSON, nullable=True)  # List of reasons as JSON array
    details = Column(JSON, nullable=True)  # Detailed score breakdown
    scanned_at = Column(DateTime, default=datetime.datetime.utcnow)

class ScamReport(Base):
    __tablename__ = "scam_reports"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True, nullable=False)
    domain = Column(String, index=True, nullable=False)
    reason = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    reporter_ip = Column(String, nullable=True)
    reported_at = Column(DateTime, default=datetime.datetime.utcnow)

class WhitelistedDomain(Base):
    __tablename__ = "whitelisted_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True, nullable=False)
    added_at = Column(DateTime, default=datetime.datetime.utcnow)

class BlacklistedDomain(Base):
    __tablename__ = "blacklisted_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True, nullable=False)
    source = Column(String, nullable=False)  # community, system, admin
    added_at = Column(DateTime, default=datetime.datetime.utcnow)
