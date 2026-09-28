from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, DateTime, Text, ForeignKey
from ..database import Base

class Scan(Base):
    __tablename__ = "scan_jobs"
    id = Column(String, primary_key=True)
    target = Column(String, nullable=False)
    status = Column(String, default="queued")
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    security_score = Column(Integer, default=100)
    duration = Column(Float, default=0)
    pages_scanned = Column(Integer, default=0)
    requests_sent = Column(Integer, default=0)
    config_json = Column(Text, default="{}")
    error = Column(Text, nullable=True)

class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("scan_jobs.id"), index=True)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    confidence = Column(String, nullable=False)
    category = Column(String, nullable=False)
    url = Column(Text, nullable=False)
    parameter = Column(String, nullable=True)
    method = Column(String, default="GET")
    description = Column(Text, default="")
    evidence = Column(Text, default="")
    impact = Column(Text, default="")
    detection = Column(Text, default="")
    recommendation = Column(Text, default="")
    owasp = Column(String, nullable=True)
    cwe = Column(String, nullable=True)
    status = Column(String, default="Open")
    reviewer_note = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

class Page(Base):
    __tablename__ = "scan_pages"
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, ForeignKey("scan_jobs.id"), index=True)
    url = Column(Text, nullable=False)
    status_code = Column(Integer)
    method = Column(String, default="GET")
    content_type = Column(String, default="")
    response_time = Column(Float, default=0)
    response_size = Column(Integer, default=0)
    title = Column(Text, default="")
    depth = Column(Integer, default=0)

class RequestRecord(Base):
    __tablename__ = "request_records"
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, ForeignKey("scan_jobs.id"), index=True)
    url = Column(Text, nullable=False)
    method = Column(String, default="GET")
    status_code = Column(Integer)
    response_time = Column(Float, default=0)
    response_length = Column(Integer, default=0)
    content_type = Column(String, default="")
    redirect_to = Column(Text, nullable=True)
    headers_json = Column(Text, default="{}")
