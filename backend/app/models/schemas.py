from pydantic import BaseModel, Field, HttpUrl
from typing import Optional

class ScanCreate(BaseModel):
    target: HttpUrl
    authorized: bool
    max_pages: int = Field(25, ge=1, le=100)
    max_depth: int = Field(2, ge=0, le=4)
    concurrency: int = Field(5, ge=1, le=5)
    follow_redirects: bool = True
    scan_javascript: bool = True
    analyze_forms: bool = True
    passive_only: bool = False

class FindingUpdate(BaseModel):
    status: Optional[str] = None
    reviewer_note: Optional[str] = None
