"""
History Schemas - Pydantic 스키마 정의
"""

from typing import Optional, List, Any
from datetime import datetime
from pydantic import BaseModel, Field


# ===== File Schemas =====
class FileUploadResponse(BaseModel):
    id: int
    filename: str
    stored_filename: str
    file_size: Optional[int] = None
    mime_type: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ===== Session Schemas =====
class SessionCreate(BaseModel):
    session_name: Optional[str] = None
    source_type: str = Field(..., description="manual, pdf_upload, file_upload")
    uploaded_file_id: Optional[int] = None
    total_iocs: int = 0


class SessionResponse(BaseModel):
    id: int
    session_name: Optional[str] = None
    source_type: str
    uploaded_file: Optional[FileUploadResponse] = None
    total_iocs: int
    status: str
    created_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    ioc_analyses: Optional[List['IocAnalysisResponse']] = None
    aggregation: Optional['AggregationResponse'] = None

    class Config:
        from_attributes = True


class SessionListResponse(BaseModel):
    sessions: List[SessionResponse]
    total: int
    page: int
    page_size: int


# ===== IOC Analysis Schemas =====
class IocAnalysisCreate(BaseModel):
    session_id: int
    ioc_value: str
    ioc_type: Optional[str] = None
    triage_result: Optional[str] = None
    malware_result: Optional[str] = None
    infrastructure_result: Optional[str] = None
    campaign_result: Optional[str] = None
    overall_threat_level: Optional[str] = None


class IocAnalysisResponse(BaseModel):
    id: int
    session_id: int
    ioc_value: str
    ioc_type: Optional[str] = None
    triage_result: Optional[Any] = None
    malware_result: Optional[Any] = None
    infrastructure_result: Optional[Any] = None
    campaign_result: Optional[Any] = None
    overall_threat_level: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ===== Aggregation Schemas =====
class AggregationCreate(BaseModel):
    session_id: int
    aggregated_report: str


class AggregationResponse(BaseModel):
    id: int
    session_id: int
    aggregated_report: Any
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# Forward reference 해결
SessionResponse.model_rebuild()
