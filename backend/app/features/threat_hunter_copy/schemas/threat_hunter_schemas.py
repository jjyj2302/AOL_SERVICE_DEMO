"""Pydantic schemas for AOL Threat Hunter API."""
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class ThreatHuntRequest(BaseModel):
    """Request schema for threat hunting investigation."""
    ioc: str = Field(..., description="IOC to investigate (IP, domain, hash, URL)")
    investigation_type: Optional[str] = Field(
        default="comprehensive",
        description="Investigation type: comprehensive, malware, infrastructure, campaign"
    )


class ThreatHuntResponse(BaseModel):
    """Response schema for threat hunting investigation."""
    status: str = Field(..., description="Investigation status: success, failed, running")
    ioc: str = Field(..., description="Investigated IOC")
    investigation_type: Optional[str] = Field(None, description="Investigation type")
    investigation_id: Optional[str] = Field(None, description="Investigation ID for tracking")
    triage_report: Optional[str] = Field(None, description="Triage assessment report (JSON string)")
    malware_report: Optional[str] = Field(None, description="Malware analysis report (JSON string)")
    infrastructure_report: Optional[str] = Field(None, description="Infrastructure correlation report (JSON string)")
    orchestrator_report: Optional[str] = Field(None, description="Intelligence orchestration report (JSON string)")
    campaign_report: Optional[str] = Field(None, description="Campaign intelligence report with hunt hypotheses (JSON string)")
    final_report: Optional[str] = Field(None, description="Combined final report (JSON string)")
    error_message: Optional[str] = Field(None, description="Error message if investigation failed")


class BatchThreatHuntRequest(BaseModel):
    """Request schema for batch threat hunting."""
    iocs: List[str] = Field(..., description="List of IOCs to investigate")
    investigation_type: Optional[str] = Field(default="comprehensive")


class BatchThreatHuntResponse(BaseModel):
    """Response schema for batch investigation."""
    total: int = Field(..., description="Total number of IOCs")
    successful: int = Field(..., description="Number of successful investigations")
    failed: int = Field(..., description="Number of failed investigations")
    results: List[ThreatHuntResponse] = Field(..., description="Individual investigation results")
