"""
Bulk Analysis Schemas - Request/Response models for API
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class AgentType(str, Enum):
    TRIAGE = "triage"
    MALWARE = "malware"
    INFRASTRUCTURE = "infrastructure"
    CAMPAIGN = "campaign"


class BulkAnalysisRequest(BaseModel):
    """Request model for bulk IOC analysis"""
    iocs: List[str] = Field(
        ...,
        description="List of IOCs to analyze",
        min_length=1,
        max_length=100
    )
    agents: Optional[List[AgentType]] = Field(
        default=None,
        description="List of agents to use. If not specified, all agents are used."
    )
    include_aggregation: bool = Field(
        default=True,
        description="Whether to include Phase 2 aggregation"
    )


class SingleIocAnalysisRequest(BaseModel):
    """Request model for single IOC analysis"""
    ioc: str = Field(..., description="IOC to analyze")
    agents: Optional[List[AgentType]] = Field(
        default=None,
        description="List of agents to use"
    )


class AgentResult(BaseModel):
    """Result from a single agent analysis"""
    status: str
    ioc: str
    agent: str
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class Phase1Results(BaseModel):
    """Results from Phase 1 parallel analysis"""
    ioc: str
    analyses: Dict[str, AgentResult]


class AggregationResult(BaseModel):
    """Result from Phase 2 aggregation"""
    status: str
    aggregated_report: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class BulkAnalysisResponse(BaseModel):
    """Response model for non-streaming bulk analysis"""
    total_iocs: int
    phase1_results: List[Dict[str, Any]]
    phase2_aggregation: Optional[Dict[str, Any]] = None


class StreamEvent(BaseModel):
    """SSE event model for streaming responses"""
    event: str
    data: Optional[Dict[str, Any]] = None
    ioc: Optional[str] = None
    agent: Optional[str] = None
    status: Optional[str] = None
    error: Optional[str] = None
    progress: Optional[Dict[str, Any]] = None
    timestamp: Optional[str] = None


class HealthCheckResponse(BaseModel):
    """Health check response"""
    status: str
    agents_available: List[str]
    message: str
