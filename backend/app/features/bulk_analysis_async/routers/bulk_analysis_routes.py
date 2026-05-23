"""
Bulk Analysis Routes - SSE Streaming API Endpoints

Provides real-time streaming results for bulk IOC analysis
"""

import json
import logging
from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from ..service import get_bulk_analysis_service
from ..schemas import (
    AgentType,
    BulkAnalysisRequest,
    SingleIocAnalysisRequest,
    BulkAnalysisResponse,
    HealthCheckResponse
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/bulk-analysis", tags=["Bulk Analysis"])


def format_sse_event(data: dict) -> str:
    """Format data as SSE event"""
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"


@router.get("/health", response_model=HealthCheckResponse)
async def health_check():
    """Check bulk analysis service health"""
    return HealthCheckResponse(
        status="healthy",
        agents_available=["triage", "malware", "infrastructure", "campaign"],
        message="Bulk analysis service is ready"
    )


@router.post("/stream/single")
async def stream_single_ioc_analysis(request: SingleIocAnalysisRequest):
    """
    Stream analysis results for a single IOC

    Returns SSE stream with results as each agent completes
    """
    service = get_bulk_analysis_service()

    # Convert agent types to strings
    selected_agents = None
    if request.agents:
        selected_agents = [agent.value for agent in request.agents]

    async def event_generator():
        try:
            # Start event
            yield format_sse_event({
                'event': 'analysis_start',
                'ioc': request.ioc,
                'agents': selected_agents or ['triage', 'malware', 'infrastructure', 'campaign'],
                'timestamp': datetime.utcnow().isoformat()
            })

            # Stream results
            async for result in service.stream_single_ioc_analysis(
                ioc=request.ioc,
                selected_agents=selected_agents
            ):
                yield format_sse_event(result)

            # Complete event
            yield format_sse_event({
                'event': 'analysis_complete',
                'ioc': request.ioc,
                'timestamp': datetime.utcnow().isoformat()
            })

        except Exception as e:
            logger.error(f"Error in single IOC analysis stream: {e}")
            yield format_sse_event({
                'event': 'error',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            })

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@router.post("/stream/bulk")
async def stream_bulk_analysis(request: BulkAnalysisRequest):
    """
    Stream bulk analysis results for multiple IOCs

    Phase 1: Stream individual agent results as they complete
    Phase 2: Stream aggregation result (if enabled)

    Returns SSE stream with progress updates
    """
    if not request.iocs:
        raise HTTPException(status_code=400, detail="At least one IOC is required")

    if len(request.iocs) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 IOCs allowed per request")

    service = get_bulk_analysis_service()

    # Convert agent types to strings
    selected_agents = None
    if request.agents:
        selected_agents = [agent.value for agent in request.agents]

    async def event_generator():
        try:
            async for result in service.stream_bulk_analysis(
                iocs=request.iocs,
                selected_agents=selected_agents,
                include_aggregation=request.include_aggregation
            ):
                yield format_sse_event(result)

        except Exception as e:
            logger.error(f"Error in bulk analysis stream: {e}")
            yield format_sse_event({
                'event': 'error',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            })

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@router.post("/sync/bulk", response_model=BulkAnalysisResponse)
async def analyze_bulk_sync(request: BulkAnalysisRequest):
    """
    Non-streaming bulk analysis

    Returns all results at once after completion
    Use for smaller batches or when streaming is not needed
    """
    if not request.iocs:
        raise HTTPException(status_code=400, detail="At least one IOC is required")

    if len(request.iocs) > 50:
        raise HTTPException(
            status_code=400,
            detail="Maximum 50 IOCs allowed for sync endpoint. Use streaming for larger batches."
        )

    service = get_bulk_analysis_service()

    # Convert agent types to strings
    selected_agents = None
    if request.agents:
        selected_agents = [agent.value for agent in request.agents]

    try:
        result = await service.analyze_bulk_sync(
            iocs=request.iocs,
            selected_agents=selected_agents,
            include_aggregation=request.include_aggregation
        )

        return BulkAnalysisResponse(
            total_iocs=result.get('total_iocs', len(request.iocs)),
            phase1_results=result.get('phase1_results', []),
            phase2_aggregation=result.get('phase2_aggregation')
        )

    except Exception as e:
        logger.error(f"Error in sync bulk analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agents")
async def get_available_agents():
    """Get list of available analysis agents"""
    return {
        "agents": [
            {
                "id": "triage",
                "name": "Triage Specialist",
                "description": "Initial threat assessment and classification"
            },
            {
                "id": "malware",
                "name": "Malware Analysis Specialist",
                "description": "Deep malware behavior and capability analysis"
            },
            {
                "id": "infrastructure",
                "name": "Infrastructure Correlation Specialist",
                "description": "Network infrastructure and hosting analysis"
            },
            {
                "id": "campaign",
                "name": "Campaign Intelligence Analyst",
                "description": "Threat actor and campaign attribution"
            }
        ]
    }
