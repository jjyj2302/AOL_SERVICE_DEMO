"""FastAPI routes for AOL Threat Hunter."""
import logging
from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import Dict, Any

from ..schemas import (
    ThreatHuntRequest,
    ThreatHuntResponse,
    BatchThreatHuntRequest,
    BatchThreatHuntResponse
)
from ..service.threat_hunt_service import get_threat_hunt_service

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/threat-hunter",
    tags=["Threat Hunter"]
)


@router.post("/investigate", response_model=ThreatHuntResponse)
async def investigate_ioc(request: ThreatHuntRequest) -> ThreatHuntResponse:
    """
    Run threat hunting investigation for a single IOC.

    This endpoint uses AOL's 5-agent system to:
    1. Triage and assess IOC significance
    2. Perform deep malware behavioral analysis
    3. Correlate infrastructure and detect campaigns
    4. Orchestrate intelligence gathering
    5. Generate strategic campaign intelligence with hunt hypotheses

    Args:
        request: ThreatHuntRequest containing IOC and investigation type

    Returns:
        ThreatHuntResponse with detailed reports from each agent
    """
    try:
        logger.info(f"Received threat hunt request for IOC: {request.ioc}")

        # Get service
        service = get_threat_hunt_service()

        # Run investigation
        result = service.investigate_ioc(
            ioc=request.ioc,
            investigation_type=request.investigation_type
        )

        return ThreatHuntResponse(**result)

    except Exception as e:
        logger.error(f"Failed to investigate IOC {request.ioc}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Investigation failed: {str(e)}"
        )


@router.post("/batch-investigate", response_model=BatchThreatHuntResponse)
async def batch_investigate_iocs(
    request: BatchThreatHuntRequest
) -> BatchThreatHuntResponse:
    """
    Run threat hunting investigations for multiple IOCs.

    Processes each IOC independently and returns aggregated results.

    Args:
        request: BatchThreatHuntRequest containing list of IOCs

    Returns:
        BatchThreatHuntResponse with all investigation results
    """
    try:
        logger.info(f"Received batch threat hunt request for {len(request.iocs)} IOCs")

        if len(request.iocs) == 0:
            raise HTTPException(
                status_code=400,
                detail="No IOCs provided for investigation"
            )

        if len(request.iocs) > 50:
            raise HTTPException(
                status_code=400,
                detail="Maximum 50 IOCs allowed per batch request"
            )

        # Get service
        service = get_threat_hunt_service()

        # Run batch investigation
        result = service.batch_investigate(
            iocs=request.iocs,
            investigation_type=request.investigation_type
        )

        return BatchThreatHuntResponse(**result)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Batch investigation failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Batch investigation failed: {str(e)}"
        )


@router.get("/health")
async def health_check() -> Dict[str, str]:
    """
    Check if Threat Hunter service is healthy.

    Returns:
        Health status message
    """
    try:
        service = get_threat_hunt_service()
        return {
            "status": "healthy",
            "service": "AOL Threat Hunter",
            "agents": "5 agents ready (Triage, Malware, Infrastructure, Orchestrator, Campaign)"
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(
            status_code=503,
            detail=f"Service unavailable: {str(e)}"
        )


# Export router
threat_hunter_routes = router
