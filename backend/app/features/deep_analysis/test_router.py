"""Temporary test router for threat_hunter_copy with Pydantic outputs."""
import logging
from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from pydantic import BaseModel

from .crew import ThreatHuntingCrew

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/threat-hunter-test",
    tags=["Threat Hunter Test (Pydantic)"]
)


class TestRequest(BaseModel):
    """Simple test request."""
    ioc: str


@router.post("/investigate")
async def test_investigate_ioc(request: TestRequest) -> Dict[str, Any]:
    """
    Test endpoint for Pydantic-enabled threat hunting.

    This uses threat_hunter_copy with structured JSON outputs.
    """
    try:
        logger.info(f"[TEST] Received investigation request for IOC: {request.ioc}")

        # Initialize crew
        crew = ThreatHuntingCrew()

        # Run investigation
        result = crew.investigate_ioc(request.ioc)

        logger.info(f"[TEST] Investigation completed for IOC: {request.ioc}")

        return result

    except Exception as e:
        logger.error(f"[TEST] Investigation failed for {request.ioc}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Investigation failed: {str(e)}"
        )


@router.get("/health")
async def health_check() -> Dict[str, str]:
    """Health check for test endpoint."""
    return {
        "status": "healthy",
        "service": "AOL Threat Hunter Test (Pydantic)",
        "note": "This is a temporary test endpoint for threat_hunter_copy"
    }
