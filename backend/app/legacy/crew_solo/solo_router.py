"""Individual Agent Execution Router - Run agents independently"""
import logging
from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from pydantic import BaseModel

from .crew import ThreatHuntingCrew

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/crew-solo",
    tags=["Crew Solo (Individual Agents)"]
)


class AgentRequest(BaseModel):
    """Request model for individual agent execution."""
    ioc: str


@router.post("/triage")
async def run_triage_agent(request: AgentRequest) -> Dict[str, Any]:
    """
    Run ONLY Triage Specialist agent - completely independent

    Returns TriageOutput with initial IOC assessment and priority discoveries.
    """
    try:
        logger.info(f"[TRIAGE SOLO] Request for IOC: {request.ioc}")

        crew = ThreatHuntingCrew()
        result = crew.run_triage_only(request.ioc)

        logger.info(f"[TRIAGE SOLO] Completed for IOC: {request.ioc}")

        return result

    except Exception as e:
        logger.error(f"[TRIAGE SOLO] Failed for {request.ioc}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Triage analysis failed: {str(e)}"
        )


@router.post("/malware")
async def run_malware_agent(request: AgentRequest) -> Dict[str, Any]:
    """
    Run ONLY Malware Specialist agent - completely independent

    Returns MalwareAnalysisOutput with behavioral analysis and infrastructure targets.
    """
    try:
        logger.info(f"[MALWARE SOLO] Request for IOC: {request.ioc}")

        crew = ThreatHuntingCrew()
        result = crew.run_malware_only(request.ioc)

        logger.info(f"[MALWARE SOLO] Completed for IOC: {request.ioc}")

        return result

    except Exception as e:
        logger.error(f"[MALWARE SOLO] Failed for {request.ioc}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Malware analysis failed: {str(e)}"
        )


@router.post("/infrastructure")
async def run_infrastructure_agent(request: AgentRequest) -> Dict[str, Any]:
    """
    Run ONLY Infrastructure Hunter agent - completely independent

    Returns InfrastructureCorrelationOutput with campaign clusters and additional IOCs.
    """
    try:
        logger.info(f"[INFRASTRUCTURE SOLO] Request for IOC: {request.ioc}")

        crew = ThreatHuntingCrew()
        result = crew.run_infrastructure_only(request.ioc)

        logger.info(f"[INFRASTRUCTURE SOLO] Completed for IOC: {request.ioc}")

        return result

    except Exception as e:
        logger.error(f"[INFRASTRUCTURE SOLO] Failed for {request.ioc}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Infrastructure analysis failed: {str(e)}"
        )


@router.post("/campaign")
async def run_campaign_agent(request: AgentRequest) -> Dict[str, Any]:
    """
    Run ONLY Campaign Analyst agent - completely independent

    Returns CampaignIntelligenceOutput with strategic assessment and hunt hypotheses.
    """
    try:
        logger.info(f"[CAMPAIGN SOLO] Request for IOC: {request.ioc}")

        crew = ThreatHuntingCrew()
        result = crew.run_campaign_only(request.ioc)

        logger.info(f"[CAMPAIGN SOLO] Completed for IOC: {request.ioc}")

        return result

    except Exception as e:
        logger.error(f"[CAMPAIGN SOLO] Failed for {request.ioc}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Campaign analysis failed: {str(e)}"
        )


@router.get("/health")
async def health_check() -> Dict[str, str]:
    """Health check for crew solo endpoints."""
    return {
        "status": "healthy",
        "service": "AOL Crew Solo (Individual Agents)",
        "note": "Run each threat hunting agent independently"
    }


@router.get("/agents")
async def list_agents() -> Dict[str, Any]:
    """List available individual agents and their capabilities."""
    return {
        "agents": [
            {
                "name": "triage",
                "endpoint": "/api/crew-solo/triage",
                "description": "IOC Triage and Priority Assessment",
                "output": "TriageOutput",
                "tools": ["VirusTotal"],
                "independent": True
            },
            {
                "name": "malware",
                "endpoint": "/api/crew-solo/malware",
                "description": "Malware Behavioral Analysis",
                "output": "MalwareAnalysisOutput",
                "tools": ["VirusTotal"],
                "independent": True
            },
            {
                "name": "infrastructure",
                "endpoint": "/api/crew-solo/infrastructure",
                "description": "Infrastructure Campaign Correlation",
                "output": "InfrastructureCorrelationOutput",
                "tools": ["URLScan"],
                "independent": True
            },
            {
                "name": "campaign",
                "endpoint": "/api/crew-solo/campaign",
                "description": "Strategic Campaign Intelligence",
                "output": "CampaignIntelligenceOutput",
                "tools": [],
                "independent": True
            }
        ]
    }
