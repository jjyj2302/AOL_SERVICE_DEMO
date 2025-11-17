"""Service layer for AOL Threat Hunter."""
import os
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path

from ..crew import ThreatHuntingCrew

logger = logging.getLogger(__name__)


class ThreatHuntService:
    """Service for running threat hunting investigations."""

    def __init__(self):
        """Initialize threat hunting service."""
        self.crew = None
        self._initialize_crew()

    def _initialize_crew(self):
        """Initialize the ThreatHuntingCrew."""
        try:
            logger.info("Initializing AOL Threat Hunting Crew...")
            self.crew = ThreatHuntingCrew()
            logger.info("Threat Hunting Crew initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Threat Hunting Crew: {e}")
            raise

    def investigate_ioc(
        self,
        ioc: str,
        investigation_type: str = "comprehensive"
    ) -> Dict[str, Any]:
        """
        Run threat hunting investigation for a single IOC.

        Args:
            ioc: The indicator of compromise to investigate
            investigation_type: Type of investigation (comprehensive, malware, infrastructure, campaign)

        Returns:
            Dictionary containing investigation results and reports
        """
        try:
            logger.info(f"Starting threat hunting investigation for IOC: {ioc}")

            # Prepare inputs
            inputs = {
                'ioc': ioc,
                'investigation_timestamp': datetime.now().isoformat(),
                'investigation_type': investigation_type
            }

            # Run the crew
            result = self.crew.crew().kickoff(inputs=inputs)

            # Read generated reports
            reports_dir = Path("reports")
            reports = {}

            if reports_dir.exists():
                report_files = {
                    'triage_report': 'triage_assessment.md',
                    'malware_report': 'malware_analysis.md',
                    'infrastructure_report': 'infrastructure_analysis.md',
                    'orchestrator_report': 'final_intelligence_report.md',
                    'campaign_report': 'campaign_intelligence.md'
                }

                for key, filename in report_files.items():
                    report_path = reports_dir / filename
                    if report_path.exists():
                        try:
                            with open(report_path, 'r', encoding='utf-8') as f:
                                reports[key] = f.read()
                        except Exception as e:
                            logger.warning(f"Failed to read {filename}: {e}")
                            reports[key] = None
                    else:
                        reports[key] = None

            return {
                'status': 'success',
                'ioc': ioc,
                'investigation_id': str(datetime.now().timestamp()),
                'final_report': str(result),
                **reports
            }

        except Exception as e:
            logger.error(f"Investigation failed for IOC {ioc}: {e}", exc_info=True)
            return {
                'status': 'failed',
                'ioc': ioc,
                'error_message': str(e),
                'triage_report': None,
                'malware_report': None,
                'infrastructure_report': None,
                'orchestrator_report': None,
                'campaign_report': None,
                'final_report': None
            }

    def batch_investigate(
        self,
        iocs: list,
        investigation_type: str = "comprehensive"
    ) -> Dict[str, Any]:
        """
        Run investigations for multiple IOCs.

        Args:
            iocs: List of IOCs to investigate
            investigation_type: Type of investigation

        Returns:
            Dictionary containing batch investigation results
        """
        logger.info(f"Starting batch investigation for {len(iocs)} IOCs")

        results = []
        successful = 0
        failed = 0

        for ioc in iocs:
            try:
                result = self.investigate_ioc(ioc, investigation_type)
                results.append(result)

                if result['status'] == 'success':
                    successful += 1
                else:
                    failed += 1

            except Exception as e:
                logger.error(f"Failed to investigate {ioc}: {e}")
                results.append({
                    'status': 'failed',
                    'ioc': ioc,
                    'error_message': str(e)
                })
                failed += 1

        return {
            'total': len(iocs),
            'successful': successful,
            'failed': failed,
            'results': results
        }


# Singleton instance
_threat_hunt_service: Optional[ThreatHuntService] = None


def get_threat_hunt_service() -> ThreatHuntService:
    """Get or create the ThreatHuntService singleton."""
    global _threat_hunt_service
    if _threat_hunt_service is None:
        _threat_hunt_service = ThreatHuntService()
    return _threat_hunt_service
