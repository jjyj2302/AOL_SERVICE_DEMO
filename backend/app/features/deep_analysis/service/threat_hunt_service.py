"""Service layer for threat hunting investigations using CrewAI."""
import logging
import json
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
from functools import lru_cache

from ..crew import ThreatHuntingCrew
from app.core.database import SessionLocal
from app.features.history.crud import history_crud

logger = logging.getLogger(__name__)


@lru_cache()
def get_threat_hunt_service() -> 'ThreatHuntService':
    """
    Get singleton instance of ThreatHuntService.

    Returns:
        ThreatHuntService: Singleton service instance
    """
    return ThreatHuntService()


class ThreatHuntService:
    """
    Service for running threat hunting investigations.

    This service uses the ThreatHuntingCrew to perform comprehensive
    IOC investigations and returns structured Pydantic JSON outputs.
    """

    def __init__(self):
        """Initialize the threat hunt service with a crew instance."""
        self.crew = ThreatHuntingCrew()
        logger.info("ThreatHuntService initialized with Pydantic-enabled crew")

    def _save_to_database(
        self,
        ioc: str,
        triage_report: Optional[str] = None,
        malware_report: Optional[str] = None,
        infrastructure_report: Optional[str] = None,
        campaign_report: Optional[str] = None,
        final_report: Optional[str] = None,
        uploaded_file_id: Optional[int] = None
    ) -> Optional[int]:
        """
        Save investigation results to database.

        Returns:
            Session ID if successful, None otherwise
        """
        db = SessionLocal()
        try:
            # Create analysis session
            session = history_crud.create_session(
                db=db,
                source_type='deep_analysis',
                session_name=f"Deep Analysis: {ioc}",
                uploaded_file_id=uploaded_file_id,
                total_iocs=1
            )

            # Parse reports from JSON strings
            def parse_json_safe(json_str: Optional[str]) -> Optional[dict]:
                if not json_str:
                    return None
                try:
                    return json.loads(json_str)
                except (json.JSONDecodeError, TypeError):
                    return {'raw': json_str}

            # Detect IOC type
            ioc_type = self._detect_ioc_type(ioc)

            # Extract threat level from triage report
            threat_level = None
            triage_data = parse_json_safe(triage_report)
            if triage_data and isinstance(triage_data, dict):
                threat_level = triage_data.get('threat_level') or triage_data.get('overall_threat_level')

            # Create IOC analysis record
            history_crud.create_ioc_analysis(
                db=db,
                session_id=session.id,
                ioc_value=ioc,
                ioc_type=ioc_type,
                triage_result=parse_json_safe(triage_report),
                malware_result=parse_json_safe(malware_report),
                infrastructure_result=parse_json_safe(infrastructure_report),
                campaign_result=parse_json_safe(campaign_report),
                overall_threat_level=threat_level
            )

            # Create aggregation result (final report)
            if final_report:
                history_crud.create_aggregation(
                    db=db,
                    session_id=session.id,
                    aggregated_report=parse_json_safe(final_report) or {'raw': final_report}
                )

            # Update session status
            history_crud.update_session_status(db, session.id, 'completed', total_iocs=1)

            logger.info(f"Saved investigation results to database. Session ID: {session.id}")
            return session.id

        except Exception as e:
            logger.error(f"Failed to save to database: {e}", exc_info=True)
            return None
        finally:
            db.close()

    def _detect_ioc_type(self, ioc: str) -> str:
        """Detect IOC type based on format."""
        import re

        # IP address pattern
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if re.match(ip_pattern, ioc):
            return 'ip'

        # MD5 hash (32 hex chars)
        if re.match(r'^[a-fA-F0-9]{32}$', ioc):
            return 'md5'

        # SHA1 hash (40 hex chars)
        if re.match(r'^[a-fA-F0-9]{40}$', ioc):
            return 'sha1'

        # SHA256 hash (64 hex chars)
        if re.match(r'^[a-fA-F0-9]{64}$', ioc):
            return 'sha256'

        # URL pattern
        if ioc.startswith(('http://', 'https://')):
            return 'url'

        # Email pattern
        if '@' in ioc and '.' in ioc:
            return 'email'

        # Domain (default)
        return 'domain'

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
            Dictionary containing investigation results with Pydantic JSON outputs
        """
        try:
            logger.info(f"Starting threat hunting investigation for IOC: {ioc}")

            # Run the crew investigation
            crew_result = self.crew.investigate_ioc(ioc)

            # Extract Pydantic outputs from tasks_output
            reports = {}

            if 'result' in crew_result and hasattr(crew_result['result'], 'tasks_output'):
                tasks_output = crew_result['result'].tasks_output

                # Map task names to report keys (must match crew.py method names)
                task_mapping = {
                    'initial_assessment': 'triage_report',
                    'malware_analysis': 'malware_report',
                    'infrastructure_correlation': 'infrastructure_report',
                    'campaign_synthesis': 'campaign_report'
                }

                for task in tasks_output:
                    task_name = task.name if hasattr(task, 'name') else None
                    if task_name in task_mapping:
                        report_key = task_mapping[task_name]
                        # Store raw string directly (like AI Agents pattern)
                        if hasattr(task, 'raw') and task.raw:
                            reports[report_key] = task.raw
                            logger.info(f"Stored raw output for {task_name}")
                        else:
                            reports[report_key] = None
                            logger.warning(f"No raw output found for {task_name}")

            # Extract final report (campaign synthesis) - store as raw string
            final_report = None
            if 'result' in crew_result and hasattr(crew_result['result'], 'raw'):
                final_report = crew_result['result'].raw
                logger.info("Stored final report as raw string")

            logger.info(f"Investigation completed for IOC: {ioc}")

            # Save to database
            session_id = self._save_to_database(
                ioc=ioc,
                triage_report=reports.get('triage_report'),
                malware_report=reports.get('malware_report'),
                infrastructure_report=reports.get('infrastructure_report'),
                campaign_report=reports.get('campaign_report'),
                final_report=final_report
            )

            return {
                'status': 'success',
                'ioc': ioc,
                'investigation_type': investigation_type,
                'session_id': session_id,
                **reports,
                'final_report': final_report
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

        logger.info(f"Batch investigation completed. Success: {successful}, Failed: {failed}")

        return {
            'status': 'completed',
            'total': len(iocs),
            'successful': successful,
            'failed': failed,
            'results': results
        }

    async def batch_investigate_async(
        self,
        iocs: List[str],
        investigation_type: str = "comprehensive"
    ) -> Dict[str, Any]:
        """
        Run investigations for multiple IOCs in parallel.

        Args:
            iocs: List of IOCs to investigate
            investigation_type: Type of investigation

        Returns:
            Dictionary containing batch investigation results
        """
        logger.info(f"Starting parallel batch investigation for {len(iocs)} IOCs")

        # Create async tasks for all IOCs
        tasks = [
            asyncio.to_thread(self.investigate_ioc, ioc, investigation_type)
            for ioc in iocs
        ]

        # Execute all tasks in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results and handle exceptions
        processed_results = []
        successful = 0
        failed = 0

        for ioc, result in zip(iocs, results):
            if isinstance(result, Exception):
                logger.error(f"Failed to investigate {ioc}: {result}")
                processed_results.append({
                    'status': 'failed',
                    'ioc': ioc,
                    'error_message': str(result)
                })
                failed += 1
            else:
                processed_results.append(result)
                if result.get('status') == 'success':
                    successful += 1
                else:
                    failed += 1

        logger.info(f"Parallel batch investigation completed. Success: {successful}, Failed: {failed}")

        return {
            'status': 'completed',
            'total': len(iocs),
            'successful': successful,
            'failed': failed,
            'results': processed_results
        }
