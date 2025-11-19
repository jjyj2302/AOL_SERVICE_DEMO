"""Service layer for AOL Threat Hunter."""
import os
import json
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

            # Generate structured final report summary
            final_report_summary = self._generate_final_summary(reports_dir, ioc)

            # Debug: Log the structure of final_report
            logger.info(f"Final report structure keys: {list(final_report_summary.keys())}")
            if 'full_analysis' in final_report_summary:
                logger.info(f"Full analysis keys: {list(final_report_summary['full_analysis'].keys())}")
                if 'campaign' in final_report_summary['full_analysis']:
                    campaign_keys = list(final_report_summary['full_analysis']['campaign'].keys())
                    logger.info(f"Campaign data keys: {campaign_keys}")

            return {
                'status': 'success',
                'ioc': ioc,
                'investigation_id': str(datetime.now().timestamp()),
                'final_report': final_report_summary,
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

    def _generate_final_summary(self, reports_dir: Path, ioc: str) -> Dict[str, Any]:
        """
        Generate a comprehensive final summary from all reports.

        Args:
            reports_dir: Directory containing report files
            ioc: The IOC being investigated

        Returns:
            Dictionary containing full analysis with visualization data
        """
        summary = {
            'ioc': ioc,
            'timestamp': datetime.now().isoformat(),
            'overall_threat_level': 'UNKNOWN',
            'full_analysis': {},
            'statistics': {
                'total_iocs_found': 0,
                'high_confidence_iocs': 0,
                'medium_confidence_iocs': 0,
                'low_confidence_iocs': 0,
                'detection_rate_average': 0,
                'malicious_infrastructure_count': 0,
                'total_mitre_techniques': 0,
                'campaign_clusters': 0
            },
            'threat_categories': [],
            'all_iocs': [],
            'mitre_tactics_summary': [],
            'infrastructure_targets': [],
            'recommendations': [],
            'visualization_data': {
                'ioc_confidence_distribution': {},
                'detection_rates': [],
                'threat_timeline': [],
                'mitre_coverage': {}
            }
        }

        try:
            # Load all JSON reports
            json_reports = {}
            json_files = {
                'triage': 'triage_assessment.json',
                'malware': 'malware_analysis.json',
                'infrastructure': 'infrastructure_analysis.json',
                'campaign': 'campaign_intelligence.json'
            }

            for key, filename in json_files.items():
                json_path = reports_dir / filename
                if json_path.exists():
                    try:
                        with open(json_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            json_reports[key] = data
                            summary['full_analysis'][key] = data
                    except Exception as e:
                        logger.warning(f"Failed to load {filename}: {e}")

            # Load orchestrator report for executive summary
            orchestrator_path = reports_dir / 'final_intelligence_report.md'
            if orchestrator_path.exists():
                try:
                    with open(orchestrator_path, 'r', encoding='utf-8') as f:
                        summary['executive_summary'] = f.read()
                except Exception as e:
                    logger.warning(f"Failed to load orchestrator report: {e}")

            # Process Triage Data
            if 'triage' in json_reports:
                triage = json_reports['triage']
                summary['overall_threat_level'] = triage.get('severity', 'UNKNOWN')
                if triage.get('is_malicious'):
                    summary['threat_categories'].append('악성 확인')

            # Process Malware Data
            if 'malware' in json_reports:
                malware = json_reports['malware']
                if malware.get('malware_family') or malware.get('malware_type'):
                    family_or_type = malware.get('malware_family') or malware.get('malware_type')
                    summary['threat_categories'].append(f"악성코드: {family_or_type}")

                targets = malware.get('infrastructure_targets', [])
                summary['infrastructure_targets'].extend(targets)
                summary['statistics']['malicious_infrastructure_count'] = len([t for t in targets if t.get('priority') == 'HIGH'])

            # Process Infrastructure Data
            if 'infrastructure' in json_reports:
                infra = json_reports['infrastructure']
                clusters = infra.get('campaign_clusters', [])
                summary['statistics']['campaign_clusters'] = len(clusters)

                additional_iocs = infra.get('additional_iocs', [])
                summary['all_iocs'].extend(additional_iocs)
                summary['statistics']['total_iocs_found'] += len(additional_iocs)

            # Process Campaign Data
            if 'campaign' in json_reports:
                campaign = json_reports['campaign']
                if campaign.get('campaign_name'):
                    summary['threat_categories'].append(campaign['campaign_name'])

                # Extract all IOCs
                extracted_iocs = campaign.get('extracted_iocs', [])
                summary['all_iocs'].extend(extracted_iocs)
                summary['statistics']['total_iocs_found'] += len(extracted_iocs)

                # IOC confidence distribution
                for ioc_item in extracted_iocs:
                    confidence = ioc_item.get('confidence', 'UNKNOWN')
                    if confidence == 'HIGH':
                        summary['statistics']['high_confidence_iocs'] += 1
                    elif confidence == 'MEDIUM':
                        summary['statistics']['medium_confidence_iocs'] += 1
                    elif confidence == 'LOW':
                        summary['statistics']['low_confidence_iocs'] += 1

                    summary['visualization_data']['ioc_confidence_distribution'][confidence] = \
                        summary['visualization_data']['ioc_confidence_distribution'].get(confidence, 0) + 1

                # Detection rates for visualization
                detection_rates = []
                for extracted_ioc in extracted_iocs:
                    detections = extracted_ioc.get('detections', '0/0')
                    if isinstance(detections, str) and '/' in detections:
                        try:
                            detected, total = map(int, detections.split('/'))
                            if total > 0:
                                rate = (detected / total) * 100
                                detection_rates.append(rate)
                                summary['visualization_data']['detection_rates'].append({
                                    'indicator': extracted_ioc.get('indicator', '')[:20],
                                    'rate': round(rate, 1),
                                    'detected': detected,
                                    'total': total
                                })
                        except:
                            pass

                if detection_rates:
                    summary['statistics']['detection_rate_average'] = round(sum(detection_rates) / len(detection_rates), 1)

                # MITRE ATT&CK data
                mitre_tactics = campaign.get('mitre_tactics', [])
                summary['mitre_tactics_summary'] = mitre_tactics
                total_techniques = sum(len(tactic.get('techniques', [])) for tactic in mitre_tactics)
                summary['statistics']['total_mitre_techniques'] = total_techniques

                # MITRE coverage for visualization
                for tactic in mitre_tactics:
                    tactic_name = tactic.get('tactic', 'Unknown')
                    technique_count = len(tactic.get('techniques', []))
                    summary['visualization_data']['mitre_coverage'][tactic_name] = technique_count

                # Recommendations
                recommended_actions = campaign.get('recommended_actions', [])
                summary['recommendations'] = recommended_actions

            # Generate concise text summary if orchestrator report not found
            if 'executive_summary' not in summary or not summary['executive_summary']:
                threat_level_emoji = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🟢',
                    'UNKNOWN': '⚪'
                }

                summary['executive_summary'] = (
                    f"{threat_level_emoji.get(summary['overall_threat_level'], '⚪')} "
                    f"위협 수준: {summary['overall_threat_level']}\n\n"
                    f"총 {summary['statistics']['total_iocs_found']}개의 IOC가 발견되었으며, "
                    f"{summary['statistics']['high_confidence_iocs']}개의 고신뢰도, "
                    f"{summary['statistics']['medium_confidence_iocs']}개의 중신뢰도, "
                    f"{summary['statistics']['low_confidence_iocs']}개의 저신뢰도 IOC가 포함됩니다.\n\n"
                    f"평균 탐지율: {summary['statistics']['detection_rate_average']}%\n"
                    f"악성 인프라: {summary['statistics']['malicious_infrastructure_count']}개\n"
                    f"MITRE ATT&CK 기법: {summary['statistics']['total_mitre_techniques']}개\n"
                    f"캠페인 클러스터: {summary['statistics']['campaign_clusters']}개"
                )

        except Exception as e:
            logger.error(f"Failed to generate final summary: {e}", exc_info=True)
            summary['executive_summary'] = f"IOC {ioc}에 대한 조사가 완료되었습니다."

        return summary


# Singleton instance
_threat_hunt_service: Optional[ThreatHuntService] = None


def get_threat_hunt_service() -> ThreatHuntService:
    """Get or create the ThreatHuntService singleton."""
    global _threat_hunt_service
    if _threat_hunt_service is None:
        _threat_hunt_service = ThreatHuntService()
    return _threat_hunt_service
