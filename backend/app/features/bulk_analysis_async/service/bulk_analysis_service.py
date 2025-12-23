"""
Bulk Analysis Service - SSE Streaming + Async Processing

Provides streaming results as each agent completes analysis
"""

import asyncio
import json
import logging
from typing import List, Dict, Any, AsyncGenerator, Optional
from datetime import datetime

from ..crew import BulkAnalysisOrchestrator

logger = logging.getLogger(__name__)


class BulkAnalysisService:
    """Service for bulk IOC analysis with SSE streaming support"""

    def __init__(self):
        self.orchestrator = BulkAnalysisOrchestrator()

    async def stream_single_ioc_analysis(
        self,
        ioc: str,
        selected_agents: Optional[List[str]] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Stream analysis results for a single IOC as each agent completes

        Yields results in SSE-friendly format
        """
        if selected_agents is None:
            selected_agents = ['triage', 'malware', 'infrastructure', 'campaign']

        tasks = []
        for agent_type in selected_agents:
            task = asyncio.create_task(
                self.orchestrator.analyze_single_ioc_single_agent(ioc, agent_type)
            )
            tasks.append((agent_type, task))

        # Yield results as they complete
        for agent_type, task in tasks:
            try:
                result = await task
                yield {
                    'event': 'agent_complete',
                    'ioc': ioc,
                    'agent': agent_type,
                    'status': result.get('status', 'unknown'),
                    'data': result
                }
            except Exception as e:
                logger.error(f"Error in {agent_type} analysis for {ioc}: {e}")
                yield {
                    'event': 'agent_error',
                    'ioc': ioc,
                    'agent': agent_type,
                    'error': str(e)
                }

    async def stream_bulk_analysis(
        self,
        iocs: List[str],
        selected_agents: Optional[List[str]] = None,
        include_aggregation: bool = True
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Stream bulk analysis results as they complete

        Phase 1: Stream individual agent results
        Phase 2: Stream aggregation result (if enabled)
        """
        if selected_agents is None:
            selected_agents = ['triage', 'malware', 'infrastructure', 'campaign']

        # Emit start event
        yield {
            'event': 'analysis_start',
            'total_iocs': len(iocs),
            'agents': selected_agents,
            'timestamp': datetime.utcnow().isoformat()
        }

        # Create all tasks upfront
        all_tasks = []
        for ioc in iocs:
            for agent_type in selected_agents:
                task = asyncio.create_task(
                    self.orchestrator.analyze_single_ioc_single_agent(ioc, agent_type)
                )
                all_tasks.append(task)

        # Track results for aggregation
        phase1_results = {}

        # Yield results as they complete using as_completed
        completed_count = 0
        total_tasks = len(all_tasks)

        for coro in asyncio.as_completed(all_tasks):
            try:
                result = await coro
                completed_count += 1

                ioc = result.get('ioc')
                agent = result.get('agent')

                # Store for aggregation
                if ioc not in phase1_results:
                    phase1_results[ioc] = {}
                phase1_results[ioc][agent] = result

                # Yield individual result
                yield {
                    'event': 'agent_complete',
                    'ioc': ioc,
                    'agent': agent,
                    'status': result.get('status', 'unknown'),
                    'data': result,
                    'progress': {
                        'completed': completed_count,
                        'total': total_tasks,
                        'percentage': round((completed_count / total_tasks) * 100, 1)
                    }
                }
            except Exception as e:
                completed_count += 1
                logger.error(f"Error in bulk analysis task: {e}")
                yield {
                    'event': 'agent_error',
                    'error': str(e),
                    'progress': {
                        'completed': completed_count,
                        'total': total_tasks,
                        'percentage': round((completed_count / total_tasks) * 100, 1)
                    }
                }

        # Phase 1 complete event
        yield {
            'event': 'phase1_complete',
            'total_iocs': len(iocs),
            'total_analyses': completed_count,
            'timestamp': datetime.utcnow().isoformat()
        }

        # Phase 2: Aggregation
        if include_aggregation and len(iocs) > 1:
            yield {
                'event': 'aggregation_start',
                'timestamp': datetime.utcnow().isoformat()
            }

            try:
                # Prepare results for aggregation
                organized_results = [
                    {'ioc': ioc, 'analyses': analyses}
                    for ioc, analyses in phase1_results.items()
                ]

                aggregation_result = await self.orchestrator.phase2_aggregation(
                    organized_results
                )

                yield {
                    'event': 'aggregation_complete',
                    'status': aggregation_result.get('status'),
                    'data': aggregation_result,
                    'timestamp': datetime.utcnow().isoformat()
                }
            except Exception as e:
                logger.error(f"Error in aggregation: {e}")
                yield {
                    'event': 'aggregation_error',
                    'error': str(e),
                    'timestamp': datetime.utcnow().isoformat()
                }

        # Final complete event
        yield {
            'event': 'analysis_complete',
            'total_iocs': len(iocs),
            'total_analyses': completed_count,
            'timestamp': datetime.utcnow().isoformat()
        }

    async def analyze_bulk_sync(
        self,
        iocs: List[str],
        selected_agents: Optional[List[str]] = None,
        include_aggregation: bool = True
    ) -> Dict[str, Any]:
        """
        Non-streaming bulk analysis - returns all results at once

        Use this for smaller batches or when streaming is not needed
        """
        return await self.orchestrator.full_bulk_analysis(
            iocs=iocs,
            selected_agents=selected_agents,
            skip_aggregation=not include_aggregation
        )


# Singleton service instance
_service_instance = None


def get_bulk_analysis_service() -> BulkAnalysisService:
    """Get or create the bulk analysis service singleton"""
    global _service_instance
    if _service_instance is None:
        _service_instance = BulkAnalysisService()
    return _service_instance
