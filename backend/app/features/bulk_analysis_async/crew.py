#!/usr/bin/env python3
"""
Bulk Analysis Async Crew - Parallel IOC Analysis with Aggregation

Phase 1: Multiple IOCs analyzed in parallel (4 Worker Agents per IOC, No Manager)
Phase 2: Aggregation of all results into comprehensive report

Uses CrewAI's kickoff_async() for parallel execution
"""

import os
import asyncio
from typing import List, Dict, Any, Optional
from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from crewai.agents.agent_builder.base_agent import BaseAgent

from app.core.settings.api_keys.cache import APIKeyCache

# Reuse tools from deep_analysis
from app.features.deep_analysis.tools.virustotal_tool import VirusTotalTool
from app.features.deep_analysis.tools.urlscan_tool import URLScanTool

# Reuse Pydantic schemas from deep_analysis
from app.features.deep_analysis.schemas.task_outputs import (
    TriageOutput,
    MalwareAnalysisOutput,
    InfrastructureCorrelationOutput,
    CampaignIntelligenceOutput
)


@CrewBase
class BulkTriageCrew:
    """Single-agent Crew for Triage analysis - runs independently"""

    agents_config = 'config/bulk_agents.yaml'
    tasks_config = 'config/bulk_tasks.yaml'

    def __init__(self):
        self._setup_api_keys()
        self.virustotal_tool = VirusTotalTool()

    def _setup_api_keys(self):
        if not os.getenv('OPENAI_API_KEY'):
            cache = APIKeyCache.get_instance()
            openai_key_data = cache.get_key('openai')
            if openai_key_data and openai_key_data.get('key'):
                os.environ['OPENAI_API_KEY'] = openai_key_data.get('key')

    @agent
    def triage_specialist(self) -> Agent:
        return Agent(
            config=self.agents_config['triage_specialist'],
            tools=[self.virustotal_tool],
            allow_delegation=False
        )

    @task
    def triage_task(self) -> Task:
        return Task(
            config=self.tasks_config['bulk_triage_assessment'],
            agent=self.triage_specialist(),
            output_pydantic=TriageOutput
        )

    @crew
    def crew(self) -> Crew:
        return Crew(
            agents=[self.triage_specialist()],
            tasks=[self.triage_task()],
            process=Process.sequential,
            verbose=True
        )


@CrewBase
class BulkMalwareCrew:
    """Single-agent Crew for Malware analysis - runs independently"""

    agents_config = 'config/bulk_agents.yaml'
    tasks_config = 'config/bulk_tasks.yaml'

    def __init__(self):
        self._setup_api_keys()
        self.virustotal_tool = VirusTotalTool()

    def _setup_api_keys(self):
        if not os.getenv('OPENAI_API_KEY'):
            cache = APIKeyCache.get_instance()
            openai_key_data = cache.get_key('openai')
            if openai_key_data and openai_key_data.get('key'):
                os.environ['OPENAI_API_KEY'] = openai_key_data.get('key')

    @agent
    def malware_specialist(self) -> Agent:
        return Agent(
            config=self.agents_config['malware_analysis_specialist'],
            tools=[self.virustotal_tool],
            allow_delegation=False
        )

    @task
    def malware_task(self) -> Task:
        return Task(
            config=self.tasks_config['bulk_malware_analysis'],
            agent=self.malware_specialist(),
            output_pydantic=MalwareAnalysisOutput
        )

    @crew
    def crew(self) -> Crew:
        return Crew(
            agents=[self.malware_specialist()],
            tasks=[self.malware_task()],
            process=Process.sequential,
            verbose=True
        )


@CrewBase
class BulkInfrastructureCrew:
    """Single-agent Crew for Infrastructure analysis - runs independently"""

    agents_config = 'config/bulk_agents.yaml'
    tasks_config = 'config/bulk_tasks.yaml'

    def __init__(self):
        self._setup_api_keys()
        self.urlscan_tool = URLScanTool()

    def _setup_api_keys(self):
        if not os.getenv('OPENAI_API_KEY'):
            cache = APIKeyCache.get_instance()
            openai_key_data = cache.get_key('openai')
            if openai_key_data and openai_key_data.get('key'):
                os.environ['OPENAI_API_KEY'] = openai_key_data.get('key')

    @agent
    def infrastructure_specialist(self) -> Agent:
        return Agent(
            config=self.agents_config['infrastructure_correlation_specialist'],
            tools=[self.urlscan_tool],
            allow_delegation=False
        )

    @task
    def infrastructure_task(self) -> Task:
        return Task(
            config=self.tasks_config['bulk_infrastructure_correlation'],
            agent=self.infrastructure_specialist(),
            output_pydantic=InfrastructureCorrelationOutput
        )

    @crew
    def crew(self) -> Crew:
        return Crew(
            agents=[self.infrastructure_specialist()],
            tasks=[self.infrastructure_task()],
            process=Process.sequential,
            verbose=True
        )


@CrewBase
class BulkCampaignCrew:
    """Single-agent Crew for Campaign analysis - runs independently"""

    agents_config = 'config/bulk_agents.yaml'
    tasks_config = 'config/bulk_tasks.yaml'

    def __init__(self):
        self._setup_api_keys()

    def _setup_api_keys(self):
        if not os.getenv('OPENAI_API_KEY'):
            cache = APIKeyCache.get_instance()
            openai_key_data = cache.get_key('openai')
            if openai_key_data and openai_key_data.get('key'):
                os.environ['OPENAI_API_KEY'] = openai_key_data.get('key')

    @agent
    def campaign_specialist(self) -> Agent:
        return Agent(
            config=self.agents_config['campaign_intelligence_analyst'],
            allow_delegation=False
        )

    @task
    def campaign_task(self) -> Task:
        return Task(
            config=self.tasks_config['bulk_campaign_intelligence'],
            agent=self.campaign_specialist(),
            output_pydantic=CampaignIntelligenceOutput
        )

    @crew
    def crew(self) -> Crew:
        return Crew(
            agents=[self.campaign_specialist()],
            tasks=[self.campaign_task()],
            process=Process.sequential,
            verbose=True
        )


@CrewBase
class AggregatorCrew:
    """Aggregator Crew for Phase 2 - synthesizes all results"""

    agents_config = 'config/bulk_agents.yaml'
    tasks_config = 'config/bulk_tasks.yaml'

    def __init__(self):
        self._setup_api_keys()

    def _setup_api_keys(self):
        if not os.getenv('OPENAI_API_KEY'):
            cache = APIKeyCache.get_instance()
            openai_key_data = cache.get_key('openai')
            if openai_key_data and openai_key_data.get('key'):
                os.environ['OPENAI_API_KEY'] = openai_key_data.get('key')

    @agent
    def aggregator_analyst(self) -> Agent:
        return Agent(
            config=self.agents_config['aggregator_analyst'],
            allow_delegation=False
        )

    @task
    def aggregation_task(self) -> Task:
        return Task(
            config=self.tasks_config['bulk_aggregation'],
            agent=self.aggregator_analyst()
        )

    @crew
    def crew(self) -> Crew:
        return Crew(
            agents=[self.aggregator_analyst()],
            tasks=[self.aggregation_task()],
            process=Process.sequential,
            verbose=True
        )


class BulkAnalysisOrchestrator:
    """
    Main orchestrator for bulk IOC analysis

    Phase 1: Parallel analysis of all IOCs with 4 agents each
    Phase 2: Aggregation of all results
    """

    def __init__(self):
        # Initialize single-agent crews
        self.triage_crew = BulkTriageCrew()
        self.malware_crew = BulkMalwareCrew()
        self.infrastructure_crew = BulkInfrastructureCrew()
        self.campaign_crew = BulkCampaignCrew()
        self.aggregator_crew = AggregatorCrew()

    async def analyze_single_ioc_single_agent(
        self,
        ioc: str,
        agent_type: str
    ) -> Dict[str, Any]:
        """Run a single agent analysis for a single IOC"""
        try:
            if agent_type == 'triage':
                crew = self.triage_crew.crew()
            elif agent_type == 'malware':
                crew = self.malware_crew.crew()
            elif agent_type == 'infrastructure':
                crew = self.infrastructure_crew.crew()
            elif agent_type == 'campaign':
                crew = self.campaign_crew.crew()
            else:
                raise ValueError(f"Unknown agent type: {agent_type}")

            result = await crew.kickoff_async(inputs={'ioc': ioc})

            return {
                'status': 'completed',
                'ioc': ioc,
                'agent': agent_type,
                'result': result.raw if hasattr(result, 'raw') else str(result)
            }
        except Exception as e:
            return {
                'status': 'error',
                'ioc': ioc,
                'agent': agent_type,
                'error': str(e)
            }

    async def analyze_single_ioc_all_agents(self, ioc: str) -> Dict[str, Any]:
        """
        Run all 4 agents in parallel for a single IOC
        Returns results from all agents
        """
        tasks = [
            self.analyze_single_ioc_single_agent(ioc, 'triage'),
            self.analyze_single_ioc_single_agent(ioc, 'malware'),
            self.analyze_single_ioc_single_agent(ioc, 'infrastructure'),
            self.analyze_single_ioc_single_agent(ioc, 'campaign'),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        return {
            'ioc': ioc,
            'triage': results[0] if not isinstance(results[0], Exception) else {'error': str(results[0])},
            'malware': results[1] if not isinstance(results[1], Exception) else {'error': str(results[1])},
            'infrastructure': results[2] if not isinstance(results[2], Exception) else {'error': str(results[2])},
            'campaign': results[3] if not isinstance(results[3], Exception) else {'error': str(results[3])},
        }

    async def phase1_parallel_analysis(
        self,
        iocs: List[str],
        selected_agents: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Phase 1: Analyze all IOCs in parallel

        Args:
            iocs: List of IOCs to analyze
            selected_agents: Optional list of agents to use (default: all 4)

        Returns:
            List of results for each IOC
        """
        if selected_agents is None:
            selected_agents = ['triage', 'malware', 'infrastructure', 'campaign']

        all_tasks = []
        for ioc in iocs:
            for agent_type in selected_agents:
                all_tasks.append(
                    self.analyze_single_ioc_single_agent(ioc, agent_type)
                )

        # Execute all tasks in parallel
        results = await asyncio.gather(*all_tasks, return_exceptions=True)

        # Organize results by IOC
        organized_results = {}
        for result in results:
            if isinstance(result, Exception):
                continue
            ioc = result.get('ioc')
            agent = result.get('agent')
            if ioc not in organized_results:
                organized_results[ioc] = {}
            organized_results[ioc][agent] = result

        return [
            {'ioc': ioc, 'analyses': analyses}
            for ioc, analyses in organized_results.items()
        ]

    async def phase2_aggregation(
        self,
        phase1_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Phase 2: Aggregate all Phase 1 results into comprehensive report
        """
        # Prepare aggregation input
        all_triage = []
        all_malware = []
        all_infrastructure = []
        all_campaign = []

        for ioc_result in phase1_results:
            analyses = ioc_result.get('analyses', {})
            if 'triage' in analyses:
                all_triage.append(analyses['triage'])
            if 'malware' in analyses:
                all_malware.append(analyses['malware'])
            if 'infrastructure' in analyses:
                all_infrastructure.append(analyses['infrastructure'])
            if 'campaign' in analyses:
                all_campaign.append(analyses['campaign'])

        aggregation_input = {
            'all_triage_results': str(all_triage),
            'all_malware_results': str(all_malware),
            'all_infrastructure_results': str(all_infrastructure),
            'all_campaign_results': str(all_campaign),
            'total_iocs_analyzed': len(phase1_results)
        }

        try:
            result = await self.aggregator_crew.crew().kickoff_async(
                inputs=aggregation_input
            )
            return {
                'status': 'completed',
                'aggregated_report': result.raw if hasattr(result, 'raw') else str(result)
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    async def full_bulk_analysis(
        self,
        iocs: List[str],
        selected_agents: Optional[List[str]] = None,
        skip_aggregation: bool = False
    ) -> Dict[str, Any]:
        """
        Complete bulk analysis pipeline

        Args:
            iocs: List of IOCs to analyze
            selected_agents: Optional list of agents to use
            skip_aggregation: If True, skip Phase 2 aggregation

        Returns:
            Complete analysis results including Phase 1 and Phase 2
        """
        print(f"🚀 Starting bulk analysis for {len(iocs)} IOCs")

        # Phase 1: Parallel analysis
        print("📊 Phase 1: Parallel IOC Analysis")
        phase1_results = await self.phase1_parallel_analysis(iocs, selected_agents)

        result = {
            'total_iocs': len(iocs),
            'phase1_results': phase1_results
        }

        # Phase 2: Aggregation (optional)
        if not skip_aggregation and len(iocs) > 1:
            print("🔗 Phase 2: Aggregating Results")
            phase2_result = await self.phase2_aggregation(phase1_results)
            result['phase2_aggregation'] = phase2_result

        print("✅ Bulk analysis completed")
        return result


# Convenience function for quick bulk analysis
async def analyze_iocs_bulk(
    iocs: List[str],
    agents: Optional[List[str]] = None,
    skip_aggregation: bool = False
) -> Dict[str, Any]:
    """
    Convenience function to run bulk IOC analysis

    Args:
        iocs: List of IOCs to analyze
        agents: Optional list of agents ['triage', 'malware', 'infrastructure', 'campaign']
        skip_aggregation: Skip the aggregation phase

    Returns:
        Analysis results
    """
    orchestrator = BulkAnalysisOrchestrator()
    return await orchestrator.full_bulk_analysis(iocs, agents, skip_aggregation)
