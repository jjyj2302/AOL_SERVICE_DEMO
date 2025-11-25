#!/usr/bin/env python3
"""
Smart Threat Hunting Crew - Clean CrewAI Implementation
Following official CrewAI patterns for simplicity and maintainability
"""

import os
from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from crewai.agents.agent_builder.base_agent import BaseAgent
from typing import List
from langchain_openai import ChatOpenAI
from app.core.settings.api_keys.cache import APIKeyCache

# Import your custom tools
from .tools.virustotal_tool import VirusTotalTool
from .tools.urlscan_tool import URLScanTool

# Import Pydantic schemas for structured outputs
from .schemas.task_outputs import (
    TriageOutput,
    MalwareAnalysisOutput,
    InfrastructureCorrelationOutput,
    CampaignIntelligenceOutput
)


@CrewBase
class ThreatHuntingCrew():
    """Smart Threat Hunting Crew with ReAct-based intelligent agents"""

    agents: List[BaseAgent]
    tasks: List[Task]

    def __init__(self):
        # Set OPENAI_API_KEY from cache if not in environment
        if not os.getenv('OPENAI_API_KEY'):
            cache = APIKeyCache.get_instance()
            openai_key_data = cache.get_key('openai')
            if openai_key_data and openai_key_data.get('key'):
                openai_key = openai_key_data.get('key')
                os.environ['OPENAI_API_KEY'] = openai_key
                os.environ['CHROMA_OPENAI_API_KEY'] = openai_key  # For Chroma memory

        # Initialize tools
        self.virustotal_tool = VirusTotalTool()
        self.urlscan_tool = URLScanTool()

    @agent
    def triage_specialist(self) -> Agent:
        """Senior IOC Triage and Assessment Expert"""
        return Agent(
            config=self.agents_config['triage_specialist'],
            tools=[self.virustotal_tool],
            allow_delegation=False  # Worker agents should not delegate
        )

    @agent
    def malware_specialist(self) -> Agent:
        """Elite Malware Behavioral Analysis Expert"""
        return Agent(
            config=self.agents_config['malware_analysis_specialist'],
            tools=[self.virustotal_tool],
            allow_delegation=False  # Worker agents should not delegate
        )

    @agent
    def infrastructure_hunter(self) -> Agent:
        """Master Infrastructure Hunter and Campaign Correlation Expert"""
        return Agent(
            config=self.agents_config['infrastructure_correlation_specialist'],
            tools=[self.urlscan_tool],
            allow_delegation=False  # Worker agents should not delegate
        )

    @agent
    def campaign_analyst(self) -> Agent:
        """Strategic Threat Campaign Assessment and Attribution Expert"""
        return Agent(
            config=self.agents_config['campaign_intelligence_analyst'],
            allow_delegation=False  # Worker agents should not delegate
        )

    @agent
    def correlation_orchestrator(self) -> Agent:
        """Cross-Agent Intelligence Correlation and Investigation Orchestrator"""
        return Agent(
            config=self.agents_config['intelligence_correlation_orchestrator'],
            allow_delegation=True  # Manager MUST be able to delegate to worker agents
        )

    @task
    def initial_assessment(self) -> Task:
        """Initial IOC triage and priority assessment"""
        return Task(
            config=self.tasks_config['initial_ioc_assessment'],
            agent=self.triage_specialist(),
            output_pydantic=TriageOutput,
            output_file='reports/triage_assessment.json'
        )

    @task
    def malware_analysis(self) -> Task:
        """Deep malware behavioral analysis"""
        return Task(
            config=self.tasks_config['deep_malware_behavioral_analysis'],
            agent=self.malware_specialist(),
            context=[self.initial_assessment()],  # CrewAI handles context automatically
            output_pydantic=MalwareAnalysisOutput,
            output_file='reports/malware_analysis.json'
        )

    @task
    def infrastructure_correlation(self) -> Task:
        """Infrastructure campaign correlation and mapping"""
        return Task(
            config=self.tasks_config['infrastructure_campaign_correlation'],
            agent=self.infrastructure_hunter(),
            context=[self.initial_assessment(), self.malware_analysis()],  # Full context
            output_pydantic=InfrastructureCorrelationOutput,
            output_file='reports/infrastructure_analysis.json'
        )

    
    @task
    def campaign_synthesis(self) -> Task:
        """Strategic campaign intelligence synthesis"""
        return Task(
            config=self.tasks_config['strategic_campaign_intelligence_synthesis'],
            agent=self.campaign_analyst(),
            context=[self.initial_assessment(), self.malware_analysis(), self.infrastructure_correlation()],  # Removed orchestration task
            output_pydantic=CampaignIntelligenceOutput,
            output_file='reports/campaign_intelligence.json'
        )

    @crew
    def crew(self) -> Crew:
        """Creates the Smart Threat Hunting crew with Hierarchical Process"""
        # Ensure Chroma API key is set before Crew initialization
        if not os.getenv('CHROMA_OPENAI_API_KEY'):
            openai_key = os.getenv('OPENAI_API_KEY')
            if openai_key:
                os.environ['CHROMA_OPENAI_API_KEY'] = openai_key

        return Crew(
            agents=[
                self.triage_specialist(),
                self.malware_specialist(),
                self.infrastructure_hunter(),
                self.campaign_analyst()
            ],
            tasks=[
                self.initial_assessment(),
                self.malware_analysis(),
                self.infrastructure_correlation(),
                self.campaign_synthesis()
            ],
            process=Process.hierarchical,
            manager_agent=self.correlation_orchestrator(),
            verbose=True,
            memory=False,  # Disabled memory due to embedding compatibility issues
            cache=True,   # Enable LLM response caching
            max_iter=15
        )

    def investigate_ioc(self, ioc: str) -> dict:
        """
        Launch IOC investigation
        
        Args:
            ioc: The indicator of compromise to investigate
            
        Returns:
            Investigation results
        """
        print(f"🔍 Starting investigation for IOC: {ioc}")
        
        # CrewAI handles everything automatically!
        result = self.crew().kickoff(inputs={'ioc': ioc})
        
        print(f"✅ Investigation completed for IOC: {ioc}")
        
        return {
            'status': 'completed',
            'ioc': ioc,
            'result': result,
            'final_report': result.raw if hasattr(result, 'raw') else str(result)
        }


def main():
    """CLI entry point for threat hunting investigation"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m app.features.threat_hunter_copy.crew <IOC>")
        print("\nExamples:")
        print("  python -m app.features.threat_hunter_copy.crew rtmp.blog")
        print("  python -m app.features.threat_hunter_copy.crew 8.8.8.8")
        print("  python -m app.features.threat_hunter_copy.crew 44d88612fea8a8f36de82e1278abb02f")
        sys.exit(1)

    ioc = sys.argv[1]

    print(f"\n{'='*80}")
    print(f"🔍 Starting Pydantic-enabled investigation for IOC: {ioc}")
    print(f"{'='*80}\n")

    # Initialize crew
    threat_crew = ThreatHuntingCrew()

    # Investigate IOC
    results = threat_crew.investigate_ioc(ioc)

    print(f"\n{'='*80}")
    print(f"✅ INVESTIGATION COMPLETED")
    print(f"{'='*80}")
    print(f"Status: {results['status']}")
    print(f"IOC: {results['ioc']}")

    print(f"\n{'='*80}")
    print(f"📄 Generated JSON Files:")
    print(f"{'='*80}")
    print("  - reports/triage_assessment.json")
    print("  - reports/malware_analysis.json")
    print("  - reports/infrastructure_analysis.json")
    print("  - reports/campaign_intelligence.json")

    print(f"\n{'='*80}")
    print(f"💡 View results:")
    print(f"{'='*80}")
    print("  cat reports/campaign_intelligence.json | jq .")
    print("  # Or: cat reports/campaign_intelligence.json")


if __name__ == "__main__":
    main()