"""Pydantic schemas for structured Task outputs from AOL Threat Hunter agents.

These schemas enforce structured JSON output from LLMs instead of free-form Markdown,
enabling type-safe data processing and better frontend integration.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Literal
from datetime import datetime


# ============================================================================
# Shared/Nested Models
# ============================================================================

class DiscoveredRelationship(BaseModel):
    """Relationship discovered during IOC analysis (e.g., contacted IP, referring file)."""
    relationship_type: str = Field(
        ...,
        description="Type of relationship: contacted_ip, referring_file, passive_dns, dropped_file, etc."
    )
    indicator: str = Field(..., description="The discovered indicator (IP, hash, domain, etc.)")
    context: str = Field(..., description="Context about this relationship and its significance")
    detection_stats: Optional[str] = Field(None, description="Detection statistics if available (e.g., '21/93')")
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = Field(..., description="Confidence in this relationship's significance")


class PriorityDiscovery(BaseModel):
    """High-significance discovery requiring specialist analysis."""
    priority_rank: int = Field(..., description="Priority rank (1 = highest)")
    discovery: str = Field(..., description="Description of the discovery")
    significance: str = Field(..., description="Why this discovery is significant")
    recommended_specialist: str = Field(
        ...,
        description="Which specialist should analyze this: malware_analyst, infrastructure_hunter, campaign_analyst"
    )
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = Field(..., description="Confidence level in priority assessment")


class InfrastructureTarget(BaseModel):
    """Infrastructure target extracted from malware analysis for correlation."""
    target_type: str = Field(..., description="Type: c2_ip, c2_domain, download_url, etc.")
    target: str = Field(..., description="The actual infrastructure indicator")
    behavioral_context: str = Field(..., description="How malware uses this infrastructure")
    priority: Literal["HIGH", "MEDIUM", "LOW"] = Field(..., description="Priority for correlation analysis")


class ExtractedIOC(BaseModel):
    """IOC extracted from investigation with full context and actionable classification."""
    indicator: str = Field(..., description="The IOC value (hash, IP, domain, URL)")
    ioc_type: Literal["hash", "ipv4", "ipv6", "domain", "url"] = Field(..., description="IOC type")
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = Field(
        ...,
        description="HIGH: >15 detections, MEDIUM: 5-15 detections, LOW: <5 detections"
    )
    detections: str = Field(..., description="Detection ratio (e.g., '21/93')")
    first_seen: Optional[str] = Field(None, description="First seen timestamp")
    relationship_context: str = Field(..., description="How this IOC relates to the investigation")
    recommended_action: Literal["block", "monitor", "investigate"] = Field(
        ...,
        description="Recommended action based on confidence and threat level"
    )


class DiscoveredIOC(BaseModel):
    """New IOC discovered during analysis - designed for frontend visualization and user exploration."""
    ioc: str = Field(..., description="The discovered IOC value (hash, IP, domain, URL)")
    ioc_type: Literal["hash", "ipv4", "ipv6", "domain", "url"] = Field(..., description="IOC type")
    discovery_reason: str = Field(
        ...,
        description="WHY this IOC was discovered (e.g., 'Contacted by malware during C2 communication', 'Resolved from malicious domain in passive DNS')"
    )
    discovery_source: str = Field(
        ...,
        description="WHERE this IOC was found (e.g., 'VirusTotal contacted_ips', 'URLScan page.ip results', 'VirusTotal passive_dns')"
    )
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = Field(..., description="Confidence in this IOC's significance")
    detections: Optional[str] = Field(None, description="Detection ratio if available (e.g., '21/93')")
    first_seen: Optional[str] = Field(None, description="First seen timestamp if available")
    recommended_action: Literal["investigate", "monitor", "block", "ignore"] = Field(
        ...,
        description="Recommended action for user"
    )
    parent_ioc: str = Field(..., description="The original IOC that led to this discovery")


class HuntHypothesis(BaseModel):
    """Intelligence-driven threat hunting hypothesis with executable detection logic."""
    hypothesis_id: int = Field(..., description="Hypothesis number (1-5)")
    hypothesis_name: str = Field(..., description="Short name for this hypothesis (e.g., 'Cloudflare C2 Pattern')")
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = Field(..., description="Confidence in this hypothesis")
    hypothesis_description: str = Field(
        ...,
        description="Detailed hypothesis statement (e.g., 'If threat actor uses Cloudflare C2, then...')"
    )
    detection_platform: Literal["SIEM", "YARA", "EDR", "Network", "Endpoint"] = Field(
        ...,
        description="Platform for executing this hunt"
    )
    executable_query: str = Field(
        ...,
        description="Complete executable detection logic (e.g., SIEM query, YARA rule, network filter). MUST be syntactically valid."
    )
    hunt_timeline: str = Field(..., description="Hunt timeframe (e.g., 'Last 30 days', 'Monitor next 7 days')")
    success_criteria: str = Field(
        ...,
        description="Validation threshold (e.g., '>5 matches = confirmed threat', '>3 internal IPs = campaign')"
    )
    priority: int = Field(..., ge=1, le=5, description="Priority ranking (1 = highest)")


class MITRETactic(BaseModel):
    """MITRE ATT&CK tactic with specific techniques observed."""
    tactic: str = Field(..., description="MITRE tactic name (e.g., 'Initial Access', 'Command and Control')")
    techniques: List[str] = Field(
        default_factory=list,
        description="Specific technique IDs observed (e.g., 'T1566.001', 'T1071.001')"
    )
    evidence: str = Field(..., description="Evidence supporting this tactic identification")


# ============================================================================
# Task 1: Initial IOC Assessment (Triage)
# ============================================================================

class TriageOutput(BaseModel):
    """Structured output from Initial IOC Triage Assessment task."""

    # Core Assessment
    ioc: str = Field(..., description="The IOC being investigated")
    ioc_type: str = Field(..., description="Type of IOC: hash, domain, ip, url")
    threat_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(
        ...,
        description="Overall threat assessment level"
    )

    # Reputation & Detection
    detection_summary: str = Field(..., description="Detection statistics and vendor consensus summary")
    detection_ratio: Optional[str] = Field(None, description="Detection ratio if applicable (e.g., '21/93')")

    # Discovered Relationships
    discovered_relationships: List[DiscoveredRelationship] = Field(
        default_factory=list,
        description="All relationships discovered (contacted IPs, referring files, passive DNS, etc.)"
    )

    # Priority Discoveries
    priority_discoveries: List[PriorityDiscovery] = Field(
        default_factory=list,
        description="High-significance discoveries ranked by priority"
    )

    # Recommendations
    recommended_next_steps: List[str] = Field(
        default_factory=list,
        description="Specific recommendations for follow-on specialist analysis"
    )

    # Discovered IOCs for User Exploration
    discovered_iocs: List[DiscoveredIOC] = Field(
        default_factory=list,
        description="All NEW IOCs discovered during analysis (IPs, domains, hashes, URLs) with discovery context for frontend visualization"
    )

    # Summary
    analytical_summary: str = Field(
        ...,
        description="Executive summary of triage findings and analytical reasoning"
    )


# ============================================================================
# Task 2: Deep Malware Behavioral Analysis
# ============================================================================

class MalwareAnalysisOutput(BaseModel):
    """Structured output from Deep Malware Behavioral Analysis task."""

    # Malware Identification
    malware_family: Optional[str] = Field(None, description="Identified malware family name")
    malware_type: Optional[str] = Field(None, description="Malware type: trojan, ransomware, backdoor, etc.")
    behavioral_profile: str = Field(..., description="Comprehensive behavioral characteristics of the malware")

    # Infrastructure Usage
    infrastructure_usage_patterns: str = Field(
        ...,
        description="How malware uses discovered infrastructure (C2, downloads, exfiltration)"
    )
    communication_mechanisms: List[str] = Field(
        default_factory=list,
        description="Communication protocols and mechanisms used by malware"
    )

    # Attack Chain
    attack_chain_analysis: str = Field(
        ...,
        description="Complete attack chain from initial access through objectives"
    )
    payload_delivery_methods: List[str] = Field(
        default_factory=list,
        description="Methods used to deliver payloads"
    )

    # Infrastructure Targets
    infrastructure_targets: List[InfrastructureTarget] = Field(
        default_factory=list,
        description="Specific infrastructure targets extracted for correlation analysis"
    )

    # Relationships
    parent_child_relationships: List[str] = Field(
        default_factory=list,
        description="Parent-child file relationships and execution flow"
    )

    # Context
    contextual_analysis: str = Field(
        ...,
        description="How malware analysis relates to original IOC investigation"
    )

    # Recommendations
    correlation_recommendations: List[str] = Field(
        default_factory=list,
        description="Recommended infrastructure correlation targets with behavioral context"
    )

    # Discovered IOCs for User Exploration
    discovered_iocs: List[DiscoveredIOC] = Field(
        default_factory=list,
        description="All NEW IOCs discovered during malware analysis (C2 IPs, domains, contacted hosts) with discovery context"
    )


# ============================================================================
# Task 3: Infrastructure Campaign Correlation
# ============================================================================

class InfrastructureCluster(BaseModel):
    """Infrastructure cluster showing potential campaign coordination."""
    cluster_name: str = Field(..., description="Name/identifier for this infrastructure cluster")
    infrastructure_elements: List[str] = Field(
        ...,
        description="Infrastructure elements in this cluster (IPs, ASNs, domains)"
    )
    clustering_evidence: str = Field(..., description="Evidence supporting this clustering assessment")
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = Field(..., description="Confidence in campaign coordination")


class InfrastructureCorrelationOutput(BaseModel):
    """Structured output from Infrastructure Campaign Correlation task."""

    # Infrastructure Mapping
    infrastructure_relationship_map: str = Field(
        ...,
        description="Complete infrastructure relationship mapping with confidence assessments"
    )

    # Campaign Clustering
    campaign_clusters: List[InfrastructureCluster] = Field(
        default_factory=list,
        description="Identified campaign clusters showing infrastructure reuse or coordination"
    )
    clustering_assessment: str = Field(
        ...,
        description="Assessment of campaign clustering with evidence of coordination"
    )

    # Discovered IOCs
    additional_iocs: List[ExtractedIOC] = Field(
        default_factory=list,
        description="Additional IOCs discovered through infrastructure correlation"
    )

    # ASN & Hosting Analysis
    asn_hosting_patterns: str = Field(
        ...,
        description="ASN and hosting pattern analysis with clustering significance"
    )

    # Temporal Analysis
    temporal_correlation: str = Field(
        ...,
        description="Deployment timing and coordination patterns analysis"
    )

    # Campaign Assessment
    campaign_scale_assessment: str = Field(
        ...,
        description="Campaign-scale infrastructure assessment with scope and distribution"
    )

    # Discovered IOCs for User Exploration
    discovered_iocs: List[DiscoveredIOC] = Field(
        default_factory=list,
        description="All NEW IOCs discovered through infrastructure hunting (related IPs, domains, URLs) with discovery context"
    )


# ============================================================================
# Task 4: Strategic Campaign Intelligence Synthesis
# ============================================================================

class ThreatActorAttribution(BaseModel):
    """Threat actor attribution assessment with confidence and evidence."""
    attributed_actor: Optional[str] = Field(None, description="Attributed threat actor or group name")
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = Field(..., description="Attribution confidence level")
    overlap_indicators: List[str] = Field(
        default_factory=list,
        description="Specific overlap indicators supporting attribution"
    )
    attribution_rationale: str = Field(..., description="Detailed rationale for attribution assessment")


class CampaignIntelligenceOutput(BaseModel):
    """Structured output from Strategic Campaign Intelligence Synthesis task."""

    # Executive Summary
    executive_summary: str = Field(
        ...,
        description="High-level summary of key findings for decision-makers"
    )
    threat_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(
        ...,
        description="Overall threat level assessment"
    )

    # Campaign Classification
    campaign_name: str = Field(..., description="Campaign name or identifier")
    campaign_confidence: Literal["HIGH", "MEDIUM", "LOW"] = Field(
        ...,
        description="Confidence that this represents coordinated campaign activity"
    )
    campaign_evidence: List[str] = Field(
        default_factory=list,
        description="Specific evidence supporting campaign classification"
    )

    # TTPs & Attack Chain
    mitre_tactics: List[MITRETactic] = Field(
        default_factory=list,
        description="MITRE ATT&CK tactics and techniques with evidence"
    )
    attack_chain_ttps: str = Field(
        ...,
        description="Detailed attack chain with specific TTPs (NOT generic descriptions)"
    )

    # Attribution
    threat_actor_attribution: ThreatActorAttribution = Field(
        ...,
        description="Threat actor attribution assessment"
    )

    # IOC Extraction (MANDATORY)
    extracted_iocs: List[ExtractedIOC] = Field(
        ...,
        description="COMPLETE IOC extraction from ALL previous agent findings. MUST include all hashes, IPs, domains, URLs mentioned."
    )

    # Hunt Hypotheses (MANDATORY)
    hunt_hypotheses: List[HuntHypothesis] = Field(
        ...,
        min_length=3,
        max_length=5,
        description="3-5 intelligence-driven hunt hypotheses with executable detection logic"
    )

    # Recommendations
    recommended_actions: List[str] = Field(
        default_factory=list,
        description="Immediate actions prioritized by confidence and organizational risk"
    )

    # Intelligence Gaps
    intelligence_gaps: List[str] = Field(
        default_factory=list,
        description="Identified intelligence gaps and recommendations for continued monitoring"
    )

    # Discovered IOCs for User Exploration
    discovered_iocs: List[DiscoveredIOC] = Field(
        default_factory=list,
        description="All NEW IOCs discovered across all analysis phases with comprehensive discovery context"
    )

    # Risk Assessment
    organizational_impact: str = Field(..., description="Assessment of organizational impact and risk")
