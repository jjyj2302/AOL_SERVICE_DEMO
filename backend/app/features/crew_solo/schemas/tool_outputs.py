"""Pydantic schemas for structured Tool outputs."""
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Literal
from datetime import datetime


# ============================================================================
# VirusTotal Tool Outputs
# ============================================================================

class DetectionStats(BaseModel):
    """Detection statistics from security vendors."""
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total: int = 0

    @property
    def detection_ratio(self) -> str:
        """Return detection ratio as string (e.g., '21/93')."""
        return f"{self.malicious}/{self.total}"

    @property
    def confidence_level(self) -> Literal["HIGH", "MEDIUM", "LOW"]:
        """Determine confidence level based on detection ratio."""
        if self.total == 0:
            return "LOW"
        ratio = self.malicious / self.total
        if ratio > 0.15:  # >15% detection
            return "HIGH"
        elif ratio > 0.05:  # 5-15%
            return "MEDIUM"
        else:
            return "LOW"


class CommunicatingFile(BaseModel):
    """File that communicates with or references an IOC."""
    hash_sha256: str
    hash_md5: Optional[str] = None
    hash_sha1: Optional[str] = None
    filename: str = "Unknown"
    file_type: Optional[str] = None
    file_size: Optional[int] = None
    detection_stats: DetectionStats
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class ContactedIP(BaseModel):
    """IP address contacted by malware."""
    ip: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    asn_name: Optional[str] = None


class ContactedDomain(BaseModel):
    """Domain contacted by malware."""
    domain: str
    detection_stats: Optional[DetectionStats] = None


class BehavioralIndicators(BaseModel):
    """Behavioral indicators from sandbox analysis."""
    mitre_tactics: List[str] = Field(default_factory=list)
    processes_created: List[str] = Field(default_factory=list)
    files_written: List[str] = Field(default_factory=list)
    files_dropped: List[str] = Field(default_factory=list)
    registry_keys_set: List[str] = Field(default_factory=list)
    dns_lookups: List[str] = Field(default_factory=list)
    http_requests: List[str] = Field(default_factory=list)
    mutexes_created: List[str] = Field(default_factory=list)


class VirusTotalHashOutput(BaseModel):
    """Structured output from VirusTotal hash analysis."""
    hash_sha256: str
    hash_md5: Optional[str] = None
    hash_sha1: Optional[str] = None
    filename: str = "Unknown"
    file_type: str = "Unknown"
    file_size: Optional[int] = None
    detection_stats: DetectionStats
    first_seen: Optional[str] = None
    last_analysis: Optional[str] = None

    # C2 Infrastructure
    contacted_ips: List[ContactedIP] = Field(default_factory=list)
    contacted_domains: List[ContactedDomain] = Field(default_factory=list)
    contacted_urls: List[str] = Field(default_factory=list)

    # File Relationships
    parent_files: List[CommunicatingFile] = Field(default_factory=list)
    dropped_files: List[CommunicatingFile] = Field(default_factory=list)
    similar_files: List[str] = Field(default_factory=list)

    # Behavioral Data
    behavioral_indicators: Optional[BehavioralIndicators] = None

    # Digital Signature
    signature_info: Optional[Dict[str, str]] = None


class DNSResolution(BaseModel):
    """DNS resolution record."""
    ip: str
    last_seen: Optional[str] = None


class VirusTotalDomainOutput(BaseModel):
    """Structured output from VirusTotal domain analysis."""
    domain: str
    detection_stats: DetectionStats
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    categories: List[str] = Field(default_factory=list)

    # DNS & Infrastructure
    resolved_ips: List[DNSResolution] = Field(default_factory=list)
    subdomains: List[str] = Field(default_factory=list)

    # Related Files
    communicating_files: List[CommunicatingFile] = Field(default_factory=list)
    referring_files: List[CommunicatingFile] = Field(default_factory=list)

    # URLs
    urls: List[str] = Field(default_factory=list)

    # Reputation
    vt_community_score: Optional[int] = None


class VirusTotalIPOutput(BaseModel):
    """Structured output from VirusTotal IP analysis."""
    ip: str
    detection_stats: DetectionStats
    country: Optional[str] = None
    asn: Optional[str] = None
    asn_name: Optional[str] = None

    # Passive DNS
    passive_dns: List[DNSResolution] = Field(default_factory=list)

    # Related Files
    communicating_files: List[CommunicatingFile] = Field(default_factory=list)
    downloaded_files: List[CommunicatingFile] = Field(default_factory=list)

    # Hosted URLs
    hosted_urls: List[str] = Field(default_factory=list)


# ============================================================================
# URLScan Tool Outputs
# ============================================================================

class URLScanResult(BaseModel):
    """Individual URLScan result."""
    url: str
    domain: str
    scan_time: str
    page_ip: Optional[str] = None
    server_ip: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    status_code: Optional[int] = None
    urlscan_link: str


class URLScanOutput(BaseModel):
    """Structured output from URLScan search."""
    query: str
    total_results: int
    results_shown: int

    # Individual Results
    results: List[URLScanResult] = Field(default_factory=list)

    # Extracted IOCs
    unique_domains: List[str] = Field(default_factory=list)
    unique_ips: List[str] = Field(default_factory=list)
    unique_urls: List[str] = Field(default_factory=list)
    unique_asns: List[str] = Field(default_factory=list)
    unique_countries: List[str] = Field(default_factory=list)

    # Temporal Patterns
    date_range_start: Optional[str] = None
    date_range_end: Optional[str] = None
    recent_activity_count: int = 0  # Last 30 days

    # TLD Distribution
    tld_distribution: Dict[str, int] = Field(default_factory=dict)
