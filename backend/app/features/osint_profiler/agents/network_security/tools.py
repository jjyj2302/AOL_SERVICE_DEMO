"""
NetworkSecurityAgent Tools - 네트워크 보안 분석 도구 모음

책임 :
- API 키 로딩 (get_apikey 사용)
- IP 분석 도구 생성 (AbuseIPDB, VirusTotal, Shodan, CrowdSec, AlienVault)
- Domain 분석 도구 생성 (VirusTotal, SafeBrowsing, URLScan)
- BGP/ASN 분석 도구 생성 (BGPView)
- LangChain Tool 래핑 및 입력 검증

설계 패턴 : 
- Agent 인스턴스를 받아서 agent_instance.db로 API 키 조회
- API 키 조회 불가시 해당 도구는 건너뜁니다.
- Pydantic 스키마로 입력 검증 실시
근데 프롬프트 엔지니어링 전부 다시해야하긴 함.
"""

from typing import List
from langchain.tools import Tool, StructuredTool
from pydantic import BaseModel, Field, IPvAnyAddress

from app.features.ioc_tools.ioc_lookup.single_lookup.service import external_api_clients
from app.core.settings.api_keys.crud.api_keys_settings_crud import get_apikey

# Pydantic Input Schemas
class IPInput(BaseModel):
      """IP 주소 입력 검증 스키마 (IPv4/IPv6)"""
      ip: IPvAnyAddress = Field(
          description="조사할 IP 주소 (IPv4/IPv6). 예: '8.8.8.8' 또는 '2001:4860:4860::8888'"
      )


  class DomainInput(BaseModel):
      """도메인 입력 검증 스키마"""
      domain: str = Field(
          description="조사할 도메인 이름. 예: 'example.com'"
      )

# IP Analysis Tools
def create_ip_tools(agent_instance) -> List[Tool]:
    """
    IP 분석 도구 5개 생성

    Tools:
    1. AbuseIPDB - 커뮤니티 기반 IP 악성 행위 신고 DB
    2. VirusTotal - 멀티 AV (안티 바이러스) IP 평판 및 관계 분석
    3. Shodan - 인터넷 전체 스캔 데이터 (포트/서비스/배너)
    4. CrowdSec - 커뮤니티 기반 IP 평판 및 행위 분석
    5. AlienVault OTX - 위협 인텔리전스 피드 및 관계 IOC

    Args:
        agent_instance: NetworkSecurityAgent 인스턴스
    Returns:
        List[Tool] : LangChain StructuredTool 리스트 
    """
    tools = []
    db = agent_instance.db

    # 1. AbuseIPDB
    abuseipdb_key = get_apikey(db, "abuseipdb")
    if abuseipdb_key:
        def abuseipdb_check(ip: str) -> dict:
            """AbuseIPDB IP 평판 조회"""
            return external_api_clients.abuseipdb_ip_check(
                ioc=ip,
                apikey=abuseipdb_key
            )

        tools.append(StructuredTool.from_function(
              func=abuseipdb_check,
              name="abuseipdb_check",
              description=""""Check IP reputation and abuse reports from a community-driven database (AbuseIPDB).
              USE WHEN:
              - Investigating suspicious IPs found in logs/IR
              - Evaluating threat level before adding to firewall blacklists
              - Reviewing historical abuse patterns (port-scan, brute-force, spam)
              RETURNS:
              { "abuseConfidenceScore": int(0-100), 
                "totalReports": int, 
                "countryCode": str, 
                "domain": str, 
                "isp": str, 
                "asn": str, 
                "usageType": str,
                "reports": [ { "category": [int], "comment": str, "reportedAt": str } ] }
              LIMITS:
              - Free tier daily quota; 429 on exceed. Community-driven → false positives possible (especially shared/VPN/CDN/hosting IPs).
              INTERPRETATION:
              - Higher score = stronger signal, not absolute proof. Always check recency and categories, and corroborate with other sources.
              DON'T USE:
              - As sole verdict, or to label shared/recycled IPs "malicious" without temporal/context data.""",
              args_schema=IPInput
        ))

    # 2. VirusTotal IP
    vt_key = get_apikey(db, "virustotal")
    if vt_key:
        def virustotal_ip_check(ip: str) -> dict:
            """VirusTotal IP 평판 조회"""
            return external_api_clients.virustotal(
                ioc=ip,
                type='ip',
                apikey=vt_key
            )
        tools.append(StructuredTool.from_function(
            func=virustotal_ip_check,
            name="virustotal_ip_lookup",
            description="""Cross-validate IP reputation and realtionships via multi-vendor telemetry (VirusTotal).
            USE WHEN:
            - Verifying suspicious IPs during malware/IOC analysis
            - Investigating C2 infrastructure, passive DNS, related domains/URLs/samples
            RETURNS:
            { "last_analysis_stats": { "malicious": int, "suspicious": int, "harmless": int, "undetected": int },
              "resolutions": [ { "hostname": str, "last_resolved": str }],
              "detected_urls": [ { "url": str, "positives": int, "scan_data": str }],
              "whois": str, 
              "asn": str,
              "country": str,
              "detected_communicating_samples": [ { "sha256": str, "date": str }]
            }
            LIMITS:
            - Strict free-quota/rate limits (204/429 when exhausted).
            - Zero/clean results  ≠ safe; new/targeted threats can be missed.
            INTERPRETATIONS:
            - Use as initial assessment and for correlation-not a final veredict.
            - Consider time windows/caching.
            DON'T USE:
            - As sole decision factor or for real-time guarantees (results can be dealyed/cached).""",
            args_schema=IPInput
        ))
    
    # 3. Shodan
    shodan_key = get_apikey(db, "shodan")
    if shodan_key:
        def shodan_ip_check(ip:str) -> dict:
            """Shodan 인터넷 스캔 데이터 조회"""
            return external_api_clients.check_shodan(
                ioc=ip,
                apikey=shodan_key,
                method='ip'
            )
        
        tools.append(StructuredTool.from_function(
            func=shodan_ip_check,
            name="shodan_ip_scan",
            description="""Retrieve exposed services/ports/banners/SSL for an IP from Internet-wide scans (Shodan).
            USE WHEN:
            - Discovering attack surface and unintended exposures
            - Fingerprinting C2/misconfigured services (product/version/banner/SSL)
            - IoT/device discovery and posture assessment
            RETURNS:
            { "ports": [int],
              "hostnames": [str],
              "services": [ {"port": int, "product" str, "version": str, "banner": str, "ssl": { ... } } ],
              "vulns": [ "CVE-..." ],
              "org": str, 
              "asn" : str,
              "location": { "country": str, "city": str, "lat": float, "lon": float },
              "os": str,
              "tags": [str] 
            }
            LIMITS:
            - Free tier heavily restricted; historical data lag (weeks-months).
            - No internal/private IP coverage.
            INTERPRETATION:
            - Validate whether exposures are intentional. Pay attention to expired certs, unexpected open ports, default configs.
            DON't USE:
            For active scanning or real-time prot state; for RFC1918/internal ranges; or for misuse (responsible use).""",
            args_schema=IPInput
        ))

    # 4. CrowdSec
    crowdsec_key = get_apikey(db, "crowdsec")
    if crowdsec_key:
        def crowdsec_check(ip: str) -> dict:
            """CrowdSec 커뮤니티 평판 조회"""
            return external_api_clients.crowdsec(
                ioc=ip,
                apikey=crowdsec_key
            )
        
        tools.append(StructuredTool.from_function(
            func=crowdsec_check,
            name="crowdsec_reputation_check",
            description="""Check IP against CrowdSec community signals for behaviors and recent sightings.
            USE WHEN:
            - Validating automated blocking decisions from CrowdSec agents
            - Correlating log findings (ssh-bf/http-scan/web-exploit) with community reports
            RETURNS:
            { "behaviors": [ "ssh-bf", "http-scan", ... ],
              "reputation": "malicious|suspicious|safe",
              "confidence": int(0-100),
              "seen_by": int, "first_seen": str, "last_seen": str
            }
            LIMITS:
            Free tier has retention/coverage constraints; 429 on exceed. Regional coverage may vary.
            INTERPRETATION:
            - Combine confidence with seen_by (wider consensus = stronger signal).
            - Corroborate with local telemetry.
            DON'T USE:
            - AS sole blocking criterion, in regions with low coverage, or for long-range (beyond retention) history.""",
            args_schema=IPInput
        ))
    
    # 5. AlientVault OTX
    alienvault_key = get_apikey(db, "alienvault")
    if alienvault_key:
        def alienvault_ip_check(ip: str) -> dict:
            """AlienVault OTX 위협 인텔리전스 조회"""
            return external_api_clients.alienvaultotx(
                ioc=ip,
                type='ip',
                apikey=alienvault_key
            )
        
        tools.append(StructuredTool.from_function(
            func=alienvault_ip_check,
            name="alienvault_ip_intelligence",
            description="""Enrich IP with AlienVault OTX pulses: community threat reports and related IOCs.
            USE WHEN:
            - Adding campaign/actor context (tags/TLP/industries) to an IP
            - Expanding to related indicators (domains/URLs/hashes) and passive DNS
            RETURNS:
            { "pulses": [ { "name": str, "description": str, "tags": [str], "indicators": [...] }],
              "passive_dns": [ { "hostname": str, "last_seen": str } ],
              "asn": str, "geo": { "country": str }
            }
            Limits:
            Free quota/rate limits; community quality varies and updates can lag.
            INTERPRETATION:
            Prefer multiple/verified pulses and recent updates; use cross-source consensus.
            DON'T USE:
            As a real-time blocking source or single-source truth for attribution.""",
            args_schema=IPInput
        ))
    
    return tools

def create_domain_tools(agent_instance) -> List[Tool]:
    """
    도메인 분석 도구 3개 생성

    Tools:
    1. VirusTotal - 멀티 AV 엔진 도메인 평판 및 관계 분석
    2. Google Safe Browsing - 피싱/악성 도메인 탐지
    3. URLScan.io - 도메인 스캔 및 스크린샷

    Args:
        agent_instance: NetworkSecurityAgent 인스턴스

    Returns:
        List[Tool]: LangChain StructuredTool 리스트
    """
    tools = []
    db = agent_instance.db

    # 1. VirusTotal Domain
    vt_key = get_apikey(db, "virustotal")
    if vt_key:
        def virustotal_domain_check(domain: str) -> dict:
              """VirusTotal 도메인 평판 조회"""
              return external_api_clients.virustotal(
                  ioc=domain,
                  type='domain',
                  apikey=vt_key
              )

        tools.append(StructuredTool.from_function(
              func=virustotal_domain_check,
              name="virustotal_domain_lookup",
              description="""Multi-AV domain reputation check for SOC/threat hunting workflows.
              USE WHEN:
              - Phishing/malware domain investigation (70+ AV engines consensus)
              - Infrastructure mapping (IP relations, subdomains, connected files)
              - Brand impersonation detection via favicon hash/domain patterns
              RETURNS:
              { "last_analysis_stats": { "malicious": int, "harmless": int },
                "categories": {}, 
                "dns_records": {}, 
                "subdomains": [],
                "whois": str, 
                "detected_urls": [] }
              INTERPRETATION: 
              - 0/70=clean, 50+/70=high-risk. Check Relations tab for pivot points.
              - Recent registration + low popularity + detections = likely malicious.
              LIMITS: Rate limit 204/429. May miss zero-hour threats.""",
              args_schema=DomainInput
        ))
    
    # 2. Google Safe Browsing
    safebrowse_key = get_apikey(db, "safeBrowse")
    if safebrowse_key:
        def safebrowsing_domain_check(domain: str) -> dict:
            """Google Safe Browsing 도메인 체크"""
            url = f"http://{domain}"
            return external_api_clients.safeBrowse_url_check(
                ioc=url,
                apikey=safebrowse_key
            )

        tools.append(StructuredTool.from_function(
              func=safebrowsing_domain_check,
              name="safebrowsing_domain_check",
              description="""Real-time phishing/malware blocklist used by Chrome/Gmail.
              USE WHEN:
              - Pre-click URL validation in email security workflows
              - Enterprise browser protection policy enforcement
              - Automated bulk URL scanning via pysafebrowsing
              RETURNS:
              { "matches": [ { "threatType": "MALWARE|SOCIAL_ENGINEERING", "threat": { "url": str } } ] }
              Empty matches = not blacklisted (≠safe).
              USE CASE: Gmail Enhanced Safe Browsing, Chrome Enterprise blocking.
              LIMITS: Daily quota. Conservative detection (new threats delayed).""",
              args_schema=DomainInput
        ))
    
    # 3. URLScan.io 
    def urlscan_domain_check(domain: str) -> dict:
        """URLScan.io 도메인 검색"""
        return external_api_clients.urlscanio(ioc=domain)

    tools.append(StructuredTool.from_function(
        func=urlscan_domain_check,
        name="urlscan_domain_search",
        description="""Visual/behavioral domain analysis with screenshots and HTTP traces.
        USE WHEN:
        - Phishing kit detection (POST credentials, brand logos)
        - Typosquatting discovery via favicon hash queries
        - Email security automation (Tines/SOAR integration)
        QUERY EXAMPLES:
        date:[now-7d TO now] AND task.method:POST (credential harvesting)
        page.domain:/.*paypal.*/ NOT paypal.com (brand abuse)
        RETURNS:
        { "results": [{ "page": {}, "screenshot": url, "stats": {} }]}
        INTERPRETATION: Check screenshots for visual deception, POST requests for data theft.
        LIMITS: Free tier rate limits. No real-time scanning without API key.""",
        args_schema=DomainInput
    ))

    return tools

# BGP/ASN Analysis Tools
def create_bgp_tools(agent_instance) -> List[Tool]:
    """BGP/ASN 분석 도구 생성
    Tools:
    BGPView - IP->ASN/BGN 정보 조회
    Args:
        agent_instance: NetworkSecurityAgent 인스턴스
    Returns:
        List[Tool]: LangChain StructuredTool 리스트
    """
    tools = []
    db = agent_instance.db
    def bgpview_check(ip: str) -> dict:
          """BGPView IP→ASN/BGP 정보 조회"""
          return external_api_clients.check_bgpview(ioc=ip)

    tools.append(StructuredTool.from_function(
          func=bgpview_check,
          name="bgpview_ip_lookup",
          description="""BGPView — IP→BGP/ASN intel (free/no key)
          USE WHEN: map IP→ASN/ISP & prefixes; infra attribution; range expand
          RETURNS: asn{num,name,country,alloc_at}; prefixes[]; rir; peering/ix(if any); ptr
          LIMITS: fair-use; 429 on bursts→≥2s backoff; data may lag; BGP is observational
          DON'T USE: RFC1918/unrouted; as ownership proof (cross-check RDAP/WHOIS)
          INTERPRET: ASN≠owner; use upstream/downstream to infer provider/scale
          FLOW: IPAgent→BGPView→RDAP/WHOIS cross-check→expand by ASN/prefix→pattern hunt
          TIPS: cache results; retry+backoff; fallback: HE BGP Toolkit / RIPEstat / Team Cymru""",
          args_schema=IPInput
      ))

      return tools