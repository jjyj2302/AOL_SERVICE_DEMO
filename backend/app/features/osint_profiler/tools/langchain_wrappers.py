"""
LangChain Tools 래퍼 모듈
기존 external_api_client.py의 18개 OSINT API를 LangChain Tool 형식으로 변환해
LLM Agent가 사용할 수 있도록 한다.

카테고리 : 
- Email : 3개 (HIBP, EmailRep, Hunter)
- IP : 5개 (AbuseIPDB, VirusTotal, Shodan, CrowdSec, AlienValut)
- Domain : 3개 (VirusTotal, SafeBrowsing, URLScan)
- Hash : 3개 (VirusTotal, MalwareBazaar, ThreatFox)
- URL : 1개 (URLhaus)
- GitHub : 1개 (GitHub Code Search)
- Misc : 4개 (BGPView, NIST NVD, Pulsedive, Reddit)
"""

from typing import List, Dict, Any, Optional
from langchain.tools import Tool, StructuredTool
from pydantic import BaseModel, Field, EmailStr,  IPvAnyAddress  # EmilStr: 이메일 형식 검증용
from sqlalchemy.orm import Session

# 기존 API 클라이언트 IMPORT.
from app.features.ioc_tools.ioc_lookup.single_lookup.service import external_api_clients
from app.core.settings.api_keys.crud.api_keys_settings_crud import get_apikey
class OSINTToolFactory:
    """
    기존 OSINT API 클라이언트를 LangChain Tools로 변환하는 팩토리
    총 18개 API를 7개 카테고리로 분류하여 LLM Agent에게 제공한다.
    """
    def __init__(self, db: Session):
        """
        Args:
            db: SQLAlchemy DB 세션 (API 키 조회용)
        """
        self.db = db
        self.api_keys = self._load_api_keys()
    
    def _load_api_keys(self) -> Dict[str, str]:
        """
        DB에서 API 키를 조회하여 딕셔너리로 반환.
        Returns:
            Dict[str, str]: {api_key_name: api_key_value}
        """
        # TODO : 18개 서비스의 API 키 로드 구현
        api_keys = {}

        # 필요한 API 키 목록
        key_names = [
            'hibp_api_key',      # Have I Been Pwned
            'emailrepio',        # EmailRep.io
            'hunterio_api_key',  # Hunter.io
            'abuseipdb',         # AbuseIPDB
            'virustotal',        # VirusTotal
            'shodan',            # Shodan
            'crowdsec',          # CrowdSec
            'alienvault',        # AlienVault OTX
            'safeBrowse',        # Google Safe Browsing
            'urlhaus',           # URLhaus
            'github_pat',        # GitHub
            'bgpview',           # BGPView
            'nist_nvd_api_key',  # NIST NVD
            'pulsedive',         # Pulsedive
            'reddit_cid',        # Reddit Client ID
            'reddit_cs',         # Reddit Client Secret
            'malwarebazaar',     # MalwareBazaar
            'threatfox',         # ThreatFox
        ]

        for key_name in key_names:
            try:
                key_value = get_apikey(self.db, key_name)
                if key_value:
                    api_keys[key_name] = key_value
            except Exception as e:
                # API 키가 없어도 계속 진행 (선택적 도구)
                pass
        return api_keys
    
    def _get_missing_keys(self) -> List[str]:
        """
        설정되지 않은 API 키 목록 반환
        Returns:
            List[str]: 누락된 API 키 이름 목록
        """
        all_keys = [
             'hibp_api_key', 'emailrepio', 'hunterio_api_key', 'abuseipdb', 'virustotal', 'shodan', 'crowdsec', 'alienvault',
              'safeBrowse', 'urlhaus', 'github_pat', 'bgpview', 'nist_nvd_api_key', 'pulsedive', 'reddit_cid', 'reddit_cs',
              'malwarebazaar', 'threatfox'
        ]
        return [key for key in all_keys if key not in self.api_keys]

    # 1. Email Tools (3개)
    def create_email_tools(self) -> List[Tool]:
        """ 
        이메일 분석 도구 3개 생성 
        Tools : 
        1. Have I Been Pwned - 데이터 유출 이력 조회
        2. EmailRep.io - 평판 점수 및 의심 플래그
        3. Hunter.io - 전송 가능 여부 검증 및 도메인 인텔리전스
        """
        # 입력 검증 스키마
        class EmailInput(BaseModel):
            """ 이메일 주소 입력 검증 """
            email: EmailStr = Field(description="조사할 유효한 이메일 주소")
        tools = []

        # 1. Have I Been Pwned (HIBP)
        if 'hibp_api_key' in self.api_keys:
            def hibp_check(email: str) -> dict:
                """HIBP API 호출 래퍼 함수"""
                return external_api_clients.haveibeenpwnd_email_check(
                    ioc=email,
                    apikey=self.api_keys['hibp_api_key']
                )

            tools.append(StructuredTool.from_function(
                func=hibp_check,
                name="haveibeenpwned_check",
                description="""Check if email appears in known data breach databases.
                USE WHEN:
                - Investigating email security history
                - Assessing sender credibility in phishing investigations
                - Checking historical account compromise
                RETURNS: 
                 JSON with `breaches` (array of breach objects with Name/Date/DataClasses), 
                 `message` ("Not found in any breaches"), or `error`/`is_rate_limited` on failure.
                LIMIT: 1,500 req/day; returns 429 with retry_after on rate limit.
                DON'T USE: For real-time spam filtering (use EmailRep), bulk
                validation (rate limit), or as proof of current active compromise.""", args_schema=EmailInput
            ))

        # 2. EmailRep.io
        if 'emailrepio' in self.api_keys:
            def emailrep_check(email: str) -> dict:
                """EmailRep API 호출 래퍼 함수"""
                return external_api_clients.emailrep_email_check(
                    ioc=email,
                    apikey=self.api_keys['emailrepio']
                )

            tools.append(StructuredTool.from_function(
                func=emailrep_check,
                name="emailrep_reputation_check",
                description="""Analyze email reputation and suspicious activity indicators.
                USE WHEN:
                - Quick triage of email sender trustworthiness
                - Filtering spam/phishing emails in incident response
                - Assessing email-based threat priority
                RETURNS: JSON with `reputation` (high/medium/low/none), `suspicious`
                (bool), `references` (int), `details` object containing
                spam/malicious/credentials_leaked/data_breach/malware_delivery flags.
                LIMIT: 300 req/day; returns 429 on rate limit.
                DON'T USE: As definitive malware verdict without corroborating IOCs,
                for PII collection, or to replace multi-source validation.""", args_schema=EmailInput
            ))

        # 3. Hunter.io
        if 'hunterio_api_key' in self.api_keys:
            def hunter_verify(email: str) -> dict:
                """Hunter.io API 호출 래퍼 함수"""
                return external_api_clients.hunter_email_check(
                    ioc=email,
                    apikey=self.api_keys['hunterio_api_key']
                )

            tools.append(StructuredTool.from_function(
                func=hunter_verify,
                name="hunter_email_verification",
                description="""Verify email deliverability and discover domain-related intelligence.
                USE WHEN:
                - Verifying if email address actually exists
                - Finding other emails at target organization/domain
                - Expanding OSINT investigation from email to company infrastructure
                RETURNS: JSON with `status` (valid/invalid/accept_all/unknown),
                 `score` (0-100 confidence), `mx_records` (bool), `smtp_server` (bool),
                 `sources` (array of discovery sources), domain info.
                LIMIT: 50 req/month (free tier); returns 429 on rate limit.
                DON'T USE: For mass email harvesting, unsolicited outreach campaigns,
                SMTP probing at scale, or violating anti-scraping policies.""", args_schema=EmailInput
            ))

        return tools
    
    # 2. IP Tools (5개)
    def create_ip_tools(self) -> List[Tool]:
        """ 
        IP 주소 분석 도구 5개 생성
        Tools :
        1. AbuseIPDB - IP 악성 행위 신고 데이터베이스
        2. VirusTotal - IP 평판 및 악성 코드 연관성
        3. Shodan - IP 포트 및 서비스 정보
        4. CrowdSec - 커뮤니티 기반 IP 평판
        5. AlientVault OTX - 위협 인텔리전스 피드
         """
        # 입력 검증 스키마 (함수 내 중복 정의 방지)
        class IPInput(BaseModel):
            """IP 주소 입력 검증 (IPv4/IPv6 모두 지원)"""
            ip: IPvAnyAddress = Field(description="조사할 유효한 IPv4 또는 IPv6 주소")
        
        tools = []

        # 1. AbuseIPDB
        if 'abuseipdb' in self.api_keys:
            def abuseipdb_check(ip: str) -> dict:
                """AbuseIPDB API 호출 래퍼 함수"""
                return external_api_clients.abuseipdb_ip_check(
                    ioc=ip,
                    apikey=self.api_keys['abuseipdb']
                )

            tools.append(StructuredTool.from_function(
                func=abuseipdb_check,
                name="abuseipdb_check",
                description="""Check IP reputation and abuse reports from a community-driven database (AbuseIPDB).
                USE WHEN:
                - Investigating suspicious IPs found in logs/IR
                - Evaluating threat level before adding to firewall blacklists
                - Reviewing historical abuse patterns (port-scan, brute-force, spam)
                RETURNS:
                { "abuseConfidenceScore": int(0-100), "totalReports": int, "countryCode": str,
                "domain": str, "isp": str, "asn": str, "usageType": str,
                "reports": [ { "category": [int], "comment": str, "reportedAt": str } ] }

                LIMIT:
                Free tier daily quota; 429 on exceed. Community-driven → false positives possible
                (especially shared/VPN/CDN/hosting IPs).

                INTERPRETATION:
                Higher score = stronger signal, not absolute proof. Always check recency and categories,
                and corroborate with other sources.

                DON'T USE:
                As sole verdict, or to label shared/recycled IPs “malicious” without temporal/context data.
                """, args_schema=IPInput
            ))

        # 2. VirusTotal
        if 'virustotal' in self.api_keys:
            def  virustotal_ip_check(ip: str) -> dict:
                """VirusTotal IP API 호출 래퍼 함수"""
                return external_api_clients.virustotal(
                    ioc=ip,
                    apikey=self.api_keys['virustotal'],
                    type='ip' # IP 타입 명시
                )

            tools.append(StructuredTool.from_function(
                func=virustotal_ip_check,
                name="virustotal_ip_lookup",
                description="""Cross-validate IP reputation and relationships via multi-vendor telemetry (VirusTotal).
                USE WHEN:
                - Verifying suspicious IPs during malware/IOC analysis
                - Investigating C2 infrastructure, passive DNS, related domains/URLs/samples
                RETURNS:
                { "last_analysis_stats": { "malicious": int, "suspicious": int, "harmless": int, "undetected": int },
                "resolutions": [ { "hostname": str, "last_resolved": str } ],
                "detected_urls": [ { "url": str, "positives": int, "scan_date": str } ],
                "whois": str, "asn": str, "country": str,
                "detected_communicating_samples": [ { "sha256": str, "date": str } ] }
                LIMIT:
                Strict free-quota/rate limits (204/429 when exhausted). Zero/clean results ≠ safe; new/targeted
                threats can be missed.
                INTERPRETATION:
                Use as initial assessment and for correlation—not a final verdict. Consider time windows/caching.
                DON'T USE:
                As sole decision factor or for real-time guarantees (results can be delayed/cached).
                """, args_schema=IPInput
            ))
        
         # 3. Shodan
        if 'shodan' in self.api_keys:
            def shodan_ip_check(ip: str) -> dict:
                """Shodan API 호출 래퍼 함수"""
                return external_api_clients.check_shodan(
                    ioc=ip,
                    apikey=self.api_keys['shodan'],
                    method='ip'  # IP 검색 모드
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
                { "ports": [int], "hostnames": [str],
                "services": [ { "port": int, "product": str, "version": str, "banner": str, "ssl": { ... } } ],
                "vulns": [ "CVE-..." ], "org": str, "asn": str,
                "location": { "country": str, "city": str, "lat": float, "lon": float }, "os": str, "tags": [str] }
                LIMIT:
                Free tier heavily restricted; historical data lag (weeks–months). No internal/private IP coverage.
                INTERPRETATION:
                Validate whether exposures are intentional. Pay attention to expired certs, unexpected open ports,
                default configs.
                DON'T USE:
                For active scanning or real-time port state; for RFC1918/internal ranges; or for misuse (responsible use).
                """, args_schema=IPInput
            ))

        # 4. CrowdSec
        if 'crowdsec' in self.api_keys:
            def crowdsec_check(ip: str) -> dict:
                """CrowdSec API 호출 래퍼 함수"""
                return external_api_clients.crowdsec(
                    ioc=ip,
                    apikey=self.api_keys['crowdsec']
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
                "reputation": "malicious|suspicious|safe", "confidence": int(0-100),
                "seen_by": int, "first_seen": str, "last_seen": str }
                LIMIT:
                Free tier has retention/coverage constraints; 429 on exceed. Regional coverage may vary.
                INTERPRETATION:
                Combine confidence with seen_by (wider consensus = stronger signal). Corroborate with local telemetry.
                DON'T USE:
                As sole blocking criterion, in regions with low coverage, or for long-range (beyond retention) history.
                """, args_schema=IPInput
            ))
        
        # 5. AlienVault OTX
        if 'alienvault' in self.api_keys:
            def alienvault_ip_check(ip: str) -> dict:
                """AlienVault OTX API 호출 래퍼 함수"""
                return external_api_clients.alienvaultotx(
                    ioc=ip,
                    apikey=self.api_keys['alienvault'],
                    type='ip'  # IP 타입 명시
                )

            tools.append(StructuredTool.from_function(
                func=alienvault_ip_check,
                name="alienvault_ip_intelligence",
                description="""Enrich IP with AlienVault OTX pulses: community threat reports and related IOCs.
                USE WHEN:
                 - Adding campaign/actor context (tags/TLP/industries) to an IP
                 - Expanding to related indicators (domains/URLs/hashes) and passive DNS
                RETURNS:
                { "pulses": [ { "name": str, "description": str, "tags": [str], "indicators": [ ... ] } ],
                "related_indicators": [ { "type": "domain|url|hash", "value": str } ],
                "passive_dns": [ { "hostname": str, "last_seen": str } ],
                "asn": str, "geo": { "country": str } }
                LIMIT:
                Free quota/rate limits; community quality varies and updates can lag.
                INTERPRETATION:
                Prefer multiple/verified pulses and recent updates; use cross-source consensus.
                DON'T USE:
                As a real-time blocking source or single-source truth for attribution.
                """, args_schema=IPInput
            ))
        
        return tools

    
    # 3. Domain Tools (3개)
    def create_domain_tools(self) -> List[Tool]:
        """ 
        도메인 분석 도구 3개 생성 
        Tools :
        1. VirusTotal - 도메인 평판 및 관계 분석
        2. Google Safe Browsing - 악성 도메인 탐지
        3. URLScan.io - 도메인 스캔 및 스크린샷
        """
        # 입력 검증 스키마
        class DomainInput(BaseModel):
            """ 도메인 입력 검증 """
            domain: str = Field(description="조사할 유효한 도메인 이름 (예: example.com)")
        tools = []

        # 1. VirusTotal
        if 'virustotal' in self.api_keys:
            def virustotal_domain_check(domain: str) -> dict:
                """VirusTotal 도메인 API 호출 래퍼 함수"""
                return external_api_clients.virustotal(
                    ioc=domain,
                    apikey=self.api_keys['virustotal'],
                    type='domain' # 도메인 타입 명시
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
                "categories": {}, "dns_records": {}, "subdomains": [],
                "whois": str, "detected_urls": [] }
                INTERPRETATION:
                0/70=clean, 50+/70=high-risk. Check Relations tab for pivot points.
                Recent registration + low popularity + detections = likely malicious.
                LIMITS: Rate limit 204/429. May miss zero-hour threats.
                """, args_schema=DomainInput
            ))
        
        # 2. Google Safe Browsing
        if 'safeBrowse' in self.api_keys:
            def safebrowsing_domain_check(domain: str) -> dict:
                """Google Safe Browsing API 호출 래퍼 함수 (도메인 체크용으로 URL 형식 변환)"""
                # Safe Browsing API는 URL 단위로 체크하므로 도메인을 URL로 변환해야 한다.
                url = f"http://{domain}"
                return external_api_clients.safeBrowse_url_check(
                    ioc=url,
                    apikey=self.api_keys['safeBrowse']
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
                { "matches": [ { "threatType": "MALWARE|SOCIAL_ENGINEERING",
                "threat": { "url": str } } ] }
                Empty matches = not blacklisted (≠safe).
                USE CASE: Gmail Enhanced Safe Browsing, Chrome Enterprise blocking.
                LIMITS: Daily quota. Conservative detection (new threats delayed).
                """, args_schema=DomainInput
            ))

        # 3. URLScan.io 
        # URLScan.io의 Search API는 완전 무료이고 API 키가 선택 사항이므로 무조건 추가
        def urlscan_domain_check(domain: str) -> dict:
            """URLScan.io API 호출 래퍼 함수"""
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
            { "results": [{ "page": {}, "screenshot": url, "stats": {} }] }
            INTERPRETATION: Check screenshots for visual deception, POST requests for data theft.
            LIMITS: Free tier rate limits. No real-time scanning without API key.
            """, args_schema=DomainInput
        ))
        return tools
    
    # 4. Hash Tools (3개)
    def create_hash_tools(self) -> List[Tool]:
        """
        해시 분석 도구 3개 생성
        Tools:
        1. VirusTotal - 멀티 AV 엔진 파일 분석
        2. MalwareBazaar - 멀웨어 샘플 DB 검색
        3. ThreatFox - IOC 위협 인텔리전스
        """
        tools = []

        # Pydantic 입력 스키마 (해시 검증)
        class HashInput(BaseModel):
            hash_value: str = Field(
                description="파일 해시 (MD5, SHA1, SHA256 형식). 예: a1b2c3d4e5f6..."
            )

        # 1. VirusTotal Hash Check
        if 'virustotal' in self.api_keys:
            def virustotal_hash_check(hash_value: str) -> dict:
                """VirusTotal 멀티 AV 엔진 파일 해시 분석"""
                return external_api_clients.virustotal(
                    ioc=hash_value,
                    type='hash',
                    apikey=self.api_keys['virustotal']
                )

            tools.append(StructuredTool.from_function(
                func=virustotal_hash_check,
                name="virustotal_hash_lookup",
                description="""Multi-AV(70+) hash reputation & behavior analysis.
                USE WHEN:
                - Quick malicious verdict needed
                - Engine-wise detections/community comments/relations(IP·domain) required
                - IR metadata(first/last_seen) fast retrieval
                RETURNS:
                - last_analysis_stats(detection ratio), file meta(name/size/type), behavior(network·file·registry), relation graph, comments/reputation
                LIMITS:
                - Public: ~4 req/min, ~500 req/day (subject to change)
                - Hash-only lookup recommended (no upload for policy compliance)
                DON'T USE:
                - Novel/unregistered hash(may return empty)
                - Already confirmed malicious by internal/MBZ(save quota)
                WORKFLOW: MalwareBazaar(free screening) → VirusTotal(accurate verdict) → extract relations(IP·domain) → expand IOCs""", args_schema=HashInput
            ))

        # 2. MalwareBazaar Hash Check (무료, API 키 불필요)
        def malwarebazaar_hash_check(hash_value: str) -> dict:
            """MalwareBazaar 멀웨어 샘플 DB 검색"""
            return external_api_clients.malwarebazaar_hash_check(ioc=hash_value)

        tools.append(StructuredTool.from_function(
            func=malwarebazaar_hash_check,
            name="malwarebazaar_hash_lookup",
            description="""abuse.ch community malware sample DB lookup(free/no key).
            USE WHEN:
            - 1st-pass 'known sample' screening(save VT quota)
            - Family/tags/signature(YARA)·first/last_seen needed
            RETURNS:
            - family/alias, tags, file_type/name/size, first_seen/last_seen, signature(YARA), (research) download link
            LIMITS:
            - Free, minimal rate limit(service quality consideration)
            DON'T USE:
            - Benign files(mostly unregistered)
            - Zero-day/very recent samples(update lag possible)
            WORKFLOW: Use as first-pass filter → if matched, get family/tags → proceed to VT for detailed analysis""", args_schema=HashInput
        ))

        # 3. ThreatFox Hash Check
        if 'threatfox' in self.api_keys:
            def threatfox_hash_check(hash_value: str) -> dict:
                """ThreatFox IOC 위협 인텔리전스 검색"""
                return external_api_clients.threatfox_ip_check(
                    ioc=hash_value,
                    apikey=self.api_keys['threatfox']
                )

            tools.append(StructuredTool.from_function(
                func=threatfox_hash_check,
                name="threatfox_hash_lookup",
                description="""abuse.ch ThreatFox IOC DB hash-based threat intel lookup.
                USE WHEN:
                - Hash ↔ campaign/family mapping, C2/payload type identification
                - Latest intel(confidence/first_seen/tags) for rule enrichment
                RETURNS:
                - malware_alias/printable, threat_type(payload/c2 etc), confidence_level, first_seen, tags, reference links
                LIMITS:
                - Free, minor rate limit exists(public figures vary)
                DON'T USE:
                - Old sample long-term history(focus on recent threats)
                - Simple sample meta only(→ MBZ first)
                WORKFLOW: Use after MBZ/VT for campaign context → extract C2 servers/domains → expand IOCs for infrastructure mapping""", args_schema=HashInput
            ))

        return tools
    
    # 5. URL Tools (1개)
    def create_url_tools(self) -> List[Tool]:
        """
        URL 분석 도구 1개 생성
        Tools:
        1. URLhaus - abuse.ch 악성 URL 데이터베이스
        """
        tools = []

        # Pydantic 입력 스키마 (URL 검증)
        class URLInput(BaseModel):
            url: str = Field(
                description="조사할 URL (전체 URL 형식). 예: https://example.com/path"
            )

        # 1. URLhaus URL Check (무료, API 키 불필요)
        def urlhaus_url_check(url: str) -> dict:
            """URLhaus 악성 URL 데이터베이스 검색"""
            return external_api_clients.urlhaus_url_check(ioc=url)

        tools.append(StructuredTool.from_function(
            func=urlhaus_url_check,
            name="urlhaus_url_lookup",
            description="""abuse.ch URLhaus malicious-URL DB lookup (free/no key).
            USE WHEN:
            - Verify phishing/malware-distribution URLs; need payload/hash/tags
            fast
            - Quick prescreen before VT/URLScan; save higher-cost quotas
            RETURNS:
            - url_status(online/offline), threat(malware_download/phishing), tags
            - payload_hash/filename/signature, reporter, first_seen/last_online
            - host/domain, referenced URLhaus ID(s)
            LIMITS:
            - Free; fair-use rate limits; coverage may lag for brand-new URLs
            DON'T USE:
            - Benign/internal links as "reputation" source (mostly not indexed)
            WORKFLOW:
            - URLhaus prescreen → if hit: enrich payload/threat fields
            - Extract host/domain → DomainAgent (DNS/WHOIS/relations)
            - Extract IPs → IPAgent (infra map, ASN/risk score)""", args_schema=URLInput
        ))

        return tools
    
    # 6. GitHub Tools (1개)
    def create_github_tools(self) -> List[Tool]:
        """
        GitHub 분석 도구 1개 생성
        Tools:
        1. GitHub Code Search - IOC가 코드에 하드코딩된 경우 검색
        """
        tools = []

        # Pydantic 입력 스키마 (GitHub 검색)
        class GitHubInput(BaseModel):
            ioc: str = Field(
                description="검색할 IOC (IP, domain, email, API key 등). 예: 192.168.1.1"
            )

        # 1. GitHub Code Search
        if 'github_pat' in self.api_keys:
            def github_code_search(ioc: str) -> dict:
                """GitHub 코드 저장소에서 IOC 검색"""
                return external_api_clients.search_github(
                    ioc=ioc,
                    access_token=self.api_keys['github_pat']
                )

            tools.append(StructuredTool.from_function(
                func=github_code_search,
                name="github_code_search",
                description="""GitHub code IOC/secret search (public repos).
                USE WHEN:
                - Hardcoded creds/C2 IPs/leaked secrets/API keys
                RETURNS:
                - total_count, items[repo/path/snippet/lines/sha/score]
                LIMITS:
                - 30/min PAT (10 unauth); max 1k results; default branch only; <384KB
                file
                DON'T USE:
                - Common strings (false positives); private repos (need org access)
                INTERPRET:
                - score → sha age → code context → repo owner reputation
                WORKFLOW:
                - Search IOC → identify repos/owners → extract related IOCs → expand investigation""", args_schema=GitHubInput
            ))

        return tools
    
    # 7. Misc Tools (4개) 기타 도구들
    def create_misc_tools(self) -> List[Tool]:
        """
        기타 분석 도구 4개 생성
        Tools:
        1. BGPView - IP BGP/ASN 정보, IP 인프라 귀속 분석
        2. NIST NVD - CVE 취약점 검색
        3. Pulsedive - 종합 위협 인텔리전스
        4. Reddit - 소셜 미디어 OSINT
        """
        tools = []

        # Pydantic 입력 스키마들
        class IPInput(BaseModel):
            ip: str = Field(
                description="조사할 IP 주소. 예: 8.8.8.8"
            )

        class CVEInput(BaseModel):
            cve_id: str = Field(
                description="CVE 식별자. 예: CVE-2021-44228"
            )

        class IOCInput(BaseModel):
            ioc: str = Field(
                description="조사할 IOC (IP, domain, hash, URL 등)"
            )

        # 1. BGPView (무료, API 키 불필요)
        # 해당 IP가 누구 소유의 IP 인가를 판단한다. 
        def bgpview_check(ip: str) -> dict:
            """BGPView IP BGP/ASN 정보 검색"""
            return external_api_clients.check_bgpview(ioc=ip)

        tools.append(StructuredTool.from_function(
            func=bgpview_check,
            name="bgpview_ip_lookup",
            description="""BGPView — IP→BGP/ASN intel (free/no key)
            USE WHEN: map IP→ASN/ISP & prefixes; infra attribution; range expand
            RETURNS: asn{num,name,country,alloc_at}; prefixes[]; rir;
            peering/ix(if any); ptr
            LIMITS: fair-use; 429 on bursts→≥2s backoff; data may lag; BGP is
            observational
            DON'T USE: RFC1918/unrouted; as ownership proof (cross-check
            RDAP/WHOIS)
            INTERPRET: ASN≠owner; use upstream/downstream to infer provider/scale
            FLOW: IPAgent→BGPView→RDAP/WHOIS cross-check→expand by
            ASN/prefix→pattern hunt
            TIPS: cache results; retry+backoff; fallback: HE BGP Toolkit /
            RIPEstat / Team Cymru""", args_schema=IPInput
        ))

        # 2. NIST NVD CVE Search
        # 공격 대상의 취약점을 분석한다.
        if 'nist_nvd_api_key' in self.api_keys:
            def nist_nvd_search(cve_id: str) -> dict:
                """NIST NVD CVE 취약점 정보 검색"""
                return external_api_clients.search_nist_nvd(
                    ioc=cve_id,
                    apikey=self.api_keys['nist_nvd_api_key'] 
                )

            tools.append(StructuredTool.from_function(
                func=nist_nvd_search,
                name="nist_nvd_cve_lookup",
                description="""NIST NVD — CVE intel (free / key-optional)
                USE WHEN: CVE details/CVSS; affected products/versions; exploit refs
                RETURNS: desc; cvss{v2,v3,vector,severity}; CPE[affected products]; refs; published/modified
                LIMITS: 5/30s(no key) → 50/30s(key); add ≥6s backoff; paging ≤~2000; 403/429 on exceed; NVD lag(24–48h)
                DON’T USE: non-CVE IDs (use vendor advisories); real-time 0-days
                INTERPRET: CVSS ≠ exploitability → check EPSS/CISA KEV; prefer v3 over v2
                FLOW: scan/log → extract CVE → NVD lookup → CPE match → HashAgent(exploit/patch) → action
                TIPS: batch+cache; retry on 429; alt: CVE.org / vendor advisories""", args_schema=CVEInput
            ))

        # 3. Pulsedive Threat Intel
        # 종합 위협 인텔리전스 플랫폼. 여러 피드를 하나로 통합한다. 
        if 'pulsedive' in self.api_keys:
            def pulsedive_check(ioc: str) -> dict:
                """Pulsedive 종합 위협 인텔리전스 검색"""
                return external_api_clients.check_pulsedive(
                    ioc=ioc,
                    apikey=self.api_keys['pulsedive']
                )

            tools.append(StructuredTool.from_function(
                func=pulsedive_check,
                name="pulsedive_ioc_lookup",
                description="""Pulsedive — multi-feed IOC threat intel (API key req.)
                USE WHEN: SIEM/SOAR enrichment; IR quick risk/classification; hunting bulk analyze
                RETURNS: risk{score(0-100),factors}; indicator_type;
                analysis{passive(WHOIS/DNS),active(HTTP/SSL/ports)};
                threats/campaigns; tags/refs; JSON/CSV/STIX
                LIMITS: Free 30 req/min, 1000 req/day; plan-based quotas; rate-limit
                headers; active scans take seconds; community-fed→verify with other sources
                DON'T USE: as sole reputation source; deep historical analytics
                (limited retention)
                INTERPRET: ≥80 high-risk/act; 50-79 investigate; <50 monitor; combine with VT/AbuseIPDB consensus
                FLOW: primary checks(VT/AbuseIPDB/URLhaus)→Pulsedive enrich→pull
                campaigns/attrs→pivot/expand
                TIPS: batch & cache; backoff on 429; log remaining quota from headers; prefer JSON over CSV for automation""", args_schema=IOCInput
            ))

        # 4. Reddit Search
        # 커뮤니티 논의에서 IOC 언급/관련 인시던트 검색
        if 'reddit_cid' in self.api_keys and  'reddit_cs' in self.api_keys:
            def reddit_search(ioc: str) -> dict:
                """Reddit 소셜 미디어 OSINT 검색"""
                return external_api_clients.search_reddit(
                    ioc=ioc,
                    client_id=self.api_keys['reddit_cid'],
                    client_secret=self.api_keys['reddit_cs']
                )

            tools.append(StructuredTool.from_function(
                func=reddit_search,
                name="reddit_ioc_search",
                description="""Reddit — social OSINT (OAuth req: client_id/secret)
                USE WHEN: community discussions/incident reports; victim/researcher mentions in r/netsec, r/cybersecurity; hacker chatter in underground subreddits; early threat signals
                RETURNS: posts[{title,selftext,author,subreddit,score,created_utc,url, num_comments}]; comments; permalink (JSON)
                LIMITS: OAuth 60 req/min; user_agent required; page≈25;
                private/restricted subs blocked; token refresh every 60min; 429 on bulk
                DON'T USE: as technical reputation source (use threat intel feeds);
                real-time IR (posting lag); deleted/removed content
                INTERPRET: score+comments+recency for signal strength; check author history (karma/age); use hour/day time filter for fresh signals; underground subs may use code/slang 
                FLOW: After technical analysis→Reddit for community context→identify related incidents→extract additional IOCs from discussions
                TIPS: batch & cache; backoff on 429; store post IDs for dedup; search r/blueteam, r/asknetsec for defensive context""", args_schema=IOCInput
            ))

        return tools
    
    # 통합 메서드
    def create_all_tools(self) -> List[Tool]:
        """
        모든 카테고리의 도구를 생성하여 통합 리스트로 반환.
        Returns:
            List[Tool]: 모든 18개 LangChain Tool 객체 리스트
        """
        all_tools = []
        all_tools.extend(self.create_email_tools())
        all_tools.extend(self.create_ip_tools())
        all_tools.extend(self.create_domain_tools())
        all_tools.extend(self.create_hash_tools())
        all_tools.extend(self.create_url_tools())
        all_tools.extend(self.create_github_tools())
        all_tools.extend(self.create_misc_tools())
        
        return all_tools
    
    def get_tools_summary(self) -> Dict[str, Any]:
        """
        사용 가능한 도구 요약 정보
        Returns:
            도구 개수, 이름, 누락된 API 키 등의 정보
        """
        all_tools = self.create_all_tools()
        return {
            "total_tools": len(all_tools),
            "tool_names": [tool.name for tool in all_tools],
            "missing_api_keys": self._get_missing_keys(),
            "categories": {
                  "email": len(self.create_email_tools()),
                  "ip": len(self.create_ip_tools()),
                  "domain": len(self.create_domain_tools()),
                  "hash": len(self.create_hash_tools()),
                  "url": len(self.create_url_tools()),
                  "github": len(self.create_github_tools()),
                  "misc": len(self.create_misc_tools()),
                }
        }
