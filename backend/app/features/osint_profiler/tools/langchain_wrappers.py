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
from pydantic import BaseModel, Field, EmailStr # EmilStr: 이메일 형식 검증용
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
        """ IP 분석 도구 5개 생성 """
        # TODO : Step 5에서 구현
        return []
    
    # 3. Domain Tools (3개)
    def create_domain_tools(self) -> List[Tool]:
        """ 도메인 분석 도구 3개 생성 """
        # TODO : Step 6에서 구현
        return []
    
    # 4. Hash Tools (3개)
    def create_hash_tools(self) -> List[Tool]:
        """ 해시 분석 도구 3개 생성 """
        # TODO : Step 7에서 구현
        return []
    
    # 5. URL Tools (1개)
    def create_url_tools(self) -> List[Tool]:
        """ URL 분석 도구 1개 생성 """
        # TODO : Step 8에서 구현
        return []
    
    # 6. GitHub Tools (1개)
    def create_github_tools(self) -> List[Tool]:
        """ GitHub 분석 도구 1개 생성 """
        # TODO : Step 9에서 구현
        return []
    
    # 7. Misc Tools (4개)
    def create_misc_tools(self) -> List[Tool]:
        """ 기타 분석 도구 4개 생성 """
        # TODO : Step 10에서 구현
        return []
    
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
