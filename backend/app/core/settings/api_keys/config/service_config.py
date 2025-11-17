from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

class ServiceTier(str, Enum):
    FREE = "free"
    PAID = "paid"
    FREEMIUM = "freemium"

@dataclass
class ServiceDefinition:
    """Service configuration definition"""
    name: str
    key: str  # Internal key used for API calls
    description: str
    documentation_url: str
    supported_ioc_types: List[str]
    required_keys: List[str]
    tier: ServiceTier
    category: str
    icon: str
    is_active: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)

class ServiceCategory(str, Enum):
    THREAT_INTELLIGENCE = "threat_intelligence"
    SECURITY_SCANNING = "security_scanning"
    EMAIL_IDENTITY = "email_identity"
    DEVELOPMENT_RESEARCH = "development_research"
    SOCIAL_MEDIA = "social_media"
    NETWORK_INFRASTRUCTURE = "network_infrastructure"

# Service definitions
SERVICE_DEFINITIONS = {
    "abuseipdb": ServiceDefinition(
        name="AbuseIPDB",
        key="abuseipdb",
        description="온라인 공격과 관련된 악성 IP 주소를 보고하고 식별하는 중앙 저장소",
        documentation_url="https://www.abuseipdb.com/api",
        supported_ioc_types=["IPv4", "IPv6"],
        required_keys=["abuseipdb"],
        tier=ServiceTier.FREE,
        category=ServiceCategory.THREAT_INTELLIGENCE,
        icon="aipdb_logo_small"
    ),
    "alienvault": ServiceDefinition(
        name="AlienVault OTX",
        key="alienvault",
        description="새로운 위협 및 공격 방법을 공유하는 협업 위협 인텔리전스 플랫폼",
        documentation_url="https://otx.alienvault.com/api",
        supported_ioc_types=["IPv4", "IPv6", "Domain", "URL", "MD5", "SHA1", "SHA256"],
        required_keys=["alienvault"],
        tier=ServiceTier.FREE,
        category=ServiceCategory.THREAT_INTELLIGENCE,
        icon="avotx_logo_small"
    ),
    "bgpview": ServiceDefinition(
        name="BGPView",
        key="bgpview",
        description="네트워크 인텔리전스 및 IP 주소 조사를 위한 BGP 라우팅 정보 및 ASN 조회 서비스",
        documentation_url="https://bgpview.docs.apiary.io/",
        supported_ioc_types=["IPv4", "IPv6", "ASN"],
        required_keys=["bgpview"],
        tier=ServiceTier.FREEMIUM,
        category=ServiceCategory.NETWORK_INFRASTRUCTURE,
        icon="bgpview_logo_small"
    ),
    "checkphishai": ServiceDefinition(
        name="CheckPhish.ai",
        key="checkphish",
        description="도메인 모니터링, 이메일 링크 보호, 피싱 탐지를 위한 무료 도구",
        documentation_url="https://checkphish.ai/docs/checkphish-api/",
        supported_ioc_types=["IPv4", "Domain", "URL"],
        required_keys=["checkphishai"],
        tier=ServiceTier.FREE,
        category=ServiceCategory.SECURITY_SCANNING,
        icon="checkphish_logo_small"
    ),
    "crowdsec": ServiceDefinition(
        name="CrowdSec",
        key="crowdsec",
        description="전 세계 사용자들의 데이터를 기반으로 맥락화된 인사이트를 제공하는 대규모 위협 인텔리전스 네트워크",
        documentation_url="https://app.crowdsec.net/settings/api-keys",
        supported_ioc_types=["IPv4"],
        required_keys=["crowdsec"],
        tier=ServiceTier.FREE,
        category=ServiceCategory.THREAT_INTELLIGENCE,
        icon="crowdsec_logo_small"
    ),
    "github": ServiceDefinition(
        name="GitHub",
        key="github",
        description="분산 버전 관리를 통해 코드를 생성, 저장, 관리 및 공유하는 개발자 플랫폼",
        documentation_url="https://docs.github.com/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
        supported_ioc_types=["IPv4", "IPv6", "Domain", "URL", "Email", "MD5", "SHA1", "SHA256", "CVE"],
        required_keys=["github_pat"],
        tier=ServiceTier.FREE,
        category=ServiceCategory.DEVELOPMENT_RESEARCH,
        icon="github_logo_small"
    ),
    "safebrowse": ServiceDefinition(
        name="Google Safe Browsing",
        key="safeBrowse",
        description="위험한 사이트 및 악성 다운로드에 대해 사용자에게 경고하여 수십억 대의 기기를 보호하는 Google 서비스",
        documentation_url="https://developers.google.com/safe-browsing/v4/get-started",
        supported_ioc_types=["Domain", "URL"],
        required_keys=["safeBrowse"],
        tier=ServiceTier.FREE,
        category=ServiceCategory.SECURITY_SCANNING,
        icon="safeBrowse_logo_small"
    ),
    "haveibeenpwned": ServiceDefinition(
        name="Have I Been Pwned",
        key="haveibeenpwned",
        description="여러 데이터 유출 사고를 검색하여 이메일 주소나 전화번호가 유출되었는지 확인하는 서비스",
        documentation_url="https://haveibeenpwned.com/API/v3#Authorisation",
        supported_ioc_types=["Email"],
        required_keys=["hibp_api_key"],
        tier=ServiceTier.PAID,
        category=ServiceCategory.EMAIL_IDENTITY,
        icon="hibp_logo_small"
    ),
    "hunterio": ServiceDefinition(
        name="Hunter.io",
        key="hunterio",
        description="연락처 정보를 찾고 콜드 이메일 캠페인을 관리하는 종합 이메일 아웃리치 플랫폼",
        documentation_url="https://hunter.io/api",
        supported_ioc_types=["Email"],
        required_keys=["hunterio_api_key"],
        tier=ServiceTier.FREEMIUM,
        category=ServiceCategory.EMAIL_IDENTITY,
        icon="hunterio_logo_small"
    ),
    "ipqualityscore": ServiceDefinition(
        name="IPQualityScore",
        key="ipqualityscore",
        description="다양한 위험 신호를 측정하여 비즈니스를 보호하는 고급 사기 방지 및 보안 플랫폼",
        documentation_url="https://www.ipqualityscore.com/documentation/overview",
        supported_ioc_types=["IPv4", "IPv6"],
        required_keys=["ipqualityscore"],
        tier=ServiceTier.FREEMIUM,
        category=ServiceCategory.SECURITY_SCANNING,
        icon="ipqualityscore_logo_small"
    ),
    "maltiverse": ServiceDefinition(
        name="Maltiverse",
        key="maltiverse",
        description="100개 이상의 공개, 비공개 및 커뮤니티 소스에서 데이터를 집계하는 위협 인텔리전스 브로커",
        documentation_url="https://app.swaggerhub.com/apis-docs/maltiverse/api/1.1",
        supported_ioc_types=["IPv4", "IPv6", "Domain", "URL", "MD5", "SHA1", "SHA256"],
        required_keys=["maltiverse"],
        tier=ServiceTier.FREEMIUM,
        category=ServiceCategory.THREAT_INTELLIGENCE,
        icon="maltiverse_logo_small"
    ),
    "malwarebazaar": ServiceDefinition(
        name="MalwareBazaar",
        key="malwarebazaar",
        description="멀웨어 분석 및 위협 연구를 위한 abuse.ch의 무료 멀웨어 샘플 저장소",
        documentation_url="https://bazaar.abuse.ch/api/",
        supported_ioc_types=["MD5", "SHA1", "SHA256"],
        required_keys=['malwarebazaar'],
        tier=ServiceTier.FREEMIUM,
        category=ServiceCategory.THREAT_INTELLIGENCE,
        icon="malwarebazaar_logo_small"
    ),
    "nistnvd": ServiceDefinition(
        name="NIST NVD",
        key="nistnvd",
        description="SCAP 프로토콜을 사용하는 표준 기반 취약점 관리 데이터의 미국 정부 저장소",
        documentation_url="https://nvd.nist.gov/developers/request-an-api-key",
        supported_ioc_types=["CVE"],
        required_keys=["nist_nvd_api_key"],
        tier=ServiceTier.FREE,
        category=ServiceCategory.DEVELOPMENT_RESEARCH,
        icon="nistnvd_logo_small"
    ),
    "openai": ServiceDefinition(
        name="OpenAI",
        key="openai",
        description="AI 기반 기능 및 지능형 분석을 위한 고급 대규모 언어 모델 액세스",
        documentation_url="https://platform.openai.com/account/api-keys",
        supported_ioc_types=["AI Features"],
        required_keys=["openai"],
        tier=ServiceTier.PAID,
        category=ServiceCategory.DEVELOPMENT_RESEARCH,
        icon="openai_logo_small"
    ),
    "gemini": ServiceDefinition(
        name="Google Gemini",
        key="gemini",
        description="Google의 멀티모달 AI 모델을 활용한 고급 분석 및 컨텐츠 생성 기능",
        documentation_url="https://ai.google.dev/gemini-api/docs/api-key",
        supported_ioc_types=["AI Features"],
        required_keys=["gemini"],
        tier=ServiceTier.FREEMIUM,
        category=ServiceCategory.DEVELOPMENT_RESEARCH,
        icon="gemini_logo_small"
    ),
    "claude": ServiceDefinition(
        name="Anthropic Claude",
        key="claude",
        description="Anthropic의 Claude AI를 활용한 안전하고 정확한 분석 및 추론 기능",
        documentation_url="https://console.anthropic.com/settings/keys",
        supported_ioc_types=["AI Features"],
        required_keys=["claude"],
        tier=ServiceTier.PAID,
        category=ServiceCategory.DEVELOPMENT_RESEARCH,
        icon="claude_logo_small"
    ),
    "pulsedive": ServiceDefinition(
        name="Pulsedive",
        key="pulsedive",
        description="OSINT 피드에서 IOC를 검색, 스캔 및 보강하는 무료 위협 인텔리전스 플랫폼",
        documentation_url="https://pulsedive.com/api/",
        supported_ioc_types=["IPv4", "IPv6", "Domain", "URL", "MD5", "SHA1", "SHA256"],
        required_keys=["pulsedive"],
        tier=ServiceTier.FREE,
        category=ServiceCategory.THREAT_INTELLIGENCE,
        icon="pulsedive_logo_small"
    ),
    "reddit": ServiceDefinition(
        name="Reddit",
        key="reddit",
        description="위협 인텔리전스 및 소셜 미디어 모니터링을 위한 Reddit의 커뮤니티 네트워크 액세스",
        documentation_url="https://www.reddit.com/dev/api/",
        supported_ioc_types=["IPv4", "IPv6", "Domain", "URL", "Email", "MD5", "SHA1", "SHA256", "CVE"],
        required_keys=["reddit_cid", "reddit_cs"],
        tier=ServiceTier.FREE,
        category=ServiceCategory.SOCIAL_MEDIA,
        icon="reddit_logo_small"
    ),
    "shodan": ServiceDefinition(
        name="Shodan",
        key="shodan",
        description="인터넷 연결 장치를 위한 세계 최초의 검색 엔진, 포괄적인 장치 인텔리전스 제공",
        documentation_url="https://developer.shodan.io/api/requirements",
        supported_ioc_types=["IPv4", "IPv6", "Domain", "URL"],
        required_keys=["shodan"],
        tier=ServiceTier.FREEMIUM,
        category=ServiceCategory.NETWORK_INFRASTRUCTURE,
        icon="shodan_logo_small"
    ),
    "threatfox": ServiceDefinition(
        name="ThreatFox",
        key="threatfox",
        description="다양한 위협 소스의 침해 지표(IOC) 공유에 초점을 맞춘 Abuse.ch 프로젝트",
        documentation_url="https://threatfox.abuse.ch/api/",
        supported_ioc_types=["IPv4", "IPv6", "Domain", "URL", "MD5", "SHA1", "SHA256"],
        required_keys=["threatfox"],
        tier=ServiceTier.FREE,
        category=ServiceCategory.THREAT_INTELLIGENCE,
        icon="threatfox_logo_small"
    ),
    "urlhaus": ServiceDefinition(
        name="URLhaus",
        key="urlhaus",
        description="악성 웹사이트 추적 및 분석을 위한 abuse.ch의 무료 악성 URL 저장소",
        documentation_url="https://urlhaus-api.abuse.ch/",
        supported_ioc_types=["URL", "Domain"],
        required_keys=["urlhaus"],
        tier=ServiceTier.FREEMIUM,
        category=ServiceCategory.THREAT_INTELLIGENCE,
        icon="urlhaus_logo_small"
    ),
    "urlscanio": ServiceDefinition(
        name="URLScan.io",
        key="urlscanio",
        description="상세한 분석을 통해 의심스럽고 악성인 URL을 식별하도록 특별히 설계된 웹사이트 스캐너",
        documentation_url="https://urlscan.io/docs/api/",
        supported_ioc_types=["Domain", "URL", "IPv4"],
        required_keys=["urlscanio"],
        tier=ServiceTier.FREEMIUM,
        category=ServiceCategory.SECURITY_SCANNING,
        icon="urlscanio_logo_small"
    ),
    "virustotal": ServiceDefinition(
        name="VirusTotal",
        key="virustotal",
        description="70개 이상의 안티바이러스 스캐너 및 URL/도메인 차단 목록 서비스를 사용하는 종합 멀웨어 분석 서비스",
        documentation_url="https://developers.virustotal.com/reference/overview",
        supported_ioc_types=["IPv4", "IPv6", "Domain", "URL", "MD5", "SHA1", "SHA256"],
        required_keys=["virustotal"],
        tier=ServiceTier.FREEMIUM,
        category=ServiceCategory.THREAT_INTELLIGENCE,
        icon="vt_logo_small"
    ),
}

def get_service_definition(service_key: str) -> Optional[ServiceDefinition]:
    """Get a specific service definition by key"""
    return SERVICE_DEFINITIONS.get(service_key)

def get_all_service_definitions() -> Dict[str, ServiceDefinition]:
    """Get all service definitions"""
    return SERVICE_DEFINITIONS

def get_services_by_category(category: ServiceCategory) -> Dict[str, ServiceDefinition]:
    """Get all services in a specific category"""
    return {
        key: service for key, service in SERVICE_DEFINITIONS.items()
        if service.category == category
    }

def get_services_by_tier(tier: ServiceTier) -> Dict[str, ServiceDefinition]:
    """Get all services of a specific tier"""
    return {
        key: service for key, service in SERVICE_DEFINITIONS.items()
        if service.tier == tier
    }

def get_services_for_ioc_type(ioc_type: str) -> Dict[str, ServiceDefinition]:
    """Get all services that support a specific IOC type"""
    return {
        key: service for key, service in SERVICE_DEFINITIONS.items()
        if ioc_type in service.supported_ioc_types
    }

def get_required_keys_for_service(service_key: str) -> List[str]:
    """Get required API keys for a specific service"""
    service = get_service_definition(service_key)
    return service.required_keys if service else []