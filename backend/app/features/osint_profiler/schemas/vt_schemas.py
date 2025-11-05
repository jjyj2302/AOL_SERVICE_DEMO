"""
VirusTotal API 응답 필터링을 위한 Pydantic 스키마

목표:
1. 토큰 사용량 95% 감소 (8000 → 400 tokens)
2. IOC 확장 필드 포함 (communicating_files, resolutions)
3. LLM 친화적 마크다운 출력 지원
4. 타입 안전성 보장
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime


# ========================================
# 공통 Base Models
# ========================================

class VTAnalysisStats(BaseModel):
    """
    VirusTotal 위협 탐지 통계 (공통)

    모든 VT 응답에서 사용되는 핵심 지표
    """
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0

    class Config:
        extra = 'ignore'  # 기타 필드 자동 제거

    def to_markdown(self) -> str:
        """마크다운 형식 출력"""
        total = self.malicious + self.suspicious + self.harmless + self.undetected
        if total == 0:
            return "No analysis available"

        malicious_pct = (self.malicious / total) * 100
        return f"🔴 {self.malicious}/{total} ({malicious_pct:.1f}% malicious)"


class VTVotes(BaseModel):
    """커뮤니티 투표"""
    harmless: int = 0
    malicious: int = 0

    class Config:
        extra = 'ignore'


class VTThreatClassification(BaseModel):
    """위협 분류 (communicating_files용)"""
    suggested_threat_label: Optional[str] = None
    popular_threat_category: Optional[List[Dict[str, Any]]] = Field(default_factory=list, max_items=3)

    class Config:
        extra = 'ignore'

    def to_markdown(self) -> str:
        if not self.suggested_threat_label:
            return "No threat classification"

        categories = []
        if self.popular_threat_category:
            for cat in self.popular_threat_category[:2]:
                categories.append(f"{cat.get('value', 'unknown')} ({cat.get('count', 0)})")

        return f"**{self.suggested_threat_label}** | {', '.join(categories)}"


# ========================================
# Domain 관련 스키마
# ========================================

class VTResolution(BaseModel):
    """
    Domain ↔ IP 해석 (IOC 확장 핵심!)

    Multi-Agent 순환 조사를 위해 필수
    """
    ip_address: str
    host_name: str
    date: int  # Unix timestamp
    ip_address_last_analysis_stats: Optional[VTAnalysisStats] = None
    host_name_last_analysis_stats: Optional[VTAnalysisStats] = None

    class Config:
        extra = 'ignore'

    def to_markdown(self) -> str:
        """마크다운 출력"""
        date_str = datetime.fromtimestamp(self.date).strftime("%Y-%m-%d")
        ip_threat = self.ip_address_last_analysis_stats.to_markdown() if self.ip_address_last_analysis_stats else "N/A"
        domain_threat = self.host_name_last_analysis_stats.to_markdown() if self.host_name_last_analysis_stats else "N/A"

        return f"- `{self.ip_address}` ↔ `{self.host_name}` ({date_str})\n  - IP: {ip_threat}\n  - Domain: {domain_threat}"


class VTDomainFiltered(BaseModel):
    """
    Domain API 필터링 응답

    필수 필드:
    - reputation, last_analysis_stats (위협 평가)
    - categories (도메인 분류)
    - registrar, creation_date (신뢰도 평가)

    IOC 확장 필드:
    - communicating_files (멀웨어 파일 해시)
    - resolutions (연결된 IP 주소)
    """
    # 기본 정보
    domain: str = Field(..., description="분석 대상 도메인")

    # 위협 평가
    reputation: int = Field(default=0, description="평판 점수 (-100 ~ 100)")
    last_analysis_stats: VTAnalysisStats

    # 분류 정보
    categories: Dict[str, str] = Field(default_factory=dict, description="도메인 카테고리 (최대 5개)")
    total_votes: Optional[VTVotes] = None

    # 도메인 메타데이터
    registrar: Optional[str] = None
    creation_date: Optional[int] = None  # Unix timestamp
    last_update_date: Optional[int] = None

    # IOC 확장 필드 (Multi-Agent 핵심!)
    communicating_files: List[str] = Field(
        default_factory=list,
        max_items=10,
        description="해당 도메인과 통신한 파일 해시 목록 (HashAgent로 전달)"
    )
    resolutions: List[VTResolution] = Field(
        default_factory=list,
        max_items=10,
        description="도메인이 연결된 IP 주소 목록 (DomainAgent로 재전달)"
    )

    class Config:
        extra = 'ignore'

    def to_llm_markdown(self) -> str:
        """
        LLM 최적화 마크다운 출력

        토큰 절약:
        - 테이블 형식 대신 간결한 리스트
        - 핵심 정보만 포함
        - 중복 제거
        """
        lines = [
            f"# Domain Analysis: {self.domain}",
            "",
            "## Threat Assessment",
            f"- Reputation: {self.reputation}/100",
            f"- Detection: {self.last_analysis_stats.to_markdown()}",
        ]

        if self.total_votes:
            lines.append(f"- Community: 👍 {self.total_votes.harmless} | 👎 {self.total_votes.malicious}")

        # 카테고리 (최대 3개)
        if self.categories:
            cats = list(self.categories.items())[:3]
            lines.append(f"- Categories: {', '.join([f'{k}={v}' for k, v in cats])}")

        # 도메인 메타데이터
        if self.registrar or self.creation_date:
            lines.append("\n## Domain Metadata")
            if self.registrar:
                lines.append(f"- Registrar: {self.registrar}")
            if self.creation_date:
                created = datetime.fromtimestamp(self.creation_date).strftime("%Y-%m-%d")
                lines.append(f"- Created: {created}")

        # IOC 확장 (핵심!)
        if self.communicating_files:
            lines.append("\n## 🔍 IOC Expansion: Communicating Files")
            lines.append(f"Found {len(self.communicating_files)} malware samples:")
            for i, hash_val in enumerate(self.communicating_files[:5], 1):
                lines.append(f"{i}. `{hash_val[:16]}...`")
            if len(self.communicating_files) > 5:
                lines.append(f"... and {len(self.communicating_files) - 5} more")

        if self.resolutions:
            lines.append("\n## 🔍 IOC Expansion: IP Resolutions")
            for res in self.resolutions[:5]:
                lines.append(res.to_markdown())
            if len(self.resolutions) > 5:
                lines.append(f"... and {len(self.resolutions) - 5} more")

        return "\n".join(lines)


# ========================================
# IP 관련 스키마
# ========================================

class VTIPFiltered(BaseModel):
    """
    IP 주소 분석 응답

    필수 필드:
    - reputation, last_analysis_stats
    - as_owner, country (인프라 정보)
    """
    # 기본 정보
    ip_address: str

    # 위협 평가
    reputation: int = 0
    last_analysis_stats: VTAnalysisStats

    # 인프라 정보
    as_owner: Optional[str] = None
    asn: Optional[int] = None
    country: Optional[str] = None
    continent: Optional[str] = None

    # 네트워크 정보
    network: Optional[str] = None

    class Config:
        extra = 'ignore'

    def to_llm_markdown(self) -> str:
        """LLM 최적화 마크다운"""
        lines = [
            f"# IP Analysis: {self.ip_address}",
            "",
            "## Threat Assessment",
            f"- Reputation: {self.reputation}/100",
            f"- Detection: {self.last_analysis_stats.to_markdown()}",
            "",
            "## Infrastructure",
        ]

        if self.as_owner:
            lines.append(f"- AS Owner: {self.as_owner}")
        if self.asn:
            lines.append(f"- ASN: AS{self.asn}")
        if self.country:
            lines.append(f"- Location: {self.country}")
        if self.network:
            lines.append(f"- Network: {self.network}")

        return "\n".join(lines)


# ========================================
# Hash/File 관련 스키마
# ========================================

class VTCommunicatingFile(BaseModel):
    """
    Communicating Files 응답 (IOC 확장 핵심!)

    도메인/IP와 통신한 멀웨어 파일 목록
    """
    # 파일 해시
    sha256: str
    md5: Optional[str] = None
    sha1: Optional[str] = None

    # 파일 타입
    type_extension: Optional[str] = None

    # 위협 분류
    popular_threat_classification: Optional[VTThreatClassification] = None
    last_analysis_stats: Optional[VTAnalysisStats] = None

    class Config:
        extra = 'ignore'

    def to_markdown(self) -> str:
        """마크다운 출력"""
        threat = self.popular_threat_classification.to_markdown() if self.popular_threat_classification else "Unknown"
        stats = self.last_analysis_stats.to_markdown() if self.last_analysis_stats else "N/A"

        return f"- `{self.sha256[:16]}...` ({self.type_extension or 'unknown'})\n  - Threat: {threat}\n  - Detection: {stats}"


class VTHashFiltered(BaseModel):
    """
    File Hash 분석 응답

    필수 필드:
    - hashes (SHA256, MD5, SHA1)
    - last_analysis_stats
    - popular_threat_classification

    IOC 확장 필드:
    - contacted_ips (C2 서버)
    - contacted_domains (C2 도메인)
    """
    # 파일 해시
    sha256: str
    md5: Optional[str] = None
    sha1: Optional[str] = None

    # 파일 정보
    type_extension: Optional[str] = None
    size: Optional[int] = None

    # 위협 분류
    popular_threat_classification: Optional[VTThreatClassification] = None
    last_analysis_stats: VTAnalysisStats

    # 패키지 정보 (APK 등)
    package_name: Optional[str] = Field(None, description="Android 패키지명")
    app_name: Optional[str] = Field(None, description="앱 이름")

    # IOC 확장 (C2 인프라 발견!)
    contacted_ips: List[str] = Field(
        default_factory=list,
        max_items=10,
        description="파일이 접촉한 IP 주소 (DomainAgent로 전달)"
    )
    contacted_domains: List[str] = Field(
        default_factory=list,
        max_items=10,
        description="파일이 접촉한 도메인 (DomainAgent로 전달)"
    )

    class Config:
        extra = 'ignore'

    def to_llm_markdown(self) -> str:
        """LLM 최적화 마크다운"""
        lines = [
            f"# File Analysis: {self.sha256[:16]}...",
            "",
            "## File Information",
            f"- SHA256: `{self.sha256}`",
        ]

        if self.md5:
            lines.append(f"- MD5: `{self.md5}`")
        if self.type_extension:
            lines.append(f"- Type: {self.type_extension}")
        if self.size:
            lines.append(f"- Size: {self.size:,} bytes")

        # 앱 정보
        if self.package_name or self.app_name:
            lines.append("\n## Application Info")
            if self.app_name:
                lines.append(f"- App Name: {self.app_name}")
            if self.package_name:
                lines.append(f"- Package: {self.package_name}")

        # 위협 분류
        lines.append("\n## Threat Assessment")
        if self.popular_threat_classification:
            lines.append(f"- Classification: {self.popular_threat_classification.to_markdown()}")
        lines.append(f"- Detection: {self.last_analysis_stats.to_markdown()}")

        # IOC 확장 (C2 인프라)
        if self.contacted_domains:
            lines.append("\n## 🔍 IOC Expansion: C2 Domains")
            for i, domain in enumerate(self.contacted_domains[:5], 1):
                lines.append(f"{i}. `{domain}`")
            if len(self.contacted_domains) > 5:
                lines.append(f"... and {len(self.contacted_domains) - 5} more")

        if self.contacted_ips:
            lines.append("\n## 🔍 IOC Expansion: C2 IPs")
            for i, ip in enumerate(self.contacted_ips[:5], 1):
                lines.append(f"{i}. `{ip}`")
            if len(self.contacted_ips) > 5:
                lines.append(f"... and {len(self.contacted_ips) - 5} more")

        return "\n".join(lines)


# ========================================
# URL 관련 스키마 (URLScan.io)
# ========================================

class URLScanFiltered(BaseModel):
    """
    URLScan.io 응답 필터링

    피싱 탐지 핵심 정보만 추출
    """
    url: str

    # 페이지 정보
    page_title: Optional[str] = None
    page_domain: Optional[str] = None

    # 스크린샷
    screenshot_url: Optional[str] = Field(None, description="시각적 검증용 스크린샷")

    # 서버 정보
    ip_address: Optional[str] = None
    asn: Optional[str] = None
    country: Optional[str] = None

    # 위협 점수
    malicious_score: Optional[float] = Field(None, ge=0, le=100)

    class Config:
        extra = 'ignore'

    def to_llm_markdown(self) -> str:
        """LLM 최적화 마크다운"""
        lines = [
            f"# URL Scan: {self.url}",
            "",
            "## Page Information",
        ]

        if self.page_title:
            lines.append(f"- Title: {self.page_title}")
        if self.page_domain:
            lines.append(f"- Domain: {self.page_domain}")

        if self.screenshot_url:
            lines.append(f"\n## Visual Verification")
            lines.append(f"- Screenshot: {self.screenshot_url}")

        if self.ip_address or self.asn or self.country:
            lines.append("\n## Infrastructure")
            if self.ip_address:
                lines.append(f"- IP: {self.ip_address}")
            if self.asn:
                lines.append(f"- ASN: {self.asn}")
            if self.country:
                lines.append(f"- Country: {self.country}")

        if self.malicious_score is not None:
            lines.append(f"\n## Threat Score")
            lines.append(f"- Malicious: {self.malicious_score:.1f}/100")

        return "\n".join(lines)
