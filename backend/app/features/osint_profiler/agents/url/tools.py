"""
URLAgent Tools - URL 및 피싱 분석 도구 (Pydantic 필터링 적용)

URLScan.io를 활용한:
- URL 스크린샷 캡처 및 페이지 제목 추출
- 정상 웹사이트와 스캔 이미지 비교 (피싱 탐지)

변경사항:
- Pydantic 스키마로 토큰 절감
- 피싱 탐지 핵심 정보만 추출
"""

from typing import List
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field, HttpUrl, ValidationError

from app.features.ioc_tools.ioc_lookup.single_lookup.service import external_api_clients
from app.core.settings.api_keys.cache import get_apikey_cached
from app.features.osint_profiler.schemas.vt_schemas import URLScanFiltered


class URLInput(BaseModel):
    """URL 입력 검증 스키마"""
    url: HttpUrl = Field(
        description="분석할 URL (http:// 또는 https:// 포함). 예: 'https://example.com'"
    )


def create_urlscan_tools() -> List[StructuredTool]:
    """
    URLScan.io 도구 생성

    Returns:
        List[StructuredTool]: URLScan 분석 도구
    """
    tools = []

    urlscan_key = get_apikey_cached("urlscanio")
    if not urlscan_key.get('key'):
        return tools

    def urlscan_analyze(url: str) -> str:
        """
        URLScan.io URL 분석 및 스크린샷 캡처 (Pydantic 필터링)
        Args:
            url: 분석할 URL
        Returns:
            str: 필터링된 마크다운 형식 분석 결과
        피싱 탐지 핵심 정보만 추출
        """
        try:
            result = external_api_clients.urlscanio(ioc=str(url))

            # 에러 응답 처리
            if not result or 'error' in result:
                error_msg = result.get('message', 'Unknown error') if result else 'No response'
                return f"Error: {error_msg}"

            # URLScan.io 응답 구조: results 배열 또는 단일 객체
            # 첫 번째 결과 사용
            if 'results' in result and result['results']:
                scan_data = result['results'][0]
            else:
                scan_data = result

            # Pydantic 필터링
            page_data = scan_data.get('page', {})
            task_data = scan_data.get('task', {})

            filtered = URLScanFiltered(
                url=str(url),
                page_title=page_data.get('title'),
                page_domain=page_data.get('domain'),
                screenshot_url=task_data.get('screenshotURL') or scan_data.get('screenshot'),
                ip_address=page_data.get('ip'),
                asn=page_data.get('asn'),
                country=page_data.get('country'),
                malicious_score=scan_data.get('verdicts', {}).get('overall', {}).get('score')
            )

            # 피싱 지표 추가
            phishing_indicators = check_phishing_indicators(url, filtered.page_title or '')

            markdown_output = filtered.to_llm_markdown()
            markdown_output += "\n\n## Phishing Indicators\n"
            for indicator in phishing_indicators:
                markdown_output += f"- {indicator}\n"

            return markdown_output

        except (KeyError, ValidationError) as e:
            return f"Parsing Error: {str(e)}"

    tools.append(StructuredTool(
        name="urlscan_analyze",
        func=urlscan_analyze,
        description="""Analyze URL using URLScan.io to detect phishing and malicious sites.
        Returns:
        - page_title: Extracted page title for comparison with legitimate sites
        - screenshot: Visual capture of the page for manual verification
        - verdicts: Security assessment (malicious/suspicious/clean)
        - domain_info: WHOIS and registration details
        - ip_addresses: Connected IPs and hosting infrastructure
        - technologies: Web frameworks and libraries detected

        Phishing Detection Strategy:
        1. Extract page title from scanned URL
        2. Compare with legitimate website's actual title
        3. Check for typosquatting (e.g., paypa1.com vs paypal.com)
        4. Verify domain registration date (new domains = suspicious)
        5. Analyze screenshot for visual similarities with brand impersonation

        Use Case:
        - Input: Suspicious URL claiming to be a bank
        - Output: Page title, screenshot URL, and phishing indicators
        - Action: Compare screenshot with real bank site to confirm phishing""",
                args_schema=URLInput
    ))

    return tools


def check_phishing_indicators(url: str, page_title: str) -> List[str]:
    """
    피싱 지표 자동 탐지 보조 함수

    Args:
        url: 분석 대상 URL
        page_title: 추출된 페이지 제목

    Returns:
        List[str]: 탐지된 피싱 지표 목록
    """
    indicators = []

    url_lower = str(url).lower()
    title_lower = page_title.lower()

    # 일반적인 피싱 키워드
    phishing_keywords = [
        'login', 'verify', 'account', 'suspend', 'update',
        'secure', 'confirm', 'alert', 'warning', 'urgent'
    ]

    for keyword in phishing_keywords:
        if keyword in url_lower or keyword in title_lower:
            indicators.append(f"Keyword detected: '{keyword}'")

    # 브랜드 이름 + 이상한 도메인 조합 탐지
    brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'bank']
    suspicious_tlds = ['.top', '.xyz', '.club', '.online', '.site']

    for brand in brands:
        if brand in url_lower:
            for tld in suspicious_tlds:
                if tld in url_lower:
                    indicators.append(f"Brand '{brand}' with suspicious TLD '{tld}'")

    if not indicators:
        indicators.append("No obvious phishing indicators detected (manual review recommended)")

    return indicators
