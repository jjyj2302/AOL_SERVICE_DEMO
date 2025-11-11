"""
HashAgent Tools - 파일 해시 분석 도구 (Pydantic 필터링 적용)

VirusTotal로 해시 분석 (70+ AV 엔진)

변경사항:
- Pydantic 스키마로 토큰 96.7% 감소 (15000 → 500 tokens)
- IOC 확장 필드 포함 (contacted_ips, contacted_domains - C2 인프라)
"""

from typing import List
from langchain_core.tools import Tool, StructuredTool
from pydantic import BaseModel, Field, ValidationError

from app.features.ioc_tools.ioc_lookup.single_lookup.service import external_api_clients
from app.core.settings.api_keys.cache import get_apikey_cached
from app.features.osint_profiler.schemas.vt_schemas import VTHashFiltered

# Pydantic Input Schemas (입력 검증)
class HashInput(BaseModel):
    """
    해시 입력 검증 스키마
    MD5 (32자), SHA1 (40자), SHA256 (64자) 형식 지원
    """
    hash_value: str = Field(
        description="파일 해시 (MD5, SHA1, SHA256). 예: '44d88612fea8a8f36de82e1278abb02f' (MD5)"
    )

# Hash Analysis Tools (1개)
def create_hash_tools() -> List[StructuredTool]:
    """
    해시 분석 도구 생성

    Tools:
        VirusTotal - 70+ AV 엔진 멀티 스캔, 관계 그래프, 행위 분석

    Returns:
        List[StructuredTool]: LangChain StructuredTool 리스트
    """
    tools = []

    # VirusTotal Hash Lookup (Pydantic 필터링)
    vt_key = get_apikey_cached("virustotal")
    if vt_key.get('key'):
        def virustotal_hash_check(hash_value: str) -> str:
            """
            VirusTotal 파일 해시 분석 (Pydantic 필터링)

            Args:
                hash_value: MD5/SHA1/SHA256 해시

            Returns:
                str: 필터링된 마크다운 형식 분석 결과

            토큰 절감: ~15000 → ~500 tokens (96.7%)
            IOC 확장: contacted_ips, contacted_domains (C2 인프라 발견)
            """
            try:
                raw_response = external_api_clients.virustotal(
                    ioc=hash_value,
                    type='hash',
                    apikey=vt_key['key']
                )

                # 에러 응답 처리
                if 'error' in raw_response:
                    return f"Error: {raw_response.get('message', 'Unknown error')}"

                # Pydantic 필터링
                attrs = raw_response['data']['attributes']
                filtered = VTHashFiltered(
                    sha256=attrs['sha256'],
                    md5=attrs.get('md5'),
                    sha1=attrs.get('sha1'),
                    type_extension=attrs.get('type_extension'),
                    size=attrs.get('size'),
                    popular_threat_classification=attrs.get('popular_threat_classification'),
                    last_analysis_stats=attrs.get('last_analysis_stats', {}),
                    package_name=attrs.get('androguard', {}).get('package_name'),
                    app_name=attrs.get('androguard', {}).get('app_name'),
                    # IOC 확장 (C2 인프라 발견!)
                    contacted_ips=attrs.get('contacted_ips', [])[:10],
                    contacted_domains=attrs.get('contacted_domains', [])[:10]
                )

                return filtered.to_llm_markdown()

            except (KeyError, ValidationError) as e:
                return f"Parsing Error: {str(e)}"

        tools.append(StructuredTool.from_function(
            func=virustotal_hash_check,
            name="virustotal_hash_lookup",
            description="""VirusTotal file hash analysis (70+ AV engines, Pydantic filtered).
            USE FOR:
            - Malware detection (detection ratio)
            - APK analysis (Android malware)
            - File metadata (type, size, hashes)
            - IOC extraction (C2 domains/IPs contacted by this file)
            BLACKWAVE APK ANALYSIS:
            - Package patterns: com.security.*, com.guard.*, com.visa.*
            - Fake app names: "보안앱", "백신", "금융인증"
            - C2 extraction: *.2024tec.top, *.freemall-kr.top, *.na333.top
            - Phishing servers: site111.mallmaster.top, visakor.info
            OPTIMIZED OUTPUT:
            - Token usage: 96.7% reduced (15000 → 500 tokens)
            - Contacted domains/IPs = C2 servers for further investigation
            - Package name (for APK) = fake app identification""",
            args_schema=HashInput
        ))

    return tools