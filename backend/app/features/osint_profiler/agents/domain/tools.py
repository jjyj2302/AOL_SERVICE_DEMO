"""
DomainAgent Tools - 도메인 및 네트워크 분석 도구 (Pydantic 필터링 적용)

핵심 도구:
- VirusTotal IP/Domain 평판 조회 (필터링)
- URLScan.io 도메인/URL 스캔

변경사항:
- Pydantic 스키마로 토큰 95% 감소 (8000 → 400 tokens)
- IOC 확장 필드 포함 (communicating_files, resolutions)
"""

from typing import List, Dict, Any
from langchain_core.tools import Tool, StructuredTool
from pydantic import BaseModel, Field, IPvAnyAddress, ValidationError

from app.features.ioc_tools.ioc_lookup.single_lookup.service import external_api_clients
from app.core.settings.api_keys.cache import get_apikey_cached
from app.features.osint_profiler.schemas.vt_schemas import (
    VTDomainFiltered,
    VTIPFiltered,
    VTResolution,
    VTCommunicatingFile,
    URLScanFiltered
)


# ===== Pydantic Input Schemas =====
class IPInput(BaseModel):
    """IP 주소 입력 검증"""
    ip: IPvAnyAddress = Field(
        description="조사할 IP 주소 (IPv4/IPv6). 예: '8.8.8.8'"
    )


class DomainInput(BaseModel):
    """도메인 입력 검증"""
    domain: str = Field(
        description="조사할 도메인. 예: 'example.com'"
    )


# ===== Tool Creation Functions =====

def create_ip_tools() -> List[Tool]:
    """
    IP 분석 도구 생성 (VirusTotal, Pydantic 필터링)

    Returns:
        List[Tool]: VirusTotal IP 평판 조회 도구 (필터링됨)
    """
    tools = []

    vt_key = get_apikey_cached("virustotal")
    if vt_key.get('key'):
        def virustotal_ip_check(ip: str) -> str:
            """
            VirusTotal IP 평판 조회 (Pydantic 필터링)

            토큰 절감: ~6000 → ~300 tokens (95%)
            """
            try:
                raw_response = external_api_clients.virustotal(
                    ioc=str(ip),
                    type='ip',
                    apikey=vt_key['key']
                )

                # 에러 응답 처리
                if 'error' in raw_response:
                    return f"Error: {raw_response.get('message', 'Unknown error')}"

                # Pydantic 필터링
                attrs = raw_response['data']['attributes']
                filtered = VTIPFiltered(
                    ip_address=raw_response['data']['id'],
                    reputation=attrs.get('reputation', 0),
                    last_analysis_stats=attrs.get('last_analysis_stats', {}),
                    as_owner=attrs.get('as_owner'),
                    asn=attrs.get('asn'),
                    country=attrs.get('country'),
                    continent=attrs.get('continent'),
                    network=attrs.get('network')
                )

                return filtered.to_llm_markdown()

            except (KeyError, ValidationError) as e:
                return f"Parsing Error: {str(e)}"

        tools.append(StructuredTool.from_function(
            func=virustotal_ip_check,
            name="virustotal_ip_lookup",
            description="VT IP reputation (filtered for LLM efficiency)",
            args_schema=IPInput
        ))

    return tools


def create_domain_tools() -> List[Tool]:
    """
    도메인 분석 도구 생성 (VirusTotal, Pydantic 필터링)

    Returns:
        List[Tool]: VirusTotal 도메인 평판 조회 도구 (필터링됨)
    """
    tools = []

    vt_key = get_apikey_cached("virustotal")
    if vt_key.get('key'):
        def virustotal_domain_check(domain: str) -> str:
            """
            VirusTotal 도메인 평판 조회 (Pydantic 필터링)

            토큰 절감: ~8000 → ~400 tokens (95%)
            """
            try:
                raw_response = external_api_clients.virustotal(
                    ioc=domain,
                    type='domain',
                    apikey=vt_key['key']
                )

                # 에러 응답 처리
                if 'error' in raw_response:
                    return f"Error: {raw_response.get('message', 'Unknown error')}"

                # Pydantic 필터링 (IOC 확장 필드는 아직 비어있음)
                attrs = raw_response['data']['attributes']
                filtered = VTDomainFiltered(
                    domain=raw_response['data']['id'],
                    reputation=attrs.get('reputation', 0),
                    last_analysis_stats=attrs.get('last_analysis_stats', {}),
                    categories=attrs.get('categories', {}),
                    total_votes=attrs.get('total_votes'),
                    registrar=attrs.get('registrar'),
                    creation_date=attrs.get('creation_date'),
                    last_update_date=attrs.get('last_modification_date'),
                    # communicating_files와 resolutions는 별도 도구에서 채움
                )

                return filtered.to_llm_markdown()

            except (KeyError, ValidationError) as e:
                return f"Parsing Error: {str(e)}"

        tools.append(StructuredTool.from_function(
            func=virustotal_domain_check,
            name="virustotal_domain_lookup",
            description="VT domain reputation (filtered for LLM efficiency)",
            args_schema=DomainInput
        ))

    return tools


def create_urlscan_tools() -> List[Tool]:
    """
    URLScan.io 도구 생성

    Returns:
        List[Tool]: URLScan.io 스캔 도구
    """
    tools = []

    urlscan_key = get_apikey_cached("urlscan")
    if urlscan_key.get('key'):
        def urlscan_check(url: str) -> dict:
            """URLScan.io로 URL/도메인 스캔"""
            return external_api_clients.urlscan_io(
                ioc=url,
                apikey=urlscan_key['key']
            )

        tools.append(StructuredTool.from_function(
            func=urlscan_check,
            name="urlscan_lookup",
            description="URLScan analysis",
            args_schema=DomainInput
        ))

    return tools


def create_domain_extended_tools() -> List[Tool]:
    """
    VirusTotal 확장 도구 (IOC 확장 핵심! Pydantic 필터링)

    Returns:
        List[Tool]: communicating_files, resolutions (siblings 제외)
    """
    tools = []

    vt_key = get_apikey_cached("virustotal")
    if not vt_key.get('key'):
        return tools

    apikey = vt_key['key']

    # 1. Communicating Files (IOC 확장 핵심!)
    def vt_domain_communicating_files(domain: str, limit: int = 10) -> str:
        """
        도메인과 통신하는 악성 파일 조회 (Pydantic 필터링)

        IOC 확장: 멀웨어 해시 목록 → HashAgent로 전달
        토큰 절감: ~12000 → ~600 tokens (95%)
        """
        try:
            raw_response = external_api_clients.virustotal_domain_communicating_files(
                domain=domain,
                apikey=apikey,
                limit=limit
            )

            # 에러 응답 처리
            if 'error' in raw_response:
                return f"Error: {raw_response.get('message', 'Unknown error')}"

            # Pydantic 필터링 (배열 응답)
            files = []
            for item in raw_response.get('data', [])[:limit]:
                attrs = item['attributes']
                file_obj = VTCommunicatingFile(
                    sha256=attrs['sha256'],
                    md5=attrs.get('md5'),
                    sha1=attrs.get('sha1'),
                    type_extension=attrs.get('type_extension'),
                    popular_threat_classification=attrs.get('popular_threat_classification'),
                    last_analysis_stats=attrs.get('last_analysis_stats')
                )
                files.append(file_obj)

            # 마크다운 출력
            if not files:
                return f"No communicating files found for {domain}"

            lines = [f"# Communicating Files for {domain} ({len(files)} files)"]
            for f in files:
                lines.append(f.to_markdown())

            return "\n".join(lines)

        except (KeyError, ValidationError) as e:
            return f"Parsing Error: {str(e)}"

    tools.append(StructuredTool.from_function(
        func=vt_domain_communicating_files,
        name="virustotal_domain_communicating_files",
        description="Find malware files communicating with domain (IOC expansion for HashAgent)",
        args_schema=DomainInput
    ))

    # 2. Passive DNS Resolutions (IOC 확장 핵심!)
    def vt_domain_resolutions(domain: str, limit: int = 10) -> str:
        """
        도메인 Passive DNS 이력 조회 (Pydantic 필터링)

        IOC 확장: IP 주소 목록 → DomainAgent로 재조사
        토큰 절감: ~3000 → ~300 tokens (90%)
        """
        try:
            raw_response = external_api_clients.virustotal_domain_resolutions(
                domain=domain,
                apikey=apikey,
                limit=limit
            )

            # 에러 응답 처리
            if 'error' in raw_response:
                return f"Error: {raw_response.get('message', 'Unknown error')}"

            # Pydantic 필터링 (배열 응답)
            resolutions = []
            for item in raw_response.get('data', [])[:limit]:
                attrs = item['attributes']
                res = VTResolution(
                    ip_address=attrs['ip_address'],
                    host_name=attrs.get('host_name', domain),
                    date=attrs['date'],
                    ip_address_last_analysis_stats=attrs.get('ip_address_last_analysis_stats'),
                    host_name_last_analysis_stats=attrs.get('host_name_last_analysis_stats')
                )
                resolutions.append(res)

            # 마크다운 출력
            if not resolutions:
                return f"No DNS resolutions found for {domain}"

            lines = [f"# DNS Resolutions for {domain} ({len(resolutions)} IPs)"]
            for r in resolutions:
                lines.append(r.to_markdown())

            return "\n".join(lines)

        except (KeyError, ValidationError) as e:
            return f"Parsing Error: {str(e)}"

    tools.append(StructuredTool.from_function(
        func=vt_domain_resolutions,
        name="virustotal_domain_resolutions",
        description="DNS history (IOC expansion for IP investigation)",
        args_schema=DomainInput
    ))

    return tools
