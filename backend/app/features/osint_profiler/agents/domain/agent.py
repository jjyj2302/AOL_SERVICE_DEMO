"""
DomainAgent - 도메인 및 네트워크 분석 전문 에이전트
"""

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from .tools import (
    create_ip_tools,
    create_domain_tools,
    create_urlscan_tools,
    create_domain_extended_tools
)
from app.core.settings.api_keys.cache import APIKeyCache
from app.features.osint_profiler.state import OsintState


def create_domain_agent(llm_model: str = "gpt-4"):
    """
    도메인 및 네트워크 분석 전문 에이전트

    사용 도구:
    - VirusTotal IP/Domain 평판 조회
    - URLScan.io URL/도메인 스캔
    """
    # DB에서 OpenAI API 키 가져오기
    api_cache = APIKeyCache.get_instance()
    openai_key = api_cache.get_key("openai").get("key", "")

    llm = ChatOpenAI(model=llm_model, temperature=0, api_key=openai_key)

    # 도구 등록 (Pydantic 필터링으로 token 절감 완료!)
    tools = []
    tools.extend(create_ip_tools())                # VirusTotal IP (1개)
    tools.extend(create_domain_tools())            # VirusTotal Domain (1개)
    tools.extend(create_urlscan_tools())           # URLScan.io (1개)
    tools.extend(create_domain_extended_tools())   # IOC 확장: communicating_files, resolutions (2개)

    return create_react_agent(
        model=llm,
        tools=tools,
        name="domain_expert",
        state_schema=OsintState,
        prompt="""Domain/IP expert with IOC expansion capability.

**Available Tools:**
1. virustotal_domain_check - Domain reputation analysis (Pydantic filtered)
2. vt_domain_communicating_files - Extract malware hashes from domain (IOC expansion)
3. vt_domain_resolutions - Extract IP addresses from domain (IOC expansion)
4. virustotal_ip_check - IP reputation analysis
5. urlscan_analyze - URL/phishing analysis

**Workflow for Domain Analysis:**
1. virustotal_domain_check → Get reputation, categories
2. vt_domain_communicating_files → Extract file hashes for HashAgent
3. vt_domain_resolutions → Extract IPs for further analysis
4. urlscan_analyze → Screenshot and phishing detection

**Your Job:**
- Execute ALL relevant tools for comprehensive analysis
- Extract NEW IOCs from results (hashes, IPs, domains, URLs)
- Return findings for circular investigation via Evaluator

**Pydantic Filtering Applied:** All responses are token-optimized."""
    )
