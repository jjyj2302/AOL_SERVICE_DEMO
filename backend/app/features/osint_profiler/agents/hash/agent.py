"""
HashAgent - 파일 해시 및 멀웨어 분석 전문 에이전트
"""

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from .tools import create_hash_tools
from app.core.settings.api_keys.cache import APIKeyCache
from app.features.osint_profiler.state import OsintState


def create_hash_agent(llm_model: str = "gpt-4"):
    """파일 해시 및 멀웨어 분석 전문 에이전트"""
    # DB에서 OpenAI API 키 가져오기
    api_cache = APIKeyCache.get_instance()
    openai_key = api_cache.get_key("openai").get("key", "")

    llm = ChatOpenAI(model=llm_model, temperature=0, api_key=openai_key)
    tools = create_hash_tools()

    return create_react_agent(
        model=llm,
        tools=tools,
        name="hash_expert",
        state_schema=OsintState,
        prompt="""You are a file hash and malware analysis expert.
        Analyze file hashes (MD5/SHA1/SHA256) using VirusTotal.
        Focus on detection ratios, malware families, and behavioral analysis.
        Extract C2 servers and related IOCs from analysis results.
        For APK files, identify fake app patterns and phishing infrastructure."""
    )
