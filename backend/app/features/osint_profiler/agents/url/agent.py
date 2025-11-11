"""
URLAgent - URL 및 피싱 분석 전문 에이전트
"""

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from .tools import create_urlscan_tools
from app.core.settings.api_keys.cache import APIKeyCache
from app.features.osint_profiler.state import OsintState


def create_url_agent(llm_model: str = "gpt-4"):
    """
    URL 및 피싱 분석 전문 에이전트 (URLScan.io 사용)
    Args:
        llm_model: 사용할 LLM 모델
    Returns:
        CompiledGraph
    """
    # DB에서 OpenAI API 키 가져오기
    api_cache = APIKeyCache.get_instance()
    openai_key = api_cache.get_key("openai").get("key", "")

    llm = ChatOpenAI(model=llm_model, temperature=0, api_key=openai_key)
    tools = create_urlscan_tools()

    return create_react_agent(
        model=llm,
        tools=tools,
        name="url_expert",
        state_schema=OsintState,
        prompt="""You are a URL and phishing analysis expert.
        Use URLScan.io to analyze suspicious URLs and detect phishing attempts.

        Your analysis should include:
        1. Extract the page title from the scanned URL
        2. Provide the screenshot URL for visual verification
        3. Identify phishing indicators (typosquatting, brand impersonation)
        4. Compare the scanned page with the legitimate website it claims to be
        5. Check domain registration details and IP addresses

        Phishing Detection Strategy:
        - Compare page title with real website's title
        - Look for domain typos (e.g., paypa1.com instead of paypal.com)
        - Check for suspicious TLDs (.top, .xyz, .club)
        - Analyze screenshot for visual brand impersonation
        - Verify domain age (new domains are suspicious)

        Always provide the screenshot URL so users can manually verify the page appearance."""
    )
