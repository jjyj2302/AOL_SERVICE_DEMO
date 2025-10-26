"""
IdentityAgent Tools - 신원/개인정보 분석 도구 모음

책임:
- API 키 로딩 (get_apikey 사용)
- Email 분석 도구 생성 (HaveIBeenPwned, EmailRep, Hunter.io)
- GitHub 분석 도구 생성 (Code Search - 유출된 자격 증명 검색)
- Reddit 분석 도구 생성 (Social OSINT)

설계 패턴:
- Agent 인스턴스를 받아서 agent_instance.db로 API 키 조회
- Pydantic 스키마로 입력 검증
- API 키 없으면 해당 도구 건너뜀 (if 문 체크)
"""
from typing import List
from langchain.tools import Tool, StructuredTool
from pydantic import BaseModel, Field, EmailStr

from app.features.ioc_tools.ioc_lookup.single_lookup.service import external_api_clients
from app.core.settings.api_keys.crud.api_keys_settings_crud import get_apikey

# Pydantic Input Schemas
class EmailInput(BaseModel):
    """이메일 주소 입력 검증 스키마"""
    email: EmailStr = Field(
        description="조사할 이메일 주소. 예: 'user@example.com'"
    )

class IOCInput(BaseModel):
    """범용 IOC 입력 스키마 (GitHub, Reddit 등)"""
    ioc: str = Field(
        description="조사할 IOC (IP, domain, email, API key 등). 예: '192.168.1.1'"
    )

# Email Analysis Tools
def create_email_tools(agent_instance) -> List[Tool]:
    """
    이메일 분석 도구 3개 생성

    Tools:
    1. Have I Been Pwned - 데이터 유출 이력 조회
    2. EmailRep.io - 이메일 평판 점수 및 의심 플래그
    3. Hunter.io - 이메일 전송 가능성 검증 및 도메인 인텔리전스

    Args:
        agent_instance: IdentityAgent 인스턴스

    Returns:
        List[Tool]: LangChain StructuredTool 리스트
    """
    tools = []
    db = agent_instance.db

    # 1. Have I Been Pwned
    hibp_key = get_apikey(db, "haveibeenpwned")
    if hibp_key.get('key'):
        def hibp_check(email: str) -> dict:
            """
            Have I Been Pwned 데이터 유출 이력 조회
            Args:
                email: 조사할 이메일 주소
            Returns:
                dict: HIBP API 응답 (breaches, paste 정보)
            """
            return external_api_clients.haveibeenpwnd_email_check(
                ioc=email,
                apikey=hibp_key['key']
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
            JSON with `breaches` (array of breach objects with Name/Date/DataClasses), `message` ("Not found in any breaches"), or `error`/`is_rate_limited` on failure.
            LIMIT: 1,500 req/day; returns 429 with retry_after on rate limit.
            DON'T USE: For real-time spam filtering (use EmailRep), bulk
            validation (rate limit), or as proof of current active compromise.""",
            args_schema=EmailInput
        ))

    # 2. EmailRep.io
    emailrep_key = get_apikey(db, "emailrepio")
    if emailrep_key.get('key'):
        def emailrep_check(email: str) -> dict:
            """
            EmailRep.io 이메일 평판 조회
            Args:
                email: 조사할 이메일 주소
            Returns:
                dict: EmailRep API 응답 (reputation, suspicious 플래그)
            """
            return external_api_clients.emailrep_email_check(
                ioc=email,
                apikey=emailrep_key['key']
            )

        tools.append(StructuredTool.from_function(
            func=emailrep_check,
            name="emailrep_reputation_check",
            description="""Analyze email reputation and suspicious activity indicators.
            USE WHEN:
            - Quick triage of email sender trustworthiness
            - Filtering spam/phishing emails in incident response
            - Assessing email-based threat priority
            RETURNS: JSON with `reputation` (high/medium/low/none), `suspicious` (bool), `references` (int), `details` object containing spam/malicious/credentials_leaked/data_breach/malware_delivery flags.
            LIMIT: 300 req/day; returns 429 on rate limit.
            DON'T USE: As definitive malware verdict without corroborating IOCs, for PII collection, or to replace multi-source validation.""",
            args_schema=EmailInput
        ))

      # 3. Hunter.io
    hunter_key = get_apikey(db, "hunterio")
    if hunter_key.get('key'):
        def hunter_verify(email: str) -> dict:
            """
            Hunter.io 이메일 검증

            Args:
                email: 조사할 이메일 주소

            Returns:
                dict: Hunter.io API 응답 (deliverability, score)
            """
            return external_api_clients.hunter_email_check(
                ioc=email,
                apikey=hunter_key['key']
            )

        tools.append(StructuredTool.from_function(
            func=hunter_verify,
            name="hunter_email_verification",
            description="""Verify email deliverability and discover domain-related intelligence.
            USE WHEN:
            - Verifying if email address actually exists
            - Finding other emails at target organization/domain
            - Expanding OSINT investigation from email to company infrastructure
            RETURNS: JSON with `status`(valid/invalid/accept_all/unknown), `score` (0-100 confidence), `mx_records` (bool), `smtp_server` (bool), `sources` (array of discovery sources), domain info.
            LIMIT: 50 req/month (free tier); returns 429 on rate limit.
            DON'T USE: For mass email harvesting, unsolicited outreach campaigns, SMTP probing at scale, or violating anti-scraping policies.""",
            args_schema=EmailInput
        ))

    return tools

# GitHub Analysis Tool
def create_github_tools(agent_instance) -> List[Tool]:
    """
    GitHub 분석 도구 1개 생성
    Tools:
        GitHub Code Search - 유출된 자격증명/API 키 검색
    Args:
        agent_instance: IdentityAgent 인스턴스
    Returns:
        List[Tool]: LangChain StructuredTool 리스트
    """
    tools = []
    db = agent_instance.db

    # GitHub Code Search
    github_key = get_apikey(db, "github_pat")
    if github_key.get('key'):
        def github_code_search(ioc: str) -> dict:
            """
            GitHub 코드 저장소에서 IOC 검색
            Args:
                ioc: 검색할 IOC (IP, API 키, 자격증명 등)
            Returns:
                dict: GitHub API 응답 (repositories, code snippets)
            """
            return external_api_clients.search_github(
                ioc=ioc,
                apikey=github_key['key']
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
            - 30/min PAT (10 unauth); max 1k results; default branch only; < 384KB
            file
            DON'T USE:
            - Common strings (false positives); private repos (need org access)
            INTERPRET:
            - score → sha age → code context → repo owner reputation
            WORKFLOW:
            - Search IOC → identify repos/owners → extract related IOCs → expand investigation""",
            args_schema=IOCInput
        ))

    return tools

# Reddit Analysis Tools
def create_reddit_tools(agent_instance) -> List[Tool]:
    """
    Reddit 소셜 OSINT 도구 1개 생성

    Tools:
        Reddit Search - 커뮤니티 논의/인시던트 검색
    Args:
        agent_instance: IdentityAgent 인스턴스
    Returns:
        List[Tool]: LangChain StructuredTool 리스트
    """
    tools = []
    db = agent_instance.db

    # Reddit Search (OAuth 필요: client_id + client_secret)
    reddit_cid = get_apikey(db, "reddit_cid")
    reddit_cs = get_apikey(db, "reddit_cs")

    if reddit_cid and reddit_cid.get('key') and reddit_cs and reddit_cs.get('key'):
        def reddit_search(ioc: str) -> dict:
            """
            Reddit 소셜 미디어 OSINT 검색
            Args:
                ioc: 검색할 IOC
            Returns:
                dict: Reddit API 응답 (posts, comments)
            """
            return external_api_clients.search_reddit(
                ioc=ioc,
                client_id=reddit_cid['key'],
                client_secret=reddit_cs['key']
            )

        tools.append(StructuredTool.from_function(
            func=reddit_search,
            name="reddit_ioc_search",
            description="""Reddit — social OSINT (OAuth req: client_id/secret)
            USE WHEN: community discussions/incident reports; victim/researcher mentions in r/netsec, r/cybersecurity; hacker chatter in underground subreddits; early threat signals
            RETURNS: posts[{title,selftext,author,subreddit,score,created_utc,url, num_comments}]; comments; permalink (JSON)
            LIMITS: OAuth 60 req/min; user_agent required; page≈25; private/restricted subs blocked; token refresh every 60min; 429 on bulk
            DON'T USE: as technical reputation source (use threat intel feeds); real-time IR (posting lag); deleted/removed content
            INTERPRET: score+comments+recency for signal strength; check author history (karma/age); use hour/day time filter for fresh signals; underground subs may use code/slang
            FLOW: After technical analysis→Reddit for community context→identify related incidents→extract additional IOCs from discussions
            TIPS: batch & cache; backoff on 429; store post IDs for dedup; search r/blueteam, r/asknetsec for defensive context""",
            args_schema=IOCInput
        ))

    return tools