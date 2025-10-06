# OSINT 프로파일링 자동화 통합 계획서

## 📋 프로젝트 개요

### 목표
기존 AOL_SERVICE_DEMO 프로젝트에 LLM 기반 OSINT 자동화 기능을 추가하여, 사용자가 이메일/IP/도메인 등을 입력하면 LLM이 자동으로 적절한 도구를 선택하고 순서를 결정하여 조사를 수행하는 시스템 구축.

### 현재 상태
- ✅ **25개 OSINT API 클라이언트 구현됨** (`backend/app/features/ioc_tools/ioc_lookup/single_lookup/service/external_api_clients.py`)
- ✅ **LLM 서비스 구축됨** (`backend/app/utils/llm_service.py`) - OpenAI, Anthropic, Google 지원
- ✅ **API 키 관리 시스템** (`backend/app/core/settings/api_keys/`)
- ❌ **도구 선택은 수동** - 사용자가 직접 서비스명 지정 필요
- ❌ **피드백 루프 없음** - 결과 기반 추가 조사 불가
- ❌ **크로스 타입 연계 없음** - 이메일 → 도메인 → IP 자동 추적 불가

### 최종 목표 (Multi-Agent Orchestration)
```
Knowledge Agent (오케스트레이터)
├── Email Agent (이메일 전문 조사)
├── IP Agent (IP 주소 전문 조사)
├── Domain Agent (도메인 전문 조사)
├── Photo Agent (이미지/얼굴 분석)
└── Crypto Agent (암호화폐 추적)
```

---

## 🎯 통합 전략

### 선택된 레포지토리
1. **LLM_OSINT** (1순위, 9.5/10)
   - MIT 라이선스
   - Knowledge Agent, ReAct 패턴, 피드백 루프
   - 저장소: https://github.com/ShrivuShankar/LLM_OSINT

2. **Profil3r** (2순위, 8/10) - Phase 2에서 추가 예정
   - 순열 생성기, 이메일 검증, 리포트 생성

### 통합 방식
- ❌ 코드 그대로 복사 (X)
- ✅ 아이디어와 패턴을 참고하여 **우리 프로젝트 구조에 맞게 재작성**
- ✅ 기존 LLM 서비스, API 클라이언트와 **통합**

---

## 📅 Phase 1: LLM_OSINT 핵심 통합 (3주)

### Week 1: LangChain 설정 및 API Tools 래핑

#### 목표
기존 25개 API 클라이언트를 LangChain Tools로 변환하여 LLM이 사용할 수 있게 만들기

#### 작업 내용

##### 1.1 의존성 추가
```bash
# backend/requirements.txt에 추가
langchain==0.1.20
langchain-core==0.1.52
langchain-openai==0.0.8
langchain-anthropic==0.1.11
langchain-google-genai==1.0.1
```

##### 1.2 디렉토리 구조 생성
```bash
backend/app/features/osint_profiler/
├── __init__.py
├── agents/
│   ├── __init__.py
│   ├── web_agent.py          # ReAct Agent (Week 2)
│   └── knowledge_agent.py    # Knowledge Agent (Week 3)
├── tools/
│   ├── __init__.py
│   └── langchain_wrappers.py # Week 1에서 작성
├── utils/
│   ├── __init__.py
│   └── content_processor.py  # LLM Map-Reduce (Week 2)
├── workflows/
│   ├── __init__.py
│   └── feedback_loop.py      # Feedback Loop (Week 3)
└── routers/
    ├── __init__.py
    └── osint_routes.py       # FastAPI 엔드포인트
```

##### 1.3 LangChain Tools 래퍼 작성

**파일:** `backend/app/features/osint_profiler/tools/langchain_wrappers.py`

```python
"""
OSINT API 클라이언트를 LangChain Tools로 래핑

Based on LLM_OSINT by Shrivu Shankar (MIT License)
Modified for AOL_SERVICE_DEMO integration
"""

from typing import List, Dict, Any
from langchain.tools import Tool
from langchain.agents import AgentType
from sqlalchemy.orm import Session
from app.features.ioc_tools.ioc_lookup.single_lookup.service import external_api_clients
from app.core.settings.api_keys.crud.api_keys_settings_crud import get_apikey


class OSINTToolFactory:
    """기존 API 클라이언트를 LangChain Tools로 변환하는 팩토리"""

    def __init__(self, db: Session):
        self.db = db
        self.api_keys = self._load_api_keys()

    def _load_api_keys(self) -> Dict[str, str]:
        """DB에서 모든 API 키 로드"""
        keys = {}
        key_names = [
            'virustotal', 'abuseipdb', 'alienvault', 'shodan', 'crowdsec',
            'emailrepio', 'hunterio', 'hibp_api_key', 'github_pat',
            'virustotal', 'malwarebazaar', 'threatfox', 'urlhaus'
        ]

        for key_name in key_names:
            key_data = get_apikey(name=key_name, db=self.db)
            if key_data and key_data.get('is_active'):
                keys[key_name] = key_data.get('key')

        return keys

    def create_email_tools(self) -> List[Tool]:
        """이메일 관련 도구 생성"""
        tools = []

        # HaveIBeenPwned
        if 'hibp_api_key' in self.api_keys:
            tools.append(Tool(
                name="haveibeenpwned_check",
                func=lambda email: external_api_clients.haveibeenpwnd_email_check(
                    ioc=email,
                    apikey=self.api_keys['hibp_api_key']
                ),
                description="""
                이메일 주소가 데이터 유출 사고에 포함되었는지 확인합니다.
                입력: 이메일 주소 (예: user@example.com)
                출력: 유출 사고 목록, 유출 날짜, 유출된 데이터 유형
                사용 시점: 이메일 주소의 보안 이력을 확인할 때
                """
            ))

        # EmailRep.io
        if 'emailrepio' in self.api_keys:
            tools.append(Tool(
                name="emailrep_check",
                func=lambda email: external_api_clients.emailrep_email_check(
                    ioc=email,
                    apikey=self.api_keys['emailrepio']
                ),
                description="""
                이메일 주소의 평판과 신뢰도를 확인합니다.
                입력: 이메일 주소
                출력: 평판 점수, 스팸 가능성, 의심스러운 활동 여부
                사용 시점: 이메일 주소의 신뢰성을 평가할 때
                """
            ))

        # Hunter.io
        if 'hunterio' in self.api_keys:
            tools.append(Tool(
                name="hunter_email_check",
                func=lambda email: external_api_clients.hunter_email_check(
                    ioc=email,
                    apikey=self.api_keys['hunterio']
                ),
                description="""
                이메일 주소의 유효성과 관련 정보를 조회합니다.
                입력: 이메일 주소
                출력: 이메일 형식 유효성, 도메인 정보, 관련 소셜 프로필
                사용 시점: 이메일 주소가 실제로 존재하는지 확인할 때
                """
            ))

        return tools

    def create_ip_tools(self) -> List[Tool]:
        """IP 관련 도구 생성"""
        tools = []

        # AbuseIPDB
        if 'abuseipdb' in self.api_keys:
            tools.append(Tool(
                name="abuseipdb_check",
                func=lambda ip: external_api_clients.abuseipdb_ip_check(
                    ioc=ip,
                    apikey=self.api_keys['abuseipdb']
                ),
                description="""
                IP 주소의 악성 활동 보고 이력을 확인합니다.
                입력: IPv4 주소 (예: 1.2.3.4)
                출력: 악성 점수(0-100), 보고 횟수, 악성 활동 유형
                사용 시점: IP 주소가 악성인지 우선 확인할 때
                """
            ))

        # Shodan
        if 'shodan' in self.api_keys:
            tools.append(Tool(
                name="shodan_check",
                func=lambda ip: external_api_clients.check_shodan(
                    ioc=ip,
                    method='ip',
                    apikey=self.api_keys['shodan']
                ),
                description="""
                IP 주소의 열린 포트, 서비스, 배너 정보를 조회합니다.
                입력: IPv4 주소
                출력: 열린 포트 목록, 실행 중인 서비스, 호스팅 정보, 위치
                사용 시점: IP의 인프라 정보와 노출된 서비스를 파악할 때
                """
            ))

        # CrowdSec
        if 'crowdsec' in self.api_keys:
            tools.append(Tool(
                name="crowdsec_check",
                func=lambda ip: external_api_clients.crowdsec(
                    ioc=ip,
                    apikey=self.api_keys['crowdsec']
                ),
                description="""
                IP 주소가 CrowdSec 커뮤니티에서 차단되었는지 확인합니다.
                입력: IPv4 주소
                출력: 차단 여부, 공격 유형, 차단한 사용자 수
                사용 시점: 커뮤니티 기반 위협 인텔리전스를 확인할 때
                """
            ))

        # VirusTotal (IP)
        if 'virustotal' in self.api_keys:
            tools.append(Tool(
                name="virustotal_ip_check",
                func=lambda ip: external_api_clients.virustotal(
                    ioc=ip,
                    type='ip',
                    apikey=self.api_keys['virustotal']
                ),
                description="""
                IP 주소를 89개 보안 엔진으로 검사합니다.
                입력: IPv4 주소
                출력: 악성 판정 수, 각 엔진별 결과, 관련 도메인 목록
                사용 시점: 다중 엔진 검증이 필요할 때
                """
            ))

        # AlienVault OTX (IP)
        if 'alienvault' in self.api_keys:
            tools.append(Tool(
                name="alienvault_ip_check",
                func=lambda ip: external_api_clients.alienvaultotx(
                    ioc=ip,
                    type='ip',
                    apikey=self.api_keys['alienvault']
                ),
                description="""
                IP 주소와 관련된 위협 인텔리전스 펄스를 조회합니다.
                입력: IPv4 주소
                출력: 위협 펄스, 관련 캠페인, 연관된 IOC 목록
                사용 시점: IP가 알려진 공격 캠페인의 일부인지 확인할 때
                """
            ))

        return tools

    def create_domain_tools(self) -> List[Tool]:
        """도메인 관련 도구 생성"""
        tools = []

        # VirusTotal (Domain)
        if 'virustotal' in self.api_keys:
            tools.append(Tool(
                name="virustotal_domain_check",
                func=lambda domain: external_api_clients.virustotal(
                    ioc=domain,
                    type='domain',
                    apikey=self.api_keys['virustotal']
                ),
                description="""
                도메인을 89개 보안 엔진으로 검사합니다.
                입력: 도메인 이름 (예: example.com)
                출력: 악성 판정 수, DNS 레코드, 관련 IP 주소
                사용 시점: 도메인의 악성 여부를 확인할 때
                """
            ))

        # URLScan.io
        tools.append(Tool(
            name="urlscan_check",
            func=lambda domain: external_api_clients.urlscanio(ioc=domain),
            description="""
            도메인/URL의 스크린샷과 네트워크 활동을 분석합니다.
            입력: 도메인 또는 URL
            출력: 스크린샷, HTTP 요청, 리디렉션 체인, 연관 도메인
            사용 시점: 도메인의 실제 콘텐츠와 동작을 확인할 때
            참고: API 키 없이 사용 가능하지만 제한적
            """
        ))

        # AlienVault OTX (Domain)
        if 'alienvault' in self.api_keys:
            tools.append(Tool(
                name="alienvault_domain_check",
                func=lambda domain: external_api_clients.alienvaultotx(
                    ioc=domain,
                    type='domain',
                    apikey=self.api_keys['alienvault']
                ),
                description="""
                도메인과 관련된 위협 인텔리전스를 조회합니다.
                입력: 도메인 이름
                출력: 위협 펄스, 관련 IP, 연관된 URL
                사용 시점: 도메인이 알려진 위협의 일부인지 확인할 때
                """
            ))

        return tools

    def create_hash_tools(self) -> List[Tool]:
        """파일 해시 관련 도구 생성"""
        tools = []

        # VirusTotal (Hash)
        if 'virustotal' in self.api_keys:
            tools.append(Tool(
                name="virustotal_hash_check",
                func=lambda hash_val: external_api_clients.virustotal(
                    ioc=hash_val,
                    type='hash',
                    apikey=self.api_keys['virustotal']
                ),
                description="""
                파일 해시를 89개 엔진으로 검사합니다.
                입력: MD5, SHA1, 또는 SHA256 해시
                출력: 악성 판정 수, 파일 이름, 파일 유형, 행위 분석
                사용 시점: 파일이 악성인지 확인할 때
                """
            ))

        # MalwareBazaar
        if 'malwarebazaar' in self.api_keys:
            tools.append(Tool(
                name="malwarebazaar_check",
                func=lambda hash_val: external_api_clients.malwarebazaar_hash_check(
                    ioc=hash_val,
                    apikey=self.api_keys['malwarebazaar']
                ),
                description="""
                악성코드 데이터베이스에서 파일 해시를 검색합니다.
                입력: MD5, SHA1, SHA256 해시
                출력: 악성코드 패밀리, 태그, 다운로드 링크
                사용 시점: 알려진 악성코드 샘플인지 확인할 때
                """
            ))

        return tools

    def create_url_tools(self) -> List[Tool]:
        """URL 관련 도구 생성"""
        tools = []

        # URLhaus
        if 'urlhaus' in self.api_keys:
            tools.append(Tool(
                name="urlhaus_check",
                func=lambda url: external_api_clients.urlhaus_url_check(
                    ioc=url,
                    apikey=self.api_keys['urlhaus']
                ),
                description="""
                악성 URL 데이터베이스에서 URL을 검색합니다.
                입력: URL
                출력: 악성 여부, 배포하는 악성코드, 온라인 상태
                사용 시점: URL이 악성코드를 배포하는지 확인할 때
                """
            ))

        # ThreatFox
        if 'threatfox' in self.api_keys:
            tools.append(Tool(
                name="threatfox_check",
                func=lambda ioc: external_api_clients.threatfox_ip_check(
                    ioc=ioc,
                    apikey=self.api_keys['threatfox']
                ),
                description="""
                ThreatFox 데이터베이스에서 IOC를 검색합니다.
                입력: IP, 도메인, URL, 해시
                출력: 위협 유형, 악성코드 패밀리, 신뢰도
                사용 시점: 다양한 IOC 유형을 한 번에 확인할 때
                """
            ))

        return tools

    def create_github_tools(self) -> List[Tool]:
        """GitHub 관련 도구 생성"""
        tools = []

        if 'github_pat' in self.api_keys:
            tools.append(Tool(
                name="github_search",
                func=lambda query: external_api_clients.search_github(
                    ioc=query,
                    apikey=self.api_keys['github_pat']
                ),
                description="""
                GitHub에서 코드, 커밋, 이슈를 검색합니다.
                입력: 검색어 (IP, 도메인, 이메일, CVE 등)
                출력: 관련 레포지토리, 코드 스니펫, 커밋 내역
                사용 시점: IOC가 공개 코드에 포함되어 있는지 확인할 때
                """
            ))

        return tools

    def create_all_tools(self) -> List[Tool]:
        """모든 사용 가능한 도구를 생성"""
        all_tools = []
        all_tools.extend(self.create_email_tools())
        all_tools.extend(self.create_ip_tools())
        all_tools.extend(self.create_domain_tools())
        all_tools.extend(self.create_hash_tools())
        all_tools.extend(self.create_url_tools())
        all_tools.extend(self.create_github_tools())

        return all_tools

    def get_tools_summary(self) -> Dict[str, List[str]]:
        """사용 가능한 도구 요약 반환"""
        all_tools = self.create_all_tools()

        summary = {
            "total_tools": len(all_tools),
            "tool_names": [tool.name for tool in all_tools],
            "missing_api_keys": []
        }

        # 누락된 API 키 확인
        required_keys = {
            'virustotal', 'abuseipdb', 'shodan', 'emailrepio',
            'hunterio', 'hibp_api_key', 'github_pat'
        }
        missing = required_keys - set(self.api_keys.keys())
        summary["missing_api_keys"] = list(missing)

        return summary
```

##### 1.4 테스트 스크립트 작성

**파일:** `backend/tests/test_osint_tools_wrapper.py`

```python
"""
LangChain Tools 래퍼 테스트
"""
import pytest
from sqlalchemy.orm import Session
from app.features.osint_profiler.tools.langchain_wrappers import OSINTToolFactory
from app.core.database import get_db

def test_tool_factory_initialization():
    """도구 팩토리 초기화 테스트"""
    db = next(get_db())
    factory = OSINTToolFactory(db)

    assert factory is not None
    assert isinstance(factory.api_keys, dict)

def test_create_email_tools():
    """이메일 도구 생성 테스트"""
    db = next(get_db())
    factory = OSINTToolFactory(db)

    email_tools = factory.create_email_tools()

    assert len(email_tools) > 0
    for tool in email_tools:
        assert hasattr(tool, 'name')
        assert hasattr(tool, 'description')
        assert hasattr(tool, 'func')

def test_create_ip_tools():
    """IP 도구 생성 테스트"""
    db = next(get_db())
    factory = OSINTToolFactory(db)

    ip_tools = factory.create_ip_tools()

    assert len(ip_tools) > 0
    assert any('abuseipdb' in tool.name for tool in ip_tools)
    assert any('shodan' in tool.name for tool in ip_tools)

def test_tool_execution():
    """도구 실행 테스트 (실제 API 호출 없이 구조 확인)"""
    db = next(get_db())
    factory = OSINTToolFactory(db)

    all_tools = factory.create_all_tools()

    # 각 도구가 호출 가능한지 확인
    for tool in all_tools:
        assert callable(tool.func)

def test_tools_summary():
    """도구 요약 정보 테스트"""
    db = next(get_db())
    factory = OSINTToolFactory(db)

    summary = factory.get_tools_summary()

    assert 'total_tools' in summary
    assert 'tool_names' in summary
    assert 'missing_api_keys' in summary
    assert summary['total_tools'] > 0
```

##### 1.5 Week 1 검증 기준

**완료 조건:**
- ✅ `langchain_wrappers.py` 작성 완료
- ✅ 최소 15개 이상의 Tool 생성됨
- ✅ 모든 테스트 통과
- ✅ `OSINTToolFactory.create_all_tools()` 정상 동작
- ✅ 각 Tool의 description이 명확하게 작성됨 (LLM이 이해할 수 있도록)

**테스트 명령:**
```bash
cd backend
pytest tests/test_osint_tools_wrapper.py -v
```

**예상 출력:**
```
test_tool_factory_initialization PASSED
test_create_email_tools PASSED
test_create_ip_tools PASSED
test_tool_execution PASSED
test_tools_summary PASSED

Total tools created: 18
Missing API keys: []
```

---

### Week 2: ReAct Agent 구현

#### 목표
단일 입력(이메일, IP, 도메인)을 받아 LLM이 자동으로 도구를 선택하고 실행하는 ReAct Agent 구현

#### 작업 내용

##### 2.1 LLM Map-Reduce 유틸리티 작성

**파일:** `backend/app/features/osint_profiler/utils/content_processor.py`

```python
"""
LLM Map-Reduce 패턴 구현 - 대용량 콘텐츠 처리

Based on LLM_OSINT by Shrivu Shankar (MIT License)
Modified for AOL_SERVICE_DEMO integration with existing LLM service
"""

from typing import List, Dict, Any
from sqlalchemy.orm import Session
from app.utils.llm_service import LLMService, create_llm_service


class ContentProcessor:
    """대용량 텍스트를 LLM으로 처리하는 Map-Reduce 유틸리티"""

    def __init__(self, db: Session, llm_model: str = "gpt-4"):
        self.llm_service = create_llm_service(db)
        self.llm_model = llm_model

    def chunk_by_tokens(self, text: str, max_tokens: int = 2000) -> List[str]:
        """텍스트를 토큰 제한에 맞게 청크로 분할"""
        # 간단한 구현: 단어 기준 분할 (실제로는 tiktoken 사용 권장)
        words = text.split()
        chunks = []
        current_chunk = []
        current_length = 0

        for word in words:
            word_length = len(word) // 4  # 대략적인 토큰 추정
            if current_length + word_length > max_tokens:
                chunks.append(' '.join(current_chunk))
                current_chunk = [word]
                current_length = word_length
            else:
                current_chunk.append(word)
                current_length += word_length

        if current_chunk:
            chunks.append(' '.join(current_chunk))

        return chunks

    def map_reduce(
        self,
        texts: List[str],
        map_prompt_template: str,
        reduce_prompt_template: str
    ) -> str:
        """
        Map-Reduce 패턴으로 여러 텍스트를 처리

        Args:
            texts: 처리할 텍스트 목록
            map_prompt_template: Map 단계 프롬프트 ('{text}' 플레이스홀더 포함)
            reduce_prompt_template: Reduce 단계 프롬프트 ('{summaries}' 플레이스홀더 포함)

        Returns:
            최종 요약 결과
        """
        # Map 단계: 각 텍스트를 개별 요약
        mapped_results = []
        for text in texts:
            prompt = map_prompt_template.format(text=text)
            result = self.llm_service.execute_prompt(
                self.llm_model,
                "당신은 정보를 간결하게 요약하는 전문가입니다.",
                prompt
            )
            mapped_results.append(result)

        # Reduce 단계: 요약들을 하나로 통합
        if len(mapped_results) == 1:
            return mapped_results[0]

        # 재귀적 Reduce (요약이 너무 많으면 다시 청크로 나눔)
        while len(mapped_results) > 5:
            reduced_batch = []
            for i in range(0, len(mapped_results), 5):
                batch = mapped_results[i:i+5]
                combined = "\n\n".join(batch)
                reduced = self.llm_service.execute_prompt(
                    self.llm_model,
                    "당신은 여러 요약을 하나로 통합하는 전문가입니다.",
                    reduce_prompt_template.format(summaries=combined)
                )
                reduced_batch.append(reduced)
            mapped_results = reduced_batch

        # 최종 Reduce
        final_combined = "\n\n".join(mapped_results)
        final_result = self.llm_service.execute_prompt(
            self.llm_model,
            "당신은 최종 보고서를 작성하는 전문가입니다.",
            reduce_prompt_template.format(summaries=final_combined)
        )

        return final_result

    def process_investigation_results(
        self,
        results: List[Dict[str, Any]]
    ) -> str:
        """
        여러 OSINT 도구 실행 결과를 요약

        Args:
            results: [{"tool": "virustotal", "output": {...}}, ...]

        Returns:
            통합 요약
        """
        # 각 결과를 텍스트로 변환
        texts = []
        for result in results:
            tool_name = result.get('tool', 'Unknown')
            output = result.get('output', {})
            text = f"도구: {tool_name}\n결과: {str(output)[:500]}"
            texts.append(text)

        map_prompt = """
        다음 OSINT 도구 실행 결과를 분석하고 핵심 정보만 추출하세요:

        {text}

        핵심 정보:
        - 위협 여부 (악성/정상/의심)
        - 중요 발견 사항
        - 신뢰도
        """

        reduce_prompt = """
        다음은 여러 OSINT 도구의 분석 결과입니다:

        {summaries}

        위 결과들을 종합하여 최종 판단을 내리세요:
        1. 전반적인 위협 수준
        2. 일치하는 발견 사항
        3. 상충되는 정보
        4. 추가 조사가 필요한 영역
        """

        return self.map_reduce(texts, map_prompt, reduce_prompt)
```

##### 2.2 ReAct Agent 구현

**파일:** `backend/app/features/osint_profiler/agents/web_agent.py`

```python
"""
OSINT Web Agent - ReAct 패턴 구현

Based on LLM_OSINT by Shrivu Shankar (MIT License)
Modified for AOL_SERVICE_DEMO integration
"""

import logging
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from langchain.agents import AgentType, initialize_agent
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI
from app.features.osint_profiler.tools.langchain_wrappers import OSINTToolFactory
from app.core.settings.api_keys.crud.api_keys_settings_crud import get_apikey

logger = logging.getLogger(__name__)


class OSINTWebAgent:
    """
    ReAct 패턴을 사용하는 OSINT 조사 에이전트

    Thought (생각) → Action (행동) → Observation (관찰) 루프
    """

    def __init__(
        self,
        db: Session,
        llm_model: str = "gpt-4",
        max_iterations: int = 10,
        verbose: bool = True
    ):
        self.db = db
        self.llm_model = llm_model
        self.max_iterations = max_iterations
        self.verbose = verbose

        # LLM 설정
        self.llm = self._setup_llm()

        # OSINT 도구 로드
        tool_factory = OSINTToolFactory(db)
        self.tools = tool_factory.create_all_tools()

        # ReAct Agent 초기화
        self.agent = initialize_agent(
            tools=self.tools,
            llm=self.llm,
            agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
            verbose=verbose,
            max_iterations=max_iterations,
            handle_parsing_errors=True,
            early_stopping_method="generate"
        )

        logger.info(f"OSINTWebAgent initialized with {len(self.tools)} tools")

    def _setup_llm(self):
        """LLM 모델 설정"""
        # API 키 가져오기
        openai_key_obj = get_apikey(name="openai", db=self.db)
        anthropic_key_obj = get_apikey(name="anthropic", db=self.db)
        gemini_key_obj = get_apikey(name="gemini", db=self.db)

        openai_api_key = openai_key_obj.get('key') if openai_key_obj else None
        anthropic_api_key = anthropic_key_obj.get('key') if anthropic_key_obj else None
        gemini_api_key = gemini_key_obj.get('key') if gemini_key_obj else None

        # 모델 선택
        if "gpt" in self.llm_model.lower() and openai_api_key:
            return ChatOpenAI(
                model_name=self.llm_model,
                openai_api_key=openai_api_key,
                temperature=0.1,  # 낮은 temperature로 일관성 확보
                max_tokens=2000
            )
        elif "claude" in self.llm_model.lower() and anthropic_api_key:
            return ChatAnthropic(
                model_name=self.llm_model,
                anthropic_api_key=anthropic_api_key,
                temperature=0.1,
                max_tokens=2000
            )
        elif "gemini" in self.llm_model.lower() and gemini_api_key:
            return ChatGoogleGenerativeAI(
                model=self.llm_model,
                google_api_key=gemini_api_key,
                temperature=0.1,
                max_output_tokens=2000
            )
        else:
            # 기본값: GPT-4
            if openai_api_key:
                return ChatOpenAI(
                    model_name="gpt-4",
                    openai_api_key=openai_api_key,
                    temperature=0.1,
                    max_tokens=2000
                )
            else:
                raise ValueError("사용 가능한 LLM API 키가 없습니다")

    async def investigate(self, query: str, context: str = "") -> Dict[str, Any]:
        """
        OSINT 조사 수행

        Args:
            query: 조사 대상 (이메일, IP, 도메인 등)
            context: 추가 컨텍스트 (예: "피싱 의심", "악성코드 분석")

        Returns:
            {
                "query": 입력 쿼리,
                "result": LLM 최종 결론,
                "intermediate_steps": 실행된 도구와 결과,
                "tool_calls": 호출된 도구 수
            }
        """
        logger.info(f"Starting investigation for: {query}")

        # 조사 프롬프트 구성
        investigation_prompt = self._build_investigation_prompt(query, context)

        try:
            # Agent 실행
            result = self.agent.invoke({"input": investigation_prompt})

            return {
                "query": query,
                "context": context,
                "result": result.get('output', ''),
                "intermediate_steps": result.get('intermediate_steps', []),
                "tool_calls": len(result.get('intermediate_steps', []))
            }

        except Exception as e:
            logger.error(f"Investigation failed: {str(e)}", exc_info=True)
            return {
                "query": query,
                "error": str(e),
                "result": f"조사 중 오류 발생: {str(e)}"
            }

    def _build_investigation_prompt(self, query: str, context: str) -> str:
        """조사 프롬프트 생성"""
        base_prompt = f"""
당신은 OSINT(Open Source Intelligence) 전문가입니다.

조사 대상: {query}
"""

        if context:
            base_prompt += f"추가 정보: {context}\n"

        base_prompt += """

다음 지침을 따라 조사를 수행하세요:

1. 먼저 입력 유형을 식별하세요 (이메일/IP/도메인/URL/해시)
2. 해당 유형에 적합한 도구를 선택하세요
3. 우선순위가 높은 도구부터 실행하세요:
   - 이메일: haveibeenpwned_check → emailrep_check → hunter_email_check
   - IP: abuseipdb_check → virustotal_ip_check → shodan_check
   - 도메인: virustotal_domain_check → urlscan_check → alienvault_domain_check
   - 해시: virustotal_hash_check → malwarebazaar_check
4. 각 도구의 결과를 분석하고 추가 조사가 필요한지 판단하세요
5. 최종 결론을 작성하세요:
   - 위협 수준 (안전/의심/위험/고위험)
   - 핵심 발견 사항
   - 권장 조치

제약 조건:
- 최대 {max_iterations}번의 도구 호출만 가능합니다
- 동일한 도구를 반복 호출하지 마세요
- 명확한 결론에 도달하면 조사를 종료하세요
""".format(max_iterations=self.max_iterations)

        return base_prompt

    def get_available_tools_summary(self) -> List[str]:
        """사용 가능한 도구 목록 반환"""
        return [tool.name for tool in self.tools]
```

##### 2.3 FastAPI 엔드포인트 추가

**파일:** `backend/app/features/osint_profiler/routers/osint_routes.py`

```python
"""
OSINT Profiler API 라우터
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from app.core.database import get_db
from app.features.osint_profiler.agents.web_agent import OSINTWebAgent

router = APIRouter(prefix="/api/osint", tags=["OSINT Profiler"])


class InvestigationRequest(BaseModel):
    """조사 요청 모델"""
    query: str = Field(..., description="조사 대상 (이메일, IP, 도메인 등)")
    context: Optional[str] = Field(None, description="추가 컨텍스트")
    llm_model: Optional[str] = Field("gpt-4", description="사용할 LLM 모델")
    max_iterations: Optional[int] = Field(10, description="최대 반복 횟수")

    class Config:
        json_schema_extra = {
            "example": {
                "query": "araiunity@gmail.com",
                "context": "피싱 의심 이메일",
                "llm_model": "gpt-4",
                "max_iterations": 10
            }
        }


class InvestigationResponse(BaseModel):
    """조사 결과 모델"""
    query: str
    context: Optional[str]
    result: str
    tool_calls: int
    intermediate_steps: list


@router.post("/investigate", response_model=InvestigationResponse)
async def investigate_ioc(
    request: InvestigationRequest,
    db: Session = Depends(get_db)
):
    """
    OSINT 자동 조사 수행

    LLM이 입력을 분석하고 자동으로 적절한 도구를 선택하여 조사합니다.
    """
    try:
        # Web Agent 생성
        agent = OSINTWebAgent(
            db=db,
            llm_model=request.llm_model,
            max_iterations=request.max_iterations,
            verbose=True
        )

        # 조사 실행
        result = await agent.investigate(
            query=request.query,
            context=request.context or ""
        )

        return InvestigationResponse(**result)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tools")
async def get_available_tools(db: Session = Depends(get_db)):
    """사용 가능한 OSINT 도구 목록 조회"""
    from app.features.osint_profiler.tools.langchain_wrappers import OSINTToolFactory

    factory = OSINTToolFactory(db)
    summary = factory.get_tools_summary()

    return summary
```

##### 2.4 메인 앱에 라우터 등록

**파일:** `backend/app/main.py` (기존 파일 수정)

```python
# 기존 import에 추가
from app.features.osint_profiler.routers import osint_routes

# 기존 app 생성 후 라우터 추가
app.include_router(osint_routes.router)
```

##### 2.5 Week 2 검증 기준

**완료 조건:**
- ✅ `web_agent.py` 작성 완료
- ✅ `content_processor.py` 작성 완료
- ✅ FastAPI 엔드포인트 `/api/osint/investigate` 동작
- ✅ 실제 조사 테스트 성공

**테스트 명령:**
```bash
# 서버 시작
cd backend
uvicorn app.main:app --reload

# 다른 터미널에서 API 테스트
curl -X POST "http://localhost:8000/api/osint/investigate" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "1.2.3.4",
    "context": "의심스러운 IP",
    "llm_model": "gpt-4",
    "max_iterations": 5
  }'
```

**예상 출력:**
```json
{
  "query": "1.2.3.4",
  "context": "의심스러운 IP",
  "result": "조사 결과: 1.2.3.4는 고위험 IP로 판단됩니다.\n\n핵심 발견사항:\n1. AbuseIPDB - Abuse Score 100%, 543 reports\n2. VirusTotal - 15/89 engines flagged as malicious\n3. Shodan - Ports 22, 80, 443 open\n\n권장 조치: 즉시 차단",
  "tool_calls": 3,
  "intermediate_steps": [
    ["abuseipdb_check", "1.2.3.4"],
    ["virustotal_ip_check", "1.2.3.4"],
    ["shodan_check", "1.2.3.4"]
  ]
}
```

---

### Week 3: Knowledge Agent + 피드백 루프 구현

#### 목표
ReAct Agent를 오케스트레이션하고 결과 기반 추가 조사를 자동으로 결정하는 Knowledge Agent 구현

#### 작업 내용

##### 3.1 Knowledge Agent 구현

**파일:** `backend/app/features/osint_profiler/agents/knowledge_agent.py`

```python
"""
OSINT Knowledge Agent - 반복적 조사 오케스트레이터

Based on LLM_OSINT by Shrivu Shankar (MIT License)
Modified for AOL_SERVICE_DEMO integration with existing API clients
"""

import logging
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.utils.llm_service import LLMService, create_llm_service
from app.features.osint_profiler.agents.web_agent import OSINTWebAgent
from app.features.osint_profiler.utils.content_processor import ContentProcessor

logger = logging.getLogger(__name__)


class OSINTKnowledgeAgent:
    """
    LLM 기반 OSINT 조사 오케스트레이터

    여러 ReAct Agent를 조율하고 피드백 루프를 통해 심화 조사 수행
    """

    def __init__(
        self,
        db: Session,
        llm_model: str = "gpt-4",
        verbose: bool = True
    ):
        self.db = db
        self.llm_model = llm_model
        self.verbose = verbose

        # LLM 서비스
        self.llm_service = create_llm_service(db)

        # Content Processor
        self.processor = ContentProcessor(db, llm_model)

        logger.info(f"OSINTKnowledgeAgent initialized with model: {llm_model}")

    async def investigate(
        self,
        initial_query: str,
        context: str = "",
        deep_dive_rounds: int = 2,
        topics_per_round: int = 3,
        max_api_calls: int = 20
    ) -> Dict[str, Any]:
        """
        반복적 OSINT 조사 수행

        Args:
            initial_query: 초기 조사 대상
            context: 추가 컨텍스트
            deep_dive_rounds: 심화 조사 라운드 수
            topics_per_round: 라운드당 조사할 주제 수
            max_api_calls: 최대 API 호출 횟수 (비용 제한)

        Returns:
            {
                "initial_query": 초기 쿼리,
                "total_rounds": 총 라운드 수,
                "findings": 라운드별 발견사항,
                "summary": 최종 요약,
                "total_api_calls": 총 API 호출 수
            }
        """
        logger.info(f"Starting knowledge agent investigation: {initial_query}")

        findings = []
        total_api_calls = 0

        # Round 0: 초기 조사
        web_agent = OSINTWebAgent(self.db, self.llm_model, verbose=self.verbose)
        initial_result = await web_agent.investigate(initial_query, context)

        findings.append({
            "round": 0,
            "type": "initial",
            "query": initial_query,
            "result": initial_result['result'],
            "tool_calls": initial_result['tool_calls']
        })

        total_api_calls += initial_result['tool_calls']

        logger.info(f"Round 0 completed. API calls: {initial_result['tool_calls']}")

        # Deep Dive Rounds: 심화 조사
        for round_num in range(1, deep_dive_rounds + 1):
            if total_api_calls >= max_api_calls:
                logger.warning(f"API call limit reached: {max_api_calls}")
                break

            # LLM에게 다음 조사 주제 결정 요청
            next_topics = await self._decide_next_topics(
                findings,
                topics_per_round,
                max_api_calls - total_api_calls
            )

            if not next_topics:
                logger.info(f"No more topics to investigate at round {round_num}")
                break

            # 각 주제에 대해 조사 수행
            round_findings = []
            for topic in next_topics:
                if total_api_calls >= max_api_calls:
                    break

                logger.info(f"Round {round_num} - Investigating: {topic}")

                # 새로운 Web Agent로 조사
                topic_result = await web_agent.investigate(topic, context)

                round_findings.append({
                    "topic": topic,
                    "result": topic_result['result'],
                    "tool_calls": topic_result['tool_calls']
                })

                total_api_calls += topic_result['tool_calls']

            findings.append({
                "round": round_num,
                "type": "deep_dive",
                "topics": next_topics,
                "findings": round_findings,
                "total_tool_calls": sum(f['tool_calls'] for f in round_findings)
            })

            logger.info(f"Round {round_num} completed. API calls: {total_api_calls}")

        # 최종 요약 생성
        summary = await self._generate_final_summary(findings)

        return {
            "initial_query": initial_query,
            "context": context,
            "total_rounds": len(findings),
            "findings": findings,
            "summary": summary,
            "total_api_calls": total_api_calls,
            "max_api_calls": max_api_calls
        }

    async def _decide_next_topics(
        self,
        findings: List[Dict],
        max_topics: int,
        remaining_api_calls: int
    ) -> List[str]:
        """
        LLM이 기존 발견 내용을 분석하고 다음 조사 주제 결정

        이것이 피드백 루프의 핵심!
        """
        # 발견 내용 요약
        findings_summary = self._format_findings_for_llm(findings)

        system_prompt = """
당신은 OSINT 조사 전문가입니다.
지금까지의 조사 결과를 분석하고, 추가로 깊이 조사할 가치가 있는 주제를 제안하세요.

제안 기준:
1. 초기 조사에서 새로운 IOC가 발견된 경우 (예: IP 조사 중 도메인 발견)
2. 의심스러운 연관성이 발견된 경우
3. 불완전하거나 상충되는 정보가 있는 경우
4. 공격 인프라를 더 파악할 필요가 있는 경우

제안하지 말아야 할 것:
1. 이미 충분히 조사된 주제
2. 결론이 명확한 경우
3. 추가 조사로 얻을 정보가 적은 경우
"""

        user_prompt = f"""
지금까지의 조사 결과:

{findings_summary}

남은 API 호출 가능 횟수: {remaining_api_calls}

위 결과를 바탕으로 추가 조사가 필요한 주제를 {max_topics}개 이하로 제안하세요.
각 주제는 구체적인 조사 대상(이메일, IP, 도메인 등)을 포함해야 합니다.

만약 추가 조사가 필요 없다면 "STOP"이라고만 답하세요.

형식:
1. [조사 대상]: [이유]
2. [조사 대상]: [이유]
"""

        response = self.llm_service.execute_prompt(
            self.llm_model,
            system_prompt,
            user_prompt,
            temperature=0.3  # 일관성 있는 주제 선택
        )

        # 응답 파싱
        if "STOP" in response.upper():
            return []

        topics = []
        for line in response.split('\n'):
            line = line.strip()
            if line and (line[0].isdigit() or line.startswith('-')):
                # "1. example.com: 의심스러운 도메인" → "example.com"
                parts = line.split(':', 1)
                if len(parts) >= 1:
                    topic = parts[0].strip()
                    # 번호 제거
                    topic = topic.lstrip('0123456789.-) ')
                    if topic:
                        topics.append(topic)

        return topics[:max_topics]

    def _format_findings_for_llm(self, findings: List[Dict]) -> str:
        """발견 내용을 LLM이 읽기 쉬운 형식으로 변환"""
        formatted = []

        for finding in findings:
            round_num = finding['round']

            if finding['type'] == 'initial':
                formatted.append(f"""
=== Round {round_num}: 초기 조사 ===
대상: {finding['query']}
결과:
{finding['result'][:500]}...
도구 호출 수: {finding['tool_calls']}
""")
            else:  # deep_dive
                formatted.append(f"\n=== Round {round_num}: 심화 조사 ===")
                for topic_finding in finding['findings']:
                    formatted.append(f"""
주제: {topic_finding['topic']}
결과:
{topic_finding['result'][:300]}...
""")

        return '\n'.join(formatted)

    async def _generate_final_summary(self, findings: List[Dict]) -> str:
        """모든 발견 내용을 종합하여 최종 요약 생성"""
        findings_text = self._format_findings_for_llm(findings)

        system_prompt = """
당신은 OSINT 조사 보고서를 작성하는 전문가입니다.
여러 라운드에 걸친 조사 결과를 종합하여 명확하고 실행 가능한 보고서를 작성하세요.
"""

        user_prompt = f"""
다음은 {len(findings)}개 라운드에 걸친 OSINT 조사 결과입니다:

{findings_text}

위 결과를 종합하여 다음 형식의 최종 보고서를 작성하세요:

## 조사 요약
[한 줄 요약]

## 위협 평가
- 위협 수준: [안전/의심/위험/고위험]
- 신뢰도: [낮음/중간/높음]

## 핵심 발견사항
1. [발견사항 1]
2. [발견사항 2]
3. [발견사항 3]

## 연관된 IOC
- [발견된 모든 IOC 나열: IP, 도메인, 이메일 등]

## 권장 조치
1. [즉시 조치]
2. [추가 조사 필요 사항]
3. [모니터링 권장 사항]

## 조사 통계
- 총 라운드: [N]
- 총 도구 호출: [N]
- 조사 범위: [초기 대상 → 확장된 대상들]
"""

        summary = self.llm_service.execute_prompt(
            self.llm_model,
            system_prompt,
            user_prompt,
            temperature=0.2,
            max_tokens=2000
        )

        return summary
```

##### 3.2 피드백 루프 워크플로우

**파일:** `backend/app/features/osint_profiler/workflows/feedback_loop.py`

```python
"""
OSINT 피드백 루프 워크플로우

자동 IOC 추출 및 크로스 타입 연계 조사
"""

import re
import logging
from typing import List, Dict, Any, Set
from sqlalchemy.orm import Session
from app.features.osint_profiler.agents.knowledge_agent import OSINTKnowledgeAgent

logger = logging.getLogger(__name__)


class FeedbackLoopWorkflow:
    """
    결과 기반 자동 피드백 루프

    예: 이메일 조사 → 도메인 발견 → 도메인 조사 → IP 발견 → IP 조사
    """

    def __init__(self, db: Session, llm_model: str = "gpt-4"):
        self.db = db
        self.knowledge_agent = OSINTKnowledgeAgent(db, llm_model)

    async def investigate_with_auto_expansion(
        self,
        initial_ioc: str,
        max_expansion_depth: int = 3,
        max_total_iocs: int = 10
    ) -> Dict[str, Any]:
        """
        자동 확장 조사

        초기 IOC를 조사하고, 결과에서 새로운 IOC를 추출하여 재귀적으로 조사

        Args:
            initial_ioc: 시작 IOC
            max_expansion_depth: 최대 확장 깊이
            max_total_iocs: 조사할 최대 IOC 수

        Returns:
            전체 조사 결과 및 IOC 그래프
        """
        investigated_iocs: Set[str] = set()
        all_findings = []
        ioc_graph = {"nodes": [], "edges": []}

        # BFS로 IOC 확장
        queue = [(initial_ioc, 0)]  # (ioc, depth)

        while queue and len(investigated_iocs) < max_total_iocs:
            current_ioc, depth = queue.pop(0)

            if current_ioc in investigated_iocs:
                continue

            if depth > max_expansion_depth:
                continue

            logger.info(f"Investigating {current_ioc} at depth {depth}")

            # 조사 수행
            result = await self.knowledge_agent.investigate(
                initial_query=current_ioc,
                deep_dive_rounds=1,  # 자동 확장이므로 deep dive는 1 라운드만
                topics_per_round=2
            )

            investigated_iocs.add(current_ioc)
            all_findings.append({
                "ioc": current_ioc,
                "depth": depth,
                "result": result
            })

            # 그래프에 노드 추가
            ioc_graph["nodes"].append({
                "id": current_ioc,
                "type": self._identify_ioc_type(current_ioc),
                "depth": depth
            })

            # 결과에서 새로운 IOC 추출
            new_iocs = self._extract_iocs_from_result(result)

            for new_ioc in new_iocs:
                if new_ioc not in investigated_iocs:
                    queue.append((new_ioc, depth + 1))

                    # 그래프에 엣지 추가
                    ioc_graph["edges"].append({
                        "source": current_ioc,
                        "target": new_ioc,
                        "relationship": "discovered_in"
                    })

        return {
            "initial_ioc": initial_ioc,
            "investigated_iocs": list(investigated_iocs),
            "total_iocs": len(investigated_iocs),
            "max_depth_reached": max(f['depth'] for f in all_findings),
            "findings": all_findings,
            "ioc_graph": ioc_graph
        }

    def _identify_ioc_type(self, ioc: str) -> str:
        """IOC 유형 식별"""
        # 이메일
        if '@' in ioc and '.' in ioc:
            return "email"

        # IPv4
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
            return "ipv4"

        # 도메인
        if '.' in ioc and not ioc.startswith('http'):
            return "domain"

        # URL
        if ioc.startswith('http'):
            return "url"

        # 해시 (간단한 추정)
        if re.match(r'^[a-fA-F0-9]{32}$', ioc):
            return "md5"
        if re.match(r'^[a-fA-F0-9]{40}$', ioc):
            return "sha1"
        if re.match(r'^[a-fA-F0-9]{64}$', ioc):
            return "sha256"

        return "unknown"

    def _extract_iocs_from_result(self, result: Dict[str, Any]) -> List[str]:
        """조사 결과에서 IOC 추출"""
        iocs = []

        # 결과 텍스트 추출
        text = result.get('summary', '')
        for finding in result.get('findings', []):
            if finding.get('type') == 'initial':
                text += ' ' + finding.get('result', '')
            else:
                for f in finding.get('findings', []):
                    text += ' ' + f.get('result', '')

        # 이메일 추출
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
        iocs.extend(emails)

        # IPv4 추출
        ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)
        iocs.extend(ips)

        # 도메인 추출 (간단한 패턴)
        domains = re.findall(r'\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b', text)
        iocs.extend(domains)

        # URL 추출
        urls = re.findall(r'https?://[^\s]+', text)
        iocs.extend(urls)

        # 중복 제거 및 자기 자신 제외
        unique_iocs = list(set(iocs))

        # 최대 5개만 반환 (무한 확장 방지)
        return unique_iocs[:5]
```

##### 3.3 Knowledge Agent 엔드포인트 추가

**파일:** `backend/app/features/osint_profiler/routers/osint_routes.py` (기존 파일에 추가)

```python
# 기존 import에 추가
from app.features.osint_profiler.agents.knowledge_agent import OSINTKnowledgeAgent
from app.features.osint_profiler.workflows.feedback_loop import FeedbackLoopWorkflow


class KnowledgeAgentRequest(BaseModel):
    """Knowledge Agent 요청 모델"""
    query: str = Field(..., description="조사 대상")
    context: Optional[str] = Field(None, description="추가 컨텍스트")
    deep_dive_rounds: Optional[int] = Field(2, description="심화 조사 라운드 수")
    topics_per_round: Optional[int] = Field(3, description="라운드당 조사할 주제 수")
    max_api_calls: Optional[int] = Field(20, description="최대 API 호출 횟수")
    llm_model: Optional[str] = Field("gpt-4", description="사용할 LLM 모델")


class FeedbackLoopRequest(BaseModel):
    """피드백 루프 요청 모델"""
    initial_ioc: str = Field(..., description="시작 IOC")
    max_expansion_depth: Optional[int] = Field(3, description="최대 확장 깊이")
    max_total_iocs: Optional[int] = Field(10, description="조사할 최대 IOC 수")
    llm_model: Optional[str] = Field("gpt-4", description="사용할 LLM 모델")


@router.post("/knowledge-agent")
async def knowledge_agent_investigate(
    request: KnowledgeAgentRequest,
    db: Session = Depends(get_db)
):
    """
    Knowledge Agent를 사용한 심화 조사

    여러 라운드에 걸쳐 LLM이 자동으로 추가 조사 주제를 선택합니다.
    """
    try:
        agent = OSINTKnowledgeAgent(db, llm_model=request.llm_model)

        result = await agent.investigate(
            initial_query=request.query,
            context=request.context or "",
            deep_dive_rounds=request.deep_dive_rounds,
            topics_per_round=request.topics_per_round,
            max_api_calls=request.max_api_calls
        )

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/feedback-loop")
async def feedback_loop_investigation(
    request: FeedbackLoopRequest,
    db: Session = Depends(get_db)
):
    """
    자동 확장 조사 (피드백 루프)

    초기 IOC를 조사하고, 발견된 새로운 IOC를 자동으로 추가 조사합니다.
    예: 이메일 → 도메인 → IP → 관련 도메인
    """
    try:
        workflow = FeedbackLoopWorkflow(db, llm_model=request.llm_model)

        result = await workflow.investigate_with_auto_expansion(
            initial_ioc=request.initial_ioc,
            max_expansion_depth=request.max_expansion_depth,
            max_total_iocs=request.max_total_iocs
        )

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
```

##### 3.4 Week 3 검증 기준

**완료 조건:**
- ✅ `knowledge_agent.py` 작성 완료
- ✅ `feedback_loop.py` 작성 완료
- ✅ 엔드포인트 `/api/osint/knowledge-agent` 동작
- ✅ 엔드포인트 `/api/osint/feedback-loop` 동작
- ✅ 피드백 루프 테스트 성공 (이메일 → 도메인 → IP 자동 추적)

**테스트 시나리오:**

```bash
# 1. Knowledge Agent 테스트
curl -X POST "http://localhost:8000/api/osint/knowledge-agent" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "araiunity@gmail.com",
    "deep_dive_rounds": 2,
    "topics_per_round": 2,
    "max_api_calls": 15
  }'
```

**예상 출력:**
```json
{
  "initial_query": "araiunity@gmail.com",
  "total_rounds": 3,
  "findings": [
    {
      "round": 0,
      "type": "initial",
      "query": "araiunity@gmail.com",
      "result": "유출 이력 없음, 도메인 gmail.com은 정상",
      "tool_calls": 3
    },
    {
      "round": 1,
      "type": "deep_dive",
      "topics": ["gmail.com", "araiunity GitHub 검색"],
      "findings": [...],
      "total_tool_calls": 4
    }
  ],
  "summary": "## 조사 요약\n이메일 araiunity@gmail.com은 정상적인 Gmail 계정으로 판단됨\n\n## 위협 평가\n- 위협 수준: 안전\n...",
  "total_api_calls": 7
}
```

```bash
# 2. 피드백 루프 테스트 (자동 확장)
curl -X POST "http://localhost:8000/api/osint/feedback-loop" \
  -H "Content-Type: application/json" \
  -d '{
    "initial_ioc": "malicious@phishing-site.com",
    "max_expansion_depth": 2,
    "max_total_iocs": 5
  }'
```

**예상 출력:**
```json
{
  "initial_ioc": "malicious@phishing-site.com",
  "investigated_iocs": [
    "malicious@phishing-site.com",
    "phishing-site.com",
    "45.142.212.61",
    "another-phishing.com"
  ],
  "total_iocs": 4,
  "max_depth_reached": 2,
  "ioc_graph": {
    "nodes": [
      {"id": "malicious@phishing-site.com", "type": "email", "depth": 0},
      {"id": "phishing-site.com", "type": "domain", "depth": 1},
      {"id": "45.142.212.61", "type": "ipv4", "depth": 2}
    ],
    "edges": [
      {"source": "malicious@phishing-site.com", "target": "phishing-site.com", "relationship": "discovered_in"},
      {"source": "phishing-site.com", "target": "45.142.212.61", "relationship": "discovered_in"}
    ]
  }
}
```

---

## Phase 1 완료 기준

### ✅ 최종 검증 체크리스트

#### 기능 검증
- [ ] 이메일 입력 시 LLM이 자동으로 이메일 도구 선택
- [ ] IP 입력 시 LLM이 자동으로 IP 도구 선택
- [ ] 도메인 입력 시 LLM이 자동으로 도메인 도구 선택
- [ ] 피드백 루프: 이메일 → 도메인 → IP 자동 추적 동작
- [ ] Knowledge Agent: 2-3 라운드 심화 조사 동작
- [ ] API 호출 횟수 제한 동작 (max_api_calls)

#### 성능 검증
- [ ] 단일 조사 (ReAct Agent): 평균 10-30초 이내 완료
- [ ] Knowledge Agent (2 rounds): 평균 1-2분 이내 완료
- [ ] 피드백 루프 (depth=2): 평균 2-3분 이내 완료

#### 비용 검증
- [ ] 단일 조사: 평균 3-5개 API 호출
- [ ] Knowledge Agent: 평균 7-15개 API 호출
- [ ] 피드백 루프: 평균 10-20개 API 호출

#### 문서화
- [ ] API 문서 자동 생성 (FastAPI Swagger)
- [ ] 사용 예시 README 작성
- [ ] 저작권 고지 파일 작성 (THIRD_PARTY_LICENSES.md)

---

## 📚 저작권 고지

**파일:** `backend/app/features/osint_profiler/THIRD_PARTY_LICENSES.md`

```markdown
# Third-Party Licenses

## LLM_OSINT

This OSINT Profiler module incorporates architectural patterns and concepts from LLM_OSINT.

**Original Repository:** https://github.com/ShrivuShankar/LLM_OSINT
**Author:** Shrivu Shankar
**License:** MIT License

Copyright (c) 2023 Shrivu Shankar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

### Modifications Made

- Integrated with existing LLM service (`app/utils/llm_service.py`)
- Adapted to use existing OSINT API clients (25 services in `external_api_clients.py`)
- Added SQLAlchemy database integration for API key management
- Restructured for FastAPI framework
- Added Korean language support
- Implemented cost controls (max_api_calls parameter)
- Added IOC graph visualization for feedback loop
```

---

## 🚀 Phase 2 Preview (1주, Week 4)

Phase 1 완료 후 진행할 Profil3r 통합 작업:

### Profil3r 통합 계획
1. **순열 생성기** (1-2일)
   - `backend/app/features/osint_profiler/utils/permutations.py`
   - 이름 → 이메일 후보 자동 생성
   - Knowledge Agent 앞단에 연결

2. **이메일 검증기** (1일)
   - `backend/app/features/osint_profiler/validators/email_validator.py`
   - MX 레코드 확인
   - API 호출 전 사전 필터링

3. **워커 풀** (2-3일)
   - `backend/app/features/osint_profiler/utils/async_executor.py`
   - asyncio + Semaphore
   - 동시 API 호출 최적화

4. **다중 포맷 리포트** (2-3일)
   - `backend/app/features/osint_profiler/reports/report_generator.py`
   - JSON, CSV, HTML 생성
   - Jinja2 템플릿

---

## 📖 다음 세션에서 Claude에게 전달할 내용

**Phase 1 작업을 시작하려면 이 문서를 Claude에게 제공하고 다음과 같이 말하세요:**

```
이 OSINT_INTEGRATION_PLAN.md 파일을 읽고 Phase 1 Week 1부터 시작해줘.
Week 1 작업: LangChain Tools 래핑 구현

먼저 다음을 확인하고 진행:
1. backend/requirements.txt에 langchain 의존성 추가
2. 디렉토리 구조 생성
3. langchain_wrappers.py 작성
4. 테스트 작성 및 실행

각 단계마다 완료 확인을 받고 다음으로 넘어가자.
```

**또는 특정 주차를 시작하려면:**

```
OSINT_INTEGRATION_PLAN.md의 Week 2부터 시작해줘.
ReAct Agent 구현부터 진행하자.
```

**또는 검증만 하려면:**

```
OSINT_INTEGRATION_PLAN.md의 Phase 1 완료 기준에 따라
현재 구현 상태를 검증해줘.
```

---

## 🎯 성공 지표

Phase 1 완료 시 다음이 가능해야 합니다:

### 시나리오 1: 이메일 자동 조사
```bash
입력: "suspicious@example.com"
결과: LLM이 자동으로 HaveIBeenPwned → EmailRep → Hunter 순서로 실행
시간: 20-30초
API 호출: 3-5회
```

### 시나리오 2: IP 자동 조사
```bash
입력: "45.142.212.61"
결과: LLM이 자동으로 AbuseIPDB → VirusTotal → Shodan 순서로 실행
시간: 15-25초
API 호출: 3-4회
```

### 시나리오 3: 크로스 타입 자동 추적
```bash
입력: "malicious@phishing-site.com"
결과:
  Round 0: 이메일 조사 → 도메인 "phishing-site.com" 발견
  Round 1: 도메인 조사 → IP "45.142.212.61" 발견
  Round 2: IP 조사 → 관련 도메인 5개 추가 발견
시간: 2-3분
API 호출: 12-15회
총 IOC: 7개
```

### 시나리오 4: 심화 조사
```bash
입력: "1.2.3.4" + context: "APT 공격 의심"
결과:
  Round 0: IP 기본 조사
  Round 1: LLM이 "관련 도메인 조사" + "GitHub 검색" 제안
  Round 2: LLM이 "암호화폐 주소 추적" + "C&C 인프라 분석" 제안
시간: 1.5-2분
API 호출: 10-12회
```

---

## 💡 트러블슈팅 가이드

### 문제 1: LangChain 도구 호출 실패
**증상:** `Tool execution failed: Tool not found`
**해결:**
```python
# langchain_wrappers.py에서 도구 이름 확인
tools = factory.create_all_tools()
for tool in tools:
    print(f"Tool name: {tool.name}")

# Agent 초기화 시 올바른 도구 전달 확인
```

### 문제 2: LLM이 환각(Hallucination)
**증상:** 존재하지 않는 도구를 호출 시도
**해결:**
```python
# Tool description을 더 명확하게 작성
# "지원하지 않는 것" 명시 추가
description="""
이 도구는 IP 주소만 조회합니다.
지원: IPv4 주소 (예: 1.2.3.4)
지원 안 함: 도메인, 이메일, 비트코인 주소
"""
```

### 문제 3: API 비용 폭증
**증상:** 하나의 조사에서 30번 이상 API 호출
**해결:**
```python
# max_api_calls 파라미터 강제
agent.investigate(
    query="...",
    max_api_calls=10  # 강제 제한
)

# Knowledge Agent에서 제한 적용
if total_api_calls >= max_api_calls:
    break
```

### 문제 4: 응답 시간 느림
**증상:** 단일 조사에 2분 이상 소요
**해결:**
```python
# Week 4에서 구현할 워커 풀 사용
# 현재는 LLM timeout 설정
ChatOpenAI(
    model_name="gpt-4",
    request_timeout=30  # 30초 타임아웃
)
```

---

## 📝 다음 단계 요약

1. **이 문서를 저장**하고 Claude에게 제공
2. **Week 1부터 순차적으로 진행**
3. **각 주차 완료 시 검증** 실행
4. **Phase 1 완료 후 Phase 2로 진행**

**예상 일정:**
- Week 1: 1주일 (LangChain Tools)
- Week 2: 1주일 (ReAct Agent)
- Week 3: 1주일 (Knowledge Agent + 피드백 루프)
- **Total: 3주**

**최종 결과물:**
- ✅ LLM 기반 OSINT 자동화 시스템
- ✅ 이메일/IP/도메인 자동 조사
- ✅ 피드백 루프 (크로스 타입 추적)
- ✅ Knowledge Agent (심화 조사)
- ✅ 25개 API 자동 선택 및 실행

이 시스템이 완성되면 사용자는 단순히 "araiunity@gmail.com"만 입력하면, LLM이 자동으로:
1. 이메일 유형 식별
2. 적절한 도구 선택 (HaveIBeenPwned, EmailRep, Hunter)
3. 순서대로 실행
4. 결과 분석
5. 추가 조사 필요 시 도메인/IP 자동 추적
6. 최종 보고서 생성

**모든 것이 자동화됩니다!** 🎉
