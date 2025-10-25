# 🔄 AOL_SERVICE_DEMO 기존 아키텍처 재사용 가이드

> **작성일**: 2025-10-07
> **목적**: OSINT 프로파일링 자동화(Week 1-4) 개발 시 기존 인프라 최대한 활용

---

## 📑 목차

1. [프로젝트 전체 구조](#1-프로젝트-전체-구조)
2. [백엔드 상세 분석](#2-백엔드-상세-분석)
3. [프론트엔드 상세 분석](#3-프론트엔드-상세-분석)
4. [Week별 재사용 전략](#4-week별-재사용-전략)
5. [구체적 코드 재사용 예시](#5-구체적-코드-재사용-예시)

---

## 1. 프로젝트 전체 구조

### 1.1 백엔드 아키텍처

```
backend/
├── main.py                          # FastAPI 엔트리포인트
├── app/
│   ├── core/                        # 핵심 유틸리티
│   │   ├── database.py              # ✅ DB 세션 관리
│   │   ├── dependencies.py          # ✅ get_db() 의존성
│   │   ├── healthcheck.py
│   │   ├── scheduler.py
│   │   ├── config/
│   │   │   └── fastapi_config.py
│   │   ├── alerts/                  # 알림 시스템
│   │   └── settings/                # 설정 관리
│   │       ├── api_keys/            # ✅ API 키 CRUD
│   │       ├── general/
│   │       ├── keywords/
│   │       ├── modules/
│   │       └── cti_profile/
│   │
│   ├── utils/
│   │   └── llm_service.py           # ✅ LLMService (재사용!)
│   │
│   └── features/                    # 기능 모듈
│       ├── domain_lookup/           # 도메인 조회
│       ├── email_analyzer/          # 이메일 분석
│       ├── ioc_tools/               # ⭐ IOC 도구 (핵심 재사용!)
│       │   ├── ioc_defanger/        # IOC Defang
│       │   ├── ioc_extractor/       # IOC 추출
│       │   └── ioc_lookup/          # ⭐ IOC Lookup Engine
│       │       ├── bulk_lookup/
│       │       └── single_lookup/   # ✅ 18개 API 클라이언트
│       │           ├── routers/
│       │           │   ├── single_ioc_lookup_routes.py    # ✅ API 엔드포인트 패턴
│       │           │   └── unified_routes.py
│       │           ├── service/
│       │           │   ├── external_api_clients.py        # ✅ 18개 API 함수
│       │           │   ├── ioc_lookup_engine.py           # ✅ 통합 Lookup 엔진
│       │           │   └── service_registry.py            # ✅ Service Registry 패턴
│       │           └── utils/
│       │               └── ioc_utils.py                   # ✅ IOC 타입 감지
│       │
│       ├── llm_templates/           # LLM 템플릿 관리
│       │   ├── crud/
│       │   ├── models/
│       │   ├── routers/
│       │   ├── schemas/
│       │   ├── service/
│       │   │   └── llm_templates_service.py
│       │   └── utils/
│       │       ├── default_llm_templates.py
│       │       └── web_fetcher.py
│       │
│       ├── newsfeed/                # ⭐ 뉴스 피드 (시각화 재사용!)
│       │   ├── crud/
│       │   ├── models/
│       │   ├── routers/
│       │   ├── schemas/
│       │   ├── service/
│       │   │   └── newsfeed_service.py
│       │   └── utils/
│       │       ├── default_rss_feeds.py
│       │       ├── fetching.py
│       │       └── validation.py
│       │
│       └── osint_profiler/          # 🆕 새로 개발할 부분
│           ├── agents/              # ❌ 비어있음 (개발 필요)
│           ├── routers/             # ❌ 비어있음 (개발 필요)
│           ├── tools/
│           │   └── langchain_wrappers.py    # ✅ 18개 LangChain Tools (완성!)
│           └── utils/               # ❌ 비어있음
```

### 1.2 프론트엔드 아키텍처

```
frontend/src/components/
├── cvss-calculator/            # CVSS 계산기
├── domain-monitoring/          # 도메인 모니터링
├── email-analyzer/             # 이메일 분석기
│
├── ioc-tools/                  # ⭐ IOC 도구 (UI 재사용!)
│   ├── ioc-defanger/
│   ├── ioc-extractor/
│   ├── ioc-lookup/             # ✅ IOC Lookup UI
│   │   └── shared/services/    # ✅ API별 결과 시각화 컴포넌트
│   │       ├── Virustotal/     # VirusTotal 결과 렌더링
│   │       ├── GitHub/         # GitHub 결과 렌더링
│   │       ├── AbuseIPDB/
│   │       └── ...             # 18개 API 전용 UI 컴포넌트
│   └── shared/                 # 공통 컴포넌트
│
├── llm_templates/              # ⭐ LLM 템플릿 UI (재사용!)
│   ├── common/
│   │   ├── TemplateExampleDialog.jsx
│   │   └── TemplateFormComponents.jsx
│   ├── components/
│   │   ├── TemplateCard.jsx            # ✅ 카드 UI
│   │   └── CreateTemplateForm.jsx
│   ├── pages/
│   │   ├── TemplatesPage.jsx           # ✅ 리스트 페이지 패턴
│   │   └── CreateTemplatePage.jsx
│   └── state/
│
├── newsfeed/                   # ⭐ 뉴스 피드 UI (시각화 재사용!)
│   ├── feed/
│   │   ├── Feed.jsx                    # ✅ 피드 리스트 UI
│   │   └── NewsfeedSkeleton.jsx        # ✅ 로딩 스켈레톤
│   ├── trends/
│   │   └── Trends.jsx                  # ✅ 트렌드 차트
│   ├── headlines/
│   │   └── Headlines.jsx               # ✅ 헤드라인 요약
│   └── settings/
│       └── ManageNewsfeeds.jsx
│
├── rule-creator/               # 규칙 생성기
│   ├── sigma/
│   ├── snort/
│   ├── yara/
│   └── utils/
│
├── services/                   # API 클라이언트
├── settings/                   # 설정 UI
├── styled/                     # 스타일 컴포넌트
└── ui/                         # 공통 UI 컴포넌트
```

---

## 2. 백엔드 상세 분석

### 2.1 Core 모듈 (100% 재사용 가능)

#### 2.1.1 데이터베이스 및 의존성

**파일**: `app/core/database.py`
```python
# SQLAlchemy 설정
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()
```

**재사용 방법**:
- ✅ `osint_profiler` 모든 모듈에서 동일한 DB 세션 사용
- ✅ Agent 클래스에서 `self.db = db` 패턴 유지

---

**파일**: `app/core/dependencies.py`
```python
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

**재사용 방법**:
```python
# osint_profiler/routers/osint_routes.py
from app.core.dependencies import get_db

@router.post("/api/osint/investigate/{agent_type}")
async def investigate(db: Session = Depends(get_db)):  # ← 그대로 사용!
    pass
```

---

#### 2.1.2 API 키 관리

**파일**: `app/core/settings/api_keys/crud/api_keys_settings_crud.py`

**주요 함수**:
```python
def get_apikey(name: str, db: Session) -> Optional[str]:
    """API 키 조회"""
    # OSINT API 키 + LLM API 키 모두 관리
    pass

def create_apikey(name: str, key: str, db: Session):
    """API 키 생성"""
    pass
```

**재사용 방법**:
```python
# osint_profiler/tools/langchain_wrappers.py (이미 사용 중!)
from app.core.settings.api_keys.crud.api_keys_settings_crud import get_apikey

class OSINTToolFactory:
    def _load_api_keys(self):
        for key_name in ['hibp_api_key', 'virustotal', ...]:
            key_value = get_apikey(self.db, key_name)  # ← 그대로 사용!
```

---

#### 2.1.3 LLM 서비스

**파일**: `app/utils/llm_service.py` (198줄)

**클래스**: `LLMService`
- OpenAI (gpt-3.5, gpt-4, gpt-4o)
- Anthropic (claude-3-haiku)
- Google (gemini-pro)

**주요 메서드**:
```python
def setup_openai_model(model_id, model_name, api_key, temperature, max_tokens):
    """OpenAI 모델 등록"""

def setup_anthropic_model(...):
    """Anthropic 모델 등록"""

def execute_prompt(model_id, system_prompt, user_prompt):
    """LLM 호출 실행"""
    return response.content
```

**재사용 방법**:
```python
# osint_profiler/agents/base_agent.py
from app.utils.llm_service import create_llm_service

class BaseOSINTAgent:
    def __init__(self, db: Session, llm_model: str = "gpt-4"):
        llm_service = create_llm_service(db)  # ← 그대로 사용!
        self.llm = llm_service.models[llm_model]
```

**계획표 적용**: Week 2 (BaseOSINTAgent 구현 시 100% 재사용)

---

### 2.2 IOC Tools 모듈 (⭐ 핵심 재사용 대상)

#### 2.2.1 External API Clients

**파일**: `app/features/ioc_tools/ioc_lookup/single_lookup/service/external_api_clients.py`

**구조**:
```python
# 에러 핸들링 (중앙화)
def handle_request_errors(service_name: str, response: requests.Response) -> Dict:
    """
    - HTTP 에러 처리
    - Rate limit 처리 (429)
    - JSON 파싱 에러 처리
    """

# 18개 API 클라이언트 함수
def abuseipdb_ip_check(ioc: str, apikey: str) -> Dict:
def virustotal(ioc: str, type: str, apikey: str) -> Dict:
def haveibeenpwnd_email_check(ioc: str, apikey: str) -> Dict:
def emailrep_email_check(ioc: str, apikey: str) -> Dict:
def hunter_email_check(ioc: str, apikey: str) -> Dict:
def check_shodan(ioc: str, apikey: str, method: str) -> Dict:
def crowdsec(ioc: str, apikey: str) -> Dict:
def alienvaultotx(ioc: str, apikey: str, type: str) -> Dict:
def safeBrowse_url_check(ioc: str, apikey: str) -> Dict:
def urlscanio(ioc: str) -> Dict:  # 무료, API 키 불필요
def malwarebazaar_hash_check(ioc: str) -> Dict:  # 무료
def threatfox_ip_check(ioc: str, apikey: str) -> Dict:
def urlhaus_url_check(ioc: str) -> Dict:  # 무료
def search_github(ioc: str, access_token: str) -> Dict:
def check_bgpview(ioc: str) -> Dict:  # 무료
def search_nist_nvd(ioc: str, apikey: str) -> Dict:
def check_pulsedive(ioc: str, apikey: str) -> Dict:
def search_reddit(ioc: str, client_id: str, client_secret: str) -> Dict:
```

**재사용 상태**:
- ✅ `langchain_wrappers.py`에서 **이미 래핑 완료**
- ✅ Week 1에서 **테스트만 하면 됨**

**테스트 방법**:
```bash
# 기존 엔드포인트로 테스트!
curl "http://localhost:8000/api/ioc/lookup/haveibeenpwned?ioc=test@example.com"
curl "http://localhost:8000/api/ioc/lookup/abuseipdb?ioc=8.8.8.8"
```

---

#### 2.2.2 Service Registry 패턴

**파일**: `app/features/ioc_tools/ioc_lookup/single_lookup/service/service_registry.py`

**구조**:
```python
# 글로벌 서비스 레지스트리
_services: Dict[str, Dict[str, Any]] = {}

def register_services(ioc_lookup_service_module):
    """18개 서비스 등록"""
    _services.update({
        'virustotal': {
            'func': ioc_lookup_service_module.virustotal,
            'name': 'VirusTotal',
            'api_key_name': 'virustotal',
            'supported_ioc_types': ['ipv4', 'ipv6', 'domain', 'url', 'hash'],
            'requires_type': True,
            'type_map': {...}
        },
        'abuseipdb': {
            'func': ioc_lookup_service_module.abuseipdb_ip_check,
            'name': 'AbuseIPDB',
            'api_key_name': 'abuseipdb',
            'supported_ioc_types': ['ipv4'],
        },
        # ... 18개 서비스
    })

def get_service(service_name: str) -> Optional[Dict]:
    """서비스 설정 조회"""
    return _services.get(service_name)

def get_all_services() -> List[str]:
    """모든 서비스 이름 목록"""
    return list(_services.keys())
```

**재사용 방법**:
```python
# osint_profiler/agents/agent_registry.py (신규 작성)
# 동일한 패턴으로 Agent 등록!

_agents: Dict[str, Type[BaseOSINTAgent]] = {}

def register_agents():
    from .specialized_agents import EmailAgent, IPAgent, ...
    _agents.update({
        'email': EmailAgent,
        'ip': IPAgent,
        'domain': DomainAgent,
        # ... 7개 Agent
    })

def get_agent(agent_type: str) -> Type[BaseOSINTAgent]:
    return _agents.get(agent_type)
```

**계획표 적용**: Week 2 (Agent Registry 패턴 복사)

---

#### 2.2.3 IOC Lookup Engine

**파일**: `app/features/ioc_tools/ioc_lookup/single_lookup/service/ioc_lookup_engine.py`

**주요 함수**:
```python
def lookup_ioc(service_name: str, ioc: str, ioc_type: str, db: Session) -> Dict:
    """
    통합 IOC Lookup 실행

    흐름:
    1. Service Registry에서 서비스 설정 조회
    2. IOC 타입 검증
    3. API 키 조회 및 검증
    4. 함수 인자 준비
    5. API 호출 실행
    6. 에러 처리
    """
    # 1. 서비스 설정 조회
    service_config = service_registry.get_service(service_name)
    if not service_config:
        return {"error": 404, "message": "Service not found"}

    # 2. IOC 타입 검증
    if ioc_type not in service_config['supported_ioc_types']:
        return {"error": 400, "message": "Unsupported IOC type"}

    # 3. API 키 조회
    api_keys = _get_api_keys(service_config, db)
    if not api_keys and _requires_api_key(service_config):
        return {"error": 401, "message": "Missing API key"}

    # 4. 함수 실행
    try:
        result = service_config['func'](**func_args)
        return result
    except Exception as e:
        return {"error": 500, "message": str(e)}

def _get_api_keys(service_config, db) -> Optional[Dict]:
    """서비스별 API 키 조회"""
    # get_apikey() 사용

def _prepare_function_args(service_config, ioc, ioc_type, api_keys) -> Dict:
    """함수 인자 준비"""
    # 서비스별 파라미터 매핑
```

**재사용 방법**:
```python
# osint_profiler/agents/base_agent.py
# 동일한 에러 처리 패턴 적용!

class BaseOSINTAgent:
    async def investigate(self, query: str) -> Dict:
        try:
            # 1. 쿼리 검증
            if not self._validate_query(query):
                return {"error": 400, "message": "Invalid query"}

            # 2. Agent 실행
            result = await self.agent.ainvoke({"input": query})

            # 3. 성공 응답
            return {
                "query": query,
                "result": result["output"],
                "tools_used": [...]
            }
        except Exception as e:
            # 4. 에러 처리 (lookup_ioc와 동일한 형식!)
            return {"error": 500, "message": str(e)}
```

**계획표 적용**: Week 2 (BaseOSINTAgent 에러 처리 패턴 복사)

---

#### 2.2.4 IOC 타입 자동 감지

**파일**: `app/features/ioc_tools/ioc_lookup/single_lookup/utils/ioc_utils.py`

**주요 기능**:
```python
IOC_TYPES = {
    'IPV4': 'ipv4',
    'IPV6': 'ipv6',
    'DOMAIN': 'domain',
    'URL': 'url',
    'EMAIL': 'email',
    'MD5': 'md5',
    'SHA1': 'sha1',
    'SHA256': 'sha256',
    'CVE': 'cve',
    'UNKNOWN': 'unknown'
}

def determine_ioc_type(ioc: str) -> str:
    """
    Regex 기반 IOC 타입 자동 감지
    - IPv4: ^(\d{1,3}\.){3}\d{1,3}$
    - Email: ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$
    - Hash (MD5): ^[a-fA-F0-9]{32}$
    - ...
    """
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', ioc):
        return IOC_TYPES['EMAIL']
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ioc):
        return IOC_TYPES['IPV4']
    # ...
    return IOC_TYPES['UNKNOWN']
```

**재사용 방법**:
```python
# osint_profiler/agents/orchestrator.py (Week 3)
from app.features.ioc_tools.ioc_lookup.single_lookup.utils.ioc_utils import determine_ioc_type

class OSINTOrchestrator:
    def _detect_type(self, query: str) -> str:
        """IOC 타입 자동 감지 (재사용!)"""
        return determine_ioc_type(query)  # ← 그대로 사용!

    async def investigate(self, query: str):
        ioc_type = self._detect_type(query)

        # 타입에 맞는 Agent 선택
        if ioc_type == 'email':
            agent = EmailAgent(self.db)
        elif ioc_type == 'ipv4':
            agent = IPAgent(self.db)
        # ...
```

**계획표 적용**: Week 3 (Orchestrator IOC 타입 감지)

---

#### 2.2.5 FastAPI 엔드포인트 패턴

**파일**: `app/features/ioc_tools/ioc_lookup/single_lookup/routers/single_ioc_lookup_routes.py`

**패턴**:
```python
from fastapi import APIRouter, Query, Depends
from sqlalchemy.orm import Session
from app.core.dependencies import get_db

router = APIRouter()

@router.get("/api/ioc/lookup/{service}")
async def unified_lookup(
    service: str,
    ioc: str = Query(..., description="The IOC value"),
    ioc_type: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    통합 IOC Lookup 엔드포인트
    - Path parameter: service (서비스 선택)
    - Query parameter: ioc, ioc_type
    - DB 의존성 주입: Depends(get_db)
    """
    detected_type = ioc_type or determine_ioc_type(ioc)
    result = lookup_ioc(service, ioc, detected_type, db)
    return result

@router.get("/api/ioc/services")
async def get_available_services(db: Session = Depends(get_db)):
    """사용 가능한 서비스 목록 조회"""
    return {"services": get_all_service_configs(db)}
```

**재사용 방법**:
```python
# osint_profiler/routers/osint_routes.py
# 동일한 패턴 복사!

from fastapi import APIRouter, Query, Depends
from sqlalchemy.orm import Session
from app.core.dependencies import get_db

router = APIRouter()

@router.post("/api/osint/investigate/{agent_type}")
async def investigate_by_type(
    agent_type: str,  # Path parameter (동일)
    query: str = Query(..., description="IOC to investigate"),  # Query (동일)
    context: str = Query("", description="Additional context"),
    llm_model: str = Query("gpt-4"),
    db: Session = Depends(get_db)  # DB 의존성 (동일!)
):
    """
    Agent 기반 OSINT 조사
    - 기존 패턴과 100% 동일!
    """
    if agent_type not in AGENT_MAP:
        return {"error": 404, "message": f"Agent '{agent_type}' not found"}

    AgentClass = AGENT_MAP[agent_type]
    agent = AgentClass(db, llm_model=llm_model)
    result = await agent.investigate(query, context)
    return result

@router.get("/api/osint/agents")
async def get_available_agents():
    """사용 가능한 Agent 목록 (기존 패턴과 동일!)"""
    return {"agents": list(AGENT_MAP.keys())}
```

**계획표 적용**: Week 2 (FastAPI 엔드포인트 작성 시 패턴 100% 복사)

---

### 2.3 LLM Templates 모듈

**파일**: `app/features/llm_templates/service/llm_templates_service.py`

**기능**:
- LLM 프롬프트 템플릿 저장/조회
- 템플릿 변수 치환

**재사용 가능성**:
- 🟡 선택적 (Week 2에서는 필요 없음)
- ✅ Week 4 (RAG 구현 시 프롬프트 관리에 활용 가능)

---

### 2.4 Newsfeed 모듈 (시각화 참고)

**파일**: `app/features/newsfeed/service/newsfeed_service.py`

**기능**:
- RSS 피드 크롤링
- 뉴스 데이터 저장
- 키워드 빈도 분석

**재사용 가능성**:
- 🟡 직접 재사용은 아니지만, 데이터 처리 패턴 참고
- ✅ Week 3 (OSINT 결과 집계 로직 참고)

---

## 3. 프론트엔드 상세 분석

### 3.1 IOC Lookup UI (⭐ 핵심 재사용 대상)

**디렉토리**: `frontend/src/components/ioc-tools/ioc-lookup/`

**구조**:
```
ioc-lookup/
├── shared/
│   └── services/                # ✅ API별 결과 시각화 컴포넌트
│       ├── Virustotal/
│       │   └── Virustotal/
│       │       ├── ELFInformation.jsx
│       │       ├── ThreatClassification.jsx
│       │       ├── TypeTags.jsx
│       │       ├── Filenames.jsx
│       │       └── ... (20+ 컴포넌트)
│       ├── GitHub/
│       │   └── GithubDetails.jsx
│       ├── AbuseIPDB/
│       ├── AlienVault/
│       ├── Shodan/
│       └── ... (18개 API 전용 UI)
```

**재사용 방법**:
```jsx
// osint_profiler/components/OSINTResultCard.jsx

import VirusTotalResults from '../ioc-tools/ioc-lookup/shared/services/Virustotal/Virustotal';
import GithubDetails from '../ioc-tools/ioc-lookup/shared/services/GitHub/GithubDetails';

function OSINTResultCard({ agentResult }) {
  // Agent 결과에서 사용한 Tool 확인
  const usedTools = agentResult.tools_used || [];

  return (
    <Card>
      <CardContent>
        <Typography variant="h6">{agentResult.query}</Typography>
        <Typography>{agentResult.result}</Typography>

        {/* ✅ 기존 컴포넌트 재사용! */}
        {usedTools.includes('virustotal_ip_lookup') && (
          <VirusTotalResults data={agentResult.raw_data.virustotal} />
        )}

        {usedTools.includes('github_code_search') && (
          <GithubDetails data={agentResult.raw_data.github} />
        )}
      </CardContent>
    </Card>
  );
}
```

**계획표 적용**: Week 2 (OSINTChat 결과 렌더링 시 재사용)

---

### 3.2 Newsfeed UI (시각화 재사용)

**디렉토리**: `frontend/src/components/newsfeed/`

#### 3.2.1 Feed 리스트

**파일**: `newsfeed/feed/Feed.jsx`

**기능**:
- 뉴스 카드 리스트 렌더링
- 무한 스크롤
- 날짜 필터링

**재사용 방법**:
```jsx
// osint_profiler/components/OSINTFeed.jsx

// ✅ 기존 Feed 컴포넌트 구조 복사!
function OSINTFeed({ results }) {
  return (
    <Box sx={{ height: '100%', overflowY: 'auto' }}>
      {results.map((result, idx) => (
        <OSINTResultCard key={idx} result={result} />  // ← Feed 카드 패턴
      ))}
    </Box>
  );
}
```

#### 3.2.2 Trends 차트

**파일**: `newsfeed/trends/Trends.jsx`

**기능**:
- 키워드 빈도 차트
- 시계열 데이터 시각화

**재사용 방법**:
```jsx
// osint_profiler/components/ThreatTrends.jsx

import { BarChart, Bar, XAxis, YAxis } from 'recharts';

// ✅ 기존 Trends 패턴 복사!
function ThreatTrends({ keywords }) {
  // keywords: Agent가 발견한 위협 키워드 빈도
  return (
    <BarChart data={keywords}>
      <XAxis dataKey="keyword" />
      <YAxis />
      <Bar dataKey="frequency" fill="#ff4444" />
    </BarChart>
  );
}
```

**계획표 적용**: Week 2-3 (OSINT 결과 시각화)

---

### 3.3 LLM Templates UI

**디렉토리**: `frontend/src/components/llm_templates/`

#### 3.3.1 Template Card

**파일**: `llm_templates/components/TemplateCard.jsx`

**기능**:
- 템플릿 카드 렌더링
- 즐겨찾기, 편집, 삭제 버튼

**재사용 방법**:
```jsx
// osint_profiler/components/AgentCard.jsx

// ✅ TemplateCard 구조 복사!
function AgentCard({ agent }) {
  return (
    <Card>
      <CardHeader
        title={agent.name}
        subheader={agent.description}
      />
      <CardContent>
        <Chip label={`${agent.tools_count} tools`} />
      </CardContent>
      <CardActions>
        <Button>Start Investigation</Button>
      </CardActions>
    </Card>
  );
}
```

---

## 4. Week별 재사용 전략

### Week 1: LangChain Tools 완성 (7일)

#### 재사용 대상

| 컴포넌트 | 파일 | 재사용 방법 | 절약 시간 |
|---------|------|-----------|---------|
| **18개 API 클라이언트** | `external_api_clients.py` | 그대로 사용 | 20시간 |
| **기존 IOC Lookup 엔드포인트** | `single_ioc_lookup_routes.py` | API 테스트용 활용 | 8시간 |
| **API 키 관리** | `api_keys_settings_crud.py` | 그대로 사용 | 2시간 |

#### 작업 방법

**기존 계획**: 18개 API 개별 테스트 (10시간)
```bash
# 각 API 개별 Python 스크립트 작성
python test_hibp.py
python test_abuseipdb.py
# ... 18개
```

**새 계획**: 기존 엔드포인트 활용 (1-2시간)
```bash
# ✅ 기존 IOC Lookup API로 바로 테스트!
curl "http://localhost:8000/api/ioc/lookup/haveibeenpwned?ioc=test@example.com"
curl "http://localhost:8000/api/ioc/lookup/abuseipdb?ioc=8.8.8.8"
curl "http://localhost:8000/api/ioc/lookup/urlscanio?ioc=google.com"
# ... 18개 (10분 컷!)

# 자동화 스크립트
python test_all_apis.py  # 모든 API 순차 테스트 (1시간)
```

**구체적 코드**:
```python
# test_all_apis.py
import requests

BACKEND_URL = "http://localhost:8000"

# ✅ 기존 service_registry.py에서 서비스 목록 가져오기
SERVICES_TO_TEST = [
    ("haveibeenpwned", "test@example.com", "email"),
    ("emailrepio", "test@example.com", "email"),
    ("hunterio", "test@example.com", "email"),
    ("abuseipdb", "8.8.8.8", "ipv4"),
    ("virustotal", "8.8.8.8", "ipv4"),
    ("shodan", "8.8.8.8", "ipv4"),
    ("crowdsec", "8.8.8.8", "ipv4"),
    ("alienvault", "8.8.8.8", "ipv4"),
    ("urlscanio", "google.com", "domain"),
    ("safebrowse", "google.com", "domain"),
    ("malwarebazaar", "44d88612fea8a8f36de82e1278abb02f", "md5"),
    ("threatfox", "44d88612fea8a8f36de82e1278abb02f", "md5"),
    ("urlhaus", "http://malware.com", "url"),
    ("github", "malware.com", "domain"),
    ("bgpview", "8.8.8.8", "ipv4"),
    ("nist_nvd", "CVE-2021-44228", "cve"),
    ("pulsedive", "8.8.8.8", "ipv4"),
    ("reddit", "wannacry", "text"),
]

def test_api(service, ioc, ioc_type):
    """기존 엔드포인트로 API 테스트"""
    try:
        response = requests.get(
            f"{BACKEND_URL}/api/ioc/lookup/{service}",
            params={"ioc": ioc, "ioc_type": ioc_type},
            timeout=30
        )

        if response.status_code == 200:
            print(f"✅ {service:20s} SUCCESS")
            return True
        elif response.status_code == 401:
            print(f"⚠️  {service:20s} API key missing")
            return False
        elif response.status_code == 429:
            print(f"⏱️  {service:20s} Rate limited")
            return False
        else:
            print(f"❌ {service:20s} ERROR {response.status_code}")
            return False
    except Exception as e:
        print(f"💥 {service:20s} EXCEPTION: {str(e)[:50]}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("Week 1: API Connection Test (기존 엔드포인트 활용)")
    print("=" * 60)

    results = {}
    for service, ioc, ioc_type in SERVICES_TO_TEST:
        results[service] = test_api(service, ioc, ioc_type)

    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    success = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"✅ Success: {success}/{total}")
    print(f"❌ Failed:  {total - success}/{total}")

    if success >= 5:  # 최소 5개만 성공해도 Week 2 진행 가능
        print("\n🎉 Week 1 완료! Week 2 시작 가능!")
    else:
        print("\n⚠️  API 키 설정 필요")
```

---

### Week 2: 전문화 Agent 구현 (7일)

#### 재사용 대상

| 컴포넌트 | 파일 | 재사용 방법 | 절약 시간 |
|---------|------|-----------|---------|
| **LLMService** | `llm_service.py` | BaseOSINTAgent에서 직접 사용 | 4시간 |
| **Service Registry 패턴** | `service_registry.py` | Agent Registry 구조 복사 | 3시간 |
| **IOC Lookup Engine 에러 처리** | `ioc_lookup_engine.py` | investigate() 메서드 패턴 | 3시간 |
| **FastAPI 엔드포인트 패턴** | `single_ioc_lookup_routes.py` | osint_routes.py 구조 복사 | 2시간 |
| **DB 의존성** | `dependencies.py` | 그대로 사용 | 1시간 |

#### 작업 방법

**Day 1-3: 백엔드 Agent 구현 (기존 패턴 100% 복사)**

**파일 1**: `osint_profiler/agents/base_agent.py` (1시간)
```python
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from langchain.agents import initialize_agent, AgentType
from langchain.tools import Tool
from sqlalchemy.orm import Session

# ✅ 기존 인프라 재사용!
from app.utils.llm_service import create_llm_service  # ← LLMService
from app.features.osint_profiler.tools.langchain_wrappers import OSINTToolFactory

class BaseOSINTAgent(ABC):
    """
    ✅ IOC Lookup Engine 패턴 복사!
    """

    def __init__(self, db: Session, llm_model: str = "gpt-4"):
        self.db = db
        self.llm_model = llm_model

        # ✅ LLMService 재사용 (그대로 사용!)
        llm_service = create_llm_service(db)
        if llm_model not in llm_service.models:
            raise ValueError(f"Model {llm_model} not available")
        self.llm = llm_service.models[llm_model]

        # 각 Agent가 정의한 도구
        self.tools = self._create_tools()

        # LangChain Agent 초기화
        self.agent = self._initialize_agent()

    @abstractmethod
    def _create_tools(self) -> List[Tool]:
        """각 Agent가 구현"""
        pass

    def _initialize_agent(self):
        return initialize_agent(
            tools=self.tools,
            llm=self.llm,
            agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
            max_iterations=10,
            verbose=True,
            handle_parsing_errors=True
        )

    async def investigate(self, query: str, context: str = "") -> Dict[str, Any]:
        """
        ✅ ioc_lookup_engine.lookup_ioc() 에러 처리 패턴 복사!
        """
        prompt = f"{context}\n\nInvestigate: {query}" if context else f"Investigate: {query}"

        try:
            result = await self.agent.ainvoke({"input": prompt})

            # ✅ 기존 응답 형식과 동일!
            return {
                "query": query,
                "agent_type": self.__class__.__name__,
                "result": result["output"],
                "tool_calls": len(result.get("intermediate_steps", [])),
                "tools_used": [
                    step[0].tool for step in result.get("intermediate_steps", [])
                ]
            }
        except ValueError as e:
            # Validation error
            return {"error": 400, "message": str(e)}
        except Exception as e:
            # ✅ 기존 에러 형식과 동일!
            return {"error": 500, "message": str(e)}
```

**파일 2**: `osint_profiler/agents/specialized_agents.py` (30분)
```python
from .base_agent import BaseOSINTAgent
from ..tools.langchain_wrappers import OSINTToolFactory

# ✅ 복붙 수준! (각 Agent당 5분)

class EmailAgent(BaseOSINTAgent):
    def _create_tools(self):
        return OSINTToolFactory(self.db).create_email_tools()

class IPAgent(BaseOSINTAgent):
    def _create_tools(self):
        return OSINTToolFactory(self.db).create_ip_tools()

class DomainAgent(BaseOSINTAgent):
    def _create_tools(self):
        return OSINTToolFactory(self.db).create_domain_tools()

class HashAgent(BaseOSINTAgent):
    def _create_tools(self):
        return OSINTToolFactory(self.db).create_hash_tools()

class URLAgent(BaseOSINTAgent):
    def _create_tools(self):
        return OSINTToolFactory(self.db).create_url_tools()

class GitHubAgent(BaseOSINTAgent):
    def _create_tools(self):
        return OSINTToolFactory(self.db).create_github_tools()

class MiscAgent(BaseOSINTAgent):
    def _create_tools(self):
        return OSINTToolFactory(self.db).create_misc_tools()
```

**파일 3**: `osint_profiler/agents/agent_registry.py` (20분)
```python
# ✅ service_registry.py 패턴 100% 복사!

from typing import Dict, Type
from .base_agent import BaseOSINTAgent

_agents: Dict[str, Type[BaseOSINTAgent]] = {}

def register_agents():
    """7개 Agent 등록 (service_registry 패턴)"""
    from .specialized_agents import (
        EmailAgent, IPAgent, DomainAgent, HashAgent,
        URLAgent, GitHubAgent, MiscAgent
    )

    _agents.update({
        'email': EmailAgent,
        'ip': IPAgent,
        'domain': DomainAgent,
        'hash': HashAgent,
        'url': URLAgent,
        'github': GitHubAgent,
        'misc': MiscAgent
    })

def get_agent(agent_type: str) -> Type[BaseOSINTAgent]:
    """Agent 클래스 조회"""
    return _agents.get(agent_type)

def get_all_agents() -> Dict[str, Type[BaseOSINTAgent]]:
    """모든 Agent 조회"""
    return _agents.copy()

# 모듈 로드 시 자동 등록
register_agents()
```

**파일 4**: `osint_profiler/routers/osint_routes.py` (30분)
```python
# ✅ single_ioc_lookup_routes.py 패턴 100% 복사!

from fastapi import APIRouter, Query, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional

from app.core.dependencies import get_db  # ✅ 기존 의존성
from ..agents.agent_registry import get_agent, get_all_agents

router = APIRouter(prefix="/api/osint", tags=["OSINT Profiler"])

@router.post("/investigate/{agent_type}")
async def investigate_by_type(
    agent_type: str,
    query: str = Query(..., description="IOC to investigate"),
    context: str = Query("", description="Additional context"),
    llm_model: str = Query("gpt-4", description="LLM model to use"),
    db: Session = Depends(get_db)  # ✅ 기존 패턴!
):
    """
    타입별 전문 Agent 조사

    ✅ single_ioc_lookup_routes.unified_lookup() 패턴 복사!
    """
    AgentClass = get_agent(agent_type)
    if not AgentClass:
        raise HTTPException(
            status_code=404,
            detail=f"Agent type '{agent_type}' not found"
        )

    try:
        agent = AgentClass(db, llm_model=llm_model)
        result = await agent.investigate(query, context)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/agents")
async def get_available_agents():
    """
    사용 가능한 Agent 목록

    ✅ /api/ioc/services 패턴 복사!
    """
    agents = get_all_agents()
    return {
        "agents": [
            {
                "type": agent_type,
                "name": AgentClass.__name__,
                "description": AgentClass.__doc__
            }
            for agent_type, AgentClass in agents.items()
        ]
    }
```

**main.py에 라우터 등록** (5분)
```python
# backend/main.py
from app.features.osint_profiler.routers import osint_routes

# 기존 라우터들과 함께 등록
app.include_router(osint_routes.router)
```

---

**Day 4-7: 프론트엔드 (기존 컴포넌트 재사용)**

**파일**: `frontend/src/components/osint-profiler/OSINTChat.jsx` (2시간)
```jsx
import React, { useState } from 'react';
import { Box, TextField, IconButton, Paper, Typography } from '@mui/material';
import SendIcon from '@mui/icons-material/Send';
import api from '../../api';

// ✅ 기존 Newsfeed/Feed 구조 복사!
export default function OSINTChat({ placeholder = "IOC 입력..." }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSend = async () => {
    if (!input.trim()) return;

    const userMsg = {
      role: 'user',
      content: input,
      timestamp: new Date()
    };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      // ✅ 기존 IOC Lookup API 호출 패턴과 동일!
      const response = await api.post('/api/osint/investigate/email', {
        query: input,
        llm_model: 'gpt-4'
      });

      const agentMsg = {
        role: 'assistant',
        content: response.data.result,
        tools_used: response.data.tools_used,
        timestamp: new Date()
      };
      setMessages(prev => [...prev, agentMsg]);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* ✅ Newsfeed/Feed 스크롤 패턴 */}
      <Box sx={{ flex: 1, overflowY: 'auto', p: 3 }}>
        {messages.map((msg, idx) => (
          <MessageBubble key={idx} message={msg} />
        ))}
      </Box>

      {/* ✅ 하단 고정 입력창 */}
      <Box sx={{ p: 2, borderTop: '1px solid #e0e0e0' }}>
        <TextField
          fullWidth
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && handleSend()}
          placeholder={placeholder}
          InputProps={{
            endAdornment: (
              <IconButton onClick={handleSend}>
                <SendIcon />
              </IconButton>
            )
          }}
        />
      </Box>
    </Box>
  );
}

function MessageBubble({ message }) {
  // ✅ Newsfeed 카드 스타일 복사
  return (
    <Paper sx={{ p: 2, mb: 2 }}>
      <Typography>{message.content}</Typography>
      {message.tools_used && (
        <Typography variant="caption">
          🛠️ {message.tools_used.length} tools used
        </Typography>
      )}
    </Paper>
  );
}
```

---

### Week 3: Orchestrator + IOC 자동 확장 (7일)

#### 재사용 대상

| 컴포넌트 | 파일 | 재사용 방법 | 절약 시간 |
|---------|------|-----------|---------|
| **IOC 타입 감지** | `ioc_utils.py` | Orchestrator에서 직접 사용 | 2시간 |
| **Service Registry 패턴** | `service_registry.py` | Agent 선택 로직 참고 | 2시간 |
| **Newsfeed 데이터 집계** | `newsfeed_crud.py` | IOC 그래프 집계 참고 | 3시간 |

#### 작업 방법

**파일**: `osint_profiler/agents/orchestrator.py` (4시간)
```python
from typing import Dict, Any, List
import re
from sqlalchemy.orm import Session

# ✅ 기존 IOC 타입 감지 재사용!
from app.features.ioc_tools.ioc_lookup.single_lookup.utils.ioc_utils import determine_ioc_type

from .agent_registry import get_all_agents

class OSINTOrchestrator:
    """
    ✅ ioc_lookup_engine 패턴 + Agent 조율
    """

    def __init__(self, db: Session, llm_model: str = "gpt-4"):
        self.db = db
        self.llm_model = llm_model

        # 모든 Agent 인스턴스 생성
        agents_classes = get_all_agents()
        self.agents = {
            agent_type: AgentClass(db, llm_model)
            for agent_type, AgentClass in agents_classes.items()
        }

    def _detect_type(self, query: str) -> str:
        """
        ✅ ioc_utils.determine_ioc_type() 그대로 사용!
        """
        return determine_ioc_type(query)

    async def investigate(
        self,
        query: str,
        auto_expand: bool = True,
        max_depth: int = 2
    ) -> Dict[str, Any]:
        """종합 OSINT 조사"""

        # 1. Primary 조사
        primary_type = self._detect_type(query)
        primary_agent = self.agents.get(primary_type)

        if not primary_agent:
            return {"error": 400, "message": f"No agent for type: {primary_type}"}

        primary_result = await primary_agent.investigate(query)
        results = [primary_result]
        investigated_iocs = {query}

        # 2. Auto Expansion
        if auto_expand:
            # IOC 추출 및 확장 조사
            # (기존 계획대로 구현)
            pass

        return {
            "primary_query": query,
            "primary_type": primary_type,
            "results": results,
            "total_investigations": len(results)
        }
```

---

### Week 4: RAG 케이스 기반 학습 (7일)

#### 재사용 대상

| 컴포넌트 | 파일 | 재사용 방법 | 절약 시간 |
|---------|------|-----------|---------|
| **LLM 템플릿 저장 패턴** | `llm_templates/crud/crud.py` | 조사 사례 저장 참고 | 2시간 |
| **Newsfeed 피드 구조** | `newsfeed/models/newsfeed_models.py` | 벡터 DB 스키마 참고 | 1시간 |

---

## 5. 구체적 코드 재사용 예시

### 5.1 BaseOSINTAgent 구현 (완전 예시)

```python
# backend/app/features/osint_profiler/agents/base_agent.py

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from langchain.agents import initialize_agent, AgentType
from langchain.tools import Tool
from langchain_core.language_models import BaseChatModel
from sqlalchemy.orm import Session
import logging

# ✅ 재사용 1: LLMService
from app.utils.llm_service import create_llm_service

# ✅ 재사용 2: OSINTToolFactory
from app.features.osint_profiler.tools.langchain_wrappers import OSINTToolFactory

logger = logging.getLogger(__name__)

class BaseOSINTAgent(ABC):
    """
    모든 OSINT Agent의 기본 클래스

    ✅ 재사용한 기존 패턴:
    - LLMService (app/utils/llm_service.py)
    - IOC Lookup Engine 에러 처리 (ioc_lookup_engine.py)
    - Service Registry 초기화 패턴 (service_registry.py)
    """

    def __init__(
        self,
        db: Session,
        llm_model: str = "gpt-4",
        temperature: float = 0.7,
        max_iterations: int = 10
    ):
        """
        Args:
            db: SQLAlchemy 세션 (✅ dependencies.py get_db()와 동일)
            llm_model: 사용할 LLM 모델 ID (✅ LLMService에 등록된 모델)
            temperature: LLM temperature
            max_iterations: Agent 최대 반복 횟수
        """
        self.db = db
        self.llm_model = llm_model
        self.temperature = temperature
        self.max_iterations = max_iterations

        # ✅ 재사용 3: LLMService 초기화 (기존 패턴 그대로)
        logger.info(f"Initializing {self.__class__.__name__} with model {llm_model}")
        self.llm = self._setup_llm(llm_model)

        # ✅ 재사용 4: OSINTToolFactory (Week 1에서 완성)
        self.tools = self._create_tools()
        logger.info(f"{self.__class__.__name__} initialized with {len(self.tools)} tools")

        # LangChain Agent 초기화
        self.agent = self._initialize_agent()

    def _setup_llm(self, llm_model: str) -> BaseChatModel:
        """
        ✅ 재사용: LLMService 패턴 (llm_service.py)
        """
        llm_service = create_llm_service(self.db)

        if llm_model not in llm_service.models:
            available_models = list(llm_service.models.keys())
            raise ValueError(
                f"Model '{llm_model}' not available. "
                f"Available models: {available_models}"
            )

        return llm_service.models[llm_model]

    @abstractmethod
    def _create_tools(self) -> List[Tool]:
        """
        각 Agent가 구현해야 할 도구 생성 메서드

        ✅ 재사용: Service Registry 패턴 (service_registry.py)
        - 각 Agent는 OSINTToolFactory의 특정 메서드 호출

        Example:
            return OSINTToolFactory(self.db).create_email_tools()
        """
        pass

    def _initialize_agent(self):
        """
        LangChain ReAct Agent 초기화
        """
        return initialize_agent(
            tools=self.tools,
            llm=self.llm,
            agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
            max_iterations=self.max_iterations,
            verbose=True,
            handle_parsing_errors=True,
            return_intermediate_steps=True
        )

    async def investigate(
        self,
        query: str,
        context: str = ""
    ) -> Dict[str, Any]:
        """
        OSINT 조사 수행

        ✅ 재사용: ioc_lookup_engine.lookup_ioc() 에러 처리 패턴

        Args:
            query: 조사 대상 IOC
            context: 추가 컨텍스트

        Returns:
            {
                "query": str,
                "agent_type": str,
                "result": str,
                "tool_calls": int,
                "tools_used": List[str]
            }
            또는 에러 시:
            {
                "error": int,
                "message": str
            }
        """
        logger.info(f"{self.__class__.__name__} investigating: {query[:50]}...")

        # 프롬프트 구성
        prompt = self._build_prompt(query, context)

        try:
            # Agent 실행
            result = await self.agent.ainvoke({"input": prompt})

            # ✅ 재사용: 기존 응답 형식과 동일 (ioc_lookup_engine.py)
            return {
                "query": query,
                "agent_type": self.__class__.__name__,
                "result": result["output"],
                "tool_calls": len(result.get("intermediate_steps", [])),
                "tools_used": [
                    step[0].tool
                    for step in result.get("intermediate_steps", [])
                ],
                "intermediate_steps": result.get("intermediate_steps", [])
            }

        except ValueError as e:
            # ✅ 재사용: 기존 에러 코드 (400)
            logger.error(f"Validation error in {self.__class__.__name__}: {str(e)}")
            return {
                "error": 400,
                "message": f"Invalid input: {str(e)}"
            }

        except Exception as e:
            # ✅ 재사용: 기존 에러 코드 (500)
            logger.error(
                f"Error in {self.__class__.__name__}: {str(e)}",
                exc_info=True
            )
            return {
                "error": 500,
                "message": f"Investigation failed: {str(e)}"
            }

    def _build_prompt(self, query: str, context: str) -> str:
        """프롬프트 구성"""
        if context:
            return f"{context}\n\nInvestigate the following: {query}"
        return f"Investigate the following: {query}"

    def get_available_tools(self) -> List[str]:
        """사용 가능한 도구 목록"""
        return [tool.name for tool in self.tools]
```

---

### 5.2 FastAPI 엔드포인트 등록 (완전 예시)

```python
# backend/main.py

# ✅ 재사용: 기존 라우터 등록 패턴과 동일!

# 기존 import들
from app.features.domain_lookup.routers import external_domain_lookup_routes
from app.features.email_analyzer.routers import internal_email_analyzer_routes
from app.features.ioc_tools.ioc_lookup.single_lookup.routers import single_ioc_lookup_routes
from app.features.newsfeed.routers import external_newsfeed_routes, internal_newsfeed_routes
from app.features.llm_templates.routers import internal_llm_templates_routes

# 🆕 OSINT Profiler 라우터 추가 (기존 패턴과 동일!)
from app.features.osint_profiler.routers import osint_routes

# FastAPI 앱 생성
app = FastAPI(
    title="AOL OSINT Service",
    description="OSINT & LLM 프로파일링 플랫폼",
    version="2.0.0"
)

# ✅ 기존 라우터들
app.include_router(external_domain_lookup_routes.router)
app.include_router(internal_email_analyzer_routes.router)
app.include_router(single_ioc_lookup_routes.router)
app.include_router(external_newsfeed_routes.router)
app.include_router(internal_newsfeed_routes.router)
app.include_router(internal_llm_templates_routes.router)

# 🆕 OSINT Profiler 라우터 (패턴 동일!)
app.include_router(osint_routes.router)
```

---

## 6. 예상 시간 절약 요약

| Week | 기존 계획 시간 | 재사용 후 시간 | 절약 시간 | 절약률 |
|------|--------------|--------------|---------|--------|
| **Week 1** | 10시간 | 2시간 | 8시간 | 80% |
| **Week 2** | 25시간 | 8시간 | 17시간 | 68% |
| **Week 3** | 20시간 | 12시간 | 8시간 | 40% |
| **Week 4** | 20시간 | 15시간 | 5시간 | 25% |
| **총계** | **75시간** | **37시간** | **38시간** | **51%** |

**결론**: 기존 인프라 재사용으로 **개발 시간 50% 이상 단축 가능!**

---

## 7. 체크리스트

### Week 1 시작 전
- [ ] Backend 서버 실행 확인
- [ ] 기존 IOC Lookup API 동작 확인
- [ ] API 키 DB 확인 (어떤 키가 이미 설정되어 있는지)

### Week 2 시작 전
- [ ] LLMService 동작 확인 (OpenAI/Anthropic/Gemini 키)
- [ ] OSINTToolFactory 18개 도구 생성 확인
- [ ] langchain, langchain-openai 등 패키지 설치 확인

### Week 3 시작 전
- [ ] 7개 Agent 정상 동작 확인
- [ ] FastAPI 엔드포인트 테스트 완료

### Week 4 시작 전
- [ ] Orchestrator 동작 확인
- [ ] chromadb, sentence-transformers 설치

---

## 8. 참고 문서

### 기존 코드 분석
- `backend/app/utils/llm_service.py` - LLM 통합 서비스
- `backend/app/features/ioc_tools/ioc_lookup/` - IOC Lookup 엔진
- `backend/app/core/settings/api_keys/` - API 키 관리

### 개발 가이드
- Week 1-4 구체적 개발 일정: `OSINT_INTEGRATION_PLAN_V2.md`
- 아키텍처 비교: `ARCHITECTURE_COMPARISON.md`

---

**마지막 업데이트**: 2025-10-07
**작성자**: Claude (AI Assistant)
**목적**: 팀원 온보딩 및 개발 가속화
