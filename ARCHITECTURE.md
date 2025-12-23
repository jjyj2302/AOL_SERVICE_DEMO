# OSINT Multi-Agent 시스템 아키텍처 분석

## 개요

`site111.mallmaster.top` 도메인 분석을 통해 검증된 Multi-Agent OSINT 시스템의 완전한 아키텍처 문서입니다.

## 1. 시스템 흐름도

```
┌─────────────────────────────────────────────────────────────────┐
│ CLIENT REQUEST                                                  │
│ POST /api/osint/investigate                                     │
│ {"query": "site111.mallmaster.top"}                            │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ FastAPI Router                                                  │
│ osint_routes.py:51 → get_supervisor() [싱글톤 캐시]            │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ OSINT Supervisor (LangGraph)                                    │
│ GPT-4가 쿼리 분석 → "도메인 형식" → domain_expert로 라우팅      │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Domain Expert Agent (ReAct 패턴)                                │
│ 1. 생각: "도메인 평판 확인 필요"                                 │
│ 2. 행동: virustotal_domain("site111.mallmaster.top")           │
│ 3. 관찰: [VirusTotal 응답 수신]                                 │
│ 4. 최종 답변: "4/83 벤더가 악성으로 탐지..."                     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ VirusTotal Tool                                                 │
│ tools.py:374 → get_apikey_cached("virustotal") [메모리 조회]    │
│ tools.py:398 → external_api_clients.virustotal(...)            │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ VirusTotal API v3                                               │
│ GET /api/v3/domains/site111.mallmaster.top                      │
│ Response: {"malicious": 4, "harmless": 79, "reputation": -10}  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ 최종 응답                                                        │
│ {                                                               │
│   "query": "site111.mallmaster.top",                            │
│   "result": "도메인 분석: 4/83 벤더가 악성 탐지...",             │
│   "execution_time_ms": 3547,                                    │
│   "messages_count": 4                                           │
│ }                                                               │
└─────────────────────────────────────────────────────────────────┘
```

## 2. 핵심 컴포넌트

### 2.1 Supervisor (감독자)

**파일**: `backend/app/features/osint_profiler/supervisor.py`

**역할**:
- 쿼리 분석 및 적절한 에이전트로 라우팅
- 4개 전문 에이전트 관리

**라우팅 규칙**:
```python
CVE-2024-XXXX  → vulnerability_expert (NVD)
google.com     → domain_expert (VirusTotal)
8.8.8.8        → domain_expert (VirusTotal)
abc123hash...  → hash_expert (VirusTotal)
https://...    → url_expert (URLScan.io)
```

**생성 과정**:
```python
# Line 35: LLM 초기화
llm = ChatOpenAI(model="gpt-4", temperature=0)

# Line 38-48: 4개 에이전트 생성
vuln_agent = create_vulnerability_agent(llm_model)
domain_agent = create_domain_agent(llm_model)
hash_agent = create_hash_agent(llm_model)
url_agent = create_url_agent(llm_model)

# Line 54: langgraph-supervisor 사용
workflow = create_supervisor(
    agents=[vuln_agent, domain_agent, hash_agent, url_agent],
    model=llm,
    output_mode="last_message",
    supervisor_name="osint_supervisor"
)

# Line 85: 컴파일
supervisor = workflow.compile()
```

### 2.2 Domain Expert Agent

**파일**: `backend/app/features/osint_profiler/agents/domain/agent.py`

**역할**: IP 주소 및 도메인 평판 분석

**구현 패턴**: ReAct (Reason + Act)
```python
def create_domain_agent(llm_model="gpt-4"):
    llm = ChatOpenAI(model=llm_model, temperature=0)
    tools = create_virustotal_only_tools()  # VirusTotal IP/Domain 도구

    return create_react_agent(
        model=llm,
        tools=tools,
        name="domain_expert",
        prompt="Use VirusTotal to check IP/domain reputation..."
    )
```

**ReAct 루프 예시**:
```
Iteration 1:
  Thought: "I need to check domain reputation"
  Action: virustotal_domain("site111.mallmaster.top")
  Observation: "4/83 vendors flagged as malicious, reputation: -10"

Iteration 2:
  Thought: "Analysis complete"
  Final Answer: "Domain shows malicious indicators..."
```

### 2.3 VirusTotal Tools

**파일**: `backend/app/features/osint_profiler/agents/domain/tools.py`

**함수**: `create_virustotal_only_tools()` (Lines 365-410)

**생성되는 도구**:

1. **virustotal_ip** - IP 평판 조회
2. **virustotal_domain** - 도메인 평판 조회

**도구 구현**:
```python
def create_virustotal_only_tools() -> List[StructuredTool]:
    tools = []

    # API 키 캐시에서 조회 (DB 쿼리 없음!)
    vt_key = get_apikey_cached("virustotal")
    if not vt_key.get('key'):
        return tools

    # 도메인 조회 도구
    def virustotal_domain_check(domain: str) -> dict:
        return external_api_clients.virustotal(
            ioc=domain,
            type="domain",
            apikey=vt_key['key']
        )

    tools.append(StructuredTool(
        name="virustotal_domain",
        func=virustotal_domain_check,
        description="Check domain reputation from VirusTotal",
        args_schema=DomainInput  # Pydantic 입력 검증
    ))

    return tools
```

**Pydantic 스키마**:
```python
class DomainInput(BaseModel):
    domain: str = Field(description="조사할 도메인")

class IPInput(BaseModel):
    ip: IPvAnyAddress = Field(description="조사할 IP (IPv4/IPv6)")
```

### 2.4 API Key Cache (싱글톤)

**파일**: `backend/app/core/settings/api_keys/cache.py`

**역할**: 모든 API 키를 메모리에 캐싱하여 DB 쿼리 제거

**싱글톤 구현**:
```python
class APIKeyCache:
    _instance: Optional['APIKeyCache'] = None
    _cache: Dict[str, dict] = {}
    _initialized: bool = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
```

**초기화** (main.py lifespan에서 한 번만 호출):
```python
# Line 82-83
api_cache = APIKeyCache.get_instance()
api_cache.load_all_keys(db)  # 26개 서비스 API 키 로드
```

**사용**:
```python
# O(1) 메모리 조회
vt_key = get_apikey_cached("virustotal")
# Returns: {"name": "virustotal", "key": "abc123...", "is_active": true}
```

**성능 비교**:
- **이전**: 매 도구 호출마다 DB 쿼리 (100-500ms)
- **이후**: 메모리 조회 (<1ms)
- **개선**: **100-500배 빠름**

### 2.5 Supervisor Cache (싱글톤)

**파일**: `backend/app/features/osint_profiler/supervisor_cache.py`

**역할**: Supervisor를 서버 시작 시 한 번만 생성하여 캐싱

**초기화** (main.py lifespan):
```python
# Line 86-88
supervisor_cache = SupervisorCache.get_instance()
supervisor_cache.initialize(llm_model="gpt-4")
```

**사용**:
```python
# osint_routes.py Line 51
supervisor = get_supervisor()  # 캐시된 인스턴스 반환 (0ms)
```

**성능 개선**:
- **이전**: 매 요청마다 Supervisor 생성 (4-5초)
- **이후**: 캐시에서 조회 (<1ms)
- **개선**: 무한대 (초기화 비용 제거)

### 2.6 External API Client

**파일**: `backend/app/features/ioc_tools/ioc_lookup/single_lookup/service/external_api_clients.py`

**VirusTotal 함수** (Lines 697-726):
```python
def virustotal(ioc: str, type: str, apikey: str) -> Dict[str, Any]:
    # API 키 검증
    if not apikey:
        return {"error": 401, "message": "VirusTotal API key is missing."}

    # IOC 타입 → VirusTotal 엔드포인트 매핑
    type_map = {
        'ip': 'ip_addresses',
        'domain': 'domains',
        'url': 'urls',
        'hash': 'files'
    }

    # HTTP GET 요청
    response = requests.get(
        url=f'https://www.virustotal.com/api/v3/{type_map[type]}/{ioc}',
        headers={'x-apikey': apikey}
    )

    return handle_request_errors("VirusTotal", response)
```

**에러 핸들링** (Lines 10-76):
```python
def handle_request_errors(service_name: str, response: requests.Response):
    # Rate Limit 감지 (429 상태 코드)
    if response.status_code == 429:
        retry_after = response.headers.get('Retry-After')
        return {
            "error": 429,
            "message": f"{service_name} rate limit exceeded",
            "retry_after": retry_after,
            "is_rate_limited": True
        }

    # 성공 응답
    if 200 <= response.status_code < 300:
        return response.json()

    # 기타 에러
    return {
        "error": response.status_code,
        "message": f"{service_name} error: {response.text}"
    }
```

## 3. 데이터 변환 지점

### 3.1 쿼리 입력 → LangGraph 메시지

```python
# HTTP Request Body
{"query": "site111.mallmaster.top"}

# ↓ osint_routes.py Line 56
{"messages": [{"role": "user", "content": "site111.mallmaster.top"}]}
```

### 3.2 도구 인자 → API 파라미터

```python
# tools.py Line 396
virustotal_domain_check(domain="site111.mallmaster.top")

# ↓ external_api_clients.py Line 722
virustotal(ioc="site111.mallmaster.top", type="domain", apikey="abc123")

# ↓ HTTP Request
GET https://www.virustotal.com/api/v3/domains/site111.mallmaster.top
Headers: {"x-apikey": "abc123..."}
```

### 3.3 API 응답 → 에이전트 관찰

```python
# VirusTotal API 응답
{
  "data": {
    "attributes": {
      "last_analysis_stats": {"malicious": 4, "harmless": 79},
      "reputation": -10,
      "categories": {"Forcepoint": "Suspicious"}
    }
  }
}

# ↓ ReAct Agent Observation
"VirusTotal analysis: 4/83 vendors flagged as malicious. Reputation: -10"
```

### 3.4 에이전트 출력 → 최종 응답

```python
# Domain Agent 응답
AIMessage(content="Domain analysis: 4 vendors flagged as malicious...")

# ↓ Router Response Model
InvestigationResponse(
    query="site111.mallmaster.top",
    result="Domain analysis: 4 vendors flagged...",
    execution_time_ms=3547,
    messages_count=4
)
```

## 4. 성능 특성

### 4.1 서버 시작 시간 (일회성)

```
1. 데이터베이스 테이블 생성:    ~100ms
2. API 키 캐시 로드:           ~500ms (26개 서비스)
3. Supervisor 생성:            ~4000ms
   ├─ LLM 초기화:             ~1000ms
   ├─ 4개 에이전트 생성:       ~2000ms
   ├─ 도구 바인딩:            ~500ms
   └─ 그래프 컴파일:          ~500ms
────────────────────────────────────
총 시작 시간:                 ~4600ms (한 번만 발생)
```

### 4.2 요청당 지연 시간

```
1. 라우터 처리:               <1ms
2. Supervisor 캐시 조회:      <1ms
3. GPT-4 라우팅 결정:         ~800ms
4. Domain Agent 초기화:       0ms (미리 컴파일됨)
5. ReAct 루프 (2회 반복):
   ├─ GPT-4 추론:            ~800ms
   ├─ API 키 캐시 조회:       <1ms
   ├─ VirusTotal API 호출:   ~1200ms
   └─ GPT-4 최종 답변:       ~800ms
────────────────────────────────────
총 요청 시간:                ~3600ms
```

### 4.3 병목 지점 분석

**주요 병목**:
1. **LLM 추론 (GPT-4)**: ~2400ms (3회 LLM 호출)
   - Supervisor 라우팅: ~800ms
   - Agent 추론: ~800ms
   - 최종 답변 생성: ~800ms

2. **외부 API 지연**: ~1200ms
   - VirusTotal API: ~1000ms
   - 네트워크 왕복 시간: ~200ms

**무시할 수 있는 비용**:
- 메모리 조회 (캐시): <1ms
- 그래프 실행 오버헤드: <10ms
- Pydantic 검증: <1ms

## 5. 핵심 디자인 패턴

### 5.1 Singleton Pattern (싱글톤)

**적용 대상**:
- `APIKeyCache`: API 키 메모리 캐싱
- `SupervisorCache`: Supervisor 인스턴스 캐싱

**이점**:
- 중복 초기화 방지
- 메모리 효율성
- 일관된 상태 관리

### 5.2 ReAct Pattern (추론 + 행동)

**LangGraph의 `create_react_agent`가 구현**:

```
반복:
  1. Reasoning (추론): "무엇을 해야 하는가?"
  2. Action (행동): 도구 실행
  3. Observation (관찰): 도구 결과 분석
  4. 종료 조건 확인: 최종 답변 또는 반복
```

**장점**:
- LLM이 자율적으로 도구 선택
- 다단계 추론 가능
- 명시적 종료 조건

### 5.3 Supervisor Pattern (감독자)

**LangGraph의 `create_supervisor`가 구현**:

```
Supervisor (GPT-4)
├─ 쿼리 타입 분석
├─ 적절한 에이전트로 라우팅
├─ 에이전트 실행 모니터링
└─ 최종 결과 반환
```

**라우팅 로직**:
- 도메인 감지 → domain_expert
- CVE 형식 감지 → vulnerability_expert
- 해시 감지 → hash_expert
- URL 감지 → url_expert

### 5.4 Dependency Injection (의존성 주입)

**이전 방식 (안티 패턴)**:
```python
def check_domain(db: Session, domain: str):
    api_key = db.query(APIKey).filter(...).first()  # DB 쿼리!
    return virustotal(domain, api_key.value)
```

**개선된 방식 (캐시)**:
```python
def check_domain(domain: str):
    api_key = get_apikey_cached("virustotal")  # 메모리 조회!
    return virustotal(domain, api_key['key'])
```

## 6. 보안 고려사항

### 6.1 API 키 보호

**로그 마스킹** (cache.py Line 67):
```python
if key_value:
    masked = f"{key_value[:4]}...{key_value[-4:]}"
    print(f"  [ACTIVE] {key_name}: {masked}")

# 출력 예: [ACTIVE] virustotal: 77b2...dcc2
```

**환경 변수 격리**:
- OpenAI 키: `os.environ["OPENAI_API_KEY"]`로 설정
- 서비스 키: DB에 저장, 메모리에 캐싱
- 평문 로깅 절대 금지

### 6.2 입력 검증

**Pydantic 스키마**:
```python
class IPInput(BaseModel):
    ip: IPvAnyAddress  # IPv4/IPv6 형식 자동 검증

class DomainInput(BaseModel):
    domain: str
```

**LangChain StructuredTool**:
- 도구 실행 전 자동 입력 검증
- 스키마 불일치 시 ValidationError 발생

### 6.3 에러 처리

**중앙 집중식 에러 핸들러**:
- API 에러 응답 정제
- 정보 누출 방지
- 디버깅용 로깅

**Rate Limit 처리**:
- 429 상태 코드 감지
- 구조화된 재시도 가이드 반환
- 연쇄 장애 방지

## 7. 파일 구조

```
/home/jyj0203/Ajou25-2/AOL_SERVICE_DEMO/
├── backend/
│   ├── main.py                                    # FastAPI 앱 + 시작 로직
│   ├── test_single_ioc.py                         # CLI 테스트 도구
│   └── app/
│       ├── core/
│       │   ├── dependencies.py                    # get_db() 함수
│       │   └── settings/
│       │       └── api_keys/
│       │           └── cache.py                   # APIKeyCache 싱글톤
│       └── features/
│           ├── osint_profiler/
│           │   ├── supervisor.py                  # Supervisor 생성
│           │   ├── supervisor_cache.py            # SupervisorCache 싱글톤
│           │   ├── routers/
│           │   │   └── osint_routes.py            # HTTP 엔드포인트
│           │   └── agents/
│           │       ├── domain/
│           │       │   ├── agent.py               # Domain Agent
│           │       │   └── tools.py               # VirusTotal 도구
│           │       ├── hash/
│           │       │   ├── agent.py               # Hash Agent
│           │       │   └── tools.py               # VirusTotal Hash
│           │       ├── url/
│           │       │   ├── agent.py               # URL Agent
│           │       │   └── tools.py               # URLScan 도구
│           │       └── vulnerability/
│           │           ├── agent.py               # CVE Agent
│           │           └── tools.py               # NVD 도구
│           └── ioc_tools/
│               └── ioc_lookup/
│                   └── single_lookup/
│                       └── service/
│                           └── external_api_clients.py  # API 통합
```

## 8. 실제 분석 결과 (site111.mallmaster.top)

### 실행 흐름
```
1. 쿼리 수신: "site111.mallmaster.top"
2. Supervisor 분석: "도메인 형식 감지"
3. 라우팅: domain_expert 선택
4. Domain Agent 실행:
   - 도구 선택: virustotal_domain
   - API 키 조회: get_apikey_cached("virustotal")
   - API 호출: VirusTotal domains API
5. 응답 수신:
   - 악성 탐지: 4/83 벤더
   - 평판 점수: -10
   - 카테고리: "Phishing" (alphaMountain.ai)
6. 최종 분석:
   - 생성일: 2023-03-27
   - IP: 91.195.240.12
   - 결론: 피싱 도메인 의심
```

### 실행 시간
```
총 실행 시간: 3547ms
├─ Supervisor 라우팅: ~800ms
├─ Agent 추론: ~800ms
├─ VirusTotal API: ~1200ms
└─ 최종 답변 생성: ~800ms
```

## 9. 시스템 강점

1. **관심사 분리**:
   - Supervisor: 라우팅
   - Agent: 도메인 전문성
   - Tool: 외부 API 통합
   - Cache: 성능 최적화

2. **확장성**:
   - 새 에이전트 추가: Supervisor 수정 불필요
   - 새 도구 추가: Agent 수정 불필요
   - FastAPI 워커를 통한 수평 확장

3. **유지보수성**:
   - 명확한 파일 구조
   - 타입 힌트 + Pydantic 스키마
   - 중앙 집중식 에러 처리

4. **성능**:
   - 싱글톤 캐싱으로 중복 작업 제거
   - 메모리 기반 API 키 조회
   - 미리 컴파일된 LangGraph 워크플로우

5. **확장 가능성**:
   - 새 에이전트: `/agents/new_agent/` 생성
   - 새 도구: 기존 `tools.py`에 추가
   - 새 API: `external_api_clients.py`에 추가

## 10. 향후 개선 사항

### 단기
- [ ] URLScan.io API 키 설정 (현재 empty)
- [ ] Hash agent description 길이 축소 (토큰 절약)
- [ ] Rate limit 자동 재시도 로직

### 중기
- [ ] RAG Agent 추가 (사고 이력 기반 분석)
- [ ] Memory 기능 (MemorySaver, InMemoryStore)
- [ ] Streaming 응답

### 장기
- [ ] 결과 데이터베이스 저장
- [ ] 대시보드 UI
- [ ] 실시간 위협 인텔리전스 피드

---

**작성일**: 2025-10-30
**시스템 버전**: v1.0
**테스트 완료**: ✅ 5/5 테스트 통과
