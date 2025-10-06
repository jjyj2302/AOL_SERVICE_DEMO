# 아키텍처 비교 분석: 기존 vs LLM 기반 OSINT 시스템

## 📊 전체 구조 비교

### 현재 구조 (규칙 기반)

```
사용자 입력
    ↓
[수동 서비스 선택]
    ↓
ioc_lookup_engine.py (정적 라우팅)
    ↓
service_registry.py (서비스 매핑)
    ↓
external_api_clients.py (25개 API 함수)
    ↓
결과 반환 (JSON)
```

### 새로운 구조 (LLM 기반)

```
사용자 입력 (IOC만)
    ↓
Knowledge Agent (오케스트레이터)
    ↓
┌─────────────┴─────────────┐
│    ReAct Agent (추론)      │
│  Thought → Action → Obs   │
└─────────────┬─────────────┘
              ↓
[LLM이 자동 도구 선택]
    ↓
LangChain Tools (25개 API 래핑)
    ↓
external_api_clients.py (재사용)
    ↓
결과 → LLM 분석 → 피드백 루프
    ↓
추가 조사 or 최종 요약
```

---

## 🔍 세부 비교

### 1. 사용자 인터페이스 레이어

#### 기존 (수동)
```python
# backend/app/features/ioc_tools/ioc_lookup/single_lookup/routers/single_ioc_lookup_routes.py

@router.post("/lookup")
def lookup_single_ioc(
    service_name: str,  # ❌ 사용자가 서비스를 직접 지정해야 함
    ioc: str,
    ioc_type: str,      # ❌ 사용자가 타입도 지정해야 함
    db: Session = Depends(get_db)
):
    """
    사용자가 결정해야 할 것:
    1. 어떤 서비스를 사용할지 (virustotal? shodan? abuseipdb?)
    2. IOC 타입이 무엇인지 (ipv4? domain? email?)
    3. 추가 조사가 필요한지
    """
    result = lookup_ioc(service_name, ioc, ioc_type, db)
    return result
```

**사용 예시:**
```bash
# 사용자가 3번 요청 보내야 함
curl -X POST "/api/ioc/lookup" -d '{"service_name": "abuseipdb", "ioc": "1.2.3.4", "ioc_type": "ipv4"}'
curl -X POST "/api/ioc/lookup" -d '{"service_name": "virustotal", "ioc": "1.2.3.4", "ioc_type": "ipv4"}'
curl -X POST "/api/ioc/lookup" -d '{"service_name": "shodan", "ioc": "1.2.3.4", "ioc_type": "ipv4"}'
```

#### 새로운 구조 (자동)
```python
# backend/app/features/osint_profiler/routers/osint_routes.py

@router.post("/knowledge-agent")
async def knowledge_agent_investigate(
    query: str,         # ✅ IOC만 입력
    context: str = "",  # ✅ 선택적 컨텍스트
    deep_dive_rounds: int = 2
):
    """
    LLM이 자동으로 결정:
    1. IOC 타입 식별
    2. 적절한 도구 선택
    3. 실행 순서 결정
    4. 추가 조사 필요 여부
    """
    agent = OSINTKnowledgeAgent(db)
    result = await agent.investigate(query, context, deep_dive_rounds)
    return result
```

**사용 예시:**
```bash
# 사용자가 1번만 요청 → LLM이 자동으로 3개 도구 실행
curl -X POST "/api/osint/knowledge-agent" -d '{"query": "1.2.3.4"}'

# LLM 내부 처리:
# 1. "이것은 IPv4 주소"
# 2. "abuseipdb → virustotal → shodan 순서로 조사"
# 3. 자동 실행
# 4. 결과 분석
# 5. "추가로 리버스 DNS 조회 필요" → 자동 실행
```

**차이점:**
- 기존: 사용자가 **3번 요청** + 서비스명/타입 수동 지정
- 새로운: 사용자가 **1번 요청** + LLM이 모든 것 자동 처리

---

### 2. 도구 선택 레이어

#### 기존: 정적 라우팅 (service_registry.py)

```python
# backend/app/features/ioc_tools/ioc_lookup/single_lookup/service/service_registry.py

_services = {
    'virustotal': {
        'func': ioc_lookup_service_module.virustotal,
        'supported_ioc_types': ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256'],
        'api_key_name': 'virustotal'
    },
    'abuseipdb': {
        'func': ioc_lookup_service_module.abuseipdb_ip_check,
        'supported_ioc_types': ['ipv4'],
        'api_key_name': 'abuseipdb'
    },
    # ... 23개 더
}

def lookup_ioc(service_name: str, ioc: str, ioc_type: str, db: Session):
    """
    정적 라우팅:
    - 사용자가 service_name을 지정하면 그대로 실행
    - 조건문 없음, 추론 없음
    """
    service_config = _services.get(service_name)

    # 타입 체크만
    if ioc_type not in service_config['supported_ioc_types']:
        return {"error": "지원하지 않는 타입"}

    # 바로 실행
    return service_config['func'](ioc, apikey)
```

**특징:**
- ✅ 빠름 (조건문만)
- ❌ 지능 없음 (사용자가 모든 것 결정)
- ❌ 컨텍스트 이해 불가 ("피싱 의심" 같은 정보 무시)
- ❌ 순서 최적화 불가

#### 새로운 구조: LLM 기반 동적 선택

```python
# backend/app/features/osint_profiler/agents/web_agent.py

class OSINTWebAgent:
    """
    ReAct 패턴: Thought → Action → Observation
    """

    def __init__(self, db: Session):
        # LangChain Tools 로드
        self.tools = OSINTToolFactory(db).create_all_tools()

        # LLM Agent 초기화
        self.agent = initialize_agent(
            tools=self.tools,
            llm=ChatOpenAI(model="gpt-4"),
            agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION
        )

    async def investigate(self, query: str, context: str):
        """
        LLM이 동적으로 결정:
        1. IOC 타입 식별
        2. 컨텍스트 고려 (예: "피싱 의심")
        3. 우선순위 도구 선택
        4. 결과 기반 추가 도구 선택
        """
        prompt = f"""
        조사 대상: {query}
        컨텍스트: {context}

        사용 가능한 도구:
        - abuseipdb_check: IP 평판 확인
        - virustotal_ip_check: 멀티 엔진 스캔
        - shodan_check: 포트/서비스 정보
        ... (25개 도구)

        당신은 OSINT 전문가입니다.
        적절한 순서로 도구를 선택하여 조사하세요.
        """

        # LLM이 자동으로 도구 선택 및 실행
        result = self.agent.invoke({"input": prompt})

        """
        LLM 내부 추론 예시:

        Thought: "1.2.3.4는 IP 주소입니다. 먼저 평판을 확인해야 합니다."
        Action: abuseipdb_check("1.2.3.4")
        Observation: "Abuse Score 100%, 고위험 IP"

        Thought: "고위험으로 판명됨. 다중 엔진 검증이 필요합니다."
        Action: virustotal_ip_check("1.2.3.4")
        Observation: "15/89 engines flagged as malicious"

        Thought: "악성 확인. 열린 포트를 조사해 공격 벡터를 파악하겠습니다."
        Action: shodan_check("1.2.3.4")
        Observation: "Ports 22, 80, 443 open"

        Thought: "충분한 정보 수집 완료. 최종 결론을 작성하겠습니다."
        Final Answer: "고위험 IP, 즉시 차단 권장..."
        """

        return result
```

**특징:**
- ✅ 지능적 (LLM이 상황 판단)
- ✅ 컨텍스트 이해 ("피싱 의심" → URL 도구 우선)
- ✅ 동적 순서 최적화
- ✅ 결과 기반 추가 조사
- ⚠️ 느림 (LLM 추론 시간)
- ⚠️ 비용 (LLM API 호출)

---

### 3. 실행 엔진 레이어

#### 기존: 단일 실행 (ioc_lookup_engine.py)

```python
# backend/app/features/ioc_tools/ioc_lookup/single_lookup/service/ioc_lookup_engine.py

def lookup_ioc(service_name: str, ioc: str, ioc_type: str, db: Session, **kwargs):
    """
    1회 실행만 가능
    - 1개 서비스
    - 1개 IOC
    - 결과 반환하고 종료
    """
    service_config = service_registry.get_service(service_name)

    # API 키 가져오기
    api_keys = _get_api_keys(service_config, db)

    # 함수 인자 준비
    func_args = _prepare_function_args(service_config, ioc, ioc_type, api_keys, **kwargs)

    # 실행
    result = service_config['func'](**func_args)

    return result  # 끝
```

**플로우:**
```
사용자 요청 → 1개 서비스 실행 → 결과 반환 → 종료
```

**한계:**
- ❌ 연쇄 조사 불가
- ❌ 피드백 루프 없음
- ❌ 크로스 타입 추적 불가 (이메일 → 도메인 → IP)

#### 새로운 구조: 피드백 루프 (feedback_loop.py)

```python
# backend/app/features/osint_profiler/workflows/feedback_loop.py

class FeedbackLoopWorkflow:
    """
    자동 확장 조사

    이메일 조사 → 도메인 발견 → 도메인 조사 → IP 발견 → IP 조사
    """

    async def investigate_with_auto_expansion(
        self,
        initial_ioc: str,
        max_expansion_depth: int = 3
    ):
        """
        재귀적 조사:
        1. 초기 IOC 조사
        2. 결과에서 새로운 IOC 추출
        3. 새로운 IOC를 또 조사
        4. depth 제한까지 반복
        """
        investigated_iocs = set()
        queue = [(initial_ioc, 0)]  # BFS

        while queue:
            current_ioc, depth = queue.pop(0)

            if depth > max_expansion_depth:
                continue

            # 1. 현재 IOC 조사
            result = await self.knowledge_agent.investigate(current_ioc)
            investigated_iocs.add(current_ioc)

            # 2. 결과에서 새로운 IOC 추출
            new_iocs = self._extract_iocs_from_result(result)
            # 예: "Related domain: malware.com" → "malware.com" 추출

            # 3. 큐에 추가 (다음 라운드에서 조사)
            for new_ioc in new_iocs:
                if new_ioc not in investigated_iocs:
                    queue.append((new_ioc, depth + 1))

        return {
            "initial_ioc": initial_ioc,
            "investigated_iocs": list(investigated_iocs),
            "ioc_graph": self._build_graph(...)
        }
```

**플로우:**
```
초기 입력: "hacker@malware.com"
    ↓
Round 0 (depth=0): 이메일 조사
    → 결과: "도메인 malware.com 발견"
    ↓
Round 1 (depth=1): malware.com 조사
    → 결과: "IP 45.142.212.61로 리졸브, 관련 도메인 evil.com 발견"
    ↓
Round 2 (depth=2): 45.142.212.61 조사 + evil.com 조사
    → 결과: "동일 IP에 15개 피싱 사이트 호스팅 중"
    ↓
최종 결과:
    - 조사된 IOC: 17개 (이메일 1 + 도메인 2 + IP 1 + 추가 도메인 13)
    - IOC 그래프 생성
    - "대규모 피싱 캠페인 인프라" 결론
```

**특징:**
- ✅ 자동 확장
- ✅ IOC 간 연관성 파악
- ✅ 그래프 시각화 가능
- ⚠️ 무한 루프 가능성 (depth 제한 필수)

---

### 4. 데이터 흐름 비교

#### 기존: 단방향 흐름

```
┌─────────────┐
│   사용자    │
└──────┬──────┘
       │ 1. "virustotal로 1.2.3.4 조회"
       ↓
┌─────────────────────┐
│ ioc_lookup_engine   │
└──────┬──────────────┘
       │ 2. service_registry에서 'virustotal' 찾기
       ↓
┌─────────────────────┐
│  service_registry   │
└──────┬──────────────┘
       │ 3. virustotal 함수 포인터 반환
       ↓
┌─────────────────────┐
│ external_api_clients│
└──────┬──────────────┘
       │ 4. API 호출
       ↓
┌─────────────────────┐
│   VirusTotal API    │
└──────┬──────────────┘
       │ 5. 결과 반환
       ↓
┌─────────────┐
│   사용자    │ 결과 확인 → 다음 도구 수동 선택
└─────────────┘
```

**흐름 특징:**
- 단방향 (사용자 → 시스템 → 사용자)
- 피드백 없음
- 1회 실행 후 종료

#### 새로운 구조: 순환 피드백 흐름

```
┌─────────────┐
│   사용자    │
└──────┬──────┘
       │ 1. "1.2.3.4" (IOC만 입력)
       ↓
┌──────────────────────────────────┐
│     Knowledge Agent              │
│  (오케스트레이터)                 │
└──────┬───────────────────────────┘
       │ 2. ReAct Agent 생성
       ↓
┌──────────────────────────────────┐
│       ReAct Agent                │
│   ┌─────────────────────┐        │
│   │  LLM: "IP 주소 식별" │        │
│   └─────────┬───────────┘        │
│             ↓                    │
│   ┌─────────────────────┐        │
│   │ Tool: abuseipdb     │        │
│   └─────────┬───────────┘        │
└─────────────┼────────────────────┘
              │ 3. API 호출
              ↓
┌─────────────────────┐
│ external_api_clients│
└──────┬──────────────┘
       │ 4. 결과: "Abuse Score 100%"
       ↓
┌──────────────────────────────────┐
│       ReAct Agent                │
│   ┌──────────────────────────┐   │
│   │ LLM: "고위험 확인됨.     │   │
│   │      VirusTotal로 검증"  │   │
│   └─────────┬────────────────┘   │
│             ↓                    │
│   ┌─────────────────────┐        │
│   │ Tool: virustotal    │        │
│   └─────────┬───────────┘        │
└─────────────┼────────────────────┘
              │ 5. API 호출
              ↓
         ... (반복)
              ↓
┌──────────────────────────────────┐
│     Knowledge Agent              │
│   ┌──────────────────────────┐   │
│   │ LLM: "3개 도구 결과 분석.│   │
│   │  추가 조사 필요한가?"    │   │
│   └─────────┬────────────────┘   │
└─────────────┼────────────────────┘
              │ 6. 피드백 루프 결정
              ↓
     [Round 2로 진입 or 종료]
              ↓
┌─────────────┐
│   사용자    │ 최종 요약 보고서
└─────────────┘
```

**흐름 특징:**
- 순환 구조 (결과 → 분석 → 추가 조사)
- LLM이 매 단계 결정
- 자동 종료 조건 판단

---

## 📁 디렉토리 구조 변화

### 기존 구조

```
backend/app/features/ioc_tools/
├── ioc_lookup/
│   ├── single_lookup/
│   │   ├── service/
│   │   │   ├── ioc_lookup_engine.py       # 실행 엔진
│   │   │   ├── service_registry.py        # 서비스 매핑
│   │   │   └── external_api_clients.py    # 25개 API 함수
│   │   ├── routers/
│   │   │   └── single_ioc_lookup_routes.py
│   │   └── utils/
│   │       └── ioc_utils.py
```

**특징:**
- ✅ 간단명료
- ✅ 의존성 적음
- ❌ 확장성 낮음 (새 기능 추가 어려움)

### 새로운 구조 (추가)

```
backend/app/features/
├── ioc_tools/                          # 기존 (유지)
│   └── ioc_lookup/
│       └── single_lookup/
│           └── service/
│               └── external_api_clients.py   # ✅ 재사용!
│
├── osint_profiler/                     # ✨ 신규
│   ├── agents/
│   │   ├── web_agent.py                # ReAct Agent
│   │   └── knowledge_agent.py          # 오케스트레이터
│   ├── tools/
│   │   └── langchain_wrappers.py       # API → LangChain Tools 변환
│   ├── workflows/
│   │   └── feedback_loop.py            # 피드백 루프 로직
│   ├── utils/
│   │   ├── content_processor.py        # LLM Map-Reduce
│   │   ├── permutations.py             # 이름 → 이메일 변환 (Phase 2)
│   │   ├── async_executor.py           # 워커 풀 (Phase 2)
│   │   └── email_validator.py          # 이메일 검증 (Phase 2)
│   ├── reports/
│   │   └── report_generator.py         # 리포트 생성 (Phase 2)
│   ├── routers/
│   │   └── osint_routes.py             # 새 API 엔드포인트
│   └── THIRD_PARTY_LICENSES.md
```

**특징:**
- ✅ 기존 코드 재사용 (external_api_clients.py)
- ✅ 새 기능은 별도 모듈로 분리
- ✅ 확장 가능 (Phase 3에서 전문 에이전트 추가)
- ⚠️ 복잡도 증가

---

## 🔄 API 엔드포인트 변화

### 기존 엔드포인트

```python
POST /api/ioc/lookup
{
  "service_name": "virustotal",
  "ioc": "1.2.3.4",
  "ioc_type": "ipv4"
}

응답:
{
  "result": {
    "malicious": 15,
    "clean": 74,
    ...
  }
}
```

**사용 시나리오:**
```bash
# 1. AbuseIPDB 조회
curl -X POST /api/ioc/lookup -d '{"service_name": "abuseipdb", "ioc": "1.2.3.4", "ioc_type": "ipv4"}'

# 2. 결과 확인 후 VirusTotal 조회
curl -X POST /api/ioc/lookup -d '{"service_name": "virustotal", "ioc": "1.2.3.4", "ioc_type": "ipv4"}'

# 3. 결과 확인 후 Shodan 조회
curl -X POST /api/ioc/lookup -d '{"service_name": "shodan", "ioc": "1.2.3.4", "ioc_type": "ipv4"}'

# 4. 결과 분석은 사용자가 직접
```

**문제점:**
- 사용자가 3번 요청
- 매번 서비스명/타입 입력
- 결과 분석은 수동
- 추가 조사 판단도 수동

### 새로운 엔드포인트

#### 1. 단일 조사 (ReAct Agent)

```python
POST /api/osint/investigate
{
  "query": "1.2.3.4",
  "context": "의심스러운 접속 로그"  # 선택
}

응답:
{
  "query": "1.2.3.4",
  "result": "고위험 IP로 판단됨. AbuseIPDB, VirusTotal, Shodan 조사 완료. 즉시 차단 권장.",
  "tool_calls": 3,
  "intermediate_steps": [
    {"tool": "abuseipdb_check", "result": "Abuse Score 100%"},
    {"tool": "virustotal_ip_check", "result": "15/89 malicious"},
    {"tool": "shodan_check", "result": "Ports 22,80,443 open"}
  ]
}
```

#### 2. 심화 조사 (Knowledge Agent)

```python
POST /api/osint/knowledge-agent
{
  "query": "malicious@phishing-site.com",
  "deep_dive_rounds": 2,
  "max_api_calls": 15
}

응답:
{
  "initial_query": "malicious@phishing-site.com",
  "total_rounds": 3,
  "findings": [
    {
      "round": 0,
      "type": "initial",
      "result": "이메일 평판 낮음, 도메인 phishing-site.com 발견"
    },
    {
      "round": 1,
      "type": "deep_dive",
      "topics": ["phishing-site.com", "GitHub 검색"],
      "findings": [...]
    },
    {
      "round": 2,
      "type": "deep_dive",
      "topics": ["45.142.212.61", "관련 도메인"],
      "findings": [...]
    }
  ],
  "summary": "대규모 피싱 캠페인 인프라. 17개 연관 IOC 발견. 즉시 차단 권장.",
  "total_api_calls": 12
}
```

#### 3. 자동 확장 조사 (Feedback Loop)

```python
POST /api/osint/feedback-loop
{
  "initial_ioc": "hacker@evil.com",
  "max_expansion_depth": 3,
  "max_total_iocs": 10
}

응답:
{
  "initial_ioc": "hacker@evil.com",
  "investigated_iocs": [
    "hacker@evil.com",
    "evil.com",
    "45.142.212.61",
    "evil2.com",
    "evil3.com",
    ...
  ],
  "total_iocs": 8,
  "max_depth_reached": 2,
  "ioc_graph": {
    "nodes": [
      {"id": "hacker@evil.com", "type": "email", "depth": 0},
      {"id": "evil.com", "type": "domain", "depth": 1},
      {"id": "45.142.212.61", "type": "ipv4", "depth": 2}
    ],
    "edges": [
      {"source": "hacker@evil.com", "target": "evil.com"},
      {"source": "evil.com", "target": "45.142.212.61"}
    ]
  }
}
```

**사용 시나리오:**
```bash
# 1번만 요청
curl -X POST /api/osint/feedback-loop -d '{"initial_ioc": "1.2.3.4"}'

# LLM이 자동으로:
# - IP 조사 → 도메인 발견 → 도메인 조사 → 관련 IP 발견 → ...
# - 총 8개 IOC 조사
# - 연관성 그래프 생성
# - 최종 요약
```

**개선점:**
- 1번 요청으로 완료
- IOC만 입력 (타입/서비스 자동 판단)
- 자동 분석 및 요약
- 크로스 타입 추적
- 그래프 시각화

---

## 🧠 의사결정 레이어 비교

### 기존: 사용자가 모든 것 결정

```
[사용자 의사결정]
1. IOC 타입 식별 (이메일? IP? 도메인?)
2. 어떤 서비스 사용? (VirusTotal? Shodan? AbuseIPDB?)
3. 순서는? (AbuseIPDB 먼저? VirusTotal 먼저?)
4. 추가 조사 필요? (도메인도 조회? IP도 조회?)
5. 결과 해석 (위험한가? 안전한가?)

[시스템 역할]
- 사용자가 지정한 서비스 실행
- 결과 반환
```

**예시:**
```
사용자: "1.2.3.4를 조사하고 싶어"

시스템: "어떤 서비스를 사용하시겠습니까?"
사용자: "AbuseIPDB"
시스템: [AbuseIPDB 실행] "Abuse Score 100%"

사용자: "음... 다른 것도 확인해야겠다. VirusTotal도 조회해줘"
시스템: [VirusTotal 실행] "15/89 malicious"

사용자: "Shodan도 확인해야지"
시스템: [Shodan 실행] "Ports 22, 80, 443 open"

사용자: "이 IP가 호스팅하는 도메인도 조사해야겠네..."
시스템: "도메인을 입력하세요"
사용자: ...
```

### 새로운 구조: LLM이 결정

```
[사용자 의사결정]
1. 조사 대상 제공
2. (선택) 컨텍스트 제공 ("피싱 의심", "APT 공격" 등)

[LLM 의사결정]
1. IOC 타입 자동 식별
2. 컨텍스트 기반 도구 선택
3. 우선순위 최적화
4. 결과 분석 후 추가 조사 자동 결정
5. 위협 수준 평가
6. 최종 요약 및 권장 조치

[시스템 역할]
- LLM 추론 실행
- 도구 자동 실행
- 결과 종합
```

**예시:**
```
사용자: "1.2.3.4를 조사해줘. APT 공격 의심돼"

LLM: [내부 추론]
     "1. IPv4 주소 식별
      2. 'APT 공격' 컨텍스트 → 정밀 조사 필요
      3. 평판 → 멀티엔진 → 인프라 → 연관 IOC 순서로 진행
      4. 도구 선택: AbuseIPDB → VirusTotal → Shodan → AlienVault"

시스템: [자동 실행]
     - AbuseIPDB: "고위험"
     - VirusTotal: "악성 확인"
     - Shodan: "C&C 서버 특징"
     - AlienVault: "APT28 캠페인 연관"

LLM: [추가 조사 결정]
     "AlienVault에서 관련 도메인 발견 → 자동 추가 조사"

시스템: [Round 2 자동 진행]
     - 관련 도메인 5개 조사
     - IP 범위 조사
     - GitHub에서 IOC 검색

최종 결과:
     "고위험 APT28 캠페인 인프라. 17개 연관 IOC 발견.
      즉시 네트워크 차단 및 보안팀 에스컬레이션 권장."
```

---

## 📊 성능 및 효율성 비교

### 시나리오: IP 주소 종합 조사

#### 기존 방식

```
단계 1: AbuseIPDB 조회
  - 요청: POST /api/ioc/lookup {"service_name": "abuseipdb", ...}
  - 응답 시간: 2초
  - 사용자 대기 → 결과 분석 (30초)

단계 2: VirusTotal 조회
  - 요청: POST /api/ioc/lookup {"service_name": "virustotal", ...}
  - 응답 시간: 3초
  - 사용자 대기 → 결과 분석 (30초)

단계 3: Shodan 조회
  - 요청: POST /api/ioc/lookup {"service_name": "shodan", ...}
  - 응답 시간: 2초
  - 사용자 대기 → 결과 분석 (20초)

총 소요 시간:
  - API 시간: 7초
  - 사용자 작업: 80초
  - 합계: 87초 (~1.5분)

사용자 작업:
  - 요청 3번
  - 결과 분석 3번
  - 다음 도구 결정 3번
```

#### 새로운 방식 (단일 조사)

```
단계 1: 1번 요청
  - 요청: POST /api/osint/investigate {"query": "1.2.3.4"}
  - LLM 추론: 3초
  - API 호출 (3개): 7초
  - LLM 분석: 2초
  - 총 응답 시간: 12초

총 소요 시간: 12초

사용자 작업:
  - 요청 1번
  - 결과 확인 1번
```

**개선:**
- 시간: 87초 → 12초 (7배 빠름)
- 요청 횟수: 3번 → 1번
- 사용자 작업: 9단계 → 2단계

#### 새로운 방식 (심화 조사)

```
단계 1: 1번 요청
  - 요청: POST /api/osint/knowledge-agent {"query": "1.2.3.4", "deep_dive_rounds": 2}

Round 0:
  - LLM 추론: 3초
  - API 호출 (3개): 7초
  - LLM 분석: 2초

Round 1:
  - LLM이 추가 주제 선정: 3초
  - API 호출 (4개): 9초
  - LLM 분석: 2초

Round 2:
  - LLM이 추가 주제 선정: 3초
  - API 호출 (3개): 7초
  - LLM 분석: 2초

최종 요약 생성: 5초

총 소요 시간: 46초

총 API 호출: 10개
총 IOC 조사: 5개 (IP + 관련 도메인 2개 + 관련 IP 2개)
```

**기존 방식으로 같은 작업:**
- 사용자가 10번 요청
- 매번 결과 분석 및 다음 조사 결정
- 예상 시간: 300초 이상 (5분+)

**개선:**
- 시간: 300초 → 46초 (6.5배 빠름)
- 요청 횟수: 10번 → 1번
- 조사 범위: 수동 결정 → 자동 확장

---

## 🎯 방향성의 핵심 차이

### 기존: "도구 제공 시스템"

```
철학: "우리는 25개 도구를 제공합니다. 사용자가 선택하세요."

역할:
  - 시스템: 도구 실행기
  - 사용자: 분석가

사용자 책임:
  ✅ IOC 타입 판단
  ✅ 도구 선택
  ✅ 순서 결정
  ✅ 결과 해석
  ✅ 추가 조사 결정
  ✅ 최종 결론

시스템 책임:
  ✅ 도구 실행
  ✅ 결과 반환
```

**장점:**
- ✅ 사용자가 완전히 통제
- ✅ 예측 가능한 동작
- ✅ 빠른 응답 (조건문만)
- ✅ 비용 저렴 (LLM 없음)

**단점:**
- ❌ 전문 지식 필요 (어떤 도구를 언제 쓰는지)
- ❌ 시간 소모 (반복 작업)
- ❌ 일관성 부족 (분석가마다 다른 결과)
- ❌ 확장성 부족 (IOC 늘어나면 기하급수적 증가)

### 새로운 구조: "자율 분석 시스템"

```
철학: "당신의 OSINT 전문가 에이전트입니다. IOC만 주세요."

역할:
  - 시스템: 자율 분석가
  - 사용자: 조사 의뢰인

시스템 책임:
  ✅ IOC 타입 자동 판단
  ✅ 컨텍스트 이해
  ✅ 도구 자동 선택
  ✅ 최적 순서 결정
  ✅ 결과 자동 해석
  ✅ 추가 조사 자동 결정
  ✅ IOC 간 연관성 파악
  ✅ 최종 요약 및 권장 조치

사용자 책임:
  ✅ 조사 대상 제공
  ✅ (선택) 컨텍스트 제공
  ✅ 최종 결과 검토
```

**장점:**
- ✅ 전문 지식 불필요 (LLM이 전문가 역할)
- ✅ 일관성 (동일한 논리로 분석)
- ✅ 확장성 (IOC 늘어나도 1번 요청)
- ✅ 자동 심화 (사람이 놓칠 수 있는 연관성 발견)
- ✅ 시간 절약 (자동화)

**단점:**
- ❌ 느림 (LLM 추론 시간)
- ❌ 비용 (LLM API)
- ❌ 예측 불가능 (LLM 환각 가능성)
- ❌ 통제 감소 (LLM이 결정)

---

## 🔀 통합 전략 비교

### 선택지 1: 기존 시스템 대체 (❌ 비추천)

```
ioc_tools/ 폴더 삭제
    ↓
osint_profiler/로 완전 교체
```

**문제:**
- ❌ 기존 사용자 혼란
- ❌ 기존 API 깨짐
- ❌ 빠른 조회 기능 상실
- ❌ 25개 API 함수 재작성 필요

### 선택지 2: 병렬 운영 (✅ 추천, 우리 선택)

```
backend/app/features/
├── ioc_tools/           # 기존 유지
│   └── ...              # 빠른 단일 조회용
│
├── osint_profiler/      # 신규 추가
│   └── ...              # LLM 기반 자동 분석용
```

**장점:**
- ✅ 기존 API 유지 (하위 호환성)
- ✅ external_api_clients.py 재사용
- ✅ 사용자가 선택 가능:
  - 빠른 조회 → 기존 API
  - 심화 분석 → 새 API
- ✅ 점진적 전환 가능

**API 구조:**
```
# 기존 (유지)
POST /api/ioc/lookup
- 용도: 빠른 단일 조회
- 대상: 서비스를 이미 아는 고급 사용자

# 신규 (추가)
POST /api/osint/investigate
- 용도: 자동 분석
- 대상: 일반 사용자

POST /api/osint/knowledge-agent
- 용도: 심화 조사
- 대상: 복잡한 케이스

POST /api/osint/feedback-loop
- 용도: 캠페인 추적
- 대상: APT, 피싱 캠페인 분석
```

### 선택지 3: 점진적 통합 (Phase 2-3)

```
Phase 1: 병렬 운영
    ↓
Phase 2: 기존 시스템에 LLM 기능 추가
    ↓
Phase 3: 단일 API로 통합
```

---

## 💡 실제 사용 케이스 비교

### 케이스 1: "빠른 평판 확인"

**상황:** "이 IP가 안전한지 빨리 확인하고 싶어"

**기존 방식:**
```bash
curl -X POST /api/ioc/lookup \
  -d '{"service_name": "abuseipdb", "ioc": "1.2.3.4", "ioc_type": "ipv4"}'

# 응답 시간: 2초
# 결과: {"abuse_score": 0, "reports": 0}
# 결론: 안전
```

**새로운 방식:**
```bash
curl -X POST /api/osint/investigate \
  -d '{"query": "1.2.3.4"}'

# 응답 시간: 12초 (LLM + 3개 API)
# 결과: "안전한 IP. AbuseIPDB, VirusTotal, Shodan 모두 정상."
```

**최적 선택:** **기존 방식** (빠름, 비용 저렴)

### 케이스 2: "의심스러운 이메일 조사"

**상황:** "피싱 메일에서 발견한 이메일을 조사하고 싶어"

**기존 방식:**
```bash
# 1. HaveIBeenPwned
curl -X POST /api/ioc/lookup -d '{"service_name": "haveibeenpwned", ...}'
# 결과: 유출 이력 없음

# 2. EmailRep
curl -X POST /api/ioc/lookup -d '{"service_name": "emailrepio", ...}'
# 결과: 의심스러운 평판

# 3. 도메인 추출 (수동)
# "hacker@phishing-site.com" → "phishing-site.com"

# 4. VirusTotal 도메인 조회
curl -X POST /api/ioc/lookup -d '{"service_name": "virustotal", "ioc": "phishing-site.com", "ioc_type": "domain"}'
# 결과: 악성 도메인

# 5. IP 추출 (수동으로 결과 파싱)
# "Resolved to 45.142.212.61"

# 6. IP 조회
curl -X POST /api/ioc/lookup -d '{"service_name": "abuseipdb", "ioc": "45.142.212.61", ...}'

# 총 6번 요청, 5분 소요
```

**새로운 방식:**
```bash
curl -X POST /api/osint/feedback-loop \
  -d '{"initial_ioc": "hacker@phishing-site.com", "max_expansion_depth": 2}'

# 응답 시간: 1분
# 자동 수행:
#   - 이메일 조사
#   - 도메인 자동 추출 및 조사
#   - IP 자동 추출 및 조사
#   - 관련 도메인 자동 발견 및 조사
# 결과: "대규모 피싱 캠페인 인프라. 17개 연관 IOC 발견."
```

**최적 선택:** **새로운 방식** (자동화, 포괄적)

### 케이스 3: "APT 공격 인프라 분석"

**상황:** "APT 그룹의 C&C 서버로 의심되는 IP를 심층 분석하고 싶어"

**기존 방식:**
```
사용자가 수동으로:
1. 10개 이상의 서비스 조회
2. 각 결과에서 연관 IOC 추출
3. 연관 IOC를 다시 조회
4. 연관성 매핑
5. 최종 보고서 작성

예상 시간: 30분 ~ 1시간
```

**새로운 방식:**
```bash
curl -X POST /api/osint/knowledge-agent \
  -d '{
    "query": "45.142.212.61",
    "context": "APT28 캠페인 의심",
    "deep_dive_rounds": 3,
    "max_api_calls": 30
  }'

# 응답 시간: 3-4분
# 자동 수행:
#   Round 0: IP 기본 조사 (5개 도구)
#   Round 1: 관련 도메인, GitHub 검색 (8개 도구)
#   Round 2: 인프라 범위 파악, 암호화폐 추적 (10개 도구)
#   Round 3: 공격 캠페인 연관성 분석 (7개 도구)
# 결과:
#   - 30개 API 호출
#   - 25개 연관 IOC 발견
#   - IOC 그래프 생성
#   - 최종 위협 보고서
```

**최적 선택:** **새로운 방식** (불가능 → 가능)

---

## 📈 확장성 비교

### 기존: 선형 확장

```
조사 대상 1개 → 사용자 작업 N번
조사 대상 5개 → 사용자 작업 5N번
조사 대상 10개 → 사용자 작업 10N번

예: IP 10개를 종합 조사
  - 각 IP당 3개 서비스 = 30번 요청
  - 사용자 대기 시간: 10분
  - 사용자 작업: 90단계
```

### 새로운 구조: 병렬 확장

```
조사 대상 1개 → 1번 요청
조사 대상 5개 → 1번 요청 (일괄 처리)
조사 대상 10개 → 1번 요청 (일괄 처리)

예: IP 10개를 종합 조사
  - 1번 요청 (배열로 전달)
  - LLM이 자동으로 30개 API 호출 (병렬)
  - 응답 시간: 2분 (워커 풀 사용 시)
  - 사용자 작업: 2단계 (요청 + 결과 확인)
```

**Phase 2에서 추가할 일괄 처리 API:**
```python
POST /api/osint/batch-investigate
{
  "iocs": ["1.2.3.4", "example.com", "hacker@evil.com", ...],
  "max_concurrent": 10  # 워커 풀
}

# 10개 IOC를 동시에 조사
# 각 IOC별로 자동 도구 선택
# 최종 통합 보고서 생성
```

---

## 🎯 최종 요약

### 핵심 변화

| 측면 | 기존 | 새로운 |
|------|------|--------|
| **철학** | 도구 제공 시스템 | 자율 분석 시스템 |
| **사용자 역할** | 분석가 | 의뢰인 |
| **시스템 역할** | 도구 실행기 | 전문가 에이전트 |
| **입력** | 서비스명 + IOC + 타입 | IOC만 |
| **도구 선택** | 사용자 | LLM |
| **실행 패턴** | 단일 실행 | 피드백 루프 |
| **결과** | Raw 데이터 | 분석 + 요약 |
| **확장** | 선형 (N배) | 자동 (크로스 타입) |
| **속도** | 빠름 (2초/호출) | 중간 (10-60초/조사) |
| **비용** | 저렴 (API만) | 중간 (API + LLM) |

### 방향성 변화

**Before (기존):**
```
"우리는 강력한 도구들을 제공합니다.
 당신이 전문가라면 효율적으로 사용할 수 있을 겁니다."
```

**After (새로운):**
```
"우리는 당신의 OSINT 전문가입니다.
 조사 대상만 말씀해주세요. 나머지는 저희가 알아서 합니다."
```

### 공존 전략

```
┌─────────────────────────────────┐
│     사용자 선택                  │
└────────┬────────────────────────┘
         │
    ┌────┴────┐
    │         │
빠른 조회?  심화 분석?
    │         │
    ↓         ↓
┌──────┐  ┌────────────┐
│ 기존 │  │ LLM 기반   │
│ API  │  │ Agent      │
└───┬──┘  └─────┬──────┘
    │           │
    └─────┬─────┘
          ↓
  external_api_clients.py
      (공유 재사용)
```

---

## 🚀 다음 단계

이 분석 문서를 바탕으로:

1. ✅ **OSINT_INTEGRATION_PLAN.md** - 구현 계획서 (완료)
2. ✅ **ARCHITECTURE_COMPARISON.md** - 구조 비교 (현재 문서)
3. ⏭️ **다음:** Phase 1 Week 1 시작

**시작 명령:**
```
OSINT_INTEGRATION_PLAN.md를 읽고 Phase 1 Week 1부터 시작해줘.
먼저 langchain 의존성 추가하고, 디렉토리 구조 생성하자.
```
