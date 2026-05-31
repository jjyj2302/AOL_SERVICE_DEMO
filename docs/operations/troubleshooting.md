# Troubleshooting Log — 금융권 AX 전환 중 발생한 이슈

> 마이그레이션 진행 중 만난 문제와 해결법 기록. 동일 이슈 재발 시 빠르게 참조.
> Notion 그대로 붙여넣을 수 있도록 마크다운 형식.

---

## 📊 요약 표

| # | 영역 | 문제 | 원인 | 해결 |
|---|---|---|---|---|
| 1 | **deps** | langgraph 1.x 설치 실패 | langchain-core 1.x 요구, CrewAI 스택은 0.3.x 호환 | langgraph 0.2.x 라인 핀 |
| 2 | **deps** | `module 'langchain' has no attribute 'debug'` | langchain-core 와 langchain 버전 불일치 | 둘 다 0.3.x 라인으로 정합 |
| 3 | **deps** | langgraph-supervisor 충돌 | 옛 osint_profiler 잔재 패키지 | uninstall (현 코드 미사용) |
| 4 | **langgraph** | `'triage' is already being used as a state key` | 노드명·state 필드명 동일 | 노드명에 `_step` 접미사 |
| 5 | **langgraph** | Audit Ledger / MCP calls 빈 리스트 | 노드가 full state 반환 시 리스트 교체 | `Annotated[..., add]` 리듀서 + delta dict 반환 |
| 6 | **docker** | `env file /etc/aol/.env not found` | 로컬 검증 시 prod 경로 미존재 | `env_file: path: ..., required: false` |
| 7 | **docker** | compose config 가 backend/docker-compose.yaml 을 찾음 | 작업 디렉터리가 `backend/` 였음 | repo root 에서 docker compose 실행 |
| 8 | **venv** | sys.path 가 miniconda3 를 가리킴 | backend/venv 의 pyvenv.cfg 손상 | `pip install --user` 로 임시 우회, 정식 검증은 docker |
| 9 | **docs** | ARCHITECTURE.md 가 존재하지 않는 모듈 묘사 | 옛 osint_profiler 기준 문서, 마이그레이션 미반영 | 상단에 outdated 안내 + PHASE_LOG 참조 |
| 10 | **git** | 커밋 거부됨 | ZETTY 컨벤션 (scope 표준, Co-Authored 제거) 미준수 | 컨벤션 strict 적용, scope 매핑 (api/llm/infra/docs/ci/db) 재정의 |

---

## 🔬 상세 이슈 노트

### #1 · langgraph 1.x ↔ langchain 0.3.x 의존성 충돌

**증상**
```
langchain-openai 0.3.11 requires langchain-core<1.0.0,>=0.3.49,
but you have langchain-core 1.4.0 which is incompatible.
```

**원인**: `langgraph>=0.2.50` 만 지정하면 pip 가 최신인 1.x 를 선택. langgraph 1.x 는 langchain-core 1.x 를 끌어옴. 그러나 본 저장소의 CrewAI / langchain-openai / langchain-anthropic 은 langchain-core 0.3.x 에 핀.

**해결**: requirements.txt 에 명시적 상한 추가.
```
langgraph>=0.2.50,<0.3
langgraph-checkpoint>=2.0.0,<3
langchain-mcp-adapters>=0.0.6,<0.1
```

---

### #2 · `module 'langchain' has no attribute 'debug'`

**증상**: LangGraph 실행 시 콜백 관리자가 `langchain.debug` 접근 실패.

**원인**: `langchain-core` 와 `langchain` 패키지 버전 불일치. core 가 신버전인데 langchain 본체가 옛 버전이면 디버그 모드 조회 시 AttributeError.

**해결**: 두 패키지 같은 마이너 라인으로 맞춤.
```bash
pip install "langchain>=0.3,<1" "langchain-core>=0.3,<1"
```

---

### #3 · langgraph-supervisor 호환성 충돌

**증상**
```
langgraph-supervisor 0.0.7 requires langgraph<0.4.0,>=0.3.5,
but you have langgraph 0.2.76
```

**원인**: 옛 `osint_profiler` 모듈이 langgraph-supervisor 를 썼으나, 본 마이그레이션에서 현 코드는 supervisor 패키지 미사용. pip 가 unsatisfiable extras 로 경고만 출력.

**해결**: `pip uninstall langgraph-supervisor` (어차피 안 쓰임).

---

### #4 · LangGraph 노드명 ↔ State 필드명 충돌

**증상**
```python
ValueError: 'triage' is already being used as a state key
```

**원인**: LangGraph 0.2.x 는 노드명이 state 의 필드명과 같을 수 없음.
```python
class ThreatHuntState(BaseModel):
    triage: TriageFindings | None = None   # ← 필드명

graph.add_node("triage", triage_node)       # ← 노드명 (같으면 거부)
```

**해결**: 노드명에 `_step` 접미사 부여하여 분리.
```python
graph.add_node("triage_step", lambda s: triage_node(s, mcp))
graph.add_edge("triage_step", "malware_step")
```

---

### #5 · Audit Ledger / MCP calls 가 빈 리스트로 종료

**증상**: 그래프 실행 후 `state.audit_ledger == []`, `state.mcp_calls == []`.
중간 노드에서 append 했음에도 최종 state 에 반영 안 됨.

**원인**: LangGraph 가 Pydantic state 를 노드 간에 직렬화/역직렬화하며,
노드가 full state 를 반환하면 리스트 필드를 **마지막 값으로 교체**.
이전 노드의 append 가 사라짐.

**해결**: 두 가지 변경 동시 적용.

1) **State 에 누적 리듀서 적용**
```python
from operator import add
from typing import Annotated

audit_ledger: Annotated[list[LedgerEntry], add] = Field(default_factory=list)
mcp_calls:    Annotated[list[McpCallRecord], add] = Field(default_factory=list)
```

2) **노드는 delta dict 만 반환** (full state 반환 금지)
```python
def triage_node(state, mcp):
    return {
        "triage": new_findings,
        "audit_ledger": [new_entry],   # ← 이 노드가 추가한 1건만
        "mcp_calls": new_calls,        # ← 이 노드가 호출한 것만
    }
```

이렇게 하면 LangGraph 가 `add` 리듀서로 concat 처리.

---

### #6 · docker compose 로컬 검증 실패 (env_file 누락)

**증상**
```
env file /etc/aol/.env not found: stat /etc/aol/.env: no such file or directory
```

**원인**: docker-compose.prod.yaml 의 `env_file: - /etc/aol/.env` 는 EC2 user-data 가 부팅 시 생성하는 경로. 개발자 로컬에는 당연히 없음. 그런데 `docker compose config` 검증이 이걸 강제로 stat() 함.

**해결**: Compose v2.20+ 의 신 문법으로 optional 처리.
```yaml
env_file:
  - path: /etc/aol/.env
    required: false
```

---

### #7 · docker compose 가 docker-compose.yaml 을 찾지 못함

**증상**
```
open .../backend/docker-compose.yaml: no such file or directory
```

**원인**: `cd backend && docker compose ...` 실행했는데 compose 파일은 repo root 에 있음.

**해결**: docker compose 명령은 항상 repo root 에서. CI/CD 워크플로에서도 `working-directory: .` 명시.

---

### #8 · venv 가 miniconda3 를 가리킴 (sys.path 손상)

**증상**: `backend/venv/bin/python -c "import sys; print(sys.path)"` 가 `/home/jyj0203/miniconda3/...` 만 출력. 즉 venv 의 site-packages 가 PATH 에 없음.

**원인**: 과거 conda 환경에서 venv 를 만들어서 pyvenv.cfg 의 `home = ...` 가 miniconda3 를 가리키게 됨. venv 의 활성화가 실제로 격리되지 않음.

**해결 (임시)**: 검증을 위해 `pip install --user` 로 langgraph 등 설치. 코드 실행 시 `~/.local/lib/python3.12/site-packages` 가 잡힘.

**해결 (정식)**: venv 재생성 — `python3 -m venv backend/venv && backend/venv/bin/pip install -r backend/requirements.txt`. 단, **운영/CI 검증은 docker 컨테이너 내부에서 수행**하는 게 안전.

---

### #9 · ARCHITECTURE.md 가 존재하지 않는 모듈 묘사

**증상**: ARCHITECTURE.md 에 `osint_profiler/supervisor.py`, `langgraph-supervisor` 사용을 상세히 묘사하나 실제 코드에 해당 모듈 없음. 면접관/리뷰어가 코드 ↔ 문서 정합성 깨졌다고 판단할 우려.

**원인**: 본 시스템이 과거 LangGraph supervisor 기반에서 CrewAI 로 한 번 옮겨졌고, 그 과정에서 ARCHITECTURE.md 가 갱신 안 됨.

**해결**: 본 마이그레이션 (CrewAI → LangGraph + MCP) 일환으로 문서 상단에 outdated 안내 추가, PHASE_LOG.md 와 신규 모듈 (`langgraph_threat_hunter/`) 을 참조 포인터로 명시.

---

### #10 · 커밋 컨벤션 미준수로 git commit 거부

**증상**: 커밋 진행하려다 한 차례 거부 → 사용자가 ZETTY 컨벤션 재명시.

**원인**: scope 표준 (api, infra, llm, db, ci, docs) 을 따르지 않고 `readme`, `phase-log`, `deploy`, `backend` 등 임의 명명 사용. Co-Authored-By 자동 추가도 제거 필요.

**해결**: 본 저장소 scope 매핑 락인.
| 대상 | scope |
|---|---|
| backend FastAPI / Python | `api` |
| LangGraph 에이전트 / MCP | `llm` |
| Docker / EC2 / Compose | `infra` |
| GitHub Actions | `ci` |
| README / ARCHITECTURE / PHASE_LOG | `docs` |
| SQLAlchemy / DB 스키마 | `db` |

이후 모든 커밋은 위 매핑에 strict 준수, Co-Authored 행은 제거.

---

---

## 📊 Phase 14~16 이슈 (Live LLM + Tool Use + MCP wire-up)

| # | 영역 | 문제 | 원인 | 해결 |
|---|---|---|---|---|
| 11 | **integrity** | "MCP 5종 도구" 라고 광고했으나 사실 mock | `mcp_clients.py` 의 live 분기가 `# TODO(live)` placeholder. README/ARCHITECTURE 에 wire-up 예정만 적고 진행 안 함 — 데모에서 mock 데이터를 실 데이터로 오해 가능 | (이번 세션) `mcp_clients.py` 의 live 분기 실 HTTP 구현. VT/DNSTwist/Shodan(InternetDB)/crt.sh/NVD/EPSS/CISA-KEV 직접 호출 |
| 12 | **frontend** | Confidence Gate 가 무한 "running" 표시 | `pickNextNode("confidence_gate")` 가 fallback 으로 자기 자신("confidence_gate") 반환 → done 직후 다시 running 으로 덮어쓰기 | (1) 함수 시작에 `if currentId === "confidence_gate" → return null` 추가 (2) 다음노드 셋팅 가드 (nextId !== currentId && status !== "done"/"skipped") (3) done 이벤트에서 running 잔재 → done 강제 |
| 13 | **llm** | MCP 호출은 했는데 LLM 한테 전달 안 됨 | `triage_node` 등에서 `m.virustotal(s, ioc, type)` 호출만 하고 반환값 변수에 받지 않음 → LLM 사용자 메시지에 미포함. 실 데이터가 있어도 LLM 은 추정만 함 | `_live_user_prompt(state, prior, mcp_data=)` 에 mcp_data 파라미터 추가, JSON 직렬화하여 user 메시지에 포함. `triage/malware/infrastructure/campaign` 각각 mcp 결과를 변수에 받아 전달 |
| 14 | **env** | `ANTHROPIC_API_KEY` 가 backend 컨테이너에 안 들어감 | docker-compose env passthrough 가 `${ANTHROPIC_API_KEY:-}` 라 shell env 가 비면 빈값. Bash tool 각 호출이 새 shell 라 inline `KEY=... docker compose up` 가 휘발 | docker-compose.yaml 에 명시적 추가 `- ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}`. 재시작 시 inline 으로 shell env 주입 |
| 15 | **infra** | backend healthcheck `/health` 가 404 | 우리 시스템에는 `/api/healthcheck` (구) 또는 `/api/lg/health` (신규 LangGraph) 만 존재 | docker-compose.prod.yaml 의 healthcheck URL 을 `/api/lg/health` 로 변경 — 그래프 컴파일 + 시나리오 가용성까지 동시 검증 |
| 16 | **anthropic** | Claude JSON 응답이 `{"findings": ..., "chat_message": ...}` 래퍼로 옴 | 시스템 프롬프트가 그렇게 지시. 코드는 `findings.get("route_plan")` 처럼 평탄 접근 — fallback 만 발동 | `unwrap_findings(parsed)` 헬퍼 추가하여 wrapper → inner findings + chat_message 분리. orchestrator/specialist 모두 이 헬퍼 사용 |
| 17 | **frontend** | Tool Use 자유 대화 시 채팅창에 specialist 참여가 안 보임 | conversation.py 가 generator 로 텍스트 chunk 만 yield. tool_use/tool_result 이벤트 미발생 | conversation.py 를 `AsyncIterator[dict]` 로 변경, 이벤트 종류 (text/tool_use/tool_result) 분리. router 에서 SSE 타입 매핑. frontend 에 tool_use/tool_result 핸들러 추가 — 자문 요청/응답 별도 버블 + 우측 Agent Studio 의 specialist running→done 점등 |

---

## 📌 재발 방지 체크리스트

작업 시작 전 다음을 확인:

- [ ] requirements.txt 핀 범위가 `langchain-core 0.3.x` 호환인지
- [ ] LangGraph 노드명이 state 필드명과 충돌하지 않는지
- [ ] state 의 리스트 필드 중 누적이 필요한 것은 `Annotated[..., add]` 적용했는지
- [ ] 노드 반환은 delta dict 인지 (full state 금지)
- [ ] docker-compose 의 env_file 은 `required: false` 인지
- [ ] docker compose 명령은 repo root 에서 호출하는지
- [ ] venv 활성화 후 `which python` 으로 격리 확인했는지
- [ ] 문서 (README / ARCHITECTURE) 와 코드가 정합한지
- [ ] 커밋 메시지가 ZETTY 컨벤션 (type/scope/subject) 인지, Co-Authored 행 없는지
- [ ] **MCP 도구는 실 호출인지 mock 인지 명확히 README 에 표기**
- [ ] **MCP 결과가 LLM user 메시지에 실제 포함되는지 (호출만 하고 버리는 코드 금지)**
- [ ] **LangGraph 노드 상태머신에서 종단 노드가 자기 자신을 next 로 반환하지 않는지**
- [ ] **Claude JSON 응답이 `{findings, chat_message}` wrapper 일 가능성을 항상 unwrap 처리**
- [ ] **docker-compose 의 healthcheck URL 이 실제 서버에 존재하는 path 인지**
- [ ] **shell env 휘발 — backend 재시작 시 API_KEY 명시적 inline 주입**
