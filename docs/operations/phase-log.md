# Phase Log — 금융권 네트워크 보안 AX 전환

> 본 프로젝트의 **금융권 네트워크 보안 AX (AI Transformation)** 전환 진행 기록.
> 각 Phase 별로 (1) 무엇을 했는지, (2) 무엇이 개선됐는지, (3) 남은 작업을 누적 기록.
> Notion 에 그대로 붙여넣을 수 있는 마크다운 형식.

---

## 📌 전체 로드맵 (재정렬 v2 — 2026-05-23)

| Phase | 주제 | 상태 |
|---|---|---|
| **Phase 1** | 기반 정비 — README/문서 금융권 리포지셔닝 | ✅ 완료 |
| **Phase 2** | LangGraph 신규 모듈 — Orchestrator + 5 Specialist | ✅ 완료 |
| **Phase 3** | MCP 5종 게이트웨이 추상화 (VT/DNSTwist/Shodan/OSINT/CVE) | ✅ 완료 |
| **Phase 4** | 5대 금융권 시뮬레이션 시나리오 + chat_message | ✅ 완료 |
| **Phase 5** | DB SQLite → PostgreSQL 16 마이그레이션 | ✅ 완료 |
| **Phase 6** | EC2 단일 인스턴스 배포 산출물 (compose.prod + user-data) | ✅ 완료 |
| **Phase 7** | CI/CD 파이프라인 정리 + pytest 슈트 44 케이스 | ✅ 완료 |
| **Phase 8** | NotebookLM 3-패널 챗 UI + SSE 실시간 스트리밍 | ✅ 완료 |
| **Phase 9** | CrewAI 레거시 모듈 폐기 (legacy/ 이동 + 의존성 제거) | 🟡 진행중 |
| **Phase 10** | PDF 리포트 생성기 + `/report.pdf` 엔드포인트 | ⚪ 대기 |
| **Phase 11** | ARCHITECTURE.md 정식 LangGraph 다이어그램 갱신 | ⚪ 대기 |
| **Phase 12** | docker compose 실 기동 + 라이브 데모 검증 | ⚪ 대기 |

---

## 🤖 시스템 구조 — Hierarchical Multi-Agent (6 Agents)

```
사용자 IoC 입력
    │
    ▼
🧠 Investigation Orchestrator
    │  (IoC 타입 분석 → route_plan 결정)
    │  cve   → [triage, campaign]
    │  hash  → [triage, malware, infra, campaign]
    │  ip/domain/url → [triage, infra, campaign]
    │
    ▼  조건부 라우팅 (LangGraph add_conditional_edges)
┌──────────────────────────────────────────────┐
│ 🔍 Triage Specialist     (VirusTotal MCP)    │
│ 👾 Malware Specialist    (VT + OSINT MCP)    │
│ 🌍 Infrastructure Hunter (DNSTwist+Shodan)   │
│ 📈 Campaign Analyst      (CVE-MCP EPSS/KEV)  │
└──────────────────────────────────────────────┘
    │  (각 Specialist 가 chat_message + 구조화 산출물 동시 산출)
    ▼
🛡️ Confidence Gate
    │  L0~L4 자동화 등급 + 핵심 자산 휴먼 승인 강제
    ▼
산출물:
  • Audit Ledger (감사 추적)
  • 방화벽 차단 규칙
  • 헌팅 쿼리 (SPL/KQL/Sigma)
  • Executive Summary
  • PDF 리포트
```

---

## 🎨 UI 구조 — NotebookLM 3-패널

```
┌─ 자료실 (Left) ─┬─ 대화 (Center) ─┬─ Agent Studio (Right) ─┐
│ 📚 샘플 시나리오 │  진짜 대화만    │  🤖 6 Agents Pipeline   │
│  S1~S5 카드     │  user ↔ agent  │  실시간 진행 바         │
│                 │                 │                         │
│ 📥 분석 리포트   │  Bubble UI     │  📊 메트릭 4-카드        │
│  PDF 보관함     │  + SSE 스트림  │  📥 PDF 다운로드        │
│                 │                 │  🛡️ FW 규칙            │
│                 │                 │  🔍 헌팅 쿼리           │
│                 │                 │  🧩 MCP Tool Calls      │
└─────────────────┴─────────────────┴────────────────────────┘
```

채팅창 = 자연어 대화만. 기술 산출물은 우측 Agent Studio 로 분리.

---

## ✅ Phase 1 — 기반 정비 (README/문서)

- 타이틀: 금융권 SOC Tier-1 자동화 Multi-Agent CTI 플랫폼
- 4단 AX 서사: Why → How → Impact → Deliverable
- 임팩트 표: 99.6% 시간 감축 (시나리오 6종) + KPI 5종
- 컴플라이언스 매핑: 전자금융감독규정 §13/§15, FSI, ISMS-P, DORA
- 비교표: vs SOAR / 단일 AI / 폐쇄형 AI SOC
- sLLM 톤다운: PoC 옵션임을 명시

## ✅ Phase 2 — LangGraph + Orchestrator (6 Agents)

- `backend/app/features/langgraph_threat_hunter/` 패키지 신설
- `ThreatHuntState` Pydantic — IoC + route_plan + findings + ledger + mcp_calls
- 6개 에이전트: 🧠 Orchestrator + 🔍 Triage + 👾 Malware + 🌍 Infra + 📈 Campaign + 🛡️ Gate
- **동적 라우팅**: IoC 타입 (cve/hash/ip/domain/url) 별로 specialist 스킵
- L0~L4 Confidence Gating + 핵심 자산 휴먼 승인 강제 (kakaobank, swift 등)

## ✅ Phase 3 — MCP 5종 게이트웨이

- `McpRegistry` 클래스 — VT / DNSTwist / Shodan / OSINT / CVE
- simulation / live 모드 분기 (live 는 wire-up 예정)
- McpCallRecord 자동 기록 (tool / elapsed_ms / cached / simulation)

## ✅ Phase 4 — Simulation Mode + chat_message

- 5개 시드: S1 카카오뱅크 / S2 보이스피싱 / S3 랜섬웨어 / S4 노출자산 / S5 CVE
- 각 시나리오의 각 에이전트에 한국어 chat_message 사전 정의
- 게이트는 신뢰도·등급 기반 메시지 자동 생성
- 정량 효과: S1 30분→4초 (99.7%↓), S2 180분→8초, S3 120분→12초 등

## ✅ Phase 5 — PostgreSQL 마이그레이션

- SQLAlchemy DATABASE_URL 환경변수 → PostgreSQL 우선, SQLite fallback
- docker-compose 에 `postgres:16-alpine` 서비스 + named volume
- prod 오버레이: pg_isready healthcheck, 1 vCPU / 2 GB 제한
- EC2 user-data: `/aol/postgres_password` SSM 시크릿 + 임시 패스워드 fallback

## ✅ Phase 6 — EC2 배포 산출물

- `docker-compose.prod.yaml`: healthcheck 4종 + 로그 로테이션 + 리소스 제한
- `deploy/ec2-userdata.sh`: 멀티 OS 부트스트랩 + SSM 시크릿 + git 동기화 + compose up
- `docs/DEPLOYMENT.md`: IAM/SG/배포/운영/트러블슈팅/비용

## ✅ Phase 7 — CI/CD + pytest 슈트

- `.github/workflows/ci.yml` 들여쓰기 깨진 것 재작성, 4-job 파이프라인
- `cd.yml` 의 deprecated `actions/create-release@v1` → `softprops/action-gh-release@v2`
- `backend/tests/` 디렉터리 신설 — 44 케이스 / 0.5초 / 100% 통과
- datetime.utcnow() → timezone-aware now (deprecation 200+→1)

## ✅ Phase 8 — NotebookLM 3-패널 챗 UI + SSE

- 프론트 신규 컴포넌트:
  - `ThreatHunterPage.jsx` — 3-패널 레이아웃 메인
  - `SourcesPanel.jsx` — 좌측 (샘플 시나리오 + 분석 리포트)
  - `ChatPanel.jsx` — 가운데 순수 대화 (user/assistant 버블)
  - `ResultsSidebar.jsx` — 우측 (메트릭 + 산출물)
  - `AgentPipelinePanel.jsx` — 6-에이전트 실시간 진행 바
- 백엔드: `POST /api/lg/chat/stream` SSE — 노드별 delta 를 실시간 yield
- pace 파라미터: 시연용 0.5초 노드 간 지연 (육안 확인 가능)
- 사이드바: `🤖 AI Threat Hunter` 로 통합 (기존 `Simulation` 메뉴 폐기)
- 챗 패널 = 자연어만, 우측 패널 = 기술 산출물 (관심사 분리)

## 🟡 Phase 9 — CrewAI 레거시 폐기 (진행중)

### 계획
1. `backend/app/features/{deep_analysis,crew_solo,bulk_analysis_async}/` → `backend/app/legacy/` 로 이동 (git mv)
2. `main.py` 의 CrewAI 라우터 import 제거
3. `requirements.txt` 의 `crewai`, `crewai-tools` 제거
4. 프론트엔드: 기존 `Agents.jsx` 의 라우트가 새 ThreatHunter 로 리다이렉트되도록 정리 (별도 작업)
5. README 의 CrewAI 언급 모두 제거

### 영향
- 백엔드 의존성 크기 ~200MB 감축
- 단일 멀티에이전트 path (LangGraph) 로 통합 — 유지보수 단순화

## ⚪ Phase 10 — PDF 리포트 생성기

### 계획
1. `reportlab` 의존성 추가
2. `backend/app/features/langgraph_threat_hunter/pdf_report.py` 신설
3. 엔드포인트: `GET /api/lg/simulate/{scenario_id}/report.pdf`
4. PDF 내용: 시나리오 제목 + Before/After + 6 에이전트 산출물 + FW 규칙 + 헌팅 쿼리 + Executive Summary
5. 프론트 자료실의 PDF 링크 동작 검증

## ⚪ Phase 11 — ARCHITECTURE.md 정식 다이어그램

### 계획
- 옛 osint_profiler 잔재 제거
- Mermaid 다이어그램 3 종:
  1. 6-Agent + Orchestrator + 동적 라우팅
  2. MCP Tool Mesh
  3. 3-패널 UI ↔ SSE ↔ LangGraph 흐름
- 각 에이전트의 코드 위치 / 입출력 / 도구 명시

## ⚪ Phase 12 — docker compose 실 기동 + 데모 검증

### 계획
1. `docker compose -f docker-compose.yaml -f docker-compose.prod.yaml up --build -d`
2. 헬스체크 4종 확인 (postgres / redis / backend / frontend)
3. curl 검증:
   - `GET /api/lg/health`
   - `GET /api/lg/scenarios`
   - `POST /api/lg/chat/stream` (S1)
4. 브라우저 `http://localhost:4000/threat-hunter` 접속 → S1 카드 클릭 → 챗 + 에이전트 파이프라인 + 산출물 실시간 표시 확인
5. 스크린샷 / GIF 캡처

---

## 🧭 의사결정 기록 (누적)

| 일자 | 결정 | 근거 |
|---|---|---|
| 2026-05-23 | Path B (Full LangGraph) 채택 | 산업 표준, 토큰 18% 절감, audit trail 자연 표현 |
| 2026-05-23 | LangGraph 0.2.x 라인 핀 | 1.x 는 langchain-core 1.x 강제 → 기존 스택 충돌 |
| 2026-05-23 | Simulation Mode 우선 | API 키 없이 BOB 면접/금융권 PoC 시연 가능 |
| 2026-05-23 | DB SQLite → PostgreSQL 16 | LangGraph PostgresSaver/JSONB/pgvector 친화 |
| 2026-05-23 | sLLM "PoC 옵션"으로 톤다운 | 실 구동 안 됨을 정직히 표기 |
| 2026-05-23 | Orchestrator agent 추가 (5→6) | 진짜 hierarchical 멀티에이전트 — 동적 라우팅 |
| 2026-05-23 | NotebookLM 3-패널 UI 채택 | 채팅(자연어) vs Agent Studio(기술 산출물) 분리 |
| 2026-05-23 | SSE 스트리밍 + pace 파라미터 | 노드별 진행 실시간 시각화 — 시연 임팩트 |
| 2026-05-23 | CrewAI 모듈 legacy 이동 | 도메인 분리 (LangGraph 가 동일 기능 커버) |

---

## 📚 레퍼런스

- [taylorwalton/talon](https://github.com/taylorwalton/talon) — Anonymizing MCP proxy
- [zhadyz/AI_SOC](https://github.com/zhadyz/AI_SOC) — L0~L4 신뢰도 게이팅
- [FunnyWolf/agentic-soc-platform](https://github.com/FunnyWolf/agentic-soc-platform) — SIEM 통합
- [beenuar/AiSOC](https://github.com/beenuar/AiSOC) — Investigation Ledger, MITRE ATT&CK
- [BurtTheCoder/mcp-dnstwist](https://github.com/BurtTheCoder/mcp-dnstwist)
- [ADEOSec/mcp-shodan](https://github.com/ADEOSec/mcp-shodan)
- [mukul975/cve-mcp-server](https://github.com/mukul975/cve-mcp-server)
- [langchain-ai/langchain-mcp-adapters](https://github.com/langchain-ai/langchain-mcp-adapters)
