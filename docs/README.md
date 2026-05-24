# 📚 AOL Threat Hunter — Documentation Index

본 시스템의 모든 기술 문서를 기능별로 정리.
처음이라면 루트의 [`README.md`](../README.md) 의 30초 요약 + Live Demo 부터 보세요.

---

## 🏗️ Architecture (시스템 구조)

| 문서 | 내용 |
|---|---|
| [`architecture/README.md`](architecture/README.md) | **시스템 전체 아키텍처** — 인프라 토폴로지, 외부 의존성, 컴포넌트 책임 |
| [`architecture/langgraph.md`](architecture/langgraph.md) | **LangGraph StateGraph 상세** — State 스키마, 조건부 라우팅, Delta 패턴 |
| [`architecture/agents.md`](architecture/agents.md) | **6 Agent 상세** — Orchestrator / Triage / Malware / Infrastructure / Campaign / Confidence Gate |
| [`architecture/mcp.md`](architecture/mcp.md) | **MCP Tool Mesh** — Why MCP, 5종 도구 wire-up 방식 |

---

## 💰 Cost (비용 분석)

| 문서 | 내용 |
|---|---|
| [`cost/README.md`](cost/README.md) | **LLM 차등 적용 비용 분석** — Anthropic 실측 59.1%↓ vs Sonnet (현실 baseline) / 91.8%↓ vs Opus (naive), 모델 매핑, 월간 절감액 |

---

## 🏦 Compliance (컴플라이언스 매핑)

| 문서 | 내용 |
|---|---|
| [`compliance/README.md`](compliance/README.md) | **한국 금융권 컴플라이언스** — 전자금융감독규정 §13/§15, ISMS-P, FSI C-TAS, DORA 매핑 |

---

## 🚀 Deployment (배포)

| 문서 | 내용 |
|---|---|
| [`deployment/README.md`](deployment/README.md) | **EC2 단일 인스턴스 배포** — IAM/SG/SSM 시크릿, docker-compose.prod, user-data 부트스트랩 |

---

## 🧪 Scenarios (시나리오·검증)

| 문서 | 내용 |
|---|---|
| [`scenarios/test-questions.md`](scenarios/test-questions.md) | **시연 질문지** — 2026 한국 금융권 보안 핫토픽 기반 입력 케이스 |
| [`scenarios/real-incidents.md`](scenarios/real-incidents.md) | **실 침해사고 검증** — SKT 2696만/쿠팡 3370만/YES24 100억/롯데카드 297만/KT vs 본 시스템 |

---

## 🛠️ Operations (운영·진행)

| 문서 | 내용 |
|---|---|
| [`operations/phase-log.md`](operations/phase-log.md) | **Phase 진행 기록** — 14+ Phase 의 무엇/왜/언제 (Notion 동기화) |
| [`operations/troubleshooting.md`](operations/troubleshooting.md) | **이슈 해결 모음** — 17건의 증상-원인-해결 + 재발 방지 체크리스트 |

---

## 📸 Screenshots

| 파일 | 설명 |
|---|---|
| [`screenshots/01-threat-hunter-empty.png`](screenshots/01-threat-hunter-empty.png) | 빈 상태 — 3-패널 레이아웃 + 자료실 5 시나리오 |
| [`screenshots/02-threat-hunter-cleaned-sidebar.png`](screenshots/02-threat-hunter-cleaned-sidebar.png) | 사이드바 정리 시도 (이후 복원됨) |
| [`screenshots/03-threat-hunter-after-live.png`](screenshots/03-threat-hunter-after-live.png) | 라이브 LLM 모드 실 기동 확인 |
| [`screenshots/04-threat-hunter-current.png`](screenshots/04-threat-hunter-current.png) | 최신 — 사이드바 8 탭 + 3-패널 |

---

## 📂 산출물 파일 위치

```
backend/app/features/langgraph_threat_hunter/
├── state.py            ThreatHuntState + Annotated reducers
├── confidence.py       L0~L4 게이팅 + 핵심 자산 키워드
├── mcp_clients.py      McpRegistry — 5 도구 실 wire-up (Phase 16)
├── simulations.py      5 시나리오 시드 + chat_message
├── nodes.py            Orchestrator + 4 Specialist + Gate (live + sim)
├── graph.py            StateGraph + 조건부 엣지
├── agent_prompts.py    에이전트별 시스템 프롬프트 + 모델 매핑 (Phase 17)
├── conversation.py     Claude 자유 대화 + Tool Use 멀티에이전트 (Phase 14)
├── pdf_report.py       reportlab PDF 리포트
├── cost_analysis.py    모델 매핑 + 가격표 + 3 전략 계산
├── legacy_wrappers.py  옛 CrewAI 페이지 LangGraph wrapper (Phase 15)
└── router.py           /api/lg/* + /api/crew-solo/* + /api/threat-hunter/*

backend/tests/                   51 pytest / 0.5초 / 100% 통과
benchmarks/run_model_comparison.py   Anthropic API 실측 ($0.57)

frontend/src/components/threat-hunter/
├── ThreatHunterPage.jsx        3-패널 메인 + SSE 파싱 + Tool Use 핸들러
├── SourcesPanel.jsx            좌측 자료실
├── ChatPanel.jsx               가운데 대화 (user/assistant 버블)
├── ResultsSidebar.jsx          우측 Agent Studio (메트릭+산출물)
├── AgentPipelinePanel.jsx      6-Agent 실시간 진행 바
└── CostAnalysisCard.jsx        3 전략 비용 카드
```
