# Phase Log — 금융권 네트워크 보안 AX 전환

> 본 프로젝트의 **금융권 네트워크 보안 AX (AI Transformation)** 전환 진행 기록.
> 각 Phase별로 (1) **무엇을 했는지**, (2) **무엇이 개선됐는지**, (3) **남은 작업**을 누적 기록한다.
> Notion에 그대로 붙여넣을 수 있는 마크다운 형식.

---

## 📌 전체 로드맵

| Phase | 주제 | 상태 | 기간 |
|---|---|---|---|
| **Phase 1** | 기반 정비 — README/문서 리포지셔닝 | 🟡 진행중 | 1~2일 |
| **Phase 2** | LangGraph 풀 마이그레이션 | ⚪ 대기 | 2~3일 |
| **Phase 3** | MCP 통합 (DNSTwist · Shodan · CVE · OSINT · VT) | ⚪ 대기 | 2일 |
| **Phase 4** | Simulation Mode (5대 금융권 시나리오) | ⚪ 대기 | 1.5~2일 |
| **Phase 5** | 산출물 생성기 + EC2 배포 | ⚪ 대기 | 1.5~2일 |

---

## ✅ Phase 1 — 기반 정비 (README/문서 리포지셔닝)

**기간**: 2026-05-23 ~

### 한 일

#### 📝 README 전면 리포지셔닝
1. **타이틀·태그라인 전환**
   - Before: `OSINT & LLM 기반 침해사고 프로파일링 자동화 시스템`
   - After: `금융권 네트워크 위협 인텔리전스 AX — Multi-Agent 기반 SOC 자동화 플랫폼`
2. **4단 AX 서사구조 도입** (Why → How → Impact → Deliverable)
3. **아키텍처 다이어그램 갱신**: CrewAI → **LangGraph + MCP Tool Mesh**
4. **L0~L4 Confidence-Gated Automation 표 추가** (망분리/금융권 안전성)
5. **금융권 SecOps 7대 구조적 문제** Why 섹션으로 정리 (번아웃, 알람피로, MTTR 등)
6. **Impact 정량 효과표** 추가 — 업무 시나리오 6종 + SOC KPI 종합
7. **5대 금융권 시뮬레이션 시나리오** 명세 추가 (Simulation Mode)
8. **컴플라이언스 매핑 테이블** 추가 (전자금융감독규정 §13/§15, FSI C-TAS, ISMS-P, DORA, MITRE ATT&CK)
9. **경쟁사 비교표** 추가 (vs. 기존 SOAR / 단일 AI 도구)
10. **Agents × MCP Tool Mesh 매트릭스** — 각 에이전트가 어떤 MCP를 호출하는지 매핑

### 무엇이 개선됐나 (Before / After)

| 항목 | Before | After |
|---|---|---|
| **타깃 시장** | 범용 침해사고 분석 | **금융권 SOC Tier-1 자동화** |
| **에이전트 프레임워크 (계획)** | CrewAI | **LangGraph (토큰 18% 절감)** |
| **도구 통합 방식** | 하드코딩된 API 호출 | **MCP 표준 인터페이스** (확장 무한대) |
| **자동화 안전성** | 명시 없음 | **L0~L4 Confidence Gating** 명시 |
| **정량 가치 제안** | 정성적 설명 | **시나리오 6종 + KPI 5종 정량화** (99% 시간 감축) |
| **컴플라이언스 서사** | 없음 | **전자금융감독규정·FSI·ISMS-P·DORA 매핑** |
| **데모 재현성** | 라이브 API 의존 | **Simulation Mode** (시드 데이터로 동일 결과 재현) |

### 다음 단계 (Phase 1 잔여)
- [ ] Tech Stack 배지 갱신 (CrewAI → LangGraph + MCP)
- [ ] Detailed Features 섹션 4 모듈을 금융권 시나리오 톤으로 재서술
- [ ] Getting Started에 EC2 프로덕션 배포 path 추가
- [ ] ARCHITECTURE.md 정합성 수정 (현재 존재하지 않는 모듈 묘사)

### 커밋 기록
- `d97d132e` — `docs(readme): 금융권 네트워크 보안 AX 포지셔닝으로 전환`
- `8cb8629a` — `docs(readme): Impact/Deliverables/Simulation/Compliance/비교 섹션 추가`

---

## ⚪ Phase 2 — LangGraph 풀 마이그레이션 (예정)

**예상 기간**: 2~3일

### 계획
1. `langgraph` + `langchain-mcp-adapters` 의존성 추가
2. `deep_analysis/crew.py` → `LangGraph StateGraph` 변환
   - Nodes: triage / malware / infrastructure / campaign + L0~L4 confidence gate
   - State: `InvestigationState` (Pydantic, 누적 컨텍스트)
3. `bulk_analysis_async/crew.py`, `crew_solo/crew.py` 동일 패턴 적용
4. `Investigation Ledger` 테이블 신설 (audit trail)
5. 기존 SSE 스트리밍 호환성 유지

### 기대 개선
- 토큰 사용량 **−18%**
- 명시적 state graph → audit trail 자연스럽게 표현
- LangSmith 디버깅 가능
- 휴먼-인-더-루프 (interrupt) 네이티브 지원

---

## ⚪ Phase 3 — MCP 통합 (예정)

**예상 기간**: 2일

### 통합 MCP TOP 5

| # | MCP | 금융권 적용 |
|---|---|---|
| 1 | **DNSTwist MCP** | 가짜 은행/카드사 도메인 자동 탐지 |
| 2 | **Shodan MCP** | 금융사 외부 노출 자산 모니터링 |
| 3 | **CVE MCP** (EPSS/KEV/MITRE) | 패치 우선순위화 (전자금융감독규정 §13) |
| 4 | **OSINT MCP** (Censys/BGP/Wayback) | 공격자 인프라 심층 추적 |
| 5 | **VirusTotal MCP** | 평판 분석 (기존 도구 대체) |

### 통합 방식
- `langchain-mcp-adapters` 통한 LangChain 호환 도구 변환
- MCP 서버는 docker-compose에 사이드카로 추가
- 시뮬레이션 모드에서는 시드 응답 사용 (API 키 없이 데모 가능)

---

## ⚪ Phase 4 — Simulation Mode (예정)

**예상 기간**: 1.5~2일

### 5대 시나리오 시드 데이터
- `backend/data/simulations/s1_kakaobank_phishing.json`
- `backend/data/simulations/s2_voicephishing_c2.json`
- `backend/data/simulations/s3_ransomware.json`
- `backend/data/simulations/s4_exposed_assets.json`
- `backend/data/simulations/s5_cve_prioritization.json`

### 신규 엔드포인트
- `GET /api/simulate/scenarios` — 시나리오 목록
- `POST /api/simulate/{scenario_id}` — 시나리오 실행 (Before/After 타임스탬프 자동 기록)

### 프론트엔드 신규 패널 (기존 컴포넌트 재활용)
- 사이드바: **🎬 Simulation** 메뉴 추가
- DNSTwist 타이포스쿼트 결과 테이블
- Shodan 노출 자산 카드

---

## ⚪ Phase 5 — 산출물 생성기 + EC2 배포 (예정)

**예상 기간**: 1.5~2일

### 산출물 생성기
- PDF 리포트 (Jinja2 + WeasyPrint)
- 방화벽 규칙 export (FW 벤더 형식)
- SIEM 헌팅 쿼리 export (Splunk SPL / Elastic KQL / Sigma)

### 배포 산출물
- `docker-compose.prod.yaml` — 프로덕션 오버레이 (env_file, healthcheck, log rotation, no dev ports)
- `deploy/ec2-userdata.sh` — EC2 user-data로 자동 부트스트랩 (Docker 설치 + SSM Parameter Store 시크릿 + compose up)
- EC2 t3.large 단일 인스턴스에 실배포 + smoke test

---

## 🧭 의사결정 기록

| 일자 | 결정사항 | 근거 |
|---|---|---|
| 2026-05-23 | **Path B (Full LangGraph 마이그레이션) 채택** | 금융권 AX 포트폴리오에서 LangGraph가 산업 표준 (AiSOC/Talon 등). 토큰 18% 절감 + Audit Ledger 자연 표현 |
| 2026-05-23 | **Frontend 유지 + Simulation Mode 중심** | 의사결정자 설득을 위해 UI 필수. 신규 풀스택 대신 기존 컴포넌트 재활용 + 1~2개 패널 추가 |
| 2026-05-23 | **MCP TOP 5 선정** | DNSTwist는 금융권 특화(가짜 은행 도메인), Shodan은 노출 자산, CVE-MCP는 컴플라이언스 직결 |

---

## 📚 레퍼런스

분석한 유사 프로젝트:
- [taylorwalton/talon](https://github.com/taylorwalton/talon) — Anonymizing MCP proxy, air-gapped Ollama
- [zhadyz/AI_SOC](https://github.com/zhadyz/AI_SOC) — Confidence-gated automation L0~L4
- [FunnyWolf/agentic-soc-platform](https://github.com/FunnyWolf/agentic-soc-platform) — Webhook+Redis Stream SIEM 통합
- [beenuar/AiSOC](https://github.com/beenuar/AiSOC) — Investigation Ledger, MITRE ATT&CK 정렬, DORA/PCI-DSS

활용 MCP:
- [BurtTheCoder/mcp-dnstwist](https://github.com/BurtTheCoder/mcp-dnstwist)
- [ADEOSec/mcp-shodan](https://github.com/ADEOSec/mcp-shodan)
- [mukul975/cve-mcp-server](https://github.com/mukul975/cve-mcp-server)
- [badchars/osint-mcp-server](https://github.com/badchars/osint-mcp-server)
- [langchain-ai/langchain-mcp-adapters](https://github.com/langchain-ai/langchain-mcp-adapters)
