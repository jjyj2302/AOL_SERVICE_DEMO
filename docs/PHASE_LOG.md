# Phase Log — 금융권 네트워크 보안 AX 전환

> 본 프로젝트의 **금융권 네트워크 보안 AX (AI Transformation)** 전환 진행 기록.
> 각 Phase별로 (1) **무엇을 했는지**, (2) **무엇이 개선됐는지**, (3) **남은 작업**을 누적 기록한다.
> Notion에 그대로 붙여넣을 수 있는 마크다운 형식.

---

## 📌 전체 로드맵

| Phase | 주제 | 상태 | 기간 |
|---|---|---|---|
| **Phase 1** | 기반 정비 — README/문서 리포지셔닝 | ✅ 완료 | 2026-05-23 |
| **Phase 2** | LangGraph StateGraph 신규 모듈 신설 | ✅ 완료 | 2026-05-23 |
| **Phase 3** | MCP 5종 게이트웨이 추상화 | ✅ 완료 | 2026-05-23 |
| **Phase 4** | Simulation Mode — 5대 금융권 시나리오 | ✅ 완료 | 2026-05-23 |
| **Phase 5** | EC2 단일 인스턴스 배포 산출물 | ✅ 완료 | 2026-05-23 |
| **Phase 5.5** | DB 마이그레이션 — SQLite → PostgreSQL 16 | ✅ 완료 | 2026-05-23 |
| **Phase 6** | CI/CD 파이프라인 정리 | 🟡 진행중 | — |
| **Phase 7** | MCP 라이브 모드 wire-up + 프론트엔드 신규 패널 | ⚪ 대기 | — |

---

## ✅ Phase 1 — 기반 정비 (README/문서 리포지셔닝)

### 한 일
1. **타이틀·태그라인 전환** — OSINT 침해사고 → 금융권 SOC Tier-1 자동화 Multi-Agent CTI
2. **4단 AX 서사구조 도입** (Why → How → Impact → Deliverable)
3. **아키텍처 다이어그램 갱신** — CrewAI → **LangGraph + MCP Tool Mesh**
4. **L0~L4 Confidence-Gated Automation 표 추가** (망분리/금융권 안전성)
5. **Why 섹션** — 금융권 SecOps 7대 구조적 문제 정리
6. **Impact 정량 효과표** — 업무 시나리오 6종 + SOC KPI 종합
7. **5대 금융권 시뮬레이션 시나리오** 명세
8. **컴플라이언스 매핑** — 전자금융감독규정 §13/§15, FSI C-TAS, ISMS-P, DORA, MITRE ATT&CK
9. **경쟁사 비교표** (vs. 기존 SOAR / 단일 AI 도구)
10. **Agents × MCP Tool Mesh 매트릭스**
11. **LLM Abstraction Layer 섹션** — sLLM 은 PoC 단계 옵션임을 명시 (과대표기 방지)
12. **Tech Stack 배지 갱신** — CrewAI 제거, LangGraph/MCP/sLLM-Ready 추가

### 무엇이 개선됐나
| 항목 | Before | After |
|---|---|---|
| **타깃 시장** | 범용 침해사고 분석 | **금융권 SOC Tier-1 자동화** |
| **에이전트 프레임워크 (계획)** | CrewAI | **LangGraph (토큰 18% 절감)** |
| **도구 통합 방식** | 하드코딩 API 호출 | **MCP 표준 인터페이스** |
| **자동화 안전성** | 명시 없음 | **L0~L4 Confidence Gating** |
| **정량 가치 제안** | 정성적 | **시나리오 6종 + KPI 5종 정량화** (≥95% 시간 감축) |
| **컴플라이언스 서사** | 없음 | **전자금융감독규정·FSI·ISMS-P·DORA 매핑** |
| **데모 재현성** | 라이브 API 의존 | **Simulation Mode** (시드 데이터 동일 결과 재현) |
| **sLLM 표기** | 막연한 약속 | **PoC 옵션임을 명시, 데모는 OpenAI** |

### 커밋 기록
- `d97d132e` docs(readme): 금융권 네트워크 보안 AX 포지셔닝으로 전환
- `8cb8629a` docs(readme): Impact/Deliverables/Simulation/Compliance/비교 섹션 추가
- `f1c8e216` docs(phase-log): Notion 동기화용 Phase 진행 로그 신설
- `c3c18e67` docs(readme): Tech Stack/Features/Getting Started 금융권 톤 + LLM 추상화 명확화

---

## ✅ Phase 2 — LangGraph StateGraph 신규 모듈

### 한 일
- `backend/app/features/langgraph_threat_hunter/` 패키지 신설
- **`state.py`** — `ThreatHuntState` (Pydantic) IoC·진행단계·신뢰도·Audit Ledger·MCP 호출·산출물 전역 누적 상태
- **`confidence.py`** — L0~L4 등급 매핑 + 금융권 핵심 자산 휴먼 승인 강제 (코어뱅킹/임원PC/SWIFT 키워드)
- **`nodes.py`** — 5개 노드 (triage/malware/infrastructure/campaign/confidence_gate) delta dict 반환 패턴
- **`graph.py`** — StateGraph 빌더, 시뮬레이션 그래프는 모듈 로딩 시 싱글톤 컴파일
- **`router.py`** — 4종 FastAPI 엔드포인트 (`/api/lg/...`)
- `backend/main.py` 에 라우터 등록

### 무엇이 개선됐나
| 항목 | Before | After |
|---|---|---|
| 다중 에이전트 오케스트레이션 | CrewAI hierarchical (블랙박스) | **LangGraph StateGraph 명시적 상태 머신** |
| 노드별 실행 추적 | (없음) | **Audit Ledger 자동 기록** (node/elapsed_ms/tools_called) |
| 자동화 신뢰도 게이팅 | (없음) | **L0~L4 등급 + 핵심 자산 휴먼 승인** |
| 단위 테스트 가능성 | 어려움 (Crew 단위) | **노드 함수 단위로 단순 테스트 가능** |

### 커밋 기록
- `563d7837` docs(llm): ARCHITECTURE 옛 osint_profiler 기반임을 상단 안내
- `95a5d310` chore(api): langgraph 및 langchain-mcp-adapters 의존성 추가
- `abeacc85` feat(llm): LangGraph 위협 헌팅 state 스키마 및 신뢰도 게이팅 신설
- `ff9d4504` feat(llm): LangGraph StateGraph 노드 및 그래프 빌더 추가

---

## ✅ Phase 3 — MCP 5종 게이트웨이 추상화

### 한 일
- **`mcp_clients.py`** — `McpRegistry` 클래스 신설
- 5개 MCP 통합: VirusTotal · DNSTwist · Shodan · OSINT · CVE
- `simulation` / `live` 모드 분기 — simulation 은 시드 데이터, live 는 `langchain-mcp-adapters` (현재는 placeholder)
- **`McpCallRecord`** 자동 기록 — tool/input_key/elapsed_ms/cached/simulation 플래그

### 무엇이 개선됐나
| 항목 | Before | After |
|---|---|---|
| 외부 도구 호출 인터페이스 | 도구별로 다른 클라이언트 코드 | **MCP 표준 인터페이스 단일** |
| 호출 기록 추적 | (없음) | **모든 MCP 호출이 McpCallRecord 로 자동 기록** |
| 시연 재현성 | API 키 + 외부 호출 필요 | **simulation 모드로 100% 재현 가능** |

### 커밋 기록
- `9e6adbbb` feat(llm): MCP 도구 5종 게이트웨이 추상화 신설

---

## ✅ Phase 4 — Simulation Mode (5대 금융권 시나리오)

### 한 일
- **`simulations.py`** — 5개 시나리오 시드 데이터
  - **S1** 카카오뱅크 사칭 피싱 (DNSTwist + URLScan)
  - **S2** 보이스피싱 C2 인프라 클러스터링 (VT + Shodan)
  - **S3** 금융권 표적 랜섬웨어 IoC (4-Agent + VT + OSINT)
  - **S4** 사내 외부노출 자산 점검 (Shodan, 전자금융감독규정 §13)
  - **S5** 금융권 표적 CVE 우선순위화 (CVE-MCP EPSS/KEV/MITRE)
- `GET /api/lg/scenarios` / `POST /api/lg/simulate/{id}` 엔드포인트
- FastAPI TestClient 통합 테스트 5개 시나리오 모두 통과
- Before/After 측정 자동화 (`before_minutes` ↔ `actual_elapsed_ms`)

### 무엇이 개선됐나
| 시나리오 | Before (수동) | After (본 시스템) | 개선율 |
|---|---|---|---|
| S1 카카오뱅크 사칭 추적 | 30분 | <5초 | ≈99.7% ↓ |
| S2 보이스피싱 C2 클러스터링 | 180분 | <10초 | ≈99.9% ↓ |
| S3 랜섬웨어 심층 분석 | 120분 | <15초 | ≈99.8% ↓ |
| S4 외부노출 자산 점검 | 60분 | <10초 | ≈99.7% ↓ |
| S5 CVE 우선순위화 | 45분 | <5초 | ≈99.8% ↓ |

### 커밋 기록
- `5fbba4ac` feat(llm): 5대 금융권 시뮬레이션 시나리오 시드 데이터 추가
- `e9608053` feat(api): /api/lg 라우터 등록 및 시뮬레이션 엔드포인트 노출

---

## ✅ Phase 5 — EC2 단일 인스턴스 배포 산출물

### 한 일
- **`docker-compose.prod.yaml`** — base compose 의 production overlay
  - env_file 로 `/etc/aol/.env` 분리 (SSM 시크릿 주입 지점)
  - healthcheck 3종 (redis / backend / frontend)
  - 로그 로테이션 (json-file, 합산 ≤160MB)
  - backend 외부 포트 미노출 (expose only)
  - restart=always + 리소스 제한 (t3.large 80% 가용)
- **`deploy/ec2-userdata.sh`** — EC2 user-data 자동 부트스트랩
  - 멀티 OS 지원 (dnf / yum / apt)
  - SSM Parameter Store 에서 시크릿 안전 주입
  - Docker Compose v2 플러그인 자동 설치
  - 재실행 멱등 (`git reset --hard origin/...`)
- **`docs/DEPLOYMENT.md`** — IAM/SG/배포/운영/트러블슈팅/비용 추산 단일 가이드

### 커밋 기록
- `999dadd7` feat(deploy): EC2 단일 인스턴스 프로덕션 배포 산출물 추가

---

## ✅ Phase 5.5 — DB 마이그레이션 (SQLite → PostgreSQL 16)

### 한 일
- **`backend/app/core/database.py`** — `DATABASE_URL` 환경변수 우선, SQLite fallback
- **`backend/requirements.txt`** — `psycopg2-binary` 의존성 추가
- **`docker-compose.yaml`** — `postgres:16-alpine` 서비스 + 명명 볼륨 `postgres_data`
- **`docker-compose.prod.yaml`** — postgres healthcheck (`pg_isready`) + 리소스 제한 (1 vCPU / 2 GB) + log rotation
- **`deploy/ec2-userdata.sh`** — `/aol/postgres_password` SSM 시크릿 로딩 + 미등록 시 임시 24자 랜덤 패스워드 생성
- **`docs/DEPLOYMENT.md`** — 아키텍처 다이어그램에 postgres 추가, SSM/리소스 표 갱신, RDS 분리 + pgvector 로드맵

### 무엇이 개선됐나
| 항목 | Before (SQLite) | After (PostgreSQL 16) |
|---|---|---|
| 동시 쓰기 | 단일 라이터 락 | **다중 라이터 가능 — SOC 다중 분석가 동시 작업** |
| JSON 저장 | TEXT + json.dumps | **JSONB 네이티브 — MCP 호출 기록 인덱싱 가능** |
| LangGraph 체크포인터 | 별도 구현 필요 | **PostgresSaver 네이티브 지원** |
| 벡터 검색 (RAG) | 미지원 | **pgvector 확장 활성화 가능** |
| HA / 백업 | 수동 파일 복사 | **AWS RDS 분리 → 자동 백업/스냅샷** |
| 산업 표준 정합성 | 데모 수준 | **AiSOC / OpenCTI 등 산업 표준 일치** |

### 커밋 기록
- `e1122bcf` feat(db): SQLAlchemy 엔진 PostgreSQL 우선 + SQLite fallback
- `693e7ba9` chore(api): psycopg2-binary 의존성 추가
- `becd180b` feat(infra): docker-compose 에 postgres 16-alpine 서비스 추가
- `1a164e03` feat(infra): postgres 프로덕션 오버레이 healthcheck 및 리소스 제한
- `f43cb067` feat(infra): EC2 user-data postgres 시크릿 주입 및 DATABASE_URL 생성
- `d8d7fe7b` docs(infra): DEPLOYMENT 가이드 PostgreSQL 섹션 보강

---

## 🟡 Phase 6 — CI/CD 파이프라인 정리 (진행중)

### 계획
- 기존 `.github/workflows/` 점검 → LangGraph 모듈/Docker 빌드/Compose 검증 추가
- Python 린트 (`ruff`/`mypy`) + 신규 모듈 import 검증 단계 추가
- ESLint 정리 점검
- docker-compose config 검증을 PR 워크플로에 추가

---

## ⚪ Phase 7 — MCP 라이브 모드 + 프론트엔드 신규 패널 (대기)

### 계획
- `langchain-mcp-adapters` 의 `MultiServerMCPClient` 로 실 MCP 서버 wire-up
- 프론트엔드 사이드바 **🎬 Simulation** 메뉴 + DNSTwist 타이포스쿼트 테이블 + Shodan 노출 자산 카드 추가

---

## 🧭 의사결정 기록

| 일자 | 결정 | 근거 |
|---|---|---|
| 2026-05-23 | Path B (Full LangGraph 마이그레이션) 채택 | 금융권 AX 포트폴리오에서 산업 표준. 토큰 18% 절감 + Audit Ledger 자연 표현 |
| 2026-05-23 | Frontend 유지 + Simulation Mode 중심 | 의사결정자 설득에 UI 필수. 신규 풀스택 대신 기존 컴포넌트 재활용 |
| 2026-05-23 | MCP TOP 5 선정 (DNSTwist · Shodan · CVE · OSINT · VT) | DNSTwist=금융권 특화 사칭 도메인, CVE=컴플라이언스 직결, Shodan=노출자산 |
| 2026-05-23 | LangGraph 신규 모듈을 기존 CrewAI 와 병렬 신설 | 기존 CrewAI 코드 회귀 위험 없이 새 path 검증 가능 |
| 2026-05-23 | LangGraph 0.2.x 라인 핀 | 1.x 는 langchain-core 1.x 강제 → CrewAI 스택 충돌 |
| 2026-05-23 | Simulation Mode 우선 구현 | API 키 없이 데모/PoC 가능, BOB·면접에서 즉시 시연 가능 |
| 2026-05-23 | DB SQLite → PostgreSQL 16 | LangGraph PostgresSaver/JSONB/pgvector 친화, 다중 동시 분석 지원 |
| 2026-05-23 | sLLM "PoC 옵션"으로 톤다운 | 실 구동 안 됨을 명시 (과대 포장 방지) — BOB 면접 정직성 |
| 2026-05-23 | 커밋 ZETTY 컨벤션 strict + Co-Authored 제거 | 팀 일관성 + 사용자 요청 |

---

## 📚 레퍼런스

### 산업 참조 프로젝트
- [taylorwalton/talon](https://github.com/taylorwalton/talon) — Anonymizing MCP proxy, air-gapped Ollama
- [zhadyz/AI_SOC](https://github.com/zhadyz/AI_SOC) — L0~L4 신뢰도 게이팅
- [FunnyWolf/agentic-soc-platform](https://github.com/FunnyWolf/agentic-soc-platform) — Webhook+Redis Stream SIEM
- [beenuar/AiSOC](https://github.com/beenuar/AiSOC) — Investigation Ledger, MITRE ATT&CK, DORA/PCI-DSS

### MCP 후보군
- [BurtTheCoder/mcp-dnstwist](https://github.com/BurtTheCoder/mcp-dnstwist)
- [ADEOSec/mcp-shodan](https://github.com/ADEOSec/mcp-shodan)
- [mukul975/cve-mcp-server](https://github.com/mukul975/cve-mcp-server)
- [badchars/osint-mcp-server](https://github.com/badchars/osint-mcp-server)
- [langchain-ai/langchain-mcp-adapters](https://github.com/langchain-ai/langchain-mcp-adapters)
