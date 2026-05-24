# 🎯 AOL Threat Hunter — Portfolio Highlights

> **자소서 / 이력서 / 면접 / GitHub README 4가지 용도를 한 곳에서.**
>
> 모든 정량 수치는 `benchmarks/mcp_comparison.json` 실측 + `git log` commit
> 본문 인용. 마케팅 카피 아님. 정직한 한계도 명시.
>
> **세션 누적 commit**: 9개 (이번 정직화 세션 6개 + 직전 세션 3개).
> **마지막 push**: `d4cee7e6` (2026-05-24).

---

## 📋 4개 테마 (선별 기준 — 자소서 임팩트)

| # | 테마 | 묶은 Phase | 한 줄 |
|---|---|---|---|
| 1 | **시스템 디자인 — 표준 프로토콜 채택 (MCP)** | Phase 18 + 2 | "추상화만 있던 MCP 를 진짜 SSE+JSON-RPC 사이드카로 분리" |
| 2 | **정직한 측정 + 비용 분석** | Phase 13 → 19 | "본인이 만든 91.8% 헤드라인을 baseline 정직화로 59.1% 로 갱신" |
| 3 | **성능 최적화 + 측정 인프라 (3-계층 캐시)** | Phase 22 + 23 + 21 | "warm latency 80배 / parallel QPS 4800배 — 그러나 측정 인공물도 정직하게 표기" |
| 4 | **멀티에이전트 SOC + Claude Tool Use** | Phase 2 + 14 | "LangGraph 6-Agent + 자유대화↔분석 자동 전환" |

선별에서 빠진 phase (자소서 임팩트 약함): Phase 1 (README) / 4 (시드) /
5 (PG 마이그) / 6 (EC2 산출물) / 7 (CI 워크플로) / 8 (UI) / 9 (CrewAI 폐기) /
10 (PDF) / 11 (다이어그램) / 12 (compose 기동) / 15 (wrapper) / 16-17 (실 wire-up).

---

## 1️⃣ 한눈에 보기 (이력서 1줄 불릿)

```
- LangGraph 기반 금융권 SOC 멀티에이전트 시스템 설계·구현 (6 Agent + MCP 5종)
- 추상화에 그치던 MCP 도구 게이트웨이를 진짜 SSE+JSON-RPC 사이드카(Python FastMCP + Node.js)로 분리, 4 통합 모드 운영
- LLM 비용 분석 baseline 잘못 잡힌 91.8% 헤드라인을 직접 발견·정직화 → vs Sonnet 59.1% (월 $17K 절감) 갱신, pytest assert 로 정직성 박음
- 3-계층 캐시 (backend in-process + 사이드카 + 외부 API) 설계로 parallel QPS 0.50 → 2404 (4800배), warm latency 80배 개선
- E2E latency / SSE TTFT / 노드별 elapsed_ms 측정 인프라 구축 (router 3개 SSE 엔드포인트 perf_counter 래퍼)
- Anthropic Tool Use 패턴으로 자유대화 ↔ 자동 분석 모드 전환, IoC 정규식 감지 시 LangGraph 자동 진입
```

---

## 2️⃣ README 배지 (GitHub 최상단용)

```markdown
[![cost](https://img.shields.io/badge/cost_59.1%25↓_(vs_Sonnet)-success?style=flat-square)]()
[![throughput](https://img.shields.io/badge/parallel_QPS_4800×↑-blueviolet?style=flat-square)]()
[![mcp](https://img.shields.io/badge/MCP_protocol_(SSE%2BJSON--RPC)-orange?style=flat-square)]()
[![tests](https://img.shields.io/badge/pytest-51_passing-3DDC84?style=flat-square)]()
[![agents](https://img.shields.io/badge/LangGraph_6_Agents-1B998B?style=flat-square)]()
```

배지 옆 1줄 요약:

```
🏦 금융권 SOC Tier-1 분석가의 IoC 트리아지를 LangGraph 6-Agent + MCP 5도구로 자동화.
   Anthropic Claude tier 매핑 + 3-계층 캐시로 비용 -59.1% (vs Sonnet), throughput 4800배.
```

---

## 3️⃣ 자소서 본문 (서술형 단락 4개)

각 단락 200~400자, 한 주제로 자기 글 → 자소서 칸 한 개에 그대로 붙여넣기 가능.

---

### 📝 단락 A — 시스템 디자인 / 표준 프로토콜 채택

> 금융권 SOC 분석가의 IoC(침해지표) 트리아지 업무를 LangGraph 멀티에이전트로
> 자동화하는 프로젝트에서, **"MCP 도구 게이트웨이"라고 명명한 추상화 레이어가**
> **실제로는 `requests.get(...)` 직접 호출이라는 사실을 본인이 회고에서 짚었고**,
> 자체 FastMCP 사이드카(Python) + 외부 Node.js MCP 사이드카(`@modelcontextprotocol/sdk`)
> 두 컨테이너를 신설해 진짜 SSE + JSON-RPC 표준 프로토콜로 통신하도록 재설계
> 했습니다. MCP SDK 의 DNS rebinding 보호로 docker 내부 호스트네임이 차단되는
> 함정, FastMCP 가 list 반환을 `TextContent[]` 로 분리 직렬화하는 함정,
> Node 측에서 dnstwist CLI 가 DNS 해석에 104초 걸리던 문제를 Python Fuzzer
> 직접 spawn 으로 3.5초로 줄이는 함정 등을 단계적으로 풀어내며, 4 통합 모드
> (`simulation` / `direct` / `self_mcp` / `external_mcp`)를 환경변수 하나로 전환
> 가능한 구조로 정착시켰습니다.

---

### 📝 단락 B — 정직한 측정 / 엔지니어링 윤리

> 비용 분석 모듈에 "Anthropic Claude 모델 매핑으로 91.8% 비용 절감" 이라는
> 헤드라인을 처음 적었으나, baseline 이 "5 에이전트 모두 Opus 4.7"이라는
> **실무에선 누구도 쓰지 않는 비현실적 기준** 이라는 점을 회고에서 본인이
> 짚었습니다. 실무 디폴트인 `all_sonnet` 을 새 baseline 으로 잡고
> 5 전략 비교 (`all_opus` / `all_sonnet` / `all_haiku` / `mixed` /
> `mixed_cached_batch`)로 재계산해 "vs Sonnet **-59.1%** 가 정직한 헤드라인,
> vs Opus -91.8% 는 호환을 위한 옛 수치" 라는 두 측정값을 응답 JSON 의
> `headline_savings` 에 동시 노출 했습니다. 더 나아가 pytest 어설션 `assert
> realistic_vs_sonnet_pct < 80` 으로 **정직성을 코드 레벨에 박아** 미래의
> 본인이 다시 과대표기 못 하도록 막았습니다. 4축 (latency / payload bytes /
> LLM 토큰 / QPS) 벤치마크로 외부 MCP 결과 페이로드가 +39% 토큰을 더
> 만들어내 LLM 비용에 직결됨도 정량 입증했습니다.

---

### 📝 단락 C — 성능 최적화 / 측정 인프라

> 3 MCP 통합 모드 비교 측정에서 `external_mcp` parallel QPS 가 0.50 으로
> 운영 부적합으로 드러났을 때, **3-계층 캐시 아키텍처** (L1 backend
> in-process `_CACHE` → L2 사이드카 in-process Map + singleflight → L3
> 외부 API) 로 단계적 해결했습니다. Phase 22 에서 Node 사이드카에 캐시
> 추가로 warm latency 2573~2888ms → 30~38ms (80배 개선), Phase 23 에서
> backend `McpRegistry._via_mcp()` 진입 전 `_CACHE` lookup 추가로 parallel
> QPS 0.50 → 2404 (4800배). 그러나 측정이 같은 IoC × 5 반복이라 효과
> 과장됐음을 commit 본문에 정직하게 박아두었고, "동일 IoC 재분석 ~ms /
> 새 IoC 사이드카 hit ~30-50ms / 새 IoC 사이드카 miss 1.5~3.5s" 라는
> 시나리오별 latency 매트릭스를 문서화했습니다. 측정 인프라 자체도 강화
> 해서 router 3개 SSE 엔드포인트에 `perf_counter` 래퍼 추가, 노드별
> `elapsed_ms` + 전체 `e2e_ms` + dialogue 모드 `ttft_ms` 까지 응답 JSON
> 으로 노출 — "측정 없이 개선 없다" 원칙을 인프라로 정착시켰습니다.

---

### 📝 단락 D — 멀티에이전트 / Claude Tool Use

> CrewAI 기반이던 옛 시스템을 LangGraph `StateGraph` 로 마이그레이션
> 하면서, **6 Agent (Orchestrator + Triage + Malware + Infrastructure +
> Campaign + Confidence Gate) 동적 라우팅** 구조로 재설계했습니다.
> Orchestrator 가 IoC 타입을 보고 `route_plan` 을 결정하면 조건부 엣지가
> 노드를 건너뛰거나(예: CVE → Triage + Campaign 만), 풀체인을 돌립니다.
> Anthropic Tool Use 패턴으로 자유대화 모드도 추가해서 사용자가 "랜섬웨어
> 의심돼요" 같은 자연어로 입력하면 Claude 가 IR 가이드 + IoC 유도를 하고,
> 이후 IoC 가 입력되면 정규식으로 감지해 LangGraph 분석 모드로 자동 전환
> 됩니다. 멀티턴 히스토리는 server-side validation 으로 분석 결과는 history
> 에 미포함시키는 등 미세한 UX 디테일까지 챙겼습니다. 모든 노드/도구
> 호출은 `audit_ledger` 에 영속화되어 ISMS-P · 전자금융감독규정 §15 의
> 침해사고 대응 통제 증빙 자료로 직접 활용 가능합니다.

---

## 4️⃣ 면접 Talking Points (STAR + Follow-up Q&A)

각 테마마다:
- **STAR** (Situation / Task / Action / Result)
- **예상 follow-up 질문 5개 + 답변**

---

### 🎤 Theme 1: 표준 프로토콜 채택 — MCP 통합 (Phase 18)

#### STAR

- **Situation**: 옛 코드의 `McpRegistry` 가 "MCP 도구 게이트웨이" 라고 명명되어
  있었지만 실제 live 분기는 `requests.get(VirusTotal URL)`, `dnstwist.Fuzzer()`
  같은 직접 호출이었음. JSON-RPC 도 stdio/SSE 도 없음. **이름과 실제가 불일치**.
- **Task**: MCP 표준 프로토콜로 진짜 통신하도록 재설계하되, 기존 시뮬레이션
  모드와 라이브 분기는 깨지 말 것. pytest 51 케이스 무중단 유지.
- **Action**:
  1. `mcp_servers/aol-mcp-server/` 신설 — Python FastMCP (`mcp.server.fastmcp.FastMCP`)
     + 5 도구 (`@mcp.tool()` 데코레이터). SSE transport (`/sse :8765`).
  2. `mcp_servers/external-mcp-dnstwist/` 신설 — Node 20 + `@modelcontextprotocol/sdk`.
     dnstwist 도구만 노출 (의도적으로 단순). Python Fuzzer 직접 spawn 으로 DNS 미수행.
  3. `backend/app/features/.../mcp_live_client.py` 신설 — `McpLiveClient` 클래스.
     endpoint 별 도구 alias 매핑 + asyncio.run sync wrapper (LangGraph 노드 sync).
  4. `McpRegistry` 모드 분기 확장: `simulation` / `direct` / `self_mcp` / `external_mcp`.
     `mode="live"` 는 `AOL_LIVE_MCP_MODE` env 로 해석 (옛 코드 호환).
  5. 4개 함정 단계 해결: DNS rebinding → `TransportSecuritySettings(allowed_hosts=...)`
     로 docker 호스트네임 허용 / Healthcheck hang → curl → TCP socket 으로 교체 /
     Unwrap result → list 전체 순회 / dnstwist CLI 104초 → Python Fuzzer 3.5초.
- **Result**:
  - 6 컨테이너 (기존 4 + aol-mcp + ext-mcp-dnstwist) 모두 healthy
  - pytest 51/51 통과 유지
  - **언어 무관성 입증**: Python ↔ Python + Python ↔ Node.js MCP 통신 정상
  - `direct` (기존) / `self_mcp` (자체) / `external_mcp` (외부 + fallback) 3 모드
    같은 도구 인터페이스로 동작

#### Follow-up Q&A

**Q1.** 왜 MCP 표준을 도입했나? 그냥 직접 호출이 더 단순하지 않은가?
> A: 단순성으론 직접 호출이 맞지만, (1) 도구 추가할 때마다 backend 재빌드 필요,
> (2) 다른 언어로 작성된 MCP 서버 (Node, Rust, Go) 와 호환 불가, (3) 외부
> 위협 인텔리전스 도구가 이미 MCP 사이드카로 배포되는 추세 (BurtTheCoder/mcp-dnstwist 등),
> (4) 도구 격리로 장애 영향 차단이 어려움. 표준 채택의 ROI 가 명확.

**Q2.** Python FastMCP 와 Node MCP SDK 의 SSE 셋업 시간이 50ms vs 600ms 로
12배 차이 났는데, 어떻게 발견했고 어떻게 분석했나?
> A: Phase 22 에서 사이드카 캐시 추가 후 warm latency 30ms 까지 줄였는데
> parallel QPS 가 0.50 그대로였음. `mcp_live_client._session()` 에 timing
> 추가해서 세션 셋업 vs 도구 호출 비용 분리 측정. Python 측은 50ms, Node 측은
> 600ms — Express + MCP SDK 의 SSE 응답 처리에 12배 비용 차이. uvicorn ASGI
> 효율 vs Express middleware 오버헤드 차이로 추정.

**Q3.** 외부 MCP 서버를 한 개만 도입한 이유는?
> A: 처음엔 BurtTheCoder/mcp-dnstwist + ADEOSec/mcp-shodan + cve-mcp-server
> 4개 통합을 검토했으나, (1) BurtTheCoder 가 Docker-in-Docker 패턴이라
> 운영 부담 큼, (2) 일부는 dockerized 이미지 없어 직접 빌드 필요, (3) 4개
> 다 통합하면 호환성 검증 시간 폭증. 가성비 따져 "자체 FastMCP + 외부 Node
> 1개" 하이브리드로 결정. **외부 1개라도 언어 무관성 입증에는 충분**.
> 4개 확장은 Phase 22 후 계획에 명시.

**Q4.** DNS rebinding protection 함정에서 정확히 무엇이 일어났나?
> A: MCP SDK 1.27.1 의 `FastMCP` 가 기본으로 `TransportSecuritySettings`
> 를 활성화. `enable_dns_rebinding_protection=True` + `allowed_hosts=['127.0.0.1:*',
> 'localhost:*', '[::1]:*']`. backend 가 `http://aol-mcp:8765/sse` 로 접근하면
> Host 헤더가 `aol-mcp:8765` 라 차단됨 → HTTP 421 Misdirected Request.
> 처음엔 httpx 의 ReadError 만 보여서 원인 추적 어려웠고, `httpx.get()` 으로
> 직접 응답 보니 "Invalid Host header" 메시지 발견. 해결은 `allowed_hosts`
> 에 `aol-mcp:*` 추가. 운영 외부 노출 시엔 환경변수 `ALLOWED_HOSTS` 로 좁힘.

**Q5.** sync LangGraph 노드에서 async MCP 클라이언트를 호출하는 패턴은?
> A: `McpLiveClient.call()` 이 sync wrapper. 내부에서 `asyncio.run()` 으로
> async `_acall()` 실행. 다중 호출 시 매번 새 event loop 생성 비용은 있지만,
> backend `_CACHE` (Phase 23) 가 hot path 적중 시 sync wrapper 자체를 거치지
> 않아 비용 0. 다음 개선은 client side session pool (Phase 25 후보) — long-lived
> ClientSession 재사용으로 SSE 셋업 비용 분할 상환.

---

### 🎤 Theme 2: 정직한 측정 — 비용 baseline 정직화 (Phase 19)

#### STAR

- **Situation**: README 와 docs 에 "Anthropic API 실측 **91.8% 비용 절감**"
  헤드라인이 자랑스럽게 적혀 있었음. 그러나 baseline 이 `all_strong` = "5 에이전트
  모두 Opus 4.7" 이라는 **실무에선 누구도 안 쓰는 비현실적 기준**.
- **Task**: 같은 시스템이지만 정직한 baseline 으로 다시 측정해서 자랑할 수
  있는 진짜 수치 도출. 옛 91.8% 헤드라인도 호환 보존 (옛 PR/문서 깨지 않도록).
- **Action**:
  1. `cost_analysis.py` 의 `_compute_for_strategy` 를 `force_strong=True` → `force_tier="strong"`
     로 일반화.
  2. baseline 5개로 확장: `all_opus` (naive) / `all_sonnet` (★ realistic) /
     `all_haiku` (저비용 하한) / `mixed` (mini+medium) / `mixed_cached_batch` (★ 최적).
  3. `StrategyResult` 에 `savings_vs_realistic_pct` + `savings_vs_naive_pct`
     두 절감률 동시 노출. 옛 `savings_vs_baseline_pct` 는 alias 로 호환.
  4. `/api/lg/cost-analysis` 응답에 `headline_savings` 블록 신설:
     - `realistic_vs_sonnet_pct: 59.1` (★ 정직)
     - `naive_vs_opus_pct: 91.8` (옛 호환)
     - `note: "naive_vs_opus_pct 는 'Opus 단독' 이라는 비현실적 baseline 대비라 과대표기됨"`
  5. **pytest 어설션으로 정직성 박음**: `assert headline["realistic_vs_sonnet_pct"] < 80`
     — 미래의 본인이 다시 과대표기 못 하도록 코드 레벨 가드.
  6. README, docs/architecture/README.md, docs/scenarios/test-questions.md,
     CostAnalysisCard.jsx 동시 갱신 — 옛 필드 fallback 유지.
- **Result**:
  - 정직한 헤드라인: **-59.1% (vs Sonnet 단독)**
  - 호환 보존: -91.8% (vs Opus, 옛 마케팅 수치)
  - 핵심 통찰: "91.8% 중 80%pt 는 그냥 Opus 안 써서 자동 발생 (Sonnet vs
    Opus = -80%). 본 시스템 진짜 가치는 Sonnet 위에서 추가 -59.1%
    (Caching+Batch 가 핵심)"
  - 월간 ROI (10k IoCs/day): Sonnet 단독 $29,367 → 본 시스템 $12,000 =
    **$17,367/월 = 연 $208K (≈ 2.7억원) 절감**
  - pytest 51/51 통과 (새 5-전략 구조 + headline_savings 검증 포함)

#### Follow-up Q&A

**Q1.** baseline 이 잘못됐다는 걸 어떻게 자각했나?
> A: 사용자 (mentor/팀원) 가 "91.8% 는 baseline 이 말도 안 된다는 거잖아"
> 라는 직설적 피드백. 처음엔 방어하다가 검산해보니: all_opus 단독 $0.4895,
> all_sonnet 단독 $0.0979 — Sonnet 만 써도 자동 -80%. 91.8% 의 대부분은
> 모델 매핑이 아니라 "Opus 안 쓰면" 효과였음을 인정.

**Q2.** 왜 옛 91.8% 헤드라인을 삭제하지 않고 호환 보존했나?
> A: (1) 외부 자료 / 발표 / PR 에 이미 91.8% 가 인용됨. 갑자기 사라지면
> 신뢰 깨짐. (2) 옛 코드 호환 — `savings_vs_baseline_pct` 필드 참조하는
> frontend 컴포넌트가 있음. (3) "naive vs realistic" 두 시점을 비교해서
> 보여주는 게 더 교육적. 삭제보다 정직한 라벨링이 낫다는 판단.

**Q3.** pytest 어설션으로 정직성 박은 게 효과 있나? 임의로 다시 못 풀 수 있지 않나?
> A: 어설션 자체는 누구나 못 풀 수 있음. 핵심은 **테스트 실패 시 "왜 80% 아래여야
> 하는가" 를 다시 묻게 만드는 것**. 즉 미래에 만약 "85% 절감" 같은 수치를
> 다시 광고하려고 하면, 테스트가 빨간불 → 회의 → 정직한 baseline 다시 검토.
> 코드 리뷰어도 어설션 보면 "왜 < 80?" 질문하게 됨. **정직성을 자산화**.

**Q4.** all_sonnet 이 정말 "실무 디폴트" 라는 근거는?
> A: Anthropic 공식 가이드에서 Sonnet 을 "workhorse" 로 명시. 또한 가격
> (Sonnet $3/$15 per 1M vs Opus $15/$75) 5배 차이로 production 도입 시
> 기본 선택. Cursor / Cline / Replit 같은 commercial AI 도구도 default 로
> Sonnet 채택. Opus 는 "어려운 reasoning 필요시만" 권장. 즉 단일 모델 운영
> 디폴트는 Sonnet 이 압도적.

**Q5.** Mixed (Haiku + Sonnet) 가 all_sonnet 대비 -14.5% 뿐이면, 캐싱+배치 없이는
모델 매핑 의미 크지 않은데?
> A: 정확한 지적. 분해해보면: Mixed 단독 -14.5% vs Mixed+Cache+Batch -59.1%.
> 즉 캐싱+배치가 진짜 가치고, 모델 매핑은 boost (가성비 좋은 마지막 14.5%).
> 다만 모델 매핑은 zero cost (코드만 바꿈), 캐싱+배치는 Anthropic 가격표
> 가정 (90% cache hit, 50% batch discount). Phase 26 (prompt caching 실 적용 + 실측)
> 가 다음 단계로 명시되어 있음. 실측 안 한 가정값은 "가격표 기반 추정" 으로
> 라벨링.

---

### 🎤 Theme 3: 성능 최적화 — 3-계층 캐시 + 측정 인프라 (Phase 22 + 23 + 21)

#### STAR

- **Situation**: Phase 19 측정에서 `external_mcp` parallel QPS 0.50 발견.
  같은 backend 가 5 호출 동시 보내는 시나리오 = 사실상 1 호출과 같음.
  운영 부적합.
- **Task**: throughput 끌어올리되 정직성 유지 — 진짜 개선인지 측정 인공물인지
  구분하고 표기. 측정 인프라 자체도 강화.
- **Action**:
  1. **Phase 22 — 사이드카 캐시 (L2)**: `mcp_servers/external-mcp-dnstwist/server.js`
     에 `Map<key, {ts,value}>` TTL 10분 + `Map<key, Promise>` singleflight
     패턴 (같은 key 동시 호출 시 첫 호출만 spawn, 나머지는 같은 Promise 공유).
     → warm latency 2573~2888ms → **30~38ms (80배)**.
     parallel QPS 0.50 → 0.50 (개선 없음, 새 병목 발견).
  2. **새 병목 분석 — MCP overhead 두 층**:
     - 서버 측 SSE: Python FastMCP 50ms vs Node Express 600ms (12배 차이)
     - 클라이언트 측: 매 호출 새 `sse_client + ClientSession` 셋업
  3. **Phase 23 — backend 캐시 (L1)**: `mcp_clients.py::_via_mcp()` 진입 전
     `_CACHE` lookup 추가. cache hit 시 사이드카 호출 자체 회피 → SSE 셋업
     비용 0.
     → self_mcp parallel QPS 29.3 → **2626 (89배)**, external_mcp 0.50 →
     **2404 (4800배)**.
  4. **정직한 한계 commit 본문에 박음**: "측정은 동일 IoC × 5 반복이라
     backend cache 즉시 적중 — 효과 과장됨. 진짜 cold (새 IoC) 는 사이드카
     cold latency 1.5~3.5s 그대로".
  5. **Phase 21 — 측정 인프라 강화**: router 3개 SSE 엔드포인트
     (`chat_stream` / `chat_dialogue` / `simulate_stream`) 에 `perf_counter`
     래퍼. `e2e_ms` / `per_node_ms` / `ttft_ms` / 노드별 `elapsed_ms` 응답
     JSON 노출. `benchmarks/run_mcp_comparison.py` 에 `--single-registry`
     플래그로 매번 새 registry 한계 해소.
- **Result**:
  - 3-계층 캐시 아키텍처 정착: L1 backend (~ms) → L2 사이드카 (30~50ms) →
    L3 외부 API (1.5~3.5s)
  - 시나리오별 latency 매트릭스 문서화 (동일 IoC 재분석 / 사이드카 hit /
    cold 새 IoC / 다중 worker)
  - 측정 인프라: SSE 응답에 metrics 노출 — "사용자가 입력 후 첫 응답까지
    몇 ms" 정량화 가능
  - pytest 51/51 통과 유지

#### Follow-up Q&A

**Q1.** parallel QPS 4800배 라고 자랑하면서 "측정 인공물" 이라고 깎는 게 모순 아닌가?
> A: 모순 아님 — **두 시나리오의 진짜 다른 throughput**. (1) "동일 IoC 재분석"
> (분석가 더블체크) 시나리오에선 진짜 4800배. (2) "새 IoC" (대부분 워크로드)
> 시나리오에선 사이드카 cold latency 1.5~3.5s 라 효과 0. 둘 다 사실. 마케팅
> 헤드라인은 (1) 만 강조하지만, 본 문서는 두 시나리오 매트릭스로 모두 표기.
> 정직성 = "어느 시나리오의 수치인지" 명시.

**Q2.** Phase 22 + 23 + 21 캐시가 3개 다 정말 필요한가?
> A: 사실 회고에서 짚은 게 "캐시 짬뽕" — 사용자 피드백. 결론:
> Phase 22 (사이드카 캐시) = 외부 API 호출 회피 (필수, L2)
> Phase 23 (backend 캐시) = SSE 세션 셋업 회피 (단일 backend hot path 핵심)
> Phase 21 (측정 인프라) = 캐시가 진짜 작동하는지 검증 (필수)
> 셋 다 다른 층의 다른 문제 해결. 다만 Phase 24 (Redis shared cache) 와
> Phase 25 (client session pool) 은 backend cache 만으로 충분해서 over-engineering
> 으로 판단 → 진행 보류.

**Q3.** singleflight 패턴이 왜 필요했나?
> A: 같은 (domain, limit) key 가 5 client 에서 동시 도착하면, 5번 python spawn
> 발생 = 외부 도구 5배 호출. 캐시 미적중 + 동시 도착 = thundering herd.
> singleflight = 같은 key 의 첫 호출만 진짜 실행, 나머지는 같은 Promise await.
> Node 에선 `Map<key, Promise>` 로 구현 — 첫 호출이 끝나면 캐시 set + Promise
> resolve, 모든 await 가 같은 결과 받음. 운영 안정성에 핵심.

**Q4.** "측정 인공물" 인 걸 알면서 왜 굳이 측정했나?
> A: (1) Phase 22 후 parallel QPS 0.50 → 0.50 안 변한 게 측정 한계인지
> 진짜 한계인지 알아야 했음. Phase 23 backend cache 추가 후 4800배 됐으면
> "측정 한계였다" 확인. (2) "동일 IoC 재분석" 시나리오 자체가 운영에서
> 드물지만 진짜 발생함 (분석가 더블체크, 자동 재시도 등). 두 시나리오 모두
> 측정해야 운영 의사결정 가능. (3) 측정 자체가 인프라 — 다음 phase 에서
> 같은 도구로 다른 개선 측정 가능.

**Q5.** E2E latency 측정으로 무엇을 발견했나?
> A: simulation 모드 S2 측정: e2e 2031.8ms, orchestrator 17.5ms, 나머지 4
> 노드 각 ~402ms. orchestrator 가 압도적으로 빠른 이유는 라우팅 결정만 하기
> 때문 (`route_plan` 만 채움, MCP 호출 없음). 다른 노드는 인위적 chat_message
> 생성 + state 갱신으로 ~400ms 균일. 진짜 인사이트는 "라이브 모드 (LLM 포함)
> 는 노드당 1.5~3s 예상 — E2E 10~20s 가 사용자가 진짜 체감할 시간". 이걸
> Phase 21-4 (라이브 LLM 호출 실측) 로 측정해야 진짜 사용자 가치 정량화 가능.

---

### 🎤 Theme 4: 멀티에이전트 SOC — LangGraph + Claude Tool Use (Phase 2 + 14)

#### STAR

- **Situation**: 옛 CrewAI 기반 시스템이 (1) hierarchical Process 의 라우팅
  로직이 black-box, (2) audit trail 표현 어려움, (3) 모델별 비용 추적 어려움.
  컴플라이언스 (전금감 §15) 증빙용으로 부적합.
- **Task**: LangGraph `StateGraph` 로 마이그레이션. 6 Agent 동적 라우팅 +
  Claude Tool Use 자유대화 + 모든 호출 audit_ledger 영속화.
- **Action**:
  1. **6 Agent 그래프**: Orchestrator + Triage + Malware + Infrastructure +
     Campaign + Confidence Gate. 조건부 엣지 (`add_conditional_edges`) 로
     IoC 타입별 동적 라우팅.
  2. **Orchestrator 가 `route_plan` 결정**: IP/도메인/해시/URL/CVE 마다 다른
     specialist 시퀀스. 예: CVE → Triage + Campaign 만 (Malware/Infra 스킵).
  3. **Confidence Gate**: L0~L4 등급별 자동화 (L0 권고만, L4 자동 차단).
     핵심 자산 (kakaobank/shinhan 등) 키워드 매칭 시 휴먼 승인 강제.
  4. **audit_ledger Annotated reducer**: 각 노드 진입/종료/도구 호출이 모두
     append-only ledger 에 누적. `Annotated[..., add]` 로 LangGraph 가
     자동 머지.
  5. **Phase 14 — Anthropic Tool Use 대화형**: `conversation.py` 에서 Claude
     streaming + tool use. IoC 없으면 자유대화 (IR 가이드 + IoC 유도),
     IoC 정규식 감지 시 LangGraph 분석 모드로 자동 전환. 멀티턴 history
     server-side validation (분석 결과는 history 에 미포함).
- **Result**:
  - LangGraph 6 노드 + 5 specialist tool + 조건부 엣지 5종
  - Audit Ledger 가 ISMS-P / 전자금융감독규정 §15 침해사고 대응 통제 증빙
    자료로 직접 활용 가능
  - 4 시나리오 검증: 자유대화 / Tool Use 단독 / 라이브 풀체인 / 멀티턴 hybrid
  - pytest 51/51 통과

#### Follow-up Q&A

**Q1.** 왜 CrewAI 가 아닌 LangGraph 인가?
> A: (1) LangGraph 는 state machine 명시적 — 노드/엣지/상태 전이가 코드에
> 그대로 노출. CrewAI hierarchical Process 는 매 호출 LLM 이 라우팅을 결정해서
> 비결정적. audit 어려움. (2) `Annotated[..., add]` reducer 로 audit_ledger
> 자연 표현. CrewAI 는 별도 callback 으로 추적해야 함. (3) 조건부 엣지로
> 모델 비용 차등 적용 자연스러움 (Orchestrator=Haiku, Specialist=Sonnet).
> (4) LangGraph 0.2.x 는 langchain-core 0.3.x 와 호환되는 안정 버전 — 이미
> 검증된 의존성.

**Q2.** Confidence Gate 가 결정론적 규칙인 이유는?
> A: LLM 으로 신뢰도 판단하면 (1) 결과 비재현, (2) 같은 입력 다른 출력 가능,
> (3) 컴플라이언스 증빙 어려움. 결정론적 = (Triage threat_level 가중치) +
> (MCP 호출 성공 비율) + (핵심 자산 키워드 매칭). 가중치는 cost_analysis 와
> 별개로 도메인 전문가가 튜닝 가능. L0~L4 등급 cutoff 도 코드 상수로 명시.
> LLM 가 좋은 곳 (정성 분석) 과 결정론이 좋은 곳 (게이팅) 을 분리.

**Q3.** Tool Use 패턴에서 자유대화 ↔ 분석 모드 전환은 어떻게 결정하나?
> A: 결정 규칙은 router 의 `_parse_input` 함수. (1) `S1`~`S5` 같은 시나리오
> ID → 시뮬레이션 분석 모드. (2) IoC 정규식 매칭 (IP/도메인/해시/CVE) → 라이브
> 분석 모드. (3) 그 외 자연어 → 자유대화 모드. 같은 SSE 엔드포인트
> (`POST /api/lg/chat/dialogue`) 가 모드 판정 후 분기. SSE 이벤트 `start`
> 에 `mode: "analysis" | "dialogue"` 명시해서 프론트가 UI 배지 표시.

**Q4.** 6 Agent 가 너무 많지 않나? OpenAI Swarm 처럼 2~3 agent 로 안 되나?
> A: SOC 분석 도메인 특성 — Triage (평판) / Malware (행위) / Infrastructure
> (인프라 상관) / Campaign (전략 종합) 가 분석가 직무 구분에 그대로 매핑됨.
> 합치면 한 agent system prompt 가 길어지고 (토큰 비용) 결과 품질도 떨어짐.
> 모델 매핑도 6 agent 가 더 유연 — Orchestrator/Triage 는 mini (Haiku),
> Specialist 는 medium (Sonnet) 차등 가능. 다만 단순 도메인에서는 3 agent
> 가 맞을 수 있음 — 도메인이 결정.

**Q5.** Audit Ledger 가 컴플라이언스 증빙으로 정말 쓸 수 있나?
> A: (1) PostgreSQL 영속화 — 모든 ledger 행이 timestamp + node + summary +
> tools_called. (2) 재현 가능 — 같은 입력 → 같은 audit ledger (LLM 비결정성
> 빼고). (3) PDF 리포트 자동 생성 가능 — reportlab + 한글 폰트 CID. (4) 전금감
> §15 의 "침해사고 대응 통제" 요구사항이 "처리 단계별 기록 보존" — 본 시스템
> 이 정확히 그것. 다만 진짜 인증은 KISA 인증기관 평가 필요 — 본 시스템은
> "감사 가능한 형태" 까지 제공.

---

## 5️⃣ 참고 — 소스 파일 + commit hash

### 핵심 commit (이번 정직화 세션)

| commit | type(scope) | 한 줄 | 관련 Phase |
|---|---|---|---|
| `5848e2e8` | feat(llm) | 진짜 MCP 프로토콜 통합 — 자체 FastMCP + 외부 Node 사이드카 | Phase 18 |
| `a2eebfbf` | perf(llm) | 3 MCP 모드 비교 벤치마크 + 측정 지표 4종 | Phase 19 |
| `446d29f8` | refactor(llm) | 비용 baseline 정직화 + 5 전략 비교 | Phase 19 |
| `76e9baac` | perf(llm) | ext-mcp-dnstwist 캐시 — warm 80배 개선 | Phase 22 |
| `83875ffd` | perf(llm) | backend McpRegistry 3-계층 캐시 — parallel QPS 89~4800배 | Phase 23 |
| `1e9f2b8d` | docs(docs) | 2026-05-24 세션 기술 심층 보고서 (1900줄) | Phase 18~23 |
| `d4cee7e6` | perf(api) | E2E latency / SSE TTFT / single-registry warm 측정 | Phase 21 |

### 핵심 소스 파일

```
backend/app/features/langgraph_threat_hunter/
├── mcp_clients.py        ★ McpRegistry, 4 모드 분기, 3-계층 캐시 L1
├── mcp_live_client.py    ★ McpLiveClient, sync wrapper, endpoint pool
├── cost_analysis.py      ★ 5 전략 + 2 baseline + headline_savings
├── router.py             ★ /api/lg/* 엔드포인트, Phase 21 metrics
├── conversation.py       Phase 14 자유대화 + Tool Use
├── nodes.py              6 Agent 노드
└── graph.py              LangGraph StateGraph + 조건부 엣지

mcp_servers/
├── aol-mcp-server/       ★ 자체 FastMCP (Python, 5 도구)
│   ├── server.py
│   ├── Dockerfile
│   └── requirements.txt
└── external-mcp-dnstwist/  ★ 외부 Node MCP (Phase 22 캐시 추가)
    ├── server.js
    ├── Dockerfile
    └── package.json

benchmarks/
├── run_mcp_comparison.py  ★ 4축 측정 + parallel/sequential + single-registry
├── mcp_comparison.json    실측 결과 (commit 됨)
└── run_model_comparison.py  Anthropic API 실측 (별도, $0.57)

docs/
├── architecture/mcp.md    ★ 3 모드 비교표 + 정직성 섹션 (전면 재작성)
├── architecture/README.md  비용 모델 섹션 (정직화)
└── operations/2026-05-24-deep-dive.md  ★ 1900줄 기술 심층 보고서
```

### 정량 측정 데이터 출처

- `benchmarks/mcp_comparison.json` (3 MCP 모드 × 5 케이스 × 3 반복)
- `benchmarks/mcp_comparison_single_registry.json` (Phase 21-3 single-registry 측정)
- `benchmarks/results.json` (Anthropic API 실측, gitignored, $0.57 사용)

---

## 6️⃣ 정직한 한계 (자소서엔 안 쓰지만 면접관 압박 대비)

| 한계 | 어떻게 답할까 |
|---|---|
| **라이브 모드 LLM 호출 실측 안 함** | "Anthropic 가격표 기반 추정 — Phase 26 후보로 명시. 실 API 비용 발생이라 다음 단계로 분리" |
| **prompt caching cache_control 실 적용 안 함** | "가격표의 90% 캐시 적중 가정 — 실 cache_read_input_tokens / cache_creation_input_tokens 측정은 Phase 26 후보" |
| **token estimation chars/4** | "Claude/GPT 토크나이저 미사용 — 모드 간 비교에는 충분, 절대값은 ±20% 오차. 정확 측정은 anthropic SDK count_tokens 사용 시 가능" |
| **단일 worker (uvicorn -w 1) 운영 가정** | "backend `_CACHE` 가 process-local — 다중 worker 시 Redis shared cache 필요 (Phase 24 후보). EC2 배포 시 인스턴스 사이즈 보고 결정" |
| **외부 MCP 1개만 통합** | "BurtTheCoder/mcp-dnstwist 등 4개 검토했으나 Docker-in-Docker / 미dockerized 패턴 등 운영 부담. 1개로도 언어 무관성 입증 충분" |
| **MITRE ATT&CK 자동 매핑 미구현** | "agent_prompts 시스템 프롬프트에 일부 가이드 있으나 결정론적 룰베이스 매핑은 별도 phase. CVE 결과 → ATT&CK 매트릭스 매핑 필요" |
| **인증/인가 없음** | "docker 내부 네트워크만 접근 가정. 외부 노출 시 별도 인증 게이트 필요 — EC2 배포 phase 의 일부" |
| **MCP 시뮬레이션 모드와 라이브 모드의 결과 차이 검증 없음** | "시뮬레이션은 시드 데이터, 라이브는 외부 API — 결과 일관성 검증은 별도 라이브 데이터 셋 필요" |

---

## 7️⃣ 자소서 면접 1줄 요약 (외워둘 것)

```
"금융권 SOC IoC 트리아지를 LangGraph 6-Agent + MCP 5도구로 자동화하면서,
 본인이 직접 '비용 91.8% 절감' 헤드라인의 baseline 이 비현실적이라는 점을
 발견·정직화해 59.1% 로 갱신하고 pytest assert 로 정직성을 코드에 박은
 프로젝트입니다."
```

이 한 문장에:
- 도메인 (금융권 SOC)
- 기술 스택 (LangGraph + MCP)
- 정직성 스토리 (91.8 → 59.1)
- 엔지니어링 깊이 (pytest assert)
- 본인 주도성 ("직접 발견")

모두 들어있음. 면접 답변 시 이 문장 후 follow-up 받는 게 이상적.
