# 🧩 MCP (Model Context Protocol) — Why & How

본 시스템이 외부 위협 인텔리전스 도구를 통합하는 방식. 표준 MCP 추상화를
유지하되 실제로는 직접 HTTP / Python 라이브러리로 wire-up.

---

## Why MCP — 직접 API 호출 대신 추상화 레이어를 둔 이유

| 항목 | 직접 API 호출 (mock 데이터 없이) | MCP 추상화 (본 시스템) |
|---|---|---|
| 도구 추가 | 노드별 코드 수정 + 재배포 | `McpRegistry` 메서드 하나 추가 |
| 다른 LLM 으로 전환 | 도구별 어댑터 재작성 | LangChain MCP Adapter 로 무관 |
| 호출 기록 | 도구마다 별도 로깅 코드 | 단일 `McpCallRecord` → Audit Ledger 통합 |
| 시뮬레이션·테스트 | mock 라이브러리 별도 셋업 | `mode="simulation"` 한 플래그로 분기 |
| 향후 사이드카 분리 | 큰 리팩토링 | stdio/sse transport 만 교체 |
| 데이터 출처 추적 | 코드 곳곳에 분산 | 모든 결과에 `_source` 필드 |

---

## How — `McpRegistry` 게이트웨이 구현

`backend/app/features/langgraph_threat_hunter/mcp_clients.py`

```python
@dataclass
class McpRegistry:
    """5종 MCP 도구를 단일 인터페이스로 추상화."""
    mode: str = "simulation"  # 또는 "live"
    _scenario_id: str | None = None

    def virustotal(self, state, ioc, ioc_type) -> dict: ...
    def dnstwist(self, state, domain) -> list[dict]: ...
    def shodan(self, state, target) -> list[dict]: ...
    def osint(self, state, target) -> list[dict]: ...
    def cve(self, state, cve_id) -> dict: ...
```

각 메서드는:
1. **시뮬레이션 모드** 면 시드 데이터 반환 (외부 호출 0회)
2. **라이브 모드** 면 실 HTTP/Python 라이브러리 호출
3. 결과를 `McpCallRecord` 로 자동 기록 → `state.mcp_calls` 누적
4. 캐시 적용 (10분 TTL)

---

## 5종 MCP 도구 실 wire-up

### 1. VirusTotal — IoC 평판 조회

| 속성 | 값 |
|---|---|
| 엔드포인트 | `https://www.virustotal.com/api/v3/{ip_addresses,domains,urls,files}/{ioc}` |
| 인증 | `x-apikey` 헤더 (env `VIRUSTOTAL_API_KEY`) |
| 무료 티어 | 4 req/min, 500 req/day |
| 자가 보호 | 분당 4회 = 15초 간격 자가 레이트리밋 |
| 응답 (성공) | `{ioc, type, detection_ratio: "N/M", stats, reputation, creation_date, categories}` |
| 응답 (키 없음) | `{_error: "VIRUSTOTAL_API_KEY 미설정"}` |

### 2. DNSTwist — 타이포스쿼트 변형 생성

| 속성 | 값 |
|---|---|
| 구현 | Python `dnstwist` 라이브러리 (pip install dnstwist) |
| API 키 | 불필요 (로컬 실행) |
| 입력 | 도메인 (예: `kakaobank.com`) |
| 출력 | 4,000~10,000 변형 생성 (호모그래프/하이픈/TLD swap 등) |
| 본 시스템 사용 | 상위 30 변형만 추출 → 상위 15건만 LLM 에 전달 (토큰 절약) |

### 3. Shodan — 노출 자산 점검

| 속성 | 값 |
|---|---|
| 무료 (InternetDB) | `https://internetdb.shodan.io/{ip}` — IP 만, 응답 가벼움 |
| 유료 (Shodan API) | `https://api.shodan.io/shodan/host/{ip}` (env `SHODAN_API_KEY` 있으면) |
| 응답 | `[{target, port, service, cve, severity}, ...]` |
| 폴백 | InternetDB 만 사용 가능, paid 키는 보강용 |

### 4. crt.sh — Certificate Transparency 로그

| 속성 | 값 |
|---|---|
| 엔드포인트 | `https://crt.sh/?q={target}&output=json` |
| API 키 | 불필요 (공개) |
| 응답 | `[{common_name, issuer_name, not_before, not_after}, ...]` |
| 본 시스템 사용 | 상위 5건만 LLM 에 전달 |

### 5. CVE — NVD + EPSS + CISA KEV (3종 조합)

| 도구 | 엔드포인트 | 데이터 |
|---|---|---|
| NVD | `services.nvd.nist.gov/rest/json/cves/2.0?cveId=...` | CVE 메타 + CVSS 점수 |
| EPSS | `api.first.org/data/v1/epss?cve=...` | 1년 내 악용 확률 (0~1) |
| CISA KEV | `cisa.gov/sites/.../known_exploited_vulnerabilities.json` | 실제 악용 카탈로그 (1일 캐시) |

종합 응답:
```json
{
  "cve_id": "CVE-2024-21762",
  "description": "Fortinet FortiOS pre-auth RCE...",
  "cvss_score": 9.8,
  "cvss_severity": "CRITICAL",
  "epss": 0.97,
  "epss_percentile": 0.998,
  "kev_listed": true,
  "_source": "live"
}
```

---

## 데이터 흐름 — MCP → LLM 통합

`backend/app/features/langgraph_threat_hunter/nodes.py` 의 라이브 모드:

```python
def infrastructure_node(state, mcp):
    # 1. MCP 도구 3종 병렬 호출 (실 HTTP)
    dt_result = mcp.dnstwist(state, state.ioc)         # DNSTwist 변형
    sh_result = mcp.shodan(state, state.ioc)           # Shodan 노출
    os_result = mcp.osint(state, state.ioc)            # crt.sh 인증서

    # 2. LLM 사용자 메시지에 MCP 결과를 JSON 직렬화 포함
    prompt = _live_user_prompt(state, prior_findings, mcp_data={
        "dnstwist": dt_result[:15],     # 토큰 절약
        "shodan": sh_result,
        "osint_crtsh": os_result[:5],
    })

    # 3. Specialist Claude 호출 — 실 데이터 기반 분석
    findings, meta = call_agent("infrastructure", prompt, max_tokens=1300)
```

Specialist Claude (Sonnet 4.5) 의 system prompt 에 "MCP 도구 결과가 실
데이터로 들어옴. 없거나 _error 면 추정/일반론 기반으로 답변, 데이터 출처를
chat_message 에 명시하라" 규약 명시.

---

## 시뮬레이션 vs 라이브 모드 분기

```python
# 시뮬레이션 (시드)
if self.mode == "simulation":
    return get_scenario(self._scenario_id)["infrastructure"]["typosquat_domains"]

# 라이브 (실 호출)
import dnstwist
fuzzer = dnstwist.Fuzzer(domain)
fuzzer.generate()
return [{"domain": p["domain"], "technique": p["fuzzer"]} for p in list(fuzzer.permutations())[:30]]
```

→ 같은 호출 인터페이스, 다른 데이터 출처. API 키 없거나 외부 호출 차단된
환경(예: 망분리)에서도 시뮬레이션 모드로 PoC 가능.

---

## 향후 — 진짜 MCP 사이드카 통합 (Phase 18+)

현재는 직접 HTTP/Python 라이브러리 호출이지만, MCP 프로토콜의 진정한
가치는 사이드카로 분리된 MCP 서버들이 stdio/sse 로 표준 통신하는 것:

```yaml
# docker-compose.yaml (향후)
services:
  mcp-dnstwist:
    image: burtthecoder/mcp-dnstwist
    networks: [aol-network]

  mcp-shodan:
    image: adeosec/mcp-shodan
    environment: [SHODAN_API_KEY]

  backend:
    environment:
      MCP_SERVERS: "dnstwist=stdio://mcp-dnstwist,shodan=stdio://mcp-shodan"
```

`langchain-mcp-adapters` 의 `MultiServerMCPClient` 로 위 사이드카들을 연결.
본 시스템의 `McpRegistry` 는 이미 그 추상화 준비됨 — transport 만 교체하면 됨.
