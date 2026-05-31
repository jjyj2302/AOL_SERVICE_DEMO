# 🤖 6-Agent 상세 — 역할·도구·모델·산출물

본 시스템의 LangGraph StateGraph 에 등록된 6개 에이전트. 각 에이전트는
[`backend/app/features/langgraph_threat_hunter/`](../../backend/app/features/langgraph_threat_hunter/)
의 nodes.py 에 노드 함수로, agent_prompts.py 에 시스템 프롬프트로 구현.

---

## 1. 🧠 Investigation Orchestrator

| 속성 | 값 |
|---|---|
| **역할** | IoC 타입 + 정황을 보고 어느 Specialist 를 어떤 순서로 호출할지 `route_plan` 결정 |
| **Claude 모델** | **Haiku 4.5** (mini 티어) — 라우팅만 필요 |
| **MCP 도구** | — (사용 안 함) |
| **입출력 토큰 (실측)** | 250 / 200 |
| **소요 시간 (라이브)** | ~3초 |
| **그래프 위치** | START 직후 첫 노드 |

### 라우팅 규칙

| IoC 타입 | route_plan | 이유 |
|---|---|---|
| `cve` | `[triage, campaign]` | 패치 우선순위만 — malware/infra 불필요 |
| `hash` | `[triage, malware, infrastructure, campaign]` | 풀체인 — 행위/인프라/캠페인 모두 |
| `ip`/`domain`/`url` | `[triage, infrastructure, campaign]` | malware 는 별도 EDR 트리아지 영역 |
| `unknown` | `[triage, malware, infrastructure, campaign]` | 안전한 전체 분석 |

### 출력 스키마

```json
{
  "findings": {
    "route_plan": ["triage", "infrastructure", "campaign"],
    "rationale": "도메인 IoC는 평판/인프라/캠페인 흐름이 효율적입니다."
  },
  "chat_message": "..."
}
```

---

## 2. 🔍 Triage Specialist

| 속성 | 값 |
|---|---|
| **역할** | IoC 평판·등록일·ASN·MITRE ATT&CK 패턴을 종합 → 위협 수준 신속 평가 |
| **Claude 모델** | **Haiku 4.5** (mini 티어) — 구조화 데이터 매핑 수준 |
| **MCP 도구** | VirusTotal HTTP API |
| **입출력 토큰 (실측)** | 400 / 700 |
| **소요 시간 (라이브)** | ~5초 |

### 페르소나
> "15년 경력의 Senior IOC Triage Expert. 매일 수천 건 IoC 를 평가하고
> 우선순위 정하는 베테랑. '바로 봐야 할 것' vs '나중에 봐도 되는 것'을 즉시 구분."

### 출력 스키마

```json
{
  "findings": {
    "threat_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
    "detection_ratio": "28/93",
    "mitre_tactics": ["Initial Access (TA0001)"],
    "priority_pivots": ["도메인 ≤24h 등록", "피싱 호스팅 ASN"],
    "notes": "한 문장 요약"
  },
  "chat_message": "..."
}
```

---

## 3. 👾 Malware Specialist

| 속성 | 값 |
|---|---|
| **역할** | 악성코드 행위·C2 통신·페이로드 전달 분석 → Attack chain 재구성 |
| **Claude 모델** | **Sonnet 4.5** (medium 티어) — 추론 필요 |
| **MCP 도구** | VirusTotal (hash 시), OSINT |
| **입출력 토큰 (실측)** | 440 / 1400 |
| **소요 시간 (라이브)** | ~20초 |

### 페르소나
> "세계적 수준의 Elite Malware Behavioral Analyst. Sandbox artifact 와 실
> 운영 인프라를 구분하는 게 특기. MITRE TTP 매핑으로 후속 헌팅 가설 직결."

### 출력 스키마

```json
{
  "findings": {
    "malware_family": "LockBit-KR",
    "behaviors": ["vssadmin delete shadows", "PsExec 측면이동", "AD 자격증명 수집"],
    "c2_targets": ["lockbit-pay4.onion", "194.x.x.21"],
    "payload_hashes": ["44d88612..."],
    "notes": "한 문장 요약"
  },
  "chat_message": "..."
}
```

---

## 4. 🌍 Infrastructure Hunter

| 속성 | 값 |
|---|---|
| **역할** | 공격자 인프라 상관관계 매핑, 캠페인 클러스터링, **금융권 사칭 도메인 자동 탐지** |
| **Claude 모델** | **Sonnet 4.5** (medium 티어) |
| **MCP 도구** | DNSTwist Python · Shodan InternetDB · crt.sh |
| **입출력 토큰 (실측)** | 540 / 1300 |
| **소요 시간 (라이브)** | ~15초 |

### 페르소나
> "Master Infrastructure Hunter. '누가 또 이 인프라를 쓰는가' 와 '이게 더 큰
> 작전의 일부인가' 를 항상 묻는 캠페인 클러스터링 전문가."

### MCP 도구 활용

| 도구 | 데이터 활용 |
|---|---|
| DNSTwist | 호모그래프/하이픈/TLD 변형 30종 생성 → 상위 15개를 LLM 에 전달 |
| Shodan InternetDB | IP 노출 포트·취약점 (무료) |
| crt.sh | Certificate Transparency 로그 → 관련 SSL 인증서·도메인 |

### 출력 스키마

```json
{
  "findings": {
    "typosquat_domains": [
      {"domain": "kakaobаnk.com", "technique": "Cyrillic homoglyph", "risk": "HIGH"}
    ],
    "exposed_assets": [
      {"target": "vpn.examplebank.co.kr", "port": 443, "service": "FortiGate", "cve": "CVE-2024-21762"}
    ],
    "related_infra": [{"ip": "185.x.x.x", "asn": "AS199524", "country": "RU"}],
    "campaign_cluster_id": "FINPHISH-KR-2026Q2-A",
    "notes": "..."
  },
  "chat_message": "..."
}
```

---

## 5. 📈 Campaign Analyst

| 속성 | 값 |
|---|---|
| **역할** | 모든 specialist 산출물 종합 → 위협 그룹 attribution + Attack chain + 헌팅 쿼리 + FW 규칙 + 임원 요약 |
| **Claude 모델** | **Sonnet 4.5** (medium 티어) — 가장 복잡한 종합 |
| **MCP 도구** | CVE-MCP (NVD + EPSS + CISA KEV) |
| **입출력 토큰 (실측)** | 500 / 2500 |
| **소요 시간 (라이브)** | ~30초 |

### 페르소나
> "Strategic Threat Campaign Assessment 전문가. 모든 발견을 종합하여 권위
> 있는 최종 평가를 내림. 한국 금융권 표적 위협 그룹 catalog 보유 (FIN-KR,
> VoicePhish-CN, LockBit Affiliate, Volt Typhoon 등)."

### 출력 스키마

```json
{
  "findings": {
    "threat_group_hypothesis": "FIN-KR/Phisher (추정)",
    "attack_chain": ["T1583.001 (도메인 등록)", "T1566.002 (이메일 미끼)", "T1078 (Credential Access)"],
    "hunt_hypotheses": [
      {
        "hypothesis_id": 1,
        "platform": "SIEM",
        "query": "index=proxy domain IN (...) | stats count by user, src_ip",
        "timeline": "최근 7일",
        "criteria": "≥1 매치 시 자격증명 재설정 강제"
      }
    ],
    "firewall_rules": [
      "deny ip any host kakaobаnk.com  # Cyrillic 호모그래프",
      "deny ip any 185.x.x.x/24  # Hosting ASN AS199524"
    ],
    "executive_summary": "C-Level/금감원 보고용 3~4 문장 요약"
  },
  "chat_message": "..."
}
```

---

## 6. 🛡️ Confidence Gate

| 속성 | 값 |
|---|---|
| **역할** | 모든 specialist 결과 종합 → L0~L4 자동화 등급 결정 + 핵심 자산 휴먼 승인 강제 |
| **모델** | **(LLM 무관) Python 결정론적 함수** |
| **MCP 도구** | — |
| **입출력 토큰** | 0 / 0 (비용 0) |
| **소요 시간** | <1ms |
| **그래프 위치** | 모든 specialist 종료 후 마지막 노드 |

### 점수 계산 (`confidence.py::_signal_score`)

| 신호 | 가산 |
|---|---|
| Triage threat_level=CRITICAL | +0.35 |
| Triage threat_level=HIGH | +0.25 |
| Malware family 식별 | +0.15 |
| Malware C2 발견 | +0.10 |
| Infrastructure typosquat 발견 | +0.15 |
| Infrastructure campaign cluster | +0.10 |
| Campaign threat group | +0.05 |
| Campaign hunt hypotheses | +0.05 |

→ 합산 점수 → L0~L4 매핑.

### L0~L4 자동화 매트릭스

| 등급 | 신뢰도 | 자동화 수준 | 핵심 자산이면 |
|---|---|---|---|
| L0 | <0.50 | 권고만 | 휴먼 승인 |
| L1 | 0.50~0.70 | 분석가 확인 후 처리 | 휴먼 승인 |
| L2 | 0.70~0.85 | 자동 케이스 생성 | 휴먼 승인 |
| L3 | 0.85~0.95 | 자동 SIEM 헌팅 트리거 | 휴먼 승인 |
| L4 | ≥0.95 | **자동 FW/IPS 차단** | **항상 휴먼 승인** |

### 핵심 자산 키워드 (휴먼 승인 강제)

```python
CRITICAL_ASSET_PATTERNS = (
    "core-banking", "exec-pc", "swift", "trading-engine",
    "kakaobank", "shinhan", "kbstar", "wooribank", "hanafn", "ibk",
)
```

IoC 또는 인프라 분석 결과에 위 키워드 매칭 시 등급과 무관하게
`human_approval_required = True` 강제 → 자동 차단 방지 + 분석가 검토 강제.
