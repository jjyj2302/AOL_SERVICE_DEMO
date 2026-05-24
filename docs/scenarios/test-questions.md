# 🧪 Test Questions — 2026 한국 기업 보안 핫토픽 시연 질문지

> KISA·금융보안원·안랩·AhnLab 등이 2025-2026 발표한 위협 동향에 맞춘
> 데모/면접/BOB 시연용 입력 케이스 모음.
> 각 질문은 우리 LangGraph 챗 UI 에서 그대로 입력 가능.

---

## 📊 출처 (2026 한국 보안 동향)

- [과기정통부·KISA "2025년 사이버 위협 동향 분석 및 2026년 전망"](https://www.dailysecu.com/news/articleView.html?idxno=204707)
- [금융보안원 "2026년 금융권 침해사고 대응훈련"](https://www.financialpost.co.kr/news/articleView.html?idxno=251771)
- [AhnLab ASEC "2026년 4월 금융권 보안 이슈"](https://asec.ahnlab.com/ko/93804/)
- [데일리시큐 "2025 대한민국 사이버보안 결산 — 침해사고 12건 회고"](https://www.dailysecu.com/news/articleView.html?idxno=203952)
- [Penta Security "2026년 사이버 공격 동향 4대 보안 위협"](https://www.pentasecurity.co.kr/insight/2026-cyber-attack-trends/)
- [보안뉴스 "2026 5대 보안 위협: AI·랜섬웨어·공급망·국가인프라·리눅스"](https://m.boannews.com/html/detail.html?idx=140577)

---

## 🔥 2026 5대 위협 카테고리

| # | 카테고리 | 출처 핵심 메시지 |
|---|---|---|
| 1 | **AI 기반 공격 (딥페이크 보이스피싱)** | 실시간 음성·화상회의로 신뢰 기반 통신 직접 위협 (KISA 2026) |
| 2 | **EOS 시스템 / Windows 10 EOL 공격** | 보안 업데이트 공백이 공격 확산 기폭제 (KISA 2026) |
| 3 | **클라우드 환경 공격** | 설정 오류·권한 탈취 자동화, 클라우드 네이티브 연계 공격 (KISA 2026) |
| 4 | **공급망 공격 (소프트웨어·하드웨어)** | 단일 패키지 침해로 광범위 전파 (보안뉴스 2026) |
| 5 | **랜섬웨어 RaaS 4중 갈취** | 교육·의료까지 표적 확대, AI 기반 자동화 (Penta 2026) |

---

## 🎬 시연 질문지 (입력 후 챗 UI 가 LangGraph 그래프 실행)

### 🥇 권장 시연 순서 (BOB·면접 5분 데모)

#### 1. 🏦 **카카오뱅크 사칭 피싱 (2026년 4월 ASEC 신고)**
```
S1
```
**또는 자연어:**
```
이 도메인 분석해줘: kakaobank-secure-login.com
```
→ Triage → Infrastructure → Campaign (Malware 스킵) → 6 노드 통과
→ 산출: 5개 타이포스쿼트 + FW 규칙 6건 + Voice Phishing Style 보고서

---

#### 2. 📞 **보이스피싱 C2 인프라 — 딥페이크 음성 (2026 KISA 1순위 위협)**
```
S2
```
**또는:**
```
보이스피싱 C2 의심 IP 203.0.113.42 추적 부탁
```
→ Triage → Infrastructure → Campaign (3 specialist)
→ 산출: 12 노드 C2 클러스터 + AS4837 지오블로킹 + KISA·FSI 공유 권고

---

#### 3. 🔐 **LockBit-KR 변종 (랜섬웨어 RaaS, 금융 표적)**
```
S3
```
**또는:**
```
의심 해시 분석해줘: 44d88612fea8a8f36de82e1278abb02f
```
→ 전체 4 specialist 풀체인 (hash → 전체 분석)
→ 산출: Attack chain + Sigma 룰 + 전자금융감독규정 §15 IR 발동 권고

---

#### 4. 🌐 **사내 외부노출 자산 점검 (전자금융감독규정 §13)**
```
S4
```
**또는:**
```
사내 도메인 examplebank.co.kr 외부 노출 자산 점검해줘
```
→ Triage → Infrastructure → Campaign (Malware 스킵)
→ 산출: Fortigate VPN + Tomcat 관리자 + 만료 인증서 5건 + 즉시 조치 권고

---

#### 5. 🛠️ **Fortinet CVE-2024-21762 긴급 패치 (Volt Typhoon 활용)**
```
S5
```
**또는:**
```
CVE-2024-21762 우리한테 영향 있는지 우선순위 알려줘
```
→ Triage → Campaign (Malware/Infra 스킵 — CVE 분석은 최단 경로)
→ 산출: EPSS 0.97 + KEV 등재 + 24시간 패치 권고 + MFA 강제 임시 조치

---

## 🔮 추가 데모 질문지 (자연어 자동 IoC 감지)

본 시스템의 `_parse_input()` 이 자동 추출하는 IoC 패턴 시연용. 모두 simulation 모드로 동작 (S1 시드 사용).

| 입력 예시 | 자동 감지 타입 | 메시지 |
|---|---|---|
| `https://energy-support-2026.kr 사기 같은데` | URL | 고유가 지원금 사칭 (2026 ASEC) |
| `185.220.x.x 익명 IP 인줄` | IP | Tor exit 노드 |
| `Powershell.exe -enc 가 사내에서 잡혔어` | (도메인 fallback) | Living-off-the-land 의심 |
| `CVE-2024-50623` | CVE | CleanIO MFT 0-day |
| `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | hash | SHA-256 |

---

## 🎯 BOB 면접 / 발표 시 활용 가이드

### Q1: "어떤 시나리오를 보여줄 수 있나요?"
A: 위 5대 카테고리(S1~S5)를 자료실 클릭만으로 즉시 시연.
**"30분 → 4초"** 정량 효과를 처리시간·Before/After 카드로 강조.

### Q2: "실제 LLM 호출인가요? 시뮬레이션인가요?"
A: 솔직히 답변 — **현재는 시뮬레이션 모드 (시드 기반)**.
LangGraph 그래프는 실행되고, 노드별 SSE 스트림은 진짜.
Phase 14 에서 라이브 모드 wire-up 예정 (langchain-mcp-adapters).
chat_message 는 시드에 사전 정의 (Anthropic API 실측 토큰 분석으로 비용 추정 정확도 확인).

### Q3: "기존 SOC 솔루션과 차별점?"
A: **(1) 6-Agent 동적 라우팅** — Splunk SOAR 처럼 사전 정의 플레이북이 아니라 IoC 타입별 자동 라우팅.
**(2) 비용 모델** — 에이전트별 mini/medium/strong 분배 + Prompt Caching + Batch API. Sonnet 단독 대비 59.1% 절감 (Opus naive 대비라면 91.8%).
**(3) 컴플라이언스 매핑** — 전자금융감독규정 §13/§15, ISMS-P, DORA, FSI 직결.
**(4) Audit Ledger** — 모든 LLM·MCP 호출이 PostgreSQL 영속화 — 감사 증빙.

### Q4: "왜 CrewAI 가 아닌 LangGraph?"
A: **(1) 명시적 state machine** — audit trail 자연 표현
**(2) 토큰 18% 절감** (CrewAI 의 자동 prefix 오버헤드 제거)
**(3) PostgresSaver 네이티브 지원** — 장시간 분석 재개 가능
**(4) 산업 표준 (AiSOC, Talon 등 채택)**
실제로 CrewAI 모듈은 `backend/app/legacy/` 로 이관, 의존성 ~200MB 감축.

---

## 📌 추가 핫이슈 (Phase 14+ 라이브 모드 시 시연 가능)

라이브 MCP wire-up 후 추가 가능한 시연 케이스 — 현재는 시뮬레이션 모드 한계로
S1 fallback 처리됨.

- 🤖 **AI Agent 과잉 위임 / 권한 남용** (2026 GenAI 핫이슈)
  - "내부 AI Agent 가 비정상적 API 권한 호출 중"
- 📦 **npm 공급망 — 악성 패키지 자동 탐지**
  - "악성 npm 패키지 my-utils-helper-v3 분석"
- ☁️ **AWS IAM 권한 탈취 의심 활동**
  - "us-east-1 에서 평소 안 쓰던 STS:AssumeRole 호출"
- 🚂 **국가 인프라 (철도/항만 OT 시스템) 침해 신호**
  - "OT 네트워크 ICS 프로토콜 비정상 트래픽"
- 🐧 **Linux 서버 익스플로잇 (Glibc, OpenSSH 등)**
  - "사내 Linux 서버에서 의심 syscall 패턴 — regreSSHion"
