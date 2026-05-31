"""5대 금융권 시뮬레이션 시나리오 시드 데이터.

API 키나 외부 호출 없이도 데모/PoC/교육에 그대로 활용 가능한
사전 정의 위협 인텔리전스. 각 시나리오는 LangGraph 노드를 통과하면서
state 에 주입될 전 단계 산출물을 미리 정의해둔다.
"""
from __future__ import annotations

from typing import Any

# 시나리오 ID → 시드 데이터
SIMULATION_SCENARIOS: dict[str, dict[str, Any]] = {
    "S1": {
        "id": "S1",
        "title": "🏦 카카오뱅크 사칭 피싱 캠페인 추적",
        "summary": "타이포스쿼팅·홈오그래프 기법으로 카카오뱅크 도메인을 사칭한 피싱 인프라 자동 탐지·차단 규칙 생성",
        "ioc": "kakaobank-secure-login.com",
        "ioc_type": "domain",
        "before_minutes": 30,  # 사람이 수동 처리 시 소요 (분)
        "estimated_after_seconds": 4,
        "triage": {
            "threat_level": "HIGH",
            "detection_ratio": "28/93",
            "mitre_tactics": ["Initial Access (TA0001)", "Resource Development (TA0042)"],
            "priority_pivots": [
                "kakaobank-secure-login.com 등록 ≤24h",
                "DNS A 레코드가 알려진 피싱 호스팅 ASN 으로 가리킴",
            ],
            "notes": "고객 대상 사칭 피싱 인프라로 강하게 추정 — 즉시 격리 후보",
            "chat_message": (
                "VirusTotal 평판 조회 결과 28/93 벤더가 악성으로 분류했습니다. "
                "도메인이 24시간 이내 등록됐고 알려진 피싱 호스팅 ASN (AS199524) "
                "을 가리키네요. 위협 수준 HIGH 입니다."
            ),
        },
        "malware": {
            "malware_family": None,
            "behaviors": ["Credential Harvesting Page", "Auto-Redirect to Real Bank"],
            "c2_targets": [],
            "payload_hashes": [],
            "notes": "악성코드 배포 없음 — 정적 피싱 페이지 (자격증명 탈취)",
            "chat_message": "악성코드 배포는 없습니다. 정적 피싱 페이지로 자격증명만 탈취하는 형태입니다.",
        },
        "infrastructure": {
            "typosquat_domains": [
                {"domain": "kakaobаnk.com", "technique": "Cyrillic 'а'", "registered": "2026-05-19", "risk": "HIGH"},
                {"domain": "kakao-bank.net", "technique": "Hyphen Insertion", "registered": "2026-05-20", "risk": "HIGH"},
                {"domain": "kakaobank-secure.com", "technique": "Subdomain Pad", "registered": "2026-05-21", "risk": "HIGH"},
                {"domain": "kakaobank-login.com", "technique": "Keyword Pad", "registered": "2026-05-22", "risk": "HIGH"},
                {"domain": "kakaobank-help.kr", "technique": "TLD Swap", "registered": "2026-05-22", "risk": "MEDIUM"},
            ],
            "exposed_assets": [],
            "related_infra": [
                {"asn": "AS199524", "country": "RU", "ip": "185.x.x.x", "role": "Hosting"},
                {"cert_sha256": "ab12...e9", "common_name": "*.kakaobank-secure-login.com"},
            ],
            "campaign_cluster_id": "FINPHISH-KR-2026Q2-A",
            "notes": "동일 ASN/인증서 발급 패턴으로 5개 도메인 클러스터 형성",
            "chat_message": (
                "DNSTwist 으로 타이포스쿼트 변종을 탐색했습니다. 호모그래프(키릴 а) 1건, "
                "하이픈 삽입 2건, 키워드 패드 2건 — 총 5개 도메인이 동일 인증서/ASN 패턴 "
                "으로 클러스터를 이룹니다. FINPHISH-KR-2026Q2-A 캠페인으로 보입니다."
            ),
        },
        "campaign": {
            "threat_group_hypothesis": "FIN-KR/Phisher: 국내 금융 사칭 전문 그룹 (추정)",
            "attack_chain": [
                "유사 도메인 등록 (T1583.001)",
                "Let's Encrypt 인증서 자동 발급",
                "이메일/SMS 미끼 발송 (T1566.002)",
                "위장 로그인 페이지 → 자격증명 수집",
                "수집된 자격증명을 실서비스에 즉시 사용 시도",
            ],
            "hunt_hypotheses": [
                {
                    "hypothesis_id": 1,
                    "platform": "SIEM",
                    "query": "index=proxy domain IN (\"kakaobаnk.com\", \"kakao-bank.net\", \"kakaobank-secure.com\", \"kakaobank-login.com\", \"kakaobank-help.kr\") | stats count by user, src_ip",
                    "timeline": "최근 7일",
                    "criteria": "≥1 매치 시 사용자 자격증명 재설정 강제",
                },
                {
                    "hypothesis_id": 2,
                    "platform": "Network",
                    "query": "tls.handshake.extensions_server_name matches \"kakaobank-.*\"",
                    "timeline": "실시간",
                    "criteria": "TLS SNI 매치 즉시 차단",
                },
            ],
            "firewall_rules": [
                "deny ip any host kakaobаnk.com  # 호모그래프 (Cyrillic a)",
                "deny ip any host kakao-bank.net",
                "deny ip any host kakaobank-secure.com",
                "deny ip any host kakaobank-login.com",
                "deny ip any host kakaobank-help.kr",
                "deny ip any 185.x.x.x/24  # Hosting ASN AS199524",
            ],
            "executive_summary": (
                "FIN-KR/Phisher 그룹으로 추정되는 행위자가 카카오뱅크 사칭 피싱 캠페인을 전개 중. "
                "5개 타이포스쿼트 도메인(클러스터 FINPHISH-KR-2026Q2-A) 즉시 차단 권고. "
                "고객 SMS/이메일 알림 발송 및 사기방지센터(FDS) 와 공유 필요."
            ),
            "chat_message": (
                "FIN-KR/Phisher 그룹의 작전으로 추정합니다. 즉시 5개 도메인 차단 + 고객 SMS "
                "알림 + 사기방지센터(FDS) 공유를 권고드립니다. 헌팅 쿼리 2건과 방화벽 차단 "
                "규칙 6건을 산출했습니다."
            ),
        },
    },
    "S2": {
        "id": "S2",
        "title": "📞 보이스피싱 C2 인프라 클러스터링",
        "summary": "단일 IoC 에서 출발해 동일 보이스피싱 조직 C2 인프라 12개 노드 자동 매핑",
        "ioc": "203.0.113.42",
        "ioc_type": "ip",
        "before_minutes": 180,
        "estimated_after_seconds": 8,
        "triage": {
            "threat_level": "CRITICAL",
            "detection_ratio": "41/93",
            "mitre_tactics": ["Command and Control (TA0011)", "Exfiltration (TA0010)"],
            "priority_pivots": ["VoIP SIP 트래픽 다수", "DNS-over-HTTPS 사용 흔적"],
            "notes": "보이스피싱 작업장 C2 의심 — 다중 피해자 동시 연결 관찰",
            "chat_message": (
                "VT 평판 41/93 악성 — VoIP SIP 트래픽과 DNS-over-HTTPS 흔적이 포착됐습니다. "
                "다중 피해자가 동시에 연결 중인 게 가장 큰 신호입니다. 위협 수준 CRITICAL 입니다."
            ),
        },
        "malware": {
            "malware_family": "FakeBankApp.Android",
            "behaviors": ["원격 화면 제어 (TeamViewer Hijack)", "SMS Intercept", "Contact Exfil"],
            "c2_targets": ["203.0.113.42:8443", "203.0.113.43:8443", "kr-secure-update[.]top"],
            "payload_hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
            "notes": "악성 안드로이드 앱이 사용하는 C2 인프라",
            "chat_message": "이 C2 를 쓰는 악성 안드로이드 앱 FakeBankApp 이 별도 IoC 로 잡혀있습니다 (참고).",
        },
        "infrastructure": {
            "typosquat_domains": [],
            "exposed_assets": [],
            "related_infra": [
                {"ip": "203.0.113.42", "asn": "AS4837 (CN)", "open_ports": [22, 443, 8443, 5060]},
                {"ip": "203.0.113.43", "asn": "AS4837 (CN)", "open_ports": [22, 443, 8443]},
                {"ip": "203.0.113.44", "asn": "AS4837 (CN)", "open_ports": [22, 443, 8443]},
                {"domain": "kr-secure-update.top", "resolves_to": "203.0.113.42"},
                {"domain": "bank-helpdesk.top", "resolves_to": "203.0.113.43"},
            ],
            "campaign_cluster_id": "VOICEPHISH-CN-2026Q2-Beta",
            "notes": "동일 ASN·동일 포트 패턴·DNS 회전 — 단일 조직 인프라로 강하게 클러스터링",
            "chat_message": (
                "Shodan 조회 결과 동일 ASN(AS4837/CN) 에 같은 포트(8443, 5060) 를 여는 3개 IP "
                "가 묶입니다. 도메인 2개도 같은 IP 로 회전 중 — VOICEPHISH-CN-2026Q2-Beta "
                "클러스터입니다."
            ),
        },
        "campaign": {
            "threat_group_hypothesis": "보이스피싱 콜센터 조직 (중국 거점, KR 타깃)",
            "attack_chain": [
                "악성 앱 SMS 미끼로 배포",
                "설치 시 접근권한 요청",
                "C2 ←→ 콜센터 연결",
                "전화 도청·SMS 가로채기",
                "ARS 이체 유도",
            ],
            "hunt_hypotheses": [
                {
                    "hypothesis_id": 1,
                    "platform": "SIEM",
                    "query": "(src_ip IN (203.0.113.42, 203.0.113.43, 203.0.113.44) OR dst_ip IN ...) AND port IN (8443, 5060)",
                    "timeline": "최근 30일",
                    "criteria": "≥3 호스트 매치 시 신속 격리",
                },
                {
                    "hypothesis_id": 2,
                    "platform": "EDR",
                    "query": "process.name = TeamViewer.exe AND parent.name IN (browser, banking apps)",
                    "timeline": "실시간",
                    "criteria": "비정상 부모-자식 관계 → 격리",
                },
            ],
            "firewall_rules": [
                "deny ip any 203.0.113.42/32",
                "deny ip any 203.0.113.43/32",
                "deny ip any 203.0.113.44/32",
                "deny ip any host kr-secure-update.top",
                "deny ip any host bank-helpdesk.top",
            ],
            "executive_summary": (
                "보이스피싱 조직 C2 인프라 5노드 확인. "
                "C2 ASN(AS4837/CN) 전반에 대한 지오블로킹 및 의심 SMS 사전 차단 권고. "
                "한국인터넷진흥원(KISA)·금융보안원(FSI)·이동통신사와 공유."
            ),
            "chat_message": (
                "보이스피싱 콜센터 조직 (중국 거점, 한국 타깃) 으로 추정합니다. AS4837 전반 "
                "지오블로킹 + 의심 SMS 사전 차단 + KISA·FSI·이통사 공유를 권고드립니다."
            ),
        },
    },
    "S3": {
        "id": "S3",
        "title": "🔐 금융권 표적 랜섬웨어 IoC 심층 분석",
        "summary": "주요 은행 표적 랜섬웨어 변종 의심 해시 → 행위·인프라·캠페인 전 단계 자동 분석",
        "ioc": "44d88612fea8a8f36de82e1278abb02f",
        "ioc_type": "hash",
        "before_minutes": 120,
        "estimated_after_seconds": 12,
        "triage": {
            "threat_level": "CRITICAL",
            "detection_ratio": "63/93",
            "mitre_tactics": ["Initial Access (TA0001)", "Execution (TA0002)", "Impact (TA0040)"],
            "priority_pivots": ["LockBit 4.0 변종 패턴", "한국어 랜섬노트 동봉"],
            "notes": "국내 금융권 표적 변종 의심 — 즉시 격리 필요",
            "chat_message": (
                "63/93 벤더 악성. LockBit 4.0 변종 패턴이고 한국어 랜섬노트가 동봉되어 "
                "있습니다. 위협 수준 CRITICAL — 즉시 격리 필요합니다."
            ),
        },
        "malware": {
            "malware_family": "LockBit-KR (변종)",
            "behaviors": [
                "VSS 삭제 (vssadmin delete shadows)",
                "백업 폴더 우선 암호화",
                "Active Directory 자격증명 수집",
                "측면 이동 (PsExec)",
            ],
            "c2_targets": ["lockbit-pay4.onion", "194.x.x.21"],
            "payload_hashes": [
                "44d88612fea8a8f36de82e1278abb02f",
                "55e88712fea8a8f36de82e1278abb02f",
            ],
            "notes": "한국어 랜섬노트 + KRW 비트코인 교환소 안내 — 국내 금융권 표적성 강함",
            "chat_message": (
                "VSS 삭제 (vssadmin), 백업 폴더 우선 암호화, AD 자격증명 수집, PsExec 측면 "
                "이동 행위가 관찰됐습니다. Tor onion (lockbit-pay4.onion) + 러시아 staging IP "
                "(194.x.x.21) 를 C2 로 사용합니다."
            ),
        },
        "infrastructure": {
            "typosquat_domains": [],
            "exposed_assets": [],
            "related_infra": [
                {"tor_onion": "lockbit-pay4.onion", "role": "Payment portal"},
                {"ip": "194.x.x.21", "role": "Staging", "country": "RU"},
            ],
            "campaign_cluster_id": "RANSOM-KR-2026Q2-LockBit",
            "notes": "Tor + Russia 호스팅 결합 — LockBit 운영자 인프라와 일치",
            "chat_message": (
                "Tor 결제 포털 + Russia 호스팅 — LockBit 운영자 인프라와 일치합니다. "
                "RANSOM-KR-2026Q2-LockBit 클러스터로 묶입니다."
            ),
        },
        "campaign": {
            "threat_group_hypothesis": "LockBit Affiliate (국내 금융 표적 파트너)",
            "attack_chain": [
                "Phishing → 자격증명 탈취 (T1566)",
                "VPN 접속 + Active Directory 정찰 (T1087)",
                "PsExec 측면 이동 (T1021.002)",
                "백업 시스템 우선 암호화 (T1486)",
                "ransom note 배포 + Tor 결제 포털 안내",
            ],
            "hunt_hypotheses": [
                {
                    "hypothesis_id": 1,
                    "platform": "Sigma",
                    "query": "rule: vssadmin delete shadows /all /quiet",
                    "timeline": "실시간",
                    "criteria": "탐지 즉시 호스트 격리 + IR 발동",
                },
                {
                    "hypothesis_id": 2,
                    "platform": "EDR",
                    "query": "psexec.exe with remote target across multiple endpoints in <60s window",
                    "timeline": "실시간",
                    "criteria": "측면 이동 패턴 → 자동 격리",
                },
            ],
            "firewall_rules": [
                "deny ip any 194.x.x.21/32",
                "deny tor exit nodes",
            ],
            "executive_summary": (
                "LockBit 한국 금융권 표적 변종 의심. "
                "VSS 차단 그룹정책 적용, 백업 망 분리 검증, PsExec 비활성화 권고. "
                "전자금융감독규정 §15 침해사고 보고 절차 발동 권고."
            ),
            "chat_message": (
                "LockBit Affiliate (국내 금융 표적 파트너) 로 추정합니다. VSS 차단 그룹정책 + "
                "백업 망 분리 검증 + PsExec 비활성화 + 전자금융감독규정 §15 침해사고 보고 "
                "절차 발동을 권고드립니다."
            ),
        },
    },
    "S4": {
        "id": "S4",
        "title": "🌐 사내 외부노출 자산 점검 (전자금융감독규정 §13)",
        "summary": "Shodan 기반 사내 도메인 노출 자산 자동 식별 + 조치 권고",
        "ioc": "examplebank.co.kr",
        "ioc_type": "domain",
        "before_minutes": 60,
        "estimated_after_seconds": 6,
        "triage": {
            "threat_level": "MEDIUM",
            "detection_ratio": "0/93",
            "mitre_tactics": ["Reconnaissance (TA0043)"],
            "priority_pivots": [
                "관리자 페이지(/admin) 외부 노출",
                "TLS 인증서 만료 임박 자산 3건",
            ],
            "notes": "직접 침해는 없으나 컴플라이언스 위반 가능 — 조치 우선",
            "chat_message": (
                "본 도메인 자체는 악성 0/93 으로 깨끗합니다. 다만 자산 노출 컴플라이언스 측면 "
                "에서 점검이 필요한 상태입니다."
            ),
        },
        "malware": {
            "malware_family": None,
            "behaviors": [],
            "c2_targets": [],
            "payload_hashes": [],
            "notes": "악성코드 무관 — 자산 노출 점검 시나리오",
            "chat_message": "악성코드와는 무관한 자산 점검 시나리오입니다.",
        },
        "infrastructure": {
            "typosquat_domains": [],
            "exposed_assets": [
                {"target": "vpn.examplebank.co.kr", "port": 443, "service": "Fortigate SSL VPN", "cve": "CVE-2024-21762", "severity": "CRITICAL"},
                {"target": "mail.examplebank.co.kr", "port": 25, "service": "Exim 4.94", "cve": "CVE-2023-42115", "severity": "HIGH"},
                {"target": "dev.examplebank.co.kr", "port": 22, "service": "OpenSSH 7.4", "cve": "CVE-2023-38408", "severity": "MEDIUM"},
                {"target": "admin.examplebank.co.kr", "port": 8443, "service": "Tomcat 9 manager", "cve": None, "severity": "HIGH (관리자 페이지 노출)"},
                {"target": "old.examplebank.co.kr", "port": 443, "service": "TLS 인증서 만료 D-5", "cve": None, "severity": "MEDIUM"},
            ],
            "related_infra": [],
            "campaign_cluster_id": None,
            "notes": "외부 정찰자가 우선 시도할 5개 자산 — 컴플라이언스/패치 우선순위 즉시 권고",
            "chat_message": (
                "Shodan 으로 외부 노출 자산 5건 발견. Fortigate SSL VPN (CVE-2024-21762, "
                "CRITICAL), Exim 4.94 (CVE-2023-42115, HIGH), OpenSSH 7.4, Tomcat 9 관리자 "
                "페이지 노출, 만료 임박 인증서 1건 — 외부 정찰자가 우선 시도할 자산들입니다."
            ),
        },
        "campaign": {
            "threat_group_hypothesis": None,
            "attack_chain": [],
            "hunt_hypotheses": [
                {
                    "hypothesis_id": 1,
                    "platform": "Network",
                    "query": "이상 trafic from public to admin.examplebank.co.kr:8443",
                    "timeline": "최근 90일",
                    "criteria": "허가되지 않은 출처에서 접근 시 IP 차단",
                },
            ],
            "firewall_rules": [
                "deny tcp any host admin.examplebank.co.kr eq 8443",
                "allow tcp internal_only host admin.examplebank.co.kr eq 8443",
            ],
            "executive_summary": (
                "외부 노출 자산 5건 — Fortigate VPN(CVE-2024-21762) 즉시 패치, "
                "관리자 페이지 외부 접근 차단, 만료 임박 인증서 갱신. "
                "전자금융감독규정 §13(전자금융기반시설 보호) 통제 미달 항목으로 보고."
            ),
            "chat_message": (
                "Fortigate VPN (CVE-2024-21762) 즉시 패치 + 관리자 페이지 외부 차단 + 만료 "
                "임박 인증서 갱신을 권고드립니다. 전자금융감독규정 §13 통제 미달 항목으로 "
                "보고 가능합니다."
            ),
        },
    },
    "S5": {
        "id": "S5",
        "title": "🛠️ 금융권 표적 CVE 패치 우선순위화",
        "summary": "다중 CVE 후보 → EPSS·KEV·MITRE 기반 자동 우선순위화 (전자금융감독규정 §13)",
        "ioc": "CVE-2024-21762",
        "ioc_type": "cve",
        "before_minutes": 45,
        "estimated_after_seconds": 5,
        "triage": {
            "threat_level": "CRITICAL",
            "detection_ratio": "—",
            "mitre_tactics": ["Initial Access (TA0001)"],
            "priority_pivots": [
                "CISA KEV 등재 (2024-02-09)",
                "EPSS 0.97 (97% 이내 1년 익스플로잇 확률)",
                "금융권 SSL VPN 광범위 배포",
            ],
            "notes": "Fortinet FortiOS pre-auth RCE — 금융권 표적성·악용 가능성 최고치",
            "chat_message": (
                "CVE-2024-21762 — CISA KEV 등재(2024-02-09), EPSS 0.97 (1년 내 악용 확률 "
                "97 퍼센타일). Fortinet FortiOS pre-auth RCE 이며, 금융권 SSL VPN 광범위 배포 "
                "+ 활발한 익스플로잇으로 CRITICAL 입니다."
            ),
        },
        "malware": {
            "malware_family": None,
            "behaviors": [],
            "c2_targets": [],
            "payload_hashes": [],
            "notes": "CVE 분석 — 악성코드 무관",
            "chat_message": "CVE 분석 — 악성코드 단계 무관합니다.",
        },
        "infrastructure": {
            "typosquat_domains": [],
            "exposed_assets": [
                {"target": "vpn.examplebank.co.kr", "service": "FortiGate", "patch_status": "Vulnerable"},
            ],
            "related_infra": [],
            "campaign_cluster_id": None,
            "notes": "사내 1대 노출 자산이 본 CVE 영향권",
            "chat_message": "CVE 분석 — 인프라 단계 무관합니다.",
        },
        "campaign": {
            "threat_group_hypothesis": "Volt Typhoon 등 다수 위협 그룹이 활발히 활용 (CISA 공지)",
            "attack_chain": [
                "Pre-auth RCE 익스플로잇",
                "VPN 후 internal 망 진입",
                "AD 자격증명 수집",
                "장기 잠복 (지속성)",
            ],
            "hunt_hypotheses": [
                {
                    "hypothesis_id": 1,
                    "platform": "EDR",
                    "query": "fortios outbound connection to non-corporate IP after exploit timestamp",
                    "timeline": "패치 적용 전까지 24/7",
                    "criteria": "이상 outbound 즉시 격리",
                },
            ],
            "firewall_rules": [
                "rate-limit pre-auth requests to vpn.examplebank.co.kr",
            ],
            "executive_summary": (
                "CVE-2024-21762 (EPSS 0.97, KEV 등재) — 24시간 내 긴급 패치 권고. "
                "패치 전 임시 조치: VPN 접속 IP 화이트리스트, MFA 강제. "
                "전자금융감독규정 §13(취약점 점검) 통제 미달 우선 시정."
            ),
            "chat_message": (
                "Volt Typhoon 등 다수 위협 그룹이 활용 중 (CISA 공지). 24시간 내 긴급 패치 "
                "권고드립니다. 패치 전 임시 조치로 VPN 접속 IP 화이트리스트 + MFA 강제 + "
                "outbound 이상 모니터링이 필요합니다."
            ),
        },
    },
}


def get_scenario(scenario_id: str) -> dict[str, Any] | None:
    return SIMULATION_SCENARIOS.get(scenario_id)


def list_scenarios() -> list[dict[str, Any]]:
    """프론트엔드 메뉴 노출용 요약 목록."""
    return [
        {
            "id": s["id"],
            "title": s["title"],
            "summary": s["summary"],
            "ioc": s["ioc"],
            "ioc_type": s["ioc_type"],
            "before_minutes": s["before_minutes"],
            "estimated_after_seconds": s["estimated_after_seconds"],
        }
        for s in SIMULATION_SCENARIOS.values()
    ]
