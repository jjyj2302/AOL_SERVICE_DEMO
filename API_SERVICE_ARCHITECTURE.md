# IOC Single Lookup API 서비스 아키텍처 및 데이터 흐름 정리

## 📋 목차
1. [전체 아키텍처 개요](#전체-아키텍처-개요)
2. [백엔드 구조](#백엔드-구조)
3. [프론트엔드 구조](#프론트엔드-구조)
4. [서비스별 API 응답 및 시각화](#서비스별-api-응답-및-시각화)

---

## 전체 아키텍처 개요

### 데이터 흐름
```
User Input (IOC)
    ↓
Frontend (SingleLookup.jsx)
    ↓
IOC Type Detection (iocDefinitions.js)
    ↓
ResultTable (ResultTable.js)
    ↓
ServiceFetcherRow (각 서비스별 병렬 API 호출)
    ↓
Backend API (/api/ioc/lookup/{service})
    ↓
IOC Lookup Engine (ioc_lookup_engine.py)
    ↓
External API Clients (external_api_clients.py)
    ↓
외부 위협 인텔리전스 서비스
    ↓
Backend Response (JSON)
    ↓
ServiceResultRow (getSummaryAndTlp + detailComponent)
    ↓
User View (테이블 + 상세 정보)
```

### 핵심 컴포넌트

#### 백엔드
- **라우터**: `single_ioc_lookup_routes.py` - REST API 엔드포인트
- **엔진**: `ioc_lookup_engine.py` - 서비스 조회 및 API 키 관리
- **레지스트리**: `service_registry.py` - 서비스 메타데이터 중앙 관리
- **클라이언트**: `external_api_clients.py` - 외부 API 통신

#### 프론트엔드
- **메인 UI**: `SingleLookup.jsx` - IOC 입력 및 검증
- **테이블**: `ResultTable.js` - 서비스 목록 렌더링
- **서비스 행**: `ServiceFetcherRow.js` - 개별 서비스 API 호출
- **결과 행**: `ServiceResultRow.jsx` - 결과 시각화 (요약 + TLP + 상세)
- **서비스 설정**: `serviceConfig.js` - 서비스별 메타데이터 및 파싱 로직

---

## 백엔드 구조

### 1. API 엔드포인트
**파일**: `backend/app/features/ioc_tools/ioc_lookup/single_lookup/routers/single_ioc_lookup_routes.py`

#### 주요 엔드포인트:
```python
GET /api/ioc/lookup/{service}
- 파라미터: ioc (IOC 값), ioc_type (IPv4, Domain 등)
- 역할: 특정 서비스에 IOC 조회 요청
- 응답: 서비스별 JSON 데이터 또는 에러

GET /api/ioc/service-definitions
- 역할: 모든 서비스의 메타데이터 및 API 키 상태 반환
- 응답: { serviceDefinitions: { 서비스명: { name, supportedIocTypes, isAvailable, ... } } }
```

### 2. 서비스 레지스트리
**파일**: `backend/app/features/ioc_tools/ioc_lookup/single_lookup/service/service_registry.py`

각 서비스의 **메타데이터**를 중앙에서 관리:
```python
_services = {
    'virustotal': {
        'func': ioc_lookup_service_module.virustotal,
        'name': 'VirusTotal',
        'api_key_name': 'virustotal',
        'supported_ioc_types': [IOC_TYPES['IPV4'], IOC_TYPES['DOMAIN'], ...],
        'requires_type': True,  # 일부 서비스는 타입별 엔드포인트 필요
        'type_map': { IOC_TYPES['IPV4']: 'ip', ... }
    },
    ...
}
```

### 3. 외부 API 클라이언트
**파일**: `backend/app/features/ioc_tools/ioc_lookup/single_lookup/service/external_api_clients.py`

각 외부 서비스별 **HTTP 요청 함수** 정의:
- 통일된 파라미터: `ioc` (IOC 값), `apikey` (API 키)
- 일부는 추가 파라미터: `type` (AlienVault, VirusTotal), `method` (Shodan)
- 통일된 에러 핸들링: `handle_request_errors()`
- 응답: 서비스 API의 원본 JSON (파싱 없이 그대로 반환)

**핵심 원칙**: 백엔드는 데이터 가공 없이 외부 API 응답을 그대로 프론트엔드에 전달

---

## 프론트엔드 구조

### 1. 메인 워크플로우

#### SingleLookup.jsx
- IOC 입력 받음
- `determineIocType()`로 IOC 타입 자동 감지
- 유효성 검증 후 `ResultTable` 렌더링

#### ResultTable.js
- `useServiceFilter()`로 IOC 타입에 맞는 서비스 필터링
- 각 서비스마다 `ServiceFetcherRow` 생성

#### ServiceFetcherRow.js
**역할**: 개별 서비스 API 호출 및 상태 관리
```javascript
const fetchData = async () => {
  const apiUrl = serviceConfigEntry.lookupEndpoint(ioc, iocType);
  const response = await api.get(apiUrl);

  // getSummaryAndTlp 함수로 요약 생성
  const displayProps = serviceConfigEntry.getSummaryAndTlp(response.data);

  setApiResult(response.data);  // 원본 데이터 저장
  setDisplayProps(displayProps); // 요약 데이터 저장
};
```

#### ServiceResultRow.jsx
**역할**: 결과 시각화
- **아이콘**: 서비스 로고
- **요약**: `getSummaryAndTlp()`로 생성된 한 줄 요약
- **TLP 색상**: 위협 수준 표시 (RED/AMBER/BLUE/GREEN/WHITE)
- **확장 가능**: 클릭 시 `detailComponent` 렌더링

### 2. 서비스 설정 (serviceConfig.js)

각 서비스마다 다음 정보 정의:
```javascript
SERVICE_DEFINITIONS = {
  abuseipdb: {
    name: 'AbuseIPDB',                           // 표시명
    icon: 'aipdb_logo_small',                    // 아이콘 파일명
    detailComponent: AbuseIpdbDetails,          // 상세 정보 컴포넌트
    requiredKeys: ['abuseipdb'],                // 필요한 API 키
    supportedIocTypes: ['IPv4'],                // 지원 IOC 타입
    lookupEndpoint: (ioc, type) => `/api/ioc/lookup/abuseipdb?ioc=${ioc}&ioc_type=${type}`,
    getSummaryAndTlp: (data) => {
      // 원본 API 응답을 받아서 요약 생성
      const score = data.data.abuseConfidenceScore;
      let tlp = score >= 75 ? 'RED' : score >= 25 ? 'AMBER' : 'GREEN';
      return {
        summary: `Abuse Score: ${score}%`,
        tlp,
        keyMetric: `${score}%`
      };
    },
  },
  ...
}
```

---

## 서비스별 API 응답 및 시각화

### IP 주소 관련 서비스

#### 1. AbuseIPDB
**API 키**: `abuseipdb`
**지원 IOC**: IPv4

**백엔드 응답 예시**:
```json
{
  "data": {
    "ipAddress": "1.2.3.4",
    "abuseConfidenceScore": 85,
    "totalReports": 120,
    "lastReportedAt": "2024-01-15T10:30:00Z"
  }
}
```

**프론트엔드 시각화**:
- **요약**: `Abuse Score: 85%`
- **TLP**: RED (≥75), AMBER (≥25), GREEN (<25)
- **주요 지표**: `abuseConfidenceScore`

#### 2. AlienVault OTX
**API 키**: `alienvault`
**지원 IOC**: IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256

**백엔드 응답 예시**:
```json
{
  "pulse_info": {
    "count": 5,
    "pulses": [...]
  },
  "reputation": {
    "activities": [
      { "name": "Malicious Host" }
    ]
  }
}
```

**프론트엔드 시각화**:
- **요약**: `Found in 5 pulses`
- **TLP**: RED (malicious 활동 있음), AMBER (pulse > 0), GREEN (pulse = 0)
- **주요 지표**: `pulse_info.count`

#### 3. BGPView
**API 키**: 없음 (무료)
**지원 IOC**: IPv4, IPv6, ASN

**백엔드 응답 예시**:
```json
{
  "data": {
    "prefixes": [
      {
        "asn": { "asn": 15169, "name": "GOOGLE" },
        "prefix": "8.8.8.0/24"
      }
    ]
  }
}
```

**프론트엔드 시각화**:
- **요약**: `AS15169 (GOOGLE)`
- **TLP**: BLUE (정보성)
- **주요 지표**: ASN 번호

#### 4. CrowdSec
**API 키**: `crowdsec`
**지원 IOC**: IPv4

**백엔드 응답 예시**:
```json
{
  "ip_range_score": 0.9,
  "behaviors": ["http:exploit", "ssh:bruteforce"]
}
```

**프론트엔드 시각화**:
- **요약**: `CTI Range Score: 0.9`
- **TLP**: RED (≥0.8), AMBER (≥0.5), GREEN (<0.5)
- **주요 지표**: `ip_range_score`

#### 5. IPQualityScore
**API 키**: `ipqualityscore`
**지원 IOC**: IPv4

**백엔드 응답 예시**:
```json
{
  "fraud_score": 92,
  "proxy": true,
  "vpn": true,
  "tor": false
}
```

**프론트엔드 시각화**:
- **요약**: `Fraud Score: 92`
- **TLP**: RED (≥90), AMBER (≥75), GREEN (<75)
- **주요 지표**: `fraud_score`

#### 6. Shodan
**API 키**: `shodan`
**지원 IOC**: IPv4, Domain

**백엔드 응답 예시**:
```json
{
  "ports": [80, 443, 22],
  "vulns": ["CVE-2021-44228"],
  "hostnames": ["example.com"]
}
```

**프론트엔드 시각화**:
- **요약**: `3 open port(s), 1 vulnerability(s)`
- **TLP**: RED (vulns > 0), BLUE (ports > 0), GREEN (no info)
- **주요 지표**: `ports.length / vulns.length`

---

### Domain/URL 관련 서비스

#### 7. CheckPhish
**API 키**: `checkphishai`
**지원 IOC**: IPv4, Domain, URL

**백엔드 응답 예시**:
```json
{
  "status": "DONE",
  "disposition": "phish",
  "brand": "PayPal"
}
```

**프론트엔드 시각화**:
- **요약**: `Disposition: phish`
- **TLP**: RED (phish), GREEN (clean), WHITE (unknown)
- **주요 지표**: `disposition`

#### 8. Google Safe Browsing
**API 키**: `safeBrowse`
**지원 IOC**: Domain, URL

**백엔드 응답 예시**:
```json
{
  "matches": [
    {
      "threatType": "MALWARE",
      "platformType": "ANY_PLATFORM"
    }
  ]
}
```

**프론트엔드 시각화**:
- **요약**: `Threat(s) found: MALWARE` 또는 `Clean`
- **TLP**: RED (matches 존재), GREEN (matches 없음)
- **주요 지표**: `matches[].threatType`

#### 9. URLhaus
**API 키**: `urlhaus`
**지원 IOC**: URL, Domain

**백엔드 응답 예시**:
```json
{
  "query_status": "ok",
  "url_status": "online"
}
```

**프론트엔드 시각화**:
- **요약**: `Found, status: online`
- **TLP**: RED (online), AMBER (offline), GREEN (not found)
- **주요 지표**: `url_status`

#### 10. URLScan.io
**API 키**: 없음 (무료)
**지원 IOC**: Domain, URL, IPv4

**백엔드 응답 예시**:
```json
{
  "results": [
    {
      "task": { "tags": ["phishing"] },
      "verdicts": { "overall": { "malicious": true } }
    }
  ]
}
```

**프론트엔드 시각화**:
- **요약**: `10 scan(s), 3 flagged`
- **TLP**: RED (flagged > 0), AMBER (scans > 0), GREEN (no scans)
- **주요 지표**: `flaggedCount / totalScans`

#### 11. Pulsedive
**API 키**: `pulsedive`
**지원 IOC**: IPv4, Domain, MD5, SHA1, SHA256, URL

**백엔드 응답 예시**:
```json
{
  "risk": "high",
  "threats": ["malware", "phishing"]
}
```

**프론트엔드 시각화**:
- **요약**: `Risk: high`
- **TLP**: RED (critical/high), AMBER (medium), BLUE (low), GREEN (none)
- **주요 지표**: `risk`

---

### 파일 해시 관련 서비스

#### 12. VirusTotal
**API 키**: `virustotal`
**지원 IOC**: IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256

**백엔드 응답 예시**:
```json
{
  "data": {
    "attributes": {
      "last_analysis_stats": {
        "malicious": 45,
        "suspicious": 5,
        "harmless": 10,
        "undetected": 0
      }
    }
  }
}
```

**프론트엔드 시각화**:
- **요약**: `Detected as malicious or suspicious by 50/60 engines`
- **TLP**: RED (malicious > 0), AMBER (suspicious > 0), GREEN (clean)
- **주요 지표**: `malicious + suspicious / total`

#### 13. MalwareBazaar
**API 키**: `malwarebazaar`
**지원 IOC**: MD5, SHA1, SHA256

**백엔드 응답 예시**:
```json
{
  "query_status": "ok",
  "data": [
    {
      "signature": "Emotet",
      "file_type": "exe"
    }
  ]
}
```

**프론트엔드 시각화**:
- **요약**: `Found: Emotet`
- **TLP**: RED (hash_found), GREEN (hash_not_found)
- **주요 지표**: `data[0].signature`

#### 14. ThreatFox
**API 키**: `threatfox`
**지원 IOC**: IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256

**백엔드 응답 예시**:
```json
{
  "query_status": "ok",
  "data": [
    {
      "threat_type": "botnet_cc",
      "malware": "Mirai"
    }
  ]
}
```

**프론트엔드 시각화**:
- **요약**: `Threat: botnet_cc`
- **TLP**: RED (found), GREEN (no_result)
- **주요 지표**: `data[0].threat_type`

---

### 이메일 관련 서비스

#### 15. EmailRep.io
**API 키**: `emailrepio`
**지원 IOC**: Email

**백엔드 응답 예시**:
```json
{
  "email": "test@example.com",
  "reputation": "low",
  "suspicious": true
}
```

**프론트엔드 시각화**:
- **요약**: `Reputation: low (Suspicious)`
- **TLP**: RED (suspicious), AMBER (low reputation), GREEN (high reputation)
- **주요 지표**: `reputation`

#### 16. Have I Been Pwned
**API 키**: `hibp_api_key`
**지원 IOC**: Email

**백엔드 응답 예시**:
```json
[
  { "Name": "LinkedIn", "BreachDate": "2012-05-05" },
  { "Name": "Adobe", "BreachDate": "2013-10-04" }
]
```

**프론트엔드 시각화**:
- **요약**: `Found in 2 breach(es)`
- **TLP**: RED (breaches > 0), GREEN (no breaches)
- **주요 지표**: `breachCount`

#### 17. Hunter.io
**API 키**: `hunterio_api_key`
**지원 IOC**: Email

**백엔드 응답 예시**:
```json
{
  "data": {
    "result": "deliverable",
    "disposable": false
  }
}
```

**프론트엔드 시각화**:
- **요약**: `Status: deliverable`
- **TLP**: RED (disposable or undeliverable), AMBER (risky), GREEN (deliverable)
- **주요 지표**: `result`

---

### CVE 관련 서비스

#### 18. NIST NVD
**API 키**: `nist_nvd_api_key`
**지원 IOC**: CVE

**백엔드 응답 예시**:
```json
{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2021-44228",
        "metrics": {
          "cvssMetricV31": [
            {
              "cvssData": {
                "baseSeverity": "CRITICAL",
                "baseScore": 10.0
              }
            }
          ]
        }
      }
    }
  ]
}
```

**프론트엔드 시각화**:
- **요약**: `Severity: CRITICAL`
- **TLP**: RED (CRITICAL/HIGH), AMBER (MEDIUM), BLUE (LOW), GREEN (not found)
- **주요 지표**: `cvssData.baseSeverity`

---

### OSINT/소셜 미디어 서비스

#### 19. GitHub Search
**API 키**: `github_pat`
**지원 IOC**: IPv4, IPv6, Domain, URL, Email, MD5, SHA1, SHA256, CVE

**백엔드 응답 예시**:
```json
{
  "total_count": 42,
  "items": [
    {
      "repository": { "full_name": "user/repo" },
      "path": "config.js"
    }
  ]
}
```

**프론트엔드 시각화**:
- **요약**: `42 mention(s)`
- **TLP**: AMBER (mentions > 0), GREEN (no mentions)
- **주요 지표**: `total_count`

#### 20. Reddit Search
**API 키**: `reddit_cid`, `reddit_cs`
**지원 IOC**: IPv4, IPv6, Domain, URL, Email, MD5, SHA1, SHA256, CVE

**백엔드 응답 예시**:
```json
{
  "data": {
    "dist": 15,
    "children": [
      {
        "data": {
          "title": "Discussion about...",
          "subreddit": "netsec"
        }
      }
    ]
  }
}
```

**프론트엔드 시각화**:
- **요약**: `15 mention(s)`
- **TLP**: AMBER (mentions > 0), GREEN (no mentions)
- **주요 지표**: `data.dist`

---

## TLP (Traffic Light Protocol) 색상 체계

프론트엔드는 위협 수준을 **TLP 색상**으로 표시:

| 색상 | 의미 | 사용 예시 |
|------|------|-----------|
| **RED** | 높은 위협 감지 | 악성코드 발견, 높은 abuse score, phishing 사이트 |
| **AMBER** | 의심스러운 활동 | 중간 위협 점수, 일부 보고 있음 |
| **BLUE** | 정보성 데이터 | BGP 정보, 낮은 위험도 |
| **GREEN** | 깨끗함/발견 안됨 | 위협 없음, 데이터베이스에 없음 |
| **WHITE** | 정보 없음/에러 | API 에러, 데이터 없음 |

---

## 확장 시 체크리스트

새로운 서비스 추가 시 필요한 작업:

### 백엔드
1. ✅ `external_api_clients.py`에 API 클라이언트 함수 추가
   - 파라미터: `ioc`, `apikey` (필수), 기타 (선택)
   - 리턴: `handle_request_errors()` 호출 결과

2. ✅ `service_registry.py`에 서비스 등록
   - `func`, `name`, `api_key_name`, `supported_ioc_types` 정의
   - 필요시 `requires_type`, `type_map` 정의

### 프론트엔드
1. ✅ Detail 컴포넌트 작성 (`shared/services/{ServiceName}/`)
2. ✅ `serviceConfig.js`에 서비스 정의 추가
   - `getSummaryAndTlp()` 함수 구현 (요약 + TLP 생성)
   - `detailComponent`, `icon`, `supportedIocTypes` 정의
3. ✅ 아이콘 이미지 추가 (`shared/icons/{service}_logo_small.png`)

### 데이터베이스
1. ✅ API 키 등록 (Settings → API Keys)

---

## 파일 위치 요약

### 백엔드
```
backend/app/features/ioc_tools/ioc_lookup/single_lookup/
├── routers/
│   └── single_ioc_lookup_routes.py          # REST API 엔드포인트
├── service/
│   ├── external_api_clients.py               # 외부 API 클라이언트
│   ├── ioc_lookup_engine.py                  # 조회 엔진
│   └── service_registry.py                   # 서비스 메타데이터
└── utils/
    └── ioc_utils.py                          # IOC 타입 판별
```

### 프론트엔드
```
frontend/src/components/ioc-tools/ioc-lookup/
├── single-lookup/
│   ├── SingleLookup.jsx                      # 메인 UI
│   └── components/ui/
│       ├── ResultTable.js                    # 결과 테이블
│       ├── ServiceFetcherRow.js              # API 호출
│       └── ServiceResultRow.jsx              # 결과 행 렌더링
└── shared/
    ├── config/
    │   └── serviceConfig.js                  # 서비스 설정 (getSummaryAndTlp)
    ├── services/
    │   ├── AbuseIPDB/AbuseIpdbDetails.jsx   # 각 서비스 상세 컴포넌트
    │   ├── Virustotal/VirustotalDetails.jsx
    │   └── ...
    └── icons/
        └── *.png                             # 서비스 로고
```

---

## 주요 설계 원칙

1. **백엔드는 Proxy 역할**: 외부 API 응답을 가공 없이 그대로 전달
2. **프론트엔드에서 파싱**: `getSummaryAndTlp()` 함수로 응답 해석
3. **서비스 병렬 호출**: 각 서비스는 독립적으로 비동기 호출
4. **에러 격리**: 한 서비스 실패가 다른 서비스에 영향 없음
5. **중앙 집중식 설정**: 서비스 메타데이터를 한 곳에서 관리
6. **확장 용이**: 새 서비스 추가 시 3개 파일만 수정
   - `external_api_clients.py` (백엔드)
   - `service_registry.py` (백엔드)
   - `serviceConfig.js` (프론트엔드)
