# Domain Monitoring (DomainFinder) 워크플로우 분석

## 📋 목차
1. [개요](#개요)
2. [전체 워크플로우](#전체-워크플로우)
3. [사용 도구 및 API](#사용-도구-및-api)
4. [단계별 상세 설명](#단계별-상세-설명)
5. [얻을 수 있는 정보](#얻을-수-있는-정보)

---

## 개요

**Domain Monitoring**은 **피싱 공격 방어**를 위한 도구입니다.

### 핵심 기능
- **최근 등록된 도메인 검색**: 특정 패턴과 일치하는 도메인 탐지
- **안전한 미리보기**: URLScan.io를 통한 웹사이트 스크린샷 확인
- **위협 인텔리전스 통합**: 도메인/IP를 20개 보안 서비스에 즉시 조회
- **사전 방어**: 피싱 사이트가 활성화되기 전에 발견

### 사용 시나리오
조직의 브랜드를 모방한 피싱 사이트를 조기 탐지합니다.

**예시**:
- 회사 도메인: `google.com`
- 검색 패턴: `google-*` 또는 `g00gle*`
- 결과: `google-login.com`, `google-secure.com`, `g00gle-auth.com` 등 의심스러운 도메인 발견

---

## 전체 워크플로우

```
┌─────────────────────────────────────────────────────────────────┐
│  1. 사용자 입력                                                   │
│     └─ 도메인 패턴 입력: "google-*"                              │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  2. 프론트엔드 (Monitoring.jsx)                                  │
│     └─ API 호출: GET /api/url/urlscanio/google-*                │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  3. 백엔드 (external_domain_lookup_routes.py)                   │
│     └─ FastAPI 라우터: /api/url/urlscanio/{domain}             │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  4. 백엔드 서비스 (domain_lookup_service.py)                    │
│     └─ URLScan.io API 호출 (비동기)                             │
│        https://urlscan.io/api/v1/search/?q=domain:google-*      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  5. URLScan.io 응답                                              │
│     └─ 최근 스캔된 도메인 목록 반환                             │
│        [                                                         │
│          {                                                       │
│            "task": { "domain": "google-login.com", ... },       │
│            "page": { "ip": "1.2.3.4", "status": 200, ... },     │
│            "screenshot": "https://urlscan.io/screenshots/..."   │
│          },                                                      │
│          ...                                                     │
│        ]                                                         │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  6. 프론트엔드 결과 테이블 (ResultTable.jsx)                    │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │ Domain              │ Status  │ Found                   │ │
│     ├─────────────────────────────────────────────────────────┤ │
│     │ 🇺🇸 google-login.com │ 🟢 200  │ 15.01.2025 - 10:30    │ │
│     │ 🇬🇧 google-secure.com│ 🟠 404  │ 14.01.2025 - 22:15    │ │
│     │ 🇩🇪 g00gle-auth.com  │ 🔴 500  │ 14.01.2025 - 18:45    │ │
│     └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  7. 사용자 클릭 → 상세 정보 (Details.jsx)                       │
│     ┌───────────────────────────────────────────────────────┐   │
│     │ Screenshot              │ Domain Info                 │   │
│     │ ┌─────────────────┐     │ • IP: 1.2.3.4              │   │
│     │ │                 │     │ • Country: US              │   │
│     │ │  [웹사이트]      │     │ • URL: https://...         │   │
│     │ │   스크린샷      │     │ • Server: nginx/1.18       │   │
│     │ │                 │     │ • TLS Issuer: Let's Encrypt│   │
│     │ └─────────────────┘     │                            │   │
│     │                         │ [Analyze IP] [Analyze Domain] │
│     └───────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  8. IOC Lookup 연동 (Details.jsx → ResultTable from IOC Lookup)│
│     "Analyze IP" 클릭 시:                                        │
│     └─ IOC Single Lookup의 ResultTable 컴포넌트 재사용         │
│        → 1.2.3.4를 20개 위협 인텔리전스 서비스에 조회          │
│                                                                  │
│     "Analyze Domain" 클릭 시:                                    │
│     └─ IOC Single Lookup의 ResultTable 컴포넌트 재사용         │
│        → google-login.com을 20개 서비스에 조회                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 사용 도구 및 API

### 외부 API
**URLScan.io API**
- **역할**: 최근 스캔된 웹사이트 데이터베이스 검색
- **엔드포인트**: `https://urlscan.io/api/v1/search/?q=domain:{pattern}`
- **API 키**: 불필요 (공개 검색)
- **특징**:
  - 전 세계에서 제출된 웹사이트 스캔 결과 제공
  - 스크린샷, HTTP 헤더, IP 주소, TLS 정보 포함
  - 실시간 업데이트

### 내부 컴포넌트

#### 백엔드
**파일**: `backend/app/features/domain_lookup/`

1. **external_domain_lookup_routes.py**
   ```python
   @router.get("/api/url/urlscanio/{domain}")
   async def get_urlscan_data(domain: str):
       results = await urlscanio_async(domain)
       return results
   ```
   - FastAPI 라우터
   - 도메인 패턴을 받아서 URLScan.io에 조회

2. **domain_lookup_service.py**
   ```python
   async def urlscanio_async(domain: str):
       url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
       async with httpx.AsyncClient() as client:
           response = await client.get(url)
           return response.json()['results']
   ```
   - 비동기 HTTP 클라이언트 (httpx 사용)
   - URLScan.io API 호출 및 결과 파싱

#### 프론트엔드
**파일**: `frontend/src/components/domain-monitoring/`

1. **Monitoring.jsx** (메인 페이지)
   - 도메인 패턴 입력 받기
   - 검색 버튼 클릭 시 ResultTable 렌더링

2. **ResultTable.jsx** (결과 테이블)
   ```javascript
   api.get("/api/url/urlscanio/" + domain)
     .then(response => setResponse(response.data));
   ```
   - API 호출
   - 테이블 형태로 결과 표시 (도메인, 상태 코드, 발견 날짜)
   - 페이지네이션 지원 (15/25/50/75/100 rows per page)

3. **Details.jsx** (상세 정보)
   - 웹사이트 스크린샷 표시
   - 도메인 메타데이터 (IP, 국가, URL, 서버, TLS 정보)
   - **IOC Lookup 연동 버튼**
     - `Analyze IP`: IP 주소를 IOC Single Lookup으로 조회
     - `Analyze Domain`: 도메인을 IOC Single Lookup으로 조회

---

## 단계별 상세 설명

### 1단계: 사용자 입력
**위치**: `Monitoring.jsx:37-43`

```jsx
<SearchBar
  placeholder="Please enter a domain pattern to search for..."
  buttonLabel="Search"
  onSearchClick={handleShowTable}
/>
```

**입력 예시**:
- `google-*`: "google-"로 시작하는 모든 도메인
- `*paypal*`: "paypal"을 포함하는 모든 도메인
- `amazon*.com`: "amazon"으로 시작하고 ".com"으로 끝나는 도메인

**검증**:
- 빈 입력 시 에러 메시지 표시
- 유효한 입력 시 `setSearchKey()` 및 `setshowTable(true)`

---

### 2단계: API 호출
**위치**: `ResultTable.jsx:38-43`

```javascript
useEffect(() => {
  api.get("/api/url/urlscanio/" + props.domain)
    .then(response => {
      setResponse(response.data);
    });
}, []);
```

**HTTP 요청**:
```
GET /api/url/urlscanio/google-*
Host: localhost:8000
```

---

### 3단계: 백엔드 라우터
**위치**: `external_domain_lookup_routes.py:9-14`

```python
@router.get("/api/url/urlscanio/{domain}")
async def get_urlscan_data(domain: str):
    results = await urlscanio_async(domain)
    return results
```

**역할**:
- URL 파라미터에서 도메인 패턴 추출
- 비동기 서비스 함수 호출
- 결과를 JSON으로 반환

---

### 4단계: URLScan.io API 호출
**위치**: `domain_lookup_service.py:7-25`

```python
async def urlscanio_async(domain: str):
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        data = response.json()
        return [dict(item, expanded=False) for item in data['results']]
```

**실제 API 호출**:
```
GET https://urlscan.io/api/v1/search/?q=domain:google-*
```

**비동기 처리**:
- `httpx.AsyncClient()`: 비동기 HTTP 클라이언트
- 여러 요청을 병렬로 처리 가능
- FastAPI의 비동기 라우터와 통합

---

### 5단계: URLScan.io 응답
**응답 구조**:
```json
{
  "results": [
    {
      "task": {
        "uuid": "abc123...",
        "domain": "google-login.com",
        "time": "2025-01-15T10:30:00.000Z"
      },
      "page": {
        "ip": "1.2.3.4",
        "country": "US",
        "status": 200,
        "url": "https://google-login.com",
        "server": "nginx/1.18.0",
        "mimeType": "text/html",
        "asnname": "AMAZON-02, US",
        "tlsValidDays": 89,
        "tlsAgeDays": 1,
        "tlsValidFrom": "2025-01-14",
        "tlsIssuer": "Let's Encrypt"
      },
      "screenshot": "https://urlscan.io/screenshots/abc123.png",
      "result": "https://urlscan.io/result/abc123/"
    }
  ]
}
```

**주요 필드**:
- `task.domain`: 발견된 도메인 이름
- `task.time`: URLScan.io에 스캔된 날짜/시간
- `page.ip`: 도메인이 가리키는 IP 주소
- `page.status`: HTTP 상태 코드 (200, 404, 500 등)
- `screenshot`: 웹사이트 스크린샷 URL
- `page.tlsIssuer`: SSL 인증서 발급자

---

### 6단계: 결과 테이블 렌더링
**위치**: `ResultTable.jsx:136-206`

**테이블 구조**:
| 열 | 내용 | 예시 |
|----|------|------|
| **확장 버튼** | 상세 정보 토글 | ▼ |
| **Domain** | 국가 플래그 + 도메인 이름 | 🇺🇸 google-login.com |
| **Status code** | HTTP 상태 + 색상 표시 | 🟢 200 |
| **Found** | URLScan.io 스캔 날짜 | 15.01.2025 - 10:30 |

**상태 코드 색상**:
```javascript
if (status.startsWith(2)) return <CircleIcon color="green" />;  // 성공 (200-299)
if (status.startsWith(4)) return <CircleIcon color="orange" />; // 클라이언트 에러 (404)
if (status.startsWith(5)) return <CircleIcon color="red" />;    // 서버 에러 (500-599)
```

**페이지네이션**:
- 기본: 15개/페이지
- 옵션: 25, 50, 75, 100개/페이지

---

### 7단계: 상세 정보 표시
**위치**: `Details.jsx:27-336`

#### 스크린샷 카드
```jsx
<img src={props.section["screenshot"]} style={{ width: "250px" }} />
```
- URLScan.io가 제공하는 웹사이트 스크린샷
- 클릭 시 새 탭에서 전체 크기 이미지 열기
- **안전한 미리보기**: 실제 사이트 방문 없이 확인 가능

#### 기본 정보 카드
**왼쪽 열**:
- **IP**: 도메인이 가리키는 IP 주소
- **Country**: 서버 위치 (국가 코드)

**오른쪽 열**:
- **URL**: 전체 URL
- **Result**: URLScan.io 결과 페이지 링크

#### 기술 정보 카드
**왼쪽 열**:
- **Status code**: HTTP 상태 (색상 표시)
- **Server**: 웹 서버 소프트웨어 (nginx, Apache 등)
- **MIME type**: 컨텐츠 타입 (text/html, application/json 등)
- **ASN Name**: 네트워크 소유자 (ISP/호스팅 제공자)

**오른쪽 열**:
- **TLS valid days**: SSL 인증서 유효 기간 (남은 일수)
- **TLS age in days**: 인증서 발급 후 경과 일수
- **TLS valid from**: 인증서 발급 날짜
- **TLS issuer**: 인증서 발급 기관 (Let's Encrypt, DigiCert 등)

---

### 8단계: IOC Lookup 연동
**위치**: `Details.jsx:174-190, 328-333`

#### "Analyze IP" 버튼
```jsx
<Button onClick={() => setShowIpAnalysis(!showIpAnalysis)}>
  Analyze IP
</Button>

{showIpAnalysis && <ResultTable ioc={props.section["page"]["ip"]} iocType="IPv4" />}
```

**동작**:
1. 버튼 클릭 시 `showIpAnalysis` 상태 토글
2. IOC Single Lookup의 `ResultTable` 컴포넌트 재사용
3. IP 주소를 **20개 위협 인텔리전스 서비스**에 조회
   - AbuseIPDB
   - AlienVault OTX
   - CrowdSec
   - IPQualityScore
   - Shodan
   - 등...

**결과 예시**:
| Service | Result | TLP |
|---------|--------|-----|
| AbuseIPDB | Abuse Score: 85% | 🔴 RED |
| CrowdSec | CTI Score: 0.9 | 🔴 RED |
| Shodan | 3 open ports, 1 vulnerability | 🔴 RED |

#### "Analyze Domain" 버튼
```jsx
<Button onClick={() => setShowDomainAnalysis(!showDomainAnalysis)}>
  Analyze Domain
</Button>

{showDomainAnalysis && <ResultTable ioc={props.section["task"]["domain"]} iocType="Domain" />}
```

**동작**:
1. 버튼 클릭 시 `showDomainAnalysis` 상태 토글
2. 도메인 이름을 **20개 위협 인텔리전스 서비스**에 조회
   - VirusTotal
   - Google Safe Browsing
   - URLhaus
   - ThreatFox
   - 등...

**결과 예시**:
| Service | Result | TLP |
|---------|--------|-----|
| VirusTotal | Detected by 45/60 engines | 🔴 RED |
| Google Safe Browse | Threat: MALWARE, PHISHING | 🔴 RED |
| URLhaus | Found, status: online | 🔴 RED |

---

## 얻을 수 있는 정보

### 1. 도메인 발견 정보
Domain Monitoring을 통해 얻는 **1차 정보**:

| 정보 카테고리 | 세부 항목 | 사용 목적 |
|--------------|-----------|-----------|
| **도메인 정보** | 도메인 이름, 발견 날짜 | 피싱 도메인 조기 탐지 |
| **네트워크 정보** | IP 주소, ASN, 국가 | 호스팅 제공자 파악, 지리적 위치 |
| **웹 서버 정보** | HTTP 상태 코드, 서버 소프트웨어, MIME 타입 | 사이트 활성화 여부, 기술 스택 |
| **보안 정보** | TLS 인증서 (발급자, 유효기간, 발급일) | 합법성 검증 (Let's Encrypt는 피싱에 흔함) |
| **시각 정보** | 스크린샷 | 피싱 페이지 시각적 확인 |

### 2. 위협 인텔리전스 (IOC Lookup 연동)
"Analyze IP" / "Analyze Domain" 클릭 시 얻는 **2차 정보**:

#### IP 주소 분석 (6개 서비스 지원)
| 서비스 | 제공 정보 | 판단 기준 |
|--------|-----------|-----------|
| **AbuseIPDB** | Abuse Confidence Score (0-100) | 악성 활동 보고 이력 |
| **AlienVault OTX** | Pulse 수, 악성 활동 유형 | 위협 인텔리전스 커뮤니티 데이터 |
| **CrowdSec** | CTI Range Score (0-1) | 크라우드소싱 위협 데이터 |
| **IPQualityScore** | Fraud Score (0-100) | 프록시, VPN, TOR 사용 여부 |
| **Shodan** | 열린 포트, 취약점, 배너 정보 | 서버 노출 정보 |
| **BGPView** | ASN 정보, BGP 라우팅 | 네트워크 소유자 확인 |

#### 도메인 분석 (14개 서비스 지원)
| 서비스 | 제공 정보 | 판단 기준 |
|--------|-----------|-----------|
| **VirusTotal** | 60개 엔진 탐지 결과 | 멀웨어/피싱 탐지 여부 |
| **Google Safe Browsing** | 위협 유형 (MALWARE, PHISHING 등) | Google의 블랙리스트 |
| **CheckPhish** | Phishing 판정 (clean/phish) | AI 기반 피싱 탐지 |
| **URLhaus** | 악성 URL 데이터베이스 검색 | 알려진 멀웨어 배포 사이트 |
| **ThreatFox** | 위협 유형, 멀웨어 패밀리 | abuse.ch 위협 데이터베이스 |
| **URLScan.io** | 스캔 결과, 플래그된 횟수 | 커뮤니티 스캔 결과 |
| **Pulsedive** | Risk 수준 (none/low/medium/high/critical) | 위협 인텔리전스 집계 |

### 3. 실전 사용 시나리오

#### 시나리오 1: 브랜드 보호
**조직**: Google Inc.
**검색 패턴**: `google-*`, `g00gle*`, `*google*login*`

**발견된 도메인**: `google-login-verify.com`
```
✅ 도메인 정보:
  - 도메인: google-login-verify.com
  - 발견: 2025-01-15 10:30 (최근 등록!)
  - IP: 185.220.101.45
  - 국가: 🇷🇺 Russia
  - 상태: 🟢 200 (활성화됨)

✅ 스크린샷 확인:
  → Google 로그인 페이지를 모방한 피싱 사이트 확인

✅ IP 분석 결과 (Analyze IP 클릭):
  - AbuseIPDB: Abuse Score 92% 🔴 RED
  - CrowdSec: CTI Score 0.95 🔴 RED
  - Shodan: 3 open ports, nginx/1.18 🟠 AMBER

✅ 도메인 분석 결과 (Analyze Domain 클릭):
  - VirusTotal: 45/60 엔진에서 피싱 탐지 🔴 RED
  - Google Safe Browse: PHISHING 위협 감지 🔴 RED
  - URLhaus: 악성 URL 데이터베이스 등록됨 🔴 RED

🚨 결론: 확실한 피싱 사이트 → 즉시 차단 및 신고
```

#### 시나리오 2: 조기 탐지
**조직**: PayPal
**검색 패턴**: `*paypal*secure*`

**발견된 도메인**: `paypal-secure-login.com`
```
✅ 도메인 정보:
  - 도메인: paypal-secure-login.com
  - 발견: 2025-01-15 23:50 (1시간 전 등록!)
  - IP: 104.21.45.120
  - 국가: 🇺🇸 United States
  - 상태: 🟠 404 (아직 활성화 안됨)

✅ TLS 정보:
  - 인증서 발급: Let's Encrypt (무료 인증서 - 피싱에 흔함)
  - 발급 날짜: 2025-01-15 (방금 발급됨!)
  - 유효 기간: 89일 남음

✅ IP 분석 결과:
  - AbuseIPDB: Abuse Score 0% 🟢 GREEN (신규 IP)
  - Shodan: Cloudflare CDN 감지 🔵 BLUE

✅ 도메인 분석 결과:
  - VirusTotal: 0/60 탐지 🟢 GREEN (아직 스캔 안됨)
  - Google Safe Browse: Clean 🟢 GREEN (블랙리스트 등록 전)

⚠️ 결론: 아직 활성화 안됨, 하지만 의심스러운 패턴
        → 모니터링 계속, 활성화 시 즉시 차단 준비
```

#### 시나리오 3: False Positive 구별
**조직**: Amazon
**검색 패턴**: `amazon-*`

**발견된 도메인**: `amazon-web-services.com`
```
✅ 도메인 정보:
  - 도메인: amazon-web-services.com
  - 발견: 2023-03-10 (2년 전 등록)
  - IP: 52.94.236.248
  - 국가: 🇺🇸 United States
  - 상태: 🟢 200

✅ 스크린샷 확인:
  → AWS 공식 페이지 (정상)

✅ TLS 정보:
  - 인증서 발급: DigiCert Inc. (신뢰할 수 있는 CA)
  - 유효 기간: 365일 남음

✅ IP 분석 결과:
  - AbuseIPDB: Abuse Score 0% 🟢 GREEN
  - Shodan: AWS IP 범위, 공식 서버 🔵 BLUE

✅ 도메인 분석 결과:
  - VirusTotal: 0/60 탐지 🟢 GREEN
  - Google Safe Browse: Clean 🟢 GREEN

✅ 결론: 정상 도메인 (False Positive)
```

---

## 핵심 가치

### 1. 조기 탐지
- **피싱 사이트는 등록 후 수 시간 내에 활성화**됩니다.
- URLScan.io가 **전 세계 스캔 데이터를 실시간 수집**하므로, 도메인이 등록되자마자 발견 가능.
- **활성화 전에 발견** → 피해 발생 전 차단 가능

### 2. 안전한 조사
- **직접 방문 불필요**: 스크린샷으로 사이트 내용 확인
- **샌드박스 환경**: URLScan.io가 안전한 환경에서 스캔
- **멀웨어 감염 위험 제로**

### 3. 통합 위협 인텔리전스
- **20개 보안 서비스 연동**: 한 번의 클릭으로 종합 분석
- **TLP 색상 코드**: 위협 수준 즉시 파악
- **False Positive 최소화**: 여러 서비스의 교차 검증

### 4. 자동화 가능
- **API 기반 설계**: 정기적인 자동 검색 가능
- **CI/CD 통합**: 브랜드 모니터링 파이프라인에 통합
- **알림 연동**: 새로운 의심 도메인 발견 시 자동 알림

---

## 기술 스택 요약

| 계층 | 기술 | 역할 |
|------|------|------|
| **프론트엔드** | React (MUI) | UI 렌더링 |
| | Axios | HTTP 클라이언트 |
| | date-fns | 날짜 포맷팅 |
| | react-country-flag | 국기 아이콘 표시 |
| **백엔드** | FastAPI | REST API 서버 |
| | httpx | 비동기 HTTP 클라이언트 |
| | Python async/await | 비동기 처리 |
| **외부 API** | URLScan.io | 도메인 스캔 데이터베이스 |
| **통합** | IOC Single Lookup | 20개 위협 인텔리전스 서비스 |

---

## 한계 및 주의사항

### 1. URLScan.io 의존성
- **커버리지 제한**: URLScan.io에 스캔된 도메인만 검색 가능
- **시간 지연**: 도메인 등록 후 URLScan.io에 나타나기까지 수 시간~수일 소요 가능
- **API Rate Limit**: 무료 API는 분당 요청 수 제한 있음

### 2. 패턴 매칭의 한계
- **정확한 패턴 필요**: 너무 넓은 패턴은 False Positive 증가
- **우회 가능**: 공격자가 예상 패턴을 피할 수 있음
  - 예: `google-login.com` 대신 `g00gle-l0gin.com` 사용

### 3. False Positive
- **정상 도메인도 검색될 수 있음**
  - 예: `google-cloud-platform.com` (정상)
- **수동 검토 필요**: 자동화된 판단만으로는 부족
- **컨텍스트 중요**: 스크린샷 + 위협 인텔리전스 교차 검증 필수

---

## 개선 아이디어

1. **자동 알림 시스템**
   - 새로운 의심 도메인 발견 시 Slack/Email 알림
   - 위협 수준별 우선순위 자동 분류

2. **머신러닝 기반 분류**
   - 도메인 이름 + 스크린샷 + 위협 인텔리전스 데이터를 학습
   - 피싱 확률 자동 계산

3. **자동 차단 연동**
   - 방화벽/DNS 필터와 자동 연동
   - 높은 위협 수준 도메인 자동 차단

4. **역사 추적**
   - 과거에 발견된 도메인 데이터베이스 구축
   - 공격자 패턴 분석 (IP 범위, 등록 기관, 명명 규칙 등)
