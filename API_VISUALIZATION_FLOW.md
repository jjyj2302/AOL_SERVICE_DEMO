# API to Frontend Visualization Flow

## 📋 Overview

이 문서는 외부 API들이 호출되고, 응답이 처리되어, 최종적으로 프론트엔드에서 시각화되는 전체 과정을 설명합니다.

---

## 🔄 Complete Data Flow

```
User Input (IOC)
    ↓
[Frontend] SingleLookup.jsx → IOC 유효성 검증
    ↓
[Frontend] ResultTable.js → 지원되는 서비스 필터링
    ↓
[Frontend] ServiceFetcherRow.js → 각 서비스별 병렬 API 호출
    ↓
[API Call] GET /api/ioc/lookup/{service}?ioc={value}&ioc_type={type}
    ↓
[Backend] unified_routes.py → 라우팅
    ↓
[Backend] ioc_lookup_engine.py → 서비스 레지스트리 조회 및 API 키 검증
    ↓
[Backend] external_api_clients.py → 외부 API 호출
    ↓
[External API] VirusTotal, AbuseIPDB, etc. → 실제 위협 정보 조회
    ↓
[Backend] 원본 JSON 응답 반환
    ↓
[Frontend] ServiceFetcherRow.js → getSummaryAndTlp() 호출
    ↓
[Frontend] ServiceResultRow.jsx → 요약 정보 표시 + 상세 버튼
    ↓
[Frontend] *Details.jsx 컴포넌트 → 전체 데이터 시각화
```

---

## 🎯 1. Frontend: User Input & IOC Detection

### 📁 File: `frontend/src/components/ioc-tools/ioc-lookup/single-lookup/SingleLookup.jsx`

```javascript
// 사용자가 IOC 입력 (예: 8.8.8.8)
const handleValidation = useCallback((iocInput) => {
  const trimmedIoc = iocInput.trim();

  // IOC 타입 자동 감지
  const type = determineIocType(trimmedIoc);  // → "IPv4"

  if (type !== 'unknown') {
    setSearchValue(trimmedIoc);
    setCurrentIocType(type);
    setShouldShowTable(true);  // ResultTable 렌더링
  }
}, []);
```

**역할:**
- IOC 유효성 검증
- IOC 타입 자동 감지 (IPv4, Domain, Hash, URL, Email, CVE)
- ResultTable 렌더링 트리거

---

## 🎯 2. Frontend: Service Filtering

### 📁 File: `frontend/src/components/ioc-tools/ioc-lookup/shared/hooks/useServiceFilter.js`

```javascript
export function useServiceFilter(iocType, externallyFilteredServices) {
  const apiKeys = useRecoilValue(apiKeysState);
  const { serviceDefinitions, loading } = useServiceDefinitions();

  const servicesToRender = useMemo(() => {
    return Object.entries(serviceDefinitions)
      .map(([serviceKey, serviceDef]) => ({ ...serviceDef, key: serviceKey }))
      .filter(serviceDef => {
        // 1. IOC 타입 지원 여부
        if (!serviceDef.supportedIocTypes?.includes(iocType)) {
          return false;
        }

        // 2. API 키 등록 여부
        if (!serviceDef.isAvailable) {
          return false;
        }

        return true;
      })
      .map(serviceDef => {
        const frontendConfig = SERVICE_DEFINITIONS[serviceDef.key] || {};

        return {
          ...serviceDef,
          detailComponent: frontendConfig.detailComponent,  // VirustotalDetails
          getSummaryAndTlp: frontendConfig.getSummaryAndTlp,  // 요약 생성 함수
          icon: frontendConfig.icon,
          lookupEndpoint: (ioc, iocType) =>
            `/api/ioc/lookup/${serviceDef.key}?ioc=${encodeURIComponent(ioc)}&ioc_type=${encodeURIComponent(iocType)}`,
        };
      });
  }, [iocType, serviceDefinitions, loading]);

  return servicesToRender;
}
```

**역할:**
- IOC 타입별로 지원 가능한 서비스 필터링
- API 키 활성화 여부 확인
- 프론트엔드 설정 (아이콘, 상세 컴포넌트, 요약 함수) 병합

---

## 🎯 3. Frontend: Parallel API Calls

### 📁 File: `frontend/src/components/ioc-tools/ioc-lookup/single-lookup/components/ui/ServiceFetcherRow.js`

```javascript
function ServiceFetcherRow({ ioc, iocType, serviceConfigEntry }) {
  const [loading, setLoading] = useState(true);
  const [apiResult, setApiResult] = useState(null);
  const [displayProps, setDisplayProps] = useState({ summary: "Loading...", tlp: 'WHITE' });

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);

      // 1. API 엔드포인트 생성
      const apiUrl = serviceConfigEntry.lookupEndpoint(ioc, iocType);
      // 예: "/api/ioc/lookup/virustotal?ioc=8.8.8.8&ioc_type=IPv4"

      try {
        // 2. 백엔드 API 호출
        const response = await api.get(apiUrl);

        // 3. 전체 응답 저장
        setApiResult(response.data);

        // 4. 요약 정보 생성 (getSummaryAndTlp)
        setDisplayProps(getDisplayData(response.data));
      } catch (error) {
        // 에러 처리
        const errorData = {
          error: error.response?.status || 'NETWORK_ERROR',
          message: error.response?.data?.detail || error.message,
        };
        setApiResult(errorData);
        setDisplayProps(getDisplayData(errorData));
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [ioc, iocType, serviceConfigEntry]);

  return (
    <ServiceResultRow
      service={serviceForChild}
      loading={loading}
      result={apiResult}  // 전체 응답 데이터
      summary={displayProps.summary}  // 요약 정보
      tlp={displayProps.tlp}  // 위협 레벨 색상
      ioc={ioc}
      iocType={iocType}
    />
  );
}
```

**역할:**
- 각 서비스별로 **병렬**로 API 호출
- 전체 응답 데이터 저장 (상세 정보용)
- 요약 정보 생성 (테이블 표시용)

---

## 🎯 4. Backend: Routing

### 📁 File: `backend/app/features/ioc_tools/ioc_lookup/single_lookup/routers/unified_routes.py`

```python
@router.get("/api/ioc/lookup/{service}", tags=["IOC Lookup"])
async def unified_lookup(
    service: str,  # "virustotal"
    ioc: str = Query(..., description="The IOC value to lookup"),  # "8.8.8.8"
    ioc_type: Optional[str] = Query(None, description="The IOC type"),  # "IPv4"
    db: Session = Depends(get_db)
):
    logger.info(f"Received lookup request for service={service}, ioc={ioc[:20]}...")

    # IOC 타입 감지 (클라이언트가 안 보냈을 경우)
    detected_ioc_type = ioc_type or determine_ioc_type(ioc)
    if detected_ioc_type == IOC_TYPES['UNKNOWN']:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid or unsupported IOC format for: {ioc}"
        )

    # 실제 lookup 수행
    result = lookup_ioc(service, ioc, detected_ioc_type, db)
    return result
```

**역할:**
- 서비스별 라우팅 (`/api/ioc/lookup/virustotal`, `/api/ioc/lookup/abuseipdb`, etc.)
- IOC 타입 재검증
- 통합 lookup 엔진 호출

---

## 🎯 5. Backend: Lookup Engine

### 📁 File: `backend/app/features/ioc_tools/ioc_lookup/single_lookup/service/ioc_lookup_engine.py`

```python
def lookup_ioc(service_name: str, ioc: str, ioc_type: str, db: Session, **kwargs) -> Dict[str, Any]:
    """
    통합 IOC Lookup 엔진
    """
    logger.info(f"Starting IOC lookup for service={service_name}, ioc_type={ioc_type}")

    # 1. 서비스 레지스트리에서 설정 조회
    service_config = service_registry.get_service(service_name)
    if not service_config:
        return {"error": 404, "message": f"Service '{service_name}' not found."}

    # 2. IOC 타입 지원 여부 확인
    if ioc_type not in service_config.get('supported_ioc_types', []):
        return {
            "error": 400,
            "message": f"Service '{service_name}' does not support IOC type '{ioc_type}'.",
        }

    # 3. API 키 조회
    api_keys = _get_api_keys(service_config, db)
    if api_keys is None and _requires_api_key(service_config):
        return {"error": 401, "message": f"Required API key(s) for '{service_name}' are missing."}

    # 4. 함수 인자 준비
    func_args = _prepare_function_args(service_config, ioc, ioc_type, api_keys, **kwargs)

    try:
        # 5. 실제 외부 API 호출 함수 실행
        result = service_config['func'](**func_args)
        # service_config['func'] = external_api_clients.virustotal
        logger.info(f"Successfully completed lookup for {service_name}")
        return result
    except Exception as e:
        logger.error(f"Critical error in {service_name} lookup: {str(e)}", exc_info=True)
        return {"error": 500, "message": f"An unexpected error occurred in service '{service_name}'."}
```

**역할:**
- 서비스 레지스트리 조회
- API 키 검증 및 주입
- 외부 API 클라이언트 함수 호출

---

## 🎯 6. Backend: External API Clients

### 📁 File: `backend/app/features/ioc_tools/ioc_lookup/single_lookup/service/external_api_clients.py`

```python
def virustotal(ioc: str, type: str, apikey: str) -> Dict[str, Any]:
    """
    VirusTotal API v3 호출
    """
    if not apikey:
        return {"error": 401, "message": "VirusTotal API key is missing."}

    type_map = {'ip': 'ip_addresses', 'domain': 'domains', 'url': 'urls', 'hash': 'files'}
    indicator_type = type_map.get(type, 'ip_addresses')

    if indicator_type == 'urls':
        ioc_safe = b64encode(ioc.encode()).decode().strip("=")
    else:
        ioc_safe = ioc

    logger.debug(f"Checking {type} {ioc} with VirusTotal")

    # 실제 외부 API 호출
    response = requests.get(
        url=f'https://www.virustotal.com/api/v3/{indicator_type}/{ioc_safe}',
        headers={'x-apikey': apikey}
    )

    # 에러 처리 및 JSON 반환
    return handle_request_errors("VirusTotal", response)
```

**예시 응답 (VirusTotal):**
```json
{
  "data": {
    "id": "8.8.8.8",
    "type": "ip_address",
    "attributes": {
      "last_analysis_stats": {
        "harmless": 80,
        "malicious": 2,
        "suspicious": 1,
        "undetected": 5,
        "timeout": 0
      },
      "last_analysis_results": {
        "Kaspersky": {
          "category": "malicious",
          "result": "malware",
          "method": "blacklist"
        },
        "Sophos": {
          "category": "harmless",
          "result": "clean",
          "method": "blacklist"
        }
        // ... 80개 이상의 엔진
      },
      "whois": "...",
      "reputation": -5,
      "country": "US",
      // ... 더 많은 필드
    }
  }
}
```

**역할:**
- 실제 외부 API 호출 (VirusTotal, AbuseIPDB, etc.)
- 에러 핸들링 (429 Rate Limit, 401 Unauthorized, etc.)
- **원본 JSON 응답을 그대로 반환** (가공하지 않음!)

---

## 🎯 7. Frontend: Summary Generation

### 📁 File: `frontend/src/components/ioc-tools/ioc-lookup/shared/config/serviceConfig.js`

```javascript
export const SERVICE_DEFINITIONS = {
  virustotal: {
    name: 'VirusTotal',
    icon: 'vt_logo_small',
    detailComponent: VirustotalDetailsComponent,  // 상세 컴포넌트
    requiredKeys: ['virustotal'],
    supportedIocTypes: ['IPv4', 'IPv6', 'Domain', 'URL', 'MD5', 'SHA1', 'SHA256'],

    // 🔑 핵심: 요약 정보 생성 함수
    getSummaryAndTlp: (responseData) => {
      if (responseData?.error)
        return { summary: `Error: ${responseData.message}`, tlp: 'WHITE' };

      const stats = responseData.data?.attributes?.last_analysis_stats;
      if (!stats)
        return { summary: "No analysis data", tlp: 'WHITE' };

      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const total = (stats.harmless || 0) + malicious + suspicious +
                    (stats.timeout || 0) + (stats.undetected || 0);

      let tlp = 'GREEN';
      if (malicious > 0) tlp = 'RED';
      else if (suspicious > 0) tlp = 'AMBER';

      return {
        summary: `Detected as malicious or suspicious by ${malicious + suspicious}/${total} engines`,
        tlp,
        keyMetric: `${malicious + suspicious}/${total}`
      };
    },
  },

  abuseipdb: {
    name: 'AbuseIPDB',
    detailComponent: AbuseIpdbDetails,
    getSummaryAndTlp: (responseData) => {
      if (responseData?.error)
        return { summary: `Error: ${responseData.message}`, tlp: 'WHITE' };

      const { abuseConfidenceScore } = responseData.data;

      let tlp = 'GREEN';
      if (abuseConfidenceScore >= 75) tlp = 'RED';
      else if (abuseConfidenceScore >= 25) tlp = 'AMBER';

      return {
        summary: `Abuse Score: ${abuseConfidenceScore}%`,
        tlp,
        keyMetric: `${abuseConfidenceScore}%`
      };
    },
  },

  // ... 20개 이상의 서비스
};
```

**역할:**
- 백엔드 원본 응답을 받아서 **요약 정보 생성**
- TLP (Traffic Light Protocol) 색상 결정:
  - `RED`: 악성/위험
  - `AMBER`: 의심스러움
  - `GREEN`: 안전/정상
  - `BLUE`: 정보성
  - `WHITE`: 알 수 없음/에러
- 테이블에 표시될 한 줄 요약 텍스트 생성

---

## 🎯 8. Frontend: Table Display

### 📁 File: `frontend/src/components/ioc-tools/ioc-lookup/single-lookup/components/ui/ServiceResultRow.jsx`

```javascript
function ServiceResultRow({ service, loading, result, summary, tlp, ioc, iocType }) {
  const [detailsOpen, setDetailsOpen] = useState(false);

  return (
    <>
      <TableRow>
        {/* 1. Status Icon */}
        <TableCell>
          {loading ? (
            <CircularProgress size={20} />
          ) : (
            <StatusIcon tlp={tlp} />  // RED, AMBER, GREEN, etc.
          )}
        </TableCell>

        {/* 2. Service Name & Icon */}
        <TableCell>
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <img src={`/icons/${service.icon}.png`} alt={service.name} />
            <Typography>{service.name}</Typography>
          </Box>
        </TableCell>

        {/* 3. Summary Text */}
        <TableCell>
          {loading ? (
            "Loading..."
          ) : (
            <Typography color={getTlpColor(tlp)}>
              {summary}
            </Typography>
          )}
        </TableCell>

        {/* 4. Details Button */}
        <TableCell>
          <IconButton onClick={() => setDetailsOpen(!detailsOpen)}>
            {detailsOpen ? <ExpandLess /> : <ExpandMore />}
          </IconButton>
        </TableCell>
      </TableRow>

      {/* 5. 상세 정보 (접었다 펼 수 있음) */}
      <TableRow>
        <TableCell colSpan={4}>
          <Collapse in={detailsOpen}>
            {service.detailComponent && (
              <service.detailComponent
                result={result}  // 백엔드 원본 전체 JSON
                ioc={ioc}
              />
            )}
          </Collapse>
        </TableCell>
      </TableRow>
    </>
  );
}
```

**화면 예시:**

| 상태 | 서비스 | 결과 | 상세 |
|------|--------|------|------|
| 🔴 | VirusTotal | Detected as malicious by 3/88 engines | ▼ |
| 🟢 | AbuseIPDB | Abuse Score: 0% | ▶ |
| 🟠 | AlienVault OTX | Found in 2 pulses | ▶ |

**역할:**
- 각 서비스별로 한 줄씩 표시
- TLP 색상 아이콘
- 요약 정보 표시
- 상세 정보 토글 버튼

---

## 🎯 9. Frontend: Detailed Visualization

### 📁 File: `frontend/src/components/ioc-tools/ioc-lookup/shared/services/Virustotal/VirustotalDetails.jsx`

```javascript
export default function VirustotalDetailsComponent({ result, ioc }) {
  // 에러 체크
  if (!result) {
    return <NoDetails message="Loading VirusTotal details..." />;
  }

  if (result.error || result.data?.error) {
    const errorMessage = result.error?.message || "Unknown error";
    return <NoDetails message={`Error: ${errorMessage}`} />;
  }

  if (!result.data || !result.data.attributes) {
    return <NoDetails message={`No data found for "${ioc}"`} />;
  }

  // 실제 데이터 추출
  const attributes = result.data.attributes;
  const analysisStats = attributes.last_analysis_stats || {};

  const malCount = analysisStats.malicious || 0;
  const totalEngines = (analysisStats.harmless || 0) +
                       (analysisStats.malicious || 0) +
                       (analysisStats.suspicious || 0) +
                       (analysisStats.timeout || 0) +
                       (analysisStats.undetected || 0);

  return (
    <Box sx={{ margin: 1, mt:0 }}>
      {/* 1. 기본 정보 + 통계 */}
      <Box sx={{ display: 'flex', flexDirection: 'row', gap: 2 }}>
        <Details malCount={malCount} result={result} ioc={ioc} />
        <AnalysisStatistics
            malCount={malCount}
            totalEngines={totalEngines}
            result={result}
        />
      </Box>

      {/* 2. Tags */}
      {attributes.tags && attributes.tags.length > 0 && (
        <Tags result={result} />
      )}

      {/* 3. Type Tags */}
      {attributes.type_tags && attributes.type_tags.length > 0 && (
        <TypeTags result={result} />
      )}

      {/* 4. Threat Classification */}
      {attributes.popular_threat_classification && (
        <ThreatClassification result={result} />
      )}

      {/* 5. Crowdsourced Context */}
      {attributes.crowdsourced_context && attributes.crowdsourced_context.length > 0 && (
        <CrowdsourcedContext result={result} />
      )}

      {/* 6. Popularity Ranks */}
      {attributes.popularity_ranks && Object.keys(attributes.popularity_ranks).length > 0 && (
        <PopularityRanks result={result} />
      )}

      {/* 7. Filenames (hash 타입일 때) */}
      {attributes.names && attributes.names.length > 0 && (
        <Filenames result={result} />
      )}

      {/* 8. ELF Information (hash 타입일 때) */}
      {attributes.elf_info && attributes.elf_info.section_list?.length > 0 && (
        <ELFInformation result={result} />
      )}

      {/* 9. Crowdsourced IDS Rules */}
      {attributes.crowdsourced_ids_results && attributes.crowdsourced_ids_results.length > 0 && (
        <CrowdsourcedIDSRules result={result} />
      )}

      {/* 10. Last Analysis Results (88개 엔진 결과) */}
      {attributes.last_analysis_results && Object.keys(attributes.last_analysis_results).length > 0 && (
        <LastAnalysisResults result={result} />
      )}

      {/* 11. WHOIS Information */}
      {attributes.whois && (
        <Whois result={result} />
      )}
    </Box>
  );
}
```

**역할:**
- 백엔드 원본 JSON 전체를 받아서 **모든 필드 시각화**
- 조건부 렌더링 (데이터가 있을 때만 해당 섹션 표시)
- MUI 컴포넌트로 깔끔하게 표시:
  - Card, Box, Typography
  - Table, Chip, Alert
  - Accordion, Grid

---

## 🎨 Visualization Examples

### VirusTotal Details 화면 구성:

```
┌─────────────────────────────────────────────────────────────┐
│ VirusTotal Details                                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌───────────────────┐  ┌───────────────────────────────┐  │
│  │ Basic Details     │  │ Analysis Statistics           │  │
│  │ ─────────────     │  │ ───────────────────           │  │
│  │ IP: 8.8.8.8       │  │ 🔴 Malicious:        2 (2%)   │  │
│  │ Country: US       │  │ 🟠 Suspicious:       1 (1%)   │  │
│  │ ASN: 15169        │  │ 🟢 Harmless:        80 (91%)  │  │
│  │ Reputation: -5    │  │ ⚪ Undetected:        5 (6%)   │  │
│  └───────────────────┘  │ Total Engines:      88        │  │
│                         └───────────────────────────────┘  │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Tags                                                  │  │
│  │ ───────                                               │  │
│  │  [dns]  [google]  [public-dns]                        │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Last Analysis Results (88 engines)                    │  │
│  │ ────────────────────────────────                      │  │
│  │  ✓ Kaspersky          malicious   malware             │  │
│  │  ✓ Sophos             harmless    clean               │  │
│  │  ✓ BitDefender        harmless    clean               │  │
│  │  ... (85 more)                                         │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ WHOIS Information                                      │  │
│  │ ─────────────────                                      │  │
│  │  Google LLC                                            │  │
│  │  1600 Amphitheatre Parkway                             │  │
│  │  Mountain View, CA 94043                               │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 📊 Data Transformation Layers

### Layer 1: External API (Raw JSON)
```json
{
  "data": {
    "attributes": {
      "last_analysis_stats": {
        "malicious": 2,
        "harmless": 80,
        "suspicious": 1,
        "undetected": 5
      },
      "last_analysis_results": { /* 88개 엔진 */ },
      "whois": "...",
      "reputation": -5
    }
  }
}
```

### Layer 2: Backend Passthrough (No Transformation)
- **백엔드는 데이터를 가공하지 않고 그대로 전달**
- 에러 핸들링만 수행

### Layer 3: Frontend Summary (serviceConfig.js)
```javascript
{
  summary: "Detected as malicious by 3/88 engines",
  tlp: "RED",
  keyMetric: "3/88"
}
```

### Layer 4: Frontend Detail Visualization (*Details.jsx)
- **원본 JSON 전체를 받아서 모든 필드 시각화**
- 조건부 렌더링으로 존재하는 데이터만 표시
- MUI 컴포넌트로 사용자 친화적으로 표시

---

## 🔑 Key Design Patterns

### 1. **Backend: Minimal Processing**
- 백엔드는 외부 API 응답을 **가공하지 않고 그대로 반환**
- 장점:
  - 프론트엔드가 모든 데이터에 접근 가능
  - 백엔드 로직이 단순함
  - API 응답 구조가 변경되어도 백엔드 수정 불필요

### 2. **Frontend: Two-Stage Display**
- **Stage 1: Summary (테이블 행)**
  - `getSummaryAndTlp()` 함수로 한 줄 요약 생성
  - TLP 색상으로 위험도 시각화
  - 빠른 스캔 가능

- **Stage 2: Details (펼침 패널)**
  - 전체 JSON 데이터를 받아 상세 시각화
  - 필요할 때만 로드 (성능 최적화)
  - 서비스별로 전용 컴포넌트 사용

### 3. **Service Configuration Pattern**
```javascript
{
  name: "VirusTotal",
  icon: "vt_logo_small",
  detailComponent: VirustotalDetails,  // React Component
  getSummaryAndTlp: (data) => {...},   // Function
  supportedIocTypes: [...],
  requiredKeys: [...]
}
```
- 각 서비스별 설정을 한 곳에 집중
- 새 서비스 추가가 쉬움
- 프론트엔드와 백엔드가 동일한 service key 사용

### 4. **Parallel API Calls**
- `ServiceFetcherRow`가 각 서비스별로 독립적으로 API 호출
- 병렬 처리로 빠른 응답 시간
- 한 서비스 에러가 다른 서비스에 영향 없음

---

## 🚀 Adding a New Service

### 1. Backend: Register Service

**File:** `backend/app/features/ioc_tools/ioc_lookup/single_lookup/service/service_registry.py`

```python
_services.update({
    'newservice': {
        'func': ioc_lookup_service_module.newservice_lookup,
        'name': 'New Service',
        'api_key_name': 'newservice_key',
        'supported_ioc_types': [IOC_TYPES['IPV4'], IOC_TYPES['DOMAIN']],
    }
})
```

### 2. Backend: Implement API Client

**File:** `backend/app/features/ioc_tools/ioc_lookup/single_lookup/service/external_api_clients.py`

```python
def newservice_lookup(ioc: str, apikey: str) -> Dict[str, Any]:
    if not apikey:
        return {"error": 401, "message": "API key missing"}

    response = requests.get(
        url=f'https://api.newservice.com/lookup/{ioc}',
        headers={'Authorization': f'Bearer {apikey}'}
    )
    return handle_request_errors("NewService", response)
```

### 3. Frontend: Add Service Definition

**File:** `frontend/src/components/ioc-tools/ioc-lookup/shared/config/serviceConfig.js`

```javascript
import NewServiceDetails from '../services/NewService/NewServiceDetails';

export const SERVICE_DEFINITIONS = {
  // ... existing services

  newservice: {
    name: 'New Service',
    icon: 'newservice_logo_small',
    detailComponent: NewServiceDetails,
    requiredKeys: ['newservice_key'],
    supportedIocTypes: ['IPv4', 'Domain'],
    lookupEndpoint: createSingleEndpoint('newservice'),
    getSummaryAndTlp: (responseData) => {
      if (responseData?.error)
        return { summary: `Error: ${responseData.message}`, tlp: 'WHITE' };

      const risk = responseData.risk_score;
      let tlp = 'GREEN';
      if (risk >= 70) tlp = 'RED';
      else if (risk >= 40) tlp = 'AMBER';

      return {
        summary: `Risk Score: ${risk}`,
        tlp,
        keyMetric: risk
      };
    },
  },
};
```

### 4. Frontend: Create Detail Component

**File:** `frontend/src/components/ioc-tools/ioc-lookup/shared/services/NewService/NewServiceDetails.jsx`

```javascript
import React from 'react';
import { Box, Card, Typography } from '@mui/material';
import NoDetails from '../NoDetails';

export default function NewServiceDetails({ result, ioc }) {
  if (!result || result.error) {
    return <NoDetails message="No data available" />;
  }

  return (
    <Box sx={{ margin: 1 }}>
      <Card>
        <Typography variant="h6">New Service Details</Typography>
        <Typography>IOC: {ioc}</Typography>
        <Typography>Risk Score: {result.risk_score}</Typography>
        <Typography>Threat Type: {result.threat_type}</Typography>
        {/* ... 더 많은 필드 */}
      </Card>
    </Box>
  );
}
```

### 5. Add Service Icon

**File:** `frontend/public/icons/newservice_logo_small.png`
- 작은 아이콘 이미지 추가 (32x32px 권장)

---

## 📝 Summary

### 데이터 흐름 요약:

1. **사용자 입력** → IOC 감지 및 유효성 검증
2. **서비스 필터링** → IOC 타입별 지원 가능한 서비스 선택
3. **병렬 API 호출** → 각 서비스별로 백엔드 API 호출
4. **백엔드 라우팅** → 통합 엔드포인트에서 서비스별 분기
5. **API 키 검증** → DB에서 API 키 조회 및 활성화 확인
6. **외부 API 호출** → 실제 위협 정보 서비스 호출
7. **원본 응답 반환** → 백엔드가 가공 없이 전달
8. **요약 생성** → 프론트엔드에서 한 줄 요약 생성
9. **테이블 표시** → 요약 정보 + TLP 색상 표시
10. **상세 시각화** → 사용자가 펼칠 때 전체 데이터 시각화

### 핵심 원칙:

- ✅ **Backend**: 데이터 가공 최소화, 원본 전달
- ✅ **Frontend**: 요약/상세 2단계 표시
- ✅ **Parallel**: 서비스별 독립적 병렬 호출
- ✅ **Modular**: 새 서비스 추가 용이한 구조

---

## 🔗 Related Files

### Backend:
- `backend/app/features/ioc_tools/ioc_lookup/single_lookup/routers/unified_routes.py`
- `backend/app/features/ioc_tools/ioc_lookup/single_lookup/service/ioc_lookup_engine.py`
- `backend/app/features/ioc_tools/ioc_lookup/single_lookup/service/service_registry.py`
- `backend/app/features/ioc_tools/ioc_lookup/single_lookup/service/external_api_clients.py`

### Frontend:
- `frontend/src/components/ioc-tools/ioc-lookup/single-lookup/SingleLookup.jsx`
- `frontend/src/components/ioc-tools/ioc-lookup/single-lookup/components/ui/ResultTable.js`
- `frontend/src/components/ioc-tools/ioc-lookup/single-lookup/components/ui/ServiceFetcherRow.js`
- `frontend/src/components/ioc-tools/ioc-lookup/single-lookup/components/ui/ServiceResultRow.jsx`
- `frontend/src/components/ioc-tools/ioc-lookup/shared/config/serviceConfig.js`
- `frontend/src/components/ioc-tools/ioc-lookup/shared/hooks/useServiceFilter.js`
- `frontend/src/components/ioc-tools/ioc-lookup/shared/services/Virustotal/VirustotalDetails.jsx`

---

**Last Updated:** 2025-10-13
