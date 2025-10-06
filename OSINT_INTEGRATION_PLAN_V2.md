# OSINT 프로파일링 자동화 통합 계획서 (v2.0)

**업데이트 날짜**: 2025-10-07
**변경 사항**: Week 2-3 프론트엔드 통합 전략 수정 (중복 제거 + 점진적 검증)

---

## 📋 프로젝트 개요

### 목표
기존 AOL_SERVICE_DEMO 프로젝트에 **ChatGPT 스타일 대화형 UI**를 갖춘 LLM 기반 OSINT 자동화 기능 추가.
사용자가 이메일/IP/도메인 등을 입력하면 LLM이 자동으로 적절한 도구를 선택하고 순서를 결정하여 조사를 수행.

### 현재 상태 (2025-10-07 기준)
- ✅ **18개 OSINT API 클라이언트 구현됨** (유료 6개 제거 완료)
- ✅ **LLM 서비스 구축됨** - OpenAI, Anthropic, Google 지원
- ✅ **API 키 관리 시스템** 완성
- ✅ **osint_profiler 모듈 생성** - 디렉토리 구조 완성
- ✅ **Email Tools 3개 구현 완료** (HIBP, EmailRep, Hunter.io)
- ❌ **IP/Domain/Hash/URL Tools** - 미완성 (15개 남음)
- ❌ **ReAct Agent** - 미완성
- ❌ **Knowledge Agent** - 미완성
- ❌ **대화형 프론트엔드** - 미완성

### 최종 목표
```
사용자 입력: "araiunity@gmail.com"
    ↓
[ChatGPT 스타일 UI]
    ↓
LLM Agent 자동 분석:
  1. 이메일 유형 식별 ✓
  2. HIBP → EmailRep → Hunter 순서 실행 ✓
  3. 도메인 "gmail.com" 발견 → 자동 확장 조사 ✓
  4. 최종 보고서 생성 ✓
```

---

## 📅 Phase 1: 핵심 통합 (3주)

### ⚠️ **주요 변경사항 (v2.0)**

**문제점 (v1.0):**
- Email/IP/Domain Feed별로 대화형 UI 3개 따로 개발 → **중복 코드 600줄**
- 백엔드 완성 후 프론트 개발 → **검증 지연 리스크**

**해결 방안 (v2.0):**
- **공용 `OSINTChat` 컴포넌트 1개만 개발** → 각 Feed에 임베드
- **Week 2에 프론트 통합** → 즉시 검증 + 빠른 피드백

---

## 📆 Week 1: LangChain Tools 완성 (7일)

### 목표
18개 OSINT API를 LangChain StructuredTool로 변환

### 진행 상황
- ✅ **완료**: Email Tools 3개 (HIBP, EmailRep, Hunter)
- 🔜 **남은 작업**: IP Tools 5개, Domain Tools 3개, Hash Tools 3개, URL/GitHub/Misc Tools 6개

### Day 1-2: IP Tools 구현 (5개)
```python
# backend/app/features/osint_profiler/tools/langchain_wrappers.py

def create_ip_tools(self) -> List[Tool]:
    """
    IP 분석 도구 5개 생성
    1. AbuseIPDB - IP 평판 및 악성 활동 보고
    2. VirusTotal - 멀티 엔진 IP 위협 분석
    3. Shodan - 인프라/포트/서비스 정보
    4. CrowdSec - 커뮤니티 기반 IP 평판
    5. AlienVault OTX - 위협 인텔리전스
    """
    # IPvAnyAddress Pydantic 검증
    # StructuredTool.from_function 사용
    # USE WHEN/RETURNS/LIMIT/DON'T USE 섹션
```

### Day 3-4: Domain/Hash Tools 구현 (6개)
- Domain Tools 3개: VirusTotal, URLScan.io, SafeBrowsing
- Hash Tools 3개: VirusTotal, MalwareBazaar, ThreatFox

### Day 5: URL/GitHub/Misc Tools 구현 (6개)
- URL Tools 1개: URLhaus
- GitHub Tools 1개: Code Search
- Misc Tools 4개: BGPView, NIST NVD, Pulsedive, Reddit

### Day 6-7: 테스트 작성 및 실행
```bash
# backend/tests/test_osint_tools_wrapper.py
pytest tests/test_osint_tools_wrapper.py -v

# 예상 출력:
# test_tool_factory_initialization PASSED
# test_create_all_tools PASSED (18개 확인)
# test_email_tools_execution PASSED
# test_ip_tools_execution PASSED
```

### Week 1 완료 기준
- ✅ 18개 LangChain StructuredTool 생성 완료
- ✅ 모든 테스트 통과 (pytest 100%)
- ✅ API 키 로드 정상 동작
- ✅ 각 Tool description 명확히 작성 (영어 + 한글 주석)

---

## 📆 Week 2: ReAct Agent + 대화형 프론트엔드 통합 (7일)

### ⭐ **핵심 변경: 백엔드 + 프론트 동시 개발**

### Day 1-3: ReAct Agent 백엔드 (3일)

#### 2.1 LLM Map-Reduce 유틸리티
**파일:** `backend/app/features/osint_profiler/utils/content_processor.py`
- 대용량 텍스트 청크 분할
- Map-Reduce 패턴으로 요약

#### 2.2 ReAct Agent 구현
**파일:** `backend/app/features/osint_profiler/agents/web_agent.py`

```python
class OSINTWebAgent:
    """
    ReAct 패턴 OSINT 조사 에이전트

    Thought (생각) → Action (도구 실행) → Observation (결과 분석) 루프
    """

    def __init__(self, db: Session, llm_model: str = "gpt-4"):
        self.llm = self._setup_llm()  # ChatOpenAI/ChatAnthropic/ChatGoogleGenerativeAI
        self.tools = OSINTToolFactory(db).create_all_tools()  # 18개 도구

        # LangChain ReAct Agent 초기화
        self.agent = initialize_agent(
            tools=self.tools,
            llm=self.llm,
            agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
            max_iterations=10
        )

    async def investigate(self, query: str, context: str = "") -> Dict[str, Any]:
        """
        OSINT 조사 수행

        Returns:
            {
                "query": "araiunity@gmail.com",
                "result": "조사 결과 최종 결론...",
                "intermediate_steps": [...],  # 실행된 도구 목록
                "tool_calls": 3
            }
        """
```

#### 2.3 FastAPI 엔드포인트
**파일:** `backend/app/features/osint_profiler/routers/osint_routes.py`

```python
@router.post("/api/osint/investigate")
async def investigate_ioc(request: InvestigationRequest, db: Session = Depends(get_db)):
    """
    LLM 자동 조사 엔드포인트

    Request:
        query: "1.2.3.4"
        context: "의심스러운 IP"
        llm_model: "gpt-4"
        max_iterations: 10

    Response:
        result: "조사 결과..."
        tool_calls: 3
        intermediate_steps: [...]
    """
    agent = OSINTWebAgent(db, llm_model=request.llm_model)
    result = await agent.investigate(request.query, request.context)
    return result
```

#### 2.4 메인 앱에 라우터 등록
```python
# backend/app/main.py
from app.features.osint_profiler.routers import osint_routes

app.include_router(osint_routes.router)
```

---

### Day 4-5: 공용 대화형 UI 컴포넌트 (2일)

#### ⭐ **핵심: 재사용 가능한 단일 컴포넌트**

**파일:** `frontend/src/components/osint-profiler/OSINTChat.jsx`

```jsx
import React, { useState } from 'react';
import { Box, TextField, IconButton, Paper, Typography, CircularProgress } from '@mui/material';
import SendIcon from '@mui/icons-material/Send';
import api from '../../api';

/**
 * 공용 OSINT 대화형 컴포넌트 (재사용 가능)
 *
 * Props:
 *   - initialQuery: 초기 쿼리 (선택)
 *   - endpoint: API 엔드포인트 (기본: /api/osint/investigate)
 *   - context: 추가 컨텍스트 (선택)
 *   - placeholder: 입력창 힌트 (선택)
 */
export default function OSINTChat({
  initialQuery = '',
  endpoint = '/api/osint/investigate',
  context = '',
  placeholder = '이메일, IP, 도메인 입력...'
}) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState(initialQuery);
  const [loading, setLoading] = useState(false);

  const handleSend = async () => {
    if (!input.trim() || loading) return;

    // User 메시지 추가
    const userMsg = {
      role: 'user',
      content: input,
      timestamp: new Date()
    };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      // ✅ ReAct Agent API 호출
      const response = await api.post(endpoint, {
        query: input,
        context: context,
        llm_model: 'gpt-4',
        max_iterations: 10
      });

      // Agent 응답 추가
      const agentMsg = {
        role: 'assistant',
        content: response.data.result,
        tool_calls: response.data.tool_calls || 0,
        intermediate_steps: response.data.intermediate_steps || [],
        timestamp: new Date()
      };
      setMessages(prev => [...prev, agentMsg]);

    } catch (error) {
      console.error('Investigation failed:', error);
      const errorMsg = {
        role: 'error',
        content: `오류: ${error.response?.data?.detail || error.message}`,
        timestamp: new Date()
      };
      setMessages(prev => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box sx={{
      height: 'calc(100vh - 200px)',
      display: 'flex',
      flexDirection: 'column',
      bgcolor: '#fafafa'
    }}>
      {/* 메시지 스레드 (ChatGPT 스타일 스크롤) */}
      <Box sx={{
        flex: 1,
        overflowY: 'auto',
        p: 3,
        display: 'flex',
        flexDirection: 'column',
        gap: 2
      }}>
        {messages.length === 0 && (
          <Box sx={{ textAlign: 'center', mt: 10, color: 'text.secondary' }}>
            <Typography variant="h5" gutterBottom>
              🕵️ OSINT 자동 조사 시작
            </Typography>
            <Typography variant="body1">
              이메일, IP, 도메인을 입력하면 LLM이 자동으로 조사합니다
            </Typography>
          </Box>
        )}

        {messages.map((msg, idx) => (
          <MessageBubble key={idx} message={msg} />
        ))}

        {loading && <LoadingBubble />}
      </Box>

      {/* 하단 고정 입력창 (ChatGPT 스타일) */}
      <Box sx={{
        p: 2,
        borderTop: '1px solid #e0e0e0',
        bgcolor: 'white'
      }}>
        <TextField
          fullWidth
          placeholder={placeholder}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && !e.shiftKey && handleSend()}
          disabled={loading}
          multiline
          maxRows={4}
          InputProps={{
            endAdornment: (
              <IconButton
                onClick={handleSend}
                disabled={loading || !input.trim()}
                color="primary"
              >
                {loading ? <CircularProgress size={24} /> : <SendIcon />}
              </IconButton>
            )
          }}
          sx={{
            '& .MuiOutlinedInput-root': {
              borderRadius: 3,
              bgcolor: '#f5f5f5'
            }
          }}
        />
      </Box>
    </Box>
  );
}

// 메시지 버블 컴포넌트 (ChatGPT 스타일)
function MessageBubble({ message }) {
  const isUser = message.role === 'user';
  const isError = message.role === 'error';

  return (
    <Box sx={{
      display: 'flex',
      justifyContent: isUser ? 'flex-end' : 'flex-start',
      alignItems: 'flex-start'
    }}>
      <Paper
        elevation={1}
        sx={{
          p: 2,
          maxWidth: '75%',
          bgcolor: isError ? '#ffebee' : (isUser ? '#007AFF' : 'white'),
          color: isUser ? 'white' : 'text.primary',
          borderRadius: 2
        }}
      >
        <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap' }}>
          {message.content}
        </Typography>

        {/* Agent 응답에만 도구 호출 정보 표시 */}
        {!isUser && !isError && message.tool_calls > 0 && (
          <Typography
            variant="caption"
            sx={{
              display: 'block',
              mt: 1.5,
              pt: 1.5,
              borderTop: '1px solid #e0e0e0',
              color: 'text.secondary'
            }}
          >
            🛠️ {message.tool_calls} tools used
          </Typography>
        )}

        {/* 타임스탬프 */}
        <Typography
          variant="caption"
          sx={{
            display: 'block',
            mt: 0.5,
            opacity: 0.6,
            fontSize: '0.7rem'
          }}
        >
          {message.timestamp.toLocaleTimeString('ko-KR')}
        </Typography>
      </Paper>
    </Box>
  );
}

// 로딩 버블 (Agent 생각 중 표시)
function LoadingBubble() {
  return (
    <Box sx={{ display: 'flex', justifyContent: 'flex-start' }}>
      <Paper elevation={1} sx={{ p: 2, bgcolor: 'white', borderRadius: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <CircularProgress size={16} />
          <Typography variant="body2" color="text.secondary">
            조사 중...
          </Typography>
        </Box>
      </Paper>
    </Box>
  );
}
```

---

### Day 6-7: 기존 Feed 페이지에 대화형 모드 임베드 (1일)

#### ⭐ **핵심: 2줄 추가로 통합 완료**

#### 6.1 Email Analyzer 통합
**파일:** `frontend/src/components/email-analyzer/EmailAnalyzer.jsx`

```jsx
import React, { useState } from 'react';
import { Box, ToggleButtonGroup, ToggleButton } from '@mui/material';
import OSINTChat from '../osint-profiler/OSINTChat';  // ← Import 추가
import EmailAnalyzerForm from './EmailAnalyzerForm';  // 기존 컴포넌트

export default function EmailAnalyzer() {
  const [viewMode, setViewMode] = useState('traditional');  // 'traditional' | 'chat'

  return (
    <Box sx={{ p: 3 }}>
      {/* 모드 전환 토글 */}
      <ToggleButtonGroup
        value={viewMode}
        exclusive
        onChange={(e, newMode) => newMode && setViewMode(newMode)}
        sx={{ mb: 3 }}
      >
        <ToggleButton value="traditional">기존 방식</ToggleButton>
        <ToggleButton value="chat">🤖 AI 자동 조사</ToggleButton>
      </ToggleButtonGroup>

      {/* 기존 방식 or Chat 모드 */}
      {viewMode === 'traditional' ? (
        <EmailAnalyzerForm />  {/* 기존 컴포넌트 그대로 */}
      ) : (
        <OSINTChat   {/* ← 2줄 추가로 끝! */}
          context="Email security investigation"
          placeholder="이메일 주소 입력 (예: user@example.com)"
        />
      )}
    </Box>
  );
}
```

**작업량: 10분**

---

#### 6.2 IOC Lookup (IP/Domain) 통합
**파일:** `frontend/src/components/ioc-tools/IOCLookup.jsx`

```jsx
import OSINTChat from '../osint-profiler/OSINTChat';

// 똑같이 토글 추가
{viewMode === 'chat' && (
  <OSINTChat
    context="IP/Domain threat analysis"
    placeholder="IP 또는 도메인 입력"
  />
)}
```

**작업량: 10분**

---

#### 6.3 독립 OSINT Chat 페이지 추가
**파일:** `frontend/src/components/osint-profiler/OSINTChatPage.jsx`

```jsx
import React from 'react';
import { Box, Typography, Paper } from '@mui/material';
import OSINTChat from './OSINTChat';

export default function OSINTChatPage() {
  return (
    <Box sx={{ p: 3, height: '100%' }}>
      <Paper elevation={2} sx={{ height: '100%' }}>
        <OSINTChat
          placeholder="이메일, IP, 도메인, URL, 해시 입력..."
        />
      </Paper>
    </Box>
  );
}
```

**라우팅 추가:**
```jsx
// frontend/src/Main.jsx
import OSINTChatPage from './components/osint-profiler/OSINTChatPage';

<Route path="/osint-chat" element={<OSINTChatPage />} />
```

**사이드바 메뉴 추가:**
```js
// frontend/src/sidebarConfig.js
{
  title: "OSINT Chat",
  icon: ChatBubbleIcon,
  path: "/osint-chat",
}
```

**작업량: 30분**

---

### Week 2 완료 기준
- ✅ ReAct Agent 정상 동작 (백엔드)
- ✅ `/api/osint/investigate` 엔드포인트 동작
- ✅ `OSINTChat.jsx` 컴포넌트 완성
- ✅ Email Analyzer에 Chat 모드 추가
- ✅ IOC Lookup에 Chat 모드 추가
- ✅ 독립 OSINT Chat 페이지 추가
- ✅ 실제 조사 테스트 성공 (이메일/IP 각 1건)

**테스트 시나리오:**
```bash
# 백엔드 테스트
curl -X POST "http://localhost:8000/api/osint/investigate" \
  -H "Content-Type: application/json" \
  -d '{"query": "1.2.3.4", "llm_model": "gpt-4"}'

# 프론트엔드 테스트
1. Email Analyzer → Chat 모드 → "araiunity@gmail.com" 입력
2. 결과: HIBP → EmailRep → Hunter 순서로 실행
3. 최종 결과: "유출 이력 없음, 정상 Gmail 계정"
```

---

## 📆 Week 3: Knowledge Agent + 피드백 루프 + 통합 UI (7일)

### Day 1-4: Knowledge Agent 백엔드 (4일)

#### 3.1 Knowledge Agent 구현
**파일:** `backend/app/features/osint_profiler/agents/knowledge_agent.py`

```python
class OSINTKnowledgeAgent:
    """
    LLM 기반 OSINT 조사 오케스트레이터

    여러 ReAct Agent를 조율하고 피드백 루프를 통해 심화 조사 수행
    """

    async def investigate(
        self,
        initial_query: str,
        deep_dive_rounds: int = 2,
        topics_per_round: int = 3,
        max_api_calls: int = 20
    ) -> Dict[str, Any]:
        """
        반복적 OSINT 조사 수행

        Round 0: 초기 조사 (ReAct Agent)
        Round 1: LLM이 추가 주제 결정 → 조사
        Round 2: LLM이 추가 주제 결정 → 조사

        Returns:
            {
                "total_rounds": 3,
                "findings": [round별 발견사항],
                "summary": "최종 요약",
                "total_api_calls": 15
            }
        """
```

#### 3.2 피드백 루프 워크플로우
**파일:** `backend/app/features/osint_profiler/workflows/feedback_loop.py`

```python
class FeedbackLoopWorkflow:
    """
    자동 IOC 확장 조사

    예: 이메일 조사 → 도메인 발견 → 도메인 조사 → IP 발견 → IP 조사
    """

    async def investigate_with_auto_expansion(
        self,
        initial_ioc: str,
        max_expansion_depth: int = 3,
        max_total_iocs: int = 10
    ) -> Dict[str, Any]:
        """
        BFS로 IOC 자동 확장

        Returns:
            {
                "investigated_iocs": ["email", "domain", "ip"],
                "ioc_graph": {
                    "nodes": [...],
                    "edges": [...]
                }
            }
        """
```

#### 3.3 엔드포인트 추가
```python
@router.post("/api/osint/knowledge-agent")
async def knowledge_agent_investigate(request, db):
    """심화 조사 (2-3 라운드)"""

@router.post("/api/osint/feedback-loop")
async def feedback_loop_investigation(request, db):
    """자동 확장 조사 (IOC 그래프)"""
```

---

### Day 5-6: 통합 UI 확장 (2일)

#### ⭐ **핵심: 기존 `OSINTChat` 컴포넌트 확장**

**파일:** `frontend/src/components/osint-profiler/KnowledgeChat.jsx`

```jsx
import React, { useState } from 'react';
import OSINTChat from './OSINTChat';
import { Box, Slider, Typography } from '@mui/material';

export default function KnowledgeChat() {
  const [deepDiveRounds, setDeepDiveRounds] = useState(2);
  const [maxApiCalls, setMaxApiCalls] = useState(20);

  return (
    <Box>
      {/* 설정 패널 */}
      <Box sx={{ mb: 2, p: 2, bgcolor: '#f5f5f5', borderRadius: 2 }}>
        <Typography gutterBottom>심화 조사 라운드: {deepDiveRounds}</Typography>
        <Slider
          value={deepDiveRounds}
          onChange={(e, v) => setDeepDiveRounds(v)}
          min={1}
          max={5}
          marks
        />

        <Typography gutterBottom>최대 API 호출: {maxApiCalls}</Typography>
        <Slider
          value={maxApiCalls}
          onChange={(e, v) => setMaxApiCalls(v)}
          min={10}
          max={50}
          step={5}
        />
      </Box>

      {/* ✅ 기존 OSINTChat 재사용! */}
      <OSINTChat
        endpoint="/api/osint/knowledge-agent"  {/* ← 엔드포인트만 변경 */}
        placeholder="심화 조사할 대상 입력..."
      />

      {/* IOC 그래프 시각화 (선택) */}
      <IOCGraphVisualization />
    </Box>
  );
}
```

**작업량: 2일** (설정 UI + IOC 그래프 시각화)

---

### Day 7: 최종 검증 및 테스트 (1일)

#### 테스트 시나리오

**Scenario 1: ReAct Agent (단순 조사)**
```
Input: "1.2.3.4"
Expected: AbuseIPDB → VirusTotal → Shodan (3 tools)
Time: 20-30초
```

**Scenario 2: Knowledge Agent (심화 조사)**
```
Input: "araiunity@gmail.com"
Round 0: Email 조사 (3 tools)
Round 1: LLM 제안 "gmail.com 도메인 조사" (2 tools)
Round 2: LLM 제안 "GitHub 검색" (1 tool)
Total: 6 tools, 1-2분
```

**Scenario 3: Feedback Loop (자동 확장)**
```
Input: "malicious@phishing-site.com"
Depth 0: Email 조사 → "phishing-site.com" 발견
Depth 1: Domain 조사 → "45.142.212.61" 발견
Depth 2: IP 조사 → "related-domain.com" 발견
Total IOCs: 4개, IOC 그래프 생성
```

---

### Week 3 완료 기준
- ✅ Knowledge Agent 정상 동작
- ✅ 피드백 루프 정상 동작
- ✅ IOC 자동 확장 동작 (이메일 → 도메인 → IP)
- ✅ 통합 UI 완성 (Knowledge Agent 설정 패널)
- ✅ IOC 그래프 시각화 (선택)
- ✅ 모든 테스트 시나리오 성공

---

## 📊 최종 산출물

### 백엔드
```
backend/app/features/osint_profiler/
├── tools/
│   └── langchain_wrappers.py       # 18개 LangChain Tools
├── agents/
│   ├── web_agent.py                # ReAct Agent
│   └── knowledge_agent.py          # Knowledge Agent
├── utils/
│   └── content_processor.py        # Map-Reduce
├── workflows/
│   └── feedback_loop.py            # 자동 IOC 확장
└── routers/
    └── osint_routes.py             # FastAPI 엔드포인트
```

### 프론트엔드
```
frontend/src/components/osint-profiler/
├── OSINTChat.jsx                   # ⭐ 공용 대화형 컴포넌트
├── OSINTChatPage.jsx               # 독립 Chat 페이지
├── KnowledgeChat.jsx               # Knowledge Agent UI
└── IOCGraphVisualization.jsx       # IOC 그래프 (선택)

통합된 페이지:
├── email-analyzer/EmailAnalyzer.jsx    # Chat 모드 추가 ✅
└── ioc-tools/IOCLookup.jsx             # Chat 모드 추가 ✅
```

### API 엔드포인트
```
POST /api/osint/investigate          # Week 2: ReAct Agent
POST /api/osint/knowledge-agent       # Week 3: Knowledge Agent
POST /api/osint/feedback-loop         # Week 3: 자동 확장
GET  /api/osint/tools                 # Week 2: 도구 목록
```

---

## ✅ v2.0 주요 개선사항

| 항목 | v1.0 (원래 계획) | v2.0 (수정) | 개선 효과 |
|------|-----------------|------------|----------|
| **프론트 개발 시점** | Week 3.5 별도 | Week 2 통합 | ✅ 1주 단축 |
| **대화형 UI 개수** | Email/IP/Domain 3개 | 공용 1개 | ✅ 중복 -600줄 |
| **백엔드 검증** | Week 3.5 시작 시 | Week 2 중간 | ✅ 빠른 피드백 |
| **유지보수** | 3곳 수정 필요 | 1곳만 수정 | ✅ 유지보수 1/3 |
| **총 작업 기간** | 3주 + 9일 | 3주 | ✅ 9일 절감 |

---

## 🚀 다음 단계

1. **지금**: IP Tools 5개 구현 (Step 5)
2. Domain/Hash/URL Tools 완성
3. Week 2: ReAct Agent + 공용 Chat UI
4. Week 3: Knowledge Agent + 통합
5. Phase 2: Profil3r 통합 (선택)

**예상 완료일**: 2025년 10월 28일 (3주 후)

---

## 📝 저작권 고지

**LLM_OSINT** (MIT License)
Original: https://github.com/ShrivuShankar/LLM_OSINT
Author: Shrivu Shankar

우리는 아이디어와 패턴만 참고하여 **우리 프로젝트에 맞게 재작성**했습니다.
