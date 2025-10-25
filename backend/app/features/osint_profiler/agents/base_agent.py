"""
BaseOSINTAgent - 모든 OSITNT Agent의 추상 기본 클래스
핵심 기능 : 
1. Langchain ReAct Agent 패턴 구현
2. LLM 연동 (OpenAI, Anthropic, Google)
3. Structed Output (프론트엔드 + LangGraph 호환)
"""

from abc import ABC, abstractmethod # 필수 추상 클래스 구현 명시 기능
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session
from datetime import datetime
import ipaddress
import logging
import re

# Langchain imports
from langchain.agents import initialize_agent, AgentType, AgentExecutor
from langchain.tools import Tool
from langchain_core.language_models import BaseChatModel

logger = logging.getLogger(__name__)

class BaseOSINTAgent(ABC):
    """
    모든 OSINT Agent의 추상 기본 클래스
    자식 클래스는 _create_tools() 메서드를 통해 본인이 사용할 도구들 정의.
    나머지 (LLM 초기화, Agent 실행, 결과 포맷팅)는 부모가 처리함.
    """

    def __init__(
        self,
        db: Session,
        llm_model: str="gpt-4", # OpenAI API 키로 테스트 (gpt-4)
        temperature: float = 0.7, # LLM 창의성 조절 (0=결정론적, 1=창의적)
        max_iterations: int = 10,
        verbose: bool = True
    ):
        """Agent 초기화"""
        self.db = db
        self.llm_model = llm_model
        self.temperature = temperature
        self.max_iterations = max_iterations
        self.verbose = verbose

        # LLM 초기화
        self.llm = self._setup_llm(llm_model)

        # 도구 생성
        self.tools = self._create_tools()

        # Agent 초기화
        self.agent = self._initialize_agent()

    def _setup_llm(self, llm_model: str) -> Optional[BaseChatModel]:
        """LLM 초기화"""

        try:
            # Option 1 : 기존 LLMService 사용
            from app.utils.llm_service import create_llm_service
            llm_service = create_llm_service(self.db)

            if llm_model in llm_service.models:
                logger.info(f"Using existing LLMService model : {llm_model}")
                return llm_service.models[llm_model]
            
            # Option 2: LangChain 직접 초기화 - 기존 LLMService에 모델이 없을 때
            logger.warning(f"Model {llm_model} not found in LLMService. Trying direct initilazation")
            return self._initialize_llm_directly(llm_model)
        
        except Exception as e:
            logger.error(f"LLM setup failed: {str(e)}")
            logger.warning("Agent will run in placeholder mode")
            return None
    
    def _initialize_llm_directly(self, llm_model: str) -> BaseChatModel:
        """LangChain으로 LLM 직접 초기화"""
        from app.core.settings.api_keys.crud.api_keys_settings_crud import get_apikey

        # OpenAI
        if llm_model.startswith("gpt-"):
            from langchain_openai import ChatOpenAI

            api_key = get_apikey(self.db, "openai_api_key")
            if not api_key:
                raise ValueError("OpenAI API Key not found")
            return ChatOpenAI(model=llm_model, temperature=self.temperature, api_key=api_key)

        # Anthropic
        elif llm_model.startswith("claude-"):
            from langchain_anthropic import ChatAnthropic

            api_key = get_apikey(self.db, "anthropic_api_key")
            if not api_key:
                raise ValueError("Anthropic API key not found")
            return ChatAnthropic(model=llm_model, temperature=self.temperature, api_key=api_key)
        
        # Google Gemini
        elif llm_model.startswith("gemini-"):
            from langchain_google_genai import ChatGoogleGenerativeAI

            api_key = get_apikey(self.db, "google_api_key")
            if not api_key:
                raise ValueError("Google API key not found")
            return ChatGoogleGenerativeAI(model=llm_model, temperature=self.temperature, google_api_key=api_key)

        else:
            raise ValueError(f"Unsupported model: {llm_model}")
    
    @abstractmethod #각 자식 agent에서 구현해야하는 추상 메서드 부분
    def _create_tools(self) -> List[Tool]:
        """각 Agent가 구현"""
        pass

    def _initialize_agent(self) -> Optional[AgentExecutor]:
        """LangChain Agent 초기화 (향후 LCEL/LangGraph 전환 가능)"""
        if self.llm is None:
            logger.warning("LLM not initialized. Agent will not work.")
            return None

        logger.info(f"Initializing agent with {len(self.tools)} tools")
        return initialize_agent(
            tools=self.tools, # Agent가 사용할 툴 목록
            llm=self.llm,     # 에이전트의 추론 엔진. 툴 설명을 읽고 다음 행동 생성
            agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION, # React 에이전트 유형. 제로샷으로 도구 선택을 하며, 생각과 행동을 번갈아가며 진행하는 패턴이다.
            max_iterations=self.max_iterations, #도구 -관찰 사이클이 끝없이 돌지 않도록 제한함.
            verbose=self.verbose, # 디버그 로그 출력 여부 결정
            handle_parsing_errors=True, # LLM 툴 호출 포맷 오류 관용 보정
            return_intermediate_steps=True # 실행 결과에 중간 단계 로그를 함께 반환함.
        )

    def _build_prompt(self, query: str, context: str = "") -> str:
        """
        기본 프롬프트 생성 (자식 클래스에서 오버라이드 권장)

        Args:
            query: 조사할 대상
            context: 추가 컨텍스트

        Returns:
            LLM에게 전달할 프롬프트
        """
        prompt = f"""You are an OSINT investigation expert.

TARGET: {query}

Analyze the target using available tools and provide a comprehensive report.
Extract all related IOCs (IPs, domains, URLs, hashes) for further investigation."""

        if context:
            prompt += f"\n\nADDITIONAL CONTEXT:\n{context}"

        return prompt

    async def investigate(self, query: str, context: str ="", return_format: str = "full") -> Dict[str, Any]:
        """OSINT 조사 수행 (메인 메서드)"""
        logger.info(f"{self.__class__.__name__} investigating:{query[:50]}...")

        prompt = self._build_prompt(query, context)

        try:
            if self.agent is None:
                return self._build_placeholder_result(query, return_format)

            # Agent 실행
            logger.info("Invoking LangChain agent...")
            result = await self.agent.ainvoke({"input": prompt})

            # Structed Result 생성
            agent_result = self._build_result(query=query,
                                              llm_output=result["output"],
                                              intermediate_steps=result.get("intermediate_steps",[]),
                                              status = "success")
            return self._format_output(agent_result, return_format)
        
        except ValueError as e:
            logger.error(f"Validation error: {str(e)}")
            return self._build_error_result(query, 400, "Invalid input format")
        except Exception as e:
            logger.error(f"Investigation failed: {str(e)}", exc_info = True)
            return self._build_error_result(query, 500, "Internal investigation error")

    def _build_result(self, query: str, llm_output: str, intermediate_steps: List[Tuple], status: str = "success") -> Dict[str, Any]:
        """Agent 결과를 표준 형식으로 구성 (안전 파싱 + 표준 스키마)"""

        # 사용한 도구 추출 (안전한 타입 체크)
        tools_used = []
        raw_data = {}
        safe_steps = []

        for step in intermediate_steps:
            try:
                # step은 (AgentAction, observation)이어야 함
                if not isinstance(step, tuple) or len(step) != 2:
                    continue
                action, observation = step

                # 다양한 AgentAction 구현 형식에 대응
                tool_name = getattr(action, 'tool', None) or str(action)
                tool_input = getattr(action, 'tool_input', {})
                tools_used.append(tool_name)
                raw_data[tool_name] = observation  # 관측 결과를 원시데이터로 축적
                safe_steps.append({
                    "tool": tool_name,
                    "tool_input": tool_input,
                    "output": observation
                })
            except Exception as e:
                logger.warning(f"Failed to parse intermediate step: {e}")
                continue

        # 루프 바깥에서 관련 IOC 추출 (최종 출력 텍스트 기준)
        related_iocs = self._extract_iocs(llm_output)

        return {
            "query": query,
            "agent_type": self.__class__.__name__,
            "timestamp": datetime.utcnow().isoformat() + "Z",

            # 최종/요약/신뢰도
            "result": llm_output,
            "summary": self._generate_summary(llm_output),
            "confidence": self._assess_confidence(intermediate_steps, safe_steps),

            # 사용/증거/로그
            "tool_calls": len(safe_steps),
            "tools_used": tools_used,
            "raw_data": raw_data,
            "intermediate_steps": safe_steps,

            # 확장 힌트/권고
            "related_iocs": related_iocs,
            "recommendations": self._generate_recommendations(llm_output),

            # 메타/상태
            "status": status,
            "error": None,
            "error_message": None
        }
    
    def _format_output(self, agent_result: Dict[str, Any], return_format: str) -> Dict[str, Any]:
        """출력 형식 필터링"""
        if return_format == "state":  # Orchestrator 입력받는 형식 지정함. 위의 build_result에서 반환하는 요소들 중 선택해서 입력받음 
            return {k: agent_result[k] for k in ["agent_type", "query", "summary", "confidence", "tools_used", "related_iocs", "timestamp", "status"]}
        elif return_format == "summary": # 요약 프론트엔드용
            return {k: agent_result[k] for k in ["agent_type", "query", "summary", "confidence", "status"]}
        else: # 상세 페이지 뷰 프론트엔드용
            return agent_result
    
    def _extract_iocs(self, text: str) -> List[str]:
        """IOC 추출"""
        iocs = []
        # IPv4 추출 
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        for match in re.findall(ipv4_pattern, text):
              try:
                  ipaddress.IPv4Address(match)
                  iocs.append(match)
              except ValueError:
                  pass
        
        # 도메인 추출
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        iocs.extend(re.findall(domain_pattern, text))

        # Hash 추출 (MD5, SHA1, SHA256)
        hash_pattern = r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
        iocs.extend(re.findall(hash_pattern, text))

        # 중복 제거 + 원본 쿼리는 제외한다.
        return list(set(iocs))
    
    def _generate_summary(self, llm_output: str) -> str:
        """요약문 생성"""
        sentences = llm_output.split('.')
        return sentences[0].strip() + '.' if sentences and sentences[0] else llm_output[:200]

    # 지금 신뢰도 평가를 단순히 도구 사용 개수로만 하고 있는데 , 향후 도구 품질, 탐지 일치도, 신선도 등을 반영하도록 개선해야만 함!
    # 아마 각 자식 agent에서 구현해야 할 듯
    def _assess_confidence(self, intermediate_steps: List, safe_steps: List[Dict]) -> str:
        """신뢰도 평가 (개선 : 도구 품질 고려)"""
        tool_count = len(safe_steps)
        if tool_count >= 3:
            return "high"
        elif tool_count >= 1:
            return "medium"
        else:
            return "low"

    def _generate_recommendations(self, llm_output: str) -> List[str]:
        """권장 조치 (TODO: LLM으로 생성)"""
        return []
    
    # 테스트용, LLM 응답 실패 시 안전한 기본 응답값.
    # 아직 LLM 안 붙여서 파이프라인, UI가 깨지지 않게 스키마가 같은 더미 응답을 돌려주는 용도임.
    def _build_placeholder_result(self, query: str, return_format: str) -> Dict[str, Any]:
        """Placeholder 응답"""
        result = {"query": query,
                  "agent_type": self.__class__.__name__,
                  "timestamp": datetime.utcnow().isoformat() + "Z",
                  "result": f"[PLACEHOLDER] LLM not connected. Available tools: {','.join(self.get_available_tools())}",
                  "summary": "LLM not connected (placeholder mode)",
                  "confidence": "low",
                  "tool_calls": 0,
                  "tools_used": self.get_available_tools(),
                  "raw_data": {},
                  "intermediate_steps": [],
                  "related_iocs": [],
                  "recommendations": [],
                  "status": "placeholder",
                  "error": None,
                  "error_message": None}
        return self._format_output(result, return_format)

    def _build_error_result(self, query: str, error_code: int, error_message: str) -> Dict[str, Any]:
        """에러 결과 생성"""
        return {
            "query": query,
            "agent_type": self.__class__.__name__,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "result": "",
            "summary": f"Error: {error_message}",
            "confidence": "low",
            "tool_calls": 0,
            "tools_used": [],
            "raw_data": {},
            "intermediate_steps": [],
            "related_iocs": [],
            "recommendations": [],
            "status": "error",
            "error": error_code,
            "error_message": error_message
        }

    # 에이전트가 사용할 수 있는 도구 목록 반환
    def get_available_tools(self) -> List[str]:
        """사용 가능한 도구 목록"""
        return [tool.name for tool in self.tools]
    
    # Orchestrator나 프론트엔드에서 에이전트 메타데이터 조회용
    def get_agent_info(self) -> Dict[str, Any]:
        """Agent 메타 데이터 반환"""
        return {"name": self.__class__.__name__, 
                "description": self.__doc__.strip() if self.__doc__ else "", 
                "tool_count": len(self.tools), 
                "tools": self.get_available_tools(), 
                "llm_model": self.llm_model}