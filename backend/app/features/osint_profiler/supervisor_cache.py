"""
Supervisor 싱글톤 캐시

서버 시작 시 Supervisor를 한 번만 생성하여 메모리에 캐싱.
매 요청마다 재생성하는 오버헤드 제거.
"""

from typing import Optional
from langgraph.pregel import Pregel


class SupervisorCache:
    """Supervisor 인스턴스 싱글톤 캐시"""

    _instance: Optional['SupervisorCache'] = None
    _supervisor: Optional[Pregel] = None
    _llm_model: str = "gpt-4"

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SupervisorCache, cls).__new__(cls)
        return cls._instance

    @classmethod
    def get_instance(cls) -> 'SupervisorCache':
        """싱글톤 인스턴스 반환"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def initialize(self, llm_model: str = "gpt-4") -> None:
        """
        Supervisor 초기화 (main.py의 lifespan에서 호출)

        Args:
            llm_model: 사용할 LLM 모델
        """
        if self._supervisor is None:
            from .supervisor import create_osint_supervisor

            print("Initializing OSINT Supervisor...")
            self._supervisor = create_osint_supervisor(llm_model)
            self._llm_model = llm_model
            print(f"Supervisor cached (model: {llm_model})\n")

    def get_supervisor(self) -> Pregel:
        """
        캐시된 Supervisor 반환

        Returns:
            Compiled Supervisor

        Raises:
            RuntimeError: 초기화되지 않은 경우
        """
        if self._supervisor is None:
            raise RuntimeError(
                "Supervisor not initialized. "
                "Call initialize() in main.py startup event first."
            )
        return self._supervisor

    def invalidate(self) -> None:
        """Supervisor 캐시 무효화 (재시작 필요 시)"""
        self._supervisor = None
        print("Supervisor cache invalidated")


# 편의 함수
def get_supervisor() -> Pregel:
    """캐시된 Supervisor 반환 (간편 함수)"""
    return SupervisorCache.get_instance().get_supervisor()
