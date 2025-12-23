"""
KISA IoC API Schemas
"""

from typing import List, Optional
from pydantic import BaseModel, Field
from enum import Enum


class DatasetVersion(str, Enum):
    """KISA IoC 데이터셋 버전"""
    V20240531 = "20240531"
    V20250113 = "20250113"
    LATEST = "latest"  # 가장 최신 버전


class KISAIoCResponse(BaseModel):
    """단일 KISA IoC 응답"""
    id: int
    attack_date: str
    attack_ip: str
    attack_country: Optional[str] = None
    attack_action: Optional[str] = None
    description: Optional[str] = None
    dataset_version: Optional[str] = None
    is_selected: bool = False
    selected_at: Optional[str] = None
    is_blocked: bool = False
    blocked_at: Optional[str] = None
    firewall_rule_name: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class KISAIoCListResponse(BaseModel):
    """KISA IoC 목록 응답"""
    total: int
    page: int
    per_page: int
    data: List[KISAIoCResponse]


class KISASyncRequest(BaseModel):
    """KISA IoC 동기화 요청"""
    dataset_version: DatasetVersion = Field(
        default=DatasetVersion.LATEST,
        description="동기화할 데이터셋 버전"
    )
    service_key: str = Field(
        ...,
        description="KISA OpenAPI 인증키"
    )
    force_update: bool = Field(
        default=False,
        description="강제 업데이트 (기존 데이터 덮어쓰기)"
    )


class KISASyncResponse(BaseModel):
    """KISA IoC 동기화 응답"""
    sync_id: int
    dataset_version: str
    sync_status: str
    total_records: int
    new_records: int
    updated_records: int
    failed_records: int
    error_message: Optional[str] = None
    started_at: str
    completed_at: Optional[str] = None


class KISASelectRequest(BaseModel):
    """KISA IoC 선택 요청"""
    ioc_ids: List[int] = Field(
        ...,
        description="선택할 IoC ID 목록",
        min_length=1
    )
    is_selected: bool = Field(
        default=True,
        description="선택 상태 (True: 선택, False: 선택 해제)"
    )


class KISAFirewallRequest(BaseModel):
    """방화벽 규칙 적용 요청"""
    ioc_ids: List[int] = Field(
        ...,
        description="방화벽 규칙에 적용할 IoC ID 목록",
        min_length=1
    )
    firewall_type: str = Field(
        default="generic",
        description="방화벽 유형 (paloalto, fortinet, checkpoint, generic)"
    )
    action: str = Field(
        default="block",
        description="방화벽 동작 (block, allow, monitor)"
    )
    rule_name_prefix: str = Field(
        default="KISA_IoC",
        description="방화벽 규칙 이름 접두사"
    )


class KISAFirewallResponse(BaseModel):
    """방화벽 규칙 적용 응답"""
    total_iocs: int
    applied_iocs: int
    failed_iocs: int
    firewall_rules: List[dict]
    errors: Optional[List[str]] = None
