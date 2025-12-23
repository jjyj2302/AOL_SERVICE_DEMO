"""
Threat Intelligence Database Models
"""

from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, Float, ForeignKey, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class ThreatReport(Base):
    """위협 보고서 (업로드된 PDF)"""
    __tablename__ = 'threat_reports'

    id = Column(Integer, primary_key=True, autoincrement=True)

    # 파일 정보
    filename = Column(String(255), nullable=False)
    source = Column(String(100), nullable=True)  # "mandiant", "crowdstrike", "custom"
    file_path = Column(String(500), nullable=False)
    file_hash = Column(String(64), nullable=True)  # SHA256
    file_size = Column(Integer, nullable=True)
    total_pages = Column(Integer, nullable=True)

    # 통계
    total_iocs_extracted = Column(Integer, default=0)
    iocs_selected_count = Column(Integer, default=0)
    iocs_analyzed_count = Column(Integer, default=0)

    # 상태
    status = Column(String(50), default='uploaded')  # uploaded, extracted, selected, analyzing, completed, error

    # 타임스탬프
    upload_date = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # 관계
    extracted_iocs = relationship("ExtractedIOC", back_populates="report", cascade="all, delete-orphan")
    firewall_requests = relationship("FirewallBlockRequest", back_populates="report")

    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'source': self.source,
            'file_size': self.file_size,
            'total_pages': self.total_pages,
            'total_iocs_extracted': self.total_iocs_extracted,
            'iocs_selected_count': self.iocs_selected_count,
            'iocs_analyzed_count': self.iocs_analyzed_count,
            'status': self.status,
            'upload_date': self.upload_date.isoformat() if self.upload_date else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }


class ExtractedIOC(Base):
    """PDF에서 추출된 IOC"""
    __tablename__ = 'extracted_iocs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(Integer, ForeignKey('threat_reports.id'), nullable=False)

    # IOC 정보
    ioc_type = Column(String(20), nullable=False)  # ip, domain, hash, url, cve, email
    ioc_value = Column(String(500), nullable=False, index=True)
    context = Column(Text, nullable=True)  # PDF에서 발견된 문맥
    page_number = Column(Integer, nullable=True)

    # 사용자 선택 (핵심!)
    is_selected = Column(Boolean, default=False)
    selected_at = Column(DateTime(timezone=True), nullable=True)

    # AI 추천 (False Positive 필터링)
    confidence_score = Column(Float, default=1.0)  # 0.0 ~ 1.0
    is_false_positive = Column(Boolean, default=False)
    recommendation = Column(String(50), default='analyze')  # analyze, skip, review

    # 분석 상태
    is_analyzed = Column(Boolean, default=False)
    analyzed_at = Column(DateTime(timezone=True), nullable=True)

    # 분석 결과 (간략)
    severity = Column(String(20), nullable=True)  # critical, high, medium, low, unknown
    threat_summary = Column(Text, nullable=True)

    # 분석 결과 (상세 - JSON)
    triage_result = Column(Text, nullable=True)
    malware_result = Column(Text, nullable=True)
    infrastructure_result = Column(Text, nullable=True)
    campaign_result = Column(Text, nullable=True)

    # 타임스탬프
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # 관계
    report = relationship("ThreatReport", back_populates="extracted_iocs")
    firewall_requests = relationship("FirewallBlockRequest", back_populates="ioc")

    def to_dict(self, include_analysis=False):
        result = {
            'id': self.id,
            'report_id': self.report_id,
            'ioc_type': self.ioc_type,
            'ioc_value': self.ioc_value,
            'context': self.context,
            'page_number': self.page_number,
            'is_selected': self.is_selected,
            'confidence_score': self.confidence_score,
            'is_false_positive': self.is_false_positive,
            'recommendation': self.recommendation,
            'is_analyzed': self.is_analyzed,
            'severity': self.severity,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

        if include_analysis and self.is_analyzed:
            result['analysis'] = {
                'triage': self.triage_result,
                'malware': self.malware_result,
                'infrastructure': self.infrastructure_result,
                'campaign': self.campaign_result,
                'threat_summary': self.threat_summary
            }

        return result


class FirewallBlockRequest(Base):
    """방화벽 차단 요청 이력"""
    __tablename__ = 'firewall_block_requests'

    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(Integer, ForeignKey('threat_reports.id'), nullable=False)
    ioc_id = Column(Integer, ForeignKey('extracted_iocs.id'), nullable=False)

    # IOC 정보 (빠른 조회용 중복 저장)
    ioc_value = Column(String(500), nullable=False)
    ioc_type = Column(String(20), nullable=False)
    severity = Column(String(20), nullable=True)

    # 방화벽 설정
    firewall_type = Column(String(50), nullable=False)  # paloalto, fortinet, checkpoint, generic
    action = Column(String(20), default='block')  # block, allow, monitor
    rule_name = Column(String(255), nullable=True)

    # 상태 (실제 전송은 하지 않음)
    status = Column(String(50), default='ready')  # ready, pending, simulated
    notes = Column(Text, nullable=True)

    # 타임스탬프
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    requested_by = Column(String(100), nullable=True)

    # 관계
    report = relationship("ThreatReport", back_populates="firewall_requests")
    ioc = relationship("ExtractedIOC", back_populates="firewall_requests")

    def to_dict(self):
        return {
            'id': self.id,
            'report_id': self.report_id,
            'ioc_id': self.ioc_id,
            'ioc_value': self.ioc_value,
            'ioc_type': self.ioc_type,
            'severity': self.severity,
            'firewall_type': self.firewall_type,
            'action': self.action,
            'rule_name': self.rule_name,
            'status': self.status,
            'notes': self.notes,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'requested_by': self.requested_by
        }


class KISAIoC(Base):
    """한국인터넷진흥원 침해사고 공격 IoC 지표"""
    __tablename__ = 'kisa_iocs'

    id = Column(Integer, primary_key=True, autoincrement=True)

    # KISA OpenAPI 필드
    attack_date = Column(String(50), nullable=False, index=True)  # 날짜
    attack_ip = Column(String(45), nullable=False, index=True)    # 공격 IP (IPv4/IPv6)
    attack_country = Column(String(100), nullable=True)           # 공격 IP 국가
    attack_action = Column(Text, nullable=True)                   # 수행 행위
    description = Column(Text, nullable=True)                     # 설명 (자동 생성)

    # 메타데이터
    dataset_version = Column(String(50), nullable=True, index=True)  # API 버전 (20240531, 20250113)

    # 사용자 선택 (방화벽 규칙 적용용)
    is_selected = Column(Boolean, default=False, index=True)
    selected_at = Column(DateTime(timezone=True), nullable=True)

    # 방화벽 적용 여부
    is_blocked = Column(Boolean, default=False, index=True)
    blocked_at = Column(DateTime(timezone=True), nullable=True)
    firewall_rule_name = Column(String(255), nullable=True)

    # 타임스탬프
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # 복합 인덱스 (중복 방지 및 빠른 조회)
    __table_args__ = (
        Index('idx_kisa_ip_date_version', 'attack_ip', 'attack_date', 'dataset_version', unique=True),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'attack_date': self.attack_date,
            'attack_ip': self.attack_ip,
            'attack_country': self.attack_country,
            'attack_action': self.attack_action,
            'description': self.description,
            'dataset_version': self.dataset_version,
            'is_selected': self.is_selected,
            'selected_at': self.selected_at.isoformat() if self.selected_at else None,
            'is_blocked': self.is_blocked,
            'blocked_at': self.blocked_at.isoformat() if self.blocked_at else None,
            'firewall_rule_name': self.firewall_rule_name,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class KISASyncHistory(Base):
    """KISA IoC 동기화 이력"""
    __tablename__ = 'kisa_sync_history'

    id = Column(Integer, primary_key=True, autoincrement=True)

    # 동기화 정보
    dataset_version = Column(String(50), nullable=False)  # 20240531, 20250113
    sync_status = Column(String(20), nullable=False)      # started, in_progress, completed, failed

    # 통계
    total_records = Column(Integer, default=0)
    new_records = Column(Integer, default=0)
    updated_records = Column(Integer, default=0)
    failed_records = Column(Integer, default=0)

    # 에러 정보
    error_message = Column(Text, nullable=True)

    # 타임스탬프
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'dataset_version': self.dataset_version,
            'sync_status': self.sync_status,
            'total_records': self.total_records,
            'new_records': self.new_records,
            'updated_records': self.updated_records,
            'failed_records': self.failed_records,
            'error_message': self.error_message,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }
