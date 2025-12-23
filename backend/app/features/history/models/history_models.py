"""
History Models - DB 모델 정의

분석 세션, IOC 분석 결과, 종합 결과, 업로드된 파일 저장
"""

from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class UploadedFile(Base):
    """업로드된 파일 (PDF 등) 저장"""
    __tablename__ = 'uploaded_files'

    id = Column(Integer, primary_key=True, autoincrement=True)
    filename = Column(String(255), nullable=False)  # 원본 파일명
    stored_filename = Column(String(255), nullable=False)  # 저장된 파일명 (UUID)
    file_path = Column(String(500), nullable=False)  # 서버 저장 경로
    file_size = Column(Integer, nullable=True)  # 파일 크기 (bytes)
    mime_type = Column(String(100), nullable=True)  # MIME 타입
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    sessions = relationship("AnalysisSession", back_populates="uploaded_file")

    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'stored_filename': self.stored_filename,
            'file_path': self.file_path,
            'file_size': self.file_size,
            'mime_type': self.mime_type,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class AnalysisSession(Base):
    """분석 세션 - 한 번의 분석 작업 단위"""
    __tablename__ = 'analysis_sessions'

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_name = Column(String(255), nullable=True)  # 사용자 지정 이름 (선택)
    source_type = Column(String(50), nullable=False)  # 'manual', 'pdf_upload', 'file_upload'
    uploaded_file_id = Column(Integer, ForeignKey('uploaded_files.id'), nullable=True)
    total_iocs = Column(Integer, default=0)
    status = Column(String(50), default='pending')  # pending, processing, completed, error
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    uploaded_file = relationship("UploadedFile", back_populates="sessions")
    ioc_analyses = relationship("IocAnalysis", back_populates="session", cascade="all, delete-orphan")
    aggregation = relationship("AggregationResult", back_populates="session", uselist=False, cascade="all, delete-orphan")

    def to_dict(self, include_iocs=False, include_aggregation=False):
        result = {
            'id': self.id,
            'session_name': self.session_name,
            'source_type': self.source_type,
            'uploaded_file': self.uploaded_file.to_dict() if self.uploaded_file else None,
            'total_iocs': self.total_iocs,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }
        if include_iocs:
            result['ioc_analyses'] = [ioc.to_dict() for ioc in self.ioc_analyses]
        if include_aggregation and self.aggregation:
            result['aggregation'] = self.aggregation.to_dict()
        return result


class IocAnalysis(Base):
    """개별 IOC 분석 결과"""
    __tablename__ = 'ioc_analyses'

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey('analysis_sessions.id'), nullable=False)
    ioc_value = Column(String(500), nullable=False)  # 실제 IOC 값
    ioc_type = Column(String(50), nullable=True)  # ip, domain, hash, url, email

    # 4 Agent 분석 결과 (JSON 문자열로 저장)
    triage_result = Column(Text, nullable=True)
    malware_result = Column(Text, nullable=True)
    infrastructure_result = Column(Text, nullable=True)
    campaign_result = Column(Text, nullable=True)

    # 메타데이터
    overall_threat_level = Column(String(50), nullable=True)  # critical, high, medium, low, unknown
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    session = relationship("AnalysisSession", back_populates="ioc_analyses")

    def to_dict(self):
        return {
            'id': self.id,
            'session_id': self.session_id,
            'ioc_value': self.ioc_value,
            'ioc_type': self.ioc_type,
            'triage_result': self.triage_result,
            'malware_result': self.malware_result,
            'infrastructure_result': self.infrastructure_result,
            'campaign_result': self.campaign_result,
            'overall_threat_level': self.overall_threat_level,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class AggregationResult(Base):
    """Phase 2 종합 분석 결과"""
    __tablename__ = 'aggregation_results'

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey('analysis_sessions.id'), nullable=False, unique=True)
    aggregated_report = Column(Text, nullable=False)  # JSON 문자열
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    session = relationship("AnalysisSession", back_populates="aggregation")

    def to_dict(self):
        return {
            'id': self.id,
            'session_id': self.session_id,
            'aggregated_report': self.aggregated_report,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
