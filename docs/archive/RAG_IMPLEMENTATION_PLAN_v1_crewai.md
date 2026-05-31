# RAG 구현 및 성능 측정 계획서

> **작성일**: 2025-01-11
> **목표**: Historical Analysis Memory RAG 추가 및 성능 개선 측정
> **예상 기간**: 5-7일

---

## 📋 목차

1. [프로젝트 개요](#프로젝트-개요)
2. [측정 메트릭 정의](#측정-메트릭-정의)
3. [구현 단계](#구현-단계)
4. [성능 측정 방법론](#성능-측정-방법론)
5. [예상 결과](#예상-결과)
6. [마일스톤](#마일스톤)

---

## 프로젝트 개요

### 현재 상황
- **문제점**: `backend/app/features/deep_analysis/crew.py:156`에서 `memory=False` 상태
- **영향**:
  - 동일 IOC 재분석 시 API 중복 호출
  - 과거 15,000+ 분석 결과(`IocAnalysis` 테이블) 미활용
  - 비용 및 시간 비효율

### 목표
- **Phase 1**: Historical Analysis Memory RAG 구현
- **성능 목표**:
  - 응답 시간: 5.2s → 1.8s (65% 개선)
  - API 비용: 70% 절감
  - 캐시 히트율: 45% 이상

---

## 측정 메트릭 정의

### 1. 응답 시간 (Latency)
```yaml
측정 대상:
  - IOC 분석 전체 소요 시간
  - Agent별 실행 시간 (Triage, Malware, Infrastructure, Campaign)
  - API 호출 대기 시간

측정 방법:
  - Python time.time() 활용
  - Agent 시작/종료 시점 타임스탬프 기록

목표:
  Before: 5.2초 (평균)
  After: 1.8초 (평균)
  Improvement: 65% 감소
```

### 2. API 호출 비용
```yaml
측정 대상:
  - VirusTotal API 호출 횟수
  - URLScan API 호출 횟수
  - OpenAI API 토큰 사용량

비용 계산:
  VirusTotal: $0.01/call
  URLScan: $0.005/call
  OpenAI: $0.002/1K tokens

목표 (100 IOC 분석 기준):
  Before: $5.20
  After: $1.56
  Reduction: 70%
```

### 3. Cache Hit Rate
```yaml
측정 대상:
  - RAG 완전 일치 캐시 (similarity >= 0.95)
  - RAG 부분 일치 캐시 (similarity >= 0.80)
  - 신규 분석 비율

목표:
  완전 일치: 45%
  부분 일치: 30%
  신규 분석: 25%
```

### 4. 분석 정확도 (F1 Score)
```yaml
측정 방법:
  - 공개 데이터셋 사용 (abuse.ch MalwareBazaar 등)
  - Ground Truth와 예측 비교
  - F1-Score, Precision, Recall 계산

목표:
  Before F1: 0.72
  After F1: 0.87
  Improvement: 21%
```

---

## 구현 단계

### Phase 1: 측정 인프라 구축 (Day 1-2)

#### Day 1: 성능 측정 모듈 개발
```bash
작업:
  1. backend/app/utils/performance_metrics.py 생성
     - PerformanceTracker 클래스 구현
     - API 호출 추적
     - 지연 시간 측정
     - RAG 메트릭 수집

  2. DB 모델 추가
     - backend/app/features/history/models/history_models.py
     - PerformanceExperiment 모델 추가

파일 목록:
  ✓ backend/app/utils/performance_metrics.py (NEW)
  ✓ backend/app/features/history/models/history_models.py (EDIT)
```

#### Day 2: Benchmark Test Suite 구현
```bash
작업:
  1. 테스트 IOC 데이터셋 준비
     - backend/tests/fixtures/test_iocs.json
     - 다양한 IOC 타입 (IP, Domain, Hash, URL)
     - 신규/중복/유사 IOC 포함

  2. 벤치마크 실행 스크립트
     - backend/tests/benchmark_rag.py
     - Before/After 비교 자동화

  3. DB 마이그레이션
     - alembic revision 생성

파일 목록:
  ✓ backend/tests/fixtures/test_iocs.json (NEW)
  ✓ backend/tests/benchmark_rag.py (NEW)
  ✓ backend/alembic/versions/xxx_add_performance_experiment.py (NEW)
```

---

### Phase 2: 베이스라인 측정 (Day 3)

#### Day 3: RAG 없이 성능 측정 (Before)
```bash
작업:
  1. Baseline 측정 실행
     python backend/tests/benchmark_rag.py --mode before

  2. 결과 기록
     - 응답 시간 분포
     - API 호출 통계
     - 비용 계산

  3. 결과 검증
     - 최소 3회 반복 측정
     - 평균 및 표준편차 계산
     - Outlier 제거

측정 환경:
  - Hardware: 로컬/AWS 명시
  - IOC 개수: 100개
  - 반복 횟수: 3회

출력:
  ✓ data/benchmarks/before_rag_run1.json
  ✓ data/benchmarks/before_rag_run2.json
  ✓ data/benchmarks/before_rag_run3.json
  ✓ data/benchmarks/before_rag_summary.json
```

---

### Phase 3: RAG 구현 (Day 4-5)

#### Day 4: Vector Database 설정
```bash
작업:
  1. 의존성 추가
     # backend/requirements.txt
     chromadb==0.4.22
     sentence-transformers==2.3.1

  2. ChromaDB 초기화
     - backend/app/core/vector_db.py
     - Collection 생성
     - Embedding 설정

  3. 환경 변수 추가
     - CHROMA_PERSIST_DIRECTORY=./data/chroma
     - EMBEDDING_MODEL=all-MiniLM-L6-v2

파일 목록:
  ✓ backend/requirements.txt (EDIT)
  ✓ backend/app/core/vector_db.py (NEW)
  ✓ .env.example (EDIT)
```

#### Day 5: RAG Service 구현
```bash
작업:
  1. RAG 검색 서비스
     - backend/app/utils/rag_service.py
     - 유사 IOC 검색
     - 임베딩 생성 및 저장

  2. 기존 분석 결과 임베딩
     - 마이그레이션 스크립트
     - IocAnalysis 데이터 벡터화

  3. CrewAI Agent 통합
     - backend/app/features/deep_analysis/crew.py 수정
     - RAG Context Injection

파일 목록:
  ✓ backend/app/utils/rag_service.py (NEW)
  ✓ backend/scripts/migrate_to_rag.py (NEW)
  ✓ backend/app/features/deep_analysis/crew.py (EDIT)
```

---

### Phase 4: RAG 성능 측정 (Day 6)

#### Day 6: After RAG 측정
```bash
작업:
  1. RAG 활성화 후 측정
     python backend/tests/benchmark_rag.py --mode after

  2. 비교 분석
     python backend/tests/benchmark_rag.py --compare

  3. 결과 시각화
     - 그래프 생성 (matplotlib)
     - 비교표 생성

출력:
  ✓ data/benchmarks/after_rag_run1.json
  ✓ data/benchmarks/after_rag_run2.json
  ✓ data/benchmarks/after_rag_run3.json
  ✓ data/benchmarks/after_rag_summary.json
  ✓ data/benchmarks/comparison_report.json
  ✓ data/benchmarks/charts/latency_comparison.png
  ✓ data/benchmarks/charts/cost_comparison.png
```

---

### Phase 5: 문서화 및 발표 (Day 7)

#### Day 7: 결과 정리 및 문서화
```bash
작업:
  1. README.md 업데이트
     - Performance Benchmarks 섹션 추가
     - Before/After 비교표
     - 시각화 차트 삽입

  2. 기술 문서 작성
     - docs/RAG_ARCHITECTURE.md
     - 아키텍처 다이어그램
     - 구현 세부사항

  3. 발표 자료 준비 (선택)
     - slides/RAG_Performance_Results.pdf

파일 목록:
  ✓ README.md (EDIT)
  ✓ docs/RAG_ARCHITECTURE.md (NEW)
  ✓ docs/PERFORMANCE_RESULTS.md (NEW)
```

---

## 성능 측정 방법론

### 테스트 데이터셋 구성

```yaml
총 IOC 개수: 100개

분류:
  신규 IOC (50개):
    - 처음 분석하는 IOC
    - 캐시 없음
    - API 호출 필수

  중복 IOC (30개):
    - 이미 분석했던 IOC
    - 완전 일치 캐시 테스트
    - similarity >= 0.95

  유사 IOC (20개):
    - 유사한 패턴의 IOC
    - 부분 일치 캐시 테스트
    - similarity >= 0.80
    - 예: 8.8.8.8 vs 8.8.8.9

타입별 분포:
  IP: 40개
  Domain: 30개
  Hash: 20개
  URL: 10개
```

### 측정 환경

```yaml
Hardware:
  - Local: WSL2 (개발용)
  - Cloud: AWS t3.medium (프로덕션 시뮬레이션)

Software:
  - Python: 3.12
  - FastAPI: 0.115.8
  - CrewAI: latest
  - ChromaDB: 0.4.22

측정 조건:
  - 시간대: 평일 오전 10시 (API Rate Limit 안정)
  - 네트워크: 안정된 환경
  - 캐시 워밍업: 첫 실행 결과 제외
  - 반복 횟수: 3회 (평균 사용)
```

### 통계 처리

```python
# 평균 및 표준편차 계산
import numpy as np

runs = [run1, run2, run3]
mean_latency = np.mean([r['avg_latency'] for r in runs])
std_latency = np.std([r['avg_latency'] for r in runs])

# Outlier 제거 (Z-score > 2)
filtered_runs = [r for r in runs if abs(r['avg_latency'] - mean_latency) < 2 * std_latency]
```

---

## 예상 결과

### Before RAG (Baseline)

```yaml
평균 지연 시간: 5.2초
  - Triage: 1.2초
  - Malware: 1.5초
  - Infrastructure: 1.3초
  - Campaign: 1.2초

API 호출 (100 IOC):
  - VirusTotal: 100회
  - URLScan: 50회
  - OpenAI Tokens: 125K

총 비용: $5.20

캐시 히트율: 0%
```

### After RAG (Target)

```yaml
평균 지연 시간: 1.8초 (-65%)
  - RAG 검색: 0.2초
  - Triage: 0.4초
  - Malware: 0.5초
  - Infrastructure: 0.4초
  - Campaign: 0.3초

API 호출 (100 IOC):
  - VirusTotal: 35회 (-65%)
  - URLScan: 18회 (-64%)
  - OpenAI Tokens: 45K (-64%)

총 비용: $1.56 (-70%)

캐시 히트율: 47%
  - 완전 일치: 30개 (30%)
  - 부분 일치: 17개 (17%)
  - 신규: 53개 (53%)
```

### 비교 요약

| 메트릭 | Before | After | 개선율 |
|--------|--------|-------|--------|
| **평균 지연 시간** | 5.2s | 1.8s | ⬇️ 65% |
| **VirusTotal 호출** | 100 | 35 | ⬇️ 65% |
| **URLScan 호출** | 50 | 18 | ⬇️ 64% |
| **OpenAI 토큰** | 125K | 45K | ⬇️ 64% |
| **총 비용** | $5.20 | $1.56 | ⬇️ 70% |
| **캐시 히트율** | 0% | 47% | ✅ NEW |

---

## 마일스톤

### Week 1: 인프라 + 측정

```
Day 1 (1/11): ✅ 계획 수립
  - RAG_IMPLEMENTATION_PLAN.md 작성
  - 측정 메트릭 정의
  - 예상 결과 산출

Day 2 (1/12): ⏳ 측정 모듈 개발
  - PerformanceTracker 구현
  - DB 모델 추가
  - 마이그레이션

Day 3 (1/13): ⏳ Benchmark Suite
  - 테스트 IOC 데이터셋 준비
  - benchmark_rag.py 작성
  - 첫 실행 테스트

Day 4 (1/14): ⏳ Baseline 측정
  - Before RAG 3회 반복 측정
  - 통계 분석
  - 결과 저장
```

### Week 2: RAG 구현 + 검증

```
Day 5 (1/15): ⏳ Vector DB 설정
  - ChromaDB 설치 및 설정
  - Embedding 모델 선택
  - Collection 생성

Day 6 (1/16): ⏳ RAG Service 구현
  - rag_service.py 개발
  - 기존 데이터 임베딩
  - Agent 통합

Day 7 (1/17): ⏳ After RAG 측정
  - RAG 활성화 후 측정
  - 비교 분석
  - 결과 시각화

Day 8 (1/18): ⏳ 문서화
  - README 업데이트
  - 기술 문서 작성
  - 발표 자료 준비
```

---

## 체크리스트

### 구현 전 준비
- [ ] 테스트 IOC 데이터셋 100개 준비
- [ ] AWS 계정 또는 로컬 환경 확인
- [ ] API 키 확인 (VirusTotal, URLScan, OpenAI)
- [ ] Git branch 생성 (`feature/rag-implementation`)

### Phase 1: 측정 인프라
- [ ] PerformanceTracker 클래스 구현
- [ ] PerformanceExperiment DB 모델 추가
- [ ] Alembic 마이그레이션 실행
- [ ] benchmark_rag.py 작성
- [ ] 테스트 실행 확인

### Phase 2: Baseline 측정
- [ ] Before RAG 측정 (Run 1)
- [ ] Before RAG 측정 (Run 2)
- [ ] Before RAG 측정 (Run 3)
- [ ] 통계 분석 및 Outlier 제거
- [ ] 결과 JSON 저장

### Phase 3: RAG 구현
- [ ] ChromaDB 설치 및 설정
- [ ] vector_db.py 구현
- [ ] rag_service.py 구현
- [ ] 기존 IocAnalysis 데이터 임베딩 (15,000+건)
- [ ] crew.py RAG Context Injection

### Phase 4: After 측정
- [ ] After RAG 측정 (Run 1)
- [ ] After RAG 측정 (Run 2)
- [ ] After RAG 측정 (Run 3)
- [ ] Before/After 비교 분석
- [ ] 차트 및 그래프 생성

### Phase 5: 문서화
- [ ] README.md Performance Benchmarks 섹션
- [ ] docs/RAG_ARCHITECTURE.md 작성
- [ ] docs/PERFORMANCE_RESULTS.md 작성
- [ ] 비교표 및 차트 삽입
- [ ] Git commit 및 PR 생성

---

## 참고 자료

### 기술 문서
- [ChromaDB Documentation](https://docs.trychroma.com/)
- [LangChain RAG Tutorial](https://python.langchain.com/docs/use_cases/question_answering/)
- [CrewAI Memory Guide](https://docs.crewai.com/concepts/memory)

### 벤치마크 참고
- [MLPerf Inference Benchmark](https://mlcommons.org/en/inference-edge-11/)
- [LangChain Benchmarks](https://github.com/langchain-ai/langchain-benchmarks)

### 데이터셋
- [abuse.ch MalwareBazaar](https://bazaar.abuse.ch/)
- [CIRCL COVID-19 CTI](https://www.circl.lu/covid19/)
- [MISP Event Dataset](https://www.misp-project.org/)

---

## 연락처

- **담당자**: [Your Name]
- **프로젝트**: AOL_SERVICE_DEMO
- **Repository**: [GitHub Link]
- **문의**: [Email/Slack]

---

**마지막 업데이트**: 2025-01-11
**버전**: 1.0.0
