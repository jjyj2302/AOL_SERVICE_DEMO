# Deployment Guide — AOL_SERVICE_DEMO

본 문서는 **AWS EC2 단일 인스턴스**에 본 시스템 전체 스택을 배포하는 절차를 정리합니다.
로컬 개발은 [README.md](../README.md) 의 *Getting Started* 섹션을 참고하세요.

---

## 0. 배포 아키텍처 한 눈에

```
┌────────────────────────────────────────────────────────────────────┐
│  AWS EC2 (t3.large, Amazon Linux 2023 / Ubuntu 22)                 │
│ ┌──────────┐  ┌──────────┐  ┌──────────────┐  ┌─────────────────┐ │
│ │ frontend │──▶ backend  │──▶  redis       │  │ postgres:16     │ │
│ │ nginx:80 │  │ fastapi  │  │  redis:7     │  │ aol_data        │ │
│ │  :4000   │  │  :8000   │  │   :6379      │  │   :5432         │ │
│ └────┬─────┘  └────┬─────┘  └──────────────┘  └────────┬────────┘ │
│      │             │            ▲                       ▲           │
│      │             └────────────┴───────────────────────┘           │
│      │                          │                                   │
│      │              ┌───────────▼────────────┐                      │
│      │              │ /etc/aol/.env          │ ← SSM Parameter Store│
│      │              └────────────────────────┘                      │
└──────┼─────────────────────────────────────────────────────────────┘
       │
   ┌───▼─────────┐
   │ User Browser│ ← http://<ec2-public-ip>:4000
   └─────────────┘
```

---

## 1. 사전 준비

### 1.1 IAM Instance Profile

EC2 인스턴스에 부여할 IAM 역할 (예: `AOL-SSM-ReadOnly`)에 다음 권한 필요:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ssm:GetParameter", "ssm:GetParameters"],
      "Resource": "arn:aws:ssm:ap-northeast-2:*:parameter/aol/*"
    },
    {
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "*"
    }
  ]
}
```

### 1.2 SSM Parameter Store 시크릿 등록

```bash
aws ssm put-parameter --name /aol/openai_api_key      --value sk-...    --type SecureString
aws ssm put-parameter --name /aol/virustotal_api_key  --value <vt-key>  --type SecureString
aws ssm put-parameter --name /aol/urlscan_api_key     --value <us-key>  --type SecureString
aws ssm put-parameter --name /aol/postgres_password   --value <pw>      --type SecureString
```

> PostgreSQL 패스워드는 별도 SSM 항목으로 분리 관리.
> 미등록 시 user-data 가 임시 24자 랜덤 패스워드를 생성하지만 운영 전
> 반드시 SSM 에 등록할 것 (재부트 시 새 임시 패스워드로 갱신됨).

> 시뮬레이션 모드만 운영할 거면 위 단계를 건너뛰어도 됩니다 (스크립트가 "시뮬레이션 모드"로 자동 폴백).

### 1.3 보안 그룹

| 포트 | 프로토콜 | 출처 | 용도 |
|---|---|---|---|
| 22 | TCP | 운영자 IP 단일 호스트만 | SSH (디버깅용) |
| 4000 | TCP | 0.0.0.0/0 또는 사내망 CIDR | Frontend 접속 |

> **8000 포트는 외부 노출 금지** — `docker-compose.prod.yaml` 에서 backend 는 `expose` 만, `ports` 매핑 없음.

---

## 2. 배포 (user-data 자동 부트스트랩)

### 2.1 EC2 인스턴스 생성

```bash
aws ec2 run-instances \
  --image-id ami-0c9c942bd7bf113a2  \
  --instance-type t3.large \
  --iam-instance-profile Name=AOL-SSM-ReadOnly \
  --user-data file://deploy/ec2-userdata.sh \
  --security-group-ids sg-xxxxxxxxxxxxxxxxx \
  --key-name my-keypair \
  --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=30,VolumeType=gp3}' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=aol-demo}]'
```

> `ami-0c9c942bd7bf113a2` 는 ap-northeast-2 Amazon Linux 2023 예시 — 본인 리전의 최신 AMI 로 교체.

### 2.2 부트스트랩 진행 확인

EC2 부팅 후 약 2~3분이 지나면 자동으로:

1. 시스템 업데이트
2. Docker + Compose v2 설치
3. SSM 시크릿 로드 → `/etc/aol/.env` 생성
4. 저장소 `/opt/aol` 에 클론
5. `docker compose up -d` 자동 기동

진행 로그:
```bash
ssh ec2-user@<ec2-public-ip>
sudo tail -f /var/log/aol-bootstrap.log
```

기동 완료 후:
```bash
sudo docker compose -f /opt/aol/docker-compose.yaml -f /opt/aol/docker-compose.prod.yaml ps
sudo docker compose -f /opt/aol/docker-compose.yaml -f /opt/aol/docker-compose.prod.yaml logs -f backend
```

### 2.3 헬스체크

| 컴포넌트 | 확인 명령 |
|---|---|
| Frontend | `curl -I http://<ec2-public-ip>:4000` → `200 OK` |
| Backend | (인스턴스 내부에서) `curl http://localhost:8000/health` |
| Redis | `docker compose exec redis redis-cli ping` → `PONG` |

---

## 3. 운영 작업

### 3.1 코드 갱신 / 재배포

```bash
ssh ec2-user@<ec2-public-ip>
sudo bash /opt/aol/deploy/ec2-userdata.sh   # 동일 스크립트 재실행 — 자체 멱등
```

내부적으로 `git fetch && git reset --hard origin/<branch>` 후 `docker compose up -d --build` 가 다시 돌아갑니다.

### 3.2 로그 보존 정책

`docker-compose.prod.yaml` 의 logging 설정:

| 서비스 | max-size | max-file | 합산 |
|---|---|---|---|
| backend | 20 MB | 5 | 100 MB |
| frontend | 10 MB | 3 | 30 MB |
| redis | 10 MB | 3 | 30 MB |

> 장기 보관이 필요하면 CloudWatch Logs Agent 추가 권장 (별도 ticket).

### 3.3 리소스 제한

| 서비스 | CPU 제한 | RAM 제한 | RAM 예약 |
|---|---|---|---|
| backend | 1.5 vCPU | 4 GB | 1 GB |
| frontend | 0.5 vCPU | 512 MB | — |
| postgres | 1.0 vCPU | 2 GB | — |
| redis | (제한 없음) | (시스템 의존) | — |

t3.large (2 vCPU / 8 GB) 의 약 80% 까지 사용. CrewAI/LangGraph 동시 호출 시 메모리 여유 확보.

---

## 4. 트러블슈팅

| 증상 | 원인 후보 | 조치 |
|---|---|---|
| Frontend `:4000` 접속 불가 | 보안 그룹 미설정 | SG 인바운드 TCP 4000 추가 |
| Backend healthcheck 실패 | OpenAI 키 누락 / 잘못된 키 | `/etc/aol/.env` 확인, SSM 재등록 |
| `docker compose pull` 401 | (해당없음 — 우리는 로컬 빌드) | 무시 |
| `/var/log/aol-bootstrap.log` 에 SSM 권한 에러 | IAM 권한 부족 | IAM Role 정책 재확인 (KMS:Decrypt 포함) |
| OOM 킬 | RAM 부족 | 인스턴스 타입 t3.xlarge 로 업그레이드 |

---

## 5. 비용 추산 (참고)

| 항목 | 사양 | 월 비용 (ap-northeast-2 기준) |
|---|---|---|
| EC2 t3.large | 2 vCPU / 8 GB | ≈ $60 |
| EBS gp3 30 GB | — | ≈ $3 |
| 데이터 전송 (Egress) | < 10 GB/월 | ≈ $1 |
| **합계** | — | **≈ $64 / 월** |

> 데모용으로는 사용 시간만 켜고 끄면 (1일 8시간) 약 $20/월 수준으로 절감 가능.
> LLM 사용량 (OpenAI) 은 별도.

---

## 6. 다음 단계

- [ ] CloudWatch Logs 에이전트 통합
- [ ] Application Load Balancer + TLS (Let's Encrypt) — 사외 공개 시
- [ ] **AWS RDS PostgreSQL 분리** — 컨테이너 내장 → 관리형 DB 로 이전 (HA + 자동 백업)
- [ ] pgvector 확장 활성화 — RAG 도입 시
- [ ] Blue/Green 배포 — 무중단 갱신

본 문서는 단일 인스턴스 데모 기준. 운영 규모 확장 시 별도 인프라 설계 필요.
