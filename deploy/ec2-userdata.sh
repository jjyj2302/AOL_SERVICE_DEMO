#!/bin/bash
# =====================================================================
# AOL_SERVICE_DEMO — EC2 User-Data Bootstrap
#
# 이 스크립트는 EC2 인스턴스 최초 부팅 시 1회 자동 실행됩니다.
# 수행 작업:
#   1) 시스템 업데이트 + Docker / Compose 설치
#   2) AWS SSM Parameter Store 에서 시크릿 (OpenAI/VT/URLScan 키) 안전 주입
#   3) 저장소 클론 (또는 갱신)
#   4) docker compose 프로덕션 오버레이로 스택 기동
#   5) CloudWatch logs / journald 로깅
#
# 사전 요구사항:
#   - EC2 IAM Instance Profile 에 SSM:GetParameter 권한 + KMS:Decrypt 권한
#   - SSM Parameter Store 에 SecureString 으로 시크릿 등록:
#       /aol/openai_api_key
#       /aol/virustotal_api_key
#       /aol/urlscan_api_key
#   - 인스턴스 타입: t3.large (2 vCPU / 8 GB) 이상 권장
#   - 보안 그룹: TCP 4000 (Frontend), TCP 22 (SSH) 만 인바운드 허용
# =====================================================================
set -euo pipefail

# ---- 환경 변수 (필요 시 EC2 launch 시점에 덮어쓰기 가능) ----
REPO_URL="${REPO_URL:-https://github.com/jyj0203/AOL_SERVICE_DEMO.git}"
REPO_BRANCH="${REPO_BRANCH:-dev}"
INSTALL_DIR="${INSTALL_DIR:-/opt/aol}"
ENV_DIR="${ENV_DIR:-/etc/aol}"
SSM_REGION="${SSM_REGION:-ap-northeast-2}"

LOG_FILE="/var/log/aol-bootstrap.log"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "[$(date -u +%FT%TZ)] AOL_SERVICE_DEMO bootstrap 시작"

# ---- 1) 시스템 업데이트 ----
echo "[1/5] 시스템 패키지 업데이트..."
if command -v dnf >/dev/null 2>&1; then
    dnf -y update
    dnf -y install git docker awscli jq
elif command -v yum >/dev/null 2>&1; then
    yum -y update
    yum -y install git docker awscli jq
elif command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y git docker.io awscli jq
else
    echo "지원하지 않는 패키지 매니저" >&2
    exit 1
fi

# ---- 2) Docker / Compose v2 설치 및 활성화 ----
echo "[2/5] Docker 활성화..."
systemctl enable --now docker

# Docker Compose v2 플러그인 확인 (없으면 설치)
if ! docker compose version >/dev/null 2>&1; then
    echo "  Docker Compose v2 플러그인 설치 중..."
    COMPOSE_VERSION="v2.29.2"
    mkdir -p /usr/local/lib/docker/cli-plugins
    curl -fsSL "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-$(uname -m)" \
        -o /usr/local/lib/docker/cli-plugins/docker-compose
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
fi

# ec2-user / ubuntu 를 docker 그룹에 추가 (SSH 접속 시 sudo 없이 docker 사용)
for u in ec2-user ubuntu; do
    if id "$u" &>/dev/null; then
        usermod -aG docker "$u" || true
    fi
done

# ---- 3) SSM Parameter Store 에서 시크릿 주입 ----
echo "[3/5] SSM Parameter Store 시크릿 로딩..."
mkdir -p "$ENV_DIR"
chmod 700 "$ENV_DIR"

fetch_secret() {
    local param_name="$1"
    aws ssm get-parameter \
        --name "$param_name" \
        --with-decryption \
        --region "$SSM_REGION" \
        --query 'Parameter.Value' \
        --output text 2>/dev/null || echo ""
}

OPENAI_KEY=$(fetch_secret "/aol/openai_api_key")
VT_KEY=$(fetch_secret "/aol/virustotal_api_key")
URLSCAN_KEY=$(fetch_secret "/aol/urlscan_api_key")

if [ -z "$OPENAI_KEY" ]; then
    echo "⚠️  /aol/openai_api_key 가 SSM 에 없음 — 시뮬레이션 모드로만 동작합니다."
fi

cat > "$ENV_DIR/.env" <<ENVEOF
# 자동 생성 — EC2 user-data 부트스트랩
OPENAI_API_KEY=${OPENAI_KEY}
VIRUSTOTAL_API_KEY=${VT_KEY}
URLSCAN_API_KEY=${URLSCAN_KEY}
AOL_ENV=production
AOL_SIMULATION_MODE=enabled
ENVEOF
chmod 600 "$ENV_DIR/.env"

# ---- 4) 저장소 클론 / 갱신 ----
echo "[4/5] 저장소 동기화..."
if [ -d "$INSTALL_DIR/.git" ]; then
    cd "$INSTALL_DIR"
    git fetch --all --prune
    git reset --hard "origin/${REPO_BRANCH}"
else
    git clone --branch "$REPO_BRANCH" "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# ---- 5) docker compose 기동 ----
echo "[5/5] docker compose 기동..."
cd "$INSTALL_DIR"
docker compose \
    -f docker-compose.yaml \
    -f docker-compose.prod.yaml \
    up --build -d

echo ""
echo "==============================================================="
echo "✅ AOL_SERVICE_DEMO 부팅 완료"
echo "  Frontend : http://$(curl -fsSL http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo '<EC2-PUBLIC-IP>'):4000"
echo "  Logs     : $LOG_FILE"
echo "  Compose  : cd $INSTALL_DIR && docker compose logs -f"
echo "==============================================================="
