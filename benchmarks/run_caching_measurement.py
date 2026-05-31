"""Phase 26: Anthropic Prompt Caching cache_control 실 적용 + 실측.

cost_analysis.py 는 "system 프롬프트 90% 캐시 적중" 가정으로 비용 계산.
이 가정이 실제로 작동하는지 실 API 호출로 검증.

검증 방법:
  각 5 에이전트 (orchestrator/triage/malware/infrastructure/campaign) 에 대해:
    1) cache enabled — 같은 system 프롬프트로 N=3 회 연속 호출
        - 1회차: cache_creation_input_tokens > 0 기대 (캐시 생성)
        - 2~3회차: cache_read_input_tokens > 0 기대 (캐시 적중)
    2) cache disabled (대조군) — N=3 회 호출
        - cache_read_input_tokens = 0 기대

cost_analysis.py 가정 (90% cached) vs 실측 비교:
    실측 cache_hit_ratio = cache_read / (cache_read + cache_creation + non_cached)
    → 가정 부정확하면 cost_analysis 갱신 필요

backend 컨테이너 안에서 실행:
  python benchmarks/run_caching_measurement.py --out path

⚠ 실 API 호출 — 예상 비용: 5 agents × 2 modes × 3 반복 = 30 호출 ≈ $0.30~$1.00
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = REPO_ROOT / "benchmarks" / "caching_measurement.json"

# 각 에이전트 별 동일한 user_message 사용 — system 프롬프트만 cache 대상
TEST_USER_MESSAGES: dict[str, str] = {
    "orchestrator": (
        "IoC 입력: kakaobank-secure-login.com (type=domain). "
        "라우팅 결정과 brief를 JSON으로 응답해주세요."
    ),
    "triage": (
        "도메인 kakaobank-secure-login.com 의 VirusTotal 평판 데이터: "
        '{"malicious": 28, "total": 93, "creation_date": "2026-05-22"}. '
        "위협 수준을 결정하고 priority pivot 을 JSON으로 응답해주세요."
    ),
    "malware": (
        "해시 5d41402abc4b2a76b9719d911017c592 의 행위 패턴 추정 + "
        "MITRE 매핑 + Attack chain 재구성을 JSON으로 응답해주세요."
    ),
    "infrastructure": (
        "도메인 kakaobank-secure-login.com 인프라 분석: "
        '{"typosquats": 5, "asn": "AS199524 (RU)", "cert_pattern": "*.kakaobank-secure-login.com"}. '
        "클러스터 ID 와 인프라 상관관계를 JSON으로 응답해주세요."
    ),
    "campaign": (
        "타겟: 카카오뱅크. 인프라 클러스터 FINPHISH-KR-2026Q2-A. "
        "위협 그룹 추정 + 헌팅 쿼리 + FW 룰 + executive_summary 를 JSON으로 응답해주세요."
    ),
}

REPEATS = 3
MAX_TOKENS = 2500  # 실 운영 산출물 크기 (cost_analysis estimate 와 동일)


def _run_measurement(out_path: Path) -> None:
    sys.path.insert(0, "/backend")
    from app.features.langgraph_threat_hunter.agent_prompts import (
        AGENT_PROMPTS,
        call_agent,
        has_anthropic_key,
    )

    if not has_anthropic_key():
        sys.exit("ANTHROPIC_API_KEY not set in container env")

    results: dict[str, Any] = {
        "schema": "caching_measurement.v1",
        "generated_at": int(time.time()),
        "repeats": REPEATS,
        "agents": {},
        "cost_analysis_assumption": {
            "cached_fraction": 0.9,
            "note": "cost_analysis.py 에서 input_cost = (cached_fraction × cached_price + (1-cached_fraction) × input_price) 가정. 실측으로 검증.",
        },
    }

    for agent_name, user_msg in TEST_USER_MESSAGES.items():
        sys_prompt = AGENT_PROMPTS.get(agent_name, "")
        # 토큰 추정 — chars/4 (정확값은 anthropic API 측 system_prompt input_tokens)
        sys_chars = len(sys_prompt)
        sys_est_tokens = sys_chars // 4

        agent_block: dict[str, Any] = {
            "system_prompt_chars": sys_chars,
            "system_prompt_est_tokens": sys_est_tokens,
            "cache_eligible_by_min_tokens": sys_est_tokens >= 1024,
            "cache_enabled_calls": [],
            "cache_disabled_calls": [],
        }

        # === cache enabled — N 회 ===
        for i in range(REPEATS):
            parsed, meta = call_agent(agent_name, user_msg, max_tokens=MAX_TOKENS, enable_prompt_cache=True)
            agent_block["cache_enabled_calls"].append({
                "call_index": i,
                "input_tokens": meta.get("input_tokens"),
                "output_tokens": meta.get("output_tokens"),
                "cache_creation_input_tokens": meta.get("cache_creation_input_tokens", 0),
                "cache_read_input_tokens": meta.get("cache_read_input_tokens", 0),
                "elapsed_ms": meta.get("elapsed_ms"),
                "error": meta.get("error"),
            })
            time.sleep(0.5)  # rate limiting margin

        # === cache disabled (대조군) — N 회 ===
        for i in range(REPEATS):
            parsed, meta = call_agent(agent_name, user_msg, max_tokens=MAX_TOKENS, enable_prompt_cache=False)
            agent_block["cache_disabled_calls"].append({
                "call_index": i,
                "input_tokens": meta.get("input_tokens"),
                "output_tokens": meta.get("output_tokens"),
                "cache_creation_input_tokens": meta.get("cache_creation_input_tokens", 0),
                "cache_read_input_tokens": meta.get("cache_read_input_tokens", 0),
                "elapsed_ms": meta.get("elapsed_ms"),
                "error": meta.get("error"),
            })
            time.sleep(0.5)

        # === 요약 ===
        en = agent_block["cache_enabled_calls"]
        total_input = sum((c.get("input_tokens") or 0) for c in en)
        total_cache_read = sum((c.get("cache_read_input_tokens") or 0) for c in en)
        total_cache_creation = sum((c.get("cache_creation_input_tokens") or 0) for c in en)
        total_processed_input = total_input + total_cache_read + total_cache_creation
        agent_block["summary"] = {
            "enabled_total_input_tokens": total_input,
            "enabled_total_cache_creation": total_cache_creation,
            "enabled_total_cache_read": total_cache_read,
            "enabled_total_processed": total_processed_input,
            "actual_cache_hit_ratio": (
                round(total_cache_read / total_processed_input, 3)
                if total_processed_input > 0 else 0.0
            ),
            "assumption_was": 0.9,
            "assumption_realized": (
                total_cache_read > 0 and total_processed_input > 0
                and (total_cache_read / total_processed_input) >= 0.5
            ),
        }
        results["agents"][agent_name] = agent_block
        print(f"  [{agent_name}] cache_read={total_cache_read}, creation={total_cache_creation}, input={total_input}, ratio={agent_block['summary']['actual_cache_hit_ratio']}", file=sys.stderr)

    # === 전체 요약 ===
    grand_read = sum(a["summary"]["enabled_total_cache_read"] for a in results["agents"].values())
    grand_creation = sum(a["summary"]["enabled_total_cache_creation"] for a in results["agents"].values())
    grand_input = sum(a["summary"]["enabled_total_input_tokens"] for a in results["agents"].values())
    grand_processed = grand_read + grand_creation + grand_input
    results["grand_total"] = {
        "cache_read_input_tokens": grand_read,
        "cache_creation_input_tokens": grand_creation,
        "non_cached_input_tokens": grand_input,
        "total_processed_input": grand_processed,
        "actual_cache_hit_ratio": round(grand_read / grand_processed, 3) if grand_processed > 0 else 0.0,
        "assumption": 0.9,
        "conclusion": (
            "✅ 가정 부합 (실측 ≥ 50%)"
            if (grand_processed > 0 and (grand_read / grand_processed) >= 0.5)
            else "❌ 가정 미달 — cost_analysis.py 의 cached_fraction=0.9 가정이 비현실적. "
                 "원인 분석: 시스템 프롬프트 길이가 Anthropic 최소 요구치 미달 가능 / "
                 "Sonnet 1024 tokens / Haiku 2048 tokens 필요"
        ),
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"\n[+] wrote {out_path}", file=sys.stderr)


def _run_external(out_arg: str) -> None:
    """host 에서 docker exec 로 backend 안에서 측정 (이 스크립트를 stdin 으로 파이프).

    host 환경변수 ANTHROPIC_API_KEY 를 docker exec -e 로 휘발성 주입.
    backend 이미지/볼륨/env 파일에 영구 저장 안 함.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        sys.exit("ANTHROPIC_API_KEY not set in host env — export 후 재실행")

    script = Path(__file__).read_text()
    cmd = [
        "docker", "exec", "-i",
        "-e", f"ANTHROPIC_API_KEY={api_key}",
        "backend",
        "python", "-",
        "--inside",
        "--out", "/tmp/caching_measurement.json",
    ]
    proc = subprocess.run(cmd, input=script, capture_output=False, text=True, timeout=600)
    if proc.returncode != 0:
        sys.exit(f"FAILED: returncode={proc.returncode}")

    # 결과 파일을 컨테이너에서 꺼내옴
    subprocess.run(
        ["docker", "cp", "backend:/tmp/caching_measurement.json", out_arg],
        check=True,
    )
    print(f"[+] wrote {out_arg}")

    # 요약 출력
    with open(out_arg) as f:
        data = json.load(f)
    print()
    print("=" * 90)
    print("[ Prompt Caching 실측 — agent 별 cache_read_input_tokens ]")
    print("=" * 90)
    print(f"{'agent':<16} | {'sys_chars':>9} | {'eligible':>8} | {'cache_read':>10} | {'cache_creat':>11} | {'non_cached':>10} | {'hit_ratio':>9}")
    print("-" * 90)
    for name, a in data["agents"].items():
        s = a["summary"]
        print(
            f"{name:<16} | {a['system_prompt_chars']:>9} | "
            f"{str(a['cache_eligible_by_min_tokens']):>8} | "
            f"{s['enabled_total_cache_read']:>10} | "
            f"{s['enabled_total_cache_creation']:>11} | "
            f"{s['enabled_total_input_tokens']:>10} | "
            f"{s['actual_cache_hit_ratio']:>9.1%}"
        )
    g = data["grand_total"]
    print()
    print("=" * 90)
    print(f"GRAND TOTAL: cache_read={g['cache_read_input_tokens']}, "
          f"creation={g['cache_creation_input_tokens']}, "
          f"non_cached={g['non_cached_input_tokens']}")
    print(f"실측 cache hit ratio: {g['actual_cache_hit_ratio']:.1%}  vs  cost_analysis 가정: {g['assumption']:.0%}")
    print(f"결론: {g['conclusion']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inside", action="store_true", help="backend 컨테이너 안 실행")
    parser.add_argument("--out", default=str(OUT_PATH))
    args = parser.parse_args()

    if args.inside:
        _run_measurement(Path(args.out))
    else:
        _run_external(args.out)


if __name__ == "__main__":
    main()
