"""3 MCP 통합 모드 비교 측정 — direct / self_mcp / external_mcp.

측정 지표 (호출당):
  - latency_ms      : cold (1회차) + warm avg (2회차 이후)
  - result_bytes    : JSON 직렬화 응답 크기
  - llm_tokens_est  : LLM 입력 토큰 추정 (chars/4)
  - result_count    : list 길이 또는 dict 필드 수
  - result_source   : 응답의 _source 필드

추가 (mode 단위):
  - container_memory_mb : 사이드카 컨테이너 RSS
  - image_size_mb       : 사이드카 이미지 크기
  - concurrent_qps      : 5 병렬 호출 처리량

backend 컨테이너 내부에서 실행:
  docker exec -e AOL_LIVE_MCP_MODE=<mode> backend \\
    python - --mode <mode> --inside

또는 host 에서:
  python benchmarks/run_mcp_comparison.py --all
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = REPO_ROOT / "benchmarks" / "mcp_comparison.json"

# 측정 케이스 — 모드 간 동일하게 호출
CASES: list[tuple[str, tuple[Any, ...]]] = [
    ("dnstwist", ("shinhan-secure-banking.kr",)),
    ("dnstwist", ("kakaobank-secure-login.com",)),
    ("cve", ("CVE-2024-21762",)),
    ("cve", ("CVE-2023-44487",)),
    ("osint", ("shinhan.com",)),
]

# 반복 횟수 — 첫 호출은 콜드스타트 고정으로 측정, 이후 N-1 회 평균
REPEATS = 3

# 동시 호출 측정 — 같은 도구를 N 병렬로 호출해 QPS 측정
CONCURRENT_N = 5

# 모드별 측정 대상 컨테이너 (docker stats / images)
MODE_CONTAINERS: dict[str, list[str]] = {
    "direct": ["backend"],
    "self_mcp": ["aol-mcp"],
    "external_mcp": ["aol-mcp", "ext-mcp-dnstwist"],
}
MODE_IMAGES: dict[str, list[str]] = {
    "direct": ["aol_service_demo_backend"],
    "self_mcp": ["aol_mcp_server"],
    "external_mcp": ["aol_mcp_server", "aol_ext_mcp_dnstwist"],
}


def _payload_bytes(result: Any) -> int:
    try:
        return len(json.dumps(result, default=str).encode("utf-8"))
    except Exception:  # noqa: BLE001
        return -1


def _tokens_est(result: Any) -> int:
    """대략적 LLM 입력 토큰 추정 — 정확값이 아니라 모드 간 비교용.

    Claude/GPT 토크나이저 기준 영문 1 토큰 ≈ 4 chars, 한글은 1~1.5 chars/token.
    JSON 결과는 영문/숫자/구두점 위주라 chars/4 추정.
    """
    try:
        return max(1, len(json.dumps(result, default=str)) // 4)
    except Exception:  # noqa: BLE001
        return -1


def _run_inside(mode: str) -> dict[str, Any]:
    """현재 프로세스(backend 컨테이너 내부) 에서 측정."""
    os.environ["AOL_LIVE_MCP_MODE"] = mode
    from app.features.langgraph_threat_hunter.mcp_clients import McpRegistry  # noqa: E402
    from app.features.langgraph_threat_hunter.state import ThreatHuntState  # noqa: E402

    measurements: list[dict[str, Any]] = []
    err_count = 0
    for tool, args in CASES:
        latencies_ms: list[float] = []
        result_first: Any = None
        for i in range(REPEATS):
            reg = McpRegistry(mode="live")  # __post_init__ 가 env 로 모드 해석
            state = ThreatHuntState(ioc=str(args[0]), ioc_type="domain", mode="live")
            t0 = time.perf_counter_ns()
            try:
                res = getattr(reg, tool)(state, *args)
            except Exception:  # noqa: BLE001
                err_count += 1
                latencies_ms.append(-1.0)
                continue
            elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000
            latencies_ms.append(elapsed_ms)
            if i == 0:
                result_first = res

        cold = latencies_ms[0] if latencies_ms else -1.0
        warm = [v for v in latencies_ms[1:] if v >= 0]
        warm_avg = round(statistics.mean(warm), 1) if warm else -1.0

        # 결과 메타데이터 (첫 호출 기준)
        if isinstance(result_first, list):
            result_count = len(result_first)
            first_el = result_first[0] if result_first else {}
            result_source = first_el.get("_source", "?") if isinstance(first_el, dict) else "?"
        elif isinstance(result_first, dict):
            result_count = len(result_first)
            result_source = result_first.get("_source", "?")
        else:
            result_count = 0
            result_source = "?"

        measurements.append({
            "tool": tool,
            "input": args[0],
            "cold_ms": round(cold, 1),
            "warm_avg_ms": warm_avg,
            "samples_ms": [round(v, 1) for v in latencies_ms],
            "result_count_or_fields": result_count,
            "result_source": result_source,
            "result_bytes": _payload_bytes(result_first),
            "llm_tokens_est": _tokens_est(result_first),
        })

    # 동시 호출 측정 — dnstwist 도구로 같은 도메인 5번 병렬
    concurrent_block = _measure_concurrent(mode)

    return {
        "mode": mode,
        "repeats_per_case": REPEATS,
        "cases": len(CASES),
        "errors": err_count,
        "measurements": measurements,
        "concurrent": concurrent_block,
    }


def _measure_concurrent(mode: str) -> dict[str, Any]:
    """동시/순차 두 가지 throughput 측정.

    1) parallel_qps : asyncio.gather 로 N 병렬 호출 — client 측 SSE 세션
       동시 셋업 능력 + 서버 측 동시성을 함께 본다 (현실에서 multi-request 상황).
    2) sequential_qps : 한 client 가 N 회 순차 호출 — 같은 client 가 캐시 적중
       흐름에서 낼 수 있는 effective throughput.

    동기 dnstwist 호출을 thread pool 로 감싸서 동시 실행한다.
    """
    from app.features.langgraph_threat_hunter.mcp_clients import McpRegistry  # noqa: E402
    from app.features.langgraph_threat_hunter.state import ThreatHuntState  # noqa: E402

    domain = "kakaobank-secure-login.com"

    # warm-up 1회 (캐시 상태 균일화 — 사이드카 캐시 적중 후 측정)
    warm = McpRegistry(mode="live")
    warm_state = ThreatHuntState(ioc=domain, ioc_type="domain", mode="live")
    try:
        getattr(warm, "dnstwist")(warm_state, domain)
    except Exception:  # noqa: BLE001
        pass

    async def one_call() -> float:
        reg = McpRegistry(mode="live")
        s = ThreatHuntState(ioc=domain, ioc_type="domain", mode="live")
        loop = asyncio.get_running_loop()
        t0 = time.perf_counter_ns()
        try:
            await loop.run_in_executor(None, lambda: reg.dnstwist(s, domain))
        except Exception:  # noqa: BLE001
            return -1.0
        return (time.perf_counter_ns() - t0) / 1_000_000

    async def parallel_runner():
        t0 = time.perf_counter_ns()
        results = await asyncio.gather(*[one_call() for _ in range(CONCURRENT_N)])
        total_ms = (time.perf_counter_ns() - t0) / 1_000_000
        return results, total_ms

    async def sequential_runner():
        results: list[float] = []
        t0 = time.perf_counter_ns()
        for _ in range(CONCURRENT_N):
            results.append(await one_call())
        total_ms = (time.perf_counter_ns() - t0) / 1_000_000
        return results, total_ms

    out: dict[str, Any] = {
        "tool": "dnstwist",
        "input": domain,
        "n": CONCURRENT_N,
    }

    try:
        par_per_call, par_wall = asyncio.run(parallel_runner())
        ok = [v for v in par_per_call if v >= 0]
        out["parallel"] = {
            "per_call_ms": [round(v, 1) for v in par_per_call],
            "wall_ms": round(par_wall, 1),
            "per_call_avg_ms": round(statistics.mean(ok), 1) if ok else -1,
            "qps": round(len(ok) * 1000.0 / par_wall, 2) if par_wall > 0 else 0.0,
        }
    except Exception as e:  # noqa: BLE001
        out["parallel"] = {"error": str(e)}

    try:
        seq_per_call, seq_wall = asyncio.run(sequential_runner())
        ok = [v for v in seq_per_call if v >= 0]
        out["sequential"] = {
            "per_call_ms": [round(v, 1) for v in seq_per_call],
            "wall_ms": round(seq_wall, 1),
            "per_call_avg_ms": round(statistics.mean(ok), 1) if ok else -1,
            "qps": round(len(ok) * 1000.0 / seq_wall, 2) if seq_wall > 0 else 0.0,
        }
    except Exception as e:  # noqa: BLE001
        out["sequential"] = {"error": str(e)}

    return out


def _docker_stats(name: str) -> dict[str, Any]:
    """docker stats 단발 측정."""
    try:
        out = subprocess.check_output(
            ["docker", "stats", "--no-stream", "--format",
             "{{.MemUsage}}|{{.CPUPerc}}|{{.MemPerc}}", name],
            text=True, timeout=10,
        ).strip()
    except subprocess.CalledProcessError:
        return {"name": name, "error": "not_running"}
    except subprocess.TimeoutExpired:
        return {"name": name, "error": "timeout"}
    mem_use, cpu_perc, mem_perc = out.split("|")
    mem_mb = _parse_mem(mem_use.split(" / ")[0].strip())
    return {
        "name": name,
        "memory_mb": mem_mb,
        "memory_use_raw": mem_use,
        "cpu_pct": cpu_perc,
        "memory_pct": mem_perc,
    }


def _parse_mem(s: str) -> float:
    """'124.3MiB' / '1.2GiB' → MB float."""
    s = s.strip()
    for unit, mult in (("GiB", 1024), ("MiB", 1), ("KiB", 1.0 / 1024), ("B", 1.0 / (1024 * 1024))):
        if s.endswith(unit):
            try:
                return round(float(s[: -len(unit)]) * mult, 1)
            except ValueError:
                return -1.0
    return -1.0


def _docker_image_size(repo: str) -> dict[str, Any]:
    """docker images <repo> 첫 줄 size."""
    try:
        out = subprocess.check_output(
            ["docker", "images", "--format", "{{.Repository}}|{{.Size}}", repo],
            text=True, timeout=10,
        ).strip()
    except subprocess.CalledProcessError:
        return {"repo": repo, "error": "not_found"}
    if not out:
        return {"repo": repo, "error": "not_found"}
    line = out.splitlines()[0]
    _, size = line.split("|", 1)
    return {"repo": repo, "size_raw": size, "size_mb": _parse_image_size(size)}


def _parse_image_size(s: str) -> float:
    """docker images Size '450MB' / '1.2GB' → MB float."""
    s = s.strip()
    for unit, mult in (("GB", 1024), ("MB", 1), ("kB", 1.0 / 1024)):
        if s.endswith(unit):
            try:
                return round(float(s[: -len(unit)]) * mult, 1)
            except ValueError:
                return -1.0
    return -1.0


def _run_external(mode: str) -> dict[str, Any]:
    """host 에서 docker exec 로 backend 안에서 측정.

    이 파일 자체를 stdin 으로 backend 의 python 에 파이프해서 실행 — backend
    이미지에 별도 복사할 필요 없이 매 실행마다 최신 스크립트로 측정한다.
    """
    script = Path(__file__).read_text()
    cmd = [
        "docker", "exec", "-i",
        "-e", f"AOL_LIVE_MCP_MODE={mode}",
        "backend",
        "python", "-", "--mode", mode, "--inside",
    ]
    proc = subprocess.run(cmd, input=script, capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        sys.stderr.write(f"[{mode}] FAILED: {proc.stderr}\n")
        return {"mode": mode, "error": proc.stderr[-2000:]}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return {"mode": mode, "error": f"json decode: {e}; stdout: {proc.stdout[-500:]}"}


def _summarize(report: dict[str, Any]) -> str:
    lines: list[str] = []

    # 1) 도구별 latency / payload / tokens
    lines.append("=" * 135)
    lines.append("[ 도구별 측정 ]")
    lines.append(
        f"{'mode':<14} | {'tool':<8} | {'input':<34} | {'cold ms':>7} | {'warm ms':>7} | "
        f"{'bytes':>7} | {'tokens':>6} | {'count':>5} | source"
    )
    lines.append("-" * 135)
    for mode_block in report["modes"]:
        mode = mode_block["mode"]
        for m in mode_block.get("measurements", []):
            lines.append(
                f"{mode:<14} | {m['tool']:<8} | {str(m['input'])[:34]:<34} | "
                f"{m['cold_ms']:>7.0f} | {m['warm_avg_ms']:>7.0f} | "
                f"{m['result_bytes']:>7} | {m['llm_tokens_est']:>6} | "
                f"{m['result_count_or_fields']:>5} | {m['result_source']}"
            )

    # 2) Throughput (parallel vs sequential)
    lines.append("")
    lines.append("=" * 135)
    lines.append("[ Throughput (dnstwist x N) — parallel vs sequential ]")
    lines.append(
        f"{'mode':<14} | {'N':>3} | "
        f"{'PAR per-call ms':>15} | {'PAR wall':>9} | {'PAR QPS':>8} | "
        f"{'SEQ per-call ms':>15} | {'SEQ wall':>9} | {'SEQ QPS':>8}"
    )
    lines.append("-" * 110)
    for mode_block in report["modes"]:
        c = mode_block.get("concurrent", {}) or {}
        par = c.get("parallel", {}) or {}
        seq = c.get("sequential", {}) or {}
        n = c.get("n", 0)
        if par.get("error") and seq.get("error"):
            lines.append(f"{mode_block['mode']:<14} | ERROR: parallel={par['error']} seq={seq['error']}")
            continue
        lines.append(
            f"{mode_block['mode']:<14} | {n:>3} | "
            f"{par.get('per_call_avg_ms', -1):>15.0f} | {par.get('wall_ms', -1):>9.0f} | "
            f"{par.get('qps', 0):>8.2f} | "
            f"{seq.get('per_call_avg_ms', -1):>15.0f} | {seq.get('wall_ms', -1):>9.0f} | "
            f"{seq.get('qps', 0):>8.2f}"
        )

    # 3) 컨테이너 메모리 / 이미지
    lines.append("")
    lines.append("=" * 135)
    lines.append("[ 사이드카 컨테이너 자원 ]")
    lines.append(f"{'mode':<14} | {'container':<22} | {'mem MB':>8} | {'image':<28} | {'image MB':>10}")
    lines.append("-" * 95)
    for mode_block in report["modes"]:
        mode = mode_block["mode"]
        stats_list = mode_block.get("container_stats", [])
        img_list = mode_block.get("image_sizes", [])
        for st, im in zip(stats_list, img_list):
            mem = st.get("memory_mb", "?")
            im_mb = im.get("size_mb", "?")
            lines.append(
                f"{mode:<14} | {st.get('name', '?'):<22} | {mem:>8} | "
                f"{im.get('repo', '?'):<28} | {im_mb:>10}"
            )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["direct", "self_mcp", "external_mcp"])
    parser.add_argument("--all", action="store_true", help="3 모드 모두 측정 (host 모드)")
    parser.add_argument("--inside", action="store_true", help="backend 컨테이너 내부 실행")
    parser.add_argument("--out", default=str(OUT_PATH))
    args = parser.parse_args()

    if args.inside:
        if not args.mode:
            sys.exit("--mode required with --inside")
        report = _run_inside(args.mode)
        json.dump(report, sys.stdout)
        return

    modes = ["direct", "self_mcp", "external_mcp"] if args.all else [args.mode]
    if not modes or modes == [None]:
        sys.exit("--mode or --all required")

    mode_blocks: list[dict[str, Any]] = []
    for m in modes:
        block = _run_external(m)
        # 모드별 컨테이너 자원/이미지 측정 (host 에서 docker stats/images)
        block["container_stats"] = [_docker_stats(n) for n in MODE_CONTAINERS.get(m, [])]
        block["image_sizes"] = [_docker_image_size(r) for r in MODE_IMAGES.get(m, [])]
        mode_blocks.append(block)

    report = {
        "schema": "mcp_comparison.v2",
        "generated_at": int(time.time()),
        "cases": [(t, a) for t, a in CASES],
        "modes": mode_blocks,
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2))
    print(f"[+] wrote {args.out}")
    print()
    print(_summarize(report))


if __name__ == "__main__":
    main()
