"""MCP 라이브 클라이언트 — 사이드카 컨테이너의 도구를 진짜 MCP 프로토콜로 호출.

mode 가 "self_mcp" 또는 "external_mcp" 인 경우 McpRegistry 가 이 모듈을
거쳐 sse 로 사이드카에 도달한다. JSON-RPC + SSE 통신은 MCP SDK가 처리.

LangGraph 노드는 동기 함수라 asyncio.run() 으로 감싼 sync wrapper 를 제공한다.
첫 호출에서 도구 메타데이터를 캐시하여 이후 호출은 직접 call_tool 만.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class McpServerEndpoint:
    """단일 MCP 서버 접속 정보."""
    name: str           # 'self' | 'ext_dnstwist' | 'ext_cve' ...
    url: str            # 'http://aol-mcp:8765/sse'
    transport: str = "sse"
    tool_aliases: dict[str, str] = field(default_factory=dict)
    """alias_name -> remote_tool_name 매핑 (외부 서버의 도구 이름이 다를 때)."""


class McpLiveClient:
    """여러 MCP 서버를 묶어 도구 이름 한 개로 라우팅.

    동기 호출 wrapper: 내부에서 asyncio.run / get_event_loop 로 처리.
    스레드 안전을 위해 호출마다 새 세션을 연다 (간단함 우선; 부하 시 풀로 교체).
    """

    def __init__(self, endpoints: list[McpServerEndpoint]) -> None:
        self.endpoints = endpoints
        self._tool_index: dict[str, McpServerEndpoint] = {}
        self._tool_remote_name: dict[str, str] = {}
        self._indexed = False
        self._lock = threading.Lock()

    # ---- index 빌드 (1회) ----
    def _ensure_indexed(self) -> None:
        if self._indexed:
            return
        with self._lock:
            if self._indexed:
                return
            for ep in self.endpoints:
                for alias, remote in ep.tool_aliases.items():
                    self._tool_index[alias] = ep
                    self._tool_remote_name[alias] = remote
            self._indexed = True

    @asynccontextmanager
    async def _session(self, ep: McpServerEndpoint):
        from mcp import ClientSession  # type: ignore
        from mcp.client.sse import sse_client  # type: ignore

        async with sse_client(ep.url) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session

    async def _acall(self, tool_alias: str, arguments: dict[str, Any]) -> Any:
        self._ensure_indexed()
        ep = self._tool_index.get(tool_alias)
        if ep is None:
            raise KeyError(f"tool '{tool_alias}' 가 어느 MCP 서버에도 등록되지 않음")
        remote_name = self._tool_remote_name[tool_alias]
        async with self._session(ep) as session:
            result = await session.call_tool(remote_name, arguments=arguments)
            return _unwrap_result(result)

    def call(self, tool_alias: str, arguments: dict[str, Any]) -> Any:
        """동기 호출 진입점. LangGraph 노드(sync)에서 사용."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                future = asyncio.run_coroutine_threadsafe(
                    self._acall(tool_alias, arguments), loop
                )
                return future.result(timeout=60)
        except RuntimeError:
            pass
        return asyncio.run(self._acall(tool_alias, arguments))


def _unwrap_result(result: Any) -> Any:
    """MCP CallToolResult → 파이썬 dict/list.

    FastMCP 의 규약:
      - dict 반환  → content = [TextContent(text=<json>)]  (1개)
      - list 반환  → content = [TextContent(...), ...]    (list 원소 수만큼)
      - scalar     → content = [TextContent(text=<str>)]
    """
    if hasattr(result, "isError") and result.isError:
        return {"_error": str(getattr(result, "content", "unknown_mcp_error"))}
    content = getattr(result, "content", None)
    if not content:
        return None

    parsed: list[Any] = []
    for item in content:
        text = getattr(item, "text", None)
        if text is None:
            parsed.append(item)
            continue
        try:
            parsed.append(json.loads(text))
        except (json.JSONDecodeError, ValueError):
            parsed.append(text)

    if len(parsed) == 1:
        return parsed[0]
    return parsed


# ============================================================
# 팩토리: 환경변수로 어느 사이드카에 붙을지 결정
# ============================================================
def build_client(mode: str) -> McpLiveClient | None:
    """mode 에 맞는 endpoint 묶음으로 McpLiveClient 생성.

    self_mcp     : 자체 FastMCP 사이드카 (5 도구 모두)
    external_mcp : 자체 FastMCP + 외부 MCP 서버(들) 혼합. 외부에 있는 도구는
                   alias 가 자동으로 외부로 라우팅됨.
    """
    self_url = os.getenv("AOL_MCP_SELF_URL", "http://aol-mcp:8765/sse")
    self_ep = McpServerEndpoint(
        name="self",
        url=self_url,
        transport="sse",
        tool_aliases={
            "virustotal": "virustotal",
            "dnstwist": "dnstwist",
            "shodan": "shodan",
            "osint": "osint",
            "cve": "cve",
        },
    )

    if mode == "self_mcp":
        return McpLiveClient([self_ep])

    if mode == "external_mcp":
        endpoints: list[McpServerEndpoint] = []

        ext_dnstwist_url = os.getenv("AOL_MCP_EXT_DNSTWIST_URL", "").strip()
        if ext_dnstwist_url:
            endpoints.append(McpServerEndpoint(
                name="ext_dnstwist",
                url=ext_dnstwist_url,
                transport="sse",
                tool_aliases={"dnstwist": os.getenv("AOL_MCP_EXT_DNSTWIST_TOOL", "dnstwist")},
            ))

        ext_cve_url = os.getenv("AOL_MCP_EXT_CVE_URL", "").strip()
        if ext_cve_url:
            endpoints.append(McpServerEndpoint(
                name="ext_cve",
                url=ext_cve_url,
                transport="sse",
                tool_aliases={"cve": os.getenv("AOL_MCP_EXT_CVE_TOOL", "cve_lookup")},
            ))

        # 외부에 없는 도구는 자체 FastMCP 로 fallback
        self_ep_fallback = McpServerEndpoint(
            name="self",
            url=self_url,
            transport="sse",
            tool_aliases={
                alias: alias
                for alias in ("virustotal", "dnstwist", "shodan", "osint", "cve")
                if not any(alias in ep.tool_aliases for ep in endpoints)
            },
        )
        if self_ep_fallback.tool_aliases:
            endpoints.append(self_ep_fallback)

        return McpLiveClient(endpoints) if endpoints else None

    return None
