/**
 * 외부(Node.js) MCP 서버 — dnstwist CLI 래핑.
 *
 * Phase B 비교용: 자체 Python FastMCP(aol-mcp) 와 다른 언어/SDK 로 작성된
 * MCP 서버가 백엔드와 정상 통신하는지 입증한다.
 *
 *   tool: dnstwist
 *     input  : { domain: string, limit?: number=30 }
 *     output : list of TextContent (각 원소 = JSON 변형 1건)
 *
 * 진짜 외부 서비스(별도 컨테이너, 다른 언어, 다른 MCP SDK 구현체)와의
 * MCP 프로토콜 호환성을 검증한다.
 */
import { spawn } from "node:child_process";
import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const HOST = process.env.MCP_HOST || "0.0.0.0";
const PORT = parseInt(process.env.MCP_PORT || "8766", 10);

// in-process 캐시 + singleflight (Phase 22 — QPS 0.51 → 30+ 개선용).
// 자체 FastMCP(aol-mcp) 와 동일하게 TTL 10분. 같은 (domain,limit) 동시 호출 시
// 첫 호출만 python spawn 하고 나머지는 같은 Promise 를 await — 중복 spawn 차단.
const CACHE_TTL_MS = Number(process.env.CACHE_TTL_MS || 10 * 60 * 1000);
const cache = new Map(); // key → { ts: number, value: any }
const inflight = new Map(); // key → Promise

function cacheGet(key) {
  const hit = cache.get(key);
  if (!hit) return null;
  if (Date.now() - hit.ts > CACHE_TTL_MS) {
    cache.delete(key);
    return null;
  }
  return hit.value;
}

function cacheSet(key, value) {
  cache.set(key, { ts: Date.now(), value });
}

const server = new Server(
  { name: "external-dnstwist", version: "0.1.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "dnstwist",
      description:
        "외부 Node.js MCP 서버가 제공하는 dnstwist 도메인 변형 생성. 도메인 입력, 상위 N개 변형 반환.",
      inputSchema: {
        type: "object",
        properties: {
          domain: { type: "string" },
          limit: { type: "integer", default: 30 },
        },
        required: ["domain"],
      },
    },
  ],
}));

// dnstwist CLI 기본 동작은 모든 변형에 DNS 해석을 수행해 시간이 길다 (수십초).
// 자체 FastMCP 와 공정한 비교를 위해 Python Fuzzer 클래스를 직접 호출해
// 변형 목록만 생성한다 (DNS 미수행).
const PY_FUZZER_SNIPPET = `
import json, sys, dnstwist
domain = sys.argv[1]
limit = int(sys.argv[2])
f = dnstwist.Fuzzer(domain)
f.generate()
out = []
for p in list(f.permutations())[:limit]:
    d = p.get('domain') or p.get('domain-name')
    if not d or d == domain:
        continue
    out.append({'domain': d, 'fuzzer': p.get('fuzzer') or 'unknown'})
print(json.dumps(out))
`;

function runDnstwist(domain, limit) {
  return new Promise((resolve, reject) => {
    const proc = spawn("python3", ["-c", PY_FUZZER_SNIPPET, domain, String(limit)], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (d) => (stdout += d.toString()));
    proc.stderr.on("data", (d) => (stderr += d.toString()));
    proc.on("error", reject);
    proc.on("close", (code) => {
      if (code !== 0) {
        return reject(new Error(`fuzzer exit ${code}: ${stderr.slice(0, 200)}`));
      }
      try {
        const parsed = JSON.parse(stdout);
        const mapped = parsed.map((p) => ({
          domain: p.domain,
          technique: p.fuzzer,
          risk:
            p.fuzzer === "homoglyph" || p.fuzzer === "hyphenation" || p.fuzzer === "addition"
              ? "HIGH"
              : "MEDIUM",
          _source: "external_node_mcp",
        }));
        resolve(mapped);
      } catch (e) {
        reject(new Error(`parse_failed: ${e.message}`));
      }
    });
  });
}

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args = {} } = req.params;
  if (name !== "dnstwist") {
    return { isError: true, content: [{ type: "text", text: `unknown tool: ${name}` }] };
  }
  const domain = String(args.domain || "").trim();
  const limit = Number.isInteger(args.limit) ? args.limit : 30;
  if (!domain) {
    return { isError: true, content: [{ type: "text", text: "domain is required" }] };
  }
  const cacheKey = `dnstwist:${domain}:${limit}`;

  // (1) cache hit
  const cached = cacheGet(cacheKey);
  if (cached) {
    return {
      content: cached.map((v) => ({ type: "text", text: JSON.stringify({ ...v, _cached: true }) })),
    };
  }

  // (2) in-flight singleflight — 같은 key 가 이미 실행 중이면 같은 Promise 공유
  let promise = inflight.get(cacheKey);
  if (!promise) {
    promise = runDnstwist(domain, limit)
      .then((variants) => {
        cacheSet(cacheKey, variants);
        return variants;
      })
      .finally(() => inflight.delete(cacheKey));
    inflight.set(cacheKey, promise);
  }

  try {
    const variants = await promise;
    return {
      content: variants.map((v) => ({ type: "text", text: JSON.stringify(v) })),
    };
  } catch (e) {
    return { isError: true, content: [{ type: "text", text: String(e.message || e) }] };
  }
});

// SSE transport: GET /sse 로 stream 열고 POST /messages 로 명령 수신.
const app = express();
const transports = new Map();

app.get("/sse", async (req, res) => {
  const transport = new SSEServerTransport("/messages", res);
  transports.set(transport.sessionId, transport);
  res.on("close", () => transports.delete(transport.sessionId));
  await server.connect(transport);
});

app.post("/messages", express.json(), async (req, res) => {
  const sessionId = req.query.session_id || req.query.sessionId;
  const transport = transports.get(sessionId);
  if (!transport) return res.status(404).send("session not found");
  await transport.handlePostMessage(req, res, req.body);
});

app.get("/healthz", (req, res) => res.json({ ok: true, server: "external-dnstwist" }));

app.listen(PORT, HOST, () => {
  console.log(`external-dnstwist MCP server listening sse://${HOST}:${PORT}/sse`);
});
