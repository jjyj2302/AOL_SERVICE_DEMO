/**
 * AI Threat Hunter — NotebookLM 스타일 3-패널 레이아웃.
 *
 *  ┌─ Sources (Left) ─┬─ Chat (Center) ─┬─ Agent Studio (Right) ─┐
 *  │ 샘플 시나리오     │  사용자 ↔ AI    │  파이프라인 + 산출물    │
 *  │ + 분석 리포트     │  대화만 표시     │                         │
 *  └──────────────────┴─────────────────┴────────────────────────┘
 *
 * 백엔드 SSE (/api/lg/chat/stream) 로부터 노드별 진행 이벤트를 받아
 *  - chat_message 류는 채팅 패널로
 *  - findings/deliverables 류는 우측 Agent Studio 로 분배 렌더.
 */
import { useEffect, useRef, useState } from "react";
import {
  Box,
  Chip,
  Container,
  Grid,
  Stack,
  Typography,
  alpha,
  useTheme,
} from "@mui/material";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import api from "../../api";
import SourcesPanel from "./SourcesPanel";
import ChatPanel from "./ChatPanel";
import ResultsSidebar from "./ResultsSidebar";
import { AGENTS } from "./AgentPipelinePanel";

// graph node ID → 채팅 표시용 agent 메타 (chat panel 의 메시지 헤더)
const AGENT_META = AGENTS.reduce((acc, a) => {
  acc[a.id] = { emoji: a.emoji, label: a.label, color: a.color };
  return acc;
}, {});

// node graph ID → state 내 chat_message 추출 함수
function extractChatMessage(nodeId, delta) {
  switch (nodeId) {
    case "orchestrator":
      return delta.routing_rationale || "";
    case "triage_step":
      return delta.triage?.chat_message || "";
    case "malware_step":
      return delta.malware?.chat_message || "";
    case "infrastructure_step":
      return delta.infrastructure?.chat_message || "";
    case "campaign_step":
      return delta.campaign?.chat_message || "";
    case "confidence_gate":
      return delta.gate_chat_message || "";
    default:
      return "";
  }
}

function emptyRun() {
  return {
    agentStates: {}, // {nodeId: 'idle'|'running'|'done'|'skipped'}
    elapsedByNode: {},
    toolsByNode: {},
    deliverables: null,
    parsed: null,
    title: null,
    mcp_calls: [],
    final: null,    // {confidence_score, automation_level, human_approval_required, elapsed_ms}
    pdfPath: null,
    route_plan: [],
  };
}

export default function ThreatHunterPage() {
  const theme = useTheme();
  const [scenarios, setScenarios] = useState([]);
  const [reports, setReports] = useState([]);   // {title, timestamp, pdf_path}
  const [messages, setMessages] = useState([]); // {role, agent?, text}
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [run, setRun] = useState(emptyRun());
  const runRef = useRef(run);
  runRef.current = run;

  // 시나리오 목록 로드
  useEffect(() => {
    api.get("/api/lg/scenarios")
      .then((res) => setScenarios(res.data.scenarios))
      .catch(() => {});
  }, []);

  const updateRun = (patch) => {
    setRun((prev) => {
      const next = typeof patch === "function" ? patch(prev) : { ...prev, ...patch };
      runRef.current = next;
      return next;
    });
  };

  const appendMessage = (msg) => setMessages((prev) => [...prev, msg]);

  // 대화 모드의 누적 어시스턴트 메시지 인덱스 (chat_chunk 가 같은 버블에 append 되도록)
  const dialogueAssistantIdxRef = useRef(null);

  // 사용자/어시스턴트 메시지 → Claude 호환 history (specialist 개별 chat_message 는 제외)
  const buildHistory = (msgs) => {
    return msgs
      .filter((m) => !m.specialist) // specialist 응답은 history 미포함
      .filter((m) => (m.text || "").trim())
      .map((m) => ({ role: m.role, content: m.text }));
  };

  const startStream = async (textOrScenario) => {
    const userText = textOrScenario;
    const history = buildHistory(messages);
    appendMessage({ role: "user", text: userText });
    setInput("");
    setStreaming(true);
    updateRun(emptyRun());
    dialogueAssistantIdxRef.current = null;

    try {
      const resp = await fetch(`${api.defaults.baseURL || ""}/api/lg/chat/dialogue`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: userText, history, pace: 0.4 }),
      });
      if (!resp.ok || !resp.body) throw new Error(`stream error ${resp.status}`);

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const events = buf.split("\n\n");
        buf = events.pop() || "";
        for (const ev of events) {
          const line = ev.startsWith("data: ") ? ev.slice(6) : ev;
          if (!line.trim()) continue;
          try {
            handleEvent(JSON.parse(line));
          } catch {}
        }
      }
    } catch (e) {
      appendMessage({ role: "assistant", text: `❌ 스트림 오류: ${e.message}` });
    } finally {
      setStreaming(false);
    }
  };

  const handleEvent = (ev) => {
    if (ev.type === "start") {
      if (ev.mode === "dialogue") {
        // 자유 대화 — 빈 어시스턴트 버블 1개 만들고 인덱스 기억
        setMessages((prev) => {
          const next = [...prev, { role: "assistant", text: "", dialogue: true }];
          dialogueAssistantIdxRef.current = next.length - 1;
          return next;
        });
        return;
      }
      // 분석 모드
      const initStates = {};
      AGENTS.forEach((a) => (initStates[a.id] = "idle"));
      initStates["orchestrator"] = "running";
      updateRun({
        parsed: ev.parsed,
        title: ev.title,
        agentStates: initStates,
        deliverables: { before_minutes: ev.before_minutes, estimated_after_seconds: ev.estimated_after_seconds },
        submode: ev.submode,
      });
      // 분석 시작 안내 메시지
      appendMessage({
        role: "assistant",
        text: `🔍 **${ev.submode === "live" ? "라이브" : "시뮬레이션"} 모드**로 분석 시작 — ${ev.title || ev.parsed?.ioc || ""}`,
        analysis_intro: true,
      });
      return;
    }

    if (ev.type === "chat_chunk") {
      // 자유 대화 — 누적 어시스턴트 메시지에 텍스트 append
      const idx = dialogueAssistantIdxRef.current;
      if (idx == null) return;
      setMessages((prev) => {
        const next = [...prev];
        if (next[idx]) next[idx] = { ...next[idx], text: (next[idx].text || "") + (ev.delta || "") };
        return next;
      });
      return;
    }

    if (ev.type === "tool_use") {
      // Claude 가 specialist 호출 — 채팅창에 배지 + 새로운 어시스턴트 버블 시작 준비
      const toolMap = {
        consult_triage: { id: "triage_step", label: "Triage Specialist" },
        consult_malware: { id: "malware_step", label: "Malware Specialist" },
        consult_infrastructure: { id: "infrastructure_step", label: "Infrastructure Hunter" },
        consult_campaign: { id: "campaign_step", label: "Campaign Analyst" },
      };
      const t = toolMap[ev.tool] || { id: null, label: ev.tool };
      appendMessage({
        role: "assistant",
        text: `🔧 **${t.label}** 에게 자문 요청\n\n> ${ev.question}`,
        specialist: true,
        agent: t.id ? AGENT_META[t.id] : null,
        tool_use: true,
      });
      // 우측 패널: 해당 specialist 를 'running' 으로 표시
      if (t.id) {
        updateRun((prev) => ({
          ...prev,
          agentStates: { ...prev.agentStates, [t.id]: "running" },
        }));
      }
      // 다음 chat_chunk 들은 새 버블에 누적
      dialogueAssistantIdxRef.current = null;
      return;
    }

    if (ev.type === "tool_result") {
      const toolMap = {
        consult_triage: { id: "triage_step", label: "Triage Specialist" },
        consult_malware: { id: "malware_step", label: "Malware Specialist" },
        consult_infrastructure: { id: "infrastructure_step", label: "Infrastructure Hunter" },
        consult_campaign: { id: "campaign_step", label: "Campaign Analyst" },
      };
      const t = toolMap[ev.tool] || { id: null, label: ev.tool };
      const summary = ev.summary && ev.summary !== "(no chat_message)" ? ev.summary : "구조화 자문 결과 수신";
      appendMessage({
        role: "assistant",
        text: `✅ **${t.label}** 자문 응답 (${ev.elapsed_ms ?? "?"}ms)\n\n${summary}`,
        specialist: true,
        agent: t.id ? AGENT_META[t.id] : null,
        tool_result: true,
      });
      if (t.id) {
        updateRun((prev) => ({
          ...prev,
          agentStates: { ...prev.agentStates, [t.id]: "done" },
          elapsedByNode: { ...prev.elapsedByNode, [t.id]: ev.elapsed_ms },
        }));
      }
      // Claude 가 이어서 종합하는 텍스트는 새 어시스턴트 버블로
      setMessages((prev) => {
        const next = [...prev, { role: "assistant", text: "", dialogue: true }];
        dialogueAssistantIdxRef.current = next.length - 1;
        return next;
      });
      return;
    }

    if (ev.type === "node") {
      const nodeId = ev.node;
      const delta = ev.delta || {};

      // Orchestrator 가 route_plan 반환하면 예정된 specialist 들의 "분석 중" placeholder 미리 표시
      if (nodeId === "orchestrator" && Array.isArray(delta.route_plan)) {
        const planSteps = delta.route_plan;
        const upcoming = planSteps.map((step) => `${step}_step`);
        // 기존 메시지에 placeholder 가 없는 specialist 만 추가
        setMessages((prev) => {
          const existing = new Set(prev.filter((m) => m.placeholder_for).map((m) => m.placeholder_for));
          const additions = upcoming
            .filter((nid) => !existing.has(nid))
            .map((nid) => ({
              role: "assistant",
              agent: AGENT_META[nid] || null,
              text: "🌀 분석 중...",
              specialist: true,
              placeholder_for: nid,
              isThinking: true,
            }));
          return additions.length ? [...prev, ...additions] : prev;
        });
      }

      // 현재 노드 done 처리
      updateRun((prev) => {
        const states = { ...prev.agentStates };
        states[nodeId] = "done";
        // ledger 의 마지막 엔트리에서 elapsed 추출
        const ledger = delta.audit_ledger || [];
        let elapsedNew = { ...prev.elapsedByNode };
        let toolsNew = { ...prev.toolsByNode };
        if (ledger.length > 0) {
          const last = ledger[ledger.length - 1];
          if (last.elapsed_ms != null) elapsedNew[nodeId] = last.elapsed_ms;
          if (last.tools_called?.length) toolsNew[nodeId] = last.tools_called;
        }

        // route_plan 갱신 (orchestrator 단계에서 들어옴)
        let routePlan = prev.route_plan;
        if (delta.route_plan) {
          routePlan = delta.route_plan;
          // route_plan 에 없는 specialist 는 skipped 로
          AGENTS.forEach((a) => {
            if (a.routeKey && !routePlan.includes(a.routeKey)) {
              states[a.id] = "skipped";
            }
          });
        }

        // 다음 노드를 running 으로 (route_plan 기반)
        // 가드: 다음 노드가 (1) null 아니고 (2) 현재 노드와 다르고 (3) 아직 done/skipped 가 아닌 경우만
        const nextNode = pickNextNode(nodeId, routePlan, states);
        if (nextNode && nextNode !== nodeId && states[nextNode] !== "done" && states[nextNode] !== "skipped") {
          states[nextNode] = "running";
        }

        // findings 누적
        const findings = {
          ...(prev.findings || {}),
          ...(delta.triage ? { triage: delta.triage } : {}),
          ...(delta.malware ? { malware: delta.malware } : {}),
          ...(delta.infrastructure ? { infrastructure: delta.infrastructure } : {}),
          ...(delta.campaign ? { campaign: delta.campaign } : {}),
        };

        // mcp_calls 누적
        const mcp = [...(prev.mcp_calls || []), ...(delta.mcp_calls || [])];

        // deliverables (campaign 시점에 fw rules / hunts 가 채워짐)
        let deliv = prev.deliverables || {};
        if (delta.campaign) {
          deliv = {
            ...deliv,
            firewall_rules: delta.campaign.firewall_rules || [],
            hunt_hypotheses: delta.campaign.hunt_hypotheses || [],
            executive_summary: delta.campaign.executive_summary || "",
          };
        }

        // final (gate 시점)
        let final = prev.final;
        if (nodeId === "confidence_gate") {
          final = {
            confidence_score: delta.confidence_score,
            automation_level: delta.automation_level,
            human_approval_required: delta.human_approval_required,
            elapsed_ms: delta.elapsed_ms,
          };
        }

        return {
          ...prev,
          agentStates: states,
          elapsedByNode: elapsedNew,
          toolsByNode: toolsNew,
          route_plan: routePlan,
          findings,
          mcp_calls: mcp,
          deliverables: deliv,
          final,
        };
      });

      // chat_message 가 있으면 채팅 패널에 추가 (있던 placeholder 가 있으면 교체, 없으면 신규)
      const chatText = extractChatMessage(nodeId, delta);
      if (chatText) {
        setMessages((prev) => {
          const next = [...prev];
          const idx = next.findIndex((m) => m.placeholder_for === nodeId && m.isThinking);
          const newMsg = {
            role: "assistant",
            agent: AGENT_META[nodeId],
            text: chatText,
            specialist: true,
          };
          if (idx >= 0) {
            next[idx] = newMsg;  // placeholder 교체
          } else {
            next.push(newMsg);
          }
          return next;
        });
      }
      return;
    }

    if (ev.type === "done") {
      // 잔여 정리: idle → skipped, running → done
      updateRun((prev) => {
        const states = { ...prev.agentStates };
        AGENTS.forEach((a) => {
          if (states[a.id] === "idle") states[a.id] = "skipped";
          if (states[a.id] === "running") states[a.id] = "done";
        });
        return {
          ...prev,
          agentStates: states,
          pdfPath: ev.deliverables_hint?.pdf_report_path || null,
        };
      });

      // 분석 모드 종료 시 — 전체 산출물을 채팅창에 종합 메시지로 출력
      if (ev.mode === "analysis") {
        const cur = runRef.current;
        const summary = buildFinalAnalysisSummary(cur);
        if (summary) {
          appendMessage({
            role: "assistant",
            text: summary,
            analysis_summary: true,
          });
        }
        // 자료실 리포트 추가 (PDF 다운로드는 보조)
        if (ev.deliverables_hint?.pdf_report_path) {
          const newReport = {
            title: cur.title || cur.parsed?.ioc || "분석 리포트",
            timestamp: new Date().toLocaleTimeString("ko-KR"),
            pdf_path: ev.deliverables_hint.pdf_report_path,
          };
          setReports((prev) => [newReport, ...prev]);
        }
      }
    }
  };

  // ---- 분석 결과를 채팅창용 markdown 문자열로 종합 ----
  const buildFinalAnalysisSummary = (run) => {
    const f = run.findings || {};
    const d = run.deliverables || {};
    const final = run.final || {};

    const parts = [];
    parts.push(`## ✅ 분석 완료 — ${run.title || run.parsed?.ioc || ""}`);

    // 메트릭
    if (final.automation_level || final.confidence_score != null) {
      const pct = ((final.confidence_score || 0) * 100).toFixed(0);
      const lvl = final.automation_level || "?";
      const approval = final.human_approval_required ? "**필수**" : "불필요";
      parts.push(
        `\n### 📊 메트릭\n` +
        `- 자동화 등급: **${lvl}** · 신뢰도 **${pct}%** · 휴먼 승인 ${approval}\n` +
        `- 처리 시간: ${final.elapsed_ms ?? "—"} ms`
      );
    }

    // Executive Summary
    const exec = d.executive_summary || f.campaign?.executive_summary || "";
    if (exec) {
      parts.push(`\n### 📈 Executive Summary\n${exec}`);
    }

    // 에이전트별 핵심 발견
    if (f.triage?.threat_level) {
      parts.push(
        `\n### 🔍 Triage — 위협 평가\n` +
        `- 위협 수준: **${f.triage.threat_level}** (탐지 ${f.triage.detection_ratio || "—"})\n` +
        (f.triage.mitre_tactics?.length
          ? `- MITRE 전술: ${f.triage.mitre_tactics.join(", ")}\n`
          : "") +
        (f.triage.priority_pivots?.length
          ? `- 우선 단서: ${f.triage.priority_pivots.map((p) => `\n  · ${p}`).join("")}`
          : "")
      );
    }

    if (f.malware?.malware_family || f.malware?.c2_targets?.length) {
      parts.push(
        `\n### 👾 Malware\n` +
        (f.malware.malware_family ? `- 패밀리: **${f.malware.malware_family}**\n` : "") +
        (f.malware.behaviors?.length
          ? `- 행위: ${f.malware.behaviors.join(", ")}\n`
          : "") +
        (f.malware.c2_targets?.length
          ? `- C2 타깃: ${f.malware.c2_targets.join(", ")}`
          : "")
      );
    }

    if (f.infrastructure?.typosquat_domains?.length || f.infrastructure?.campaign_cluster_id) {
      const ts = f.infrastructure.typosquat_domains || [];
      parts.push(
        `\n### 🌍 Infrastructure\n` +
        (f.infrastructure.campaign_cluster_id
          ? `- 캠페인 클러스터: **${f.infrastructure.campaign_cluster_id}**\n`
          : "") +
        (ts.length
          ? `- 타이포스쿼트 ${ts.length}건:${ts.slice(0, 5).map((t) => `\n  · \`${t.domain}\` (${t.technique || "?"})`).join("")}`
          : "")
      );
    }

    // 방화벽 규칙
    const fw = d.firewall_rules || f.campaign?.firewall_rules || [];
    if (fw.length) {
      parts.push(
        `\n### 🛡️ 방화벽 차단 규칙 (${fw.length}건)\n` +
        "```\n" + fw.join("\n") + "\n```"
      );
    }

    // 헌팅 가설
    const hunts = d.hunt_hypotheses || f.campaign?.hunt_hypotheses || [];
    if (hunts.length) {
      parts.push(`\n### 🔍 헌팅 가설 (${hunts.length}건)`);
      hunts.forEach((h, i) => {
        parts.push(
          `\n**#${h.hypothesis_id ?? i + 1}** · ${h.platform || "?"} · ${h.timeline || ""}\n` +
          "```\n" + (h.query || "") + "\n```\n" +
          (h.criteria ? `- Success: ${h.criteria}` : "")
        );
      });
    }

    parts.push(`\n---\n*우측 Agent Studio 에서 메트릭 카드 / Audit Ledger / MCP 호출 기록을 확인하실 수 있습니다.*`);
    return parts.join("\n");
  };

  const pickNextNode = (currentId, routePlan, _states) => {
    // currentId 다음에 진행될 노드 결정. 다음이 없으면 null.
    if (currentId === "confidence_gate") {
      // Gate 는 최종 노드 — 더 이상 다음 없음 (자기 자신을 다시 running 으로 두면 안 됨)
      return null;
    }
    if (currentId === "orchestrator") {
      const first = (routePlan && routePlan[0]) || null;
      return first ? `${first}_step` : "confidence_gate";
    }
    const map = {
      triage_step: "triage",
      malware_step: "malware",
      infrastructure_step: "infrastructure",
      campaign_step: "campaign",
    };
    const curKey = map[currentId];
    if (!curKey || !routePlan) return "confidence_gate";
    const idx = routePlan.indexOf(curKey);
    if (idx >= 0 && idx + 1 < routePlan.length) {
      return `${routePlan[idx + 1]}_step`;
    }
    return "confidence_gate";
  };

  const handleSubmit = () => {
    if (!input.trim() || streaming) return;
    startStream(input.trim());
  };

  const handlePickScenario = (scenarioId) => {
    if (streaming) return;
    startStream(scenarioId);
  };

  return (
    <Container maxWidth={false} sx={{ pb: 4, px: 2 }}>
      {/* Header */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3, mt: 2 }}>
        <Box
          sx={{
            p: 1.5,
            borderRadius: "16px",
            bgcolor: alpha(theme.palette.primary.main, 0.1),
            color: "primary.main",
            display: "flex",
          }}
        >
          <SmartToyIcon sx={{ fontSize: 32 }} />
        </Box>
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="h4" fontWeight={800} color="text.primary">
            AI Threat Hunter
          </Typography>
          <Typography variant="subtitle1" color="text.secondary">
            LangGraph 기반 Hierarchical Multi-Agent · 6 Agents · MCP Tool Mesh
          </Typography>
        </Box>
        <Stack direction="row" spacing={1}>
          <Chip label="LangGraph" color="primary" variant="outlined" sx={{ borderRadius: "10px", fontWeight: 600 }} />
          <Chip label="6 Agents" color="primary" sx={{ borderRadius: "10px", fontWeight: 600 }} />
        </Stack>
      </Box>

      {/* 3-패널 그리드 */}
      <Grid container spacing={2}>
        <Grid item xs={12} md={3} lg={2.5}>
          <SourcesPanel
            scenarios={scenarios}
            reports={reports}
            disabled={streaming}
            onPickScenario={handlePickScenario}
          />
        </Grid>
        <Grid item xs={12} md={6} lg={7}>
          <ChatPanel
            messages={messages}
            input={input}
            onInputChange={setInput}
            onSubmit={handleSubmit}
            streaming={streaming}
          />
        </Grid>
        <Grid item xs={12} md={3} lg={2.5}>
          <ResultsSidebar run={run} />
        </Grid>
      </Grid>
    </Container>
  );
}
