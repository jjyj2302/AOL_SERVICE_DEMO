/**
 * 6개 에이전트 (Orchestrator + 4 Specialist + Gate) 의 실행 상태를
 * 프로그레스 바로 실시간 표시. 스킵된 specialist 는 회색 처리.
 *
 * agentStates[nodeId] in {"idle", "running", "done", "skipped"}.
 */
import {
  Box,
  Chip,
  LinearProgress,
  Paper,
  Stack,
  Typography,
  alpha,
  useTheme,
} from "@mui/material";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import RadioButtonUncheckedIcon from "@mui/icons-material/RadioButtonUnchecked";
import AutorenewIcon from "@mui/icons-material/Autorenew";
import RemoveCircleOutlineIcon from "@mui/icons-material/RemoveCircleOutline";

export const AGENTS = [
  { id: "orchestrator", routeKey: null, label: "Investigation Orchestrator", emoji: "🧠", color: "#6366F1" },
  { id: "triage_step", routeKey: "triage", label: "Triage Specialist", emoji: "🔍", color: "#4F46E5" },
  { id: "malware_step", routeKey: "malware", label: "Malware Specialist", emoji: "👾", color: "#DC2626" },
  { id: "infrastructure_step", routeKey: "infrastructure", label: "Infrastructure Hunter", emoji: "🌍", color: "#059669" },
  { id: "campaign_step", routeKey: "campaign", label: "Campaign Analyst", emoji: "📈", color: "#D97706" },
  { id: "confidence_gate", routeKey: null, label: "Confidence Gate", emoji: "🛡️", color: "#7C3AED" },
];

function StatusBadge({ status, elapsed }) {
  if (status === "done") {
    return (
      <Stack direction="row" spacing={0.5} alignItems="center">
        <CheckCircleIcon color="success" sx={{ fontSize: 18 }} />
        <Typography variant="caption" color="success.main" fontWeight={600}>
          {elapsed != null ? `${elapsed}ms` : "완료"}
        </Typography>
      </Stack>
    );
  }
  if (status === "running") {
    return (
      <Stack direction="row" spacing={0.5} alignItems="center">
        <AutorenewIcon
          color="primary"
          sx={{
            fontSize: 18,
            animation: "spin 1s linear infinite",
            "@keyframes spin": { "0%": { transform: "rotate(0deg)" }, "100%": { transform: "rotate(360deg)" } },
          }}
        />
        <Typography variant="caption" color="primary.main" fontWeight={600}>
          실행 중
        </Typography>
      </Stack>
    );
  }
  if (status === "skipped") {
    return (
      <Stack direction="row" spacing={0.5} alignItems="center">
        <RemoveCircleOutlineIcon sx={{ fontSize: 18, color: "text.disabled" }} />
        <Typography variant="caption" color="text.disabled" fontWeight={600}>
          스킵
        </Typography>
      </Stack>
    );
  }
  return (
    <Stack direction="row" spacing={0.5} alignItems="center">
      <RadioButtonUncheckedIcon sx={{ fontSize: 18, color: "text.disabled" }} />
      <Typography variant="caption" color="text.disabled">
        대기
      </Typography>
    </Stack>
  );
}

export default function AgentPipelinePanel({ agentStates, elapsedByNode, toolsByNode }) {
  const theme = useTheme();
  return (
    <Paper
      variant="outlined"
      sx={{
        p: 2,
        borderRadius: "16px",
        bgcolor: alpha(theme.palette.primary.main, 0.04),
        borderColor: alpha(theme.palette.primary.main, 0.2),
        mb: 2,
      }}
    >
      <Typography variant="overline" color="text.secondary" fontWeight={700} sx={{ display: "block", mb: 1 }}>
        🤖 Agent Execution Pipeline
      </Typography>
      <Stack spacing={1.5}>
        {AGENTS.map((a) => {
          const status = agentStates[a.id] || "idle";
          const elapsed = elapsedByNode[a.id];
          const tools = toolsByNode[a.id] || [];
          const dim = status === "idle" || status === "skipped";
          const progress = status === "done" ? 100 : status === "running" ? 70 : 0;
          return (
            <Box key={a.id}>
              <Stack direction="row" alignItems="center" spacing={1} mb={0.5}>
                <Box
                  sx={{
                    width: 28,
                    height: 28,
                    borderRadius: "8px",
                    bgcolor: alpha(a.color, dim ? 0.08 : 0.2),
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontSize: 15,
                    opacity: dim ? 0.5 : 1,
                  }}
                >
                  {a.emoji}
                </Box>
                <Typography
                  variant="body2"
                  fontWeight={600}
                  sx={{ flexGrow: 1, opacity: dim ? 0.5 : 1 }}
                >
                  {a.label}
                </Typography>
                {tools.length > 0 && (
                  <Stack direction="row" spacing={0.5}>
                    {tools.map((t) => (
                      <Chip
                        key={t}
                        label={t}
                        size="small"
                        variant="outlined"
                        sx={{ height: 18, fontSize: 10, borderRadius: "6px" }}
                      />
                    ))}
                  </Stack>
                )}
                <StatusBadge status={status} elapsed={elapsed} />
              </Stack>
              <LinearProgress
                variant={status === "running" ? "indeterminate" : "determinate"}
                value={progress}
                sx={{
                  height: 4,
                  borderRadius: 2,
                  bgcolor: alpha(a.color, 0.08),
                  "& .MuiLinearProgress-bar": {
                    bgcolor: a.color,
                    ...(status === "skipped" && { bgcolor: theme.palette.text.disabled }),
                  },
                }}
              />
            </Box>
          );
        })}
      </Stack>
    </Paper>
  );
}
