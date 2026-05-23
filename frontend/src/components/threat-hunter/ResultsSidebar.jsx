/**
 * 우측 사이드바 — 대화창 외부에 에이전트 실행 진행 + 산출물을 표시.
 *
 * Props:
 *  - run: {agentStates, elapsedByNode, toolsByNode, deliverables?, parsed?, title?, mcp_calls?, route_plan?}
 */
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Chip,
  Grid,
  LinearProgress,
  Paper,
  Stack,
  Typography,
  Button,
  alpha,
  useTheme,
} from "@mui/material";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import DownloadIcon from "@mui/icons-material/Download";
import ShieldIcon from "@mui/icons-material/Shield";
import BoltIcon from "@mui/icons-material/Bolt";
import VerifiedUserIcon from "@mui/icons-material/VerifiedUser";
import WarningAmberIcon from "@mui/icons-material/WarningAmber";
import AgentPipelinePanel from "./AgentPipelinePanel";

const LEVEL_COLOR = {
  L0: "default",
  L1: "info",
  L2: "primary",
  L3: "warning",
  L4: "error",
};

function MetricCard({ icon, label, value, sub, color = "primary", progress }) {
  const theme = useTheme();
  return (
    <Paper
      variant="outlined"
      sx={{ p: 2, borderRadius: "12px", height: "100%", borderColor: "divider" }}
    >
      <Stack direction="row" spacing={1.5} alignItems="flex-start">
        <Box
          sx={{
            p: 0.75,
            borderRadius: "8px",
            bgcolor: alpha(theme.palette[color]?.main || theme.palette.primary.main, 0.1),
            color: `${color}.main`,
            display: "flex",
          }}
        >
          {icon}
        </Box>
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="caption" color="text.secondary">
            {label}
          </Typography>
          <Typography variant="h6" fontWeight={800} sx={{ lineHeight: 1.2 }}>
            {value}
          </Typography>
          {progress != null && (
            <LinearProgress
              variant="determinate"
              value={progress}
              sx={{ mt: 0.75, height: 5, borderRadius: 3 }}
              color={color}
            />
          )}
          {sub && (
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5 }}>
              {sub}
            </Typography>
          )}
        </Box>
      </Stack>
    </Paper>
  );
}

function Section({ title, count, defaultExpanded, children }) {
  return (
    <Accordion
      defaultExpanded={defaultExpanded}
      sx={{
        borderRadius: "12px !important",
        border: 1,
        borderColor: "divider",
        boxShadow: "none",
        mb: 1,
        "&:before": { display: "none" },
        "&.Mui-expanded": { mb: 1 },
      }}
    >
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Stack direction="row" spacing={1} alignItems="center">
          <Typography fontWeight={700} variant="body2">
            {title}
          </Typography>
          {count != null && <Chip size="small" label={count} sx={{ borderRadius: "8px", height: 20 }} />}
        </Stack>
      </AccordionSummary>
      <AccordionDetails>{children}</AccordionDetails>
    </Accordion>
  );
}

export default function ResultsSidebar({ run }) {
  const theme = useTheme();
  const {
    agentStates = {},
    elapsedByNode = {},
    toolsByNode = {},
    deliverables = null,
    parsed = null,
    title = null,
    mcp_calls = [],
    final = null,
    pdfPath = null,
  } = run || {};

  const score = final?.confidence_score;
  const level = final?.automation_level;
  const approval = final?.human_approval_required;
  const elapsed_ms = final?.elapsed_ms;
  const before_minutes = deliverables?.before_minutes;

  const empty = !title;

  return (
    <Box>
      <Typography variant="overline" color="text.secondary" fontWeight={700} sx={{ display: "block", mb: 1.5 }}>
        📊 분석 진행 / 산출물
      </Typography>

      {empty ? (
        <Paper
          variant="outlined"
          sx={{
            p: 4,
            textAlign: "center",
            color: "text.secondary",
            borderRadius: "16px",
            bgcolor: alpha(theme.palette.text.primary, 0.02),
          }}
        >
          <Typography variant="body2">
            좌측 채팅창에 IoC 를 입력하거나
            <br />
            샘플 시나리오를 클릭하면
            <br />
            여기에 분석 진행이 표시됩니다.
          </Typography>
        </Paper>
      ) : (
        <>
          {/* Parsed input badge */}
          {parsed && (
            <Paper
              variant="outlined"
              sx={{
                p: 1.5,
                mb: 2,
                borderRadius: "12px",
                background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.04)} 0%, ${alpha(theme.palette.primary.main, 0.08)} 100%)`,
              }}
            >
              <Typography variant="caption" color="text.secondary">분석 대상</Typography>
              <Stack direction="row" spacing={1} alignItems="center" mt={0.5} flexWrap="wrap">
                <Chip size="small" label={parsed.ioc_type} sx={{ borderRadius: "8px" }} />
                <Typography variant="body2" sx={{ fontFamily: "monospace", fontWeight: 600 }}>
                  {parsed.ioc}
                </Typography>
                {parsed.scenario_id && (
                  <Chip size="small" color="primary" label={parsed.scenario_id} sx={{ borderRadius: "8px" }} />
                )}
              </Stack>
            </Paper>
          )}

          <AgentPipelinePanel
            agentStates={agentStates}
            elapsedByNode={elapsedByNode}
            toolsByNode={toolsByNode}
          />

          {/* Metrics */}
          {level && (
            <Grid container spacing={1.5} sx={{ mb: 2 }}>
              <Grid item xs={6}>
                <MetricCard
                  icon={<ShieldIcon />}
                  label="자동화 등급"
                  value={level}
                  color={LEVEL_COLOR[level] || "default"}
                  sub="L0=권고 · L4=자동차단"
                />
              </Grid>
              <Grid item xs={6}>
                <MetricCard
                  icon={<BoltIcon />}
                  label="신뢰도"
                  value={`${(score * 100).toFixed(0)}%`}
                  color={LEVEL_COLOR[level] || "primary"}
                  progress={score * 100}
                />
              </Grid>
              <Grid item xs={6}>
                <MetricCard
                  icon={<BoltIcon />}
                  label="처리 시간"
                  value={`${elapsed_ms ?? "—"}ms`}
                  sub={before_minutes ? `Before: ${before_minutes}분` : null}
                  color="primary"
                />
              </Grid>
              <Grid item xs={6}>
                <MetricCard
                  icon={approval ? <WarningAmberIcon /> : <VerifiedUserIcon />}
                  label="휴먼 승인"
                  value={approval ? "필수" : "불필요"}
                  color={approval ? "warning" : "success"}
                />
              </Grid>
            </Grid>
          )}

          {/* PDF */}
          {pdfPath && (
            <Button
              variant="contained"
              fullWidth
              startIcon={<DownloadIcon />}
              href={pdfPath}
              target="_blank"
              sx={{ mb: 2, borderRadius: "12px", textTransform: "none", boxShadow: "none" }}
            >
              PDF 리포트 다운로드
            </Button>
          )}

          {/* FW Rules */}
          {deliverables?.firewall_rules?.length > 0 && (
            <Section title="🛡️ 방화벽 차단 규칙" count={deliverables.firewall_rules.length}>
              <Paper
                variant="outlined"
                sx={{
                  p: 1.5,
                  borderRadius: "8px",
                  fontFamily: "monospace",
                  fontSize: 11,
                  whiteSpace: "pre",
                  overflowX: "auto",
                  bgcolor: alpha(theme.palette.text.primary, 0.03),
                }}
              >
                {deliverables.firewall_rules.join("\n")}
              </Paper>
            </Section>
          )}

          {/* Hunt Hypotheses */}
          {deliverables?.hunt_hypotheses?.length > 0 && (
            <Section title="🔍 헌팅 쿼리" count={deliverables.hunt_hypotheses.length}>
              <Stack spacing={1}>
                {deliverables.hunt_hypotheses.map((h, i) => (
                  <Paper key={i} variant="outlined" sx={{ p: 1.25, borderRadius: "8px" }}>
                    <Stack direction="row" spacing={0.5} mb={0.75} alignItems="center" flexWrap="wrap">
                      <Chip size="small" label={`#${h.hypothesis_id}`} sx={{ borderRadius: "6px", height: 18 }} />
                      <Chip size="small" variant="outlined" label={h.platform} sx={{ borderRadius: "6px", height: 18 }} />
                    </Stack>
                    <Box
                      sx={{
                        fontFamily: "monospace",
                        fontSize: 11,
                        bgcolor: alpha(theme.palette.text.primary, 0.05),
                        p: 1,
                        borderRadius: "6px",
                        overflowX: "auto",
                        whiteSpace: "pre-wrap",
                      }}
                    >
                      {h.query}
                    </Box>
                  </Paper>
                ))}
              </Stack>
            </Section>
          )}

          {/* MCP Calls */}
          {mcp_calls.length > 0 && (
            <Section title="🧩 MCP Tool Calls" count={mcp_calls.length}>
              <Stack spacing={0.5}>
                {mcp_calls.map((c, i) => (
                  <Stack key={i} direction="row" spacing={1} alignItems="center" sx={{ fontSize: 12 }}>
                    <Chip size="small" label={c.tool} color="primary" variant="outlined" sx={{ borderRadius: "6px", height: 18 }} />
                    <Typography variant="caption" sx={{ fontFamily: "monospace", flexGrow: 1 }}>
                      {c.input_key}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {c.elapsed_ms}ms
                    </Typography>
                  </Stack>
                ))}
              </Stack>
            </Section>
          )}
        </>
      )}
    </Box>
  );
}
