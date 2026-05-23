/**
 * 비용 분석 카드 — 에이전트별 모델 매핑으로 얼마나 절감되는지 표시.
 *
 * GET /api/lg/cost-analysis 호출하여 3가지 전략 비용 비교 + 월간 절감액 표시.
 */
import { useEffect, useState } from "react";
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Chip,
  LinearProgress,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
  alpha,
  useTheme,
} from "@mui/material";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import SavingsIcon from "@mui/icons-material/Savings";
import api from "../../api";

function StrategyRow({ name, label, cost, savings, color, baseline }) {
  return (
    <Stack direction="row" alignItems="center" spacing={1.5} sx={{ py: 0.75 }}>
      <Box sx={{ minWidth: 110 }}>
        <Typography variant="caption" fontWeight={700} color={`${color}.main`}>
          {label}
        </Typography>
      </Box>
      <Box sx={{ flexGrow: 1 }}>
        <Typography variant="body2" fontWeight={700} sx={{ fontFamily: "monospace" }}>
          ${cost.toFixed(4)}
          <Typography component="span" variant="caption" color="text.secondary" sx={{ ml: 0.5 }}>
            / IoC
          </Typography>
        </Typography>
        {!baseline && (
          <LinearProgress
            variant="determinate"
            value={100 - savings}
            color={color}
            sx={{ height: 4, borderRadius: 2, mt: 0.5 }}
          />
        )}
      </Box>
      {!baseline ? (
        <Chip
          size="small"
          label={`-${savings}%`}
          color={color}
          sx={{ borderRadius: "8px", fontWeight: 700, height: 22, minWidth: 56 }}
        />
      ) : (
        <Chip
          size="small"
          label="기준"
          variant="outlined"
          sx={{ borderRadius: "8px", height: 22, minWidth: 56 }}
        />
      )}
    </Stack>
  );
}

export default function CostAnalysisCard() {
  const theme = useTheme();
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => {
    api.get("/api/lg/cost-analysis")
      .then((r) => setData(r.data))
      .catch((e) => setErr(e.message));
  }, []);

  if (err) return null;
  if (!data) return null;

  const s = data.strategies;
  const baseline = s.all_strong.total_cost_usd;
  const mixed = s.mixed.total_cost_usd;
  const cached = s.mixed_cached_batch.total_cost_usd;

  const monthly10k = (data.monthly_at_scale || []).find((v) => v.daily_iocs === 10000);
  const savings10k = monthly10k?.monthly_savings_vs_baseline_usd || 0;

  return (
    <Paper
      variant="outlined"
      sx={{
        p: 2,
        borderRadius: "16px",
        mb: 2,
        background: `linear-gradient(135deg, ${alpha(theme.palette.success.main, 0.04)} 0%, ${alpha(theme.palette.success.main, 0.08)} 100%)`,
        borderColor: alpha(theme.palette.success.main, 0.3),
      }}
    >
      <Stack direction="row" alignItems="center" spacing={1} mb={1.5}>
        <SavingsIcon color="success" />
        <Typography variant="overline" fontWeight={700} color="success.main">
          💰 비용 분석 (실측 기반)
        </Typography>
      </Stack>

      <Stack spacing={0.5}>
        <StrategyRow label="All-Opus" cost={baseline} color="default" baseline />
        <StrategyRow
          label="Mixed (권장)"
          cost={mixed}
          savings={s.mixed.savings_vs_baseline_pct}
          color="primary"
        />
        <StrategyRow
          label="+ Cache + Batch"
          cost={cached}
          savings={s.mixed_cached_batch.savings_vs_baseline_pct}
          color="success"
        />
      </Stack>

      {monthly10k && (
        <Box sx={{ mt: 1.5, pt: 1.5, borderTop: 1, borderColor: "divider" }}>
          <Typography variant="caption" color="text.secondary">
            금융권 SOC 규모 10,000 IoCs/일 기준 월간 절감
          </Typography>
          <Typography variant="h6" fontWeight={800} color="success.main">
            $ {savings10k.toLocaleString()}{" "}
            <Typography component="span" variant="caption" color="text.secondary">
              / 월
            </Typography>
          </Typography>
        </Box>
      )}

      <Accordion
        sx={{
          mt: 1.5,
          borderRadius: "8px !important",
          border: 1,
          borderColor: "divider",
          boxShadow: "none",
          "&:before": { display: "none" },
        }}
      >
        <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ fontSize: 18 }} />} sx={{ minHeight: 36, py: 0 }}>
          <Typography variant="caption" fontWeight={600}>
            에이전트별 모델 매핑 보기
          </Typography>
        </AccordionSummary>
        <AccordionDetails sx={{ pt: 0 }}>
          <Table size="small" sx={{ "& td, & th": { fontSize: 11, py: 0.5 } }}>
            <TableHead>
              <TableRow>
                <TableCell>Agent</TableCell>
                <TableCell>Tier</TableCell>
                <TableCell align="right">in/out</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {s.mixed.per_agent_breakdown.map((a) => (
                <TableRow key={a.node}>
                  <TableCell>{a.label}</TableCell>
                  <TableCell>
                    <Chip
                      size="small"
                      label={a.tier || "—"}
                      sx={{ borderRadius: "6px", height: 16, fontSize: 10 }}
                      color={a.tier === "mini" ? "info" : a.tier === "medium" ? "primary" : "warning"}
                    />
                  </TableCell>
                  <TableCell align="right" sx={{ fontFamily: "monospace" }}>
                    {a.input_tokens}/{a.output_tokens}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </AccordionDetails>
      </Accordion>
    </Paper>
  );
}
