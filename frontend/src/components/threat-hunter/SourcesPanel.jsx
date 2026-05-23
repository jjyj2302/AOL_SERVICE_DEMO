/**
 * 좌측 자료실 패널 (NotebookLM 의 Sources 영역에 해당).
 *
 * 두 섹션:
 *  1. 샘플 시나리오 5개 (S1~S5) — 클릭 시 onPick(scenarioId) 호출
 *  2. 분석 리포트 보관함 — 세션 내 완료된 분석 목록 (PDF 다운로드 링크)
 */
import {
  Box,
  Card,
  CardActionArea,
  CardContent,
  Chip,
  Divider,
  Paper,
  Stack,
  Typography,
  alpha,
  useTheme,
} from "@mui/material";
import PictureAsPdfIcon from "@mui/icons-material/PictureAsPdf";
import OpenInNewIcon from "@mui/icons-material/OpenInNew";

function ScenarioCard({ scenario, disabled, onPick }) {
  const theme = useTheme();
  return (
    <Card
      variant="outlined"
      sx={{
        borderRadius: "12px",
        borderColor: "divider",
        opacity: disabled ? 0.5 : 1,
        transition: "all 0.15s",
        "&:hover": disabled
          ? {}
          : {
              borderColor: "primary.main",
              boxShadow: `0 4px 12px ${alpha(theme.palette.primary.main, 0.1)}`,
              transform: "translateY(-1px)",
            },
      }}
    >
      <CardActionArea disabled={disabled} onClick={() => onPick(scenario.id)}>
        <CardContent sx={{ p: 1.5 }}>
          <Stack direction="row" alignItems="center" spacing={0.75} mb={0.5}>
            <Chip
              label={scenario.id}
              size="small"
              color="primary"
              sx={{ borderRadius: "6px", fontWeight: 700, height: 20 }}
            />
            <Typography variant="caption" color="text.secondary">
              {scenario.before_minutes}분→{scenario.estimated_after_seconds}초
            </Typography>
          </Stack>
          <Typography variant="body2" fontWeight={600} sx={{ mb: 0.25, lineHeight: 1.3 }}>
            {scenario.title}
          </Typography>
          <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
            {scenario.ioc.length > 30 ? scenario.ioc.slice(0, 30) + "…" : scenario.ioc}
          </Typography>
        </CardContent>
      </CardActionArea>
    </Card>
  );
}

function ReportItem({ report }) {
  const theme = useTheme();
  return (
    <Paper
      component="a"
      href={report.pdf_path}
      target="_blank"
      variant="outlined"
      sx={{
        p: 1.25,
        borderRadius: "10px",
        textDecoration: "none",
        display: "block",
        transition: "all 0.15s",
        "&:hover": {
          borderColor: "primary.main",
          bgcolor: alpha(theme.palette.primary.main, 0.04),
        },
      }}
    >
      <Stack direction="row" alignItems="flex-start" spacing={1}>
        <PictureAsPdfIcon sx={{ color: "error.main", fontSize: 20, mt: 0.25 }} />
        <Box sx={{ flexGrow: 1, minWidth: 0 }}>
          <Typography
            variant="body2"
            fontWeight={600}
            sx={{
              whiteSpace: "nowrap",
              overflow: "hidden",
              textOverflow: "ellipsis",
              color: "text.primary",
            }}
          >
            {report.title}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {report.timestamp}
          </Typography>
        </Box>
        <OpenInNewIcon sx={{ fontSize: 16, color: "text.disabled" }} />
      </Stack>
    </Paper>
  );
}

export default function SourcesPanel({ scenarios, reports, disabled, onPickScenario }) {
  const theme = useTheme();
  return (
    <Box>
      <Typography variant="overline" color="text.secondary" fontWeight={700} sx={{ display: "block", mb: 1.5 }}>
        📚 자료실
      </Typography>

      <Typography variant="caption" color="text.secondary" fontWeight={600} sx={{ display: "block", mb: 1 }}>
        샘플 시나리오 ({scenarios.length})
      </Typography>
      <Stack spacing={1} sx={{ mb: 3 }}>
        {scenarios.map((s) => (
          <ScenarioCard key={s.id} scenario={s} disabled={disabled} onPick={onPickScenario} />
        ))}
      </Stack>

      <Divider sx={{ my: 2 }} />

      <Typography variant="caption" color="text.secondary" fontWeight={600} sx={{ display: "block", mb: 1 }}>
        분석 리포트 ({reports.length})
      </Typography>
      {reports.length === 0 ? (
        <Paper
          variant="outlined"
          sx={{
            p: 2,
            borderRadius: "10px",
            textAlign: "center",
            bgcolor: alpha(theme.palette.text.primary, 0.02),
          }}
        >
          <Typography variant="caption" color="text.secondary">
            분석이 완료되면 PDF 리포트가 여기에 추가됩니다.
          </Typography>
        </Paper>
      ) : (
        <Stack spacing={1}>
          {reports.map((r, i) => (
            <ReportItem key={i} report={r} />
          ))}
        </Stack>
      )}
    </Box>
  );
}
