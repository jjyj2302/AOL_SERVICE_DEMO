import React, { useState } from 'react';
import {
  Box, Paper, Typography, Chip, Button, Accordion, AccordionSummary,
  AccordionDetails, Divider, useTheme, IconButton, Dialog, DialogContent
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import SecurityIcon from '@mui/icons-material/Security';
import BugReportIcon from '@mui/icons-material/BugReport';
import CloudIcon from '@mui/icons-material/Cloud';
import CampaignIcon from '@mui/icons-material/Campaign';
import SummarizeIcon from '@mui/icons-material/Summarize';
import PictureAsPdfIcon from '@mui/icons-material/PictureAsPdf';
import CloseIcon from '@mui/icons-material/Close';

const getThreatLevelColor = (level) => {
  switch (level?.toLowerCase()) {
    case 'critical': return '#AF52DE';
    case 'high': return '#FF3B30';
    case 'medium': return '#FF9500';
    case 'low': return '#34C759';
    default: return '#8E8E93';
  }
};

const formatDate = (dateStr) => {
  if (!dateStr) return '-';
  const date = new Date(dateStr);
  return date.toLocaleString('ko-KR', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
};

const AgentResultSection = ({ title, icon, data, isDarkMode }) => {
  if (!data) return null;

  const renderValue = (value, depth = 0) => {
    if (value === null || value === undefined) return <Typography color="textSecondary">-</Typography>;

    if (typeof value === 'object' && !Array.isArray(value)) {
      return (
        <Box sx={{ pl: depth > 0 ? 2 : 0 }}>
          {Object.entries(value).map(([key, val]) => (
            <Box key={key} sx={{ mb: 1 }}>
              <Typography variant="caption" sx={{ fontWeight: 600, color: isDarkMode ? '#888' : '#666' }}>
                {key.replace(/_/g, ' ').toUpperCase()}
              </Typography>
              {renderValue(val, depth + 1)}
            </Box>
          ))}
        </Box>
      );
    }

    if (Array.isArray(value)) {
      if (value.length === 0) return <Typography color="textSecondary">없음</Typography>;
      return (
        <Box sx={{ pl: depth > 0 ? 2 : 0 }}>
          {value.map((item, idx) => (
            <Box key={idx} sx={{ mb: 0.5 }}>
              {typeof item === 'object' ? renderValue(item, depth + 1) : (
                <Chip label={String(item)} size="small" sx={{ mr: 0.5, mb: 0.5 }} />
              )}
            </Box>
          ))}
        </Box>
      );
    }

    return (
      <Typography
        variant="body2"
        sx={{
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
          bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.02)',
          p: 1,
          borderRadius: 1
        }}
      >
        {String(value)}
      </Typography>
    );
  };

  return (
    <Accordion
      defaultExpanded
      sx={{
        bgcolor: isDarkMode ? 'rgba(255,255,255,0.02)' : '#FAFAFA',
        '&:before': { display: 'none' },
        borderRadius: '12px !important',
        mb: 2
      }}
    >
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          {icon}
          <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>{title}</Typography>
        </Box>
      </AccordionSummary>
      <AccordionDetails>
        {renderValue(data)}
      </AccordionDetails>
    </Accordion>
  );
};

export default function SessionDetail({ session, onBack, getFileUrl }) {
  const theme = useTheme();
  const isDarkMode = theme.palette.mode === 'dark';
  const [pdfOpen, setPdfOpen] = useState(false);

  const cardStyle = {
    bgcolor: isDarkMode ? 'rgba(28, 28, 30, 0.6)' : '#FFFFFF',
    borderRadius: '18px',
    border: isDarkMode ? '1px solid rgba(255,255,255,0.1)' : '1px solid #E5E5EA',
    overflow: 'hidden'
  };

  if (!session) return null;

  const iocAnalysis = session.ioc_analyses?.[0];

  return (
    <Box>
      {/* Header */}
      <Paper sx={{ ...cardStyle, p: 3, mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
          <Button
            startIcon={<ArrowBackIcon />}
            onClick={onBack}
            sx={{ color: isDarkMode ? '#fff' : '#000' }}
          >
            목록으로
          </Button>
        </Box>

        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
          {session.session_name || `세션 #${session.id}`}
        </Typography>

        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
          <Chip
            label={session.status}
            color={session.status === 'completed' ? 'success' : 'default'}
          />
          <Typography variant="body2" color="textSecondary">
            생성: {formatDate(session.created_at)}
          </Typography>
          {session.completed_at && (
            <Typography variant="body2" color="textSecondary">
              완료: {formatDate(session.completed_at)}
            </Typography>
          )}
          <Typography variant="body2" color="textSecondary">
            IOC 수: {session.total_iocs}
          </Typography>
        </Box>

        {/* PDF Viewer Button */}
        {session.uploaded_file && (
          <Box sx={{ mt: 2 }}>
            <Button
              variant="outlined"
              startIcon={<PictureAsPdfIcon />}
              onClick={() => setPdfOpen(true)}
              sx={{
                borderColor: isDarkMode ? 'rgba(255,255,255,0.3)' : '#E5E5EA',
                color: isDarkMode ? '#fff' : '#000'
              }}
            >
              PDF 보기: {session.uploaded_file.filename}
            </Button>
          </Box>
        )}
      </Paper>

      {/* IOC Analysis Results */}
      {iocAnalysis && (
        <Paper sx={{ ...cardStyle, p: 3, mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
            <Box>
              <Typography variant="h6" sx={{ fontWeight: 700 }}>
                IOC 분석 결과
              </Typography>
              <Typography variant="body1" sx={{ fontFamily: 'monospace', mt: 1 }}>
                {iocAnalysis.ioc_value}
              </Typography>
            </Box>
            {iocAnalysis.overall_threat_level && (
              <Chip
                label={iocAnalysis.overall_threat_level.toUpperCase()}
                sx={{
                  bgcolor: getThreatLevelColor(iocAnalysis.overall_threat_level),
                  color: '#fff',
                  fontWeight: 700
                }}
              />
            )}
          </Box>

          <Divider sx={{ mb: 3 }} />

          {/* Agent Results */}
          <AgentResultSection
            title="Triage Assessment"
            icon={<SecurityIcon sx={{ color: '#007AFF' }} />}
            data={iocAnalysis.triage_result}
            isDarkMode={isDarkMode}
          />

          <AgentResultSection
            title="Malware Analysis"
            icon={<BugReportIcon sx={{ color: '#FF3B30' }} />}
            data={iocAnalysis.malware_result}
            isDarkMode={isDarkMode}
          />

          <AgentResultSection
            title="Infrastructure Correlation"
            icon={<CloudIcon sx={{ color: '#FF9500' }} />}
            data={iocAnalysis.infrastructure_result}
            isDarkMode={isDarkMode}
          />

          <AgentResultSection
            title="Campaign Intelligence"
            icon={<CampaignIcon sx={{ color: '#AF52DE' }} />}
            data={iocAnalysis.campaign_result}
            isDarkMode={isDarkMode}
          />
        </Paper>
      )}

      {/* Aggregation Result */}
      {session.aggregation && (
        <Paper sx={{ ...cardStyle, p: 3 }}>
          <AgentResultSection
            title="종합 분석 보고서"
            icon={<SummarizeIcon sx={{ color: '#34C759' }} />}
            data={session.aggregation.aggregated_report}
            isDarkMode={isDarkMode}
          />
        </Paper>
      )}

      {/* PDF Viewer Dialog */}
      <Dialog
        open={pdfOpen}
        onClose={() => setPdfOpen(false)}
        maxWidth="lg"
        fullWidth
      >
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', p: 2 }}>
          <Typography variant="h6">
            {session.uploaded_file?.filename}
          </Typography>
          <IconButton onClick={() => setPdfOpen(false)}>
            <CloseIcon />
          </IconButton>
        </Box>
        <DialogContent sx={{ p: 0, height: '80vh' }}>
          {session.uploaded_file && (
            <iframe
              src={getFileUrl(session.uploaded_file.id)}
              style={{ width: '100%', height: '100%', border: 'none' }}
              title="PDF Viewer"
            />
          )}
        </DialogContent>
      </Dialog>
    </Box>
  );
}
