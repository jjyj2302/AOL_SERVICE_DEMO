import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  CircularProgress,
  Alert,
  Chip,
  Divider
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import BugReportIcon from '@mui/icons-material/BugReport';
import SecurityIcon from '@mui/icons-material/Security';
import PublicIcon from '@mui/icons-material/Public';
import AssessmentIcon from '@mui/icons-material/Assessment';
import CampaignIcon from '@mui/icons-material/Campaign';
import { iocLookupApi } from '../../../../shared/services/api/iocLookupApi';
import ReactMarkdown from 'react-markdown';
import { useTheme } from '@mui/material/styles';

const ThreatHunterReport = ({ ioc }) => {
  const theme = useTheme();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [reportData, setReportData] = useState(null);
  const [expanded, setExpanded] = useState('triage'); // Default expanded panel

  useEffect(() => {
    console.log('[ThreatHunterReport] Component rendered with ioc:', ioc);

    const fetchThreatHuntReport = async () => {
      console.log('[ThreatHunterReport] Starting investigation for:', ioc);
      setLoading(true);
      setError(null);

      try {
        console.log('[ThreatHunterReport] Calling API endpoint...');
        const response = await iocLookupApi.threatHuntInvestigate(ioc);
        console.log('[ThreatHunterReport] API Response:', response);
        setReportData(response);
      } catch (err) {
        console.error('[ThreatHunterReport] Investigation failed:', err);
        setError(err.message || 'Failed to generate threat hunting report');
      } finally {
        setLoading(false);
      }
    };

    if (ioc) {
      console.log('[ThreatHunterReport] IOC exists, fetching report...');
      fetchThreatHuntReport();
    } else {
      console.log('[ThreatHunterReport] No IOC provided, skipping fetch');
    }
  }, [ioc]);

  const handleAccordionChange = (panel) => (event, isExpanded) => {
    setExpanded(isExpanded ? panel : false);
  };

  if (loading) {
    return (
      <Paper sx={{ p: 4, mt: 3, textAlign: 'center', borderRadius: 2 }}>
        <CircularProgress size={40} />
        <Typography variant="h6" sx={{ mt: 2 }}>
          Running AOL Multi-Agent Investigation...
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
          This may take 1-2 minutes as our AI agents analyze the IOC
        </Typography>
      </Paper>
    );
  }

  if (error) {
    return (
      <Alert severity="error" sx={{ mt: 3, borderRadius: 2 }}>
        <Typography variant="subtitle1">Investigation Failed</Typography>
        <Typography variant="body2">{error}</Typography>
      </Alert>
    );
  }

  if (!reportData) {
    return null;
  }

  const reportSections = [
    {
      key: 'triage',
      title: 'Triage Assessment',
      icon: <AssessmentIcon />,
      content: reportData.triage_report,
      color: '#2196f3'
    },
    {
      key: 'malware',
      title: 'Malware Analysis',
      icon: <BugReportIcon />,
      content: reportData.malware_report,
      color: '#f44336'
    },
    {
      key: 'infrastructure',
      title: 'Infrastructure Correlation',
      icon: <PublicIcon />,
      content: reportData.infrastructure_report,
      color: '#ff9800'
    },
    {
      key: 'orchestrator',
      title: 'Intelligence Orchestration',
      icon: <SecurityIcon />,
      content: reportData.orchestrator_report,
      color: '#9c27b0'
    },
    {
      key: 'campaign',
      title: 'Campaign Intelligence',
      icon: <CampaignIcon />,
      content: reportData.campaign_report,
      color: '#4caf50'
    }
  ];

  return (
    <Box sx={{ mt: 3 }}>
      <Paper sx={{ p: 3, borderRadius: 2, bgcolor: theme.palette.background.paper }}>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <SecurityIcon sx={{ mr: 1, fontSize: 32, color: theme.palette.primary.main }} />
          <Typography variant="h5" fontWeight="bold">
            Threat Intelligence Report
          </Typography>
          <Chip
            label={reportData.status === 'success' ? 'Complete' : 'Failed'}
            color={reportData.status === 'success' ? 'success' : 'error'}
            size="small"
            sx={{ ml: 2 }}
          />
        </Box>

        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          IOC: <strong>{reportData.ioc}</strong>
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Investigation ID: {reportData.investigation_id}
        </Typography>

        <Divider sx={{ my: 2 }} />

        {reportSections.map((section) => (
          section.content && (
            <Accordion
              key={section.key}
              expanded={expanded === section.key}
              onChange={handleAccordionChange(section.key)}
              sx={{
                mb: 1,
                '&:before': { display: 'none' },
                borderRadius: 1,
                boxShadow: 1
              }}
            >
              <AccordionSummary
                expandIcon={<ExpandMoreIcon />}
                sx={{
                  bgcolor: expanded === section.key ? `${section.color}15` : 'transparent',
                  borderLeft: `4px solid ${section.color}`,
                  '&:hover': { bgcolor: `${section.color}10` }
                }}
              >
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <Box sx={{ color: section.color, display: 'flex', mr: 1 }}>
                    {section.icon}
                  </Box>
                  <Typography variant="h6" fontWeight="medium">
                    {section.title}
                  </Typography>
                </Box>
              </AccordionSummary>
              <AccordionDetails sx={{ p: 3 }}>
                <Box
                  sx={{
                    fontFamily: "'Noto Sans KR', 'Apple SD Gothic Neo', 'Malgun Gothic', sans-serif",
                    '& h1': {
                      fontSize: '1.75rem',
                      fontWeight: 700,
                      mt: 3,
                      mb: 2,
                      color: theme.palette.primary.main
                    },
                    '& h2': {
                      fontSize: '1.5rem',
                      fontWeight: 700,
                      mt: 3,
                      mb: 2,
                      color: theme.palette.primary.main,
                      borderBottom: `2px solid ${theme.palette.primary.light}`,
                      pb: 1
                    },
                    '& h3': {
                      fontSize: '1.25rem',
                      fontWeight: 600,
                      mt: 2.5,
                      mb: 1.5,
                      color: theme.palette.text.primary
                    },
                    '& p': {
                      mb: 2,
                      lineHeight: 2,
                      fontSize: '1rem',
                      color: theme.palette.text.primary
                    },
                    '& ul, & ol': {
                      pl: 4,
                      mb: 2,
                      lineHeight: 1.8
                    },
                    '& li': {
                      mb: 1,
                      fontSize: '0.95rem',
                      lineHeight: 1.8
                    },
                    '& strong': {
                      fontWeight: 700,
                      color: theme.palette.primary.main
                    },
                    '& code': {
                      bgcolor: theme.palette.mode === 'dark' ? '#2d2d2d' : '#f5f5f5',
                      p: 0.5,
                      borderRadius: 1,
                      fontSize: '0.9em',
                      fontFamily: "'Monaco', 'Consolas', 'Courier New', monospace"
                    },
                    '& pre': {
                      bgcolor: theme.palette.mode === 'dark' ? '#2d2d2d' : '#f5f5f5',
                      p: 2,
                      borderRadius: 1,
                      overflow: 'auto',
                      fontSize: '0.9rem',
                      lineHeight: 1.6
                    }
                  }}
                >
                  <ReactMarkdown>{section.content}</ReactMarkdown>
                </Box>
              </AccordionDetails>
            </Accordion>
          )
        ))}

        {reportData.final_report && (
          <Box sx={{ mt: 3, p: 2, bgcolor: theme.palette.background.default, borderRadius: 1 }}>
            <Typography variant="subtitle2" fontWeight="bold" gutterBottom>
              Final Summary
            </Typography>
            <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
              {reportData.final_report}
            </Typography>
          </Box>
        )}
      </Paper>
    </Box>
  );
};

export default ThreatHunterReport;
