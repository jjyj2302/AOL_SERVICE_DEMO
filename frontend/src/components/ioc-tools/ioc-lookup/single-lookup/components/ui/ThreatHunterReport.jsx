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
  Divider,
  Button,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import PictureAsPdfIcon from '@mui/icons-material/PictureAsPdf';
import PrintIcon from '@mui/icons-material/Print';
import BugReportIcon from '@mui/icons-material/BugReport';
import SecurityIcon from '@mui/icons-material/Security';
import PublicIcon from '@mui/icons-material/Public';
import AssessmentIcon from '@mui/icons-material/Assessment';
import CampaignIcon from '@mui/icons-material/Campaign';
import SummarizeIcon from '@mui/icons-material/Summarize';
import { iocLookupApi } from '../../../../shared/services/api/iocLookupApi';
import { useTheme } from '@mui/material/styles';
import CampaignIntelligenceSection from './report-sections/CampaignIntelligenceSection';
import FinalSummarySection from './report-sections/FinalSummarySection';
import TriageResult from '../../../../../agents/results/TriageResult';
import MalwareResult from '../../../../../agents/results/MalwareResult';
import InfrastructureResult from '../../../../../agents/results/InfrastructureResult';

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

        // Parse JSON strings from backend (like AI Agents pattern)
        const parsedResponse = { ...response };
        const reportFields = ['triage_report', 'malware_report', 'infrastructure_report',
          'orchestrator_report', 'campaign_report', 'final_report'];

        reportFields.forEach(field => {
          if (parsedResponse[field] && typeof parsedResponse[field] === 'string') {
            try {
              parsedResponse[field] = JSON.parse(parsedResponse[field]);
              console.log(`[ThreatHunterReport] Successfully parsed ${field}`);
            } catch (parseError) {
              console.warn(`[ThreatHunterReport] Failed to parse ${field}, keeping as string:`, parseError);
              // Keep as string if parsing fails (might be plain text/markdown)
            }
          }
        });

        console.log('[ThreatHunterReport] Parsed Response:', parsedResponse);
        setReportData(parsedResponse);
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
      content: reportData.triage_report
    },
    {
      key: 'malware',
      title: 'Malware Analysis',
      icon: <BugReportIcon />,
      content: reportData.malware_report
    },
    {
      key: 'infrastructure',
      title: 'Infrastructure Correlation',
      icon: <PublicIcon />,
      content: reportData.infrastructure_report
    },
    {
      key: 'campaign',
      title: 'Campaign Intelligence',
      icon: <CampaignIcon />,
      content: reportData.campaign_report
    }
  ];

  const handlePdfExport = () => {
    // TODO: Implement PDF export functionality
    console.log('PDF Export clicked');
    alert('PDF 내보내기 기능은 곧 추가됩니다!');
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <Box sx={{ mt: 3 }}>
      {/* Header with Title */}
      <Paper
        elevation={0}
        sx={{
          p: 3,
          mb: 2,
          borderRadius: "16px",
          bgcolor: (theme) => theme.palette.mode === 'dark'
            ? 'rgba(30, 41, 59, 0.4)'
            : 'rgba(241, 245, 249, 0.8)',
          backdropFilter: 'blur(12px)',
          border: (theme) => `1px solid ${theme.palette.divider}`,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
          <SecurityIcon sx={{ mr: 1, fontSize: 32, color: theme.palette.primary.main }} />
          <Typography variant="h5" fontWeight={700}>
            Threat Intelligence Report
          </Typography>
          <Chip
            label={reportData.status === 'success' ? 'Complete' : 'Failed'}
            color={reportData.status === 'success' ? 'success' : 'error'}
            size="small"
            sx={{ ml: 2 }}
          />
        </Box>
        <Typography variant="body2" color="text.secondary">
          IOC: <strong>{reportData.ioc}</strong> • Investigation ID: {reportData.investigation_id}
        </Typography>
      </Paper>

      {/* Agent Results */}
      <Box sx={{ mb: 4 }}>
        {reportSections.map((section) => {
          // Determine which component to use for each section
          let SectionComponent = null;

          if (section.key === 'triage' && typeof section.content === 'object') {
            SectionComponent = () => <TriageResult data={section.content} />;
          } else if (section.key === 'malware' && typeof section.content === 'object') {
            SectionComponent = () => <MalwareResult data={section.content} />;
          } else if (section.key === 'infrastructure' && typeof section.content === 'object') {
            SectionComponent = () => <InfrastructureResult data={section.content} />;
          } else if (section.key === 'campaign' && section.content) {
            SectionComponent = () => <CampaignIntelligenceSection data={section.content} />;
          }

          // Use dedicated component if available
          if (SectionComponent && section.content) {
            return (
              <Accordion
                key={section.key}
                expanded={expanded === section.key}
                onChange={handleAccordionChange(section.key)}
                elevation={0}
                sx={{
                  mb: 2,
                  '&:before': { display: 'none' },
                  borderRadius: "16px !important",
                  border: (theme) => `1px solid ${theme.palette.divider}`,
                  overflow: 'hidden'
                }}
              >
                <AccordionSummary
                  expandIcon={<ExpandMoreIcon />}
                  sx={{
                    bgcolor: (theme) => expanded === section.key
                      ? theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.03)' : 'rgba(0, 0, 0, 0.02)'
                      : 'transparent',
                    '&:hover': {
                      bgcolor: (theme) => theme.palette.mode === 'dark'
                        ? 'rgba(255, 255,255, 0.02)'
                        : 'rgba(0, 0, 0, 0.01)'
                    },
                    minHeight: 64,
                    '& .MuiAccordionSummary-content': { my: 2 }
                  }}
                >
                  <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    <Box sx={{
                      color: 'primary.main',
                      display: 'flex',
                      mr: 2,
                      width: 40,
                      height: 40,
                      alignItems: 'center',
                      justifyContent: 'center',
                      bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.04)',
                      borderRadius: "10px"
                    }}>
                      {section.icon}
                    </Box>
                    <Typography variant="h6" fontWeight={600}>
                      {section.title}
                    </Typography>
                  </Box>
                </AccordionSummary>
                <AccordionDetails sx={{ p: 3, bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(0,0,0,0.2)' : 'rgba(0,0,0,0.01)' }}>
                  <SectionComponent />
                </AccordionDetails>
              </Accordion>
            );
          }

          return null;
        })}
      </Box>

      {/* Final Summary - Now Full Width Below */}
      {reportData.final_report && (
        <FinalSummarySection data={reportData.final_report} />
      )}
    </Box>
  );
};

export default ThreatHunterReport;
