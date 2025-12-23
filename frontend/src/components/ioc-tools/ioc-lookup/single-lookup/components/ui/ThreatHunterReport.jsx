import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Tabs,
  Tab,
  CircularProgress,
  Alert,
  Chip,
  useMediaQuery,
} from '@mui/material';
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
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [reportData, setReportData] = useState(null);
  const [currentTab, setCurrentTab] = useState(0);

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

  const handleTabChange = (event, newValue) => {
    setCurrentTab(newValue);
  };

  if (loading) {
    return (
      <Paper sx={{ p: 4, mt: 3, textAlign: 'center', borderRadius: '18px', boxShadow: '0 4px 24px rgba(0,0,0,0.02)' }}>
        <CircularProgress size={40} sx={{ color: '#007AFF' }} />
        <Typography variant="h6" sx={{ mt: 2, fontWeight: 600 }}>
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
      <Alert severity="error" sx={{ mt: 3, borderRadius: '12px' }}>
        <Typography variant="subtitle1" fontWeight={600}>Investigation Failed</Typography>
        <Typography variant="body2">{error}</Typography>
      </Alert>
    );
  }

  if (!reportData) {
    return null;
  }

  const reportSections = [
    {
      key: 'summary',
      title: 'Final Summary',
      icon: <SummarizeIcon />,
      content: reportData.final_report,
      component: FinalSummarySection
    },
    {
      key: 'triage',
      title: 'Triage Assessment',
      icon: <AssessmentIcon />,
      content: reportData.triage_report,
      component: TriageResult
    },
    {
      key: 'malware',
      title: 'Malware Analysis',
      icon: <BugReportIcon />,
      content: reportData.malware_report,
      component: MalwareResult
    },
    {
      key: 'infrastructure',
      title: 'Infrastructure Correlation',
      icon: <PublicIcon />,
      content: reportData.infrastructure_report,
      component: InfrastructureResult
    },
    {
      key: 'campaign',
      title: 'Campaign Intelligence',
      icon: <CampaignIcon />,
      content: reportData.campaign_report,
      component: CampaignIntelligenceSection
    }
  ];

  // Filter out sections with no content
  const activeSections = reportSections.filter(section => section.content);

  const CurrentSectionComponent = activeSections[currentTab]?.component;
  const currentSectionData = activeSections[currentTab]?.content;

  return (
    <Box sx={{ mt: 3, fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif' }}>
      {/* Header with Title */}
      <Paper
        elevation={0}
        sx={{
          p: 3,
          mb: 3,
          borderRadius: "18px",
          bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(28, 28, 30, 0.6)' : '#FFFFFF',
          border: (theme) => `1px solid ${theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.1)' : '#E5E5EA'}`,
          boxShadow: (theme) => theme.palette.mode === 'dark' ? 'none' : '0 4px 24px rgba(0,0,0,0.02)',
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1, flexWrap: 'wrap', gap: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <SecurityIcon sx={{ mr: 1.5, fontSize: 32, color: '#007AFF' }} />
            <Typography variant="h5" fontWeight={700} sx={{ color: (theme) => theme.palette.mode === 'dark' ? '#fff' : '#1D1D1F' }}>
              Threat Intelligence Report
            </Typography>
          </Box>
          <Box sx={{ flexGrow: 1 }} />
          <Chip
            label={reportData.status === 'success' ? 'Analysis Complete' : 'Analysis Failed'}
            sx={{
              bgcolor: reportData.status === 'success' ? 'rgba(52, 199, 89, 0.1)' : 'rgba(255, 59, 48, 0.1)',
              color: reportData.status === 'success' ? '#34C759' : '#FF3B30',
              fontWeight: 600,
              borderRadius: '8px'
            }}
            size="small"
          />
        </Box>
        <Typography variant="body2" sx={{ color: (theme) => theme.palette.mode === 'dark' ? '#aaa' : '#86868B', ml: 0.5 }}>
          IOC: <strong style={{ color: theme.palette.mode === 'dark' ? '#fff' : '#1D1D1F' }}>{reportData.ioc}</strong> • Investigation ID: {reportData.investigation_id}
        </Typography>
      </Paper>

      {/* Tabs Navigation */}
      <Paper
        elevation={0}
        sx={{
          mb: 3,
          borderRadius: "14px",
          overflow: 'hidden',
          border: (theme) => `1px solid ${theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.1)' : '#E5E5EA'}`,
          bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(28, 28, 30, 0.6)' : '#FFFFFF',
          boxShadow: 'none'
        }}
      >
        <Tabs
          value={currentTab}
          onChange={handleTabChange}
          variant={isMobile ? "scrollable" : "fullWidth"}
          scrollButtons="auto"
          allowScrollButtonsMobile
          sx={{
            '& .MuiTab-root': {
              minHeight: 56,
              textTransform: 'none',
              fontSize: '0.95rem',
              fontWeight: 600,
              gap: 1,
              color: (theme) => theme.palette.mode === 'dark' ? '#aaa' : '#86868B',
              '&.Mui-selected': {
                color: '#007AFF',
              }
            },
            '& .MuiTabs-indicator': {
              backgroundColor: '#007AFF',
              height: 3,
              borderRadius: '3px 3px 0 0'
            }
          }}
        >
          {activeSections.map((section) => (
            <Tab
              key={section.key}
              icon={section.icon}
              label={section.title}
              iconPosition="start"
            />
          ))}
        </Tabs>
      </Paper>

      {/* Content Area */}
      <Box sx={{ minHeight: 400 }}>
        {CurrentSectionComponent && (
          <Paper
            elevation={0}
            sx={{
              p: 3,
              borderRadius: "18px",
              border: (theme) => `1px solid ${theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.1)' : '#E5E5EA'}`,
              bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(28, 28, 30, 0.6)' : '#FFFFFF',
              boxShadow: (theme) => theme.palette.mode === 'dark' ? 'none' : '0 4px 24px rgba(0,0,0,0.02)',
              animation: 'fadeIn 0.4s cubic-bezier(0.16, 1, 0.3, 1)',
              '@keyframes fadeIn': {
                '0%': { opacity: 0, transform: 'translateY(10px)' },
                '100%': { opacity: 1, transform: 'translateY(0)' }
              }
            }}
          >
            <CurrentSectionComponent data={currentSectionData} />
          </Paper>
        )}
      </Box>
    </Box>
  );
};

export default ThreatHunterReport;
