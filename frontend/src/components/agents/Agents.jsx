import React, { useState, useRef } from 'react';
import {
  Box,
  Typography,
  TextField,
  Button,
  Paper,
  CircularProgress,
  Alert,
  Chip,
  Divider,
  Fab,
  Badge,
} from '@mui/material';
import { alpha } from '@mui/material/styles';
import SearchIcon from '@mui/icons-material/Search';
import PsychologyIcon from '@mui/icons-material/Psychology';
import BugReportIcon from '@mui/icons-material/BugReport';
import HubIcon from '@mui/icons-material/Hub';
import AssessmentIcon from '@mui/icons-material/Assessment';
import ListAltIcon from '@mui/icons-material/ListAlt';
import SecurityIcon from '@mui/icons-material/Security';
import { determineIocType } from '../ioc-tools/ioc-lookup/shared/utils/iocDefinitions';
import DiscoveredIOCs from './DiscoveredIOCs';
import TriageResult from './results/TriageResult';
import MalwareResult from './results/MalwareResult';
import InfrastructureResult from './results/InfrastructureResult';
import CampaignResult from './results/CampaignResult';
import api from '../../api';

const AGENTS = [
  {
    id: 'triage',
    name: 'Triage Analyst',
    icon: <PsychologyIcon />,
    description: '초기 IOC 평가 및 우선 순위를 정해줍니다.',
    tools: 'VirusTotal',
    endpoint: '/api/crew-solo/triage',
  },
  {
    id: 'malware',
    name: 'Malware Analyst',
    icon: <BugReportIcon />,
    description: '악성코드 행동 패턴 및 인프라 사용을 분석합니다.',
    tools: 'VirusTotal',
    endpoint: '/api/crew-solo/malware',
  },
  {
    id: 'infrastructure',
    name: 'Infrastructure Analyst',
    icon: <HubIcon />,
    description: '인프라 캠페인 상관관계 및 클러스터링을 수행합니다.',
    tools: 'URLScan',
    endpoint: '/api/crew-solo/infrastructure',
  },
  {
    id: 'campaign',
    name: 'Campaign Analyst',
    icon: <AssessmentIcon />,
    description: '전략적 캠페인 인텔리전스 및 Hunt Hypothesis를 제공합니다.',
    tools: 'Analysis Only',
    endpoint: '/api/crew-solo/campaign',
  },
];

export default function Agents() {
  const [selectedAgent, setSelectedAgent] = useState(0);
  const [iocInput, setIocInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [iocType, setIocType] = useState('');
  const [allDiscoveredIocs, setAllDiscoveredIocs] = useState([]);
  const [agentResults, setAgentResults] = useState({});
  const discoveredIocsRef = useRef(null);

  const handleTabChange = (event, newValue) => {
    setSelectedAgent(newValue);
    // Load result for this agent if exists
    const agentId = AGENTS[newValue].id;
    if (agentResults[agentId]) {
      setResult(agentResults[agentId]);
    } else {
      setResult(null);
    }
    setError(null);
  };

  const handleIocInputChange = (e) => {
    const value = e.target.value;
    setIocInput(value);

    // Determine IOC type as user types
    if (value.trim()) {
      const type = determineIocType(value.trim());
      setIocType(type !== 'unknown' ? type : '');
    } else {
      setIocType('');
    }
  };

  const handleAnalyze = async () => {
    const trimmedIoc = iocInput.trim();

    if (!trimmedIoc) {
      setError('IOC를 입력해주세요.');
      return;
    }

    const type = determineIocType(trimmedIoc);
    if (type === 'unknown') {
      setError('유효하지 않은 IOC 형식입니다.');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const agent = AGENTS[selectedAgent];
      const response = await api.post(agent.endpoint, {
        ioc: trimmedIoc
      });

      const data = response.data;

      console.log('[DEBUG] Raw API response:', data);
      console.log('[DEBUG] data.result type:', typeof data.result);
      console.log('[DEBUG] data.result:', data.result);

      // Parse the raw JSON string if it exists
      if (data.result && data.result.raw) {
        try {
          console.log('[DEBUG] Parsing data.result.raw');
          data.result = JSON.parse(data.result.raw);
        } catch (parseError) {
          console.error('Failed to parse result.raw:', parseError);
        }
      }

      console.log('[DEBUG] Final data.result:', data.result);

      // Store result for this specific agent
      const agentId = agent.id;
      setAgentResults(prev => ({
        ...prev,
        [agentId]: data
      }));

      // Accumulate discovered IOCs
      if (data.result && data.result.discovered_iocs) {
        setAllDiscoveredIocs(prev => {
          // Combine with existing IOCs and remove duplicates based on IOC value
          const existing = prev.filter(ioc =>
            !data.result.discovered_iocs.some(newIoc => newIoc.ioc === ioc.ioc)
          );
          return [...existing, ...data.result.discovered_iocs];
        });
      }

      setResult(data);
    } catch (err) {
      setError(err.message || '분석 중 오류가 발생했습니다.');
      console.error('Agent analysis error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !loading) {
      handleAnalyze();
    }
  };

  const currentAgent = AGENTS[selectedAgent];

  const scrollToDiscoveredIocs = () => {
    discoveredIocsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const discoveredIocsCount = allDiscoveredIocs.length;

  const renderResult = () => {
    if (!result || !result.result) return null;

    const agentResult = result.result;

    switch (currentAgent.id) {
      case 'triage':
        return <TriageResult data={agentResult} />;
      case 'malware':
        return <MalwareResult data={agentResult} />;
      case 'infrastructure':
        return <InfrastructureResult data={agentResult} />;
      case 'campaign':
        return <CampaignResult data={agentResult} />;
      default:
        return null;
    }
  };

  return (
    <Box sx={{ maxWidth: "1200px", mx: "auto" }}>
      {/* Hero Section */}
      <Paper
        elevation={0}
        sx={{
          p: { xs: 3, md: 5 },
          mb: 4,
          background: (theme) => theme.palette.mode === 'dark'
            ? "linear-gradient(135deg, rgba(30,41,59,0.4) 0%, rgba(15,23,42,0.4) 100%)"
            : "linear-gradient(135deg, rgba(241,245,249,0.8) 0%, rgba(226,232,240,0.8) 100%)",
          backdropFilter: "blur(20px)",
          border: (theme) => `1px solid ${alpha(theme.palette.divider, 0.05)}`,
          color: "text.primary",
          borderRadius: "24px",
          position: "relative",
          overflow: "hidden",
          boxShadow: (theme) => theme.palette.mode === 'dark'
            ? "0 8px 32px rgba(0, 0, 0, 0.2)"
            : "0 8px 32px rgba(255, 255, 255, 0.4)"
        }}
      >
        <Box sx={{ position: "relative", zIndex: 1, maxWidth: "800px" }}>
          <Typography variant="h3" fontWeight={800} gutterBottom sx={{ mb: 1 }}>
            AI Threat Agents
          </Typography>
          <Typography variant="h6" sx={{ mb: 0, opacity: 0.7, fontWeight: 400 }}>
            전문 AI 에이전트를 선택하여 위협 분석을 시작하세요
          </Typography>
        </Box>
      </Paper>

      {/* Agent Selection Grid */}
      <Box sx={{ mb: 5 }}>
        <Typography variant="h5" fontWeight={700} gutterBottom sx={{ mb: 3, px: 1 }}>
          에이전트 선택
        </Typography>
        <Box sx={{
          display: 'grid',
          gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr', lg: 'repeat(4, 1fr)' },
          gap: 2.5
        }}>
          {AGENTS.map((agent, index) => {
            const isSelected = selectedAgent === index;
            const agentColors = {
              triage: '#5E81AC',
              malware: '#BF616A',
              infrastructure: '#A3BE8C',
              campaign: '#B48EAD'
            };
            const agentColor = agentColors[agent.id] || '#757575';

            return (
              <Paper
                key={agent.id}
                elevation={0}
                onClick={(e) => handleTabChange(e, index)}
                sx={{
                  p: 3,
                  cursor: 'pointer',
                  borderRadius: '20px',
                  background: (theme) => isSelected
                    ? `linear-gradient(135deg, ${alpha(agentColor, 0.15)} 0%, ${alpha(agentColor, 0.05)} 100%)`
                    : alpha(theme.palette.background.paper, 0.6),
                  backdropFilter: 'blur(12px)',
                  border: (theme) => `2px solid ${isSelected ? alpha(agentColor, 0.5) : alpha(theme.palette.divider, 0.1)}`,
                  transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                  position: 'relative',
                  overflow: 'hidden',
                  '&:hover': {
                    transform: 'translateY(-4px)',
                    boxShadow: `0 12px 24px -10px ${alpha(agentColor, 0.3)}`,
                    borderColor: alpha(agentColor, 0.5),
                    '& .agent-icon-box': {
                      bgcolor: agentColor,
                      color: (theme) => theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
                      transform: 'scale(1.1) rotate(5deg)'
                    }
                  },
                }}
              >
                {/* Selected Indicator */}
                {isSelected && (
                  <Box sx={{
                    position: 'absolute',
                    top: 12,
                    right: 12,
                    width: 10,
                    height: 10,
                    borderRadius: '50%',
                    bgcolor: agentColor,
                    boxShadow: `0 0 12px ${alpha(agentColor, 0.6)}`
                  }} />
                )}

                {/* Icon */}
                <Box
                  className="agent-icon-box"
                  sx={{
                    width: 64,
                    height: 64,
                    borderRadius: '16px',
                    bgcolor: alpha(agentColor, 0.1),
                    color: agentColor,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    mb: 2,
                    transition: 'all 0.3s ease',
                  }}
                >
                  {React.cloneElement(agent.icon, { sx: { fontSize: 32 } })}
                </Box>

                {/* Content */}
                <Typography variant="h6" fontWeight={700} gutterBottom sx={{ mb: 1 }}>
                  {agent.name}
                </Typography>
                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={{
                    mb: 2,
                    minHeight: 40,
                    lineHeight: 1.4
                  }}
                >
                  {agent.description}
                </Typography>

                {/* Tool Badge */}
                <Chip
                  label={`🛠️ ${agent.tools}`}
                  size="small"
                  sx={{
                    fontWeight: 600,
                    bgcolor: alpha(agentColor, 0.1),
                    color: agentColor,
                    borderRadius: '8px',
                    '& .MuiChip-label': {
                      px: 1.5
                    }
                  }}
                />

                {/* Decorative gradient overlay */}
                <Box sx={{
                  position: 'absolute',
                  top: -50,
                  right: -50,
                  width: 150,
                  height: 150,
                  borderRadius: '50%',
                  background: `radial-gradient(circle, ${alpha(agentColor, 0.05)} 0%, transparent 70%)`,
                  pointerEvents: 'none'
                }} />
              </Paper>
            );
          })}
        </Box>
      </Box>

      {/* Main Input Section - Full Width */}
      <Box sx={{ mb: 6 }}>
        <Paper
          elevation={0}
          sx={{
            p: 5,
            borderRadius: "24px",
            background: (theme) => alpha(theme.palette.background.paper, 0.6),
            backdropFilter: "blur(12px)",
            border: (theme) => `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            textAlign: "center"
          }}
        >
          <Box sx={{ mb: 4 }}>
            <Box sx={{
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: 64,
              height: 64,
              borderRadius: "20px",
              bgcolor: "primary.main",
              color: "primary.contrastText",
              mb: 2
            }}>
              {React.cloneElement(AGENTS[selectedAgent].icon, { fontSize: "large" })}
            </Box>
            <Typography variant="h4" fontWeight={700} gutterBottom>
              {AGENTS[selectedAgent].name}
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 1 }}>
              {AGENTS[selectedAgent].description}
            </Typography>
            <Chip
              label={`🛠️ ${AGENTS[selectedAgent].tools}`}
              size="small"
              sx={{ mt: 1, fontWeight: 600 }}
            />
          </Box>

          <Paper
            component="form"
            elevation={0}
            sx={{
              p: "4px 8px",
              display: "flex",
              alignItems: "center",
              borderRadius: "16px",
              bgcolor: (theme) => alpha(theme.palette.background.paper, 0.8),
              border: (theme) => `1px solid ${alpha(theme.palette.divider, 0.2)}`,
              transition: "all 0.2s ease",
              boxShadow: "0 4px 12px rgba(0,0,0,0.05)",
              "&:hover, &:focus-within": {
                transform: "translateY(-1px)",
                boxShadow: "0 8px 24px rgba(0,0,0,0.08)",
                borderColor: "primary.main"
              }
            }}
          >
            <Box sx={{ pl: 2 }} />
            <TextField
              fullWidth
              placeholder="Hash, IP, Domain, URL을 입력하세요..."
              value={iocInput}
              onChange={handleIocInputChange}
              onKeyPress={handleKeyPress}
              disabled={loading}
              variant="standard"
              InputProps={{
                disableUnderline: true,
                sx: {
                  fontSize: "1.1rem",
                  p: 1.5,
                  "&::placeholder": { opacity: 0.7 }
                }
              }}
            />
            <Button
              onClick={handleAnalyze}
              disabled={loading || !iocInput.trim()}
              sx={{
                minWidth: 50,
                width: 50,
                height: 50,
                borderRadius: "12px",
                ml: 1,
                color: "primary.contrastText",
                bgcolor: "primary.main",
                "&:hover": {
                  bgcolor: "primary.dark",
                }
              }}
            >
              {loading ? <CircularProgress size={24} color="inherit" /> : <SearchIcon />}
            </Button>
          </Paper>

          {iocType && (
            <Typography variant="caption" color="primary" sx={{ mt: 2, display: 'block', fontWeight: 600 }}>
              ✓ 감지된 유형: {iocType}
            </Typography>
          )}
        </Paper>
      </Box>

      {/* Error Display */}
      {error && (
        <Alert severity="error" sx={{ mb: 3, borderRadius: "12px" }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Result Display */}
      {result && (
        <Box sx={{ animation: "fadeIn 0.5s ease-in-out" }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
            <Typography variant="h4" fontWeight={800}>
              Analysis Result
            </Typography>
            <Chip
              label="Completed"
              color="success"
              size="small"
              sx={{ ml: 2, fontWeight: 600, borderRadius: "8px" }}
            />
          </Box>
          {renderResult()}
        </Box>
      )}

      {/* Discovered IOCs Section */}
      {allDiscoveredIocs.length > 0 && (
        <Paper
          ref={discoveredIocsRef}
          elevation={0}
          sx={{
            mt: 6,
            p: 4,
            borderRadius: "24px",
            background: (theme) => alpha(theme.palette.background.paper, 0.6),
            backdropFilter: "blur(12px)",
            border: (theme) => `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
            <SecurityIcon color="primary" sx={{ fontSize: 32 }} />
            <Typography variant="h5" fontWeight={700}>
              Discovered IOCs ({allDiscoveredIocs.length})
            </Typography>
          </Box>

          <Divider sx={{ my: 2 }} />

          <Box sx={{ mt: 3 }}>
            <DiscoveredIOCs
              discoveredIocs={allDiscoveredIocs}
              onIocClick={(ioc) => {
                setIocInput(ioc);
              }}
            />
          </Box>
        </Paper>
      )}

      {/* Floating Action Button */}
      {discoveredIocsCount > 0 && (
        <Fab
          color="primary"
          aria-label="discovered-iocs"
          onClick={scrollToDiscoveredIocs}
          sx={{
            position: 'fixed',
            bottom: 32,
            right: 32,
            boxShadow: "0 8px 24px rgba(0,0,0,0.2)"
          }}
        >
          <Badge badgeContent={discoveredIocsCount} color="error" max={99}>
            <ListAltIcon />
          </Badge>
        </Fab>
      )}

      <style>
        {`
          @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
          }
        `}
      </style>
    </Box>
  );
}
