import React, { useState, useRef } from 'react';
import {
  Box,
  Tabs,
  Tab,
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
import SearchIcon from '@mui/icons-material/Search';
import PsychologyIcon from '@mui/icons-material/Psychology';
import BugReportIcon from '@mui/icons-material/BugReport';
import HubIcon from '@mui/icons-material/Hub';
import AssessmentIcon from '@mui/icons-material/Assessment';
import ListAltIcon from '@mui/icons-material/ListAlt';
import { determineIocType } from '../ioc-tools/ioc-lookup/shared/utils/iocDefinitions';
import DiscoveredIOCs from './DiscoveredIOCs';
import TriageResult from './results/TriageResult';
import MalwareResult from './results/MalwareResult';
import InfrastructureResult from './results/InfrastructureResult';
import CampaignResult from './results/CampaignResult';

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
      const response = await fetch(`http://localhost:8000${agent.endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ioc: trimmedIoc }),
      });

      if (!response.ok) {
        throw new Error(`분석 실패: ${response.statusText}`);
      }

      const data = await response.json();

      // Parse the raw JSON string if it exists
      if (data.result && data.result.raw) {
        try {
          data.result = JSON.parse(data.result.raw);
        } catch (parseError) {
          console.error('Failed to parse result.raw:', parseError);
        }
      }

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
    <Box>
      <Typography variant="h3" gutterBottom sx={{ fontWeight: 600 }}>
        Threat Hunting Agents
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
        각 AI Agent를 선택하여 독립적인 IOC 분석을 수행하세요
      </Typography>

      {/* Agent Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs
          value={selectedAgent}
          onChange={handleTabChange}
          variant="fullWidth"
          sx={{
            borderBottom: 1,
            borderColor: 'divider',
          }}
        >
          {AGENTS.map((agent, index) => (
            <Tab
              key={agent.id}
              icon={React.cloneElement(agent.icon, { sx: { fontSize: 32 } })}
              label={agent.name}
              iconPosition="start"
              sx={{
                minHeight: 80,
                fontSize: '1.1rem',
                fontWeight: 500,
              }}
            />
          ))}
        </Tabs>
      </Paper>

      {/* Agent Info */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
          <Box sx={{ fontSize: 48 }}>
            {currentAgent.icon}
          </Box>
          <Box>
            <Typography variant="h4" sx={{ fontWeight: 500 }}>
              {currentAgent.name}
            </Typography>
            <Typography variant="h6" color="text.secondary">
              {currentAgent.description}
            </Typography>
          </Box>
        </Box>
        <Chip label={`🛠️ Tools: ${currentAgent.tools}`} size="medium" />
      </Paper>

      {/* IOC Input */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          IOC 입력
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'flex-start' }}>
          <TextField
            fullWidth
            placeholder="hash, IP, domain, URL 입력..."
            value={iocInput}
            onChange={handleIocInputChange}
            onKeyPress={handleKeyPress}
            disabled={loading}
            helperText={iocType ? `감지된 타입: ${iocType}` : ''}
            FormHelperTextProps={{
              sx: { color: 'success.main', fontFamily: 'inherit', fontSize: '1rem' }
            }}
            sx={{
              '& .MuiInputBase-input': {
                fontFamily: 'inherit',
                fontSize: '1.1rem'
              }
            }}
          />
          <Button
            variant="contained"
            onClick={handleAnalyze}
            disabled={loading || !iocInput.trim()}
            sx={{
              minWidth: 56,
              width: 56,
              height: 56,
              position: 'relative',
            }}
          >
            <SearchIcon sx={{ fontSize: 32 }} />
            {loading && (
              <CircularProgress
                size={48}
                sx={{
                  position: 'absolute',
                  top: '50%',
                  left: '50%',
                  marginTop: '-24px',
                  marginLeft: '-24px',
                }}
              />
            )}
          </Button>
        </Box>
      </Paper>

      {/* Error Display */}
      {error && (
        <Alert severity="error" sx={{ mb: 3, '& .MuiAlert-message': { fontFamily: 'inherit', fontSize: '1.1rem' } }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Result Display */}
      {result && (
        <Box>
          <Typography variant="h2" sx={{ my: 4, fontWeight: 700, fontFamily: 'inherit' }}>
            분석 결과
          </Typography>
          {renderResult()}

        </Box>
      )}

      {/* Discovered IOCs Section - Always show if any IOCs collected */}
      {allDiscoveredIocs.length > 0 && (
        <Box sx={{ mt: 4 }} ref={discoveredIocsRef}>
          <Typography variant="h2" sx={{ my: 4, fontWeight: 700, fontFamily: 'inherit' }}>
            모든 Agent에서 발견된 IOCs (총 {allDiscoveredIocs.length}개)
          </Typography>
          <DiscoveredIOCs
            discoveredIocs={allDiscoveredIocs}
            onIocClick={(ioc) => {
              setIocInput(ioc);
              // Optionally auto-analyze
            }}
          />
        </Box>
      )}

      {/* Floating Action Button for Discovered IOCs */}
      {discoveredIocsCount > 0 && (
        <Fab
          color="primary"
          aria-label="discovered-iocs"
          onClick={scrollToDiscoveredIocs}
          sx={{
            position: 'fixed',
            bottom: 32,
            right: 32,
          }}
        >
          <Badge badgeContent={discoveredIocsCount} color="error" max={99}>
            <ListAltIcon />
          </Badge>
        </Fab>
      )}
    </Box>
  );
}
