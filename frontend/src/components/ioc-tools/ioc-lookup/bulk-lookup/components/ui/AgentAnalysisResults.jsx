import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Chip,
  IconButton,
  Collapse,
  CircularProgress,
  Alert,
  Grid,
  Card,
  CardContent,
  useTheme,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  ListItemButton
} from '@mui/material';
import { alpha } from '@mui/material/styles';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import SummarizeIcon from '@mui/icons-material/Summarize';
import PsychologyIcon from '@mui/icons-material/Psychology';
import BugReportIcon from '@mui/icons-material/BugReport';
import HubIcon from '@mui/icons-material/Hub';
import AssessmentIcon from '@mui/icons-material/Assessment';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import AutoAwesomeIcon from '@mui/icons-material/AutoAwesome';
import LightbulbIcon from '@mui/icons-material/Lightbulb';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import WarningIcon from '@mui/icons-material/Warning';
import DnsIcon from '@mui/icons-material/Dns';
import {
  ResponsiveContainer,
  RadialBarChart,
  RadialBar,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip
} from 'recharts';

// Apple-style Color Palette (Consistent with BulkLookup.jsx)
const COLORS = {
  HIGH: '#FF3B30',      // System Red
  MEDIUM: '#FF9500',    // System Orange
  LOW: '#34C759',       // System Green
  UNKNOWN: '#8E8E93',   // System Gray
  CRITICAL: '#AF52DE',  // System Purple
  PRIMARY: '#007AFF',   // System Blue
  TEXT_PRIMARY: '#1D1D1F',
  TEXT_SECONDARY: '#86868B',
  BG_LIGHT: '#F5F5F7',
  CARD_BG_LIGHT: '#FFFFFF',
  BORDER_LIGHT: '#E5E5EA',
};

const AGENT_CONFIG = {
  triage: { name: 'Triage Analyst', icon: <PsychologyIcon />, color: '#5E81AC' },
  malware: { name: 'Malware Analyst', icon: <BugReportIcon />, color: '#BF616A' },
  infrastructure: { name: 'Infrastructure Analyst', icon: <HubIcon />, color: '#A3BE8C' },
  campaign: { name: 'Campaign Analyst', icon: <AssessmentIcon />, color: '#B48EAD' },
};

const AGENT_ORDER = ['triage', 'malware', 'infrastructure', 'campaign'];

const getThreatLevelColor = (level) => {
  const colors = {
    CRITICAL: COLORS.CRITICAL,
    HIGH: COLORS.HIGH,
    MEDIUM: COLORS.MEDIUM,
    LOW: COLORS.LOW,
    UNKNOWN: COLORS.UNKNOWN,
  };
  return colors[level?.toUpperCase()] || colors.UNKNOWN;
};

// Helper to safely parse JSON
const safeParse = (data) => {
  if (typeof data === 'string') {
    try {
      return JSON.parse(data);
    } catch (e) {
      return null;
    }
  }
  return data;
};

// --- Visualization Components ---

const DynamicContentRenderer = ({ data, isDarkMode, level = 0 }) => {
  if (!data) return null;

  // 1. Array Handling
  if (Array.isArray(data)) {
    if (data.length === 0) return <Typography variant="body2" color="text.secondary">No data available.</Typography>;

    // Check if array of strings/numbers
    if (typeof data[0] !== 'object') {
      return (
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
          {data.map((item, idx) => (
            <Chip
              key={idx}
              label={String(item)}
              variant="outlined"
              size="small"
              sx={{
                color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY,
                borderColor: isDarkMode ? 'rgba(255,255,255,0.2)' : COLORS.BORDER_LIGHT
              }}
            />
          ))}
        </Box>
      );
    }

    // Array of Objects -> Grid of Cards
    return (
      <Grid container spacing={2}>
        {data.map((item, idx) => (
          <Grid item xs={12} md={6} key={idx}>
            <Paper
              elevation={0}
              sx={{
                p: 2,
                bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#FFFFFF',
                border: isDarkMode ? '1px solid rgba(255,255,255,0.1)' : `1px solid ${COLORS.BORDER_LIGHT}`,
                borderRadius: '12px',
                height: '100%'
              }}
            >
              <DynamicContentRenderer data={item} isDarkMode={isDarkMode} level={level + 1} />
            </Paper>
          </Grid>
        ))}
      </Grid>
    );
  }

  // 2. Object Handling
  if (typeof data === 'object') {
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
        {Object.entries(data).map(([key, value]) => {
          // Skip empty values
          if (value === null || value === undefined || (Array.isArray(value) && value.length === 0)) return null;

          const label = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());

          return (
            <Box key={key} sx={{ mb: 1 }}>
              <Typography variant="caption" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontWeight: 600, display: 'block', mb: 0.5 }}>
                {label}
              </Typography>
              {typeof value === 'object' ? (
                <Box sx={{ pl: 1.5, borderLeft: `2px solid ${isDarkMode ? 'rgba(255,255,255,0.1)' : COLORS.BORDER_LIGHT}` }}>
                  <DynamicContentRenderer data={value} isDarkMode={isDarkMode} level={level + 1} />
                </Box>
              ) : (
                <Typography variant="body2" sx={{ color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY, wordBreak: 'break-word' }}>
                  {String(value)}
                </Typography>
              )}
            </Box>
          );
        })}
      </Box>
    );
  }

  // 3. Primitive Handling
  return (
    <Typography variant="body2" sx={{ color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY, whiteSpace: 'pre-wrap' }}>
      {String(data)}
    </Typography>
  );
};

const DiscoveryList = ({ discoveries, isDarkMode }) => {
  if (!discoveries || discoveries.length === 0) return <Typography variant="body2" color="text.secondary">No discoveries found.</Typography>;

  return (
    <Grid container spacing={2}>
      {discoveries.map((item, idx) => (
        <Grid item xs={12} key={idx}>
          <Paper elevation={0} sx={{ p: 2, bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '8px' }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
              <LightbulbIcon fontSize="small" sx={{ color: COLORS.MEDIUM }} />
              <Typography variant="subtitle2" fontWeight={700} sx={{ color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
                {item.discovery || item.indicator}
              </Typography>
              {item.confidence && (
                <Chip label={item.confidence} size="small" sx={{ height: 20, fontSize: '0.7rem' }} />
              )}
            </Box>
            <Typography variant="body2" sx={{ color: isDarkMode ? '#ccc' : COLORS.TEXT_SECONDARY, mb: 0.5 }}>
              {item.significance || item.context || item.discovery_reason}
            </Typography>
            {item.ioc_type && (
              <Chip label={item.ioc_type} size="small" variant="outlined" sx={{ height: 20, fontSize: '0.7rem', mr: 1 }} />
            )}
          </Paper>
        </Grid>
      ))}
    </Grid>
  );
};

const RelationshipList = ({ relationships, isDarkMode }) => {
  if (!relationships || relationships.length === 0) return null;

  return (
    <Box sx={{ mt: 2 }}>
      <Typography variant="subtitle2" sx={{ mb: 1, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY, fontWeight: 600 }}>
        Discovered Relationships
      </Typography>
      <TableContainer component={Paper} elevation={0} sx={{ bgcolor: 'transparent', border: isDarkMode ? '1px solid rgba(255,255,255,0.1)' : `1px solid ${COLORS.BORDER_LIGHT}` }}>
        <Table size="small">
          <TableHead>
            <TableRow sx={{ bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F5F5F7' }}>
              <TableCell sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY }}>Type</TableCell>
              <TableCell sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY }}>Indicator</TableCell>
              <TableCell sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY }}>Context</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {relationships.map((rel, idx) => (
              <TableRow key={idx}>
                <TableCell sx={{ color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>{rel.relationship_type}</TableCell>
                <TableCell sx={{ color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY, fontFamily: 'monospace' }}>{rel.indicator}</TableCell>
                <TableCell sx={{ color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>{rel.context}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};

const RiskScoreGauge = ({ score, isDarkMode }) => {
  // Score is 0-100 or 0-10. Normalize to 100.
  let normalizedScore = score;
  if (score <= 10) normalizedScore = score * 10;

  const data = [
    { name: 'Risk', value: normalizedScore, fill: normalizedScore > 70 ? COLORS.HIGH : normalizedScore > 40 ? COLORS.MEDIUM : COLORS.LOW },
    { name: 'Remaining', value: 100 - normalizedScore, fill: isDarkMode ? '#333' : '#E5E5EA' }
  ];

  return (
    <Box sx={{ position: 'relative', width: 120, height: 120, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <ResponsiveContainer width="100%" height="100%">
        <RadialBarChart innerRadius="70%" outerRadius="100%" barSize={10} data={data} startAngle={90} endAngle={-270}>
          <RadialBar background clockWise dataKey="value" cornerRadius={10} />
        </RadialBarChart>
      </ResponsiveContainer>
      <Box sx={{ position: 'absolute', textAlign: 'center' }}>
        <Typography variant="h5" fontWeight={700} sx={{ color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
          {normalizedScore}
        </Typography>
        <Typography variant="caption" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY }}>
          Risk Score
        </Typography>
      </Box>
    </Box>
  );
};

const ConfidenceBar = ({ confidence, isDarkMode }) => {
  // Confidence: High, Medium, Low or 0-100
  let value = 0;
  if (typeof confidence === 'string') {
    if (confidence.toLowerCase() === 'high') value = 90;
    else if (confidence.toLowerCase() === 'medium') value = 60;
    else value = 30;
  } else {
    value = confidence;
  }

  return (
    <Box sx={{ width: '100%', mt: 1 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
        <Typography variant="caption" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY }}>Confidence</Typography>
        <Typography variant="caption" fontWeight={600} sx={{ color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>{confidence}</Typography>
      </Box>
      <Box sx={{ width: '100%', height: 6, bgcolor: isDarkMode ? '#333' : '#E5E5EA', borderRadius: 3, overflow: 'hidden' }}>
        <Box sx={{ width: `${value}%`, height: '100%', bgcolor: COLORS.PRIMARY, borderRadius: 3 }} />
      </Box>
    </Box>
  );
};

const CapabilitiesCloud = ({ capabilities, isDarkMode }) => {
  if (!capabilities || capabilities.length === 0) return null;
  return (
    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
      {capabilities.map((cap, idx) => (
        <Chip
          key={idx}
          label={cap}
          size="small"
          sx={{
            bgcolor: isDarkMode ? 'rgba(255, 59, 48, 0.15)' : alpha(COLORS.HIGH, 0.1),
            color: COLORS.HIGH,
            border: `1px solid ${alpha(COLORS.HIGH, 0.2)}`,
            fontWeight: 500
          }}
        />
      ))}
    </Box>
  );
};

const GeoDistributionChart = ({ countries, isDarkMode }) => {
  if (!countries || countries.length === 0) return null;

  // Transform data for chart: { name: 'US', count: 5 }
  // Assuming countries is array of strings or objects. Normalize.
  const data = countries.map(c => ({
    name: typeof c === 'string' ? c : c.country_code || c.country,
    count: c.count || 1 // Simplified
  })).slice(0, 5);

  return (
    <Box sx={{ width: '100%', height: 200 }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
          <XAxis type="number" hide />
          <YAxis dataKey="name" type="category" width={40} tick={{ fill: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontSize: 12 }} />
          <Tooltip
            contentStyle={{ backgroundColor: isDarkMode ? '#333' : '#fff', borderRadius: 8, border: 'none', boxShadow: '0 4px 12px rgba(0,0,0,0.1)' }}
            itemStyle={{ color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}
          />
          <Bar dataKey="count" fill={COLORS.PRIMARY} radius={[0, 4, 4, 0]} barSize={20} />
        </BarChart>
      </ResponsiveContainer>
    </Box>
  );
};

// --- Specialized Agent Views ---

const TriageView = ({ data, isDarkMode }) => {
  // Map threat_level to risk_score if missing
  const getRiskScore = (d) => {
    if (d.risk_score !== undefined) return d.risk_score;
    const levels = { CRITICAL: 95, HIGH: 85, MEDIUM: 55, LOW: 25, UNKNOWN: 0 };
    return levels[d.threat_level?.toUpperCase()] || 0;
  };

  const score = getRiskScore(data);
  const confidence = data.confidence || data.reliability || 'Medium'; // Default to Medium if missing

  const displayedKeys = ['risk_score', 'confidence', 'reliability', 'classification', 'threat_level', 'summary', 'analytical_summary'];
  const remainingData = Object.fromEntries(Object.entries(data).filter(([key]) => !displayedKeys.includes(key)));

  return (
    <Box>
      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <Paper elevation={0} sx={{ p: 3, height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '12px' }}>
            <RiskScoreGauge score={score} isDarkMode={isDarkMode} />
            <ConfidenceBar confidence={confidence} isDarkMode={isDarkMode} />
          </Paper>
        </Grid>
        <Grid item xs={12} md={8}>
          <Box sx={{ mb: 3 }}>
            <Typography variant="subtitle2" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, mb: 1 }}>Classification</Typography>
            <Chip
              label={data.classification || data.threat_level || 'Unknown'}
              sx={{
                bgcolor: alpha(getThreatLevelColor(data.threat_level), 0.1),
                color: getThreatLevelColor(data.threat_level),
                fontWeight: 700,
                fontSize: '1rem',
                height: 32
              }}
            />
          </Box>
          <Box>
            <Typography variant="subtitle2" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, mb: 1 }}>Summary</Typography>
            <Typography variant="body1" sx={{ lineHeight: 1.6, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
              {data.summary || data.analytical_summary || 'No summary available.'}
            </Typography>
          </Box>
        </Grid>
      </Grid>

      {/* Render Remaining Data */}
      {Object.keys(remainingData).length > 0 && (
        <Box sx={{ mt: 4 }}>
          <Typography variant="subtitle2" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, mb: 2 }}>Additional Analysis Details</Typography>
          <Paper elevation={0} sx={{ p: 3, bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '12px' }}>
            <DynamicContentRenderer data={remainingData} isDarkMode={isDarkMode} />
          </Paper>
        </Box>
      )}
    </Box>
  );
};

const MalwareView = ({ data, isDarkMode }) => {
  const displayedKeys = ['malware_family', 'is_malicious', 'capabilities', 'behavior_analysis', 'indicators'];
  const remainingData = Object.fromEntries(Object.entries(data).filter(([key]) => !displayedKeys.includes(key)));

  return (
    <Box>
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={6}>
          <Paper elevation={0} sx={{ p: 2, bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '12px', height: '100%' }}>
            <Typography variant="subtitle2" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, mb: 2 }}>Malware Family</Typography>
            <Typography variant="h5" fontWeight={700} sx={{ color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY, mb: 1 }}>
              {data.malware_family || 'Unknown Family'}
            </Typography>
            <Chip label={data.is_malicious ? 'Malicious' : 'Suspicious'} color={data.is_malicious ? 'error' : 'warning'} size="small" />
          </Paper>
        </Grid>
        <Grid item xs={12} md={6}>
          <Paper elevation={0} sx={{ p: 2, bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '12px', height: '100%' }}>
            <Typography variant="subtitle2" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, mb: 2 }}>Capabilities</Typography>
            <CapabilitiesCloud capabilities={data.capabilities || data.behavior_analysis} isDarkMode={isDarkMode} />
          </Paper>
        </Grid>
      </Grid>

      {data.indicators && data.indicators.length > 0 && (
        <Box>
          <Typography variant="subtitle2" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, mb: 1 }}>Indicators of Compromise</Typography>
          <TableContainer component={Paper} elevation={0} sx={{ bgcolor: 'transparent', border: isDarkMode ? '1px solid rgba(255,255,255,0.1)' : `1px solid ${COLORS.BORDER_LIGHT}` }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F5F5F7' }}>
                  <TableCell sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY }}>Type</TableCell>
                  <TableCell sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY }}>Value</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.indicators.slice(0, 5).map((ind, idx) => (
                  <TableRow key={idx}>
                    <TableCell sx={{ color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>{ind.type}</TableCell>
                    <TableCell sx={{ color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY, fontFamily: 'monospace' }}>{ind.value}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Box>
      )}

      {/* Render Remaining Data */}
      {Object.keys(remainingData).length > 0 && (
        <Box sx={{ mt: 4 }}>
          <Typography variant="subtitle2" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, mb: 2 }}>Additional Malware Analysis</Typography>
          <Paper elevation={0} sx={{ p: 3, bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '12px' }}>
            <DynamicContentRenderer data={remainingData} isDarkMode={isDarkMode} />
          </Paper>
        </Box>
      )}
    </Box>
  );
};

const InfrastructureView = ({ data, isDarkMode }) => {
  const displayedKeys = ['hosting_provider', 'asn', 'country', 'resolutions'];
  const remainingData = Object.fromEntries(Object.entries(data).filter(([key]) => !displayedKeys.includes(key)));

  return (
    <Box>
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={6}>
          <Paper elevation={0} sx={{ p: 2, bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '12px', height: '100%' }}>
            <Typography variant="subtitle2" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, mb: 2 }}>Hosting Provider</Typography>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <DnsIcon sx={{ color: COLORS.PRIMARY }} />
              <Typography variant="body1" fontWeight={600} sx={{ color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
                {data.hosting_provider || 'Unknown Provider'}
              </Typography>
            </Box>
            <Typography variant="caption" sx={{ display: 'block', mt: 1, color: isDarkMode ? '#888' : COLORS.TEXT_SECONDARY }}>
              ASN: {data.asn || 'N/A'}
            </Typography>
          </Paper>
        </Grid>
        <Grid item xs={12} md={6}>
          <Paper elevation={0} sx={{ p: 2, bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '12px', height: '100%' }}>
            <Typography variant="subtitle2" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, mb: 2 }}>Geo Distribution</Typography>
            <GeoDistributionChart countries={[{ country: data.country || 'Unknown', count: 1 }]} isDarkMode={isDarkMode} />
          </Paper>
        </Grid>
      </Grid>

      {data.resolutions && (
        <Box>
          <Typography variant="subtitle2" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, mb: 1 }}>DNS Resolutions</Typography>
          <TableContainer component={Paper} elevation={0} sx={{ bgcolor: 'transparent', border: isDarkMode ? '1px solid rgba(255,255,255,0.1)' : `1px solid ${COLORS.BORDER_LIGHT}` }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F5F5F7' }}>
                  <TableCell sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY }}>Last Resolved</TableCell>
                  <TableCell sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY }}>IP Address</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.resolutions.slice(0, 5).map((res, idx) => (
                  <TableRow key={idx}>
                    <TableCell sx={{ color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>{res.last_resolved}</TableCell>
                    <TableCell sx={{ color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY, fontFamily: 'monospace' }}>{res.ip_address}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Box>
      )}

      {/* Render Remaining Data */}
      {Object.keys(remainingData).length > 0 && (
        <Box sx={{ mt: 4 }}>
          <Typography variant="subtitle2" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, mb: 2 }}>Additional Infrastructure Info</Typography>
          <Paper elevation={0} sx={{ p: 3, bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '12px' }}>
            <DynamicContentRenderer data={remainingData} isDarkMode={isDarkMode} />
          </Paper>
        </Box>
      )}
    </Box>
  );
};

const CampaignView = ({ data, isDarkMode }) => {
  const displayedKeys = ['campaign_name', 'attribution', 'tactics'];
  const remainingData = Object.fromEntries(Object.entries(data).filter(([key]) => !displayedKeys.includes(key)));

  return (
    <Box>
      <Paper elevation={0} sx={{ p: 3, bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '12px', mb: 3 }}>
        <Typography variant="subtitle2" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, mb: 1 }}>Attributed Campaign</Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <AssessmentIcon sx={{ fontSize: 40, color: COLORS.CRITICAL }} />
          <Box>
            <Typography variant="h5" fontWeight={700} sx={{ color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
              {data.campaign_name || 'Unattributed'}
            </Typography>
            <Typography variant="body2" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY }}>
              {data.attribution || 'No specific attribution found.'}
            </Typography>
          </Box>
        </Box>
      </Paper>

      {data.tactics && (
        <Box>
          <Typography variant="subtitle2" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, mb: 1 }}>MITRE ATT&CK Tactics</Typography>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
            {data.tactics.map((tactic, idx) => (
              <Chip
                key={idx}
                label={tactic}
                variant="outlined"
                sx={{ color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY, borderColor: isDarkMode ? 'rgba(255,255,255,0.2)' : COLORS.BORDER_LIGHT }}
              />
            ))}
          </Box>
        </Box>
      )}

      {/* Render Remaining Data */}
      {Object.keys(remainingData).length > 0 && (
        <Box sx={{ mt: 4 }}>
          <Typography variant="subtitle2" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, mb: 2 }}>Additional Campaign Details</Typography>
          <Paper elevation={0} sx={{ p: 3, bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '12px' }}>
            <DynamicContentRenderer data={remainingData} isDarkMode={isDarkMode} />
          </Paper>
        </Box>
      )}
    </Box>
  );
};

// --- Main Detail Component ---

const AgentResultDetail = ({ agent, result, isDarkMode }) => {
  const parsedData = safeParse(result?.data?.result);

  if (!parsedData) {
    return <Typography variant="body2" color="text.secondary">No detailed data available.</Typography>;
  }

  // Common Fields
  const discoveries = parsedData.discovered_iocs || parsedData.priority_discoveries || [];
  const relationships = parsedData.discovered_relationships || parsedData.infrastructure_relationship_map ? (Array.isArray(parsedData.discovered_relationships) ? parsedData.discovered_relationships : []) : [];

  return (
    <Box sx={{ p: 3 }}>
      {/* Specialized View based on Agent */}
      <Box sx={{ mb: 4 }}>
        {agent === 'triage' && <TriageView data={parsedData} isDarkMode={isDarkMode} />}
        {agent === 'malware' && <MalwareView data={parsedData} isDarkMode={isDarkMode} />}
        {agent === 'infrastructure' && <InfrastructureView data={parsedData} isDarkMode={isDarkMode} />}
        {agent === 'campaign' && <CampaignView data={parsedData} isDarkMode={isDarkMode} />}
      </Box>

      <Divider sx={{ my: 3, borderColor: isDarkMode ? 'rgba(255,255,255,0.1)' : COLORS.BORDER_LIGHT }} />

      {/* Key Findings / Discoveries (Common) */}
      {(discoveries.length > 0) && (
        <Box sx={{ mb: 3 }}>
          <Typography variant="subtitle1" fontWeight={700} sx={{ mb: 2, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY, display: 'flex', alignItems: 'center', gap: 1 }}>
            <LightbulbIcon fontSize="small" /> Key Findings
          </Typography>
          <DiscoveryList discoveries={discoveries} isDarkMode={isDarkMode} />
        </Box>
      )}

      {/* Relationships (Common) */}
      {(relationships.length > 0 || typeof parsedData.infrastructure_relationship_map === 'string') && (
        <Box sx={{ mb: 3 }}>
          {typeof parsedData.infrastructure_relationship_map === 'string' ? (
            <Box>
              <Typography variant="subtitle1" fontWeight={700} sx={{ mb: 2, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY, display: 'flex', alignItems: 'center', gap: 1 }}>
                <HubIcon fontSize="small" /> Infrastructure Map
              </Typography>
              <Paper elevation={0} sx={{ p: 2, bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '8px' }}>
                <Typography variant="body2" sx={{ color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY, whiteSpace: 'pre-wrap' }}>
                  {parsedData.infrastructure_relationship_map}
                </Typography>
              </Paper>
            </Box>
          ) : (
            <RelationshipList relationships={relationships} isDarkMode={isDarkMode} />
          )}
        </Box>
      )}

      {/* Relationships (Common) */}
      {(relationships.length > 0 || typeof parsedData.infrastructure_relationship_map === 'string') && (
        <Box sx={{ mb: 3 }}>
          {typeof parsedData.infrastructure_relationship_map === 'string' ? (
            <Box>
              <Typography variant="subtitle1" fontWeight={700} sx={{ mb: 2, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY, display: 'flex', alignItems: 'center', gap: 1 }}>
                <HubIcon fontSize="small" /> Infrastructure Map
              </Typography>
              <Paper elevation={0} sx={{ p: 2, bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '8px' }}>
                <Typography variant="body2" sx={{ color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY, whiteSpace: 'pre-wrap' }}>
                  {parsedData.infrastructure_relationship_map}
                </Typography>
              </Paper>
            </Box>
          ) : (
            <RelationshipList relationships={relationships} isDarkMode={isDarkMode} />
          )}
        </Box>
      )}
    </Box>
  );
};

// --- Master-Detail Components ---

const IOCListItem = ({ ioc, agentResults, isSelected, onClick, isDarkMode }) => {
  const agents = Object.keys(agentResults || {});
  const completedCount = agents.filter(a => agentResults[a]?.status === 'completed').length;
  const errorCount = agents.filter(a => agentResults[a]?.status === 'error').length;
  const totalCount = agents.length;

  const getThreatLevel = () => {
    const levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    for (const level of levels) {
      for (const agent of agents) {
        const result = agentResults[agent];
        if (result?.status === 'completed' && result?.data?.result) {
          try {
            const parsed = typeof result.data.result === 'string'
              ? JSON.parse(result.data.result)
              : result.data.result;
            if (parsed?.threat_level?.toUpperCase() === level) {
              return level;
            }
          } catch (e) { /* ignore */ }
        }
      }
    }
    return null;
  };

  const threatLevel = getThreatLevel();

  return (
    <ListItemButton
      selected={isSelected}
      onClick={onClick}
      sx={{
        borderRadius: '12px',
        mb: 1,
        border: isSelected
          ? (isDarkMode ? '1px solid #fff' : '1px solid #000')
          : (isDarkMode ? '1px solid rgba(255,255,255,0.05)' : `1px solid ${COLORS.BORDER_LIGHT}`),
        bgcolor: isSelected
          ? (isDarkMode ? 'rgba(255,255,255,0.1)' : '#F0F0F2')
          : (isDarkMode ? 'rgba(255,255,255,0.02)' : '#FFFFFF'),
        '&:hover': {
          bgcolor: isDarkMode ? 'rgba(255,255,255,0.08)' : '#F9F9F9',
        },
        '&.Mui-selected': {
          bgcolor: isDarkMode ? 'rgba(255,255,255,0.15)' : '#E5E5EA',
          '&:hover': {
            bgcolor: isDarkMode ? 'rgba(255,255,255,0.2)' : '#D1D1D6',
          }
        }
      }}
    >
      <Box sx={{ width: '100%' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 0.5 }}>
          <Typography variant="body2" fontWeight={600} sx={{ fontFamily: 'monospace', color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY, overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {ioc}
          </Typography>
          {threatLevel && (
            <Box sx={{
              width: 8, height: 8, borderRadius: '50%',
              bgcolor: getThreatLevelColor(threatLevel),
              boxShadow: `0 0 8px ${alpha(getThreatLevelColor(threatLevel), 0.5)}`
            }} />
          )}
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Typography variant="caption" sx={{ color: isDarkMode ? '#888' : COLORS.TEXT_SECONDARY }}>
            {completedCount}/{totalCount} Done
          </Typography>
          {errorCount > 0 && (
            <Chip label="Error" size="small" color="error" sx={{ height: 16, fontSize: '0.6rem' }} />
          )}
        </Box>
      </Box>
    </ListItemButton>
  );
};

const IOCDetailPanel = ({ ioc, agentResults, isDarkMode }) => {
  const [tabValue, setTabValue] = useState(0);
  const agents = Object.keys(agentResults || {});
  const availableAgents = AGENT_ORDER.filter(a => agents.includes(a));

  const handleTabChange = (event, newValue) => {
    setTabValue(newValue);
  };

  if (!ioc) {
    return (
      <Box sx={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: isDarkMode ? '#666' : '#999' }}>
        <Typography>Select an IOC to view details</Typography>
      </Box>
    );
  }

  return (
    <Paper
      elevation={0}
      sx={{
        height: '100%',
        borderRadius: '16px',
        border: isDarkMode ? '1px solid rgba(255,255,255,0.1)' : `1px solid ${COLORS.BORDER_LIGHT}`,
        bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#FFFFFF',
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column'
      }}
    >
      <Box sx={{ p: 2, borderBottom: isDarkMode ? '1px solid rgba(255,255,255,0.1)' : `1px solid ${COLORS.BORDER_LIGHT}` }}>
        <Typography variant="h6" fontWeight={700} sx={{ fontFamily: 'monospace', color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
          {ioc}
        </Typography>
      </Box>

      <Tabs
        value={tabValue}
        onChange={handleTabChange}
        variant="scrollable"
        scrollButtons="auto"
        sx={{
          px: 2,
          minHeight: 48,
          borderBottom: isDarkMode ? '1px solid rgba(255,255,255,0.1)' : `1px solid ${COLORS.BORDER_LIGHT}`,
          '& .MuiTab-root': {
            textTransform: 'none',
            fontWeight: 600,
            minHeight: 48,
            color: isDarkMode ? '#888' : COLORS.TEXT_SECONDARY,
            '&.Mui-selected': { color: isDarkMode ? '#fff' : '#000000' }
          },
          '& .MuiTabs-indicator': { bgcolor: isDarkMode ? '#fff' : '#000000' }
        }}
      >
        <Tab label="Summary" />
        {availableAgents.map(agent => (
          <Tab key={agent} label={AGENT_CONFIG[agent].name} iconPosition="start" icon={React.cloneElement(AGENT_CONFIG[agent].icon, { sx: { fontSize: 16 } })} />
        ))}
      </Tabs>

      <Box sx={{ flex: 1, overflowY: 'auto', p: 0, bgcolor: isDarkMode ? 'rgba(0,0,0,0.2)' : '#FAFAFA' }}>
        {/* Tab 0: Summary View */}
        {tabValue === 0 && (
          <Box sx={{ p: 3 }}>
            <Grid container spacing={2}>
              {availableAgents.map((agent) => {
                const result = agentResults[agent];
                const config = AGENT_CONFIG[agent];
                let summaryText = '';

                if (result?.status === 'completed' && result?.data?.result) {
                  try {
                    const parsed = typeof result.data.result === 'string' ? JSON.parse(result.data.result) : result.data.result;
                    if (agent === 'triage') summaryText = parsed.summary || parsed.classification || 'Analysis complete';
                    else if (agent === 'malware') summaryText = parsed.malware_family || (parsed.is_malicious ? 'Malicious Detected' : 'Clean');
                    else if (agent === 'infrastructure') summaryText = parsed.hosting_provider || parsed.country || 'Infrastructure analyzed';
                    else if (agent === 'campaign') summaryText = parsed.campaign_name || 'No campaign linked';
                    else summaryText = 'Analysis complete';
                  } catch (e) {
                    summaryText = 'Analysis complete';
                  }
                }

                return (
                  <Grid item xs={12} key={agent}>
                    <Box sx={{
                      p: 2,
                      borderRadius: '12px',
                      bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#FFFFFF',
                      border: isDarkMode ? '1px solid rgba(255,255,255,0.1)' : `1px solid ${COLORS.BORDER_LIGHT}`,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between'
                    }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, minWidth: 180 }}>
                          {React.cloneElement(config.icon, { sx: { fontSize: 20, color: isDarkMode ? '#fff' : '#000000' } })}
                          <Typography variant="body2" sx={{ fontWeight: 600, color: isDarkMode ? '#fff' : '#000000' }}>
                            {config.name}
                          </Typography>
                        </Box>
                        <Typography variant="body2" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY }}>
                          {result?.status === 'completed' ? summaryText : (result?.status === 'pending' ? 'Analyzing...' : 'Waiting...')}
                        </Typography>
                      </Box>
                      {result?.status === 'pending' && <CircularProgress size={16} sx={{ color: isDarkMode ? '#fff' : '#000000' }} />}
                      {result?.status === 'completed' && <CheckCircleIcon sx={{ fontSize: 20, color: isDarkMode ? '#fff' : '#000000' }} />}
                      {result?.status === 'error' && <ErrorIcon sx={{ fontSize: 20, color: COLORS.HIGH }} />}
                    </Box>
                  </Grid>
                );
              })}
            </Grid>
          </Box>
        )}

        {/* Individual Agent Tabs */}
        {availableAgents.map((agent, idx) => (
          tabValue === idx + 1 && (
            <AgentResultDetail
              key={agent}
              agent={agent}
              result={agentResults[agent]}
              isDarkMode={isDarkMode}
            />
          )
        ))}
      </Box>
    </Paper>
  );
};


// Aggregation Result Component (Deep Analysis Style)
function AggregationResultSection({ aggregation, currentPhase }) {
  const theme = useTheme();
  const isDarkMode = theme.palette.mode === 'dark';
  const [expanded, setExpanded] = useState(true);

  const isLoading = currentPhase === 'aggregation' && !aggregation;
  const isCompleted = aggregation?.status === 'completed';
  const hasError = aggregation?.status === 'error';

  let report = null;
  if (aggregation?.data?.aggregated_report) {
    try {
      report = typeof aggregation.data.aggregated_report === 'string'
        ? JSON.parse(aggregation.data.aggregated_report)
        : aggregation.data.aggregated_report;
    } catch (e) {
      report = aggregation.data.aggregated_report;
    }
  }

  if (!isLoading && !aggregation) return null;

  const cardStyle = {
    bgcolor: isDarkMode ? 'rgba(28, 28, 30, 0.6)' : COLORS.CARD_BG_LIGHT,
    borderRadius: '18px',
    border: isDarkMode ? '1px solid rgba(255,255,255,0.1)' : `1px solid ${COLORS.BORDER_LIGHT}`,
    boxShadow: isDarkMode ? 'none' : '0 4px 24px rgba(0,0,0,0.02)',
    overflow: 'hidden'
  };

  return (
    <Box sx={{ mt: 4 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
        <AutoAwesomeIcon sx={{ color: isDarkMode ? '#fff' : '#000000' }} />
        <Typography variant="h5" fontWeight={700} sx={{ color: isDarkMode ? '#fff' : '#000000' }}>
          Comprehensive Intelligence
        </Typography>
      </Box>

      <Paper sx={{ ...cardStyle }}>
        <Box
          sx={{
            p: 3,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            cursor: isCompleted ? 'pointer' : 'default',
            borderBottom: expanded && isCompleted ? (isDarkMode ? '1px solid rgba(255,255,255,0.1)' : `1px solid ${COLORS.BORDER_LIGHT}`) : 'none',
            bgcolor: isDarkMode ? 'rgba(255,255,255,0.02)' : '#FAFAFA'
          }}
          onClick={() => isCompleted && setExpanded(!expanded)}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: '12px',
                bgcolor: isDarkMode ? 'rgba(255,255,255,0.1)' : '#000000',
                color: '#fff',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: isDarkMode ? 'none' : '0 4px 12px rgba(0,0,0,0.2)'
              }}
            >
              <SummarizeIcon />
            </Box>
            <Box>
              <Typography variant="h6" fontWeight={700} sx={{ color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
                Aggregation Analysis
              </Typography>
              <Typography variant="body2" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY }}>
                {isLoading && 'AI 에이전트가 모든 분석 결과를 종합하고 있습니다...'}
                {isCompleted && '전체 IOC에 대한 종합 위협 인텔리전스 리포트가 생성되었습니다.'}
                {hasError && '종합 분석 중 오류가 발생했습니다.'}
              </Typography>
            </Box>
          </Box>

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {isLoading && <CircularProgress size={24} sx={{ color: isDarkMode ? '#fff' : '#000000' }} />}
            {isCompleted && <CheckCircleIcon sx={{ color: isDarkMode ? '#fff' : '#000000', fontSize: 28 }} />}
            {hasError && <ErrorIcon sx={{ color: COLORS.HIGH, fontSize: 28 }} />}
            {isCompleted && (
              <IconButton size="small" sx={{ ml: 1 }}>
                {expanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
              </IconButton>
            )}
          </Box>
        </Box>

        {hasError && (
          <Box sx={{ p: 3 }}>
            <Alert severity="error" sx={{ borderRadius: '12px' }}>{aggregation.error}</Alert>
          </Box>
        )}

        <Collapse in={expanded && isCompleted}>
          <Box sx={{ p: 4 }}>
            {typeof report === 'string' ? (
              <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap', lineHeight: 1.8, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
                {report}
              </Typography>
            ) : report && typeof report === 'object' ? (
              <Box>
                {/* Executive Summary */}
                {report.executive_summary && (
                  <Box sx={{ mb: 4, p: 3, borderRadius: '16px', bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9' }}>
                    <Typography variant="subtitle1" fontWeight={700} sx={{ color: isDarkMode ? '#fff' : '#000000', mb: 1.5, display: 'flex', alignItems: 'center', gap: 1 }}>
                      <VerifiedUserIcon fontSize="small" /> Executive Summary
                    </Typography>
                    <Typography variant="body1" sx={{ lineHeight: 1.8, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
                      {report.executive_summary}
                    </Typography>
                  </Box>
                )}

                {/* Key Findings Grid */}
                {report.key_findings && (
                  <Box sx={{ mb: 4 }}>
                    <Typography variant="h6" fontWeight={700} sx={{ mb: 2, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY, display: 'flex', alignItems: 'center', gap: 1 }}>
                      <LightbulbIcon sx={{ color: COLORS.MEDIUM }} /> Key Findings
                    </Typography>
                    <Grid container spacing={2}>
                      {Array.isArray(report.key_findings) ? (
                        report.key_findings.map((finding, idx) => (
                          <Grid item xs={12} md={6} key={idx}>
                            <Card elevation={0} sx={{
                              height: '100%',
                              bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#FFFFFF',
                              border: isDarkMode ? '1px solid rgba(255,255,255,0.1)' : `1px solid ${COLORS.BORDER_LIGHT}`,
                              borderRadius: '12px'
                            }}>
                              <CardContent>
                                <Box sx={{ display: 'flex', gap: 1.5 }}>
                                  <Box sx={{
                                    minWidth: 24, height: 24, borderRadius: '50%',
                                    bgcolor: alpha(COLORS.MEDIUM, 0.1), color: COLORS.MEDIUM,
                                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    fontWeight: 700, fontSize: '0.85rem'
                                  }}>
                                    {idx + 1}
                                  </Box>
                                  <Typography variant="body2" sx={{ lineHeight: 1.6, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
                                    {finding}
                                  </Typography>
                                </Box>
                              </CardContent>
                            </Card>
                          </Grid>
                        ))
                      ) : (
                        <Grid item xs={12}>
                          <Typography variant="body2">{report.key_findings}</Typography>
                        </Grid>
                      )}
                    </Grid>
                  </Box>
                )}

                {/* Detailed Analysis (Dynamic Section) */}
                {report.detailed_analysis && (
                  <Box sx={{ mb: 4 }}>
                    <Typography variant="h6" fontWeight={700} sx={{ mb: 2, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY, display: 'flex', alignItems: 'center', gap: 1 }}>
                      <SummarizeIcon sx={{ color: COLORS.PRIMARY }} /> Detailed Analysis
                    </Typography>
                    <Paper elevation={0} sx={{ p: 3, bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '16px' }}>
                      <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap', lineHeight: 1.8, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
                        {report.detailed_analysis}
                      </Typography>
                    </Paper>
                  </Box>
                )}

                {/* Strategic Implications (Dynamic Section) */}
                {report.strategic_implications && (
                  <Box sx={{ mb: 4 }}>
                    <Typography variant="h6" fontWeight={700} sx={{ mb: 2, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY, display: 'flex', alignItems: 'center', gap: 1 }}>
                      <AssessmentIcon sx={{ color: COLORS.CRITICAL }} /> Strategic Implications
                    </Typography>
                    <Paper elevation={0} sx={{ p: 3, bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '16px' }}>
                      <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap', lineHeight: 1.8, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
                        {report.strategic_implications}
                      </Typography>
                    </Paper>
                  </Box>
                )}

                {/* Recommendations */}
                {report.recommendations && (
                  <Box sx={{ mb: 4 }}>
                    <Typography variant="h6" fontWeight={700} sx={{ mb: 2, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY, display: 'flex', alignItems: 'center', gap: 1 }}>
                      <WarningIcon sx={{ color: COLORS.HIGH }} /> Recommendations
                    </Typography>
                    <Paper elevation={0} sx={{
                      bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#FFFFFF',
                      border: isDarkMode ? '1px solid rgba(255,255,255,0.1)' : `1px solid ${COLORS.BORDER_LIGHT}`,
                      borderRadius: '16px',
                      overflow: 'hidden'
                    }}>
                      <List disablePadding>
                        {Array.isArray(report.recommendations) ? (
                          report.recommendations.map((rec, idx) => (
                            <React.Fragment key={idx}>
                              <ListItem sx={{ py: 2 }}>
                                <ListItemIcon sx={{ minWidth: 40 }}>
                                  <CheckCircleIcon sx={{ color: COLORS.LOW }} />
                                </ListItemIcon>
                                <ListItemText
                                  primary={rec}
                                  primaryTypographyProps={{
                                    variant: 'body2',
                                    sx: { lineHeight: 1.6, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY, fontWeight: 500 }
                                  }}
                                />
                              </ListItem>
                              {idx < report.recommendations.length - 1 && <Divider component="li" sx={{ ml: 7 }} />}
                            </React.Fragment>
                          ))
                        ) : (
                          <ListItem>
                            <ListItemText primary={report.recommendations} />
                          </ListItem>
                        )}
                      </List>
                    </Paper>
                  </Box>
                )}

                {/* Other Dynamic Fields */}
                {Object.keys(report).map((key) => {
                  if (['executive_summary', 'key_findings', 'recommendations', 'detailed_analysis', 'strategic_implications'].includes(key)) return null;

                  // Skip empty objects/arrays to avoid clutter
                  if (typeof report[key] === 'object' && report[key] !== null && Object.keys(report[key]).length === 0) return null;
                  if (Array.isArray(report[key]) && report[key].length === 0) return null;

                  return (
                    <Box key={key} sx={{ mb: 4 }}>
                      <Typography variant="h6" fontWeight={700} sx={{ mb: 2, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY, textTransform: 'capitalize' }}>
                        {key.replace(/_/g, ' ')}
                      </Typography>
                      <Paper elevation={0} sx={{ p: 3, bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '16px' }}>
                        <DynamicContentRenderer data={report[key]} isDarkMode={isDarkMode} />
                      </Paper>
                    </Box>
                  );
                })}

                {!report.executive_summary && !report.key_findings && (
                  <Box
                    component="pre"
                    sx={{ p: 2, bgcolor: isDarkMode ? 'rgba(0,0,0,0.3)' : '#F5F5F7', borderRadius: '8px', overflow: 'auto', fontSize: '0.85rem', fontFamily: 'monospace', color: isDarkMode ? '#ccc' : COLORS.TEXT_PRIMARY }}
                  >
                    {JSON.stringify(report, null, 2)}
                  </Box>
                )}
              </Box>
            ) : null}
          </Box>
        </Collapse>
      </Paper>
    </Box>
  );
}

// Welcome Screen for Agent Analysis
function AgentWelcomeScreen() {
  const theme = useTheme();
  const isDarkMode = theme.palette.mode === 'dark';

  return (
    <Paper
      elevation={0}
      sx={{
        p: 4,
        textAlign: 'center',
        borderRadius: '24px',
        border: isDarkMode ? '1px dashed rgba(255,255,255,0.1)' : `1px dashed ${COLORS.BORDER_LIGHT}`,
        bgcolor: 'transparent',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: 2,
      }}
    >
      <Box sx={{
        p: 2,
        borderRadius: '50%',
        bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F5F5F7',
        mb: 1
      }}>
        <PsychologyIcon sx={{ fontSize: 40, color: isDarkMode ? '#fff' : '#000000' }} />
      </Box>
      <Typography variant="h6" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontWeight: 600 }}>
        Ready for Analysis
      </Typography>
      <Typography variant="body2" sx={{ color: isDarkMode ? '#666' : '#999', maxWidth: 400, lineHeight: 1.6 }}>
        상단의 입력창에 분석할 IOC를 입력하거나 파일을 업로드한 후,
        <br />
        <strong>"Agent 분석 시작"</strong> 버튼을 클릭해주세요.
      </Typography>
    </Paper>
  );
}

// Main Component
export default function AgentAnalysisResults({ results, aggregation, loading, currentPhase, error }) {
  const theme = useTheme();
  const isDarkMode = theme.palette.mode === 'dark';
  const [selectedIOC, setSelectedIOC] = useState(null);

  const iocList = Object.keys(results || {});
  const hasResults = iocList.length > 0;

  useEffect(() => {
    if (hasResults && !selectedIOC) {
      setSelectedIOC(iocList[0]);
    }
  }, [hasResults, iocList, selectedIOC]);

  if (error) {
    return <Alert severity="error" sx={{ mb: 2, borderRadius: '12px' }}>{error}</Alert>;
  }

  if (!hasResults && !loading) {
    return <AgentWelcomeScreen />;
  }

  return (
    <Box>
      {hasResults && (
        <>
          <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <Typography variant="h6" fontWeight={700} sx={{ color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
              Individual Analysis Results <span style={{ color: COLORS.TEXT_SECONDARY, fontSize: '0.9em', fontWeight: 500 }}>({iocList.length})</span>
            </Typography>
          </Box>

          <Grid container spacing={2} sx={{ mb: 4, height: '650px' }}>
            {/* Left Panel: List */}
            <Grid item xs={12} md={4} sx={{ height: '100%', overflowY: 'auto', pr: 1 }}>
              {iocList.map((ioc) => (
                <IOCListItem
                  key={ioc}
                  ioc={ioc}
                  agentResults={results[ioc]}
                  isSelected={selectedIOC === ioc}
                  onClick={() => setSelectedIOC(ioc)}
                  isDarkMode={isDarkMode}
                />
              ))}
            </Grid>

            {/* Right Panel: Detail */}
            <Grid item xs={12} md={8} sx={{ height: '100%' }}>
              <IOCDetailPanel
                ioc={selectedIOC}
                agentResults={selectedIOC ? results[selectedIOC] : null}
                isDarkMode={isDarkMode}
              />
            </Grid>
          </Grid>

          <Divider sx={{ my: 4, borderColor: isDarkMode ? 'rgba(255,255,255,0.1)' : COLORS.BORDER_LIGHT }} />

          <AggregationResultSection aggregation={aggregation} currentPhase={currentPhase} />
        </>
      )}
    </Box>
  );
}
