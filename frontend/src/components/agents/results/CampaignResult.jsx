import React from 'react';
import {
  Box,
  Paper,
  Typography,
  Chip,
  List,
  ListItem,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Grid,
  LinearProgress,
  useTheme,
  alpha
} from '@mui/material';
import CampaignIcon from '@mui/icons-material/Campaign';
import ShieldIcon from '@mui/icons-material/Shield';
import GpsFixedIcon from '@mui/icons-material/GpsFixed';
import TimelineIcon from '@mui/icons-material/Timeline';
import PersonIcon from '@mui/icons-material/Person';
import SearchIcon from '@mui/icons-material/Search';
import LightbulbIcon from '@mui/icons-material/Lightbulb';
import ReportProblemIcon from '@mui/icons-material/ReportProblem';
import BusinessIcon from '@mui/icons-material/Business';
import FlagIcon from '@mui/icons-material/Flag';

// Apple-style Color Palette (Consistent with TriageResult)
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

const getThreatLevelColor = (level) => {
  switch (level?.toUpperCase()) {
    case 'CRITICAL': return COLORS.CRITICAL;
    case 'HIGH': return COLORS.HIGH;
    case 'MEDIUM': return COLORS.MEDIUM;
    case 'LOW': return COLORS.LOW;
    default: return COLORS.UNKNOWN;
  }
};

const DetectionGauge = ({ detections }) => {
  if (!detections || typeof detections !== 'string') return null;

  const [detected, total] = detections.split('/').map(Number);
  if (isNaN(detected) || isNaN(total) || total === 0) return detections;

  const percentage = (detected / total) * 100;

  const getColor = () => {
    if (percentage >= 50) return 'error';
    if (percentage >= 20) return 'warning';
    return 'success';
  };

  return (
    <Box sx={{ minWidth: 120 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 0.5 }}>
        <Typography variant="body2" sx={{ fontFamily: 'monospace', fontWeight: 700 }}>
          {detected}/{total}
        </Typography>
        <Typography variant="caption" sx={{ fontWeight: 600, color: `${getColor()}.main` }}>
          {percentage.toFixed(0)}%
        </Typography>
      </Box>
      <LinearProgress
        variant="determinate"
        value={percentage}
        color={getColor()}
        sx={{
          height: 6,
          borderRadius: 3,
          bgcolor: 'grey.200',
        }}
      />
    </Box>
  );
};

export default function CampaignResult({ data }) {
  const theme = useTheme();
  const isDarkMode = theme.palette.mode === 'dark';

  if (!data) return null;

  const threatColor = getThreatLevelColor(data.threat_level);

  return (
    <Box>
      {/* Executive Summary - Hero Section */}
      <Paper
        elevation={0}
        sx={{
          p: 3,
          mb: 3,
          borderRadius: '12px',
          border: `1px solid ${isDarkMode ? 'rgba(255,255,255,0.1)' : COLORS.BORDER_LIGHT}`,
          bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : COLORS.CARD_BG_LIGHT,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2, mb: 3 }}>
          <Box
            sx={{
              p: 1.5,
              borderRadius: '12px',
              bgcolor: alpha(threatColor, 0.1),
              color: threatColor,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <CampaignIcon sx={{ fontSize: 32 }} />
          </Box>
          <Box>
            <Typography variant="overline" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontWeight: 600, letterSpacing: 1 }}>
              Campaign Intelligence
            </Typography>
            <Typography variant="h5" sx={{ fontWeight: 700, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY, mb: 1 }}>
              {data.campaign_name}
            </Typography>
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
              <Chip
                label={data.threat_level}
                size="small"
                sx={{
                  bgcolor: alpha(threatColor, 0.1),
                  color: threatColor,
                  fontWeight: 700,
                  borderRadius: '6px',
                }}
              />
              <Chip
                label={`Confidence: ${data.campaign_confidence}`}
                size="small"
                sx={{
                  bgcolor: isDarkMode ? 'rgba(255,255,255,0.1)' : COLORS.BG_LIGHT,
                  color: isDarkMode ? '#ddd' : COLORS.TEXT_SECONDARY,
                  fontWeight: 600,
                  borderRadius: '6px',
                }}
              />
            </Box>
          </Box>
        </Box>

        <Divider sx={{ my: 3, borderColor: isDarkMode ? 'rgba(255,255,255,0.1)' : COLORS.BORDER_LIGHT }} />

        <Box>
          <Typography variant="subtitle2" sx={{ mb: 1.5, color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontWeight: 600 }}>
            EXECUTIVE SUMMARY
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.8, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
            {data.executive_summary}
          </Typography>
        </Box>
      </Paper>

      {/* Campaign Evidence */}
      {data.campaign_evidence && data.campaign_evidence.length > 0 && (
        <Box sx={{ mb: 4 }}>
          <Typography variant="h6" sx={{ mb: 2, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
            <GpsFixedIcon color="primary" /> Campaign Evidence
          </Typography>
          <Grid container spacing={2}>
            {data.campaign_evidence.map((evidence, index) => (
              <Grid item xs={12} key={index}>
                <Paper
                  elevation={0}
                  sx={{
                    p: 2,
                    borderRadius: '8px',
                    border: `1px solid ${isDarkMode ? 'rgba(255,255,255,0.1)' : COLORS.BORDER_LIGHT}`,
                    bgcolor: isDarkMode ? 'rgba(255,255,255,0.02)' : COLORS.BG_LIGHT,
                    display: 'flex',
                    gap: 2,
                  }}
                >
                  <Typography variant="subtitle2" sx={{ color: COLORS.PRIMARY, fontWeight: 700, minWidth: '24px' }}>
                    {String(index + 1).padStart(2, '0')}
                  </Typography>
                  <Typography variant="body2" sx={{ color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY, lineHeight: 1.6 }}>
                    {evidence}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

      {/* MITRE ATT&CK Tactics */}
      {data.mitre_tactics && data.mitre_tactics.length > 0 && (
        <Box sx={{ mb: 4 }}>
          <Typography variant="h6" sx={{ mb: 2, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
            <ShieldIcon sx={{ color: COLORS.CRITICAL }} /> MITRE ATT&CK Tactics
          </Typography>
          <Grid container spacing={2}>
            {data.mitre_tactics.map((tactic, index) => (
              <Grid item xs={12} md={6} key={index}>
                <Paper
                  elevation={0}
                  sx={{
                    p: 3,
                    height: '100%',
                    borderRadius: '12px',
                    border: `1px solid ${isDarkMode ? 'rgba(255,255,255,0.1)' : COLORS.BORDER_LIGHT}`,
                    bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : COLORS.CARD_BG_LIGHT,
                  }}
                >
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
                    {tactic.tactic}
                  </Typography>
                  
                  {tactic.techniques && tactic.techniques.length > 0 && (
                    <Box sx={{ mb: 2, display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                      {tactic.techniques.map((technique, idx) => (
                        <Chip
                          key={idx}
                          label={technique}
                          size="small"
                          variant="outlined"
                          sx={{
                            borderColor: isDarkMode ? 'rgba(255,255,255,0.2)' : COLORS.BORDER_LIGHT,
                            color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY,
                            borderRadius: '4px',
                            fontWeight: 500
                          }}
                        />
                      ))}
                    </Box>
                  )}
                  
                  {tactic.evidence && (
                    <Box sx={{ p: 1.5, bgcolor: isDarkMode ? 'rgba(255,255,255,0.03)' : COLORS.BG_LIGHT, borderRadius: '8px' }}>
                      <Typography variant="caption" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, display: 'block', mb: 0.5, fontWeight: 600 }}>
                        EVIDENCE
                      </Typography>
                      <Typography variant="body2" sx={{ color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY, fontSize: '0.85rem' }}>
                        {tactic.evidence}
                      </Typography>
                    </Box>
                  )}
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

      {/* Attack Chain TTPs */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h6" sx={{ mb: 2, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
          <TimelineIcon sx={{ color: COLORS.MEDIUM }} /> Attack Chain TTPs
        </Typography>
        <Paper
          elevation={0}
          sx={{
            p: 3,
            borderRadius: '12px',
            border: `1px solid ${isDarkMode ? 'rgba(255,255,255,0.1)' : COLORS.BORDER_LIGHT}`,
            bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : COLORS.CARD_BG_LIGHT,
          }}
        >
          <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap', lineHeight: 1.8, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
            {data.attack_chain_ttps}
          </Typography>
        </Paper>
      </Box>

      {/* Threat Actor Attribution */}
      {data.threat_actor_attribution && (
        <Box sx={{ mb: 4 }}>
          <Typography variant="h6" sx={{ mb: 2, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
            <PersonIcon sx={{ color: COLORS.HIGH }} /> Threat Actor Attribution
          </Typography>
          <Paper
            elevation={0}
            sx={{
              p: 3,
              borderRadius: '12px',
              border: `1px solid ${isDarkMode ? 'rgba(255,255,255,0.1)' : COLORS.BORDER_LIGHT}`,
              bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : COLORS.CARD_BG_LIGHT,
            }}
          >
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="caption" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontWeight: 600, display: 'block', mb: 1 }}>
                  ATTRIBUTED ACTOR
                </Typography>
                <Typography variant="h6" sx={{ fontWeight: 700, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
                  {data.threat_actor_attribution.attributed_actor || 'Unknown'}
                </Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="caption" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontWeight: 600, display: 'block', mb: 1 }}>
                  CONFIDENCE
                </Typography>
                <Chip
                  label={data.threat_actor_attribution.confidence}
                  size="small"
                  sx={{
                    bgcolor: alpha(COLORS.HIGH, 0.1),
                    color: COLORS.HIGH,
                    fontWeight: 700,
                    borderRadius: '6px',
                  }}
                />
              </Grid>
            </Grid>

            <Divider sx={{ my: 3, borderColor: isDarkMode ? 'rgba(255,255,255,0.1)' : COLORS.BORDER_LIGHT }} />

            {data.threat_actor_attribution.overlap_indicators && data.threat_actor_attribution.overlap_indicators.length > 0 && (
              <Box sx={{ mb: 3 }}>
                <Typography variant="subtitle2" sx={{ mb: 1.5, color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontWeight: 600 }}>
                  OVERLAP INDICATORS
                </Typography>
                <List dense disablePadding>
                  {data.threat_actor_attribution.overlap_indicators.map((indicator, index) => (
                    <ListItem key={index} disablePadding sx={{ mb: 1 }}>
                      <Box sx={{ mr: 1.5, width: 6, height: 6, borderRadius: '50%', bgcolor: COLORS.HIGH }} />
                      <Typography variant="body2" sx={{ color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
                        {indicator}
                      </Typography>
                    </ListItem>
                  ))}
                </List>
              </Box>
            )}

            <Box sx={{ p: 2, bgcolor: isDarkMode ? 'rgba(255,255,255,0.03)' : COLORS.BG_LIGHT, borderRadius: '8px' }}>
              <Typography variant="caption" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, display: 'block', mb: 0.5, fontWeight: 600 }}>
                RATIONALE
              </Typography>
              <Typography variant="body2" sx={{ color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
                {data.threat_actor_attribution.attribution_rationale}
              </Typography>
            </Box>
          </Paper>
        </Box>
      )}

      {/* Hunt Hypotheses */}
      {data.hunt_hypotheses && data.hunt_hypotheses.length > 0 && (
        <Box sx={{ mb: 4 }}>
          <Typography variant="h6" sx={{ mb: 2, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
            <SearchIcon sx={{ color: COLORS.PRIMARY }} /> Hunt Hypotheses
          </Typography>
          <Grid container spacing={2}>
            {data.hunt_hypotheses.map((hypothesis, index) => (
              <Grid item xs={12} key={index}>
                <Paper
                  elevation={0}
                  sx={{
                    p: 3,
                    borderRadius: '12px',
                    border: `1px solid ${isDarkMode ? 'rgba(255,255,255,0.1)' : COLORS.BORDER_LIGHT}`,
                    bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : COLORS.CARD_BG_LIGHT,
                  }}
                >
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2, flexWrap: 'wrap' }}>
                    <Chip
                      label={`#${hypothesis.hypothesis_id}`}
                      size="small"
                      sx={{ fontWeight: 700, borderRadius: '6px' }}
                    />
                    <Typography variant="subtitle1" sx={{ flexGrow: 1, fontWeight: 700, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
                      {hypothesis.hypothesis_name}
                    </Typography>
                    <Chip
                      label={hypothesis.confidence}
                      size="small"
                      sx={{
                        bgcolor: alpha(getThreatLevelColor(hypothesis.confidence), 0.1),
                        color: getThreatLevelColor(hypothesis.confidence),
                        fontWeight: 700,
                        borderRadius: '6px',
                      }}
                    />
                  </Box>

                  <Typography variant="body2" sx={{ mb: 2, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY, lineHeight: 1.6 }}>
                    {hypothesis.hypothesis_description}
                  </Typography>

                  <Box sx={{ p: 2, bgcolor: isDarkMode ? 'rgba(0,0,0,0.3)' : '#1E1E1E', borderRadius: '8px', mb: 2, color: '#fff', fontFamily: 'monospace', fontSize: '0.85rem', overflowX: 'auto' }}>
                    {hypothesis.executable_query}
                  </Box>

                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="caption" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, display: 'block' }}>
                        PLATFORM
                      </Typography>
                      <Typography variant="body2" sx={{ fontWeight: 500, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
                        {hypothesis.detection_platform}
                      </Typography>
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="caption" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, display: 'block' }}>
                        SUCCESS CRITERIA
                      </Typography>
                      <Typography variant="body2" sx={{ fontWeight: 500, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
                        {hypothesis.success_criteria}
                      </Typography>
                    </Grid>
                  </Grid>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

      {/* Extracted IOCs */}
      {data.extracted_iocs && data.extracted_iocs.length > 0 && (
        <Box sx={{ mb: 4 }}>
          <Typography variant="h6" sx={{ mb: 2, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
            <FlagIcon sx={{ color: COLORS.UNKNOWN }} /> Extracted IOCs
          </Typography>
          <TableContainer component={Paper} elevation={0} sx={{ border: `1px solid ${isDarkMode ? 'rgba(255,255,255,0.1)' : COLORS.BORDER_LIGHT}`, borderRadius: '12px', bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : COLORS.CARD_BG_LIGHT }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : COLORS.BG_LIGHT }}>
                  <TableCell sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontWeight: 600 }}>Indicator</TableCell>
                  <TableCell sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontWeight: 600 }}>Type</TableCell>
                  <TableCell sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontWeight: 600 }}>Confidence</TableCell>
                  <TableCell sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontWeight: 600 }}>Detections</TableCell>
                  <TableCell sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontWeight: 600 }}>Action</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.extracted_iocs.map((ioc, index) => (
                  <TableRow key={index} hover>
                    <TableCell sx={{ fontFamily: 'monospace', color: isDarkMode ? '#fff' : COLORS.PRIMARY, fontWeight: 500 }}>
                      {ioc.indicator}
                    </TableCell>
                    <TableCell>
                      <Chip label={ioc.ioc_type} size="small" sx={{ borderRadius: '4px', height: 24 }} />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={ioc.confidence}
                        size="small"
                        sx={{
                          bgcolor: alpha(getThreatLevelColor(ioc.confidence), 0.1),
                          color: getThreatLevelColor(ioc.confidence),
                          fontWeight: 700,
                          borderRadius: '4px',
                          height: 24
                        }}
                      />
                    </TableCell>
                    <TableCell>
                      <DetectionGauge detections={ioc.detections} />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={ioc.recommended_action}
                        size="small"
                        variant="outlined"
                        color={ioc.recommended_action === 'block' ? 'error' : 'default'}
                        sx={{ borderRadius: '4px', height: 24 }}
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Box>
      )}

      {/* Recommended Actions */}
      {data.recommended_actions && data.recommended_actions.length > 0 && (
        <Box sx={{ mb: 4 }}>
          <Typography variant="h6" sx={{ mb: 2, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
            <LightbulbIcon sx={{ color: COLORS.LOW }} /> Recommended Actions
          </Typography>
          <Grid container spacing={2}>
            {data.recommended_actions.map((action, index) => (
              <Grid item xs={12} key={index}>
                <Paper
                  elevation={0}
                  sx={{
                    p: 2,
                    borderRadius: '8px',
                    border: `1px solid ${isDarkMode ? 'rgba(255,255,255,0.1)' : COLORS.BORDER_LIGHT}`,
                    bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : COLORS.CARD_BG_LIGHT,
                    display: 'flex',
                    gap: 2,
                    alignItems: 'flex-start'
                  }}
                >
                  <Box sx={{
                    minWidth: 24,
                    height: 24,
                    borderRadius: '50%',
                    bgcolor: alpha(COLORS.LOW, 0.1),
                    color: COLORS.LOW,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontWeight: 700,
                    fontSize: '0.8rem',
                    mt: 0.2
                  }}>
                    {index + 1}
                  </Box>
                  <Typography variant="body2" sx={{ color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY, lineHeight: 1.6 }}>
                    {action}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

      {/* Intelligence Gaps */}
      {data.intelligence_gaps && data.intelligence_gaps.length > 0 && (
        <Box sx={{ mb: 4 }}>
          <Typography variant="h6" sx={{ mb: 2, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
            <ReportProblemIcon sx={{ color: COLORS.MEDIUM }} /> Intelligence Gaps
          </Typography>
          <Grid container spacing={2}>
            {data.intelligence_gaps.map((gap, index) => (
              <Grid item xs={12} md={6} key={index}>
                <Paper
                  elevation={0}
                  sx={{
                    p: 2,
                    height: '100%',
                    borderRadius: '8px',
                    border: `1px solid ${isDarkMode ? 'rgba(255,255,255,0.1)' : COLORS.BORDER_LIGHT}`,
                    bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : COLORS.BG_LIGHT,
                    display: 'flex',
                    gap: 2,
                  }}
                >
                  <Box sx={{ color: COLORS.MEDIUM, mt: 0.5 }}>•</Box>
                  <Typography variant="body2" sx={{ color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY, lineHeight: 1.6 }}>
                    {gap}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

      {/* Organizational Impact */}
      {data.organizational_impact && (
        <Box>
          <Typography variant="h6" sx={{ mb: 2, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
            <BusinessIcon sx={{ color: COLORS.PRIMARY }} /> Organizational Impact
          </Typography>
          <Paper
            elevation={0}
            sx={{
              p: 3,
              borderRadius: '12px',
              border: `1px solid ${isDarkMode ? 'rgba(255,255,255,0.1)' : COLORS.BORDER_LIGHT}`,
              bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : COLORS.CARD_BG_LIGHT,
            }}
          >
            <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap', lineHeight: 1.8, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
              {data.organizational_impact}
            </Typography>
          </Paper>
        </Box>
      )}
    </Box>
  );
}
