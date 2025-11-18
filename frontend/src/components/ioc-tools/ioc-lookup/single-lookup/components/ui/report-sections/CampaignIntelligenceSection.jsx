import React from 'react';
import {
  Box,
  Paper,
  Typography,
  Chip,
  Alert,
  List,
  ListItem,
  ListItemText,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Grid,
  Card,
  CardContent,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import WarningIcon from '@mui/icons-material/Warning';
import InfoIcon from '@mui/icons-material/Info';
import SecurityIcon from '@mui/icons-material/Security';
import GavelIcon from '@mui/icons-material/Gavel';
import PersonSearchIcon from '@mui/icons-material/PersonSearch';
import SearchIcon from '@mui/icons-material/Search';
import FlagIcon from '@mui/icons-material/Flag';
import BugReportIcon from '@mui/icons-material/BugReport';
import RecommendIcon from '@mui/icons-material/Recommend';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import BusinessIcon from '@mui/icons-material/Business';
import { RadialBarChart, RadialBar, PolarAngleAxis, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';
import { useTheme } from '@mui/material/styles';

const CampaignIntelligenceSection = ({ data }) => {
  const theme = useTheme();

  if (!data) return null;

  // Threat Level 점수 계산
  const getThreatScore = (level) => {
    const scores = { 'CRITICAL': 100, 'HIGH': 75, 'MEDIUM': 50, 'LOW': 25, 'INFO': 10 };
    return scores[level] || 0;
  };

  const threatScore = getThreatScore(data.threat_level);

  // Threat Level 게이지 데이터
  const threatGaugeData = [
    {
      name: data.threat_level,
      value: threatScore,
      fill: data.threat_level === 'CRITICAL' || data.threat_level === 'HIGH' ? '#f44336' :
            data.threat_level === 'MEDIUM' ? '#ff9800' : '#4caf50'
    }
  ];

  // MITRE ATT&CK 기법 분포 데이터
  const getMitreTechniqueData = () => {
    if (!data.mitre_tactics || data.mitre_tactics.length === 0) return [];

    const techniqueCount = {};
    data.mitre_tactics.forEach(tactic => {
      if (tactic.techniques && Array.isArray(tactic.techniques)) {
        tactic.techniques.forEach(technique => {
          techniqueCount[technique] = (techniqueCount[technique] || 0) + 1;
        });
      }
    });

    return Object.entries(techniqueCount).map(([technique, count]) => ({
      technique,
      count
    }));
  };

  const mitreData = getMitreTechniqueData();

  // Detection Rate 분석
  const getDetectionRateData = () => {
    if (!data.extracted_iocs || data.extracted_iocs.length === 0) return [];

    return data.extracted_iocs.slice(0, 5).map(ioc => {
      const [detected, total] = (ioc.detections || '0/0').split('/').map(Number);
      const rate = total > 0 ? (detected / total) * 100 : 0;

      return {
        indicator: ioc.indicator?.slice(0, 20) + (ioc.indicator?.length > 20 ? '...' : ''),
        rate: Math.round(rate),
        detected,
        total
      };
    });
  };

  const detectionData = getDetectionRateData();

  return (
    <Box>
      {/* Executive Summary with Threat Level Gauge */}
      <Paper elevation={3} sx={{ p: 3, mb: 3, borderRadius: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <InfoIcon sx={{ mr: 1, color: 'primary.main' }} />
          <Typography variant="h6" fontWeight="bold">
            Executive Summary
          </Typography>
        </Box>

        <Grid container spacing={3}>
          {/* Left: Summary Text */}
          <Grid item xs={12} md={8}>
            <Alert
              icon={<WarningIcon />}
              severity={
                data.threat_level === 'CRITICAL' || data.threat_level === 'HIGH' ? 'error' :
                data.threat_level === 'MEDIUM' ? 'warning' : 'info'
              }
              sx={{ mb: 2 }}
            >
              <Typography variant="body2">{data.executive_summary}</Typography>
            </Alert>
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
              <Chip
                icon={<FlagIcon />}
                label={`Threat Level: ${data.threat_level}`}
                color={
                  data.threat_level === 'CRITICAL' || data.threat_level === 'HIGH' ? 'error' :
                  data.threat_level === 'MEDIUM' ? 'warning' : 'info'
                }
              />
              <Chip
                icon={<SecurityIcon />}
                label={`Campaign: ${data.campaign_name}`}
                variant="outlined"
              />
              <Chip
                label={`Confidence: ${data.campaign_confidence}`}
                variant="outlined"
                color={
                  data.campaign_confidence === 'HIGH' ? 'error' :
                  data.campaign_confidence === 'MEDIUM' ? 'warning' : 'info'
                }
              />
            </Box>
          </Grid>

          {/* Right: Threat Level Gauge */}
          <Grid item xs={12} md={4}>
            <Card sx={{ bgcolor: 'background.default', height: '100%' }}>
              <CardContent sx={{ textAlign: 'center' }}>
                <Typography variant="subtitle2" gutterBottom color="text.secondary">
                  Threat Level Score
                </Typography>
                <ResponsiveContainer width="100%" height={150}>
                  <RadialBarChart
                    cx="50%"
                    cy="50%"
                    innerRadius="60%"
                    outerRadius="90%"
                    barSize={15}
                    data={threatGaugeData}
                    startAngle={180}
                    endAngle={0}
                  >
                    <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
                    <RadialBar
                      background
                      dataKey="value"
                      cornerRadius={10}
                      fill={threatGaugeData[0].fill}
                    />
                    <text
                      x="50%"
                      y="50%"
                      textAnchor="middle"
                      dominantBaseline="middle"
                      style={{
                        fontSize: '28px',
                        fontWeight: 'bold',
                        fill: threatGaugeData[0].fill
                      }}
                    >
                      {threatScore}
                    </text>
                  </RadialBarChart>
                </ResponsiveContainer>
                <Typography variant="caption" color="text.secondary">
                  Risk Assessment (0-100)
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Paper>

      {/* Campaign Evidence */}
      {data.campaign_evidence && data.campaign_evidence.length > 0 && (
        <Paper elevation={2} sx={{ p: 3, mb: 3, borderRadius: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <SearchIcon sx={{ mr: 1, color: 'primary.main' }} />
            <Typography variant="h6" fontWeight="bold">
              Campaign Evidence
            </Typography>
          </Box>
          <List>
            {data.campaign_evidence.map((evidence, index) => (
              <ListItem key={index} sx={{ py: 0.5 }}>
                <ListItemText
                  primary={evidence}
                  primaryTypographyProps={{ variant: 'body2' }}
                />
              </ListItem>
            ))}
          </List>
        </Paper>
      )}

      {/* MITRE ATT&CK Tactics with Visualization */}
      {data.mitre_tactics && data.mitre_tactics.length > 0 && (
        <Paper elevation={2} sx={{ p: 3, mb: 3, borderRadius: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <GavelIcon sx={{ mr: 1, color: 'primary.main' }} />
            <Typography variant="h6" fontWeight="bold">
              MITRE ATT&CK Tactics
            </Typography>
          </Box>

          {/* MITRE Technique Distribution Chart */}
          {mitreData.length > 0 && (
            <Card sx={{ mb: 3, bgcolor: 'background.default' }}>
              <CardContent>
                <Typography variant="subtitle2" gutterBottom color="text.secondary">
                  Technique Distribution
                </Typography>
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={mitreData} layout="vertical">
                    <XAxis type="number" />
                    <YAxis
                      dataKey="technique"
                      type="category"
                      width={100}
                      style={{ fontSize: '12px' }}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: theme.palette.background.paper,
                        border: `1px solid ${theme.palette.divider}`
                      }}
                    />
                    <Bar dataKey="count" fill={theme.palette.primary.main} radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          )}

          {/* Tactic Details */}
          <List>
            {data.mitre_tactics.map((tactic, index) => (
              <React.Fragment key={index}>
                <ListItem alignItems="flex-start" sx={{ flexDirection: 'column', alignItems: 'flex-start' }}>
                  <Typography variant="subtitle1" fontWeight="medium" sx={{ mb: 1 }}>
                    {tactic.tactic}
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, mb: 1, flexWrap: 'wrap' }}>
                    {tactic.techniques && tactic.techniques.map((technique, idx) => (
                      <Chip
                        key={idx}
                        label={technique}
                        size="small"
                        color="primary"
                        variant="outlined"
                      />
                    ))}
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    {tactic.evidence}
                  </Typography>
                </ListItem>
                {index < data.mitre_tactics.length - 1 && <Divider sx={{ my: 1 }} />}
              </React.Fragment>
            ))}
          </List>
        </Paper>
      )}

      {/* Attack Chain TTPs */}
      {data.attack_chain_ttps && (
        <Paper elevation={2} sx={{ p: 3, mb: 3, borderRadius: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <SecurityIcon sx={{ mr: 1, color: 'primary.main' }} />
            <Typography variant="h6" fontWeight="bold">
              Attack Chain TTPs
            </Typography>
          </Box>
          <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap', lineHeight: 1.8 }}>
            {data.attack_chain_ttps}
          </Typography>
        </Paper>
      )}

      {/* Threat Actor Attribution */}
      {data.threat_actor_attribution && (
        <Paper elevation={2} sx={{ p: 3, mb: 3, borderRadius: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <PersonSearchIcon sx={{ mr: 1, color: 'primary.main' }} />
            <Typography variant="h6" fontWeight="bold">
              Threat Actor Attribution
            </Typography>
          </Box>
          <Box sx={{ mb: 2 }}>
            {data.threat_actor_attribution.attributed_actor && (
              <Chip
                label={data.threat_actor_attribution.attributed_actor}
                color="error"
                sx={{ mr: 1 }}
              />
            )}
            <Chip
              label={`Confidence: ${data.threat_actor_attribution.confidence}`}
              variant="outlined"
              color={
                data.threat_actor_attribution.confidence === 'HIGH' ? 'error' :
                data.threat_actor_attribution.confidence === 'MEDIUM' ? 'warning' : 'info'
              }
            />
          </Box>
          {data.threat_actor_attribution.overlap_indicators && data.threat_actor_attribution.overlap_indicators.length > 0 && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" gutterBottom fontWeight="medium">
                Overlap Indicators
              </Typography>
              <List dense>
                {data.threat_actor_attribution.overlap_indicators.map((indicator, index) => (
                  <ListItem key={index} sx={{ py: 0.25 }}>
                    <ListItemText
                      primary={indicator}
                      primaryTypographyProps={{ variant: 'body2' }}
                    />
                  </ListItem>
                ))}
              </List>
            </Box>
          )}
          {data.threat_actor_attribution.attribution_rationale && (
            <Box sx={{ mt: 2, p: 2, bgcolor: 'background.default', borderRadius: 1 }}>
              <Typography variant="body2" color="text.secondary">
                <strong>Attribution Rationale:</strong> {data.threat_actor_attribution.attribution_rationale}
              </Typography>
            </Box>
          )}
        </Paper>
      )}

      {/* Hunt Hypotheses */}
      {data.hunt_hypotheses && data.hunt_hypotheses.length > 0 && (
        <Paper elevation={2} sx={{ p: 3, mb: 3, borderRadius: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <BugReportIcon sx={{ mr: 1, color: 'primary.main' }} />
            <Typography variant="h6" fontWeight="bold">
              Hunt Hypotheses
            </Typography>
          </Box>
          {data.hunt_hypotheses.map((hypothesis, index) => (
            <Accordion
              key={index}
              sx={{
                mb: 1,
                '&:before': { display: 'none' },
                boxShadow: 1
              }}
            >
              <AccordionSummary
                expandIcon={<ExpandMoreIcon />}
                sx={{
                  '&:hover': { bgcolor: 'action.hover' }
                }}
              >
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: '100%' }}>
                  <Chip
                    label={`#${hypothesis.hypothesis_id}`}
                    size="small"
                    color="primary"
                  />
                  <Typography variant="subtitle2" sx={{ flexGrow: 1, fontWeight: 'medium' }}>
                    {hypothesis.hypothesis_name}
                  </Typography>
                  <Chip
                    label={hypothesis.confidence}
                    size="small"
                    color={
                      hypothesis.confidence === 'HIGH' ? 'error' :
                      hypothesis.confidence === 'MEDIUM' ? 'warning' : 'info'
                    }
                    variant="outlined"
                  />
                  <Chip
                    label={`Priority: ${hypothesis.priority}`}
                    size="small"
                    variant="outlined"
                  />
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Box>
                  <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.8 }}>
                    {hypothesis.hypothesis_description}
                  </Typography>
                  <Divider sx={{ my: 2 }} />
                  <Typography variant="subtitle2" gutterBottom fontWeight="medium">
                    Detection Platform: <Chip label={hypothesis.detection_platform} size="small" sx={{ ml: 1 }} />
                  </Typography>
                  <Paper sx={{
                    p: 2,
                    bgcolor: theme.palette.mode === 'dark' ? '#2d2d2d' : 'grey.100',
                    mb: 2,
                    borderRadius: 1
                  }}>
                    <Typography
                      variant="body2"
                      sx={{
                        fontFamily: 'monospace',
                        whiteSpace: 'pre-wrap',
                        fontSize: '0.85rem'
                      }}
                    >
                      {hypothesis.executable_query}
                    </Typography>
                  </Paper>
                  <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                    <Typography variant="body2" color="text.secondary">
                      <strong>Timeline:</strong> {hypothesis.hunt_timeline}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      <strong>Success Criteria:</strong> {hypothesis.success_criteria}
                    </Typography>
                  </Box>
                </Box>
              </AccordionDetails>
            </Accordion>
          ))}
        </Paper>
      )}

      {/* Extracted IOCs with Detection Rate Visualization */}
      {data.extracted_iocs && data.extracted_iocs.length > 0 && (
        <Paper elevation={2} sx={{ p: 3, mb: 3, borderRadius: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <FlagIcon sx={{ mr: 1, color: 'primary.main' }} />
            <Typography variant="h6" fontWeight="bold">
              Extracted IOCs
            </Typography>
          </Box>

          {/* Detection Rate Chart */}
          {detectionData.length > 0 && (
            <Card sx={{ mb: 3, bgcolor: 'background.default' }}>
              <CardContent>
                <Typography variant="subtitle2" gutterBottom color="text.secondary">
                  Top 5 IOC Detection Rates
                </Typography>
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={detectionData}>
                    <XAxis
                      dataKey="indicator"
                      angle={-45}
                      textAnchor="end"
                      height={80}
                      style={{ fontSize: '11px' }}
                    />
                    <YAxis
                      label={{
                        value: 'Detection Rate (%)',
                        angle: -90,
                        position: 'insideLeft',
                        style: { fontSize: '12px' }
                      }}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: theme.palette.background.paper,
                        border: `1px solid ${theme.palette.divider}`,
                        borderRadius: '4px'
                      }}
                      content={({ active, payload }) => {
                        if (active && payload && payload.length) {
                          const data = payload[0].payload;
                          return (
                            <Paper sx={{ p: 1.5 }} elevation={3}>
                              <Typography variant="caption" display="block" fontWeight="medium">
                                {data.indicator}
                              </Typography>
                              <Typography variant="caption" display="block" color="text.secondary">
                                Detection: {data.detected}/{data.total} ({data.rate}%)
                              </Typography>
                            </Paper>
                          );
                        }
                        return null;
                      }}
                    />
                    <Bar dataKey="rate" radius={[4, 4, 0, 0]}>
                      {detectionData.map((entry, index) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={entry.rate > 80 ? '#f44336' : entry.rate > 50 ? '#ff9800' : '#4caf50'}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          )}

          {/* IOC Table */}
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: 'action.hover' }}>
                  <TableCell><strong>Indicator</strong></TableCell>
                  <TableCell><strong>Type</strong></TableCell>
                  <TableCell><strong>Confidence</strong></TableCell>
                  <TableCell><strong>Detections</strong></TableCell>
                  <TableCell><strong>Action</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.extracted_iocs.map((ioc, index) => (
                  <TableRow
                    key={index}
                    hover
                    sx={{ '&:hover': { bgcolor: 'action.hover' } }}
                  >
                    <TableCell
                      sx={{
                        fontFamily: 'monospace',
                        fontSize: '0.875rem',
                        maxWidth: '300px',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap'
                      }}
                    >
                      {ioc.indicator}
                    </TableCell>
                    <TableCell>
                      <Chip label={ioc.ioc_type} size="small" variant="outlined" />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={ioc.confidence}
                        size="small"
                        color={
                          ioc.confidence === 'HIGH' ? 'error' :
                          ioc.confidence === 'MEDIUM' ? 'warning' : 'info'
                        }
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                      {ioc.detections}
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={ioc.recommended_action}
                        size="small"
                        color={
                          ioc.recommended_action === 'block' ? 'error' :
                          ioc.recommended_action === 'investigate' ? 'warning' : 'info'
                        }
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      )}

      {/* Recommended Actions */}
      {data.recommended_actions && data.recommended_actions.length > 0 && (
        <Paper elevation={2} sx={{ p: 3, mb: 3, borderRadius: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <RecommendIcon sx={{ mr: 1, color: 'primary.main' }} />
            <Typography variant="h6" fontWeight="bold">
              Recommended Actions
            </Typography>
          </Box>
          <List>
            {data.recommended_actions.map((action, index) => (
              <ListItem key={index} sx={{ py: 0.5 }}>
                <ListItemText
                  primary={`${index + 1}. ${action}`}
                  primaryTypographyProps={{ variant: 'body2' }}
                />
              </ListItem>
            ))}
          </List>
        </Paper>
      )}

      {/* Intelligence Gaps */}
      {data.intelligence_gaps && data.intelligence_gaps.length > 0 && (
        <Paper elevation={2} sx={{ p: 3, mb: 3, borderRadius: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <HelpOutlineIcon sx={{ mr: 1, color: 'warning.main' }} />
            <Typography variant="h6" fontWeight="bold">
              Intelligence Gaps
            </Typography>
          </Box>
          <List>
            {data.intelligence_gaps.map((gap, index) => (
              <ListItem key={index} sx={{ py: 0.5 }}>
                <ListItemText
                  primary={gap}
                  primaryTypographyProps={{ variant: 'body2' }}
                />
              </ListItem>
            ))}
          </List>
        </Paper>
      )}

      {/* Organizational Impact */}
      {data.organizational_impact && (
        <Paper elevation={2} sx={{ p: 3, borderRadius: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <BusinessIcon sx={{ mr: 1, color: 'primary.main' }} />
            <Typography variant="h6" fontWeight="bold">
              Organizational Impact
            </Typography>
          </Box>
          <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap', lineHeight: 1.8 }}>
            {data.organizational_impact}
          </Typography>
        </Paper>
      )}
    </Box>
  );
};

export default CampaignIntelligenceSection;
