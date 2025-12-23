import React from 'react';
import {
  Box,
  Paper,
  Typography,
  Chip,
  Divider,
  Grid,
  Card,
  CardContent,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  LinearProgress,
  CircularProgress,
  useTheme,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import GavelIcon from '@mui/icons-material/Gavel';
import PersonSearchIcon from '@mui/icons-material/PersonSearch';
import SearchIcon from '@mui/icons-material/Search';
import FlagIcon from '@mui/icons-material/Flag';
import BugReportIcon from '@mui/icons-material/BugReport';
import CampaignIcon from '@mui/icons-material/Campaign';
import ShieldIcon from '@mui/icons-material/Shield';
import TimelineIcon from '@mui/icons-material/Timeline';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell, RadialBarChart, RadialBar, Legend } from 'recharts';

// Apple-style Color Palette
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

const DetectionGauge = ({ detections }) => {
  if (!detections || typeof detections !== 'string') return null;

  const [detected, total] = detections.split('/').map(Number);
  if (isNaN(detected) || isNaN(total) || total === 0) return detections;

  const percentage = (detected / total) * 100;

  const getColor = () => {
    if (percentage >= 50) return COLORS.HIGH;
    if (percentage >= 20) return COLORS.MEDIUM;
    return COLORS.LOW;
  };

  return (
    <Box sx={{ minWidth: 120 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 0.5 }}>
        <Typography variant="body2" sx={{ fontFamily: 'monospace', fontWeight: 700 }}>
          {detected}/{total}
        </Typography>
        <Typography variant="caption" sx={{ fontWeight: 600, color: getColor() }}>
          {percentage.toFixed(0)}%
        </Typography>
      </Box>
      <LinearProgress
        variant="determinate"
        value={percentage}
        sx={{
          height: 6,
          borderRadius: 3,
          bgcolor: '#E5E5EA',
          '& .MuiLinearProgress-bar': {
            bgcolor: getColor(),
            borderRadius: 3,
          }
        }}
      />
    </Box>
  );
};

const CampaignIntelligenceSection = ({ data }) => {
  const theme = useTheme();
  const isDarkMode = theme.palette.mode === 'dark';

  if (!data) return null;

  const cardStyle = {
    bgcolor: isDarkMode ? 'rgba(28, 28, 30, 0.6)' : COLORS.CARD_BG_LIGHT,
    borderRadius: '18px',
    border: isDarkMode ? '1px solid rgba(255,255,255,0.1)' : `1px solid ${COLORS.BORDER_LIGHT}`,
    boxShadow: isDarkMode ? 'none' : '0 4px 24px rgba(0,0,0,0.02)',
    height: '100%',
    transition: 'transform 0.2s ease-in-out',
    '&:hover': {
      transform: 'translateY(-2px)',
      boxShadow: isDarkMode ? '0 8px 32px rgba(0,0,0,0.4)' : '0 8px 32px rgba(0,0,0,0.06)',
    }
  };

  const sectionTitleStyle = {
    fontWeight: 600,
    mb: 2,
    display: 'flex',
    alignItems: 'center',
    gap: 1,
    color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY,
    fontSize: '1.1rem'
  };

  // Threat Level Score Calculation
  const getThreatScore = (level) => {
    const scores = { 'CRITICAL': 100, 'HIGH': 75, 'MEDIUM': 50, 'LOW': 25, 'INFO': 10 };
    return scores[level] || 0;
  };
  const threatScore = getThreatScore(data.threat_level);


  // MITRE Data
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
    return Object.entries(techniqueCount).map(([technique, count]) => ({ technique, count }));
  };
  const mitreData = getMitreTechniqueData();

  // Detection Data
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
    <Box sx={{ fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif' }}>
      {/* Executive Summary - Hero Section */}
      <Paper sx={{ ...cardStyle, p: 4, mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
          <CampaignIcon sx={{ fontSize: 48, color: COLORS.PRIMARY }} />
          <Box>
            <Typography variant="h6" sx={{ opacity: 0.9, color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY }}>
              Campaign Intelligence
            </Typography>
            <Typography variant="h2" sx={{ fontWeight: 700, textTransform: 'uppercase', color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
              {data.campaign_name}
            </Typography>
          </Box>
        </Box>

        <Divider sx={{ my: 2, bgcolor: isDarkMode ? 'rgba(255,255,255,0.1)' : COLORS.BORDER_LIGHT }} />

        <Grid container spacing={3}>
          {/* Left: Summary */}
          <Grid item xs={12} md={8}>
            <Box sx={{ p: 3, bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '12px', mb: 2 }}>
              <Typography variant="body1" sx={{ lineHeight: 1.8, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
                {data.executive_summary}
              </Typography>
            </Box>

            <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
              <Chip
                icon={<ShieldIcon />}
                label={`Threat Level: ${data.threat_level}`}
                sx={{ bgcolor: isDarkMode ? 'rgba(255,255,255,0.1)' : '#F2F2F7', color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY, fontWeight: 600 }}
              />
              <Chip
                icon={<FlagIcon />}
                label={`Confidence: ${data.campaign_confidence}`}
                sx={{ bgcolor: isDarkMode ? 'rgba(255,255,255,0.1)' : '#F2F2F7', color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY, fontWeight: 600 }}
              />
            </Box>
          </Grid>

          {/* Right: Threat Score Gauge */}
          <Grid item xs={12} md={4}>
            <Card elevation={0} sx={{ bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '18px', height: '100%' }}>
              <CardContent sx={{ textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
                <Typography variant="subtitle2" gutterBottom sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontWeight: 600, mb: 2 }}>
                  Threat Level Score
                </Typography>
                <Box sx={{ position: 'relative', display: 'inline-flex' }}>
                  <CircularProgress
                    variant="determinate"
                    value={100}
                    size={120}
                    thickness={4}
                    sx={{ color: isDarkMode ? 'rgba(255,255,255,0.1)' : '#E5E5EA' }}
                  />
                  <CircularProgress
                    variant="determinate"
                    value={threatScore}
                    size={120}
                    thickness={4}
                    sx={{
                      color: COLORS[data.threat_level] || COLORS.UNKNOWN,
                      position: 'absolute',
                      left: 0,
                      [`& .MuiCircularProgress-circle`]: {
                        strokeLinecap: 'round',
                      },
                    }}
                  />
                  <Box
                    sx={{
                      top: 0,
                      left: 0,
                      bottom: 0,
                      right: 0,
                      position: 'absolute',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    <Typography variant="h4" component="div" sx={{ color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY, fontWeight: 700 }}>
                      {threatScore}
                    </Typography>
                  </Box>
                </Box>
                <Typography variant="caption" sx={{ mt: 2, color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontWeight: 500 }}>
                  Risk Assessment (0-100)
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Paper>

      {/* Campaign Evidence */}
      {data.campaign_evidence && data.campaign_evidence.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Typography sx={{ ...sectionTitleStyle, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
            <SearchIcon fontSize="small" sx={{ color: COLORS.PRIMARY }} /> 캠페인 근거
          </Typography>
          <Paper sx={{ ...cardStyle, p: 3 }}>
            <Grid container spacing={2}>
              {data.campaign_evidence.map((evidence, index) => (
                <Grid item xs={12} key={index}>
                  <Card elevation={0} sx={{ bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F5F5F7', borderRadius: '8px' }}>
                    <CardContent sx={{ p: 2 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                        <Box
                          sx={{
                            minWidth: 28, height: 28, borderRadius: '50%',
                            bgcolor: COLORS.PRIMARY, color: 'white',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            fontWeight: 700, fontSize: '0.9rem'
                          }}
                        >
                          {index + 1}
                        </Box>
                        <Typography variant="body2" sx={{ flex: 1, lineHeight: 1.7, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
                          {evidence}
                        </Typography>
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </Box>
      )}

      {/* MITRE ATT&CK Tactics */}
      {data.mitre_tactics && data.mitre_tactics.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Typography sx={{ ...sectionTitleStyle, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
            <GavelIcon fontSize="small" sx={{ color: COLORS.MEDIUM }} /> MITRE ATT&CK Tactics
          </Typography>
          <Paper sx={{ ...cardStyle, p: 3 }}>
            {/* MITRE Technique Distribution Chart */}
            {mitreData.length > 0 && (
              <Card elevation={0} sx={{ mb: 3, bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '12px' }}>
                <CardContent sx={{ p: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY, mb: 3 }}>
                    Technique Distribution
                  </Typography>
                  <Box sx={{ height: 400, width: '100%', display: 'flex', justifyContent: 'center' }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <RadialBarChart
                        cx="50%"
                        cy="50%"
                        innerRadius="20%"
                        outerRadius="90%"
                        barSize={20}
                        data={mitreData.map((item, index) => ({
                          ...item,
                          fill: [COLORS.PRIMARY, COLORS.MEDIUM, COLORS.LOW, COLORS.CRITICAL, COLORS.UNKNOWN][index % 5]
                        })).sort((a, b) => b.count - a.count)}
                      >
                        <RadialBar
                          minAngle={15}
                          label={{ position: 'insideStart', fill: '#fff', fontSize: '10px', fontWeight: 'bold' }}
                          background
                          clockWise
                          dataKey="count"
                          cornerRadius={10}
                        />
                        <Legend
                          iconSize={10}
                          layout="vertical"
                          verticalAlign="middle"
                          wrapperStyle={{ right: 0, top: '50%', transform: 'translateY(-50%)' }}
                          formatter={(value) => <span style={{ color: isDarkMode ? '#ccc' : COLORS.TEXT_PRIMARY, fontSize: '0.85rem', fontWeight: 500 }}>{value}</span>}
                        />
                        <Tooltip
                          cursor={{ fill: 'transparent' }}
                          contentStyle={{
                            backgroundColor: isDarkMode ? '#333' : '#fff',
                            border: 'none',
                            borderRadius: '8px',
                            boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
                            color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY
                          }}
                          itemStyle={{ color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}
                        />
                      </RadialBarChart>
                    </ResponsiveContainer>
                  </Box>
                </CardContent>
              </Card>
            )}

            {/* Tactic Details */}
            <Grid container spacing={2}>
              {data.mitre_tactics.map((tactic, index) => (
                <Grid item xs={12} key={index}>
                  <Card elevation={0} sx={{ bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F5F5F7', borderRadius: '8px' }}>
                    <CardContent sx={{ p: 2.5 }}>
                      <Typography variant="subtitle1" fontWeight="bold" sx={{ mb: 1.5, color: COLORS.MEDIUM }}>
                        {tactic.tactic}
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 0.5, mb: 2, flexWrap: 'wrap' }}>
                        {tactic.techniques && tactic.techniques.map((technique, idx) => (
                          <Chip
                            key={idx}
                            label={technique}
                            size="small"
                            sx={{ bgcolor: 'rgba(255, 149, 0, 0.1)', color: COLORS.MEDIUM, fontWeight: 500 }}
                          />
                        ))}
                      </Box>
                      <Typography variant="body2" sx={{ lineHeight: 1.7, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
                        {tactic.evidence}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </Box>
      )}

      {/* Attack Chain TTPs */}
      {data.attack_chain_ttps && (
        <Box sx={{ mb: 3 }}>
          <Typography sx={sectionTitleStyle}>
            <TimelineIcon fontSize="small" sx={{ color: COLORS.MEDIUM }} /> 공격 체인 TTPs
          </Typography>
          <Paper sx={{ ...cardStyle, p: 3 }}>
            <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap', lineHeight: 1.8, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
              {data.attack_chain_ttps}
            </Typography>
          </Paper>
        </Box>
      )}

      {/* Threat Actor Attribution */}
      {data.threat_actor_attribution && (
        <Box sx={{ mb: 3 }}>
          <Typography sx={sectionTitleStyle}>
            <PersonSearchIcon fontSize="small" sx={{ color: COLORS.HIGH }} /> 위협 행위자 추정
          </Typography>
          <Paper sx={{ ...cardStyle, p: 3 }}>
            <Box sx={{ mb: 3, display: 'flex', gap: 1.5, flexWrap: 'wrap' }}>
              {data.threat_actor_attribution.attributed_actor && (
                <Chip
                  icon={<PersonSearchIcon />}
                  label={data.threat_actor_attribution.attributed_actor}
                  sx={{ bgcolor: 'rgba(255, 59, 48, 0.1)', color: COLORS.HIGH, fontWeight: 600 }}
                />
              )}
              <Chip
                icon={<FlagIcon />}
                label={`Confidence: ${data.threat_actor_attribution.confidence}`}
                sx={{ bgcolor: 'rgba(255, 59, 48, 0.1)', color: COLORS.HIGH, fontWeight: 600 }}
              />
            </Box>
            {data.threat_actor_attribution.overlap_indicators && data.threat_actor_attribution.overlap_indicators.length > 0 && (
              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600, mb: 1.5, color: isDarkMode ? '#ccc' : COLORS.TEXT_SECONDARY }}>
                  Overlap Indicators
                </Typography>
                <Grid container spacing={1}>
                  {data.threat_actor_attribution.overlap_indicators.map((indicator, index) => (
                    <Grid item xs={12} key={index}>
                      <Card elevation={0} sx={{ bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F5F5F7', borderRadius: '8px' }}>
                        <CardContent sx={{ p: 2 }}>
                          <Typography variant="body2" sx={{ color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>• {indicator}</Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              </Box>
            )}
            {data.threat_actor_attribution.attribution_rationale && (
              <Box sx={{ mt: 2, p: 3, bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '12px', borderLeft: `4px solid ${COLORS.HIGH}` }}>
                <Typography variant="body2" sx={{ lineHeight: 1.7, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
                  <strong>Attribution Rationale:</strong> {data.threat_actor_attribution.attribution_rationale}
                </Typography>
              </Box>
            )}
          </Paper>
        </Box>
      )}

      {/* Hunt Hypotheses */}
      {data.hunt_hypotheses && data.hunt_hypotheses.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Typography sx={sectionTitleStyle}>
            <BugReportIcon fontSize="small" sx={{ color: COLORS.PRIMARY }} /> 헌트 가설
          </Typography>
          <Paper sx={{ ...cardStyle, p: 3 }}>
            {data.hunt_hypotheses.map((hypothesis, index) => (
              <Accordion
                key={index}
                elevation={0}
                sx={{
                  mb: 2,
                  '&:before': { display: 'none' },
                  bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9',
                  borderRadius: '12px !important',
                  border: `1px solid ${isDarkMode ? 'rgba(255,255,255,0.1)' : '#E5E5EA'}`,
                }}
              >
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, width: '100%', flexWrap: 'wrap' }}>
                    <Chip
                      label={`#${hypothesis.hypothesis_id}`}
                      size="small"
                      sx={{ bgcolor: COLORS.PRIMARY, color: 'white', fontWeight: 600 }}
                    />
                    <Typography variant="subtitle1" sx={{ flexGrow: 1, fontWeight: 600, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
                      {hypothesis.hypothesis_name}
                    </Typography>
                    <Chip
                      label={hypothesis.confidence}
                      size="small"
                      sx={{
                        bgcolor: isDarkMode ? 'rgba(255,255,255,0.1)' : '#E5E5EA',
                        color: hypothesis.confidence === 'HIGH' ? COLORS.HIGH : hypothesis.confidence === 'MEDIUM' ? COLORS.MEDIUM : COLORS.LOW,
                        fontWeight: 600
                      }}
                    />
                  </Box>
                </AccordionSummary>
                <AccordionDetails sx={{ p: 3 }}>
                  <Box>
                    <Typography variant="body2" sx={{ mb: 3, lineHeight: 1.8, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
                      {hypothesis.hypothesis_description}
                    </Typography>
                    <Divider sx={{ my: 2 }} />
                    <Grid container spacing={2}>
                      <Grid item xs={12} md={6}>
                        <Card elevation={0} sx={{ bgcolor: 'rgba(0, 122, 255, 0.05)', border: `1px solid ${COLORS.PRIMARY}` }}>
                          <CardContent sx={{ p: 2 }}>
                            <Typography variant="caption" sx={{ fontWeight: 600, color: COLORS.PRIMARY }}>
                              Timeline
                            </Typography>
                            <Typography variant="body2" sx={{ mt: 0.5 }}>
                              {hypothesis.hunt_timeline}
                            </Typography>
                          </CardContent>
                        </Card>
                      </Grid>
                      <Grid item xs={12} md={6}>
                        <Card elevation={0} sx={{ bgcolor: 'rgba(52, 199, 89, 0.05)', border: `1px solid ${COLORS.LOW}` }}>
                          <CardContent sx={{ p: 2 }}>
                            <Typography variant="caption" sx={{ fontWeight: 600, color: COLORS.LOW }}>
                              Success Criteria
                            </Typography>
                            <Typography variant="body2" sx={{ mt: 0.5 }}>
                              {hypothesis.success_criteria}
                            </Typography>
                          </CardContent>
                        </Card>
                      </Grid>
                    </Grid>
                  </Box>
                </AccordionDetails>
              </Accordion>
            ))}
          </Paper>
        </Box>
      )}

      {/* Extracted IOCs */}
      {data.extracted_iocs && data.extracted_iocs.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Typography sx={sectionTitleStyle}>
            <FlagIcon fontSize="small" sx={{ color: COLORS.HIGH }} /> 추출된 IOC 목록
          </Typography>
          <Paper sx={{ ...cardStyle, p: 3 }}>
            {/* Detection Rate Chart */}
            {detectionData.length > 0 && (
              <Card elevation={0} sx={{ mb: 3, bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '12px' }}>
                <CardContent sx={{ p: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: COLORS.HIGH, mb: 3 }}>
                    Top 5 IOC Detection Rates
                  </Typography>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart
                      data={detectionData}
                      layout="vertical"
                      margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                    >
                      <XAxis type="number" hide />
                      <YAxis
                        dataKey="indicator"
                        type="category"
                        width={180}
                        tick={{ fontSize: 11, fill: isDarkMode ? '#ccc' : COLORS.TEXT_PRIMARY }}
                        axisLine={false}
                        tickLine={false}
                      />
                      <Tooltip
                        cursor={{ fill: 'transparent' }}
                        contentStyle={{
                          backgroundColor: isDarkMode ? '#333' : '#fff',
                          border: 'none',
                          borderRadius: '8px',
                          boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
                          color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY
                        }}
                        itemStyle={{ color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}
                      />
                      <Bar dataKey="rate" barSize={20} shape={(props) => {
                        const { x, y, width, height, fill } = props;
                        return (
                          <g>
                            <line x1={x} y1={y + height / 2} x2={x + width} y2={y + height / 2} stroke={fill} strokeWidth={2} />
                            <circle cx={x + width} cy={y + height / 2} r={6} fill={fill} />
                          </g>
                        );
                      }}>
                        {detectionData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.rate > 50 ? COLORS.HIGH : entry.rate > 20 ? COLORS.MEDIUM : COLORS.LOW} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            )}

            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow sx={{ bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F5F5F7' }}>
                    <TableCell sx={{ fontWeight: 600, color: COLORS.TEXT_SECONDARY }}>Indicator</TableCell>
                    <TableCell sx={{ fontWeight: 600, color: COLORS.TEXT_SECONDARY }}>Type</TableCell>
                    <TableCell sx={{ fontWeight: 600, color: COLORS.TEXT_SECONDARY }}>Confidence</TableCell>
                    <TableCell sx={{ fontWeight: 600, color: COLORS.TEXT_SECONDARY }}>Detections</TableCell>
                    <TableCell sx={{ fontWeight: 600, color: COLORS.TEXT_SECONDARY }}>Action</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {data.extracted_iocs.map((ioc, index) => (
                    <TableRow key={index} hover>
                      <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.9rem', fontWeight: 600, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
                        {ioc.indicator}
                      </TableCell>
                      <TableCell>
                        <Chip label={ioc.ioc_type} size="small" sx={{ bgcolor: 'rgba(0, 122, 255, 0.1)', color: COLORS.PRIMARY }} />
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={ioc.confidence}
                          size="small"
                          sx={{
                            bgcolor: isDarkMode ? 'rgba(255,255,255,0.1)' : '#F2F2F7',
                            color: ioc.confidence === 'HIGH' ? COLORS.HIGH : ioc.confidence === 'MEDIUM' ? COLORS.MEDIUM : COLORS.LOW
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
                          sx={{
                            bgcolor: ioc.recommended_action === 'block' ? 'rgba(255, 59, 48, 0.1)' : 'rgba(0, 122, 255, 0.1)',
                            color: ioc.recommended_action === 'block' ? COLORS.HIGH : COLORS.PRIMARY,
                            fontWeight: 600
                          }}
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </Box>
      )}
    </Box>
  );
};

export default CampaignIntelligenceSection;
