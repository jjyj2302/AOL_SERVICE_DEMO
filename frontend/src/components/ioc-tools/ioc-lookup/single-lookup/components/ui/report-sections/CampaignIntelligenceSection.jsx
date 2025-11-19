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
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Grid,
  Card,
  CardContent,
  LinearProgress,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import GavelIcon from '@mui/icons-material/Gavel';
import PersonSearchIcon from '@mui/icons-material/PersonSearch';
import SearchIcon from '@mui/icons-material/Search';
import FlagIcon from '@mui/icons-material/Flag';
import BugReportIcon from '@mui/icons-material/BugReport';
import RecommendIcon from '@mui/icons-material/Recommend';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import BusinessIcon from '@mui/icons-material/Business';
import CampaignIcon from '@mui/icons-material/Campaign';
import ShieldIcon from '@mui/icons-material/Shield';
import TimelineIcon from '@mui/icons-material/Timeline';
import { RadialBarChart, RadialBar, PolarAngleAxis, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell, PieChart, Pie } from 'recharts';
import { useTheme } from '@mui/material/styles';

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
      {/* Executive Summary - Hero Section */}
      <Paper
        sx={{
          p: 4,
          mb: 3,
          background: data.threat_level === 'CRITICAL' || data.threat_level === 'HIGH'
            ? 'linear-gradient(135deg, #f44336 0%, #c62828 100%)'
            : data.threat_level === 'MEDIUM'
            ? 'linear-gradient(135deg, #ff9800 0%, #f57c00 100%)'
            : 'linear-gradient(135deg, #4caf50 0%, #388e3c 100%)',
          color: 'white',
          borderRadius: 2,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
          <CampaignIcon sx={{ fontSize: 48 }} />
          <Box>
            <Typography variant="h6" sx={{ opacity: 0.9, fontFamily: 'inherit' }}>
              Campaign Intelligence
            </Typography>
            <Typography variant="h2" sx={{ fontWeight: 700, fontFamily: 'inherit', textTransform: 'uppercase' }}>
              {data.campaign_name}
            </Typography>
          </Box>
        </Box>

        <Divider sx={{ my: 2, bgcolor: 'rgba(255,255,255,0.3)' }} />

        <Grid container spacing={3}>
          {/* Left: Summary */}
          <Grid item xs={12} md={8}>
            <Box
              sx={{
                p: 3,
                bgcolor: 'rgba(255,255,255,0.15)',
                borderRadius: 2,
                border: '1px solid rgba(255,255,255,0.3)',
                mb: 2,
              }}
            >
              <Typography variant="body1" sx={{ lineHeight: 1.8, fontFamily: 'inherit' }}>
                {data.executive_summary}
              </Typography>
            </Box>

            <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
              <Chip
                icon={<ShieldIcon />}
                label={`Threat Level: ${data.threat_level}`}
                sx={{
                  bgcolor: 'rgba(255,255,255,0.2)',
                  color: 'white',
                  fontSize: '1rem',
                  fontWeight: 600,
                  fontFamily: 'inherit',
                }}
              />
              <Chip
                icon={<FlagIcon />}
                label={`Confidence: ${data.campaign_confidence}`}
                sx={{
                  bgcolor: 'rgba(255,255,255,0.2)',
                  color: 'white',
                  fontSize: '1rem',
                  fontWeight: 600,
                  fontFamily: 'inherit',
                }}
              />
            </Box>
          </Grid>

          {/* Right: Threat Score Gauge */}
          <Grid item xs={12} md={4}>
            <Card sx={{ bgcolor: 'rgba(255,255,255,0.15)', border: '1px solid rgba(255,255,255,0.3)', height: '100%' }}>
              <CardContent sx={{ textAlign: 'center' }}>
                <Typography variant="subtitle2" gutterBottom sx={{ color: 'white', opacity: 0.9 }}>
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
                      background={{ fill: 'rgba(255,255,255,0.2)' }}
                      dataKey="value"
                      cornerRadius={10}
                      fill="white"
                    />
                    <text
                      x="50%"
                      y="50%"
                      textAnchor="middle"
                      dominantBaseline="middle"
                      style={{
                        fontSize: '28px',
                        fontWeight: 'bold',
                        fill: 'white'
                      }}
                    >
                      {threatScore}
                    </text>
                  </RadialBarChart>
                </ResponsiveContainer>
                <Typography variant="caption" sx={{ color: 'white', opacity: 0.9 }}>
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
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <SearchIcon sx={{ fontSize: 32 }} color="info" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              캠페인 근거
            </Typography>
          </Box>
          <Paper
            sx={{
              p: 3,
              background: 'linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%)',
              border: '2px solid',
              borderColor: 'info.light',
              borderRadius: 2,
            }}
          >
            <Grid container spacing={2}>
              {data.campaign_evidence.map((evidence, index) => (
                <Grid item xs={12} key={index}>
                  <Card
                    sx={{
                      bgcolor: 'white',
                      '&:hover': {
                        boxShadow: 3,
                        transform: 'translateX(4px)',
                        transition: 'all 0.2s',
                      },
                    }}
                  >
                    <CardContent sx={{ p: 2 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                        <Box
                          sx={{
                            minWidth: 32,
                            height: 32,
                            borderRadius: '50%',
                            bgcolor: 'info.main',
                            color: 'white',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            fontWeight: 700,
                          }}
                        >
                          {index + 1}
                        </Box>
                        <Typography variant="body2" sx={{ flex: 1, lineHeight: 1.7 }}>
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

      {/* MITRE ATT&CK Tactics with Visualization */}
      {data.mitre_tactics && data.mitre_tactics.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <GavelIcon sx={{ fontSize: 32 }} color="secondary" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              MITRE ATT&CK Tactics
            </Typography>
          </Box>
          <Paper
            sx={{
              p: 3,
              background: 'linear-gradient(135deg, #f3e5f5 0%, #e1bee7 100%)',
              border: '2px solid',
              borderColor: 'secondary.light',
              borderRadius: 2,
            }}
          >

            {/* MITRE Technique Distribution Chart */}
            {mitreData.length > 0 && (
              <Card
                sx={{
                  mb: 3,
                  background: 'linear-gradient(135deg, #ffffff 0%, #f5f5f5 100%)',
                  boxShadow: 3,
                  border: '1px solid',
                  borderColor: 'secondary.light',
                }}
              >
                <CardContent sx={{ p: 3 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 3 }}>
                    <Box
                      sx={{
                        width: 4,
                        height: 24,
                        bgcolor: 'secondary.main',
                        borderRadius: 1,
                      }}
                    />
                    <Typography variant="h6" sx={{ fontWeight: 700, color: 'secondary.main' }}>
                      Technique Distribution
                    </Typography>
                  </Box>
                  <ResponsiveContainer width="100%" height={mitreData.length * 60 + 40}>
                    <BarChart
                      data={mitreData}
                      layout="vertical"
                      margin={{ top: 5, right: 30, left: 10, bottom: 5 }}
                    >
                      <defs>
                        {mitreData.map((entry, index) => (
                          <linearGradient key={`gradient-${index}`} id={`colorGradient${index}`} x1="0" y1="0" x2="1" y2="0">
                            <stop offset="0%" stopColor={
                              index % 5 === 0 ? '#9c27b0' :
                              index % 5 === 1 ? '#673ab7' :
                              index % 5 === 2 ? '#3f51b5' :
                              index % 5 === 3 ? '#2196f3' : '#00bcd4'
                            } stopOpacity={0.9} />
                            <stop offset="100%" stopColor={
                              index % 5 === 0 ? '#7b1fa2' :
                              index % 5 === 1 ? '#512da8' :
                              index % 5 === 2 ? '#303f9f' :
                              index % 5 === 3 ? '#1976d2' : '#0097a7'
                            } stopOpacity={1} />
                          </linearGradient>
                        ))}
                      </defs>
                      <XAxis
                        type="number"
                        tick={{ fontSize: 13, fontWeight: 600, fill: '#666' }}
                        axisLine={{ stroke: '#e0e0e0', strokeWidth: 2 }}
                      />
                      <YAxis
                        dataKey="technique"
                        type="category"
                        width={110}
                        tick={{ fontSize: 13, fontWeight: 700, fill: '#424242' }}
                        axisLine={{ stroke: '#e0e0e0', strokeWidth: 2 }}
                      />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: 'rgba(255, 255, 255, 0.98)',
                          border: '2px solid #9c27b0',
                          borderRadius: '8px',
                          boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
                        }}
                        labelStyle={{
                          fontWeight: 700,
                          fontSize: '14px',
                          color: '#9c27b0',
                          marginBottom: '4px',
                        }}
                        itemStyle={{
                          fontWeight: 600,
                          fontSize: '13px',
                          color: '#424242',
                        }}
                        cursor={{ fill: 'rgba(156, 39, 176, 0.1)' }}
                      />
                      <Bar
                        dataKey="count"
                        radius={[0, 8, 8, 0]}
                        barSize={35}
                        label={{
                          position: 'right',
                          fill: '#424242',
                          fontWeight: 700,
                          fontSize: 14,
                        }}
                      >
                        {mitreData.map((entry, index) => (
                          <Cell
                            key={`cell-${index}`}
                            fill={`url(#colorGradient${index})`}
                            stroke={
                              index % 5 === 0 ? '#7b1fa2' :
                              index % 5 === 1 ? '#512da8' :
                              index % 5 === 2 ? '#303f9f' :
                              index % 5 === 3 ? '#1976d2' : '#0097a7'
                            }
                            strokeWidth={2}
                          />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            )}

            {/* Tactic Details */}
            <Grid container spacing={2}>
              {data.mitre_tactics.map((tactic, index) => (
                <Grid item xs={12} key={index}>
                  <Card
                    sx={{
                      bgcolor: 'white',
                      '&:hover': {
                        boxShadow: 3,
                        transform: 'translateY(-2px)',
                        transition: 'all 0.2s',
                      },
                    }}
                  >
                    <CardContent sx={{ p: 2.5 }}>
                      <Typography variant="subtitle1" fontWeight="bold" sx={{ mb: 1.5, color: 'secondary.main' }}>
                        {tactic.tactic}
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 0.5, mb: 2, flexWrap: 'wrap' }}>
                        {tactic.techniques && tactic.techniques.map((technique, idx) => (
                          <Chip
                            key={idx}
                            label={technique}
                            size="small"
                            color="secondary"
                            variant="outlined"
                            sx={{ fontWeight: 500 }}
                          />
                        ))}
                      </Box>
                      <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
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
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <TimelineIcon sx={{ fontSize: 32 }} color="warning" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              공격 체인 TTPs
            </Typography>
          </Box>
          <Paper
            sx={{
              p: 3,
              background: 'linear-gradient(135deg, #fff3e0 0%, #ffe0b2 100%)',
              border: '2px solid',
              borderColor: 'warning.light',
              borderRadius: 2,
            }}
          >
            <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap', lineHeight: 1.8 }}>
              {data.attack_chain_ttps}
            </Typography>
          </Paper>
        </Box>
      )}

      {/* Threat Actor Attribution */}
      {data.threat_actor_attribution && (
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <PersonSearchIcon sx={{ fontSize: 32 }} color="error" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              위협 행위자 추정
            </Typography>
          </Box>
          <Paper
            sx={{
              p: 3,
              background: 'linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%)',
              border: '2px solid',
              borderColor: 'error.light',
              borderRadius: 2,
            }}
          >
            <Box sx={{ mb: 3, display: 'flex', gap: 1.5, flexWrap: 'wrap' }}>
              {data.threat_actor_attribution.attributed_actor && (
                <Chip
                  icon={<PersonSearchIcon />}
                  label={data.threat_actor_attribution.attributed_actor}
                  color="error"
                  sx={{ fontWeight: 600, fontSize: '1rem' }}
                />
              )}
              <Chip
                icon={<FlagIcon />}
                label={`Confidence: ${data.threat_actor_attribution.confidence}`}
                color={
                  data.threat_actor_attribution.confidence === 'HIGH' ? 'error' :
                  data.threat_actor_attribution.confidence === 'MEDIUM' ? 'warning' : 'info'
                }
                sx={{ fontWeight: 600, fontSize: '1rem' }}
              />
            </Box>
            {data.threat_actor_attribution.overlap_indicators && data.threat_actor_attribution.overlap_indicators.length > 0 && (
              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600, mb: 1.5 }}>
                  Overlap Indicators
                </Typography>
                <Grid container spacing={1}>
                  {data.threat_actor_attribution.overlap_indicators.map((indicator, index) => (
                    <Grid item xs={12} key={index}>
                      <Card sx={{ bgcolor: 'white' }}>
                        <CardContent sx={{ p: 2 }}>
                          <Typography variant="body2">• {indicator}</Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              </Box>
            )}
            {data.threat_actor_attribution.attribution_rationale && (
              <Box sx={{ mt: 2, p: 3, bgcolor: 'white', borderRadius: 1, borderLeft: '4px solid', borderColor: 'error.main' }}>
                <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
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
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <BugReportIcon sx={{ fontSize: 32 }} color="primary" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              헌트 가설
            </Typography>
          </Box>
          <Paper
            sx={{
              p: 3,
              background: 'linear-gradient(135deg, #e0f2f1 0%, #b2dfdb 100%)',
              border: '2px solid',
              borderColor: 'primary.light',
              borderRadius: 2,
            }}
          >
            {data.hunt_hypotheses.map((hypothesis, index) => (
              <Accordion
                key={index}
                sx={{
                  mb: 2,
                  '&:before': { display: 'none' },
                  bgcolor: 'white',
                  boxShadow: 2,
                  '&:hover': {
                    boxShadow: 4,
                  },
                }}
              >
                <AccordionSummary
                  expandIcon={<ExpandMoreIcon />}
                  sx={{
                    bgcolor: 'rgba(0, 150, 136, 0.08)',
                    '&:hover': { bgcolor: 'rgba(0, 150, 136, 0.12)' },
                  }}
                >
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, width: '100%', flexWrap: 'wrap' }}>
                    <Chip
                      label={`#${hypothesis.hypothesis_id}`}
                      size="small"
                      sx={{ bgcolor: 'primary.main', color: 'white', fontWeight: 600 }}
                    />
                    <Typography variant="subtitle1" sx={{ flexGrow: 1, fontWeight: 600 }}>
                      {hypothesis.hypothesis_name}
                    </Typography>
                    <Chip
                      label={hypothesis.confidence}
                      size="small"
                      color={
                        hypothesis.confidence === 'HIGH' ? 'error' :
                        hypothesis.confidence === 'MEDIUM' ? 'warning' : 'info'
                      }
                      sx={{ fontWeight: 600 }}
                    />
                    <Chip
                      label={`Priority: ${hypothesis.priority}`}
                      size="small"
                      color="primary"
                      variant="outlined"
                      sx={{ fontWeight: 600 }}
                    />
                  </Box>
                </AccordionSummary>
                <AccordionDetails sx={{ p: 3 }}>
                  <Box>
                    <Typography variant="body2" sx={{ mb: 3, lineHeight: 1.8 }}>
                      {hypothesis.hypothesis_description}
                    </Typography>
                    <Divider sx={{ my: 2 }} />
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="subtitle2" gutterBottom fontWeight="medium" sx={{ mb: 1 }}>
                        Detection Platform
                      </Typography>
                      <Chip
                        label={hypothesis.detection_platform}
                        size="small"
                        color="primary"
                        sx={{ fontWeight: 600 }}
                      />
                    </Box>
                    <Box sx={{ mb: 3 }}>
                      <Typography variant="subtitle2" gutterBottom fontWeight="medium" sx={{ mb: 1 }}>
                        Executable Query
                      </Typography>
                      <Paper
                        sx={{
                          p: 2,
                          bgcolor: 'grey.900',
                          borderRadius: 1,
                          border: '1px solid',
                          borderColor: 'grey.300',
                        }}
                      >
                        <Typography
                          variant="body2"
                          sx={{
                            fontFamily: 'monospace',
                            whiteSpace: 'pre-wrap',
                            fontSize: '0.85rem',
                            color: '#00ff00',
                          }}
                        >
                          {hypothesis.executable_query}
                        </Typography>
                      </Paper>
                    </Box>
                    <Grid container spacing={2}>
                      <Grid item xs={12} md={6}>
                        <Card sx={{ bgcolor: 'rgba(33, 150, 243, 0.08)', border: '1px solid', borderColor: 'primary.light' }}>
                          <CardContent sx={{ p: 2 }}>
                            <Typography variant="caption" sx={{ fontWeight: 600, color: 'primary.main' }}>
                              Timeline
                            </Typography>
                            <Typography variant="body2" sx={{ mt: 0.5 }}>
                              {hypothesis.hunt_timeline}
                            </Typography>
                          </CardContent>
                        </Card>
                      </Grid>
                      <Grid item xs={12} md={6}>
                        <Card sx={{ bgcolor: 'rgba(76, 175, 80, 0.08)', border: '1px solid', borderColor: 'success.light' }}>
                          <CardContent sx={{ p: 2 }}>
                            <Typography variant="caption" sx={{ fontWeight: 600, color: 'success.main' }}>
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

      {/* Extracted IOCs with Detection Rate Visualization */}
      {data.extracted_iocs && data.extracted_iocs.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <FlagIcon sx={{ fontSize: 32 }} color="error" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              추출된 IOC 목록
            </Typography>
          </Box>
          <Paper
            sx={{
              p: 3,
              background: 'linear-gradient(135deg, #fce4ec 0%, #f8bbd0 100%)',
              border: '2px solid',
              borderColor: 'error.light',
              borderRadius: 2,
            }}
          >

            {/* Detection Rate Chart */}
            {detectionData.length > 0 && (
              <Card
                sx={{
                  mb: 3,
                  background: 'linear-gradient(135deg, #ffffff 0%, #fef5f5 100%)',
                  boxShadow: 3,
                  border: '1px solid',
                  borderColor: 'error.light',
                }}
              >
                <CardContent sx={{ p: 3 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 3 }}>
                    <Box
                      sx={{
                        width: 4,
                        height: 24,
                        bgcolor: 'error.main',
                        borderRadius: 1,
                      }}
                    />
                    <Typography variant="h6" sx={{ fontWeight: 700, color: 'error.main' }}>
                      Top 5 IOC Detection Rates
                    </Typography>
                  </Box>
                  <Grid container spacing={3}>
                    {/* Bar Chart */}
                    <Grid item xs={12} md={7}>
                      <ResponsiveContainer width="100%" height={400}>
                        <BarChart
                          data={detectionData}
                          margin={{ top: 20, right: 10, left: 10, bottom: 60 }}
                        >
                          <defs>
                            {detectionData.map((entry, index) => (
                              <linearGradient key={`gradient-${index}`} id={`detectionGradient${index}`} x1="0" y1="0" x2="0" y2="1">
                                <stop
                                  offset="0%"
                                  stopColor={entry.rate > 80 ? '#f44336' : entry.rate > 50 ? '#ff9800' : '#4caf50'}
                                  stopOpacity={1}
                                />
                                <stop
                                  offset="100%"
                                  stopColor={entry.rate > 80 ? '#c62828' : entry.rate > 50 ? '#f57c00' : '#388e3c'}
                                  stopOpacity={0.9}
                                />
                              </linearGradient>
                            ))}
                          </defs>
                          <XAxis
                            dataKey="indicator"
                            angle={0}
                            textAnchor="middle"
                            height={60}
                            tick={{ fontSize: 11, fontWeight: 600, fill: '#424242' }}
                            axisLine={{ stroke: '#e0e0e0', strokeWidth: 2 }}
                            interval={0}
                          />
                          <YAxis
                            label={{
                              value: 'Detection Rate (%)',
                              angle: -90,
                              position: 'insideLeft',
                              style: { fontSize: 13, fontWeight: 700, fill: '#424242' }
                            }}
                            tick={{ fontSize: 13, fontWeight: 600, fill: '#666' }}
                            axisLine={{ stroke: '#e0e0e0', strokeWidth: 2 }}
                            domain={[0, 100]}
                          />
                          <Tooltip
                            contentStyle={{
                              backgroundColor: 'rgba(255, 255, 255, 0.98)',
                              border: '2px solid #f44336',
                              borderRadius: '8px',
                              boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
                              padding: '12px',
                            }}
                            content={({ active, payload }) => {
                              if (active && payload && payload.length) {
                                const data = payload[0].payload;
                                return (
                                  <Box sx={{ p: 1 }}>
                                    <Typography variant="body2" sx={{ fontWeight: 700, color: 'error.main', mb: 0.5 }}>
                                      {data.indicator}
                                    </Typography>
                                    <Typography variant="body2" sx={{ fontWeight: 600, color: 'text.primary' }}>
                                      Detection: {data.detected}/{data.total}
                                    </Typography>
                                    <Typography variant="body2" sx={{ fontWeight: 700, color: 'error.main', mt: 0.5 }}>
                                      Rate: {data.rate}%
                                    </Typography>
                                  </Box>
                                );
                              }
                              return null;
                            }}
                            cursor={{ fill: 'rgba(244, 67, 54, 0.1)' }}
                          />
                          <Bar
                            dataKey="rate"
                            radius={[8, 8, 0, 0]}
                            maxBarSize={60}
                            label={{
                              position: 'top',
                              fill: '#424242',
                              fontWeight: 700,
                              fontSize: 13,
                              formatter: (value) => `${value}%`
                            }}
                          >
                            {detectionData.map((entry, index) => (
                              <Cell
                                key={`cell-${index}`}
                                fill={`url(#detectionGradient${index})`}
                                stroke={entry.rate > 80 ? '#c62828' : entry.rate > 50 ? '#f57c00' : '#388e3c'}
                                strokeWidth={2}
                              />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </Grid>

                    {/* Pie Chart */}
                    <Grid item xs={12} md={5}>
                      <Box sx={{ height: 400, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
                        <ResponsiveContainer width="100%" height="100%">
                          <PieChart>
                            <defs>
                              {detectionData.map((entry, index) => (
                                <linearGradient key={`pieGradient-${index}`} id={`pieGradient${index}`} x1="0" y1="0" x2="1" y2="1">
                                  <stop
                                    offset="0%"
                                    stopColor={entry.rate > 80 ? '#f44336' : entry.rate > 50 ? '#ff9800' : '#4caf50'}
                                    stopOpacity={1}
                                  />
                                  <stop
                                    offset="100%"
                                    stopColor={entry.rate > 80 ? '#c62828' : entry.rate > 50 ? '#f57c00' : '#388e3c'}
                                    stopOpacity={0.8}
                                  />
                                </linearGradient>
                              ))}
                            </defs>
                            <Pie
                              data={detectionData}
                              cx="50%"
                              cy="50%"
                              labelLine={{
                                stroke: '#666',
                                strokeWidth: 1,
                              }}
                              label={({ indicator, rate }) => `${indicator.slice(0, 8)}... (${rate}%)`}
                              outerRadius={120}
                              innerRadius={60}
                              paddingAngle={3}
                              dataKey="rate"
                            >
                              {detectionData.map((entry, index) => (
                                <Cell
                                  key={`pie-cell-${index}`}
                                  fill={`url(#pieGradient${index})`}
                                  stroke={entry.rate > 80 ? '#c62828' : entry.rate > 50 ? '#f57c00' : '#388e3c'}
                                  strokeWidth={3}
                                />
                              ))}
                            </Pie>
                            <Tooltip
                              contentStyle={{
                                backgroundColor: 'rgba(255, 255, 255, 0.98)',
                                border: '2px solid #f44336',
                                borderRadius: '8px',
                                boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
                                padding: '12px',
                              }}
                              content={({ active, payload }) => {
                                if (active && payload && payload.length) {
                                  const data = payload[0].payload;
                                  return (
                                    <Box sx={{ p: 1 }}>
                                      <Typography variant="body2" sx={{ fontWeight: 700, color: 'error.main', mb: 0.5 }}>
                                        {data.indicator}
                                      </Typography>
                                      <Typography variant="body2" sx={{ fontWeight: 600, color: 'text.primary' }}>
                                        Detection: {data.detected}/{data.total}
                                      </Typography>
                                      <Typography variant="body2" sx={{ fontWeight: 700, color: 'error.main', mt: 0.5 }}>
                                        Rate: {data.rate}%
                                      </Typography>
                                    </Box>
                                  );
                                }
                                return null;
                              }}
                            />
                          </PieChart>
                        </ResponsiveContainer>
                        <Typography
                          variant="body2"
                          sx={{
                            textAlign: 'center',
                            mt: 2,
                            fontWeight: 600,
                            color: 'text.secondary',
                          }}
                        >
                          Detection Rate Distribution
                        </Typography>
                      </Box>
                    </Grid>
                  </Grid>
                </CardContent>
              </Card>
            )}

            {/* IOC Table */}
            <TableContainer sx={{ bgcolor: 'white', borderRadius: 1 }}>
              <Table>
                <TableHead>
                  <TableRow sx={{ bgcolor: 'rgba(244, 67, 54, 0.1)' }}>
                    <TableCell sx={{ fontWeight: 700, fontSize: '0.95rem' }}>Indicator</TableCell>
                    <TableCell sx={{ fontWeight: 700, fontSize: '0.95rem' }}>Type</TableCell>
                    <TableCell sx={{ fontWeight: 700, fontSize: '0.95rem' }}>Confidence</TableCell>
                    <TableCell sx={{ fontWeight: 700, fontSize: '0.95rem' }}>Detections</TableCell>
                    <TableCell sx={{ fontWeight: 700, fontSize: '0.95rem' }}>Action</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {data.extracted_iocs.map((ioc, index) => (
                    <TableRow
                      key={index}
                      sx={{
                        '&:hover': {
                          bgcolor: 'rgba(244, 67, 54, 0.05)',
                          transform: 'scale(1.01)',
                          transition: 'all 0.2s',
                        },
                      }}
                    >
                      <TableCell
                        sx={{
                          fontFamily: 'monospace',
                          fontSize: '0.9rem',
                          fontWeight: 600,
                          color: 'error.dark',
                          maxWidth: '300px',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {ioc.indicator}
                      </TableCell>
                      <TableCell>
                        <Chip label={ioc.ioc_type} size="small" color="primary" />
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={ioc.confidence}
                          size="small"
                          color={
                            ioc.confidence === 'HIGH' ? 'error' :
                            ioc.confidence === 'MEDIUM' ? 'warning' : 'info'
                          }
                        />
                      </TableCell>
                      <TableCell>
                        <DetectionGauge detections={ioc.detections} />
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={ioc.recommended_action}
                          size="small"
                          color={
                            ioc.recommended_action === 'block' ? 'error' :
                            ioc.recommended_action === 'investigate' ? 'warning' : 'info'
                          }
                          sx={{ fontWeight: 600 }}
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

      {/* Recommended Actions */}
      {data.recommended_actions && data.recommended_actions.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <RecommendIcon sx={{ fontSize: 32 }} color="success" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              권장 조치
            </Typography>
          </Box>
          <Paper
            sx={{
              p: 3,
              background: 'linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%)',
              border: '2px solid',
              borderColor: 'success.light',
              borderRadius: 2,
            }}
          >
            <Grid container spacing={2}>
              {data.recommended_actions.map((action, index) => (
                <Grid item xs={12} key={index}>
                  <Card
                    sx={{
                      bgcolor: 'white',
                      '&:hover': {
                        boxShadow: 3,
                        transform: 'translateX(4px)',
                        transition: 'all 0.2s',
                      },
                    }}
                  >
                    <CardContent sx={{ p: 2 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                        <Box
                          sx={{
                            minWidth: 32,
                            height: 32,
                            borderRadius: '50%',
                            bgcolor: 'success.main',
                            color: 'white',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            fontWeight: 700,
                          }}
                        >
                          {index + 1}
                        </Box>
                        <Typography variant="body2" sx={{ flex: 1, lineHeight: 1.7 }}>
                          {action}
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

      {/* Intelligence Gaps */}
      {data.intelligence_gaps && data.intelligence_gaps.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <HelpOutlineIcon sx={{ fontSize: 32 }} color="warning" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              인텔리전스 갭
            </Typography>
          </Box>
          <Paper
            sx={{
              p: 3,
              background: 'linear-gradient(135deg, #fff8e1 0%, #ffecb3 100%)',
              border: '2px solid',
              borderColor: 'warning.light',
              borderRadius: 2,
            }}
          >
            <Grid container spacing={2}>
              {data.intelligence_gaps.map((gap, index) => (
                <Grid item xs={12} key={index}>
                  <Card
                    sx={{
                      bgcolor: 'white',
                      borderLeft: '4px solid',
                      borderColor: 'warning.main',
                      '&:hover': {
                        boxShadow: 3,
                        transform: 'translateX(4px)',
                        transition: 'all 0.2s',
                      },
                    }}
                  >
                    <CardContent sx={{ p: 2 }}>
                      <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                        • {gap}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </Box>
      )}

      {/* Organizational Impact */}
      {data.organizational_impact && (
        <Paper
          sx={{
            p: 4,
            background: 'linear-gradient(135deg, #f3e5f5 0%, #e1bee7 100%)',
            border: '2px solid',
            borderColor: 'secondary.light',
            borderRadius: 2,
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 3 }}>
            <BusinessIcon sx={{ fontSize: 32 }} color="secondary" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              조직 영향 평가
            </Typography>
          </Box>
          <Box
            sx={{
              p: 3,
              bgcolor: 'white',
              borderRadius: 2,
              borderLeft: '6px solid',
              borderColor: 'secondary.main',
            }}
          >
            <Typography
              variant="body1"
              sx={{
                whiteSpace: 'pre-wrap',
                lineHeight: 2,
                fontFamily: 'inherit',
                fontSize: '1rem',
              }}
            >
              {data.organizational_impact}
            </Typography>
          </Box>
        </Paper>
      )}
    </Box>
  );
};

export default CampaignIntelligenceSection;
