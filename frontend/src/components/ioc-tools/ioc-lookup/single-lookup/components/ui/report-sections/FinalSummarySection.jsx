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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Alert,
  Button,
} from '@mui/material';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';
import SummarizeIcon from '@mui/icons-material/Summarize';
import AssessmentIcon from '@mui/icons-material/Assessment';
import BugReportIcon from '@mui/icons-material/BugReport';
import SecurityIcon from '@mui/icons-material/Security';
import CampaignIcon from '@mui/icons-material/Campaign';
import GpsFixedIcon from '@mui/icons-material/GpsFixed';
import SearchIcon from '@mui/icons-material/Search';
import WarningIcon from '@mui/icons-material/Warning';
import InfoIcon from '@mui/icons-material/Info';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import PictureAsPdfIcon from '@mui/icons-material/PictureAsPdf';
import PrintIcon from '@mui/icons-material/Print';

const COLORS = {
  HIGH: '#f44336',
  MEDIUM: '#ff9800',
  LOW: '#4caf50',
  UNKNOWN: '#9e9e9e',
  CRITICAL: '#d32f2f',
};

const THREAT_LEVEL_COLORS = {
  CRITICAL: '#d32f2f',
  HIGH: '#f44336',
  MEDIUM: '#ff9800',
  LOW: '#4caf50',
  UNKNOWN: '#9e9e9e',
};

export default function FinalSummarySection({ data }) {
  if (!data) return null;

  // Debug: Log the data structure
  console.log('[FinalSummarySection] Received data:', data);
  console.log('[FinalSummarySection] Data keys:', Object.keys(data));

  // Campaign data can be in two places:
  // 1. data.full_analysis.campaign (from structured summary)
  // 2. data directly (when campaign report is passed directly as final_report)
  const campaignData = data.full_analysis?.campaign || data;
  console.log('[FinalSummarySection] Campaign data keys:', Object.keys(campaignData));

  // Prepare visualization data
  const confidenceData = data.visualization_data?.ioc_confidence_distribution || {};
  const confidencePieData = Object.entries(confidenceData).map(([key, value]) => ({
    name: key,
    value: value
  }));

  const mitreData = data.visualization_data?.mitre_coverage || {};
  const mitreBarData = Object.entries(mitreData).map(([tactic, count]) => ({
    tactic: tactic.length > 15 ? tactic.substring(0, 15) + '...' : tactic,
    fullTactic: tactic,
    count: count
  }));

  const handlePdfExport = () => {
    // TODO: Implement PDF export functionality
    console.log('PDF Export clicked from Final Summary');
    alert('PDF 내보내기 기능은 곧 추가됩니다!');
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <Paper
      elevation={0}
      sx={{
        mt: 3,
        p: 4,
        background: (theme) => theme.palette.mode === 'dark'
          ? 'rgba(30, 30,30, 0.6)'
          : 'rgba(255, 255, 255, 0.8)',
        backdropFilter: 'blur(20px)',
        border: (theme) => `1px solid ${theme.palette.divider}`,
        borderRadius: '24px',
        boxShadow: (theme) => theme.palette.mode === 'dark'
          ? '0 8px 32px rgba(0, 0, 0, 0.3)'
          : '0 8px 32px rgba(0, 0, 0, 0.04)',
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3, flexWrap: 'wrap', gap: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <SummarizeIcon sx={{ fontSize: 40, color: 'text.primary' }} />
          <Typography variant="h4" sx={{ fontWeight: 700 }}>
            Final Summary
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            variant="outlined"
            startIcon={<PictureAsPdfIcon />}
            onClick={handlePdfExport}
            sx={{
              borderRadius: "12px",
              textTransform: "none",
              fontWeight: 600
            }}
          >
            PDF 저장
          </Button>
          <Button
            variant="outlined"
            startIcon={<PrintIcon />}
            onClick={handlePrint}
            sx={{
              borderRadius: "12px",
              textTransform: "none",
              fontWeight: 600
            }}
          >
            인쇄
          </Button>
        </Box>
      </Box>

      <Divider sx={{ my: 2 }} />

      {/* Threat Level & Campaign Name */}
      {(campaignData.threat_level || campaignData.campaign_name) && (
        <Box sx={{ mb: 3 }}>
          <Grid container spacing={2}>
            {campaignData.threat_level && (
              <Grid item xs={12} md={6}>
                <Card elevation={0} sx={{ bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.02)', border: (theme) => `1px solid ${theme.palette.divider}`, borderRadius: '16px', height: '100%' }}>
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                      <WarningIcon sx={{ fontSize: 32, color: THREAT_LEVEL_COLORS[campaignData.threat_level] || COLORS.UNKNOWN }} />
                      <Typography variant="h6" sx={{ fontWeight: 600 }}>
                        위협 수준
                      </Typography>
                    </Box>
                    <Typography variant="h3" sx={{ fontWeight: 700, color: THREAT_LEVEL_COLORS[campaignData.threat_level] || COLORS.UNKNOWN }}>
                      {campaignData.threat_level}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            )}
            {campaignData.campaign_name && (
              <Grid item xs={12} md={6}>
                <Card elevation={0} sx={{ bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.02)', border: (theme) => `1px solid ${theme.palette.divider}`, borderRadius: '16px', height: '100%' }}>
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                      <CampaignIcon sx={{ fontSize: 32, color: 'text.secondary' }} />
                      <Typography variant="h6" sx={{ fontWeight: 600 }}>
                        캠페인 이름
                      </Typography>
                    </Box>
                    <Typography variant="h5" sx={{ fontWeight: 700 }}>
                      {campaignData.campaign_name}
                    </Typography>
                    {campaignData.campaign_confidence && (
                      <Chip
                        label={`Confidence: ${campaignData.campaign_confidence}`}
                        sx={{ mt: 1, bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.06)', borderRadius: '12px', fontWeight: 600 }}
                      />
                    )}
                  </CardContent>
                </Card>
              </Grid>
            )}
          </Grid>
        </Box>
      )}

      {/* Executive Summary */}
      {(data.executive_summary || campaignData.executive_summary) && (
        <Box
          sx={{
            p: 3,
            bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.03)' : 'rgba(0, 0, 0, 0.02)',
            borderRadius: '16px',
            border: (theme) => `1px solid ${theme.palette.divider}`,
            mb: 3,
          }}
        >
          <Typography variant="h6" sx={{ mb: 2, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
            <InfoIcon sx={{ color: 'text.secondary' }} /> Executive Summary
          </Typography>
          <Typography
            variant="body1"
            sx={{
              whiteSpace: 'pre-wrap',
              lineHeight: 2,
              fontFamily: 'inherit',
              fontSize: '1rem',
            }}
          >
            {data.executive_summary || campaignData.executive_summary}
          </Typography>
        </Box>
      )}

      {/* Campaign Evidence */}
      {campaignData.campaign_evidence && campaignData.campaign_evidence.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Typography variant="h6" sx={{ mb: 2, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
            <GpsFixedIcon sx={{ color: 'text.secondary' }} /> 캠페인 증거
          </Typography>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            {campaignData.campaign_evidence.map((evidence, index) => (
              <Card key={index} elevation={0} sx={{ bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.03)' : 'rgba(0, 0, 0, 0.02)', border: (theme) => `1px solid ${theme.palette.divider}`, borderRadius: '12px' }}>
                <CardContent sx={{ p: 2 }}>
                  <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
                    <Box
                      sx={{
                        minWidth: 32,
                        height: 32,
                        borderRadius: '50%',
                        bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.06)',
                        color: 'text.primary',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontWeight: 700,
                      }}
                    >
                      {index + 1}
                    </Box>
                    <Typography variant="body1" sx={{ flex: 1, lineHeight: 1.8, color: 'text.primary' }}>
                      {evidence}
                    </Typography>
                  </Box>
                </CardContent>
              </Card>
            ))}
          </Box>
        </Box>
      )}

      {/* Statistics Cards */}
      {data.statistics && (
        <Box sx={{ mb: 4 }}>
          <Typography variant="h6" sx={{ mb: 2, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
            <AssessmentIcon /> 주요 통계
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ p: 2, bgcolor: 'rgba(255,255,255,0.2)', borderRadius: 2, textAlign: 'center' }}>
                <Typography variant="h3" sx={{ fontWeight: 700, mb: 1 }}>
                  {data.statistics.total_iocs_found}
                </Typography>
                <Typography variant="body2" sx={{ opacity: 0.9 }}>
                  총 IOC 발견
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ p: 2, bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.02)', border: (theme) => `1px solid ${theme.palette.divider}`, borderRadius: '12px', textAlign: 'center' }}>
                <Typography variant="h3" sx={{ fontWeight: 700, mb: 1 }}>
                  {data.statistics.high_confidence_iocs}
                </Typography>
                <Typography variant="body2" sx={{ opacity: 0.7 }}>
                  고신뢰도 IOC
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ p: 2, bgcolor: 'rgba(255,255,255,0.2)', borderRadius: 2, textAlign: 'center' }}>
                <Typography variant="h3" sx={{ fontWeight: 700, mb: 1 }}>
                  {data.statistics.detection_rate_average}%
                </Typography>
                <Typography variant="body2" sx={{ opacity: 0.9 }}>
                  평균 탐지율
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ p: 2, bgcolor: 'rgba(255,255,255,0.2)', borderRadius: 2, textAlign: 'center' }}>
                <Typography variant="h3" sx={{ fontWeight: 700, mb: 1 }}>
                  {data.statistics.malicious_infrastructure_count}
                </Typography>
                <Typography variant="body2" sx={{ opacity: 0.9 }}>
                  악성 인프라
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ p: 2, bgcolor: 'rgba(255,255,255,0.2)', borderRadius: 2, textAlign: 'center' }}>
                <Typography variant="h3" sx={{ fontWeight: 700, mb: 1 }}>
                  {data.statistics.total_mitre_techniques}
                </Typography>
                <Typography variant="body2" sx={{ opacity: 0.9 }}>
                  MITRE 기법
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ p: 2, bgcolor: 'rgba(255,255,255,0.2)', borderRadius: 2, textAlign: 'center' }}>
                <Typography variant="h3" sx={{ fontWeight: 700, mb: 1 }}>
                  {data.statistics.campaign_clusters}
                </Typography>
                <Typography variant="body2" sx={{ opacity: 0.9 }}>
                  캠페인 클러스터
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ p: 2, bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.02)', border: (theme) => `1px solid ${theme.palette.divider}`, borderRadius: '12px', textAlign: 'center' }}>
                <Typography variant="h3" sx={{ fontWeight: 700, mb: 1 }}>
                  {data.statistics.medium_confidence_iocs}
                </Typography>
                <Typography variant="body2" sx={{ opacity: 0.7 }}>
                  중신뢰도 IOC
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ p: 2, bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.02)', border: (theme) => `1px solid ${theme.palette.divider}`, borderRadius: '12px', textAlign: 'center' }}>
                <Typography variant="h3" sx={{ fontWeight: 700, mb: 1 }}>
                  {data.statistics.low_confidence_iocs}
                </Typography>
                <Typography variant="body2" sx={{ opacity: 0.7 }}>
                  저신뢰도 IOC
                </Typography>
              </Box>
            </Grid>
          </Grid>
        </Box>
      )}

      {/* MITRE ATT&CK Tactics with Techniques */}
      {campaignData.mitre_tactics && campaignData.mitre_tactics.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Typography variant="h6" sx={{ mb: 2, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
            <SecurityIcon sx={{ color: 'text.secondary' }} /> MITRE ATT&CK Tactics
          </Typography>
          <Grid container spacing={2}>
            {campaignData.mitre_tactics.map((tactic, index) => (
              <Grid item xs={12} md={6} key={index}>
                <Card elevation={0} sx={{ bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.03)' : 'rgba(0, 0, 0, 0.02)', border: (theme) => `1px solid ${theme.palette.divider}`, borderRadius: '12px', height: '100%' }}>
                  <CardContent>
                    <Typography variant="h6" sx={{ color: 'text.primary', fontWeight: 600, mb: 1 }}>
                      {tactic.tactic}
                    </Typography>
                    {tactic.techniques && tactic.techniques.length > 0 && (
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="subtitle2" sx={{ color: 'text.secondary', mb: 1 }}>
                          Techniques:
                        </Typography>
                        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                          {tactic.techniques.map((tech, idx) => (
                            <Chip
                              key={idx}
                              label={tech}
                              size="small"
                              sx={{ bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.06)', fontWeight: 600, borderRadius: '8px' }}
                            />
                          ))}
                        </Box>
                      </Box>
                    )}
                    {tactic.evidence && (
                      <Box sx={{ p: 2, bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.03)' : 'rgba(0, 0, 0, 0.02)', borderRadius: '8px', mt: 1 }}>
                        <Typography variant="body2" sx={{ color: 'text.secondary', lineHeight: 1.6 }}>
                          <strong>Evidence:</strong> {tactic.evidence}
                        </Typography>
                      </Box>
                    )}
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

      {/* Attack Chain TTPs */}
      {campaignData.attack_chain_ttps && (
        <Box sx={{ mb: 3 }}>
          <Typography variant="h6" sx={{ mb: 2, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
            <TrendingUpIcon sx={{ color: 'text.secondary' }} /> Attack Chain TTPs
          </Typography>
          <Box
            sx={{
              p: 3,
              bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.03)' : 'rgba(0, 0, 0, 0.02)',
              borderRadius: '16px',
              border: (theme) => `1px solid ${theme.palette.divider}`,
            }}
          >
            <Typography variant="body1" sx={{ lineHeight: 2, whiteSpace: 'pre-wrap' }}>
              {campaignData.attack_chain_ttps}
            </Typography>
          </Box>
        </Box>
      )}

      {/* Threat Actor Attribution */}
      {campaignData.threat_actor_attribution && (
        <Box sx={{ mb: 3 }}>
          <Typography variant="h6" sx={{ mb: 2, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
            <BugReportIcon sx={{ color: 'text.secondary' }} /> Threat Actor Attribution
          </Typography>
          <Card elevation={0} sx={{ bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.03)' : 'rgba(0, 0, 0, 0.02)', border: (theme) => `1px solid ${theme.palette.divider}`, borderRadius: '12px' }}>
            <CardContent>
              <Grid container spacing={2}>
                {campaignData.threat_actor_attribution.attributed_actor && (
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ color: 'text.secondary', mb: 0.5 }}>
                      Attributed Actor:
                    </Typography>
                    <Typography variant="h6" sx={{ color: 'text.primary', fontWeight: 600 }}>
                      {campaignData.threat_actor_attribution.attributed_actor}
                    </Typography>
                  </Grid>
                )}
                {campaignData.threat_actor_attribution.confidence && (
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ color: 'text.secondary', mb: 0.5 }}>
                      Confidence:
                    </Typography>
                    <Chip
                      label={campaignData.threat_actor_attribution.confidence}
                      sx={{
                        bgcolor: COLORS[campaignData.threat_actor_attribution.confidence] || COLORS.UNKNOWN,
                        color: 'white',
                        fontWeight: 600,
                      }}
                    />
                  </Grid>
                )}
                {campaignData.threat_actor_attribution.overlap_indicators && campaignData.threat_actor_attribution.overlap_indicators.length > 0 && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle2" sx={{ color: 'text.secondary', mb: 1 }}>
                      Overlap Indicators:
                    </Typography>
                    <Box component="ul" sx={{ m: 0, pl: 3 }}>
                      {campaignData.threat_actor_attribution.overlap_indicators.map((indicator, idx) => (
                        <li key={idx}>
                          <Typography variant="body2" sx={{ color: 'text.primary', lineHeight: 1.8 }}>
                            {indicator}
                          </Typography>
                        </li>
                      ))}
                    </Box>
                  </Grid>
                )}
                {campaignData.threat_actor_attribution.attribution_rationale && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle2" sx={{ color: 'text.secondary', mb: 1 }}>
                      Attribution Rationale:
                    </Typography>
                    <Box sx={{ p: 2, bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.03)' : 'rgba(0, 0, 0, 0.02)', borderRadius: '8px' }}>
                      <Typography variant="body2" sx={{ color: 'text.primary', lineHeight: 1.8 }}>
                        {campaignData.threat_actor_attribution.attribution_rationale}
                      </Typography>
                    </Box>
                  </Grid>
                )}
              </Grid>
            </CardContent>
          </Card>
        </Box>
      )}

      {/* Visualization Section */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {/* IOC Confidence Distribution Pie Chart */}
        {confidencePieData.length > 0 && (
          <Grid item xs={12} md={6}>
            <Card sx={{ bgcolor: 'rgba(255,255,255,0.15)', border: '1px solid rgba(255,255,255,0.3)' }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ color: 'white', fontWeight: 600 }}>
                  IOC 신뢰도 분포
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={confidencePieData}
                      cx="50%"
                      cy="50%"
                      labelLine={true}
                      label={({ name, value }) => `${name}: ${value}`}
                      outerRadius={100}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {confidencePieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[entry.name] || COLORS.UNKNOWN} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: '#333', border: 'none', borderRadius: '4px', color: 'white' }} />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>
        )}

        {/* MITRE ATT&CK Coverage Bar Chart */}
        {mitreBarData.length > 0 && (
          <Grid item xs={12} md={6}>
            <Card sx={{ bgcolor: 'rgba(255,255,255,0.15)', border: '1px solid rgba(255,255,255,0.3)' }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ color: 'white', fontWeight: 600 }}>
                  MITRE ATT&CK 커버리지
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={mitreBarData}>
                    <XAxis dataKey="tactic" tick={{ fill: 'white', fontSize: 11 }} angle={-45} textAnchor="end" height={80} />
                    <YAxis tick={{ fill: 'white' }} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#333', border: 'none', borderRadius: '4px' }}
                      content={({ active, payload }) => {
                        if (active && payload && payload.length) {
                          return (
                            <Box sx={{ bgcolor: '#333', p: 1.5, borderRadius: 1, color: 'white' }}>
                              <Typography variant="body2" sx={{ fontWeight: 600 }}>
                                {payload[0].payload.fullTactic}
                              </Typography>
                              <Typography variant="body2">
                                Count: {payload[0].value}
                              </Typography>
                            </Box>
                          );
                        }
                        return null;
                      }}
                    />
                    <Bar dataKey="count" fill="#9c27b0" radius={[8, 8, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>
        )}
      </Grid>

      {/* Extracted IOCs Table */}
      {campaignData.extracted_iocs && campaignData.extracted_iocs.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Typography variant="h6" sx={{ mb: 2, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
            <SecurityIcon /> 추출된 IOC 목록 ({campaignData.extracted_iocs.length}개)
          </Typography>
          <TableContainer sx={{ bgcolor: 'rgba(255,255,255,0.1)', borderRadius: 1, maxHeight: 600 }}>
            <Table stickyHeader>
              <TableHead>
                <TableRow>
                  <TableCell sx={{ bgcolor: 'rgba(0,0,0,0.3)', color: 'white', fontWeight: 700 }}>Indicator</TableCell>
                  <TableCell sx={{ bgcolor: 'rgba(0,0,0,0.3)', color: 'white', fontWeight: 700 }}>Type</TableCell>
                  <TableCell sx={{ bgcolor: 'rgba(0,0,0,0.3)', color: 'white', fontWeight: 700 }}>Confidence</TableCell>
                  <TableCell sx={{ bgcolor: 'rgba(0,0,0,0.3)', color: 'white', fontWeight: 700 }}>Detections</TableCell>
                  <TableCell sx={{ bgcolor: 'rgba(0,0,0,0.3)', color: 'white', fontWeight: 700 }}>First Seen</TableCell>
                  <TableCell sx={{ bgcolor: 'rgba(0,0,0,0.3)', color: 'white', fontWeight: 700 }}>Action</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {campaignData.extracted_iocs.map((ioc, index) => (
                  <TableRow key={index} sx={{ '&:hover': { bgcolor: 'rgba(255,255,255,0.1)' } }}>
                    <TableCell sx={{ color: (theme) => theme.palette.mode === 'dark' ? 'white' : 'rgba(0,0,0,0.7)', fontFamily: 'monospace', fontSize: '0.85rem', maxWidth: 300, wordBreak: 'break-all' }}>
                      {ioc.indicator}
                    </TableCell>
                    <TableCell>
                      <Chip label={ioc.ioc_type} size="small" sx={{ bgcolor: 'rgba(255,255,255,0.2)', color: (theme) => theme.palette.mode === 'dark' ? 'white' : 'rgba(0,0,0,0.7)' }} />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={ioc.confidence}
                        size="small"
                        sx={{
                          bgcolor: ioc.confidence?.includes('HIGH') ? COLORS.HIGH :
                            ioc.confidence?.includes('MEDIUM') ? COLORS.MEDIUM :
                              ioc.confidence?.includes('LOW') ? COLORS.LOW : COLORS.UNKNOWN,
                          color: 'rgba(0,0,0,0.7)',
                          fontWeight: 600
                        }}
                      />
                    </TableCell>
                    <TableCell sx={{ color: (theme) => theme.palette.mode === 'dark' ? 'white' : 'rgba(0,0,0,0.7)' }}>
                      {ioc.detections || 'N/A'}
                    </TableCell>
                    <TableCell sx={{ color: (theme) => theme.palette.mode === 'dark' ? 'white' : 'rgba(0,0,0,0.7)', fontSize: '0.85rem' }}>
                      {ioc.first_seen ? new Date(ioc.first_seen).toLocaleDateString() : 'N/A'}
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={ioc.recommended_action}
                        size="small"
                        sx={{
                          bgcolor: ioc.recommended_action === 'block' ? '#d32f2f' :
                            ioc.recommended_action === 'investigate' ? '#ff9800' : 'rgba(255,255,255,0.2)',
                          color: 'rgba(0,0,0,0.7)',
                          fontWeight: 600
                        }}
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
          {campaignData.extracted_iocs.length > 50 && (
            <Typography variant="caption" sx={{ mt: 1, display: 'block', opacity: 0.8 }}>
              모든 {campaignData.extracted_iocs.length}개의 IOC가 표시됩니다
            </Typography>
          )}
        </Box>
      )}

      {/* Hunt Hypotheses */}
      {campaignData.hunt_hypotheses && campaignData.hunt_hypotheses.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Typography variant="h6" sx={{ mb: 2, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
            <SearchIcon /> Hunt Hypotheses
          </Typography>
          <Grid container spacing={2}>
            {campaignData.hunt_hypotheses.map((hypothesis, index) => (
              <Grid item xs={12} key={index}>
                <Card sx={{
                  bgcolor: 'rgba(255,255,255,0.15)',
                  border: '2px solid rgba(255,255,255,0.3)',
                  borderLeftColor: hypothesis.priority === 1 ? '#f44336' : hypothesis.priority === 2 ? '#ff9800' : '#4caf50',
                  borderLeftWidth: 4
                }}>
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                      <Chip
                        label={`Priority ${hypothesis.priority}`}
                        sx={{
                          bgcolor: hypothesis.priority === 1 ? '#f44336' : hypothesis.priority === 2 ? '#ff9800' : '#4caf50',
                          color: 'white',
                          fontWeight: 600
                        }}
                      />
                      <Chip
                        label={hypothesis.confidence}
                        sx={{ bgcolor: COLORS[hypothesis.confidence] || COLORS.UNKNOWN, color: 'white', fontWeight: 600 }}
                      />
                    </Box>
                    <Typography variant="h6" sx={{ color: (theme) => theme.palette.mode === 'dark' ? 'white' : 'rgba(0, 0, 0, 0.7)', fontWeight: 600, mb: 1 }}>
                      {hypothesis.hypothesis_name}
                    </Typography>
                    <Typography variant="body2" sx={{ color: (theme) => theme.palette.mode === 'dark' ? 'white' : 'rgba(0, 0, 0, 0.7)', mb: 2, lineHeight: 1.8 }}>
                      {hypothesis.hypothesis_description}
                    </Typography>
                    <Grid container spacing={2}>
                      <Grid item xs={12} md={6}>
                        <Typography variant="caption" sx={{ color: (theme) => theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.8)' : 'rgba(0, 0, 0, 0.7)' }}>
                          Detection Platform:
                        </Typography>
                        <Typography variant="body2" sx={{ color: (theme) => theme.palette.mode === 'dark' ? 'white' : 'rgba(0, 0, 0, 0.7)', fontWeight: 500 }}>
                          {hypothesis.detection_platform}
                        </Typography>
                      </Grid>
                      <Grid item xs={12} md={6}>
                        <Typography variant="caption" sx={{ color: (theme) => theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.8)' : 'rgba(0, 0, 0, 0.7)' }}>
                          Hunt Timeline:
                        </Typography>
                        <Typography variant="body2" sx={{ color: (theme) => theme.palette.mode === 'dark' ? 'white' : 'rgba(0, 0, 0, 0.7)', fontWeight: 500 }}>
                          {hypothesis.hunt_timeline}
                        </Typography>
                      </Grid>
                      <Grid item xs={12}>
                        <Typography variant="caption" sx={{ color: (theme) => theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.8)' : 'rgba(0, 0, 0, 0.7)' }}>
                          Executable Query:
                        </Typography>
                        <Box sx={{
                          p: 2,
                          bgcolor: 'rgba(0,0,0,0.3)',
                          borderRadius: 1,
                          mt: 0.5,
                          fontFamily: 'monospace',
                          fontSize: '0.85rem',
                          color: '#4caf50',
                          overflowX: 'auto'
                        }}>
                          {hypothesis.executable_query}
                        </Box>
                      </Grid>
                      <Grid item xs={12}>
                        <Typography variant="caption" sx={{ color: (theme) => theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.8)' : 'rgba(0, 0, 0, 0.7)' }}>
                          Success Criteria:
                        </Typography>
                        <Typography variant="body2" sx={{ color: (theme) => theme.palette.mode === 'dark' ? 'white' : 'rgba(0, 0, 0, 0.7)', fontWeight: 500 }}>
                          {hypothesis.success_criteria}
                        </Typography>
                      </Grid>
                    </Grid>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

      {/* Threat Categories */}
      {data.threat_categories && data.threat_categories.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Typography variant="h6" sx={{ mb: 2, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
            <BugReportIcon /> 위협 분류
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            {data.threat_categories.map((category, index) => (
              <Chip
                key={index}
                label={category}
                sx={{
                  bgcolor: 'rgba(255,255,255,0.3)',
                  color: 'white',
                  fontWeight: 600,
                  fontSize: '0.9rem',
                }}
              />
            ))}
          </Box>
        </Box>
      )}

      {/* Recommendations */}
      {(campaignData.recommended_actions || data.recommendations) && (
        <Box sx={{ mb: 3 }}>
          <Typography variant="h6" sx={{ mb: 2, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
            <InfoIcon sx={{ color: 'text.secondary' }} /> 주요 권장사항
          </Typography>
          <Box
            sx={{
              p: 3,
              bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.03)' : 'rgba(0, 0, 0, 0.02)',
              borderRadius: '16px',
              border: (theme) => `1px solid ${theme.palette.divider}`,
            }}
          >
            <Box component="ul" sx={{ m: 0, pl: 3 }}>
              {(campaignData.recommended_actions || data.recommendations || []).map((rec, index) => (
                <li key={index}>
                  <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 1 }}>
                    {rec}
                  </Typography>
                </li>
              ))}
            </Box>
          </Box>
        </Box>
      )}

      {/* Intelligence Gaps */}
      {campaignData.intelligence_gaps && campaignData.intelligence_gaps.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Typography variant="h6" sx={{ mb: 2, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
            <WarningIcon /> Intelligence Gaps
          </Typography>
          <Box
            sx={{
              p: 3,
              bgcolor: 'rgba(255, 152, 0, 0.2)',
              borderRadius: 2,
              border: '1px solid rgba(255, 152, 0, 0.5)',
            }}
          >
            <Box component="ul" sx={{ m: 0, pl: 3 }}>
              {campaignData.intelligence_gaps.map((gap, index) => (
                <li key={index}>
                  <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 1 }}>
                    {gap}
                  </Typography>
                </li>
              ))}
            </Box>
          </Box>
        </Box>
      )}

      {/* Organizational Impact */}
      {campaignData.organizational_impact && (
        <Box>
          <Typography variant="h6" sx={{ mb: 2, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
            <TrendingUpIcon /> Organizational Impact
          </Typography>
          <Alert
            severity="error"
            sx={{
              bgcolor: 'rgba(244, 67, 54, 0.2)',
              border: '1px solid rgba(244, 67, 54, 0.5)',
              color: 'white',
              '& .MuiAlert-icon': {
                color: 'white'
              }
            }}
          >
            <Typography variant="body1" sx={{ lineHeight: 2 }}>
              {campaignData.organizational_impact}
            </Typography>
          </Alert>
        </Box>
      )}
    </Paper>
  );
}
