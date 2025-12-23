import React from 'react';
import {
  Box,
  Typography,
  Chip,
  Grid,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  useTheme,
} from '@mui/material';
import {
  PieChart, Pie, Cell, ResponsiveContainer,
  Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  Tooltip, Legend
} from 'recharts';
import SecurityIcon from '@mui/icons-material/Security';
import InfoIcon from '@mui/icons-material/Info';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import AssessmentIcon from '@mui/icons-material/Assessment';
import PictureAsPdfIcon from '@mui/icons-material/PictureAsPdf';
import PrintIcon from '@mui/icons-material/Print';
import GpsFixedIcon from '@mui/icons-material/GpsFixed';
import SearchIcon from '@mui/icons-material/Search';

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

const THREAT_LEVEL_COLORS = {
  CRITICAL: '#AF52DE',
  HIGH: '#FF3B30',
  MEDIUM: '#FF9500',
  LOW: '#34C759',
  UNKNOWN: '#8E8E93',
};

export default function FinalSummarySection({ data }) {
  const theme = useTheme();
  const isDarkMode = theme.palette.mode === 'dark';

  if (!data) return null;

  const campaignData = data.full_analysis?.campaign || data;

  // --- Data Preparation for Charts ---

  // 1. IOC Confidence (Donut Chart)
  const confidenceData = data.visualization_data?.ioc_confidence_distribution || {};
  const confidencePieData = Object.entries(confidenceData).map(([key, value]) => ({
    name: key,
    value: value
  }));

  // 2. MITRE ATT&CK (Radar Chart)
  // Transform the mitre_coverage object into an array for RadarChart
  const mitreData = data.visualization_data?.mitre_coverage || {};
  // If no data, provide some placeholders or handle empty state
  const radarData = Object.entries(mitreData).map(([tactic, count]) => ({
    subject: tactic,
    A: count,
    fullMark: Math.max(...Object.values(mitreData), 5) // Scale based on max value
  }));

  // --- Handlers ---
  const handlePdfExport = () => {
    alert('PDF 내보내기 기능은 곧 추가됩니다!');
  };

  const handlePrint = () => {
    window.print();
  };

  // --- Styles ---
  const cardStyle = {
    bgcolor: isDarkMode ? 'rgba(28, 28, 30, 0.6)' : COLORS.CARD_BG_LIGHT,
    borderRadius: '18px',
    border: isDarkMode ? '1px solid rgba(255,255,255,0.1)' : `1px solid ${COLORS.BORDER_LIGHT}`,
    boxShadow: isDarkMode ? 'none' : '0 4px 24px rgba(0,0,0,0.02)',
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

  return (
    <Box sx={{ mt: 2, fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif' }}>

      {/* Header Section */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 700, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY, letterSpacing: '-0.02em' }}>
            Final Summary
          </Typography>
          <Typography variant="body2" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, mt: 0.5 }}>
            Comprehensive Threat Intelligence Analysis
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            variant="outlined"
            startIcon={<PictureAsPdfIcon />}
            onClick={handlePdfExport}
            sx={{
              borderRadius: "20px",
              textTransform: "none",
              fontWeight: 500,
              borderColor: isDarkMode ? 'rgba(255,255,255,0.2)' : COLORS.BORDER_LIGHT,
              color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY,
              '&:hover': {
                borderColor: COLORS.PRIMARY,
                bgcolor: 'transparent'
              }
            }}
          >
            Export PDF
          </Button>
          <Button
            variant="outlined"
            startIcon={<PrintIcon />}
            onClick={handlePrint}
            sx={{
              borderRadius: "20px",
              textTransform: "none",
              fontWeight: 500,
              borderColor: isDarkMode ? 'rgba(255,255,255,0.2)' : COLORS.BORDER_LIGHT,
              color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY,
              '&:hover': {
                borderColor: COLORS.PRIMARY,
                bgcolor: 'transparent'
              }
            }}
          >
            Print
          </Button>
        </Box>
      </Box>

      {/* Top Cards: Threat Level & Campaign */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {/* Threat Level Card */}
        <Grid item xs={12} md={4}>
          <Card elevation={0} sx={cardStyle}>
            <CardContent sx={{ p: 3 }}>
              <Typography variant="subtitle2" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontWeight: 600, mb: 1, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Threat Level
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <Box sx={{
                  width: 12, height: 12, borderRadius: '50%',
                  bgcolor: THREAT_LEVEL_COLORS[campaignData.threat_level] || COLORS.UNKNOWN,
                  boxShadow: `0 0 12px ${THREAT_LEVEL_COLORS[campaignData.threat_level] || COLORS.UNKNOWN}`
                }} />
                <Typography variant="h3" sx={{ fontWeight: 700, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
                  {campaignData.threat_level || 'UNKNOWN'}
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Campaign Name Card */}
        <Grid item xs={12} md={8}>
          <Card elevation={0} sx={cardStyle}>
            <CardContent sx={{ p: 3 }}>
              <Typography variant="subtitle2" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontWeight: 600, mb: 1, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Campaign Identity
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Typography variant="h5" sx={{ fontWeight: 600, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
                  {campaignData.campaign_name || 'Unidentified Campaign'}
                </Typography>
                {campaignData.campaign_confidence && (
                  <Chip
                    label={campaignData.campaign_confidence}
                    size="small"
                    sx={{
                      bgcolor: isDarkMode ? 'rgba(255,255,255,0.1)' : '#F2F2F7',
                      color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY,
                      fontWeight: 600,
                      borderRadius: '6px'
                    }}
                  />
                )}
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Main Content Grid */}
      <Grid container spacing={3} sx={{ mb: 4 }}>

        {/* Left Column: Executive Summary & Evidence */}
        <Grid item xs={12} lg={7}>
          {/* Executive Summary */}
          <Card elevation={0} sx={{ ...cardStyle, mb: 3 }}>
            <CardContent sx={{ p: 3 }}>
              <Typography sx={sectionTitleStyle}>
                <InfoIcon fontSize="small" sx={{ color: COLORS.PRIMARY }} /> Executive Summary
              </Typography>
              <Typography variant="body1" sx={{
                lineHeight: 1.8,
                color: isDarkMode ? '#ddd' : '#333',
                fontSize: '1rem'
              }}>
                {data.executive_summary || campaignData.executive_summary || "No summary available."}
              </Typography>
            </CardContent>
          </Card>

          {/* Campaign Evidence */}
          {campaignData.campaign_evidence && campaignData.campaign_evidence.length > 0 && (
            <Card elevation={0} sx={cardStyle}>
              <CardContent sx={{ p: 3 }}>
                <Typography sx={sectionTitleStyle}>
                  <GpsFixedIcon fontSize="small" sx={{ color: COLORS.PRIMARY }} /> Key Evidence
                </Typography>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  {campaignData.campaign_evidence.map((evidence, index) => (
                    <Box key={index} sx={{ display: 'flex', gap: 2, alignItems: 'flex-start' }}>
                      <Box sx={{
                        minWidth: 24, height: 24, borderRadius: '50%',
                        bgcolor: isDarkMode ? 'rgba(255,255,255,0.1)' : '#F2F2F7',
                        color: isDarkMode ? '#fff' : COLORS.TEXT_SECONDARY,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        fontSize: '0.75rem', fontWeight: 700, mt: 0.3
                      }}>
                        {index + 1}
                      </Box>
                      <Typography variant="body2" sx={{ color: isDarkMode ? '#ccc' : '#444', lineHeight: 1.6 }}>
                        {evidence}
                      </Typography>
                    </Box>
                  ))}
                </Box>
              </CardContent>
            </Card>
          )}
        </Grid>

        {/* Right Column: Visualizations */}
        <Grid item xs={12} lg={5}>
          {/* MITRE ATT&CK Radar Chart */}
          <Card elevation={0} sx={{ ...cardStyle, mb: 3 }}>
            <CardContent sx={{ p: 3, display: 'flex', flexDirection: 'column', alignItems: 'center', minHeight: 350 }}>
              <Typography sx={{ ...sectionTitleStyle, width: '100%', color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
                <SecurityIcon fontSize="small" sx={{ color: COLORS.PRIMARY }} /> MITRE ATT&CK Coverage
              </Typography>
              <Box sx={{ width: '100%', height: 300, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                {radarData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <RadarChart cx="50%" cy="50%" outerRadius="70%" data={radarData}>
                      <PolarGrid stroke={isDarkMode ? '#444' : '#E5E5EA'} />
                      <PolarAngleAxis
                        dataKey="subject"
                        tick={{ fill: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontSize: 11 }}
                      />
                      <PolarRadiusAxis angle={30} domain={[0, 'auto']} tick={false} axisLine={false} />
                      <Radar
                        name="Techniques"
                        dataKey="A"
                        stroke={COLORS.PRIMARY}
                        fill={COLORS.PRIMARY}
                        fillOpacity={0.3}
                      />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: isDarkMode ? '#333' : '#fff',
                          border: 'none',
                          borderRadius: '8px',
                          boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
                          color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY
                        }}
                        itemStyle={{ color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}
                      />
                    </RadarChart>
                  </ResponsiveContainer>
                ) : (
                  <Typography variant="body2" color="text.secondary">
                    No MITRE ATT&CK data available
                  </Typography>
                )}
              </Box>
            </CardContent>
          </Card>

          {/* IOC Confidence Donut Chart */}
          <Card elevation={0} sx={cardStyle}>
            <CardContent sx={{ p: 3, minHeight: 300 }}>
              <Typography sx={{ ...sectionTitleStyle, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
                <AssessmentIcon fontSize="small" sx={{ color: COLORS.PRIMARY }} /> IOC Confidence
              </Typography>
              <Box sx={{ width: '100%', height: 250, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                {confidencePieData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={confidencePieData}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={80}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {confidencePieData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[entry.name] || COLORS.UNKNOWN} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: isDarkMode ? '#333' : '#fff',
                          border: 'none',
                          borderRadius: '8px',
                          boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
                          color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY
                        }}
                        itemStyle={{ color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}
                      />
                      <Legend
                        verticalAlign="bottom"
                        height={36}
                        iconType="circle"
                        formatter={(value) => <span style={{ color: isDarkMode ? '#ccc' : COLORS.TEXT_PRIMARY, fontSize: '0.85rem' }}>{value}</span>}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <Typography variant="body2" color="text.secondary">
                    No IOC Confidence data available
                  </Typography>
                )}
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Extracted IOCs Table */}
      {campaignData.extracted_iocs && campaignData.extracted_iocs.length > 0 && (
        <Card elevation={0} sx={cardStyle}>
          <CardContent sx={{ p: 3 }}>
            <Typography sx={sectionTitleStyle}>
              <SearchIcon fontSize="small" sx={{ color: COLORS.PRIMARY }} /> Extracted Indicators
            </Typography>
            <TableContainer sx={{ maxHeight: 400 }}>
              <Table stickyHeader size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ bgcolor: isDarkMode ? '#2c2c2e' : '#F5F5F7', color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontWeight: 600 }}>Indicator</TableCell>
                    <TableCell sx={{ bgcolor: isDarkMode ? '#2c2c2e' : '#F5F5F7', color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontWeight: 600 }}>Type</TableCell>
                    <TableCell sx={{ bgcolor: isDarkMode ? '#2c2c2e' : '#F5F5F7', color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontWeight: 600 }}>Confidence</TableCell>
                    <TableCell sx={{ bgcolor: isDarkMode ? '#2c2c2e' : '#F5F5F7', color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontWeight: 600 }}>Action</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {campaignData.extracted_iocs.map((ioc, index) => (
                    <TableRow key={index} hover sx={{ '&:last-child td, &:last-child th': { border: 0 } }}>
                      <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.85rem', color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
                        {ioc.indicator}
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={ioc.ioc_type}
                          size="small"
                          sx={{
                            bgcolor: isDarkMode ? 'rgba(255,255,255,0.1)' : '#F2F2F7',
                            color: isDarkMode ? '#ccc' : '#666',
                            fontSize: '0.75rem',
                            height: 24
                          }}
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption" sx={{
                          fontWeight: 600,
                          color: ioc.confidence?.includes('HIGH') ? COLORS.HIGH :
                            ioc.confidence?.includes('MEDIUM') ? COLORS.MEDIUM :
                              COLORS.LOW
                        }}>
                          {ioc.confidence}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={ioc.recommended_action}
                          size="small"
                          sx={{
                            bgcolor: ioc.recommended_action === 'block' ? 'rgba(255, 59, 48, 0.1)' : 'rgba(0, 122, 255, 0.1)',
                            color: ioc.recommended_action === 'block' ? COLORS.HIGH : COLORS.PRIMARY,
                            fontWeight: 600,
                            fontSize: '0.75rem',
                            height: 24
                          }}
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        </Card>
      )}

      {/* Recommendations Section */}
      {(campaignData.recommended_actions || data.recommendations) && (
        <Box sx={{ mt: 4 }}>
          <Typography sx={sectionTitleStyle}>
            <TrendingUpIcon fontSize="small" sx={{ color: COLORS.PRIMARY }} /> Recommended Actions
          </Typography>
          <Grid container spacing={2}>
            {(campaignData.recommended_actions || data.recommendations || []).map((rec, index) => (
              <Grid item xs={12} md={6} key={index}>
                <Card elevation={0} sx={{
                  ...cardStyle,
                  borderLeft: `4px solid ${COLORS.PRIMARY}`,
                  borderRadius: '12px'
                }}>
                  <CardContent sx={{ p: 2, '&:last-child': { pb: 2 } }}>
                    <Typography variant="body2" sx={{ color: isDarkMode ? '#ddd' : '#333', fontWeight: 500 }}>
                      {rec}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

    </Box>
  );
}
