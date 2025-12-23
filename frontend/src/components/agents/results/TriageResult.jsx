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
  useTheme,
} from '@mui/material';

import GpsFixedIcon from '@mui/icons-material/GpsFixed';
import LinkIcon from '@mui/icons-material/Link';
import PlaylistAddCheckIcon from '@mui/icons-material/PlaylistAddCheck';
import DescriptionIcon from '@mui/icons-material/Description';
import SecurityIcon from '@mui/icons-material/Security';
import DnsIcon from '@mui/icons-material/Dns';
import LanguageIcon from '@mui/icons-material/Language';
import { ResponsivePie } from '@nivo/pie';

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

const getThreatLevelColor = (level) => {
  switch (level?.toUpperCase()) {
    case 'CRITICAL': return COLORS.CRITICAL;
    case 'HIGH': return COLORS.HIGH;
    case 'MEDIUM': return COLORS.MEDIUM;
    case 'LOW': return COLORS.LOW;
    default: return COLORS.UNKNOWN;
  }
};

const getRelationshipIcon = (type) => {
  if (type?.includes('ip')) return <DnsIcon />;
  if (type?.includes('domain')) return <LanguageIcon />;
  return <LinkIcon />;
};

const DetectionRatioChart = ({ ratio }) => {
  if (!ratio) return null;

  const [detected, total] = ratio.split('/').map(Number);
  const undetected = total - detected;

  const data = [
    { id: '탐지', label: '탐지', value: detected, color: COLORS.HIGH },
    { id: '미탐지', label: '미탐지', value: undetected, color: '#E5E5EA' },
  ];

  return (
    <Box sx={{ height: 250, position: 'relative' }}>
      <ResponsivePie
        data={data}
        margin={{ top: 20, right: 20, bottom: 20, left: 20 }}
        innerRadius={0.6}
        padAngle={2}
        cornerRadius={4}
        activeOuterRadiusOffset={8}
        colors={{ datum: 'data.color' }}
        borderWidth={0}
        enableArcLinkLabels={false}
        arcLabelsTextColor="#ffffff"
        arcLabel={(d) => `${d.value}`}
        theme={{
          labels: { text: { fontSize: 14, fontWeight: 600 } },
        }}
      />
      <Box
        sx={{
          position: 'absolute',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          textAlign: 'center',
        }}
      >
        <Typography variant="h3" sx={{ fontWeight: 700, color: COLORS.HIGH, lineHeight: 1 }}>
          {detected}/{total}
        </Typography>
        <Typography variant="body2" sx={{ color: COLORS.TEXT_SECONDARY, fontWeight: 500, mt: 0.5 }}>
          Detection Ratio
        </Typography>
      </Box>
    </Box>
  );
};

export default function TriageResult({ data }) {
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

  return (
    <Box sx={{ fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif' }}>
      {/* Threat Level Summary */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={8}>
          <Paper sx={{ ...cardStyle, p: 4 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
              <SecurityIcon sx={{ fontSize: 48, color: getThreatLevelColor(data.threat_level) }} />
              <Box>
                <Typography variant="h6" sx={{ opacity: 0.9, color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY }}>
                  위협 수준 평가
                </Typography>
                <Typography variant="h2" sx={{ fontWeight: 700, color: getThreatLevelColor(data.threat_level) }}>
                  {data.threat_level}
                </Typography>
              </Box>
            </Box>

            <Divider sx={{ my: 2, bgcolor: isDarkMode ? 'rgba(255,255,255,0.1)' : COLORS.BORDER_LIGHT }} />

            <Box sx={{ display: 'flex', gap: 2, mb: 2, flexWrap: 'wrap' }}>
              <Chip
                label={`IOC Type: ${data.ioc_type}`}
                sx={{
                  bgcolor: isDarkMode ? 'rgba(255,255,255,0.1)' : '#F2F2F7',
                  color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY,
                  fontSize: '1rem',
                  fontWeight: 500,
                  borderRadius: '8px'
                }}
              />
            </Box>

            <Typography variant="body1" sx={{ mt: 2, lineHeight: 1.8, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
              {data.detection_summary}
            </Typography>
          </Paper>
        </Grid>

        {/* Detection Ratio Chart */}
        {data.detection_ratio && (
          <Grid item xs={12} md={4}>
            <Paper sx={{ ...cardStyle, p: 3 }}>
              <DetectionRatioChart ratio={data.detection_ratio} />
            </Paper>
          </Grid>
        )}
      </Grid>

      {/* Priority Discoveries */}
      {data.priority_discoveries && data.priority_discoveries.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Typography sx={sectionTitleStyle}>
            <GpsFixedIcon fontSize="small" sx={{ color: COLORS.PRIMARY }} /> 우선순위 발견 사항
          </Typography>
          <Grid container spacing={2}>
            {data.priority_discoveries.map((discovery, index) => (
              <Grid item xs={12} key={index}>
                <Card elevation={0} sx={{ ...cardStyle, borderLeft: discovery.priority_rank === 1 ? `4px solid ${COLORS.PRIMARY}` : undefined }}>
                  <CardContent sx={{ p: 3 }}>
                    <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
                      <Box
                        sx={{
                          minWidth: 40, height: 40, borderRadius: '50%',
                          bgcolor: discovery.priority_rank === 1 ? COLORS.PRIMARY : isDarkMode ? 'rgba(255,255,255,0.1)' : '#E5E5EA',
                          color: discovery.priority_rank === 1 ? '#fff' : COLORS.TEXT_SECONDARY,
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          fontWeight: 700, fontSize: '1.1rem'
                        }}
                      >
                        {discovery.priority_rank}
                      </Box>

                      <Box sx={{ flex: 1 }}>
                        <Box sx={{ display: 'flex', gap: 1, mb: 1, flexWrap: 'wrap' }}>
                          <Chip
                            label={discovery.confidence}
                            size="small"
                            sx={{
                              bgcolor: isDarkMode ? 'rgba(255,255,255,0.1)' : '#F2F2F7',
                              color: getThreatLevelColor(discovery.confidence),
                              fontWeight: 600
                            }}
                          />
                          <Chip
                            label={discovery.recommended_specialist}
                            size="small"
                            sx={{
                              bgcolor: 'rgba(0, 122, 255, 0.1)',
                              color: COLORS.PRIMARY,
                              fontWeight: 500
                            }}
                          />
                        </Box>

                        <Typography variant="h6" sx={{ mb: 1, fontWeight: 600, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
                          {discovery.discovery}
                        </Typography>

                        <Box sx={{ p: 2, bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '12px' }}>
                          <Typography variant="body2" sx={{ color: isDarkMode ? '#ccc' : COLORS.TEXT_SECONDARY, lineHeight: 1.6 }}>
                            <strong>중요도:</strong> {discovery.significance}
                          </Typography>
                        </Box>
                      </Box>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

      {/* Discovered Relationships */}
      {data.discovered_relationships && data.discovered_relationships.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Typography sx={sectionTitleStyle}>
            <LinkIcon fontSize="small" sx={{ color: COLORS.PRIMARY }} /> 발견된 관계
          </Typography>
          <Grid container spacing={2}>
            {data.discovered_relationships.map((rel, index) => (
              <Grid item xs={12} md={6} key={index}>
                <Card elevation={0} sx={cardStyle}>
                  <CardContent sx={{ p: 3 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
                      <Box sx={{ color: COLORS.PRIMARY }}>{getRelationshipIcon(rel.relationship_type)}</Box>
                      <Box sx={{ flex: 1 }}>
                        <Chip
                          label={rel.relationship_type}
                          size="small"
                          sx={{ bgcolor: 'rgba(0, 122, 255, 0.1)', color: COLORS.PRIMARY }}
                        />
                      </Box>
                      <Chip
                        label={rel.confidence}
                        size="small"
                        sx={{ bgcolor: isDarkMode ? 'rgba(255,255,255,0.1)' : '#F2F2F7', color: getThreatLevelColor(rel.confidence) }}
                      />
                    </Box>

                    <Box sx={{ p: 1.5, mb: 2, bgcolor: isDarkMode ? 'rgba(0,0,0,0.3)' : '#F5F5F7', borderRadius: '8px' }}>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace', fontWeight: 600, color: COLORS.HIGH, wordBreak: 'break-all' }}>
                        {rel.indicator}
                      </Typography>
                    </Box>

                    {rel.detection_stats && (
                      <Box sx={{ mb: 2 }}>
                        <Chip
                          icon={<SecurityIcon />}
                          label={rel.detection_stats}
                          size="small"
                          sx={{ bgcolor: 'rgba(255, 59, 48, 0.1)', color: COLORS.HIGH }}
                        />
                      </Box>
                    )}

                    <Typography variant="body2" sx={{ color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, lineHeight: 1.6 }}>
                      {rel.context}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

      {/* Recommended Next Steps */}
      {data.recommended_next_steps && data.recommended_next_steps.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Typography sx={sectionTitleStyle}>
            <PlaylistAddCheckIcon fontSize="small" sx={{ color: COLORS.PRIMARY }} /> 권장 후속 조치
          </Typography>
          <Paper sx={{ ...cardStyle, p: 3 }}>
            <Grid container spacing={2}>
              {data.recommended_next_steps.map((step, index) => (
                <Grid item xs={12} key={index}>
                  <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
                    <Box
                      sx={{
                        minWidth: 28, height: 28, borderRadius: '6px',
                        bgcolor: COLORS.PRIMARY, color: '#fff',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        fontWeight: 700, fontSize: '0.9rem', mt: 0.3
                      }}
                    >
                      {index + 1}
                    </Box>
                    <Typography variant="body1" sx={{ flex: 1, lineHeight: 1.6, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
                      {step}
                    </Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </Box>
      )}

      {/* Analytical Summary */}
      <Box sx={{ mb: 3 }}>
        <Typography sx={sectionTitleStyle}>
          <DescriptionIcon fontSize="small" sx={{ color: COLORS.PRIMARY }} /> 분석 요약
        </Typography>
        <Paper sx={{ ...cardStyle, p: 3, borderLeft: `4px solid ${COLORS.MEDIUM}` }}>
          <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap', lineHeight: 1.8, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
            {data.analytical_summary}
          </Typography>
        </Paper>
      </Box>
    </Box>
  );
}
