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
} from '@mui/material';
import WarningIcon from '@mui/icons-material/Warning';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import InfoIcon from '@mui/icons-material/Info';
import GpsFixedIcon from '@mui/icons-material/GpsFixed';
import LinkIcon from '@mui/icons-material/Link';
import PlaylistAddCheckIcon from '@mui/icons-material/PlaylistAddCheck';
import DescriptionIcon from '@mui/icons-material/Description';
import SecurityIcon from '@mui/icons-material/Security';
import DnsIcon from '@mui/icons-material/Dns';
import LanguageIcon from '@mui/icons-material/Language';
import { ResponsivePie } from '@nivo/pie';

const getThreatLevelColor = (level) => {
  switch (level?.toUpperCase()) {
    case 'CRITICAL':
      return 'error';
    case 'HIGH':
      return 'warning';
    case 'MEDIUM':
      return 'info';
    case 'LOW':
      return 'success';
    default:
      return 'default';
  }
};

const getThreatLevelIcon = (level) => {
  switch (level?.toUpperCase()) {
    case 'CRITICAL':
    case 'HIGH':
      return <WarningIcon />;
    case 'MEDIUM':
      return <InfoIcon />;
    case 'LOW':
      return <CheckCircleIcon />;
    default:
      return null;
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
    {
      id: '탐지',
      label: '탐지',
      value: detected,
      color: '#f44336',
    },
    {
      id: '미탐지',
      label: '미탐지',
      value: undetected,
      color: '#e0e0e0',
    },
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
        borderWidth={1}
        borderColor={{ from: 'color', modifiers: [['darker', 0.2]] }}
        enableArcLinkLabels={false}
        arcLabelsTextColor="#ffffff"
        arcLabel={(d) => `${d.value}`}
        theme={{
          labels: {
            text: {
              fontSize: 14,
              fontWeight: 600,
            },
          },
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
        <Typography
          variant="h3"
          sx={{
            fontWeight: 700,
            color: '#f44336',
            lineHeight: 1,
          }}
        >
          {detected}/{total}
        </Typography>
        <Typography
          variant="body2"
          sx={{
            color: 'text.secondary',
            fontWeight: 500,
            mt: 0.5,
          }}
        >
          Detection Ratio
        </Typography>
      </Box>
    </Box>
  );
};

export default function TriageResult({ data }) {
  if (!data) return null;

  return (
    <Box>
      {/* Threat Level Summary with Grid Layout */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        {/* Main Threat Level Card */}
        <Grid item xs={12} md={8}>
          <Paper
            sx={{
              p: 4,
              height: '100%',
              background: (theme) => theme.palette.mode === 'dark'
                ? `linear-gradient(135deg, ${
                    data.threat_level === 'CRITICAL' ? '#5d1f1f' :
                    data.threat_level === 'HIGH' ? '#5d3a1a' :
                    data.threat_level === 'MEDIUM' ? '#1a3a52' :
                    '#1e4620'
                  } 0%, ${
                    data.threat_level === 'CRITICAL' ? '#3d1414' :
                    data.threat_level === 'HIGH' ? '#3d2610' :
                    data.threat_level === 'MEDIUM' ? '#0d1f2d' :
                    '#0f2e11'
                  } 100%)`
                : `linear-gradient(135deg, ${
                    data.threat_level === 'CRITICAL' ? '#ffebee' :
                    data.threat_level === 'HIGH' ? '#fff3e0' :
                    data.threat_level === 'MEDIUM' ? '#e3f2fd' :
                    '#e8f5e9'
                  } 0%, ${
                    data.threat_level === 'CRITICAL' ? '#ffcdd2' :
                    data.threat_level === 'HIGH' ? '#ffe0b2' :
                    data.threat_level === 'MEDIUM' ? '#bbdefb' :
                    '#c8e6c9'
                  } 100%)`,
              color: (theme) => theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
              <SecurityIcon sx={{ fontSize: 48 }} />
              <Box>
                <Typography variant="h6" sx={{ opacity: 0.9, fontFamily: 'inherit' }}>
                  위협 수준 평가
                </Typography>
                <Typography variant="h2" sx={{ fontWeight: 700, fontFamily: 'inherit' }}>
                  {data.threat_level}
                </Typography>
              </Box>
            </Box>

            <Divider sx={{ my: 2, bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.3)' : 'rgba(0,0,0,0.12)' }} />

            <Box sx={{ display: 'flex', gap: 2, mb: 2, flexWrap: 'wrap' }}>
              <Chip
                label={`IOC Type: ${data.ioc_type}`}
                sx={{
                  bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.2)' : 'rgba(0,0,0,0.08)',
                  color: (theme) => theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
                  fontSize: '1rem',
                  fontWeight: 500,
                  fontFamily: 'inherit'
                }}
              />
            </Box>

            <Typography variant="body1" sx={{ mt: 2, lineHeight: 1.8, fontFamily: 'inherit' }}>
              {data.detection_summary}
            </Typography>
          </Paper>
        </Grid>

        {/* Detection Ratio Chart */}
        {data.detection_ratio && (
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: '100%' }}>
              <DetectionRatioChart ratio={data.detection_ratio} />
            </Paper>
          </Grid>
        )}
      </Grid>

      {/* Priority Discoveries */}
      {data.priority_discoveries && data.priority_discoveries.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <GpsFixedIcon sx={{ fontSize: 32 }} color="primary" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              우선순위 발견 사항
            </Typography>
          </Box>
          <Grid container spacing={2}>
            {data.priority_discoveries.map((discovery, index) => (
              <Grid item xs={12} key={index}>
                <Card
                  sx={{
                    position: 'relative',
                    overflow: 'visible',
                    border: '2px solid',
                    borderColor: discovery.priority_rank === 1 ? 'primary.main' : 'grey.300',
                    '&:hover': {
                      boxShadow: 6,
                      transform: 'translateY(-2px)',
                      transition: 'all 0.3s',
                    },
                  }}
                >
                  <CardContent sx={{ p: 3 }}>
                    <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
                      {/* Priority Number Badge */}
                      <Box
                        sx={{
                          minWidth: 48,
                          height: 48,
                          borderRadius: '50%',
                          bgcolor: discovery.priority_rank === 1 ? 'primary.main' : 'grey.400',
                          color: (theme) => theme.palette.mode === 'dark' ? '#ffffff' : discovery.priority_rank === 1 ? theme.palette.primary.contrastText : '#ffffff',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontWeight: 700,
                          fontSize: '1.2rem',
                        }}
                      >
                        {discovery.priority_rank}
                      </Box>

                      <Box sx={{ flex: 1 }}>
                        {/* Tags */}
                        <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
                          <Chip
                            label={discovery.confidence}
                            size="small"
                            color={getThreatLevelColor(discovery.confidence)}
                            sx={{ fontWeight: 600 }}
                          />
                          <Chip
                            label={discovery.recommended_specialist}
                            size="small"
                            color="primary"
                            variant="outlined"
                            sx={{ fontWeight: 500 }}
                          />
                        </Box>

                        {/* Discovery Content */}
                        <Typography
                          variant="h6"
                          sx={{
                            mb: 1.5,
                            fontFamily: 'inherit',
                            fontWeight: 600,
                            color: 'text.primary',
                          }}
                        >
                          {discovery.discovery}
                        </Typography>

                        {/* Significance */}
                        <Box
                          sx={{
                            p: 2,
                            bgcolor: (theme) => theme.palette.mode === 'dark' ? 'grey.800' : 'grey.50',
                            borderRadius: 1,
                            borderLeft: '4px solid',
                            borderColor: 'primary.main',
                          }}
                        >
                          <Typography
                            variant="body2"
                            sx={{
                              fontFamily: 'inherit',
                              color: 'text.secondary',
                              lineHeight: 1.7,
                            }}
                          >
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
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <LinkIcon sx={{ fontSize: 32 }} color="primary" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              발견된 관계
            </Typography>
          </Box>
          <Grid container spacing={2}>
            {data.discovered_relationships.map((rel, index) => (
              <Grid item xs={12} md={6} key={index}>
                <Card
                  sx={{
                    height: '100%',
                    border: '1px solid',
                    borderColor: 'grey.200',
                    '&:hover': {
                      boxShadow: 4,
                      borderColor: 'primary.main',
                      transition: 'all 0.3s',
                    },
                  }}
                >
                  <CardContent>
                    {/* Icon and Type */}
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
                      <Box
                        sx={{
                          width: 40,
                          height: 40,
                          borderRadius: 1,
                          bgcolor: 'primary.light',
                          color: 'primary.main',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                        }}
                      >
                        {getRelationshipIcon(rel.relationship_type)}
                      </Box>
                      <Box sx={{ flex: 1 }}>
                        <Chip
                          label={rel.relationship_type}
                          size="small"
                          color="primary"
                          variant="outlined"
                        />
                      </Box>
                      <Chip
                        label={rel.confidence}
                        size="small"
                        color={getThreatLevelColor(rel.confidence)}
                      />
                    </Box>

                    {/* Indicator */}
                    <Box
                      sx={{
                        p: 1.5,
                        mb: 2,
                        bgcolor: (theme) => theme.palette.mode === 'dark' ? 'grey.800' : 'grey.100',
                        borderRadius: 1,
                        border: '1px solid',
                        borderColor: (theme) => theme.palette.mode === 'dark' ? 'grey.700' : 'grey.300',
                      }}
                    >
                      <Typography
                        variant="body1"
                        sx={{
                          fontFamily: 'monospace',
                          fontWeight: 600,
                          wordBreak: 'break-all',
                          color: 'error.main',
                        }}
                      >
                        {rel.indicator}
                      </Typography>
                    </Box>

                    {/* Detection Stats */}
                    {rel.detection_stats && (
                      <Box sx={{ mb: 2 }}>
                        <Chip
                          icon={<SecurityIcon />}
                          label={rel.detection_stats}
                          size="small"
                          variant="outlined"
                          color="error"
                          sx={{ fontWeight: 500 }}
                        />
                      </Box>
                    )}

                    {/* Context */}
                    <Typography
                      variant="body2"
                      sx={{
                        color: 'text.secondary',
                        lineHeight: 1.6,
                        fontFamily: 'inherit',
                      }}
                    >
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
        <Paper
          sx={{
            p: 3,
            mb: 3,
            background: (theme) => theme.palette.mode === 'dark'
              ? 'linear-gradient(135deg, #0d1b3e 0%, #1a0d2e 100%)'
              : 'linear-gradient(135deg, #e3f2fd 0%, #f3e5f5 100%)',
            border: '2px solid',
            borderColor: 'primary.light',
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 3 }}>
            <PlaylistAddCheckIcon sx={{ fontSize: 32 }} color="primary" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              권장 후속 조치
            </Typography>
          </Box>
          <Grid container spacing={2}>
            {data.recommended_next_steps.map((step, index) => (
              <Grid item xs={12} key={index}>
                <Card
                  sx={{
                    bgcolor: (theme) => theme.palette.mode === 'dark' ? 'grey.900' : 'white',
                    '&:hover': {
                      boxShadow: 3,
                      transform: 'translateX(4px)',
                      transition: 'all 0.2s',
                    },
                  }}
                >
                  <CardContent sx={{ p: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
                      <Box
                        sx={{
                          minWidth: 32,
                          height: 32,
                          borderRadius: '4px',
                          bgcolor: 'primary.main',
                          color: 'primary.contrastText',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontWeight: 700,
                        }}
                      >
                        {index + 1}
                      </Box>
                      <Typography
                        variant="body1"
                        sx={{
                          flex: 1,
                          fontFamily: 'inherit',
                          lineHeight: 1.8,
                          fontWeight: 500,
                        }}
                      >
                        {step}
                      </Typography>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Paper>
      )}

      {/* Analytical Summary */}
      <Paper
        sx={{
          p: 4,
          background: (theme) => theme.palette.mode === 'dark'
            ? 'linear-gradient(135deg, #3d2a0f 0%, #4a3310 100%)'
            : 'linear-gradient(135deg, #fff3e0 0%, #ffe0b2 100%)',
          border: '2px solid',
          borderColor: 'warning.light',
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 3 }}>
          <DescriptionIcon sx={{ fontSize: 32 }} color="warning" />
          <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
            분석 요약
          </Typography>
        </Box>
        <Box
          sx={{
            p: 3,
            bgcolor: (theme) => theme.palette.mode === 'dark' ? 'grey.900' : 'white',
            borderRadius: 2,
            borderLeft: '6px solid',
            borderColor: 'warning.main',
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
            {data.analytical_summary}
          </Typography>
        </Box>
      </Paper>
    </Box>
  );
}
