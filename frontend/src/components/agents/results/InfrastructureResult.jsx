import React from 'react';
import {
  Box,
  Paper,
  Typography,
  Chip,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Card,
  CardContent,
  Grid,
  LinearProgress,
  useTheme,
} from '@mui/material';
import MapIcon from '@mui/icons-material/Map';
import HubIcon from '@mui/icons-material/Hub';
import AssessmentIcon from '@mui/icons-material/Assessment';
import SearchIcon from '@mui/icons-material/Search';
import BusinessIcon from '@mui/icons-material/Business';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';

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

export default function InfrastructureResult({ data }) {
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
      {/* Infrastructure Relationship Map - Hero Section */}
      <Paper sx={{ ...cardStyle, p: 4, mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
          <MapIcon sx={{ fontSize: 48, color: COLORS.PRIMARY }} />
          <Box>
            <Typography variant="h6" sx={{ opacity: 0.9, color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY }}>
              인프라 관계 맵
            </Typography>
            <Typography variant="h3" sx={{ fontWeight: 700, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
              Infrastructure Network
            </Typography>
          </Box>
        </Box>

        <Divider sx={{ my: 2, bgcolor: isDarkMode ? 'rgba(255,255,255,0.1)' : COLORS.BORDER_LIGHT }} />

        <Typography variant="body1" sx={{ mt: 2, lineHeight: 1.8, whiteSpace: 'pre-wrap', color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
          {data.infrastructure_relationship_map}
        </Typography>
      </Paper>

      {/* Campaign Clusters */}
      {data.campaign_clusters && data.campaign_clusters.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Typography sx={sectionTitleStyle}>
            <HubIcon fontSize="small" sx={{ color: COLORS.PRIMARY }} /> 캠페인 클러스터
          </Typography>
          <Grid container spacing={2}>
            {data.campaign_clusters.map((cluster, index) => (
              <Grid item xs={12} key={index}>
                <Card elevation={0} sx={{ ...cardStyle, borderLeft: cluster.confidence === 'HIGH' ? `4px solid ${COLORS.HIGH}` : undefined }}>
                  <CardContent sx={{ p: 3 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                      <Box
                        sx={{
                          width: 48, height: 48, borderRadius: '50%',
                          bgcolor: cluster.confidence === 'HIGH' ? COLORS.HIGH : COLORS.MEDIUM,
                          color: '#fff',
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          fontWeight: 700, fontSize: '1.2rem'
                        }}
                      >
                        {index + 1}
                      </Box>
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="h6" sx={{ fontWeight: 600, mb: 0.5, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY }}>
                          {cluster.cluster_name}
                        </Typography>
                        <Chip
                          label={cluster.confidence}
                          size="small"
                          sx={{
                            bgcolor: isDarkMode ? 'rgba(255,255,255,0.1)' : '#F2F2F7',
                            color: cluster.confidence === 'HIGH' ? COLORS.HIGH : COLORS.MEDIUM,
                            fontWeight: 600
                          }}
                        />
                      </Box>
                    </Box>

                    <Box sx={{ p: 2, mb: 2, bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F9F9F9', borderRadius: '12px' }}>
                      <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600, color: isDarkMode ? '#ccc' : COLORS.TEXT_SECONDARY }}>
                        인프라 요소
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                        {cluster.infrastructure_elements.map((element, idx) => (
                          <Chip
                            key={idx}
                            label={element}
                            size="small"
                            sx={{ bgcolor: 'rgba(0, 122, 255, 0.1)', color: COLORS.PRIMARY, fontFamily: 'monospace' }}
                          />
                        ))}
                      </Box>
                    </Box>

                    <Box sx={{ p: 2, bgcolor: 'rgba(0, 122, 255, 0.05)', borderRadius: '12px', borderLeft: `4px solid ${COLORS.PRIMARY}` }}>
                      <Typography variant="body2" sx={{ lineHeight: 1.7, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
                        <strong>근거:</strong> {cluster.clustering_evidence}
                      </Typography>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

      {/* Clustering Assessment */}
      <Box sx={{ mb: 3 }}>
        <Typography sx={sectionTitleStyle}>
          <AssessmentIcon fontSize="small" sx={{ color: COLORS.LOW }} /> 클러스터링 평가
        </Typography>
        <Paper sx={{ ...cardStyle, p: 3, borderLeft: `4px solid ${COLORS.LOW}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8, whiteSpace: 'pre-wrap', color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
            {data.clustering_assessment}
          </Typography>
        </Paper>
      </Box>

      {/* Additional IOCs */}
      {data.additional_iocs && data.additional_iocs.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Typography sx={sectionTitleStyle}>
            <SearchIcon fontSize="small" sx={{ color: COLORS.HIGH }} /> 추가 발견 IOC
          </Typography>
          <Paper sx={{ ...cardStyle, p: 0, overflow: 'hidden' }}>
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
                  {data.additional_iocs.map((ioc, index) => (
                    <TableRow key={index} hover>
                      <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.9rem', fontWeight: 600, color: COLORS.HIGH }}>
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

      {/* ASN & Hosting Patterns */}
      <Box sx={{ mb: 3 }}>
        <Typography sx={sectionTitleStyle}>
          <BusinessIcon fontSize="small" sx={{ color: COLORS.PRIMARY }} /> ASN & 호스팅 패턴
        </Typography>
        <Paper sx={{ ...cardStyle, p: 3 }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8, whiteSpace: 'pre-wrap', color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
            {data.asn_hosting_patterns}
          </Typography>
        </Paper>
      </Box>

      {/* Temporal Correlation */}
      <Box sx={{ mb: 3 }}>
        <Typography sx={sectionTitleStyle}>
          <AccessTimeIcon fontSize="small" sx={{ color: COLORS.MEDIUM }} /> 시간적 상관관계
        </Typography>
        <Paper sx={{ ...cardStyle, p: 3 }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8, whiteSpace: 'pre-wrap', color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
            {data.temporal_correlation}
          </Typography>
        </Paper>
      </Box>

      {/* Campaign Scale Assessment */}
      <Box sx={{ mb: 3 }}>
        <Typography sx={sectionTitleStyle}>
          <TrendingUpIcon fontSize="small" sx={{ color: COLORS.PRIMARY }} /> 캠페인 규모 평가
        </Typography>
        <Paper sx={{ ...cardStyle, p: 4 }}>
          <Box sx={{ p: 3, bgcolor: isDarkMode ? 'rgba(255,255,255,0.03)' : '#F9F9F9', borderRadius: '12px' }}>
            <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap', lineHeight: 2, color: isDarkMode ? '#ddd' : COLORS.TEXT_PRIMARY }}>
              {data.campaign_scale_assessment}
            </Typography>
          </Box>
        </Paper>
      </Box>
    </Box>
  );
}
