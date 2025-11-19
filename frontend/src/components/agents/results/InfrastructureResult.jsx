import React from 'react';
import {
  Box,
  Paper,
  Typography,
  Chip,
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
  Card,
  CardContent,
  Grid,
  LinearProgress,
} from '@mui/material';
import PublicIcon from '@mui/icons-material/Public';
import HubIcon from '@mui/icons-material/Hub';
import AssessmentIcon from '@mui/icons-material/Assessment';
import SearchIcon from '@mui/icons-material/Search';
import BusinessIcon from '@mui/icons-material/Business';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import MapIcon from '@mui/icons-material/Map';
import AccountTreeIcon from '@mui/icons-material/AccountTree';

const DetectionGauge = ({ detections }) => {
  if (!detections || typeof detections !== 'string') return null;

  const [detected, total] = detections.split('/').map(Number);
  if (isNaN(detected) || isNaN(total) || total === 0) return detections;

  const percentage = (detected / total) * 100;

  // Color based on detection rate
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
          height: 8,
          borderRadius: 4,
          bgcolor: 'grey.200',
        }}
      />
    </Box>
  );
};

export default function InfrastructureResult({ data }) {
  if (!data) return null;

  return (
    <Box>
      {/* Infrastructure Relationship Map - Hero Section */}
      <Paper
        sx={{
          p: 4,
          mb: 3,
          background: 'linear-gradient(135deg, #ff9800 0%, #f57c00 100%)',
          color: 'white',
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
          <MapIcon sx={{ fontSize: 48 }} />
          <Box>
            <Typography variant="h6" sx={{ opacity: 0.9, fontFamily: 'inherit' }}>
              인프라 관계 맵
            </Typography>
            <Typography variant="h3" sx={{ fontWeight: 700, fontFamily: 'inherit' }}>
              Infrastructure Network
            </Typography>
          </Box>
        </Box>

        <Divider sx={{ my: 2, bgcolor: 'rgba(255,255,255,0.3)' }} />

        <Typography variant="body1" sx={{ mt: 2, lineHeight: 1.8, fontFamily: 'inherit', whiteSpace: 'pre-wrap' }}>
          {data.infrastructure_relationship_map}
        </Typography>
      </Paper>

      {/* Campaign Clusters */}
      {data.campaign_clusters && data.campaign_clusters.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <HubIcon sx={{ fontSize: 32 }} color="primary" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              캠페인 클러스터
            </Typography>
          </Box>
          <Grid container spacing={2}>
            {data.campaign_clusters.map((cluster, index) => (
              <Grid item xs={12} key={index}>
                <Card
                  sx={{
                    border: '2px solid',
                    borderColor: cluster.confidence === 'HIGH' ? 'error.main' :
                                 cluster.confidence === 'MEDIUM' ? 'warning.main' : 'info.main',
                    '&:hover': {
                      boxShadow: 6,
                      transform: 'translateY(-2px)',
                      transition: 'all 0.3s',
                    },
                  }}
                >
                  <CardContent sx={{ p: 3 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                      <Box
                        sx={{
                          width: 48,
                          height: 48,
                          borderRadius: '50%',
                          bgcolor: cluster.confidence === 'HIGH' ? 'error.light' :
                                   cluster.confidence === 'MEDIUM' ? 'warning.light' : 'info.light',
                          color: cluster.confidence === 'HIGH' ? 'error.main' :
                                 cluster.confidence === 'MEDIUM' ? 'warning.main' : 'info.main',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontWeight: 700,
                          fontSize: '1.2rem',
                        }}
                      >
                        {index + 1}
                      </Box>
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="h6" sx={{ fontWeight: 600, mb: 0.5 }}>
                          {cluster.cluster_name}
                        </Typography>
                        <Chip
                          label={cluster.confidence}
                          size="small"
                          color={
                            cluster.confidence === 'HIGH' ? 'error' :
                            cluster.confidence === 'MEDIUM' ? 'warning' : 'info'
                          }
                        />
                      </Box>
                    </Box>

                    <Box
                      sx={{
                        p: 2,
                        mb: 2,
                        bgcolor: 'grey.50',
                        borderRadius: 1,
                      }}
                    >
                      <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600 }}>
                        인프라 요소
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                        {cluster.infrastructure_elements.map((element, idx) => (
                          <Chip
                            key={idx}
                            label={element}
                            size="small"
                            variant="outlined"
                            color="primary"
                            sx={{ fontFamily: 'monospace', fontWeight: 500 }}
                          />
                        ))}
                      </Box>
                    </Box>

                    <Box
                      sx={{
                        p: 2,
                        bgcolor: 'primary.light',
                        bgcolor: 'rgba(33, 150, 243, 0.08)',
                        borderRadius: 1,
                        borderLeft: '4px solid',
                        borderColor: 'primary.main',
                      }}
                    >
                      <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
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
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
          <AssessmentIcon sx={{ fontSize: 32 }} color="success" />
          <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
            클러스터링 평가
          </Typography>
        </Box>
        <Paper
          sx={{
            p: 3,
            background: 'linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%)',
            border: '2px solid',
            borderColor: 'success.light',
          }}
        >
          <Typography variant="body1" sx={{ lineHeight: 1.8, whiteSpace: 'pre-wrap' }}>
            {data.clustering_assessment}
          </Typography>
        </Paper>
      </Box>

      {/* Additional IOCs */}
      {data.additional_iocs && data.additional_iocs.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <SearchIcon sx={{ fontSize: 32 }} color="error" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              추가 발견 IOC
            </Typography>
          </Box>
          <Paper
            sx={{
              p: 3,
              background: 'linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%)',
              border: '2px solid',
              borderColor: 'error.light',
            }}
          >
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow sx={{ bgcolor: 'white' }}>
                    <TableCell sx={{ fontWeight: 700, fontSize: '0.95rem' }}>Indicator</TableCell>
                    <TableCell sx={{ fontWeight: 700, fontSize: '0.95rem' }}>Type</TableCell>
                    <TableCell sx={{ fontWeight: 700, fontSize: '0.95rem' }}>Confidence</TableCell>
                    <TableCell sx={{ fontWeight: 700, fontSize: '0.95rem' }}>Detections</TableCell>
                    <TableCell sx={{ fontWeight: 700, fontSize: '0.95rem' }}>Action</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {data.additional_iocs.map((ioc, index) => (
                    <TableRow
                      key={index}
                      sx={{
                        bgcolor: 'white',
                        '&:hover': {
                          bgcolor: 'rgba(255, 0, 0, 0.05)',
                          transform: 'scale(1.01)',
                          transition: 'all 0.2s',
                        },
                      }}
                    >
                      <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.9rem', fontWeight: 600, color: 'error.main' }}>
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

      {/* ASN & Hosting Patterns */}
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
          <BusinessIcon sx={{ fontSize: 32 }} color="info" />
          <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
            ASN & 호스팅 패턴
          </Typography>
        </Box>
        <Paper
          sx={{
            p: 3,
            background: 'linear-gradient(135deg, #e1f5fe 0%, #b3e5fc 100%)',
            border: '2px solid',
            borderColor: 'info.light',
          }}
        >
          <Typography variant="body1" sx={{ lineHeight: 1.8, whiteSpace: 'pre-wrap' }}>
            {data.asn_hosting_patterns}
          </Typography>
        </Paper>
      </Box>

      {/* Temporal Correlation */}
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
          <AccessTimeIcon sx={{ fontSize: 32 }} color="warning" />
          <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
            시간적 상관관계
          </Typography>
        </Box>
        <Paper
          sx={{
            p: 3,
            background: 'linear-gradient(135deg, #fff8e1 0%, #ffecb3 100%)',
            border: '2px solid',
            borderColor: 'warning.light',
          }}
        >
          <Typography variant="body1" sx={{ lineHeight: 1.8, whiteSpace: 'pre-wrap' }}>
            {data.temporal_correlation}
          </Typography>
        </Paper>
      </Box>

      {/* Campaign Scale Assessment */}
      <Paper
        sx={{
          p: 4,
          background: 'linear-gradient(135deg, #f3e5f5 0%, #e1bee7 100%)',
          border: '2px solid',
          borderColor: 'secondary.light',
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 3 }}>
          <TrendingUpIcon sx={{ fontSize: 32 }} color="secondary" />
          <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
            캠페인 규모 평가
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
            {data.campaign_scale_assessment}
          </Typography>
        </Box>
      </Paper>
    </Box>
  );
}
