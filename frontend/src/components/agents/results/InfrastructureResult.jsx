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
} from '@mui/material';

export default function InfrastructureResult({ data }) {
  if (!data) return null;

  return (
    <Box>
      {/* Infrastructure Relationship Map */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          🗺️ 인프라 관계 맵
        </Typography>
        <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap' }}>
          {data.infrastructure_relationship_map}
        </Typography>
      </Paper>

      {/* Campaign Clusters */}
      {data.campaign_clusters && data.campaign_clusters.length > 0 && (
        <Paper sx={{ p: 3, mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            🎯 캠페인 클러스터
          </Typography>
          <List>
            {data.campaign_clusters.map((cluster, index) => (
              <React.Fragment key={index}>
                <ListItem alignItems="flex-start">
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                        <Typography variant="subtitle1">
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
                    }
                    secondary={
                      <Box>
                        <Typography variant="body2" sx={{ mb: 1 }}>
                          <strong>인프라 요소:</strong>
                        </Typography>
                        <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 1 }}>
                          {cluster.infrastructure_elements.map((element, idx) => (
                            <Chip key={idx} label={element} size="small" variant="outlined" />
                          ))}
                        </Box>
                        <Typography variant="body2" color="text.secondary">
                          <strong>근거:</strong> {cluster.clustering_evidence}
                        </Typography>
                      </Box>
                    }
                  />
                </ListItem>
                {index < data.campaign_clusters.length - 1 && <Divider />}
              </React.Fragment>
            ))}
          </List>
        </Paper>
      )}

      {/* Clustering Assessment */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          📊 클러스터링 평가
        </Typography>
        <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap' }}>
          {data.clustering_assessment}
        </Typography>
      </Paper>

      {/* Additional IOCs */}
      {data.additional_iocs && data.additional_iocs.length > 0 && (
        <Paper sx={{ p: 3, mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            🔍 추가 발견 IOC
          </Typography>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell><strong>Indicator</strong></TableCell>
                  <TableCell><strong>Type</strong></TableCell>
                  <TableCell><strong>Confidence</strong></TableCell>
                  <TableCell><strong>Detections</strong></TableCell>
                  <TableCell><strong>Action</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.additional_iocs.map((ioc, index) => (
                  <TableRow key={index} hover>
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                      {ioc.indicator}
                    </TableCell>
                    <TableCell>
                      <Chip label={ioc.ioc_type} size="small" />
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
                    <TableCell sx={{ fontFamily: 'monospace' }}>
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

      {/* ASN & Hosting Patterns */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          🏢 ASN & 호스팅 패턴
        </Typography>
        <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap' }}>
          {data.asn_hosting_patterns}
        </Typography>
      </Paper>

      {/* Temporal Correlation */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          ⏱️ 시간적 상관관계
        </Typography>
        <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap' }}>
          {data.temporal_correlation}
        </Typography>
      </Paper>

      {/* Campaign Scale Assessment */}
      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" gutterBottom>
          📈 추가 분석 제안
        </Typography>
        <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap' }}>
          {data.campaign_scale_assessment}
        </Typography>
      </Paper>
    </Box>
  );
}
