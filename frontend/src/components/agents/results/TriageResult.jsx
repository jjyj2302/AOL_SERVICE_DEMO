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
} from '@mui/material';
import WarningIcon from '@mui/icons-material/Warning';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import InfoIcon from '@mui/icons-material/Info';
import GpsFixedIcon from '@mui/icons-material/GpsFixed';
import LinkIcon from '@mui/icons-material/Link';
import PlaylistAddCheckIcon from '@mui/icons-material/PlaylistAddCheck';
import DescriptionIcon from '@mui/icons-material/Description';

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

export default function TriageResult({ data }) {
  if (!data) return null;

  return (
    <Box>
      {/* Threat Level Summary */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
          {getThreatLevelIcon(data.threat_level)}
          <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
            위협 수준 평가
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 2, mb: 2, flexWrap: 'wrap' }}>
          <Chip
            label={`위협 수준: ${data.threat_level}`}
            color={getThreatLevelColor(data.threat_level)}
            size="medium"
            sx={{ fontSize: '1.1rem', fontWeight: 500, fontFamily: 'inherit', py: 2.5 }}
          />
          {data.detection_ratio && (
            <Chip
              label={`Detection: ${data.detection_ratio}`}
              variant="outlined"
              size="medium"
              sx={{ fontSize: '1.1rem', fontWeight: 500, fontFamily: 'inherit', py: 2.5 }}
            />
          )}
          <Chip
            label={`IOC Type: ${data.ioc_type}`}
            variant="outlined"
            size="medium"
            sx={{ fontSize: '1.1rem', fontWeight: 500, fontFamily: 'inherit', py: 2.5 }}
          />
        </Box>
        <Alert severity={getThreatLevelColor(data.threat_level)} sx={{ mt: 2 }}>
          <Typography variant="h6" sx={{ fontFamily: 'inherit' }}>
            {data.detection_summary}
          </Typography>
        </Alert>
      </Paper>

      {/* Priority Discoveries */}
      {data.priority_discoveries && data.priority_discoveries.length > 0 && (
        <Paper sx={{ p: 3, mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <GpsFixedIcon sx={{ fontSize: 28 }} color="primary" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              우선순위 발견 사항
            </Typography>
          </Box>
          <List>
            {data.priority_discoveries.map((discovery, index) => (
              <React.Fragment key={index}>
                <ListItem alignItems="flex-start">
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                        <Chip
                          label={`#${discovery.priority_rank}`}
                          size="small"
                          color="primary"
                        />
                        <Chip
                          label={discovery.confidence}
                          size="small"
                          color={getThreatLevelColor(discovery.confidence)}
                          variant="outlined"
                        />
                        <Chip
                          label={discovery.recommended_specialist}
                          size="small"
                          variant="outlined"
                        />
                      </Box>
                    }
                    secondary={
                      <Box>
                        <Typography variant="h6" sx={{ mb: 1, fontFamily: 'inherit' }}>
                          <strong>발견:</strong> {discovery.discovery}
                        </Typography>
                        <Typography variant="h6" color="text.secondary" sx={{ fontFamily: 'inherit' }}>
                          <strong>중요도:</strong> {discovery.significance}
                        </Typography>
                      </Box>
                    }
                  />
                </ListItem>
                {index < data.priority_discoveries.length - 1 && <Divider />}
              </React.Fragment>
            ))}
          </List>
        </Paper>
      )}

      {/* Discovered Relationships */}
      {data.discovered_relationships && data.discovered_relationships.length > 0 && (
        <Paper sx={{ p: 3, mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <LinkIcon sx={{ fontSize: 28 }} color="primary" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              발견된 관계
            </Typography>
          </Box>
          <List>
            {data.discovered_relationships.map((rel, index) => (
              <ListItem key={index}>
                <ListItemText
                  primary={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                      <Chip label={rel.relationship_type} size="small" />
                      <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                        {rel.indicator}
                      </Typography>
                      {rel.detection_stats && (
                        <Chip label={rel.detection_stats} size="small" variant="outlined" />
                      )}
                      <Chip
                        label={rel.confidence}
                        size="small"
                        color={getThreatLevelColor(rel.confidence)}
                        variant="outlined"
                      />
                    </Box>
                  }
                  secondary={rel.context}
                />
              </ListItem>
            ))}
          </List>
        </Paper>
      )}

      {/* Recommended Next Steps */}
      {data.recommended_next_steps && data.recommended_next_steps.length > 0 && (
        <Paper sx={{ p: 3, mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <PlaylistAddCheckIcon sx={{ fontSize: 28 }} color="primary" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              권장 후속 조치
            </Typography>
          </Box>
          <List>
            {data.recommended_next_steps.map((step, index) => (
              <ListItem key={index}>
                <ListItemText
                  primary={`${index + 1}. ${step}`}
                  primaryTypographyProps={{ variant: 'h6', fontFamily: 'inherit' }}
                />
              </ListItem>
            ))}
          </List>
        </Paper>
      )}

      {/* Analytical Summary */}
      <Paper sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
          <DescriptionIcon sx={{ fontSize: 28 }} color="primary" />
          <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
            추가 분석 제안
          </Typography>
        </Box>
        <Typography variant="h6" sx={{ whiteSpace: 'pre-wrap', lineHeight: 1.8, fontFamily: 'inherit' }}>
          {data.analytical_summary}
        </Typography>
      </Paper>
    </Box>
  );
}
