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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';

export default function CampaignResult({ data }) {
  if (!data) return null;

  return (
    <Box>
      {/* Executive Summary */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          📋 Executive Summary
        </Typography>
        <Alert
          severity={
            data.threat_level === 'CRITICAL' || data.threat_level === 'HIGH' ? 'error' :
            data.threat_level === 'MEDIUM' ? 'warning' : 'info'
          }
          sx={{ mb: 2 }}
        >
          <Typography variant="body2">{data.executive_summary}</Typography>
        </Alert>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Chip
            label={`Threat Level: ${data.threat_level}`}
            color={
              data.threat_level === 'CRITICAL' || data.threat_level === 'HIGH' ? 'error' :
              data.threat_level === 'MEDIUM' ? 'warning' : 'info'
            }
          />
          <Chip label={`Campaign: ${data.campaign_name}`} />
          <Chip
            label={`Confidence: ${data.campaign_confidence}`}
            variant="outlined"
            color={
              data.campaign_confidence === 'HIGH' ? 'error' :
              data.campaign_confidence === 'MEDIUM' ? 'warning' : 'info'
            }
          />
        </Box>
      </Paper>

      {/* Campaign Evidence */}
      {data.campaign_evidence && data.campaign_evidence.length > 0 && (
        <Paper sx={{ p: 3, mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            🔍 캠페인 근거
          </Typography>
          <List>
            {data.campaign_evidence.map((evidence, index) => (
              <ListItem key={index}>
                <ListItemText primary={`• ${evidence}`} />
              </ListItem>
            ))}
          </List>
        </Paper>
      )}

      {/* MITRE ATT&CK Tactics */}
      {data.mitre_tactics && data.mitre_tactics.length > 0 && (
        <Paper sx={{ p: 3, mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            🎯 MITRE ATT&CK Tactics
          </Typography>
          <List>
            {data.mitre_tactics.map((tactic, index) => (
              <React.Fragment key={index}>
                <ListItem alignItems="flex-start">
                  <ListItemText
                    primary={
                      <Box sx={{ mb: 1 }}>
                        <Typography variant="subtitle1">{tactic.tactic}</Typography>
                        <Box sx={{ display: 'flex', gap: 0.5, mt: 0.5, flexWrap: 'wrap' }}>
                          {tactic.techniques.map((technique, idx) => (
                            <Chip key={idx} label={technique} size="small" color="primary" />
                          ))}
                        </Box>
                      </Box>
                    }
                    secondary={tactic.evidence}
                  />
                </ListItem>
                {index < data.mitre_tactics.length - 1 && <Divider />}
              </React.Fragment>
            ))}
          </List>
        </Paper>
      )}

      {/* Attack Chain TTPs */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          🔗 Attack Chain TTPs
        </Typography>
        <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap' }}>
          {data.attack_chain_ttps}
        </Typography>
      </Paper>

      {/* Threat Actor Attribution */}
      {data.threat_actor_attribution && (
        <Paper sx={{ p: 3, mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            👤 위협 행위자 추정
          </Typography>
          <Box sx={{ mb: 2 }}>
            {data.threat_actor_attribution.attributed_actor && (
              <Chip
                label={data.threat_actor_attribution.attributed_actor}
                color="error"
                sx={{ mr: 1 }}
              />
            )}
            <Chip
              label={`Confidence: ${data.threat_actor_attribution.confidence}`}
              variant="outlined"
              color={
                data.threat_actor_attribution.confidence === 'HIGH' ? 'error' :
                data.threat_actor_attribution.confidence === 'MEDIUM' ? 'warning' : 'info'
              }
            />
          </Box>
          {data.threat_actor_attribution.overlap_indicators && data.threat_actor_attribution.overlap_indicators.length > 0 && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Overlap Indicators:
              </Typography>
              <List dense>
                {data.threat_actor_attribution.overlap_indicators.map((indicator, index) => (
                  <ListItem key={index}>
                    <ListItemText primary={`• ${indicator}`} />
                  </ListItem>
                ))}
              </List>
            </Box>
          )}
          <Typography variant="body2" color="text.secondary">
            <strong>Attribution Rationale:</strong> {data.threat_actor_attribution.attribution_rationale}
          </Typography>
        </Paper>
      )}

      {/* Hunt Hypotheses */}
      {data.hunt_hypotheses && data.hunt_hypotheses.length > 0 && (
        <Paper sx={{ p: 3, mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            🎯 Hunt Hypotheses
          </Typography>
          {data.hunt_hypotheses.map((hypothesis, index) => (
            <Accordion key={index} sx={{ mb: 1 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: '100%' }}>
                  <Chip label={`#${hypothesis.hypothesis_id}`} size="small" color="primary" />
                  <Typography variant="subtitle2" sx={{ flexGrow: 1 }}>
                    {hypothesis.hypothesis_name}
                  </Typography>
                  <Chip
                    label={hypothesis.confidence}
                    size="small"
                    color={
                      hypothesis.confidence === 'HIGH' ? 'error' :
                      hypothesis.confidence === 'MEDIUM' ? 'warning' : 'info'
                    }
                    variant="outlined"
                  />
                  <Chip label={`Priority: ${hypothesis.priority}`} size="small" />
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Box>
                  <Typography variant="body2" sx={{ mb: 2 }}>
                    {hypothesis.hypothesis_description}
                  </Typography>
                  <Divider sx={{ my: 2 }} />
                  <Typography variant="subtitle2" gutterBottom>
                    Detection Platform: {hypothesis.detection_platform}
                  </Typography>
                  <Paper sx={{ p: 2, bgcolor: 'grey.100', mb: 2 }}>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
                      {hypothesis.executable_query}
                    </Typography>
                  </Paper>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    <strong>Timeline:</strong> {hypothesis.hunt_timeline}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    <strong>Success Criteria:</strong> {hypothesis.success_criteria}
                  </Typography>
                </Box>
              </AccordionDetails>
            </Accordion>
          ))}
        </Paper>
      )}

      {/* Extracted IOCs */}
      {data.extracted_iocs && data.extracted_iocs.length > 0 && (
        <Paper sx={{ p: 3, mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            📦 추출된 IOC 목록
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
                {data.extracted_iocs.map((ioc, index) => (
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

      {/* Recommended Actions */}
      {data.recommended_actions && data.recommended_actions.length > 0 && (
        <Paper sx={{ p: 3, mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            💡 권장 조치
          </Typography>
          <List>
            {data.recommended_actions.map((action, index) => (
              <ListItem key={index}>
                <ListItemText primary={`${index + 1}. ${action}`} />
              </ListItem>
            ))}
          </List>
        </Paper>
      )}

      {/* Intelligence Gaps */}
      {data.intelligence_gaps && data.intelligence_gaps.length > 0 && (
        <Paper sx={{ p: 3, mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            🔍 인텔리전스 갭
          </Typography>
          <List>
            {data.intelligence_gaps.map((gap, index) => (
              <ListItem key={index}>
                <ListItemText primary={`• ${gap}`} />
              </ListItem>
            ))}
          </List>
        </Paper>
      )}

      {/* Organizational Impact */}
      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" gutterBottom>
          🏢 추가 분석 및 대응 전략 제안
        </Typography>
        <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap' }}>
          {data.organizational_impact}
        </Typography>
      </Paper>
    </Box>
  );
}
