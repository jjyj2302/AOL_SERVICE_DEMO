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
  Card,
  CardContent,
  Grid,
  LinearProgress,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import CampaignIcon from '@mui/icons-material/Campaign';
import ShieldIcon from '@mui/icons-material/Shield';
import GpsFixedIcon from '@mui/icons-material/GpsFixed';
import TimelineIcon from '@mui/icons-material/Timeline';
import PersonIcon from '@mui/icons-material/Person';
import SearchIcon from '@mui/icons-material/Search';
import LightbulbIcon from '@mui/icons-material/Lightbulb';
import ReportProblemIcon from '@mui/icons-material/ReportProblem';
import BusinessIcon from '@mui/icons-material/Business';
import FlagIcon from '@mui/icons-material/Flag';

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
          height: 8,
          borderRadius: 4,
          bgcolor: 'grey.200',
        }}
      />
    </Box>
  );
};

export default function CampaignResult({ data }) {
  if (!data) return null;

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
            : 'linear-gradient(135deg, #2196f3 0%, #1976d2 100%)',
          color: 'white',
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

        <Box sx={{ display: 'flex', gap: 2, mb: 3, flexWrap: 'wrap' }}>
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

        <Box
          sx={{
            p: 3,
            bgcolor: 'rgba(255,255,255,0.15)',
            borderRadius: 2,
            border: '1px solid rgba(255,255,255,0.3)',
          }}
        >
          <Typography variant="h6" sx={{ mb: 1.5, fontWeight: 600 }}>
            Executive Summary
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.8, fontFamily: 'inherit' }}>
            {data.executive_summary}
          </Typography>
        </Box>
      </Paper>

      {/* Campaign Evidence */}
      {data.campaign_evidence && data.campaign_evidence.length > 0 && (
        <Paper sx={{
          p: 3,
          mb: 3,
          background: 'linear-gradient(135deg, #2196f3 0%, #1976d2 100%)',
          color: 'white',
        }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <GpsFixedIcon sx={{ fontSize: 32 }} />
            <Typography variant="h5" sx={{ fontWeight: 600 }}>
              캠페인 근거
            </Typography>
          </Box>
          <Divider sx={{ my: 2, bgcolor: 'rgba(255,255,255,0.3)' }} />
          <List>
            {data.campaign_evidence.map((evidence, index) => (
              <ListItem key={index}>
                <Card sx={{
                  width: '100%',
                  bgcolor: 'rgba(255,255,255,0.15)',
                  border: '1px solid rgba(255,255,255,0.3)',
                  mb: 1,
                }}>
                  <CardContent sx={{ p: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
                      <Box sx={{
                        minWidth: 28,
                        height: 28,
                        borderRadius: '50%',
                        bgcolor: 'rgba(255,255,255,0.3)',
                        color: 'white',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontWeight: 700,
                        fontSize: '0.875rem',
                      }}>
                        {index + 1}
                      </Box>
                      <Typography sx={{ flex: 1, color: 'white', lineHeight: 1.8 }}>
                        {evidence}
                      </Typography>
                    </Box>
                  </CardContent>
                </Card>
              </ListItem>
            ))}
          </List>
        </Paper>
      )}

      {/* MITRE ATT&CK Tactics */}
      {data.mitre_tactics && data.mitre_tactics.length > 0 && (
        <Paper sx={{
          p: 3,
          mb: 3,
          background: 'linear-gradient(135deg, #9c27b0 0%, #7b1fa2 100%)',
          color: 'white',
        }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <ShieldIcon sx={{ fontSize: 32 }} />
            <Typography variant="h5" sx={{ fontWeight: 600 }}>
              MITRE ATT&CK Tactics
            </Typography>
          </Box>
          <Divider sx={{ my: 2, bgcolor: 'rgba(255,255,255,0.3)' }} />
          <Grid container spacing={2}>
            {data.mitre_tactics.map((tactic, index) => (
              <Grid item xs={12} md={6} key={index}>
                <Card sx={{
                  height: '100%',
                  bgcolor: 'rgba(255,255,255,0.15)',
                  border: '1px solid rgba(255,255,255,0.3)',
                }}>
                  <CardContent>
                    <Typography variant="h6" sx={{ color: 'white', fontWeight: 600, mb: 1 }}>
                      {tactic.tactic}
                    </Typography>
                    {tactic.techniques && tactic.techniques.length > 0 && (
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.8)', mb: 1, display: 'block' }}>
                          Techniques:
                        </Typography>
                        <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                          {tactic.techniques.map((technique, idx) => (
                            <Chip
                              key={idx}
                              label={technique}
                              size="small"
                              sx={{
                                bgcolor: 'rgba(255,255,255,0.25)',
                                color: 'white',
                                fontWeight: 600,
                              }}
                            />
                          ))}
                        </Box>
                      </Box>
                    )}
                    {tactic.evidence && (
                      <Box sx={{ p: 2, bgcolor: 'rgba(0,0,0,0.2)', borderRadius: 1 }}>
                        <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.9)', lineHeight: 1.6 }}>
                          <strong>Evidence:</strong> {tactic.evidence}
                        </Typography>
                      </Box>
                    )}
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Paper>
      )}

      {/* Attack Chain TTPs */}
      <Paper sx={{
        p: 3,
        mb: 3,
        background: 'linear-gradient(135deg, #ff9800 0%, #f57c00 100%)',
        color: 'white',
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
          <TimelineIcon sx={{ fontSize: 32 }} />
          <Typography variant="h5" sx={{ fontWeight: 600 }}>
            Attack Chain TTPs
          </Typography>
        </Box>
        <Divider sx={{ my: 2, bgcolor: 'rgba(255,255,255,0.3)' }} />
        <Box sx={{
          p: 2,
          bgcolor: 'rgba(255,255,255,0.15)',
          borderRadius: 1,
          border: '1px solid rgba(255,255,255,0.3)',
        }}>
          <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap', lineHeight: 1.8 }}>
            {data.attack_chain_ttps}
          </Typography>
        </Box>
      </Paper>

      {/* Threat Actor Attribution */}
      {data.threat_actor_attribution && (
        <Paper sx={{
          p: 3,
          mb: 3,
          background: 'linear-gradient(135deg, #f44336 0%, #d32f2f 100%)',
          color: 'white',
        }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <PersonIcon sx={{ fontSize: 32 }} />
            <Typography variant="h5" sx={{ fontWeight: 600 }}>
              위협 행위자 추정
            </Typography>
          </Box>
          <Divider sx={{ my: 2, bgcolor: 'rgba(255,255,255,0.3)' }} />
          <Grid container spacing={2} sx={{ mb: 2 }}>
            {data.threat_actor_attribution.attributed_actor && (
              <Grid item xs={12} md={6}>
                <Card sx={{ bgcolor: 'rgba(255,255,255,0.15)', border: '1px solid rgba(255,255,255,0.3)' }}>
                  <CardContent>
                    <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.8)', mb: 0.5, display: 'block' }}>
                      Attributed Actor:
                    </Typography>
                    <Typography variant="h6" sx={{ color: 'white', fontWeight: 600 }}>
                      {data.threat_actor_attribution.attributed_actor}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            )}
            <Grid item xs={12} md={6}>
              <Card sx={{ bgcolor: 'rgba(255,255,255,0.15)', border: '1px solid rgba(255,255,255,0.3)' }}>
                <CardContent>
                  <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.8)', mb: 0.5, display: 'block' }}>
                    Confidence:
                  </Typography>
                  <Chip
                    label={data.threat_actor_attribution.confidence}
                    sx={{
                      bgcolor: 'rgba(255,255,255,0.25)',
                      color: 'white',
                      fontWeight: 600,
                    }}
                  />
                </CardContent>
              </Card>
            </Grid>
          </Grid>
          {data.threat_actor_attribution.overlap_indicators && data.threat_actor_attribution.overlap_indicators.length > 0 && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
                Overlap Indicators:
              </Typography>
              {data.threat_actor_attribution.overlap_indicators.map((indicator, index) => (
                <Card key={index} sx={{
                  bgcolor: 'rgba(255,255,255,0.15)',
                  border: '1px solid rgba(255,255,255,0.3)',
                  mb: 1,
                }}>
                  <CardContent sx={{ p: 2 }}>
                    <Typography sx={{ color: 'white', lineHeight: 1.6 }}>
                      • {indicator}
                    </Typography>
                  </CardContent>
                </Card>
              ))}
            </Box>
          )}
          <Box sx={{
            p: 2,
            bgcolor: 'rgba(0,0,0,0.2)',
            borderRadius: 1,
            border: '1px solid rgba(255,255,255,0.3)',
          }}>
            <Typography variant="body2" sx={{ color: 'white', lineHeight: 1.8 }}>
              <strong>Attribution Rationale:</strong> {data.threat_actor_attribution.attribution_rationale}
            </Typography>
          </Box>
        </Paper>
      )}

      {/* Hunt Hypotheses */}
      {data.hunt_hypotheses && data.hunt_hypotheses.length > 0 && (
        <Paper sx={{
          p: 3,
          mb: 3,
          background: 'linear-gradient(135deg, #00bcd4 0%, #0097a7 100%)',
          color: 'white',
        }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <SearchIcon sx={{ fontSize: 32 }} />
            <Typography variant="h5" sx={{ fontWeight: 600 }}>
              Hunt Hypotheses
            </Typography>
          </Box>
          <Divider sx={{ my: 2, bgcolor: 'rgba(255,255,255,0.3)' }} />
          <Grid container spacing={2}>
            {data.hunt_hypotheses.map((hypothesis, index) => (
              <Grid item xs={12} key={index}>
                <Card sx={{
                  bgcolor: 'rgba(255,255,255,0.15)',
                  border: '1px solid rgba(255,255,255,0.3)',
                  mb: 1,
                }}>
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2, flexWrap: 'wrap' }}>
                      <Chip
                        label={`#${hypothesis.hypothesis_id}`}
                        sx={{
                          bgcolor: 'rgba(255,255,255,0.3)',
                          color: 'white',
                          fontWeight: 700,
                        }}
                      />
                      <Typography variant="h6" sx={{ flexGrow: 1, color: 'white', fontWeight: 600 }}>
                        {hypothesis.hypothesis_name}
                      </Typography>
                      <Chip
                        label={hypothesis.confidence}
                        sx={{
                          bgcolor: hypothesis.confidence === 'HIGH' ? 'rgba(244, 67, 54, 0.8)' :
                                   hypothesis.confidence === 'MEDIUM' ? 'rgba(255, 152, 0, 0.8)' : 'rgba(33, 150, 243, 0.8)',
                          color: 'white',
                          fontWeight: 600,
                        }}
                      />
                      <Chip
                        label={`Priority: ${hypothesis.priority}`}
                        sx={{
                          bgcolor: 'rgba(255,255,255,0.3)',
                          color: 'white',
                          fontWeight: 600,
                        }}
                      />
                    </Box>
                    <Typography variant="body1" sx={{ mb: 2, color: 'black', lineHeight: 1.8 }}>
                      {hypothesis.hypothesis_description}
                    </Typography>
                    <Divider sx={{ my: 2, bgcolor: 'rgba(255,255,255,0.3)' }} />
                    <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1, color: 'black' }}>
                      Detection Platform: {hypothesis.detection_platform}
                    </Typography>
                    <Box sx={{ p: 2, bgcolor: 'rgba(0,0,0,0.3)', borderRadius: 1, mb: 2 }}>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace', whiteSpace: 'pre-wrap', color: 'rgba(255,255,255,0.95)' }}>
                        {hypothesis.executable_query}
                      </Typography>
                    </Box>
                    <Typography variant="body2" sx={{ mb: 1, color: 'rgba(255,255,255,0.9)' }}>
                      <strong>Timeline:</strong> {hypothesis.hunt_timeline}
                    </Typography>
                    <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.9)' }}>
                      <strong>Success Criteria:</strong> {hypothesis.success_criteria}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Paper>
      )}

      {/* Extracted IOCs */}
      {data.extracted_iocs && data.extracted_iocs.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <SearchIcon sx={{ fontSize: 32 }} color="info" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              추출된 IOC 목록
            </Typography>
          </Box>
          <Paper
            sx={{
              p: 3,
              background: 'linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%)',
              border: '2px solid',
              borderColor: 'info.light',
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
                {data.extracted_iocs.map((ioc, index) => (
                  <TableRow
                    key={index}
                    sx={{
                      bgcolor: 'white',
                      '&:hover': {
                        bgcolor: 'rgba(33, 150, 243, 0.08)',
                        transform: 'scale(1.005)',
                        transition: 'all 0.2s',
                      },
                    }}
                  >
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.9rem', fontWeight: 600, color: 'info.dark' }}>
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
                        variant="outlined"
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
        <Paper sx={{
          p: 3,
          mb: 3,
          background: 'linear-gradient(135deg, #4caf50 0%, #388e3c 100%)',
          color: 'white',
        }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <LightbulbIcon sx={{ fontSize: 32 }} />
            <Typography variant="h5" sx={{ fontWeight: 600 }}>
              권장 조치
            </Typography>
          </Box>
          <Divider sx={{ my: 2, bgcolor: 'rgba(255,255,255,0.3)' }} />
          <Grid container spacing={1}>
            {data.recommended_actions.map((action, index) => (
              <Grid item xs={12} key={index}>
                <Card sx={{
                  bgcolor: 'rgba(255,255,255,0.15)',
                  border: '1px solid rgba(255,255,255,0.3)',
                  '&:hover': {
                    boxShadow: 3,
                    bgcolor: 'rgba(255,255,255,0.25)',
                    transform: 'translateX(4px)',
                    transition: 'all 0.2s',
                  },
                }}>
                  <CardContent sx={{ p: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
                      <Box sx={{
                        minWidth: 32,
                        height: 32,
                        borderRadius: '4px',
                        bgcolor: 'rgba(255,255,255,0.3)',
                        color: 'white',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontWeight: 700,
                      }}>
                        {index + 1}
                      </Box>
                      <Typography variant="body1" sx={{ flex: 1, lineHeight: 1.8, fontWeight: 500, color: 'white' }}>
                        {action}
                      </Typography>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Paper>
      )}

      {/* Intelligence Gaps */}
      {data.intelligence_gaps && data.intelligence_gaps.length > 0 && (
        <Paper sx={{
          p: 3,
          mb: 3,
          background: 'linear-gradient(135deg, #ffc107 0%, #ffa000 100%)',
          color: 'white',
        }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <ReportProblemIcon sx={{ fontSize: 32 }} />
            <Typography variant="h5" sx={{ fontWeight: 600 }}>
              인텔리전스 갭
            </Typography>
          </Box>
          <Divider sx={{ my: 2, bgcolor: 'rgba(255,255,255,0.3)' }} />
          <Grid container spacing={1}>
            {data.intelligence_gaps.map((gap, index) => (
              <Grid item xs={12} key={index}>
                <Card sx={{
                  bgcolor: 'rgba(255,255,255,0.15)',
                  border: '1px solid rgba(255,255,255,0.3)',
                  '&:hover': {
                    boxShadow: 3,
                    bgcolor: 'rgba(255,255,255,0.25)',
                    transform: 'translateX(4px)',
                    transition: 'all 0.2s',
                  },
                }}>
                  <CardContent sx={{ p: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
                      <Box sx={{
                        minWidth: 28,
                        height: 28,
                        borderRadius: '50%',
                        bgcolor: 'rgba(255,255,255,0.3)',
                        color: 'white',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontWeight: 700,
                        fontSize: '0.875rem',
                      }}>
                        {index + 1}
                      </Box>
                      <Typography variant="body1" sx={{ flex: 1, lineHeight: 1.8, color: 'white' }}>
                        {gap}
                      </Typography>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Paper>
      )}

      {/* Organizational Impact */}
      <Paper sx={{
        p: 4,
        background: 'linear-gradient(135deg, #673ab7 0%, #512da8 100%)',
        color: 'white',
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 3 }}>
          <BusinessIcon sx={{ fontSize: 32 }} />
          <Typography variant="h5" sx={{ fontWeight: 600 }}>
            추가 분석 및 대응 전략 제안
          </Typography>
        </Box>
        <Divider sx={{ my: 2, bgcolor: 'rgba(255,255,255,0.3)' }} />
        <Box sx={{
          p: 3,
          bgcolor: 'rgba(255,255,255,0.15)',
          borderRadius: 2,
          borderLeft: '6px solid rgba(255,255,255,0.5)',
        }}>
          <Typography variant="body1" sx={{
            whiteSpace: 'pre-wrap',
            lineHeight: 2,
            fontFamily: 'inherit',
            fontSize: '1rem',
          }}>
            {data.organizational_impact}
          </Typography>
        </Box>
      </Paper>
    </Box>
  );
}
