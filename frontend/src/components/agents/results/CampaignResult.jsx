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
import GavelIcon from '@mui/icons-material/Gavel';
import PersonSearchIcon from '@mui/icons-material/PersonSearch';
import RecommendIcon from '@mui/icons-material/Recommend';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';

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
          background: (theme) => {
            const isDark = theme.palette.mode === 'dark';
            if (data.threat_level === 'CRITICAL' || data.threat_level === 'HIGH') {
              return isDark
                ? 'linear-gradient(135deg, #5d1f1f 0%, #3d1414 100%)'
                : 'linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%)';
            } else if (data.threat_level === 'MEDIUM') {
              return isDark
                ? 'linear-gradient(135deg, #5d3a1a 0%, #3d2610 100%)'
                : 'linear-gradient(135deg, #fff3e0 0%, #ffe0b2 100%)';
            } else {
              return isDark
                ? 'linear-gradient(135deg, #1e4620 0%, #0f2e11 100%)'
                : 'linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%)';
            }
          },
          color: (theme) => theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
          borderRadius: 2,
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

        <Divider sx={{ my: 2, bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.3)' : 'rgba(0,0,0,0.12)' }} />

        <Box
          sx={{
            p: 3,
            bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.15)' : 'rgba(0,0,0,0.08)',
            borderRadius: 2,
            border: (theme) => theme.palette.mode === 'dark' ? '2px solid rgba(255,255,255,0.3)' : '2px solid rgba(0,0,0,0.2)',
            mb: 2,
          }}
        >
          <Typography variant="body1" sx={{ lineHeight: 1.8, fontFamily: 'inherit' }}>
            {data.executive_summary}
          </Typography>
        </Box>

        <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
          <Chip
            icon={<ShieldIcon />}
            label={`Threat Level: ${data.threat_level}`}
            sx={{
              bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.2)' : 'rgba(0,0,0,0.15)',
              color: (theme) => theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
              border: (theme) => theme.palette.mode === 'dark' ? '1px solid rgba(255,255,255,0.3)' : '1px solid rgba(0,0,0,0.2)',
              fontSize: '1rem',
              fontWeight: 600,
              fontFamily: 'inherit',
            }}
          />
          <Chip
            icon={<FlagIcon />}
            label={`Confidence: ${data.campaign_confidence}`}
            sx={{
              bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.2)' : 'rgba(0,0,0,0.15)',
              color: (theme) => theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
              border: (theme) => theme.palette.mode === 'dark' ? '1px solid rgba(255,255,255,0.3)' : '1px solid rgba(0,0,0,0.2)',
              fontSize: '1rem',
              fontWeight: 600,
              fontFamily: 'inherit',
            }}
          />
        </Box>
      </Paper>

      {/* Campaign Evidence */}
      {data.campaign_evidence && data.campaign_evidence.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <SearchIcon sx={{ fontSize: 32 }} color="info" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              캠페인 근거
            </Typography>
          </Box>
          <Paper
            sx={{
              p: 3,
              background: (theme) => theme.palette.mode === 'dark'
                ? 'linear-gradient(135deg, #0d1f2d 0%, #082429 100%)'
                : 'linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%)',
              border: '2px solid',
              borderColor: 'info.light',
              borderRadius: 2,
            }}
          >
          <Grid container spacing={2}>
            {data.campaign_evidence.map((evidence, index) => (
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
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                      <Box
                        sx={{
                          minWidth: 32,
                          height: 32,
                          borderRadius: '50%',
                          bgcolor: 'info.main',
                          color: 'white',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontWeight: 700,
                        }}
                      >
                        {index + 1}
                      </Box>
                      <Typography variant="body2" sx={{ flex: 1, lineHeight: 1.7 }}>
                        {evidence}
                      </Typography>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Paper>
        </Box>
      )}

      {/* MITRE ATT&CK Tactics */}
      {data.mitre_tactics && data.mitre_tactics.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <GavelIcon sx={{ fontSize: 32 }} color="secondary" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              MITRE ATT&CK Tactics
            </Typography>
          </Box>
          <Paper
            sx={{
              p: 3,
              background: (theme) => theme.palette.mode === 'dark'
                ? 'linear-gradient(135deg, #250d2b 0%, #1a1229 100%)'
                : 'linear-gradient(135deg, #f3e5f5 0%, #e1bee7 100%)',
              border: '2px solid',
              borderColor: 'secondary.light',
              borderRadius: 2,
            }}
          >
          <Grid container spacing={2}>
            {data.mitre_tactics.map((tactic, index) => (
              <Grid item xs={12} key={index}>
                <Card
                  sx={{
                    bgcolor: (theme) => theme.palette.mode === 'dark' ? 'grey.900' : 'white',
                    '&:hover': {
                      boxShadow: 3,
                      transform: 'translateY(-2px)',
                      transition: 'all 0.2s',
                    },
                  }}
                >
                  <CardContent sx={{ p: 2.5 }}>
                    <Typography variant="subtitle1" fontWeight="bold" sx={{ mb: 1.5, color: 'secondary.main' }}>
                      {tactic.tactic}
                    </Typography>
                    <Box sx={{ display: 'flex', gap: 0.5, mb: 2, flexWrap: 'wrap' }}>
                      {tactic.techniques && tactic.techniques.map((technique, idx) => (
                        <Chip
                          key={idx}
                          label={technique}
                          size="small"
                          color="secondary"
                          variant="outlined"
                          sx={{ fontWeight: 500 }}
                        />
                      ))}
                    </Box>
                    <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                      {tactic.evidence}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Paper>
        </Box>
      )}

      {/* Attack Chain TTPs */}
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
          <TimelineIcon sx={{ fontSize: 32 }} color="warning" />
          <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
            공격 체인 TTPs
          </Typography>
        </Box>
        <Paper
          sx={{
            p: 3,
            background: (theme) => theme.palette.mode === 'dark'
              ? 'linear-gradient(135deg, #332b08 0%, #3d2610 100%)'
              : 'linear-gradient(135deg, #fff3e0 0%, #ffe0b2 100%)',
            border: '2px solid',
            borderColor: 'warning.light',
            borderRadius: 2,
          }}
        >
          <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap', lineHeight: 1.8 }}>
            {data.attack_chain_ttps}
          </Typography>
        </Paper>
      </Box>

      {/* Threat Actor Attribution */}
      {data.threat_actor_attribution && (
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <PersonSearchIcon sx={{ fontSize: 32 }} color="error" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              위협 행위자 추정
            </Typography>
          </Box>
          <Paper
            sx={{
              p: 3,
              background: (theme) => theme.palette.mode === 'dark'
                ? 'linear-gradient(135deg, #3d1414 0%, #5d1f1f 100%)'
                : 'linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%)',
              border: '2px solid',
              borderColor: 'error.light',
              borderRadius: 2,
            }}
          >
          <Box sx={{ mb: 3, display: 'flex', gap: 1.5, flexWrap: 'wrap' }}>
            {data.threat_actor_attribution.attributed_actor && (
              <Chip
                icon={<PersonSearchIcon />}
                label={data.threat_actor_attribution.attributed_actor}
                color="error"
                sx={{ fontWeight: 600, fontSize: '1rem' }}
              />
            )}
            <Chip
              icon={<FlagIcon />}
              label={`Confidence: ${data.threat_actor_attribution.confidence}`}
              color={
                data.threat_actor_attribution.confidence === 'HIGH' ? 'error' :
                data.threat_actor_attribution.confidence === 'MEDIUM' ? 'warning' : 'info'
              }
              sx={{ fontWeight: 600, fontSize: '1rem' }}
            />
          </Box>
          {data.threat_actor_attribution.overlap_indicators && data.threat_actor_attribution.overlap_indicators.length > 0 && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600, mb: 1.5 }}>
                Overlap Indicators
              </Typography>
              <Grid container spacing={1}>
                {data.threat_actor_attribution.overlap_indicators.map((indicator, index) => (
                  <Grid item xs={12} key={index}>
                    <Card sx={{ bgcolor: (theme) => theme.palette.mode === 'dark' ? 'grey.900' : 'white' }}>
                      <CardContent sx={{ p: 2 }}>
                        <Typography variant="body2">• {indicator}</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Box>
          )}
          {data.threat_actor_attribution.attribution_rationale && (
            <Box sx={{ mt: 2, p: 3, bgcolor: (theme) => theme.palette.mode === 'dark' ? 'grey.900' : 'white', borderRadius: 1, borderLeft: '4px solid', borderColor: 'error.main' }}>
              <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                <strong>Attribution Rationale:</strong> {data.threat_actor_attribution.attribution_rationale}
              </Typography>
            </Box>
          )}
        </Paper>
        </Box>
      )}

      {/* Hunt Hypotheses */}
      {data.hunt_hypotheses && data.hunt_hypotheses.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <SearchIcon sx={{ fontSize: 32 }} color="primary" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              헌트 가설
            </Typography>
          </Box>
          <Paper
            sx={{
              p: 3,
              background: (theme) => theme.palette.mode === 'dark'
                ? 'linear-gradient(135deg, #082429 0%, #0d3a42 100%)'
                : 'linear-gradient(135deg, #e0f2f1 0%, #b2dfdb 100%)',
              border: '2px solid',
              borderColor: 'primary.light',
              borderRadius: 2,
            }}
          >
          {data.hunt_hypotheses.map((hypothesis, index) => (
            <Accordion
              key={index}
              sx={{
                mb: 2,
                '&:before': { display: 'none' },
                bgcolor: (theme) => theme.palette.mode === 'dark' ? 'grey.900' : 'white',
                boxShadow: 2,
                '&:hover': {
                  boxShadow: 4,
                },
              }}
            >
              <AccordionSummary
                expandIcon={<ExpandMoreIcon />}
                sx={{
                  bgcolor: 'rgba(0, 150, 136, 0.08)',
                  '&:hover': { bgcolor: 'rgba(0, 150, 136, 0.12)' },
                }}
              >
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, width: '100%', flexWrap: 'wrap' }}>
                  <Chip
                    label={`#${hypothesis.hypothesis_id}`}
                    size="small"
                    sx={{
                      bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.2)' : 'primary.main',
                      color: (theme) => theme.palette.mode === 'dark' ? '#000000' : 'white',
                      fontWeight: 600
                    }}
                  />
                  <Typography variant="subtitle1" sx={{ flexGrow: 1, fontWeight: 600 }}>
                    {hypothesis.hypothesis_name}
                  </Typography>
                  <Chip
                    label={hypothesis.confidence}
                    size="small"
                    color={
                      hypothesis.confidence === 'HIGH' ? 'error' :
                      hypothesis.confidence === 'MEDIUM' ? 'warning' : 'info'
                    }
                    sx={{ fontWeight: 600 }}
                  />
                  <Chip
                    label={`Priority: ${hypothesis.priority}`}
                    size="small"
                    color="primary"
                    variant="outlined"
                    sx={{ fontWeight: 600 }}
                  />
                </Box>
              </AccordionSummary>
              <AccordionDetails sx={{ p: 3 }}>
                <Box>
                  <Typography variant="body2" sx={{ mb: 3, lineHeight: 1.8 }}>
                    {hypothesis.hypothesis_description}
                  </Typography>
                  <Divider sx={{ my: 2 }} />
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="subtitle2" gutterBottom fontWeight="medium" sx={{ mb: 1 }}>
                      Detection Platform
                    </Typography>
                    <Chip
                      label={hypothesis.detection_platform}
                      size="small"
                      color="primary"
                      sx={{ fontWeight: 600 }}
                    />
                  </Box>
                  <Box sx={{ mb: 3 }}>
                    <Typography variant="subtitle2" gutterBottom fontWeight="medium" sx={{ mb: 1 }}>
                      Executable Query
                    </Typography>
                    <Paper
                      sx={{
                        p: 2,
                        bgcolor: 'grey.900',
                        borderRadius: 1,
                        border: '1px solid',
                        borderColor: 'grey.300',
                      }}
                    >
                      <Typography
                        variant="body2"
                        sx={{
                          fontFamily: 'monospace',
                          whiteSpace: 'pre-wrap',
                          fontSize: '0.85rem',
                          color: '#00ff00',
                        }}
                      >
                        {hypothesis.executable_query}
                      </Typography>
                    </Paper>
                  </Box>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Card sx={{ bgcolor: 'rgba(33, 150, 243, 0.08)', border: '1px solid', borderColor: 'primary.light' }}>
                        <CardContent sx={{ p: 2 }}>
                          <Typography variant="caption" sx={{ fontWeight: 600, color: 'primary.main' }}>
                            Timeline
                          </Typography>
                          <Typography variant="body2" sx={{ mt: 0.5 }}>
                            {hypothesis.hunt_timeline}
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Card sx={{ bgcolor: 'rgba(76, 175, 80, 0.08)', border: '1px solid', borderColor: 'success.light' }}>
                        <CardContent sx={{ p: 2 }}>
                          <Typography variant="caption" sx={{ fontWeight: 600, color: 'success.main' }}>
                            Success Criteria
                          </Typography>
                          <Typography variant="body2" sx={{ mt: 0.5 }}>
                            {hypothesis.success_criteria}
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  </Grid>
                </Box>
              </AccordionDetails>
            </Accordion>
          ))}
        </Paper>
        </Box>
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
              background: (theme) => theme.palette.mode === 'dark'
                ? 'linear-gradient(135deg, #0d1f2d 0%, #082429 100%)'
                : 'linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%)',
              border: '2px solid',
              borderColor: 'info.light',
              borderRadius: 2,
            }}
          >
            <TableContainer sx={{ bgcolor: (theme) => theme.palette.mode === 'dark' ? 'grey.900' : 'white', borderRadius: 1 }}>
              <Table>
              <TableHead>
                <TableRow sx={{ bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(33, 150, 243, 0.15)' : 'rgba(33, 150, 243, 0.1)' }}>
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
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <RecommendIcon sx={{ fontSize: 32 }} color="success" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              권장 조치
            </Typography>
          </Box>
          <Paper
            sx={{
              p: 3,
              background: (theme) => theme.palette.mode === 'dark'
                ? 'linear-gradient(135deg, #0f2e11 0%, #1e4620 100%)'
                : 'linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%)',
              border: '2px solid',
              borderColor: 'success.light',
              borderRadius: 2,
            }}
          >
            <Grid container spacing={2}>
              {data.recommended_actions.map((action, index) => (
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
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                        <Box
                          sx={{
                            minWidth: 32,
                            height: 32,
                            borderRadius: '50%',
                            bgcolor: 'success.main',
                            color: 'white',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            fontWeight: 700,
                          }}
                        >
                          {index + 1}
                        </Box>
                        <Typography variant="body2" sx={{ flex: 1, lineHeight: 1.7 }}>
                          {action}
                        </Typography>
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </Box>
      )}

      {/* Intelligence Gaps */}
      {data.intelligence_gaps && data.intelligence_gaps.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
            <HelpOutlineIcon sx={{ fontSize: 32 }} color="warning" />
            <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
              인텔리전스 갭
            </Typography>
          </Box>
          <Paper
            sx={{
              p: 3,
              background: (theme) => theme.palette.mode === 'dark'
                ? 'linear-gradient(135deg, #332b08 0%, #4a3f0d 100%)'
                : 'linear-gradient(135deg, #fff8e1 0%, #ffecb3 100%)',
              border: '2px solid',
              borderColor: 'warning.light',
              borderRadius: 2,
            }}
          >
            <Grid container spacing={2}>
              {data.intelligence_gaps.map((gap, index) => (
                <Grid item xs={12} key={index}>
                  <Card
                    sx={{
                      bgcolor: (theme) => theme.palette.mode === 'dark' ? 'grey.900' : 'white',
                      borderLeft: '4px solid',
                      borderColor: 'warning.main',
                      '&:hover': {
                        boxShadow: 3,
                        transform: 'translateX(4px)',
                        transition: 'all 0.2s',
                      },
                    }}
                  >
                    <CardContent sx={{ p: 2 }}>
                      <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                        • {gap}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </Box>
      )}

      {/* Organizational Impact */}
      <Paper
        sx={{
          p: 4,
          background: (theme) => theme.palette.mode === 'dark'
            ? 'linear-gradient(135deg, #1a1229 0%, #2a1f3d 100%)'
            : 'linear-gradient(135deg, #f3e5f5 0%, #e1bee7 100%)',
          border: '2px solid',
          borderColor: 'secondary.light',
          borderRadius: 2,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 3 }}>
          <BusinessIcon sx={{ fontSize: 32 }} color="secondary" />
          <Typography variant="h4" sx={{ fontWeight: 600, fontFamily: 'inherit' }}>
            조직 영향 평가
          </Typography>
        </Box>
        <Box
          sx={{
            p: 3,
            bgcolor: (theme) => theme.palette.mode === 'dark' ? 'grey.900' : 'white',
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
            {data.organizational_impact}
          </Typography>
        </Box>
      </Paper>
    </Box>
  );
}
