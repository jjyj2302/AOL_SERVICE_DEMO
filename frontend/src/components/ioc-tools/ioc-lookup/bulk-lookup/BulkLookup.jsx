import React, { useState, useCallback } from 'react';
import {
  Box, Typography, Alert, TextField, Button, Paper, Grid,
  Chip, LinearProgress, useTheme, CircularProgress
} from '@mui/material';
import { TextFields } from '@mui/icons-material';
import UploadFileIcon from '@mui/icons-material/UploadFile';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import StopIcon from '@mui/icons-material/Stop';
import AutoAwesomeIcon from '@mui/icons-material/AutoAwesome';
import SearchIcon from '@mui/icons-material/Search';
import { useBulkAgentProcessor } from './hooks/useBulkAgentProcessor';
import AgentAnalysisResults from './components/ui/AgentAnalysisResults';

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

const BulkLookup = () => {
  const theme = useTheme();
  const isDarkMode = theme.palette.mode === 'dark';
  const [iocsInput, setIocsInput] = useState('');
  const [formError, setFormError] = useState('');

  const {
    results: agentResults,
    aggregation,
    loading: processing,
    progress,
    processorError,
    setProcessorError,
    currentPhase,
    performAnalysis,
    cancelAnalysis,
  } = useBulkAgentProcessor();

  const handleIocsInputChange = useCallback((event) => {
    setIocsInput(event.target.value);
    if (processorError) setProcessorError('');
    if (formError) setFormError('');
  }, [processorError, setProcessorError, formError]);

  const handleDragOver = useCallback((event) => {
    event.preventDefault();
  }, []);

  const handleDrop = useCallback((event) => {
    event.preventDefault();
    if (processing) return;

    const files = event.dataTransfer.files;
    if (files.length === 0) return;

    const file = files[0];
    const allowedMimeTypes = ['text/csv', 'text/markdown', 'text/plain'];
    const allowedExtensions = ['.csv', '.md', '.txt'];
    const fileExtension = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();

    if (!allowedMimeTypes.includes(file.type) && !allowedExtensions.includes(fileExtension)) {
      setFormError(`잘못된 파일 형식입니다. CSV, MD 또는 TXT 파일을 업로드하세요.`);
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => setIocsInput(e.target.result);
    reader.onerror = () => setFormError(`파일 읽기 오류: ${file.name}`);
    reader.readAsText(file);
  }, [processing]);

  const handleSubmit = useCallback(() => {
    if (formError) setFormError('');
    performAnalysis(iocsInput, [], true);
  }, [formError, iocsInput, performAnalysis]);

  const isSubmitDisabled = processing || !iocsInput.trim();

  const cardStyle = {
    bgcolor: isDarkMode ? 'rgba(28, 28, 30, 0.6)' : COLORS.CARD_BG_LIGHT,
    borderRadius: '18px',
    border: isDarkMode ? '1px solid rgba(255,255,255,0.1)' : `1px solid ${COLORS.BORDER_LIGHT}`,
    boxShadow: isDarkMode ? 'none' : '0 4px 24px rgba(0,0,0,0.02)',
    transition: 'transform 0.2s ease-in-out',
    overflow: 'hidden'
  };

  return (
    <Box sx={{ fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif', maxWidth: 1600, mx: 'auto', px: 2 }}>
      {/* Hero Section */}
      <Paper sx={{ ...cardStyle, p: 3, mb: 2, background: isDarkMode ? 'linear-gradient(135deg, rgba(28,28,30,0.8) 0%, rgba(44,44,46,0.8) 100%)' : 'linear-gradient(135deg, #FFFFFF 0%, #F5F5F7 100%)' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 1 }}>
          <Box sx={{
            p: 1,
            borderRadius: '12px',
            bgcolor: isDarkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.05)',
            color: isDarkMode ? '#fff' : '#000000',
            display: 'flex'
          }}>
            <AutoAwesomeIcon sx={{ fontSize: 28 }} />
          </Box>
          <Box>
            <Typography variant="h6" sx={{ opacity: 0.8, color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY, fontWeight: 600, letterSpacing: '0.5px', fontSize: '0.9rem' }}>
              AI-Powered Intelligence
            </Typography>
            <Typography variant="h4" sx={{ fontWeight: 800, color: isDarkMode ? '#fff' : COLORS.TEXT_PRIMARY, letterSpacing: '-0.5px' }}>
              Bulk Analysis
            </Typography>
          </Box>
        </Box>
        <Typography variant="body1" sx={{ maxWidth: 1000, lineHeight: 1.5, color: isDarkMode ? '#ccc' : COLORS.TEXT_SECONDARY, fontSize: '1rem' }}>
          여러 개의 IOC(Indicators of Compromise)를 입력하면, AI 에이전트 팀이 병렬로 심층 분석을 수행하고
          위협 인텔리전스를 종합하여 제공합니다.
        </Typography>
      </Paper>

      {/* Input Section */}
      <Paper sx={{ ...cardStyle, p: 0, mb: 3 }}>
        <Box sx={{ p: 2, px: 3, borderBottom: isDarkMode ? '1px solid rgba(255,255,255,0.1)' : `1px solid ${COLORS.BORDER_LIGHT}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, color: isDarkMode ? '#fff' : '#000000', display: 'flex', alignItems: 'center', gap: 1, fontSize: '1.1rem' }}>
            <SearchIcon sx={{ color: isDarkMode ? '#fff' : '#000000' }} /> IOC 입력 및 업로드
          </Typography>
        </Box>
        <Box sx={{ p: 3 }}>
          <Grid container spacing={4}>
            {/* Text Input Section */}
            <Grid item xs={12} md={7}>
              <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
                <Typography variant="subtitle2" sx={{ mb: 1.5, fontWeight: 600, color: isDarkMode ? '#ccc' : COLORS.TEXT_SECONDARY }}>
                  직접 입력 (한 줄에 하나씩)
                </Typography>
                <TextField
                  placeholder="예: 192.168.1.1&#10;malicious-site.com&#10;a1b2c3d4e5..."
                  multiline
                  fullWidth
                  variant="outlined"
                  value={iocsInput}
                  onChange={handleIocsInputChange}
                  disabled={processing}
                  minRows={6}
                  maxRows={6}
                  sx={{
                    flex: 1,
                    '& .MuiOutlinedInput-root': {
                      borderRadius: '12px',
                      bgcolor: isDarkMode ? 'rgba(0,0,0,0.2)' : '#F5F5F7',
                      fontFamily: 'monospace',
                      fontSize: '0.95rem',
                      '& fieldset': { border: 'none' },
                      '&:hover fieldset': { border: 'none' },
                      '&.Mui-focused fieldset': { border: `2px solid ${COLORS.PRIMARY}` },
                    }
                  }}
                />
              </Box>
            </Grid>

            {/* File Drop Section */}
            <Grid item xs={12} md={5}>
              <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
                <Typography variant="subtitle2" sx={{ mb: 1.5, fontWeight: 600, color: isDarkMode ? '#ccc' : COLORS.TEXT_SECONDARY }}>
                  파일 업로드 (.txt, .csv, .md)
                </Typography>
                <Box
                  onDrop={handleDrop}
                  onDragOver={handleDragOver}
                  sx={{
                    flex: 1,
                    border: `2px dashed ${isDarkMode ? 'rgba(255,255,255,0.2)' : '#E5E5EA'}`,
                    borderRadius: '12px',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    cursor: processing ? 'not-allowed' : 'pointer',
                    transition: 'all 0.2s ease',
                    bgcolor: isDarkMode ? 'rgba(255,255,255,0.02)' : '#FAFAFA',
                    '&:hover': {
                      borderColor: processing ? undefined : COLORS.PRIMARY,
                      bgcolor: processing ? undefined : (isDarkMode ? 'rgba(10, 132, 255, 0.05)' : 'rgba(0, 122, 255, 0.02)')
                    }
                  }}
                >
                  <Box sx={{
                    p: 2,
                    borderRadius: '50%',
                    bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F0F0F2',
                    mb: 2
                  }}>
                    <UploadFileIcon sx={{ fontSize: 32, color: isDarkMode ? '#aaa' : COLORS.TEXT_SECONDARY }} />
                  </Box>
                  <Typography variant="body2" sx={{ color: isDarkMode ? '#ccc' : COLORS.TEXT_PRIMARY, fontWeight: 600, mb: 0.5 }}>
                    파일을 드래그하여 놓으세요
                  </Typography>
                  <Typography variant="caption" sx={{ color: isDarkMode ? '#888' : COLORS.TEXT_SECONDARY }}>
                    또는 클릭하여 선택
                  </Typography>
                </Box>
              </Box>
            </Grid>

            {/* Analyze Button Section */}
            <Grid item xs={12}>
              <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2, mt: 2 }}>
                {processing ? (
                  <Button
                    variant="contained"
                    onClick={cancelAnalysis}
                    startIcon={<StopIcon />}
                    size="large"
                    sx={{
                      minWidth: 200,
                      height: 50,
                      borderRadius: '25px',
                      bgcolor: COLORS.HIGH,
                      fontWeight: 700,
                      boxShadow: '0 4px 12px rgba(255, 59, 48, 0.3)',
                      '&:hover': { bgcolor: '#D70015' }
                    }}
                  >
                    분석 중단
                  </Button>
                ) : (
                  <Button
                    variant="contained"
                    onClick={handleSubmit}
                    disabled={isSubmitDisabled}
                    startIcon={<PlayArrowIcon />}
                    size="large"
                    sx={{
                      minWidth: 240,
                      height: 56,
                      borderRadius: '28px',
                      bgcolor: isDarkMode ? '#FFFFFF' : '#000000',
                      color: isDarkMode ? '#000000' : '#FFFFFF',
                      fontSize: '1.1rem',
                      fontWeight: 700,
                      boxShadow: isDarkMode ? '0 8px 20px rgba(255, 255, 255, 0.2)' : '0 8px 20px rgba(0, 0, 0, 0.3)',
                      '&:hover': {
                        bgcolor: isDarkMode ? '#E5E5E5' : '#333333',
                        transform: 'translateY(-2px)',
                        boxShadow: isDarkMode ? '0 12px 24px rgba(255, 255, 255, 0.3)' : '0 12px 24px rgba(0, 0, 0, 0.4)'
                      },
                      transition: 'all 0.2s ease',
                      '&.Mui-disabled': { bgcolor: isDarkMode ? 'rgba(255,255,255,0.1)' : '#E5E5EA' }
                    }}
                  >
                    Agent 분석 시작
                  </Button>
                )}
              </Box>
            </Grid>
          </Grid>
        </Box>
      </Paper>

      {/* Progress */}
      {processing && (
        <Paper sx={{ ...cardStyle, p: 3, mb: 4 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
              <CircularProgress size={20} sx={{ color: isDarkMode ? '#fff' : '#000000' }} />
              <Typography variant="subtitle1" fontWeight={600} sx={{ color: isDarkMode ? '#fff' : '#000000' }}>
                {currentPhase === 'phase1' && 'Phase 1: 개별 IOC 분석 중...'}
                {currentPhase === 'aggregation' && 'Phase 2: 종합 인텔리전스 생성 중...'}
                {currentPhase === 'complete' && '분석 완료'}
              </Typography>
            </Box>
            <Chip
              label={`${progress.completed}/${progress.total} (${progress.percentage?.toFixed(1) || 0}%)`}
              size="small"
              sx={{
                bgcolor: isDarkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.05)',
                color: isDarkMode ? '#fff' : '#000000',
                fontWeight: 700
              }}
            />
          </Box>
          <LinearProgress
            variant="determinate"
            value={progress.percentage || 0}
            sx={{
              height: 10,
              borderRadius: 5,
              bgcolor: isDarkMode ? 'rgba(255,255,255,0.1)' : '#E5E5EA',
              '& .MuiLinearProgress-bar': {
                bgcolor: isDarkMode ? '#fff' : '#000000',
                borderRadius: 5,
              }
            }}
          />
        </Paper>
      )}

      {/* Error Display */}
      {formError && (
        <Alert severity="error" sx={{ mb: 3, borderRadius: '12px' }}>
          {formError}
        </Alert>
      )}

      {/* Results */}
      <AgentAnalysisResults
        results={agentResults}
        aggregation={aggregation}
        loading={processing}
        currentPhase={currentPhase}
        error={processorError}
      />
    </Box>
  );
};

export default BulkLookup;
