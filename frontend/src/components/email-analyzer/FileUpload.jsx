import React, { useState } from "react";
import api from "../../api";
import { useDropzone } from "react-dropzone";
import {
  Button,
  Box,
  Grid,
  LinearProgress,
  Typography,
  Paper,
  useTheme,
  Stack,
  alpha,
  IconButton,
  Menu,
  MenuItem,
  Divider,
  Tooltip
} from "@mui/material";
import {
  Mail as MailIcon,
  MailOutline as MailOutlineIcon,
  MarkEmailRead as MarkEmailReadIcon,
  Error as ErrorIcon,
  Add as AddIcon,
  Settings as SettingsIcon,
  Send as SendIcon,
  Description as DescriptionIcon
} from "@mui/icons-material";
import Result from "./Result";

const isLightMode = (theme) => theme.palette.mode === 'light';

const capabilityCards = [
  { title: "Security Analysis", desc: "Performs basic security checks on .eml files" },
  { title: "IOC Extraction", desc: "Extracts and analyzes IOCs using OSINT services" },
  { title: "Attachment Analysis", desc: "Generates hash values for all email attachments" },
  { title: "Privacy-Friendly", desc: "Analyze attachments without exposing original files" }
];

export default function FileUpload() {
  const theme = useTheme();
  const [uploadProgress, setUploadProgress] = useState(0);
  const [file, setFile] = useState(null);
  const [showResult, setShowResult] = useState(false);
  const [menuAnchorEl, setMenuAnchorEl] = useState(null);
  const [settingsAnchorEl, setSettingsAnchorEl] = useState(null);

  const { getRootProps, getInputProps, acceptedFiles, isDragActive, isDragAccept, isDragReject } = useDropzone({
    accept: { "message/rfc822": [".eml"] },
    multiple: false,
  });

  const uploadFiles = (file) => {
    setUploadProgress(0);
    const formData = new FormData();
    formData.append("file", file);

    api.post(`/api/mailanalyzer/`, formData, {
      headers: { "Content-Type": "multipart/form-data" },
      onUploadProgress: (e) => setUploadProgress(Math.round((e.loaded * 100) / e.total)),
    })
    .then((res) => {
      setFile(res.data);
      setShowResult(true);
      setUploadProgress(0);
    })
    .catch((err) => {
      console.error(err);
      setUploadProgress(0);
    });
  };

  const handleAnalyze = () => acceptedFiles.length > 0 && uploadFiles(acceptedFiles[0]);

  const getIntroStyles = () => isLightMode(theme) ? {
    backgroundColor: theme.palette.background.default,
    border: '1px solid rgba(0,0,0,0.12)',
  } : {
    backgroundColor: alpha(theme.palette.background.paper, 0.6),
    backdropFilter: 'blur(10px)',
  };

  const getCardStyles = () => isLightMode(theme) ? {
    backgroundColor: theme.palette.background.default,
    border: '1px solid rgba(0,0,0,0.12)',
    '&:hover': { backgroundColor: theme.palette.background.paper, borderColor: 'rgba(0,0,0,0.2)', boxShadow: '0 2px 8px rgba(0,0,0,0.08)' }
  } : {
    backgroundColor: alpha(theme.palette.primary.main, 0.08),
    border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
    '&:hover': { backgroundColor: alpha(theme.palette.primary.main, 0.12), transform: 'translateY(-2px)' }
  };

  const getInputBarStyles = () => {
    const borderColor = isDragAccept ? theme.palette.success.main
      : isDragReject ? theme.palette.error.main
      : isLightMode(theme) ? 'rgba(0,0,0,0.12)' : alpha(theme.palette.primary.main, 0.2);

    return isLightMode(theme) ? {
      backgroundColor: theme.palette.background.default,
      border: `2px solid ${borderColor}`,
      borderRadius: '12px',
      '&:hover': {
        backgroundColor: theme.palette.background.paper,
        borderColor: isDragActive ? borderColor : 'rgba(0,0,0,0.2)',
        boxShadow: '0 2px 8px rgba(0,0,0,0.08)'
      }
    } : {
      backgroundColor: alpha(theme.palette.background.paper, 0.7),
      backdropFilter: 'blur(10px)',
      border: `2px solid ${borderColor}`,
      borderRadius: '50px',
      '&:hover': {
        borderColor: theme.palette.primary.main,
        boxShadow: `0 0 0 4px ${alpha(theme.palette.primary.main, 0.1)}`
      }
    };
  };

  const getDragIcon = () => {
    if (isDragAccept) return <MarkEmailReadIcon sx={{ color: 'success.main', fontSize: 28 }} />;
    if (isDragReject) return (
      <ErrorIcon sx={{
        color: 'error.main', fontSize: 28,
        animation: 'shake 0.5s',
        '@keyframes shake': {
          '0%, 100%': { transform: 'translateX(0)' },
          '25%': { transform: 'translateX(-4px)' },
          '75%': { transform: 'translateX(4px)' }
        }
      }} />
    );
    return <MailOutlineIcon sx={{ color: 'text.secondary', fontSize: 28 }} />;
  };

  const getDragText = () => {
    if (isDragAccept) return "파일을 놓으세요...";
    if (isDragReject) return ".eml 파일만 가능합니다";
    return ".eml 파일 드래그 또는 클릭하여 업로드";
  };

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto', py: 4 }}>
      {/* Introduction */}
      <Paper elevation={0} sx={{ p: 4, mb: 4, borderRadius: 2, ...getIntroStyles() }}>
        <Typography variant="h4" sx={{ mb: 3, fontWeight: 600, textAlign: 'center' }}>
          Email Analyzer
        </Typography>
        <Box sx={{ mb: 4 }}>
          <Typography paragraph color="text.secondary" sx={{ textAlign: 'center', maxWidth: 800, mx: 'auto' }}>
            Email Analyzer is a module that allows you to analyze .eml files for potential threats.
            To use the module, simply drag an .eml file into it. The module will then parse the file
            and perform basic security checks to identify any potential risks.
          </Typography>
          <Typography color="text.secondary" sx={{ textAlign: 'center', maxWidth: 800, mx: 'auto' }}>
            It also extracts all indicators of compromise (IOCs) from the file and makes it possible
            to analyze them using various open source intelligence (OSINT) services.
          </Typography>
        </Box>

        <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>Capabilities</Typography>
        <Grid container spacing={2}>
          {capabilityCards.map((card, idx) => (
            <Grid item xs={12} sm={6} md={3} key={idx}>
              <Paper elevation={0} sx={{ p: 2.5, borderRadius: 2, transition: 'all 0.2s ease', ...getCardStyles() }}>
                <Typography color="primary" fontWeight="medium" sx={{ mb: 0.5 }}>{card.title}</Typography>
                <Typography variant="body2" color="text.secondary">{card.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Upload Section */}
      <Stack spacing={3} alignItems="center" sx={{ mb: 4 }}>
        <Paper elevation={0} sx={{ width: '100%', maxWidth: 900, p: 1.5, display: 'flex', alignItems: 'center', gap: 1, transition: 'all 0.2s ease', ...getInputBarStyles() }}>
          {/* Menu */}
          <Tooltip title="메뉴">
            <IconButton onClick={(e) => setMenuAnchorEl(e.currentTarget)} sx={{ color: 'primary.main' }}>
              <AddIcon />
            </IconButton>
          </Tooltip>
          <Menu anchorEl={menuAnchorEl} open={Boolean(menuAnchorEl)} onClose={() => setMenuAnchorEl(null)}>
            <MenuItem onClick={() => { window.location.reload(); setMenuAnchorEl(null); }}>
              <DescriptionIcon sx={{ mr: 1, fontSize: 20 }} /> 새 분석
            </MenuItem>
            <Divider />
            <MenuItem onClick={() => setMenuAnchorEl(null)}>
              <SettingsIcon sx={{ mr: 1, fontSize: 20 }} /> 설정
            </MenuItem>
          </Menu>

          {/* Dropzone */}
          <Box {...getRootProps()} sx={{ flex: 1, py: 1, px: 2, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 1, borderRadius: '40px', transition: 'background-color 0.2s', backgroundColor: isDragActive ? alpha(theme.palette.primary.main, 0.08) : 'transparent', '&:hover': { backgroundColor: alpha(theme.palette.action.hover, 0.04) } }}>
            <input {...getInputProps()} />
            {acceptedFiles.length > 0 ? (
              <Stack direction="row" alignItems="center" spacing={1} sx={{ width: '100%' }}>
                <MailIcon sx={{ color: 'primary.main', fontSize: 24 }} />
                <Box sx={{ flex: 1 }}>
                  <Typography variant="body2" fontWeight="medium">{acceptedFiles[0].name}</Typography>
                  <Typography variant="caption" color="text.secondary">{(acceptedFiles[0].size / 1024).toFixed(2)} KB</Typography>
                </Box>
              </Stack>
            ) : (
              <Stack direction="row" alignItems="center" spacing={1.5} sx={{ flex: 1 }}>
                {getDragIcon()}
                <Typography variant="body1" color={isDragAccept ? "success.main" : isDragReject ? "error.main" : "text.secondary"} sx={{ fontWeight: isDragActive ? 500 : 400 }}>
                  {getDragText()}
                </Typography>
              </Stack>
            )}
          </Box>

          <Divider orientation="vertical" flexItem sx={{ mx: 0.5 }} />

          {/* Settings */}
          <Tooltip title="분석 옵션">
            <IconButton onClick={(e) => setSettingsAnchorEl(e.currentTarget)} size="small">
              <SettingsIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          <Menu anchorEl={settingsAnchorEl} open={Boolean(settingsAnchorEl)} onClose={() => setSettingsAnchorEl(null)}>
            <MenuItem onClick={() => setSettingsAnchorEl(null)}>전체 분석</MenuItem>
            <MenuItem onClick={() => setSettingsAnchorEl(null)}>IOC만 추출</MenuItem>
            <MenuItem onClick={() => setSettingsAnchorEl(null)}>빠른 스캔</MenuItem>
          </Menu>

          {/* Analyze Button */}
          <Button
            variant="contained"
            onClick={handleAnalyze}
            disabled={acceptedFiles.length === 0 || uploadProgress > 0}
            startIcon={uploadProgress > 0 ? null : <SendIcon />}
            sx={{
              borderRadius: '40px',
              px: 3,
              textTransform: 'none',
              fontWeight: 600,
              background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
              '&:hover': { background: 'linear-gradient(135deg, #764ba2 0%, #667eea 100%)' },
              '&:disabled': { background: theme.palette.action.disabledBackground }
            }}
          >
            {uploadProgress > 0 ? `${uploadProgress}%` : "Analyze"}
          </Button>
        </Paper>

        {/* Progress Bar */}
        {uploadProgress > 0 && uploadProgress < 100 && (
          <Box sx={{ width: '100%', maxWidth: 900 }}>
            <LinearProgress variant="determinate" value={uploadProgress} sx={{ height: 6, borderRadius: 3, backgroundColor: alpha(theme.palette.primary.main, 0.1), '& .MuiLinearProgress-bar': { borderRadius: 3, background: 'linear-gradient(90deg, #667eea 0%, #764ba2 100%)' } }} />
          </Box>
        )}
      </Stack>

      {/* Result */}
      {showResult && <Box sx={{ mt: 4 }}><Result result={file} /></Box>}
    </Box>
  );
}
