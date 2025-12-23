import React, { useState } from 'react';
import { Box, Typography, TextField, InputAdornment, IconButton, Paper, Fade } from '@mui/material';
import { MdNetworkCheck, MdDomain, MdLink, MdEmail, MdFingerprint, MdBugReport } from 'react-icons/md';
import { Search as SearchIcon, Add as AddIcon, AutoAwesome as AutoAwesomeIcon } from '@mui/icons-material';

const IOC_TYPES = [
  { icon: MdNetworkCheck, label: "IP Address", color: "#4285F4" },
  { icon: MdDomain, label: "Domain", color: "#EA4335" },
  { icon: MdLink, label: "URL", color: "#FBBC04" },
  { icon: MdEmail, label: "Email", color: "#34A853" },
  { icon: MdFingerprint, label: "Hash", color: "#9C27B0" },
  { icon: MdBugReport, label: "CVE", color: "#FF6D00" },
];

const IocTypeCard = ({ icon: Icon, label, color }) => (
  <Paper
    elevation={0}
    sx={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      p: 2.5,
      borderRadius: 3,
      border: '1.5px solid',
      borderColor: 'divider',
      transition: 'all 0.2s ease-in-out',
      cursor: 'default',
      minHeight: 110,
      '&:hover': {
        borderColor: color,
        boxShadow: `0 4px 12px ${color}40`,
        transform: 'translateY(-2px)',
      },
    }}
  >
    <Icon size={38} style={{ color, marginBottom: 8 }} />
    <Typography variant="body2" fontWeight="medium" color="text.secondary" fontSize="0.9rem">
      {label}
    </Typography>
  </Paper>
);

export default function WelcomeScreen({ onSubmit }) {
  const [inputValue, setInputValue] = useState("");

  const handleKeyPress = (event) => {
    if (event.key === "Enter" && inputValue.trim()) {
      onSubmit(inputValue);
    }
  };

  const handleSearchClick = (e) => {
    e.preventDefault();
    if (inputValue.trim()) {
      onSubmit(inputValue);
    }
  };

  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '70vh',
        py: 4,
        maxWidth: '900px',
        mx: 'auto'
      }}
    >
      <Fade in={true} timeout={800}>
        <Box sx={{ width: '100%' }}>
          {/* Title Section */}
          <Box sx={{ textAlign: 'center', mb: 4 }}>
            <Typography
              variant="h3"
              component="h1"
              sx={{
                fontWeight: 700,
                background: 'linear-gradient(90deg, #4285F4 0%, #9C27B0 100%)',
                backgroundClip: 'text',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                mb: 2,
                fontSize: { xs: '2rem', md: '2.75rem' },
                letterSpacing: '-0.02em'
              }}
            >
              AOL Threat Intelligence
            </Typography>
            <Typography variant="h6" color="text.secondary" sx={{ fontSize: '1.15rem', opacity: 0.8 }}>
              어떤 위협을 분석해볼까요?
            </Typography>
          </Box>

          {/* IOC Type Icons */}
          <Box
            sx={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(125px, 1fr))',
              gap: 2,
              width: '100%',
              mb: 6,
            }}
          >
            {IOC_TYPES.map((type) => (
              <IocTypeCard key={type.label} {...type} />
            ))}
          </Box>

          {/* Floating Input Box */}
          <Box component="form" onSubmit={handleSearchClick} sx={{ width: "100%", position: "relative" }}>
            <TextField
              fullWidth
              placeholder="분석할 IOC를 입력하세요 (IP, Domain, URL, Email, Hash, CVE)..."
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyPress={handleKeyPress}
              sx={{
                "& .MuiOutlinedInput-root": {
                  bgcolor: "background.paper",
                  borderRadius: "24px",
                  pr: 1,
                  pl: 2,
                  height: "64px",
                  boxShadow: "0 4px 20px rgba(0,0,0,0.1)",
                  transition: "all 0.2s ease",
                  "& fieldset": { border: "1px solid", borderColor: "divider" },
                  "&:hover": {
                    boxShadow: "0 6px 24px rgba(0,0,0,0.15)",
                    "& fieldset": { borderColor: "primary.main" }
                  },
                  "&.Mui-focused": {
                    boxShadow: "0 8px 28px rgba(0,0,0,0.2)",
                    "& fieldset": { borderColor: "primary.main", borderWidth: 1 }
                  }
                },
                "& input": {
                  fontSize: "1.1rem",
                  ml: 1
                }
              }}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <IconButton sx={{ color: "text.secondary", p: 1 }}>
                      <AddIcon />
                    </IconButton>
                  </InputAdornment>
                ),
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton
                      onClick={handleSearchClick}
                      disabled={!inputValue.trim()}
                      sx={{
                        bgcolor: inputValue.trim() ? "primary.main" : "action.disabledBackground",
                        color: "white",
                        "&:hover": { bgcolor: "primary.dark" },
                        transition: "all 0.2s",
                        p: 1.5
                      }}
                    >
                      {inputValue.trim() ? <AutoAwesomeIcon /> : <SearchIcon />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />
          </Box>
        </Box>
      </Fade>
    </Box>
  );
}