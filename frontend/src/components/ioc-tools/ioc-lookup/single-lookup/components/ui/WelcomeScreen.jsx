import React, { useState } from 'react';
import { Box, Typography, TextField, InputAdornment, IconButton, Paper } from '@mui/material';
import { MdNetworkCheck, MdDomain, MdLink, MdEmail, MdFingerprint, MdBugReport, MdSearch } from 'react-icons/md';

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

  const handleSearchClick = () => {
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
      }}
    >
      {/* Title Section */}
      <Box sx={{ textAlign: 'center', mb: 2.5 }}>
        <Typography
          variant="h3"
          component="h1"
          sx={{
            fontWeight: 600,
            background: 'linear-gradient(90deg, #1976d2 0%, #42a5f5 100%)',
            backgroundClip: 'text',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            mb: 2,
            fontSize: '2.75rem',
          }}
        >
          AOL Threat Intelligence
        </Typography>
        <Typography variant="h6" color="text.secondary" sx={{ mb: 4, fontSize: '1.15rem' }}>
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
          maxWidth: 900,
          mb: 4,
        }}
      >
        {IOC_TYPES.map((type) => (
          <IocTypeCard key={type.label} {...type} />
        ))}
      </Box>

      {/* Search Input */}
      <Box sx={{ width: '100%', maxWidth: 900 }}>
        <TextField
          fullWidth
          variant="outlined"
          placeholder="Enter an IOC to analyze (IP, Domain, URL, Email, Hash, CVE)..."
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          onKeyPress={handleKeyPress}
          sx={{
            '& .MuiOutlinedInput-root': {
              borderRadius: 50,
              backgroundColor: 'background.paper',
              pr: 1,
              fontSize: '1.05rem',
              '&:hover fieldset': {
                borderColor: 'primary.main',
              },
              '&.Mui-focused fieldset': {
                borderWidth: 2,
              },
            },
            '& .MuiOutlinedInput-input': {
              padding: '16px 20px',
              fontSize: '1.05rem',
            },
          }}
          InputProps={{
            endAdornment: (
              <InputAdornment position="end">
                <IconButton
                  onClick={handleSearchClick}
                  disabled={!inputValue.trim()}
                  sx={{
                    width: 45,
                    height: 45,
                    backgroundColor: 'primary.main',
                    color: 'white',
                    '&:hover': {
                      backgroundColor: 'primary.dark',
                    },
                    '&.Mui-disabled': {
                      backgroundColor: 'action.disabledBackground',
                    },
                  }}
                >
                  <MdSearch size={26} />
                </IconButton>
              </InputAdornment>
            ),
          }}
        />
      </Box>
    </Box>
  );
}