import React, { useState, useRef, useCallback, useEffect } from "react";
import {
  Alert,
  AlertTitle,
  Box,
  Grow,
  Typography,
  Chip,
  Paper,
  Grid,
} from "@mui/material";
import { useLocation } from "react-router-dom";
import PublicIcon from "@mui/icons-material/Public";
import LanguageIcon from "@mui/icons-material/Language";
import LinkIcon from "@mui/icons-material/Link";
import EmailIcon from "@mui/icons-material/Email";
import FingerprintIcon from "@mui/icons-material/Fingerprint";
import BugReportIcon from "@mui/icons-material/BugReport";
import ResultTable from "./components/ui/ResultTable";
import SearchBar from "../../../styled/SearchBar";
import { determineIocType } from "../shared/utils/iocDefinitions";

const STORAGE_KEY = "aol_ioc_search_history";
const MAX_HISTORY = 50;

// Example IOCs for quick search
const EXAMPLE_IOCS = [
  { label: "8.8.8.8", type: "IP Address" },
  { label: "google.com", type: "Domain" },
  { label: "malware@example.com", type: "Email" },
  { label: "44d88612fea8a8f36de82e1278abb02f", type: "MD5 Hash" },
  { label: "CVE-2021-44228", type: "CVE" },
  { label: "https://example.com/malware", type: "URL" },
];

// IOC Types with icons and descriptions
const IOC_TYPES = [
  {
    icon: <PublicIcon />,
    title: "IP Address",
    description: "IPv4 and IPv6 addresses",
    color: "#2196F3",
  },
  {
    icon: <LanguageIcon />,
    title: "Domain",
    description: "Domain names and subdomains",
    color: "#4CAF50",
  },
  {
    icon: <LinkIcon />,
    title: "URL",
    description: "Web addresses and endpoints",
    color: "#FF9800",
  },
  {
    icon: <EmailIcon />,
    title: "Email",
    description: "Email addresses",
    color: "#9C27B0",
  },
  {
    icon: <FingerprintIcon />,
    title: "Hash",
    description: "MD5, SHA1, SHA256",
    color: "#F44336",
  },
  {
    icon: <BugReportIcon />,
    title: "CVE",
    description: "Vulnerability identifiers",
    color: "#FF5722",
  },
];

const Analyzer = () => {
  const [searchValue, setSearchValue] = useState("");
  const [currentIocType, setCurrentIocType] = useState("");
  const [isInputInvalid, setIsInputInvalid] = useState(false);
  const [shouldShowTable, setShouldShowTable] = useState(false);
  const inputRef = useRef(null);
  const location = useLocation();

  // Save search to history
  const saveToHistory = useCallback((ioc, iocType) => {
    const newEntry = {
      id: Date.now(),
      ioc,
      iocType,
      timestamp: new Date().toISOString(),
    };

    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      const currentHistory = stored ? JSON.parse(stored) : [];

      // Remove duplicate if exists
      const filtered = currentHistory.filter((item) => item.ioc !== ioc);
      // Add new entry at the beginning
      const updated = [newEntry, ...filtered].slice(0, MAX_HISTORY);

      // Save to localStorage
      localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));

      // Dispatch event to notify Main component
      window.dispatchEvent(new Event("iocHistoryUpdate"));
    } catch (error) {
      console.error("Failed to save search history:", error);
    }
  }, []);

  const handleValidation = useCallback((iocInput) => {
    const trimmedIoc = iocInput.trim();

    if (!trimmedIoc) {
      setShouldShowTable(false);
      setIsInputInvalid(false);
      setSearchValue("");
      setCurrentIocType("");
      return false;
    }

    const type = determineIocType(trimmedIoc);

    if (type !== 'unknown') {
      setIsInputInvalid(false);
      setSearchValue(trimmedIoc);
      setCurrentIocType(type);
      setShouldShowTable(true);
      saveToHistory(trimmedIoc, type);
      return true;
    } else {
      setShouldShowTable(false);
      setIsInputInvalid(true);
      return false;
    }
  }, [saveToHistory]);

  const handleSubmitSearch = useCallback(() => {
    const inputValue = inputRef.current?.value || "";
    handleValidation(inputValue);
  }, [handleValidation]);

  const handleKeyPress = useCallback((event) => {
    if (event.key === "Enter") {
      handleSubmitSearch();
    }
  }, [handleSubmitSearch]);

  const handleCloseError = useCallback(() => {
    setIsInputInvalid(false);
  }, []);

  // Handle clicking on example IOC chip
  const handleExampleClick = useCallback((ioc) => {
    if (inputRef.current) {
      inputRef.current.value = ioc;
    }
    handleValidation(ioc);
  }, [handleValidation]);

  // Handle IOC from location state (from history click)
  useEffect(() => {
    if (location.state?.ioc) {
      const ioc = location.state.ioc;
      if (inputRef.current) {
        inputRef.current.value = ioc;
      }
      handleValidation(ioc);
      // Clear the state to prevent re-triggering
      window.history.replaceState({}, document.title);
    }
  }, [location.state, handleValidation]);

  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        minHeight: shouldShowTable ? 'auto' : 'calc(100vh - 200px)',
        justifyContent: shouldShowTable ? 'flex-start' : 'center',
        alignItems: 'center',
        px: 2,
      }}
    >
      <Box
        sx={{
          width: '100%',
          maxWidth: shouldShowTable ? '100%' : '800px',
          transition: 'all 0.3s ease-in-out',
        }}
      >
        {!shouldShowTable && (
          <Box sx={{ textAlign: 'center', mb: 4 }}>
            <Typography
              variant="h3"
              sx={{
                fontWeight: 500,
                background: 'linear-gradient(45deg, #2196F3 30%, #21CBF3 90%)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                mb: 1,
              }}
            >
              AOL Threat Intelligence
            </Typography>
            <Typography
              variant="h5"
              sx={{
                fontWeight: 400,
                color: 'text.secondary',
              }}
            >
              어떤 위협 지표를 분석해볼까요?
            </Typography>
          </Box>
        )}

        <SearchBar
          ref={inputRef}
          placeholder="Enter an IOC to analyze (IP, Domain, URL, Email, Hash, CVE)..."
          buttonLabel="Analyze"
          onKeyDown={handleKeyPress}
          onSearchClick={handleSubmitSearch}
          size={shouldShowTable ? "medium" : "large"}
          fullWidth
        />

        {/* Quick Example Chips */}
        {!shouldShowTable && (
          <Box sx={{ mt: 3, textAlign: 'center' }}>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
              예시로 검색해보기
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, justifyContent: 'center' }}>
              {EXAMPLE_IOCS.map((example, index) => (
                <Chip
                  key={index}
                  label={example.label}
                  onClick={() => handleExampleClick(example.label)}
                  sx={{
                    cursor: 'pointer',
                    '&:hover': {
                      backgroundColor: 'primary.main',
                      color: 'white',
                    },
                  }}
                />
              ))}
            </Box>
          </Box>
        )}

        {/* IOC Types Grid */}
        {!shouldShowTable && (
          <Box sx={{ mt: 5 }}>
            <Typography variant="h6" sx={{ mb: 2, textAlign: 'center', color: 'text.secondary' }}>
              지원하는 IOC 타입
            </Typography>
            <Grid container spacing={2}>
              {IOC_TYPES.map((iocType, index) => (
                <Grid item xs={6} sm={4} md={4} key={index}>
                  <Paper
                    elevation={0}
                    sx={{
                      p: 2,
                      textAlign: 'center',
                      border: '1px solid',
                      borderColor: 'divider',
                      borderRadius: 2,
                      transition: 'all 0.3s ease',
                      '&:hover': {
                        borderColor: iocType.color,
                        transform: 'translateY(-4px)',
                        boxShadow: `0 4px 20px ${iocType.color}33`,
                      },
                    }}
                  >
                    <Box sx={{ color: iocType.color, mb: 1 }}>
                      {React.cloneElement(iocType.icon, { fontSize: 'large' })}
                    </Box>
                    <Typography variant="subtitle2" fontWeight="bold" sx={{ mb: 0.5 }}>
                      {iocType.title}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {iocType.description}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Box>
        )}

        <Box sx={{ my: 1 }}>
          {isInputInvalid && (
            <Grow in={true}>
              <Alert
                severity="error"
                variant="filled"
                onClose={handleCloseError}
                sx={{ borderRadius: 1 }}
              >
                <AlertTitle>
                  <b>Invalid Input</b>
                </AlertTitle>
                Please enter a supported IOC type. The entered value does not match
                known formats for IP, Domain, URL, Email, Hash, or CVE.
              </Alert>
            </Grow>
          )}
        </Box>
      </Box>

      {shouldShowTable && searchValue && currentIocType && (
        <Box sx={{ width: '100%', mt: 2 }}>
          <ResultTable
            ioc={searchValue}
            iocType={currentIocType}
          />
        </Box>
      )}
    </Box>
  );
};

export default Analyzer;
